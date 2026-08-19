"""Custody mode: this server as a confidential OAuth client for Power BI.

The MCP client signs in against *this* server, which brokers the user's
interactive sign-in with Entra, keeps the refresh token, and hands the client a
credential of its own. Two OAuth relationships, and neither token is ever
presented to a party it was not issued for.

The alternatives it exists to avoid:

  passthrough  the client obtains a Power BI token and sends it here, so this
               server accepts a token minted for another resource
  OBO          the exchange happens server-side, where a conditional access
               challenge arrives somewhere the user cannot answer it

Here the Power BI token comes from an authorization code redeemed with the
user's browser in the loop, so conditional access is satisfied at sign-in. When
a stored refresh token later stops working - revoked, expired, or a policy
re-evaluation demanding interaction - the session is dropped and the client is
asked to sign in again, which it can actually do.

The relaying that makes an OAuth proxy awkward is absent by construction. The
redirect URI sent to Entra is a fixed value this server owns, so no
client-supplied value reaches Entra's redirect parameter; and because the code
the client redeems is one this server issued, correlating the two PKCE legs is
a lookup rather than a search.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import jwt
import requests
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from .token_store import (
    AuthorizationCode,
    PendingAuthorization,
    Session,
    TokenStore,
    fingerprint,
    new_secret,
)

logger = logging.getLogger(__name__)

POWER_BI_SCOPE = "https://analysis.windows.net/powerbi/api/.default"

# Renew this far ahead of expiry, so a token cannot lapse mid-request.
REFRESH_SKEW_SECONDS = 300

HTTP_TIMEOUT = 30

# Entra answers with these when the refresh token can no longer be redeemed
# without the user present. Retrying cannot help; only a new sign-in will.
_INTERACTION_REQUIRED = frozenset({"invalid_grant", "interaction_required", "login_required", "consent_required"})


class CustodyError(RuntimeError):
    """Something went wrong that the operator, not the user, has to fix."""


class SessionExpired(RuntimeError):
    """The stored credentials no longer work; the client must sign in again."""


def s256(verifier: str) -> str:
    """The PKCE challenge for a verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class CustodyFlow:
    """The authorization server, and the Power BI token source behind it."""

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        public_url: str,
        redirect_uris: Tuple[str, ...],
        store: TokenStore,
        client_ids: Tuple[str, ...] = (),
        authority: str = "https://login.microsoftonline.com",
    ):
        if not public_url:
            raise CustodyError(
                "AUTH_MODE=custody requires PUBLIC_URL, the address clients and browsers reach this "
                "server on. It is what Entra redirects back to, so it cannot be inferred from a request."
            )
        if not redirect_uris:
            raise CustodyError(
                "AUTH_MODE=custody requires CUSTODY_REDIRECT_URIS: the exact redirect URIs of the MCP "
                "clients allowed to sign in. Without it any caller could have an authorization code "
                "delivered wherever it liked."
            )
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.public_url = public_url.rstrip("/")
        self.redirect_uris = redirect_uris
        self.client_ids = client_ids
        self.store = store
        self.authority = authority.rstrip("/")

    # ── endpoints Entra publishes ─────────────────────────────────────────
    @property
    def entra_authorize_endpoint(self) -> str:
        return f"{self.authority}/{self.tenant_id}/oauth2/v2.0/authorize"

    @property
    def entra_token_endpoint(self) -> str:
        return f"{self.authority}/{self.tenant_id}/oauth2/v2.0/token"

    @property
    def callback_url(self) -> str:
        """Fixed, and ours. No client-supplied value is ever sent to Entra."""
        return f"{self.public_url}/callback"

    # ── validation ────────────────────────────────────────────────────────
    def _redirect_uri_allowed(self, redirect_uri: str) -> bool:
        # Exact match only: prefix matching is what lets an attacker append a
        # path or a userinfo section and still be accepted.
        return redirect_uri in self.redirect_uris

    def _client_allowed(self, client_id: str) -> bool:
        return not self.client_ids or client_id in self.client_ids

    # ── /authorize ────────────────────────────────────────────────────────
    async def authorize(self, request: Request) -> Any:
        params = request.query_params
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        challenge = params.get("code_challenge", "")
        method = params.get("code_challenge_method", "")
        client_state = params.get("state")

        # Anything wrong with the redirect target is reported here rather than
        # sent there, since redirecting is exactly what must not happen.
        if not self._redirect_uri_allowed(redirect_uri):
            logger.warning("Rejected /authorize for a redirect_uri that is not allowed: %r", redirect_uri)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "redirect_uri is not registered"},
            )
        if not self._client_allowed(client_id):
            logger.warning("Rejected /authorize for unknown client_id %r", client_id)
            return JSONResponse(
                status_code=400, content={"error": "unauthorized_client", "error_description": "unknown client_id"}
            )

        if params.get("response_type", "code") != "code":
            return self._redirect_error(
                redirect_uri, client_state, "unsupported_response_type", "only code is supported"
            )
        if not challenge or method != "S256":
            return self._redirect_error(
                redirect_uri, client_state, "invalid_request", "PKCE with code_challenge_method=S256 is required"
            )

        verifier = new_secret(32)
        state = new_secret(32)
        self.store.put_pending(
            state,
            PendingAuthorization(
                client_id=client_id,
                redirect_uri=redirect_uri,
                client_code_challenge=challenge,
                client_state=client_state,
                entra_code_verifier=verifier,
                created_at=time.time(),
            ),
        )

        query = urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "redirect_uri": self.callback_url,
                "response_mode": "query",
                "scope": f"{POWER_BI_SCOPE} offline_access",
                "state": state,
                "code_challenge": s256(verifier),
                "code_challenge_method": "S256",
            }
        )
        return RedirectResponse(f"{self.entra_authorize_endpoint}?{query}", status_code=302)

    @staticmethod
    def _redirect_error(redirect_uri: str, state: Optional[str], error: str, description: str):
        payload = {"error": error, "error_description": description}
        if state:
            payload["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(payload)}", status_code=302)

    # ── /callback ─────────────────────────────────────────────────────────
    async def callback(self, request: Request) -> Any:
        params = request.query_params
        state = params.get("state", "")
        pending = self.store.take_pending(state)
        if pending is None:
            # Unknown, replayed, or expired: there is nowhere safe to redirect.
            logger.warning("Rejected /callback with an unrecognised state")
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "unknown or expired authorization state"},
            )

        if params.get("error"):
            return self._redirect_error(
                pending.redirect_uri,
                pending.client_state,
                params.get("error", "access_denied"),
                params.get("error_description", "the sign-in was not completed"),
            )

        code = params.get("code", "")
        if not code:
            return self._redirect_error(
                pending.redirect_uri, pending.client_state, "invalid_request", "no code returned"
            )

        try:
            tokens = self._redeem_at_entra(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.callback_url,
                    "code_verifier": pending.entra_code_verifier,
                }
            )
        except SessionExpired as exc:
            return self._redirect_error(pending.redirect_uri, pending.client_state, "access_denied", str(exc))

        identity = self._identify(tokens.get("access_token", ""))
        session = Session(
            user_oid=identity.get("oid", ""),
            user_tid=identity.get("tid", ""),
            username=identity.get("username", ""),
            refresh_token=tokens.get("refresh_token", ""),
            access_token=tokens.get("access_token"),
            access_token_expires_at=time.time() + float(tokens.get("expires_in", 3600)),
        )
        if not session.refresh_token:
            # Without offline_access the session would die at the first expiry
            # and the user would be sent back to sign in every hour.
            logger.error("Entra returned no refresh token; check that offline_access is consented")
            return self._redirect_error(
                pending.redirect_uri, pending.client_state, "server_error", "no refresh token was issued"
            )

        session_key = new_secret(16)
        self.store.put_session(session_key, session)

        our_code = new_secret(32)
        self.store.put_code(
            our_code,
            AuthorizationCode(
                client_id=pending.client_id,
                redirect_uri=pending.redirect_uri,
                client_code_challenge=pending.client_code_challenge,
                session_key=session_key,
                created_at=time.time(),
            ),
        )
        logger.info("Established a custody session for %s", session.username or session.user_oid)

        payload = {"code": our_code}
        if pending.client_state:
            payload["state"] = pending.client_state
        return RedirectResponse(f"{pending.redirect_uri}?{urlencode(payload)}", status_code=302)

    # ── /token ────────────────────────────────────────────────────────────
    async def token(self, request: Request) -> Any:
        form = await request.form()
        grant_type = str(form.get("grant_type", ""))

        if grant_type == "authorization_code":
            return self._grant_authorization_code(form)
        if grant_type == "refresh_token":
            return self._grant_refresh_token(form)
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_grant_type", "error_description": f"{grant_type!r} is not supported"},
        )

    def _grant_authorization_code(self, form) -> JSONResponse:
        record = self.store.take_code(str(form.get("code", "")))
        if record is None:
            return self._token_error("invalid_grant", "unknown, expired, or already redeemed code")

        verifier = str(form.get("code_verifier", ""))
        # The client proves it is the one that started this sign-in. Correlating
        # the two PKCE legs is this lookup, because the code is one we issued.
        if not verifier or not secrets.compare_digest(s256(verifier), record.client_code_challenge):
            logger.warning("Rejected a token request whose code_verifier did not match")
            return self._token_error("invalid_grant", "code_verifier does not match code_challenge")

        client_id = str(form.get("client_id", ""))
        if client_id and client_id != record.client_id:
            return self._token_error("invalid_grant", "code was issued to a different client")
        if str(form.get("redirect_uri", record.redirect_uri)) != record.redirect_uri:
            return self._token_error("invalid_grant", "redirect_uri does not match the authorization request")

        session = self.store.get_session(record.session_key)
        if session is None:
            return self._token_error("invalid_grant", "the session has expired")
        return self._issue(record.session_key, session)

    def _grant_refresh_token(self, form) -> JSONResponse:
        presented = str(form.get("refresh_token", ""))
        resolved = self._resolve(presented, "refresh")
        if resolved is None:
            return self._token_error("invalid_grant", "unknown or superseded refresh token")
        session_key, session = resolved
        return self._issue(session_key, session)

    def _issue(self, session_key: str, session: Session) -> JSONResponse:
        """Mint a new pair for this session, retiring whatever came before."""
        access_secret = new_secret(32)
        refresh_secret = new_secret(32)
        session.access_secret_fingerprint = fingerprint(access_secret)
        session.refresh_secret_fingerprint = fingerprint(refresh_secret)
        self.store.put_session(session_key, session)
        return JSONResponse(
            content={
                "access_token": f"{session_key}.{access_secret}",
                "refresh_token": f"{session_key}.{refresh_secret}",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )

    @staticmethod
    def _token_error(error: str, description: str) -> JSONResponse:
        return JSONResponse(status_code=400, content={"error": error, "error_description": description})

    # ── /revoke ───────────────────────────────────────────────────────────
    async def revoke(self, request: Request) -> Any:
        form = await request.form()
        presented = str(form.get("token", ""))
        session_key, _, _ = presented.partition(".")
        if session_key:
            self.store.delete_session(session_key)
        # RFC 7009: an unknown token is not an error, so this says nothing
        # about whether the token existed.
        return JSONResponse(content={})

    # ── resolving what a client presents ──────────────────────────────────
    def _resolve(self, presented: str, kind: str) -> Optional[Tuple[str, Session]]:
        session_key, separator, secret = presented.partition(".")
        if not separator or not secret:
            return None
        session = self.store.get_session(session_key)
        if session is None:
            return None
        expected = session.access_secret_fingerprint if kind == "access" else session.refresh_secret_fingerprint
        if not expected or not secrets.compare_digest(expected, fingerprint(secret)):
            return None
        return session_key, session

    def resolve_access_token(self, presented: str) -> Optional[Tuple[str, Session]]:
        """The session an incoming bearer token belongs to, if it is still live."""
        return self._resolve(presented, "access")

    # ── the Power BI token itself ─────────────────────────────────────────
    def power_bi_token(self, session_key: str, session: Session) -> str:
        """A usable Power BI access token, refreshed if it is close to expiry."""
        if session.access_token and session.access_token_expires_at - time.time() > REFRESH_SKEW_SECONDS:
            return session.access_token

        try:
            tokens = self._redeem_at_entra(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": session.refresh_token,
                    "scope": f"{POWER_BI_SCOPE} offline_access",
                }
            )
        except SessionExpired:
            # Nothing here can rescue it, and leaving the session in place would
            # only produce the same failure on the next call.
            self.store.delete_session(session_key)
            raise

        session.access_token = tokens.get("access_token")
        session.access_token_expires_at = time.time() + float(tokens.get("expires_in", 3600))
        if tokens.get("refresh_token"):
            session.refresh_token = tokens["refresh_token"]
        self.store.put_session(session_key, session)
        if not session.access_token:
            raise SessionExpired("Entra returned no access token")
        return session.access_token

    def drop_session(self, session_key: str) -> None:
        self.store.delete_session(session_key)

    # ── talking to Entra ──────────────────────────────────────────────────
    def _redeem_at_entra(self, payload: Dict[str, str]) -> Dict[str, Any]:
        body = {"client_id": self.client_id, "client_secret": self.client_secret, **payload}
        try:
            response = requests.post(self.entra_token_endpoint, data=body, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            raise CustodyError(f"Could not reach Entra: {exc}") from exc

        if response.ok:
            return response.json()

        try:
            error = response.json()
        except ValueError:
            error = {}
        code = error.get("error", "invalid_grant")
        description = error.get("error_description", response.text[:500])
        logger.warning(
            "Entra refused the token request (%s): %s", code, description.splitlines()[0] if description else ""
        )

        if code in _INTERACTION_REQUIRED or error.get("claims"):
            raise SessionExpired(f"{code}: the user must sign in again")
        raise CustodyError(f"Entra returned {code}: {description}")

    @staticmethod
    def _identify(access_token: str) -> Dict[str, str]:
        """Label the session from the token Entra just issued us.

        Read unverified and used only for logging and request context: it came
        straight from Entra's token endpoint over TLS in answer to our own
        request, and nothing is authorised on the strength of these claims.
        """
        try:
            claims = jwt.decode(access_token, options={"verify_signature": False})
        except Exception:
            return {}
        return {
            "oid": claims.get("oid", ""),
            "tid": claims.get("tid", ""),
            "username": claims.get("upn") or claims.get("preferred_username") or "",
        }
