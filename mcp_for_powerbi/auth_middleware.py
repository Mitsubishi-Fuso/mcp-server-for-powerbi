"""Entra ID (Azure AD) Authentication Middleware for FastAPI/Starlette.

Validates JWT tokens and enriches request context with user information.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

import jwt
from jwt import InvalidTokenError, PyJWKClient
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

MatchMode = Literal["all", "any"]


# Changed to dataclass:
# This reduces boilerplate and makes claim mapping easier to maintain
# when new token fields are added later.
@dataclass(slots=True)
class EntraIDPayload:
    """Typed wrapper for Entra ID JWT claims."""

    payload: Dict[str, Any]

    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    exp: Optional[int] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None

    aio: Optional[str] = None
    azp: Optional[str] = None
    azpacr: Optional[str] = None
    idp: Optional[str] = None
    name: Optional[str] = None
    oid: Optional[str] = None
    preferred_username: Optional[str] = None
    rh: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    scp: Optional[str] = None
    sid: Optional[str] = None
    tid: Optional[str] = None
    uti: Optional[str] = None
    ver: Optional[str] = None
    xms_ftd: Optional[str] = None

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "EntraIDPayload":
        return cls(
            payload=payload,
            iss=payload.get("iss"),
            sub=payload.get("sub"),
            aud=payload.get("aud"),
            exp=payload.get("exp"),
            nbf=payload.get("nbf"),
            iat=payload.get("iat"),
            aio=payload.get("aio"),
            azp=payload.get("azp"),
            azpacr=payload.get("azpacr"),
            idp=payload.get("idp"),
            name=payload.get("name"),
            oid=payload.get("oid"),
            preferred_username=payload.get("preferred_username"),
            rh=payload.get("rh"),
            roles=payload.get("roles", []) or [],
            scp=payload.get("scp"),
            sid=payload.get("sid"),
            tid=payload.get("tid"),
            uti=payload.get("uti"),
            ver=payload.get("ver"),
            xms_ftd=payload.get("xms_ftd"),
        )

    def get_scopes(self) -> List[str]:
        """Parse scopes from scp claim.

        Entra ID usually returns scopes as a space-delimited string.
        We also tolerate commas defensively to avoid parsing failures
        if a different format appears.
        """
        if not self.scp:
            return []
        return [scope.strip() for scope in re.split(r"[ ,]+", self.scp) if scope.strip()]

    def to_dict(self) -> Dict[str, Any]:
        return self.payload


class EntraIDAuthMiddleware(BaseHTTPMiddleware):
    """Middleware to validate Entra ID (Azure AD) v2.0 access tokens."""

    def __init__(
        self,
        app,
        tenant_id: str,
        audience: str,
        required_scopes: Optional[List[str]] = None,
        required_roles: Optional[List[str]] = None,
        scope_match_mode: MatchMode = "all",
        role_match_mode: MatchMode = "all",
        log_level: str = "info",
    ):
        super().__init__(app)
        self.tenant_id = tenant_id
        self.audiences = self._parse_audiences(audience)
        self.required_scopes = required_scopes or []
        self.required_roles = required_roles or []

        # Added explicit match mode validation:
        # Previous logic always behaved like "all". This makes authorization
        # behavior configurable and easier to understand.
        self.scope_match_mode = self._validate_match_mode(scope_match_mode, "scope_match_mode")
        self.role_match_mode = self._validate_match_mode(role_match_mode, "role_match_mode")

        self.log_level = log_level.lower()

        self.jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        self.issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"

        self.jwks_client = PyJWKClient(
            self.jwks_uri,
            cache_keys=True,
            max_cached_keys=10,
            cache_jwk_set=True,
            lifespan=360,
        )

        logger.info(
            "EntraIDAuthMiddleware initialized: tenant=%s, audience=%s, scope_match_mode=%s, role_match_mode=%s",
            tenant_id,
            ", ".join(self.audiences),
            self.scope_match_mode,
            self.role_match_mode,
        )

    @staticmethod
    def _validate_match_mode(value: str, field_name: str) -> MatchMode:
        normalized = value.lower().strip()
        if normalized not in {"all", "any"}:
            raise ValueError(f"{field_name} must be 'all' or 'any'")
        return normalized  # type: ignore[return-value]

    @staticmethod
    def _parse_audiences(audience: str) -> List[str]:
        parsed = [item.strip() for item in audience.split(",") if item.strip()]
        if not parsed:
            raise ValueError("AUDIENCE must contain at least one non-empty value")
        return parsed

    def _log(self, level: str, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        if self.log_level == "debug" or level != "debug":
            log_fn = getattr(logger, level, logger.info)
            if meta:
                log_fn("%s %s", message, meta)
            else:
                log_fn(message)

    def _extract_token(self, request: Request) -> Optional[str]:
        auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth_header:
            return None
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()
        return None

    def _decode_token_unverified(self, token: str) -> Dict[str, Any]:
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as exc:
            self._log("debug", f"Failed to decode token: {exc}")
            return {}

    @staticmethod
    def _matches_required(
        required: List[str],
        granted: List[str],
        mode: MatchMode,
    ) -> bool:
        if not required:
            return True

        granted_set = set(granted)

        # Added configurable matching:
        # "all" preserves strict validation.
        # "any" supports cases where one of several scopes/roles is sufficient.
        if mode == "all":
            return all(item in granted_set for item in required)
        return any(item in granted_set for item in required)

    async def dispatch(self, request: Request, call_next):
        token = self._extract_token(request)
        if not token:
            self._log("warning", "auth.no_authorization_header")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "missing_authorization",
                    "message": "Authorization header with Bearer token required",
                },
            )

        unverified_claims: Dict[str, Any] = {}

        # Changed behavior:
        # Unverified token decoding now happens only in debug mode.
        # This avoids routinely reading untrusted claims during normal request flow.
        if self.log_level == "debug":
            unverified_claims = self._decode_token_unverified(token)
            safe_payload = {
                "iss": unverified_claims.get("iss"),
                "aud": unverified_claims.get("aud"),
                "ver": unverified_claims.get("ver"),
                "tid": unverified_claims.get("tid"),
                "azp": unverified_claims.get("azp"),
                "scp": unverified_claims.get("scp"),
                "roles": unverified_claims.get("roles"),
                "oid": unverified_claims.get("oid"),
                "preferred_username": unverified_claims.get("preferred_username"),
                "name": unverified_claims.get("name"),
                "exp": unverified_claims.get("exp"),
                "expected": {
                    "issuer": self.issuer,
                    "audience": self.audiences,
                },
            }
            self._log("debug", "auth.token.debug", safe_payload)

        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audiences,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )

            entra_payload = EntraIDPayload.from_dict(payload)

            if self.required_roles:
                user_roles = entra_payload.roles or []
                if not self._matches_required(self.required_roles, user_roles, self.role_match_mode):
                    self._log(
                        "warning",
                        "auth.roles.insufficient",
                        {
                            "roles_required": self.required_roles,
                            "role_match_mode": self.role_match_mode,
                            "oid": entra_payload.oid,
                            "username": entra_payload.preferred_username,
                        },
                    )

                    # Changed response body:
                    # Do not return granted roles to the client.
                    # Keep permission details in logs only to avoid leaking auth data.
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "insufficient_roles",
                            "message": "Token does not contain the required role permissions",
                        },
                    )

            if self.required_scopes:
                user_scopes = entra_payload.get_scopes()
                if not self._matches_required(self.required_scopes, user_scopes, self.scope_match_mode):
                    self._log(
                        "warning",
                        "auth.scopes.insufficient",
                        {
                            "scopes_required": self.required_scopes,
                            "scope_match_mode": self.scope_match_mode,
                            "oid": entra_payload.oid,
                            "username": entra_payload.preferred_username,
                        },
                    )

                    # Changed response body:
                    # Do not expose granted scopes in the API response.
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "insufficient_scopes",
                            "message": "Token does not contain the required delegated permissions",
                        },
                    )

            request.state.authenticated = entra_payload
            request.state.bearer_token = token

            self._log(
                "debug",
                "auth.authenticated",
                {
                    "oid": entra_payload.oid,
                    "username": entra_payload.preferred_username,
                    "scopes": entra_payload.get_scopes(),
                    "roles": entra_payload.roles,
                },
            )

        except jwt.ExpiredSignatureError:
            self._log("warning", "auth.token.expired")
            return JSONResponse(
                status_code=401,
                content={"error": "token_expired", "message": "Token has expired"},
            )

        except jwt.InvalidAudienceError as exc:
            # Only decode unverified claims here when needed for diagnostics.
            if not unverified_claims:
                unverified_claims = self._decode_token_unverified(token)

            self._log(
                "warning",
                f"auth.token.invalid_audience: {exc}",
                {
                    "expected_audience": self.audiences,
                    "current_token_aud": unverified_claims.get("aud"),
                },
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_audience",
                    "message": f"Token audience mismatch. Expected one of: {', '.join(self.audiences)}",
                },
            )

        except jwt.InvalidIssuerError as exc:
            # Only decode unverified claims here when needed for diagnostics.
            if not unverified_claims:
                unverified_claims = self._decode_token_unverified(token)

            self._log(
                "warning",
                f"auth.token.invalid_issuer: {exc}",
                {
                    "expected_issuer": self.issuer,
                    "current_token_iss": unverified_claims.get("iss"),
                },
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_issuer",
                    "message": f"Token issuer mismatch. Expected: {self.issuer}",
                },
            )

        except InvalidTokenError as exc:
            self._log("warning", f"auth.token.invalid: {exc}")
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "message": str(exc)},
            )

        except Exception as exc:
            message = str(exc).lower()

            # Added more precise error handling:
            # JWKS / signing-key fetch failures are closer to upstream identity
            # provider availability problems than generic authentication errors.
            if any(keyword in message for keyword in ["jwks", "signing key", "certificate", "connection", "timeout"]):
                self._log("error", f"auth.identity_provider_unavailable: {exc}")
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "identity_provider_unavailable",
                        "message": "Failed to fetch identity provider signing keys",
                    },
                )

            self._log("error", f"auth.error: {exc}")
            return JSONResponse(
                status_code=500,
                content={"error": "authentication_error", "message": "Failed to authenticate"},
            )

        return await call_next(request)


def get_authenticated_user(request: Request) -> Optional[EntraIDPayload]:
    """Helper to get authenticated user from request state."""
    return getattr(request.state, "authenticated", None)


def get_bearer_token(request: Request) -> Optional[str]:
    """Helper to get bearer token from request state."""
    return getattr(request.state, "bearer_token", None)