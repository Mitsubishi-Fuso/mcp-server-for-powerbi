"""
On-Behalf-Of (OBO) Token Flow for Power BI API Access
Acquires Power BI tokens using the user's token via OBO flow
"""

import time
import hashlib
import logging
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass
import requests

logger = logging.getLogger(__name__)


@dataclass
class ClaimsChallengeInfo:
    """Information about a claims challenge from Azure AD"""

    status: int
    www_authenticate: str
    claims: str  # base64 form, as carried in a WWW-Authenticate header
    decoded_claims: Optional[Any] = None
    error: Optional[str] = None
    error_description: Optional[str] = None
    trace_id: Optional[str] = None
    correlation_id: Optional[str] = None
    # Raw JSON claims string, as the token endpoint returns it. This is what a
    # client must send as the `claims` query parameter on /authorize.
    claims_raw: Optional[str] = None
    suberror: Optional[str] = None
    error_codes: Optional[List[int]] = None


class ClaimsChallengeError(Exception):
    """Exception raised when a claims challenge is encountered"""

    def __init__(self, message: str, info: ClaimsChallengeInfo):
        super().__init__(message)
        self.info = info


@dataclass
class OboTokenCacheEntry:
    """Cache entry for OBO tokens"""

    token: str
    expires_at: float  # Unix timestamp


class OboTokenCache:
    """Simple in-memory cache for OBO tokens"""

    def __init__(self):
        self._cache: Dict[str, OboTokenCacheEntry] = {}

    def _generate_key(self, tenant_id: str, client_id: str, assertion: str, scopes: List[str]) -> str:
        """Generate cache key from OBO parameters"""
        hash_input = assertion.encode("utf-8")
        assertion_hash = hashlib.sha256(hash_input).hexdigest()
        scopes_str = " ".join(sorted(scopes))
        return f"{tenant_id}|{client_id}|{assertion_hash}|{scopes_str}"

    def get(self, tenant_id: str, client_id: str, assertion: str, scopes: List[str]) -> Optional[str]:
        """Get cached token if valid"""
        key = self._generate_key(tenant_id, client_id, assertion, scopes)
        entry = self._cache.get(key)

        if entry is None:
            return None

        # Check if token is expired (with 5 second buffer)
        if entry.expires_at <= time.time() + 5:
            del self._cache[key]
            return None

        return entry.token

    def set(self, tenant_id: str, client_id: str, assertion: str, scopes: List[str], token: str, expires_in: int):
        """Cache token with expiration"""
        key = self._generate_key(tenant_id, client_id, assertion, scopes)
        # Subtract 60 seconds from expiration for safety
        ttl_seconds = max(0, expires_in - 60)
        expires_at = time.time() + ttl_seconds
        self._cache[key] = OboTokenCacheEntry(token=token, expires_at=expires_at)

    def invalidate(self, tenant_id: str, client_id: str, assertion: str, scopes: List[str]):
        """Invalidate cached token"""
        key = self._generate_key(tenant_id, client_id, assertion, scopes)
        if key in self._cache:
            del self._cache[key]


# Global cache instance
_obo_cache = OboTokenCache()


def _extract_claims_param(www_authenticate: Optional[str]) -> Optional[str]:
    """Extract claims parameter from WWW-Authenticate header"""
    if not www_authenticate:
        return None

    import re

    match = re.search(r'claims="([^"]+)"', www_authenticate, re.IGNORECASE)
    return match.group(1) if match else None


def _decode_claims_payload(claims: str) -> Any:
    """Decode a claims parameter, which may be raw JSON or base64-encoded JSON"""
    import base64
    import json

    stripped = claims.strip()
    if stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return stripped

    try:
        # Tolerate missing padding and the base64url alphabet.
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        try:
            return json.loads(decoded)
        except json.JSONDecodeError:
            return decoded
    except Exception:
        return None


def _encode_claims_for_header(claims: str) -> str:
    """Return the base64 form of a claims value, for use in WWW-Authenticate"""
    import base64

    stripped = claims.strip()
    if not stripped.startswith("{"):
        # Already base64 (came from a header).
        return stripped
    return base64.b64encode(stripped.encode("utf-8")).decode("ascii")


# Suberrors that Entra ID returns on the token endpoint when the caller must
# repeat the request interactively to satisfy a conditional access policy.
_INTERACTION_SUBERRORS = {
    "basic_action",
    "additional_action",
    "message_only",
    "consent_required",
    "user_password_expired",
    "bad_token",
}

# Error codes that always mean "the user must sign in again interactively",
# even when Entra returns no claims blob to replay.
_INTERACTION_ERROR_CODES = {
    50076,  # MFA required
    50079,  # MFA enrolment required
    50158,  # External security challenge not satisfied
    53000,  # Device not compliant
    53001,  # Device not domain joined
    53003,  # Blocked by conditional access
    65001,  # Consent required
}


def _build_claims_challenge(
    response_status: int, www_authenticate: Optional[str], error_data: Dict[str, Any]
) -> Optional[ClaimsChallengeInfo]:
    """
    Detect a conditional-access claims challenge in an Entra ID token error.

    The token endpoint signals these in the JSON body (a `claims` property plus
    a `suberror`), not in a WWW-Authenticate header, so the header alone is not
    enough to spot one.
    """
    claims_value = _extract_claims_param(www_authenticate) or error_data.get("claims")
    suberror = error_data.get("suberror")
    error_codes = error_data.get("error_codes") or []

    needs_interaction = (
        bool(claims_value)
        or suberror in _INTERACTION_SUBERRORS
        or any(code in _INTERACTION_ERROR_CODES for code in error_codes)
        or error_data.get("error") in ("interaction_required", "consent_required")
    )
    if not needs_interaction:
        return None

    claims_b64 = _encode_claims_for_header(claims_value) if claims_value else ""

    if not www_authenticate:
        # Synthesise a step-up challenge (RFC 9470) so downstream clients get a
        # standard signal to re-authenticate.
        parts = ['Bearer error="insufficient_claims"']
        if claims_b64:
            parts.append(f'claims="{claims_b64}"')
        description = error_data.get("error_description")
        if description:
            # Keep it to one line and free of quotes so the header stays valid.
            flattened = " ".join(description.split()).replace('"', "'")
            parts.append(f'error_description="{flattened[:400]}"')
        www_authenticate = ", ".join(parts)

    return ClaimsChallengeInfo(
        status=response_status,
        www_authenticate=www_authenticate,
        claims=claims_b64,
        decoded_claims=_decode_claims_payload(claims_value) if claims_value else None,
        error=error_data.get("error"),
        error_description=error_data.get("error_description"),
        trace_id=error_data.get("trace_id"),
        correlation_id=error_data.get("correlation_id"),
        claims_raw=claims_value or None,
        suberror=suberror,
        error_codes=error_codes or None,
    )


def acquire_obo_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    assertion: str,
    scopes: List[str],
    on_claims_challenge: Optional[Callable[[ClaimsChallengeInfo], None]] = None,
    log_fn: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None,
) -> Dict[str, Any]:
    """
    Acquire an access token using On-Behalf-Of flow

    Args:
        tenant_id: Azure AD tenant ID
        client_id: Client application ID
        client_secret: Client application secret
        assertion: User's access token to exchange
        scopes: List of scopes to request
        on_claims_challenge: Optional callback for claims challenges
        log_fn: Optional logging function (level, message, meta)

    Returns:
        Dict with 'access_token' and 'expires_in'

    Raises:
        ClaimsChallengeError: If a claims challenge is encountered
        Exception: For other errors
    """

    def log(level: str, msg: str, meta: Optional[Dict[str, Any]] = None):
        if log_fn:
            log_fn(level, msg, meta)
        else:
            log_method = getattr(logger, level, logger.info)
            if meta:
                log_method(f"{msg} {meta}")
            else:
                log_method(msg)

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "requested_token_use": "on_behalf_of",
        "assertion": assertion,
        "scope": " ".join(scopes),
    }

    log("info", "obo.request", {"tokenUrl": token_url, "scopes": scopes})

    try:
        response = requests.post(
            token_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=30
        )

        www_authenticate = response.headers.get("WWW-Authenticate")

        if not response.ok:
            try:
                error_data = response.json()
            except Exception:
                error_data = {}

            # 2000 chars so a claims blob is never truncated out of the log.
            log(
                "error",
                "obo.error",
                {"status": response.status_code, "body": response.text[:2000], "wwwAuthenticate": www_authenticate},
            )

            # Check for claims challenge, in the body as well as the header.
            info = _build_claims_challenge(response.status_code, www_authenticate, error_data)
            if info:
                log(
                    "warning",
                    "obo.claims_challenge",
                    {
                        "status": info.status,
                        "claims": info.claims,
                        "decodedClaims": info.decoded_claims,
                        "error": info.error,
                        "suberror": info.suberror,
                        "errorCodes": info.error_codes,
                        "traceId": info.trace_id,
                        "correlationId": info.correlation_id,
                        "wwwAuthenticate": info.www_authenticate,
                    },
                )

                if on_claims_challenge:
                    on_claims_challenge(info)

                raise ClaimsChallengeError("obo_claims_challenge", info)

            detail = error_data.get("error_description") or response.text[:300]
            raise Exception(f"obo_failed: status {response.status_code}: {detail}")

        result = response.json()
        access_token = result.get("access_token")

        if not access_token:
            log("error", "obo.no_access_token", {"body": response.text[:600]})
            raise Exception("obo_failed: no access_token in response")

        log("debug", "obo.success", {"expires_in": result.get("expires_in"), "token_type": result.get("token_type")})

        return result

    except ClaimsChallengeError:
        raise
    except Exception as e:
        log("error", f"obo.exception: {e}")
        raise


def get_obo_token_cached(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    assertion: str,
    scopes: List[str],
    on_claims_challenge: Optional[Callable[[ClaimsChallengeInfo], None]] = None,
    log_fn: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None,
) -> str:
    """
    Get OBO token with caching

    Args:
        tenant_id: Azure AD tenant ID
        client_id: Client application ID
        client_secret: Client application secret
        assertion: User's access token to exchange
        scopes: List of scopes to request
        on_claims_challenge: Optional callback for claims challenges
        log_fn: Optional logging function (level, message, meta)

    Returns:
        Access token string

    Raises:
        ClaimsChallengeError: If a claims challenge is encountered
        Exception: For other errors
    """

    def log(level: str, msg: str, meta: Optional[Dict[str, Any]] = None):
        if log_fn:
            log_fn(level, msg, meta)

    # Check cache first
    cached_token = _obo_cache.get(tenant_id, client_id, assertion, scopes)
    if cached_token:
        if log_fn:
            log("debug", "obo.cache.hit", {"keyPreview": "..."})
        return cached_token

    if log_fn:
        log("debug", "obo.cache.miss", {"keyPreview": "..."})

    # Acquire new token
    result = acquire_obo_token(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        assertion=assertion,
        scopes=scopes,
        on_claims_challenge=on_claims_challenge,
        log_fn=log_fn,
    )

    token = result["access_token"]
    expires_in = result.get("expires_in", 3600)

    # Cache token
    _obo_cache.set(
        tenant_id=tenant_id, client_id=client_id, assertion=assertion, scopes=scopes, token=token, expires_in=expires_in
    )

    return token


def invalidate_obo_token(tenant_id: str, client_id: str, assertion: str, scopes: List[str]):
    """Invalidate cached OBO token"""
    _obo_cache.invalidate(tenant_id, client_id, assertion, scopes)
