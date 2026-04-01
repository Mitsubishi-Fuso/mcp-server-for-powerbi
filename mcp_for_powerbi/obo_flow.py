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
    claims: str
    decoded_claims: Optional[Any] = None
    error: Optional[str] = None
    error_description: Optional[str] = None
    trace_id: Optional[str] = None
    correlation_id: Optional[str] = None


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
    
    def _generate_key(
        self,
        tenant_id: str,
        client_id: str,
        assertion: str,
        scopes: List[str]
    ) -> str:
        """Generate cache key from OBO parameters"""
        hash_input = assertion.encode('utf-8')
        assertion_hash = hashlib.sha256(hash_input).hexdigest()
        scopes_str = " ".join(sorted(scopes))
        return f"{tenant_id}|{client_id}|{assertion_hash}|{scopes_str}"
    
    def get(
        self,
        tenant_id: str,
        client_id: str,
        assertion: str,
        scopes: List[str]
    ) -> Optional[str]:
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
    
    def set(
        self,
        tenant_id: str,
        client_id: str,
        assertion: str,
        scopes: List[str],
        token: str,
        expires_in: int
    ):
        """Cache token with expiration"""
        key = self._generate_key(tenant_id, client_id, assertion, scopes)
        # Subtract 60 seconds from expiration for safety
        ttl_seconds = max(0, expires_in - 60)
        expires_at = time.time() + ttl_seconds
        self._cache[key] = OboTokenCacheEntry(token=token, expires_at=expires_at)
    
    def invalidate(
        self,
        tenant_id: str,
        client_id: str,
        assertion: str,
        scopes: List[str]
    ):
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
    """Decode base64-encoded claims parameter"""
    try:
        import base64
        import json
        decoded = base64.b64decode(claims).decode('utf-8')
        try:
            return json.loads(decoded)
        except json.JSONDecodeError:
            return decoded
    except Exception:
        return None


def acquire_obo_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    assertion: str,
    scopes: List[str],
    on_claims_challenge: Optional[Callable[[ClaimsChallengeInfo], None]] = None,
    log_fn: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None
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
        "scope": " ".join(scopes)
    }
    
    log("info", "obo.request", {"tokenUrl": token_url, "scopes": scopes})
    
    try:
        response = requests.post(
            token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30
        )
        
        www_authenticate = response.headers.get("WWW-Authenticate")
        
        if not response.ok:
            body_preview = response.text[:600]
            log("error", "obo.error", {
                "status": response.status_code,
                "body": body_preview,
                "wwwAuthenticate": www_authenticate
            })
            
            # Check for claims challenge
            claims_param = _extract_claims_param(www_authenticate)
            if claims_param and www_authenticate:
                try:
                    error_data = response.json()
                except Exception:
                    error_data = {}
                
                decoded_claims = _decode_claims_payload(claims_param)
                info = ClaimsChallengeInfo(
                    status=response.status_code,
                    www_authenticate=www_authenticate,
                    claims=claims_param,
                    decoded_claims=decoded_claims,
                    error=error_data.get("error"),
                    error_description=error_data.get("error_description"),
                    trace_id=error_data.get("trace_id"),
                    correlation_id=error_data.get("correlation_id")
                )
                
                log("warning", "obo.claims_challenge", {
                    "status": info.status,
                    "claims": info.claims,
                    "decodedClaims": info.decoded_claims,
                    "traceId": info.trace_id,
                    "correlationId": info.correlation_id,
                    "wwwAuthenticate": info.www_authenticate
                })
                
                if on_claims_challenge:
                    on_claims_challenge(info)
                
                raise ClaimsChallengeError("obo_claims_challenge", info)
            
            raise Exception(f"obo_failed: status {response.status_code}")
        
        result = response.json()
        access_token = result.get("access_token")
        
        if not access_token:
            log("error", "obo.no_access_token", {"body": response.text[:600]})
            raise Exception("obo_failed: no access_token in response")
        
        log("debug", "obo.success", {
            "expires_in": result.get("expires_in"),
            "token_type": result.get("token_type")
        })
        
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
    log_fn: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None
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
        log_fn=log_fn
    )
    
    token = result["access_token"]
    expires_in = result.get("expires_in", 3600)
    
    # Cache token
    _obo_cache.set(
        tenant_id=tenant_id,
        client_id=client_id,
        assertion=assertion,
        scopes=scopes,
        token=token,
        expires_in=expires_in
    )
    
    return token


def invalidate_obo_token(
    tenant_id: str,
    client_id: str,
    assertion: str,
    scopes: List[str]
):
    """Invalidate cached OBO token"""
    _obo_cache.invalidate(tenant_id, client_id, assertion, scopes)
