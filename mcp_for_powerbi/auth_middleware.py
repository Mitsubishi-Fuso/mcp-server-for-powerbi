"""
Entra ID (Azure AD) Authentication Middleware for FastAPI/Starlette
Validates JWT tokens and enriches request context with user information
"""
import logging
from typing import Optional, Dict, Any, List

import jwt
from jwt import PyJWKClient
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class EntraIDPayload:
    """Entra ID specific JWT claims"""
    
    def __init__(self, payload: Dict[str, Any]):
        self.payload = payload
        
        # Standard claims
        self.iss: Optional[str] = payload.get("iss")
        self.sub: Optional[str] = payload.get("sub")
        self.aud: Optional[str] = payload.get("aud")
        self.exp: Optional[int] = payload.get("exp")
        self.nbf: Optional[int] = payload.get("nbf")
        self.iat: Optional[int] = payload.get("iat")
        
        # Entra ID specific claims
        self.aio: Optional[str] = payload.get("aio")
        self.azp: Optional[str] = payload.get("azp")
        self.azpacr: Optional[str] = payload.get("azpacr")
        self.idp: Optional[str] = payload.get("idp")
        self.name: Optional[str] = payload.get("name")
        self.oid: Optional[str] = payload.get("oid")
        self.preferred_username: Optional[str] = payload.get("preferred_username")
        self.rh: Optional[str] = payload.get("rh")
        self.roles: Optional[List[str]] = payload.get("roles", [])
        self.scp: Optional[str] = payload.get("scp")
        self.sid: Optional[str] = payload.get("sid")
        self.tid: Optional[str] = payload.get("tid")
        self.uti: Optional[str] = payload.get("uti")
        self.ver: Optional[str] = payload.get("ver")
        self.xms_ftd: Optional[str] = payload.get("xms_ftd")
    
    def get_scopes(self) -> List[str]:
        """Parse scopes from scp claim (space or comma delimited)"""
        if not self.scp:
            return []
        # Support both space- and comma-delimited scope strings
        import re
        return [s.strip() for s in re.split(r'[ ,]+', self.scp) if s.strip()]
    
    def to_dict(self) -> Dict[str, Any]:
        """Return full payload as dictionary"""
        return self.payload


class EntraIDAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate Entra ID (Azure AD) v2.0 access tokens
    """
    
    def __init__(
        self,
        app,
        tenant_id: str,
        audience: str,
        required_scopes: Optional[List[str]] = None,
        required_roles: Optional[List[str]] = None,
        log_level: str = "info"
    ):
        super().__init__(app)
        self.tenant_id = tenant_id
        self.audiences = self._parse_audiences(audience)
        self.required_scopes = required_scopes or []
        self.required_roles = required_roles or []
        self.log_level = log_level.lower()
        
        # JWKS URI for Entra ID v2.0
        self.jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        self.issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        
        # PyJWKClient with caching
        self.jwks_client = PyJWKClient(
            self.jwks_uri,
            cache_keys=True,
            max_cached_keys=10,
            cache_jwk_set=True,
            lifespan=360  # 6 hours
        )
        
        logger.info(
            f"EntraIDAuthMiddleware initialized: tenant={tenant_id}, audience={', '.join(self.audiences)}"
        )

    @staticmethod
    def _parse_audiences(audience: str) -> List[str]:
        """Parse single or comma-separated audience values from configuration."""
        parsed = [a.strip() for a in audience.split(",") if a.strip()]
        if not parsed:
            raise ValueError("AUDIENCE must contain at least one non-empty value")
        return parsed
    
    def _log(self, level: str, message: str, meta: Optional[Dict[str, Any]] = None):
        """Structured logging"""
        if self.log_level == "debug" or level != "debug":
            log_fn = getattr(logger, level, logger.info)
            if meta:
                log_fn(f"{message} {meta}")
            else:
                log_fn(message)
    
    def _extract_token(self, request: Request) -> Optional[str]:
        """Extract bearer token from Authorization header"""
        auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
        
        if not auth_header:
            return None
        
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:]
        
        return None
    
    def _decode_token_unverified(self, token: str) -> Dict[str, Any]:
        """Decode JWT without verification (for debugging)"""
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            self._log("debug", f"Failed to decode token: {e}")
            return {}
    
    async def dispatch(self, request: Request, call_next):
        """Validate token and enrich request with user info"""
        
        # Extract token
        token = self._extract_token(request)
        
        if not token:
            self._log("warning", "auth.no_authorization_header")
            return JSONResponse(
                status_code=401,
                content={"error": "missing_authorization", "message": "Authorization header required"}
            )
   
        # Decode once for debug and mismatch diagnostics.
        unverified_claims = self._decode_token_unverified(token)
        current_token_aud = unverified_claims.get("aud")
        current_token_iss = unverified_claims.get("iss")

        # Debug logging: decode token unverified
        if self.log_level == "debug":
            safe_payload = {
                "iss": current_token_iss,
                "aud": current_token_aud,
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
                    "audience": self.audiences
                }
            }
            self._log("debug", "auth.token.debug", safe_payload)

        # Verify and decode token
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            
            # Decode and verify token
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
                    "verify_iss": True
                }
            )
            
            # Create EntraIDPayload object
            entra_payload = EntraIDPayload(payload)
            
            # Validate required roles
            if self.required_roles:
                user_roles = entra_payload.roles or []
                if not all(role in user_roles for role in self.required_roles):
                    self._log("warning", "roles not granted", {
                        "roles_required": self.required_roles,
                        "roles_granted": user_roles
                    })
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "insufficient_roles",
                            "message": f"Required roles: {', '.join(self.required_roles)}. Granted: {', '.join(user_roles)}"
                        }
                    )
            
            # Validate required scopes
            if self.required_scopes:
                user_scopes = entra_payload.get_scopes()
                if not all(scope in user_scopes for scope in self.required_scopes):
                    self._log("warning", "scopes not granted", {
                        "scopes_required": self.required_scopes,
                        "scopes_granted": user_scopes
                    })
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "insufficient_scopes",
                            "message": f"Required scopes: {', '.join(self.required_scopes)}. Granted: {', '.join(user_scopes)}"
                        }
                    )
            
            # Attach authenticated payload to request state
            request.state.authenticated = entra_payload
            request.state.bearer_token = token
            
            self._log("debug", "authenticated", {
                "oid": entra_payload.oid,
                "username": entra_payload.preferred_username,
                "scopes": entra_payload.get_scopes(),
                "roles": entra_payload.roles
            })
            
        except jwt.ExpiredSignatureError:
            self._log("warning", "auth.token.expired")
            return JSONResponse(
                status_code=401,
                content={"error": "token_expired", "message": "Token has expired"}
            )
        except jwt.InvalidAudienceError as e:
            self._log("warning", f"auth.token.invalid_audience: {e}", {
                "expected_audience": self.audiences,
                "current_token_aud": current_token_aud
            })
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_audience",
                    "message": f"Token audience mismatch. Expected: {', '.join(self.audiences)}"
                }
            )
        except jwt.InvalidIssuerError as e:
            self._log("warning", f"auth.token.invalid_issuer: {e}", {
                "expected_issuer": self.issuer,
                "current_token_iss": current_token_iss
            })
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_issuer",
                    "message": f"Token issuer mismatch. Expected: {self.issuer}"
                }
            )
        except jwt.InvalidTokenError as e:
            self._log("warning", f"auth.token.invalid: {e}")
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "message": str(e)}
            )
        except Exception as e:
            self._log("error", f"auth.error: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": "authentication_error", "message": "Failed to authenticate"}
            )
        
        # Continue with request
        response = await call_next(request)
        return response


def get_authenticated_user(request: Request) -> Optional[EntraIDPayload]:
    """Helper to get authenticated user from request state"""
    return getattr(request.state, "authenticated", None)


def get_bearer_token(request: Request) -> Optional[str]:
    """Helper to get bearer token from request state"""
    return getattr(request.state, "bearer_token", None)
