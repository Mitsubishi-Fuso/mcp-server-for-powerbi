"""
MCP Server for Power BI with Streamable HTTP Transport and OAuth
Uses modern streamable-http transport with Entra ID authentication for Azure/LibreChat deployment
"""

import os
import sys
import inspect
import logging
from typing import Any
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

import json

# Import all tools and configurations from the main server
from .server import (
    mcp,
    PowerBIAPIError,
    PowerBIClient,
    set_request_scoped_powerbi_client_factory,
    reset_request_scoped_powerbi_client_factory,
)

# Import authentication
from .auth_middleware import EntraIDAuthMiddleware, get_authenticated_user, get_bearer_token
from .obo_flow import ClaimsChallengeError, get_obo_token_cached, invalidate_obo_token
from .auth_mode import PASSTHROUGH, PASSTHROUGH_WARNING, AuthModeError, resolve_auth_mode
from fastmcp.exceptions import ToolError
from fastmcp.tools import FunctionTool

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "3001"))
TENANT_ID = os.getenv("TENANT_ID")
AUDIENCE = os.getenv("AUDIENCE")


def _first_env(*names: str) -> str | None:
    """Read the first of several environment variables that is set."""
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


# OBO_* and the bare CLIENT_* forms are the historical names, still honoured.
ENTRA_CLIENT_ID = _first_env("ENTRA_CLIENT_ID", "OBO_CLIENT_ID", "CLIENT_ID")
ENTRA_CLIENT_SECRET = _first_env("ENTRA_CLIENT_SECRET", "OBO_CLIENT_SECRET", "CLIENT_SECRET")

POWER_BI_DEFAULT_SCOPE = "https://analysis.windows.net/powerbi/api/.default"

# Ensure required configuration
if not TENANT_ID or not AUDIENCE:
    logger.error("TENANT_ID and AUDIENCE are required in environment")
    sys.exit(1)

try:
    AUTH_MODE = resolve_auth_mode(
        os.getenv("AUTH_MODE"),
        has_credentials=bool(ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET),
    )
except AuthModeError as exc:
    logger.error("%s", exc)
    sys.exit(1)

# Optional role/scope requirements
REQUIRED_ROLES = [s.strip() for s in os.getenv("REQUIRED_ROLES", "").split(",") if s.strip()]
REQUIRED_SCOPES = [s.strip() for s in os.getenv("REQUIRED_SCOPES", "").split(",") if s.strip()]

LOG_LEVEL = os.getenv("LOG_LEVEL", "info").lower()
if LOG_LEVEL == "debug":
    logging.getLogger().setLevel(logging.DEBUG)


# ── Client Factory ─────────────────────────────────────────────────────────
def create_powerbi_client(request: Request) -> PowerBIClient:
    """Build a Power BI client for this request, per the configured auth mode."""
    user_token = get_bearer_token(request)
    if not user_token:
        raise ToolError("Missing user authentication token")

    if AUTH_MODE == PASSTHROUGH:
        # The caller's token is already addressed to Power BI, and is sent on
        # unchanged. Deprecated: see auth_mode.PASSTHROUGH_WARNING.
        return PowerBIClient(token=user_token)

    tenant_id = TENANT_ID
    if not tenant_id:
        raise ToolError("TENANT_ID is not configured")

    client_id, client_secret = ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET
    if not client_id or not client_secret:
        raise ToolError("Entra client credentials are not configured")

    def token_provider() -> str:
        try:
            return get_obo_token_cached(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                assertion=user_token,
                scopes=[POWER_BI_DEFAULT_SCOPE],
            )
        except ClaimsChallengeError:
            # Carries a conditional access challenge the client must satisfy
            # interactively; it has to reach the transport intact.
            raise
        except Exception as exc:
            raise ToolError(
                f"Failed to acquire Power BI token via OBO. Requested scope: {POWER_BI_DEFAULT_SCOPE}. Details: {exc}"
            )

    # Lets the tool-call handler discard this token if Power BI rejects it, so
    # a stale cache entry costs one retry rather than a re-authentication.
    request.state.invalidate_downstream_token = lambda: invalidate_obo_token(
        tenant_id, client_id, user_token, [POWER_BI_DEFAULT_SCOPE]
    )

    return PowerBIClient(token=user_token, token_provider=token_provider)


def _drop_cached_downstream_token(request: Request) -> bool:
    """Discard the Power BI token this server minted, so the next call re-mints it.

    Returns False when there is nothing to discard: under passthrough the token
    is the caller's own, and only the client can replace it.
    """
    invalidate = getattr(request.state, "invalidate_downstream_token", None)
    if invalidate is None:
        return False
    invalidate()
    return True


def _log_tool_error(tool_name: str, tool_error: Exception) -> None:
    """Log a caller-correctable tool failure: one line at INFO, the rest at DEBUG.

    These messages are written for a model that has to act on them, so they
    carry suggestions and context and can run to dozens of lines. That is the
    right size for a tool result and the wrong size for a log at INFO, where it
    buries the surrounding request in a wall of advice aimed at someone else.
    """
    message = str(tool_error)
    summary, separator, _ = message.partition("\n")
    logger.info("Tool %s returned an error: %s", tool_name, summary)
    if separator:
        logger.debug("Tool %s error detail:\n%s", tool_name, message)


async def _invoke_tool(tool_info: Any, ctx: Any, tool_args: dict, tool_name: str) -> Any:
    """Call a registered tool, whether its implementation is sync or async."""
    if not isinstance(tool_info, FunctionTool):
        raise ToolError(f"Tool {tool_name} is not callable")
    if inspect.iscoroutinefunction(tool_info.fn):
        return await tool_info.fn(ctx, **tool_args)
    return tool_info.fn(ctx, **tool_args)


# ── Error responses ────────────────────────────────────────────────────────
def _header_safe(value: str, limit: int = 200) -> str:
    """Collapse a message into something that can sit in a quoted header param."""
    collapsed = " ".join(value.split())
    collapsed = collapsed.replace("\\", " ").replace('"', "'")
    if len(collapsed) > limit:
        collapsed = collapsed[: limit - 1].rstrip() + "\u2026"
    return collapsed


def _tool_error_response(request_id: Any, message: str) -> JSONResponse:
    """Report a tool failure as an MCP result the calling model can read."""
    return JSONResponse(
        content={
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": message}], "isError": True},
            "id": request_id,
        }
    )


def _unauthenticated_response(request_id: Any, exc: PowerBIAPIError) -> JSONResponse:
    """Report that Power BI rejected the token, so the client re-authenticates.

    Reached only once re-minting the token has already been tried and failed,
    so whatever is wrong is upstream of this server: the caller's sign-in no
    longer buys access to Power BI. Returning that as a tool result would leave
    the model apologising for a failure it cannot act on, while the client sat
    on a session it did not know was dead.
    """
    description = _header_safe(f"Power BI rejected the access token ({exc.error_code}).")
    return JSONResponse(
        status_code=401,
        headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{description}"'},
        content={
            "jsonrpc": "2.0",
            "error": {
                "code": -32001,
                "message": "unauthenticated: Power BI rejected the access token.",
                "data": {
                    "powerBiStatus": exc.status_code,
                    "powerBiCode": exc.error_code,
                    "detail": str(exc),
                },
            },
            "id": request_id,
        },
    )


# ── Routes ──────────────────────────────────────────────────────────────────
async def health_check(request: Request):
    """Health check endpoint"""
    return PlainTextResponse("MCP mcp-server-for-powerbi is running")


async def revoke_handler(request: Request):
    """Token revocation endpoint for LibreChat compatibility"""
    # LibreChat calls this when disconnecting, just return success
    logger.info("Token revocation requested (no-op)")
    return JSONResponse(status_code=200, content={"success": True, "message": "Token revocation acknowledged"})


async def mcp_handler(request: Request):
    """MCP endpoint with authentication and OBO flow"""

    # Get authenticated user
    user = get_authenticated_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "unauthorized", "message": "Authentication required"})

    logger.info(f"MCP request from user: {user.preferred_username or user.oid}")

    context_token = set_request_scoped_powerbi_client_factory(lambda: create_powerbi_client(request))

    try:
        # Parse MCP JSON-RPC request
        body = await request.json()
        method = body.get("method")
        params = body.get("params", {})
        request_id = body.get("id")

        logger.info(f"MCP request: method={method}, id={request_id}")

        # Handle MCP notifications (no response needed)
        if request_id is None:
            if method == "notifications/initialized":
                logger.info("Client initialized notification received")
                return JSONResponse(content={})
            elif method.startswith("notifications/"):
                logger.info(f"Notification received: {method}")
                return JSONResponse(content={})
            else:
                logger.warning(f"Unknown notification: {method}")
                return JSONResponse(content={})

        # Handle MCP methods
        if method == "ping":
            # Respond to ping/keep-alive requests
            return JSONResponse(content={"jsonrpc": "2.0", "result": {}, "id": request_id})

        elif method == "initialize":
            # Return server capabilities
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mcp-server-for-powerbi", "version": "0.2.0"},
                    },
                    "id": request_id,
                }
            )

        elif method == "tools/list":
            # Build tool list dynamically from FastMCP registry to avoid schema drift.
            tools_by_key = await mcp.get_tools()
            tools_payload = []
            for tool_key in sorted(tools_by_key.keys()):
                tool = tools_by_key[tool_key]
                mcp_tool = tool.to_mcp_tool(include_fastmcp_meta=False)
                tools_payload.append(
                    {
                        "name": mcp_tool.name,
                        "description": mcp_tool.description or "",
                        "inputSchema": mcp_tool.inputSchema
                        or {
                            "type": "object",
                            "properties": {},
                            "required": [],
                        },
                    }
                )

            return JSONResponse(content={"jsonrpc": "2.0", "result": {"tools": tools_payload}, "id": request_id})

        elif method == "tools/call":
            # Execute a tool
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            logger.info(f"Calling tool: {tool_name} with args: {tool_args}")

            # Get the tool info from mcp
            tool_info = await mcp.get_tool(tool_name)
            if not tool_info:
                return JSONResponse(
                    status_code=404,
                    content={
                        "jsonrpc": "2.0",
                        "error": {"code": -32601, "message": f"Tool not found: {tool_name}"},
                        "id": request_id,
                    },
                )

            # Execute the tool
            try:
                # Call the tool's function
                from fastmcp import Context

                ctx = Context(fastmcp=mcp)

                try:
                    result = await _invoke_tool(tool_info, ctx, tool_args, tool_name)
                except PowerBIAPIError as rejected:
                    # Under OBO the rejected token is one this server minted, and
                    # a cache entry that outlived the real expiry is the usual
                    # cause. Drop it and try once more, rather than sending the
                    # caller off to sign in again for something a fresh exchange
                    # would have fixed.
                    if not (rejected.is_token_rejection() and _drop_cached_downstream_token(request)):
                        raise
                    logger.info(
                        "Power BI rejected our token on %s (%s %s); retrying once with a fresh one",
                        tool_name,
                        rejected.status_code,
                        rejected.error_code,
                    )
                    result = await _invoke_tool(tool_info, ctx, tool_args, tool_name)

                # Check for claims challenge
                claims_challenge = getattr(request.state, "claims_challenge_holder", {}).get("challenge")
                if claims_challenge:
                    return JSONResponse(
                        status_code=401,
                        headers={"WWW-Authenticate": claims_challenge.www_authenticate},
                        content={
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32001,
                                "message": "claims_challenge: Conditional access challenge required.",
                                "data": {
                                    "claims": claims_challenge.claims,
                                    "decodedClaims": claims_challenge.decoded_claims,
                                    "error": claims_challenge.error,
                                    "errorDescription": claims_challenge.error_description,
                                    "traceId": claims_challenge.trace_id,
                                    "correlationId": claims_challenge.correlation_id,
                                },
                            },
                            "id": request_id,
                        },
                    )

                # Return tool result
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(result, indent=2) if not isinstance(result, str) else result,
                                }
                            ]
                        },
                        "id": request_id,
                    }
                )

            except PowerBIAPIError as tool_error:
                # A rejection that survived the retry above is not something the
                # model can act on, so make the client re-authenticate. Anything
                # else Power BI reports is an ordinary tool failure.
                if tool_error.is_token_rejection():
                    logger.warning(
                        "Power BI rejected the token on %s (%s %s)",
                        tool_name,
                        tool_error.status_code,
                        tool_error.error_code,
                    )
                    return _unauthenticated_response(request_id, tool_error)

                _log_tool_error(tool_name, tool_error)
                return _tool_error_response(request_id, str(tool_error))

            except ClaimsChallengeError:
                # Let the outer handler turn this into a 401 + WWW-Authenticate.
                raise

            except ToolError as tool_error:
                # Expected, caller-correctable failure: bad DAX, unknown dataset,
                # insufficient permissions. Report it as a tool result with
                # isError set, so the calling model sees the message and can fix
                # its query, rather than as a server fault the client can only
                # treat as a transport failure.
                _log_tool_error(tool_name, tool_error)
                return _tool_error_response(request_id, str(tool_error))

            except Exception as tool_error:
                # Genuinely unexpected - keep the traceback and the 500.
                logger.exception("Unexpected error executing tool %s", tool_name)
                return JSONResponse(
                    status_code=500,
                    content={
                        "jsonrpc": "2.0",
                        "error": {"code": -32000, "message": f"Tool execution failed: {str(tool_error)}"},
                        "id": request_id,
                    },
                )

        else:
            # Unsupported method
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": request_id,
                },
            )

    except ClaimsChallengeError as e:
        logger.warning("Claims challenge (%s/%s): %s", e.info.error, e.info.suberror, e.info.error_description)
        try:
            req_id = body.get("id") if "body" in locals() else None
        except Exception:
            req_id = None

        return JSONResponse(
            status_code=401,
            headers={"WWW-Authenticate": e.info.www_authenticate},
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32001,
                    "message": (
                        "claims_challenge: re-authentication is required to satisfy a conditional access "
                        f"policy on the Power BI API. {e.info.error_description or ''}".strip()
                    ),
                    "data": {
                        "claims": e.info.claims,
                        # Raw JSON form: pass this as the `claims` parameter on a
                        # fresh /authorize request to satisfy the challenge.
                        "claimsRaw": e.info.claims_raw,
                        "decodedClaims": e.info.decoded_claims,
                        "error": e.info.error,
                        "suberror": e.info.suberror,
                        "errorCodes": e.info.error_codes,
                        "errorDescription": e.info.error_description,
                        "traceId": e.info.trace_id,
                        "correlationId": e.info.correlation_id,
                    },
                },
                "id": req_id,
            },
        )
    except Exception as e:
        logger.error(f"MCP handler error: {e}", exc_info=True)
        try:
            req_id = body.get("id") if "body" in locals() else None
        except Exception:
            req_id = None

        return JSONResponse(
            status_code=500, content={"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}, "id": req_id}
        )
    finally:
        reset_request_scoped_powerbi_client_factory(context_token)


# ── Application Setup ───────────────────────────────────────────────────────
def create_app() -> Starlette:
    """Create Starlette application with authentication"""

    logger.info("Authentication mode: %s", AUTH_MODE)
    if AUTH_MODE == PASSTHROUGH:
        logger.warning("%s", PASSTHROUGH_WARNING)

    # Keep explicit runtime checks so failures remain actionable in logs/responses.
    if not TENANT_ID:
        raise ToolError("TENANT_ID is not configured")
    if not AUDIENCE:
        raise ToolError("AUDIENCE is not configured")

    # Create authentication middleware instance
    auth_middleware = EntraIDAuthMiddleware(
        app=None,
        tenant_id=TENANT_ID,
        audience=AUDIENCE,
        required_scopes=REQUIRED_SCOPES,
        required_roles=REQUIRED_ROLES,
        log_level=LOG_LEVEL,
    )

    # Wrapper for /mcp route that applies authentication
    async def authenticated_mcp_handler(request: Request):
        """MCP handler with authentication check"""

        async def call_next(req):
            return await mcp_handler(req)

        return await auth_middleware.dispatch(request, call_next)

    # CORS and Auth middleware stack
    middleware = [
        Middleware(
            CORSMiddleware,  # type: ignore[arg-type]
            # Starlette does not support wildcard ports in allow_origins.
            allow_origins=[],
            allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$",
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["Content-Type", "Authorization", "mcp-session-id"],
            expose_headers=["Mcp-Session-Id"],
        )
    ]

    # Create app with routes
    app = Starlette(
        debug=(LOG_LEVEL == "debug"),
        routes=[
            Route("/", health_check, methods=["GET"]),
            Route("/mcp", authenticated_mcp_handler, methods=["POST", "GET", "DELETE"]),
            Route("/revoke", revoke_handler, methods=["POST"]),
        ],
        middleware=middleware,
    )

    return app


def main():
    """Run the MCP server with streamable-http transport and OAuth"""
    import uvicorn

    logger.info("Starting MCP Server for Power BI with Entra ID Authentication")
    logger.info(f"Tenant: {TENANT_ID}")
    logger.info(f"Audience: {AUDIENCE}")
    logger.info(f"Required Scopes: {REQUIRED_SCOPES}")
    logger.info(f"Required Roles: {REQUIRED_ROLES}")
    logger.info(f"Listening on http://0.0.0.0:{PORT}")

    app = create_app()

    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level=LOG_LEVEL)


if __name__ == "__main__":
    main()
