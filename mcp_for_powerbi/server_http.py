"""
MCP Server for Power BI with Streamable HTTP Transport and OAuth
Uses modern streamable-http transport with Entra ID authentication for Azure/LibreChat deployment
"""

import os
import sys
import logging
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
    PowerBIClient,
    set_request_scoped_powerbi_client_factory,
    reset_request_scoped_powerbi_client_factory,
)

# Import authentication
from .auth_middleware import EntraIDAuthMiddleware, get_authenticated_user, get_bearer_token
from .obo_flow import ClaimsChallengeError, get_obo_token_cached
from fastmcp.exceptions import ToolError
from fastmcp.tools import FunctionTool

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "3001"))
TENANT_ID = os.getenv("TENANT_ID")
AUDIENCE = os.getenv("AUDIENCE")
OBO_CLIENT_ID = os.getenv("OBO_CLIENT_ID") or os.getenv("CLIENT_ID")
OBO_CLIENT_SECRET = os.getenv("OBO_CLIENT_SECRET") or os.getenv("CLIENT_SECRET")
HAS_OBO_CREDENTIALS = bool(OBO_CLIENT_ID and OBO_CLIENT_SECRET)

POWER_BI_DEFAULT_SCOPE = "https://analysis.windows.net/powerbi/api/.default"

# Ensure required configuration
if not TENANT_ID or not AUDIENCE:
    logger.error("TENANT_ID and AUDIENCE are required in environment")
    sys.exit(1)

# Optional role/scope requirements
REQUIRED_ROLES = [s.strip() for s in os.getenv("REQUIRED_ROLES", "").split(",") if s.strip()]
REQUIRED_SCOPES = [s.strip() for s in os.getenv("REQUIRED_SCOPES", "").split(",") if s.strip()]

LOG_LEVEL = os.getenv("LOG_LEVEL", "info").lower()
if LOG_LEVEL == "debug":
    logging.getLogger().setLevel(logging.DEBUG)


# ── Client Factory ─────────────────────────────────────────────────────────
def create_powerbi_client(request: Request) -> PowerBIClient:
    """Create PowerBI client from request context with an OBO-exchanged Power BI token."""
    user_token = get_bearer_token(request)
    if not user_token:
        raise ToolError("Missing user authentication token")

    tenant_id = TENANT_ID
    if not tenant_id:
        raise ToolError("TENANT_ID is not configured")

    def token_provider() -> str:
        requested_scopes = [POWER_BI_DEFAULT_SCOPE]

        # Backward-compatible fallback: if OBO credentials aren't configured,
        # pass through the caller token as-is.
        client_id = OBO_CLIENT_ID
        client_secret = OBO_CLIENT_SECRET
        if not client_id or not client_secret:
            logger.debug("OBO credentials unavailable; reusing incoming token for Power BI.")
            return user_token

        try:
            return get_obo_token_cached(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                assertion=user_token,
                scopes=requested_scopes,
            )
        except ClaimsChallengeError:
            raise
        except Exception as exc:
            raise ToolError(
                f"Failed to acquire Power BI token via OBO. Requested scope: {requested_scopes[0]}. Details: {str(exc)}"
            )

    return PowerBIClient(token=user_token, token_provider=token_provider)


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

                # tool_info.fn is the actual function
                if isinstance(tool_info, FunctionTool):
                    # Check if it's async or sync
                    import inspect

                    if inspect.iscoroutinefunction(tool_info.fn):
                        result = await tool_info.fn(ctx, **tool_args)
                    else:
                        result = tool_info.fn(ctx, **tool_args)
                else:
                    raise ToolError(f"Tool {tool_name} is not callable")

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

            except ToolError as tool_error:
                # Expected, caller-correctable failure: bad DAX, unknown dataset,
                # insufficient permissions. Report it as a tool result with
                # isError set, so the calling model sees the message and can fix
                # its query, rather than as a server fault the client can only
                # treat as a transport failure.
                _log_tool_error(tool_name, tool_error)
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [{"type": "text", "text": str(tool_error)}],
                            "isError": True,
                        },
                        "id": request_id,
                    }
                )

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
        logger.warning(f"Claims challenge: {e.info.error_description}")
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
                    "message": "claims_challenge",
                    "data": {
                        "claims": e.info.claims,
                        "decodedClaims": e.info.decoded_claims,
                        "error": e.info.error,
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
    if HAS_OBO_CREDENTIALS:
        logger.info("OBO credentials configured for downstream Power BI token exchange.")
    else:
        logger.warning(
            "OBO credentials are not configured. Incoming bearer token will be reused for "
            "the Power BI API; this can fail when the token audience does not match."
        )
    logger.info(f"Listening on http://0.0.0.0:{PORT}")

    app = create_app()

    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level=LOG_LEVEL)


if __name__ == "__main__":
    main()
