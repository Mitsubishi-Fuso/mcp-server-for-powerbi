import requests
import time
import json
import base64
import logging
import re
from contextvars import ContextVar, Token
from typing import Any, Callable, Dict, Tuple
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError
from .obo_flow import ClaimsChallengeError
from fastmcp.server.dependencies import get_http_headers

BASE_URL = "https://api.powerbi.com/v1.0/myorg"
FABRIC_BASE_URL = "https://api.fabric.microsoft.com/v1"
TIMEOUT = 30
MAX_DEFINITION_RETRIES = 8
DEFAULT_RETRY_AFTER_SECONDS = 5
INITIAL_DEFINITION_REQUEST_RETRIES = 3

mcp = FastMCP("MCP Server for Power BI")
logger = logging.getLogger(__name__)
_request_scoped_client_factory: ContextVar[Callable[[], "PowerBIClient"] | None] = ContextVar(
    "request_scoped_powerbi_client_factory",
    default=None,
)


def set_request_scoped_powerbi_client_factory(
    factory: Callable[[], "PowerBIClient"],
) -> Token[Callable[[], "PowerBIClient"] | None]:
    """Set request-scoped PowerBIClient factory for current context."""
    return _request_scoped_client_factory.set(factory)


def reset_request_scoped_powerbi_client_factory(
    token: Token[Callable[[], "PowerBIClient"] | None],
) -> None:
    """Reset request-scoped PowerBIClient factory to previous state."""
    _request_scoped_client_factory.reset(token)

class PowerBIClient:
    def __init__(
        self,
        token: str | None = None,
        token_provider: Callable[[str], str] | None = None,
    ):
        if token is None and token_provider is None:
            request_factory = _request_scoped_client_factory.get()
            if request_factory:
                scoped_client = request_factory()
                self.token = scoped_client.token
                self._token_provider = getattr(scoped_client, "_token_provider", None)
                self.headers = scoped_client.headers
                return

        # Get token from HTTP Authorization header (OAuth flow)
        if token is None:
            try:
                headers = get_http_headers()
                auth = headers.get("authorization", "")
                if auth.startswith("Bearer "):
                    token = auth[7:]
                elif auth.startswith("bearer "):
                    token = auth[7:]
                elif auth:  # Raw token without "Bearer " prefix
                    token = auth
            except Exception:
                # get_http_headers() will fail in certain modes, that's expected
                pass

        if not token:
            raise ToolError(
                "Missing Power BI access token. Please provide it via Authorization header: 'Bearer <token>'"
            )
        self.token = token
        self._token_provider = token_provider
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _get_headers_for_service(self, service: str) -> Dict[str, str]:
        """Build auth headers for Power BI/Fabric calls."""
        if self._token_provider:
            try:
                access_token = self._token_provider(service)
            except ToolError:
                raise
            except ClaimsChallengeError as exc:
                raise ToolError(
                    f"Claims challenge required for {service} token. "
                    f"WWW-Authenticate: {exc.info.www_authenticate}"
                )
            except Exception as exc:
                raise ToolError(f"Failed to get {service} access token: {str(exc)}")
            if not access_token:
                raise ToolError(f"Missing {service} access token")
            return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        return self.headers

    def _build_error_message(self, status_code: int, error_data: Any, path: str) -> str:
        """Build a detailed error message with helpful suggestions."""
        suggestions = []

        # Extract error details
        if isinstance(error_data, dict):
            error_code = error_data.get("error", {}).get("code", "Unknown")
            error_message = error_data.get("error", {}).get("message", str(error_data))
        else:
            error_code = "Unknown"
            error_message = str(error_data)

        # Build context-aware suggestions based on status code and path
        if status_code == 401:
            suggestions.extend([
                "Verify the Power BI access token is valid and not expired",
                "Check if the required permission scope is present in the token",
                "Ensure the token has the necessary API permissions (Dataset.ReadWrite.All or Dataset.Read.All)"
            ])
        elif status_code == 403:
            if "TokenExpired" in error_code:
                suggestions.append("The access token has expired - please obtain a new token")
            else:
                suggestions.extend([
                    "Verify you have access to the requested workspace",
                    "Check if you are a member or admin of the workspace",
                    "Ensure you have the required permissions for this operation",
                    "The authorization header might be incorrect - check for typos"
                ])
        elif status_code == 404:
            if "/datasets/" in path:
                suggestions.append("The specified dataset ID does not exist or you don't have access to it")
            elif "/groups/" in path:
                suggestions.append("The specified workspace ID does not exist or you don't have access to it")
            else:
                suggestions.append("The requested resource was not found")
        elif status_code == 400:
            suggestions.extend([
                "Check if all required parameters are provided",
                "Verify parameter formats (IDs should be valid UUIDs)",
                "For DAX queries, check syntax and table/column references"
            ])
        elif status_code == 429:
            suggestions.append("Rate limit exceeded - please wait before retrying (limit: 120 requests per minute)")

        # Build the error message
        error_parts = [f"Power BI API Error ({status_code})"]
        if error_code != "Unknown":
            error_parts.append(f"Code: {error_code}")
        error_parts.append(f"Message: {error_message}")

        if suggestions:
            error_parts.append("\nSuggestions:")
            for suggestion in suggestions:
                error_parts.append(f"  - {suggestion}")

        return "\n".join(error_parts)

    def request(self, method: str, path: str, json_body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        url = f"{BASE_URL}{path}"
        try:
            r = requests.request(
                method,
                url,
                headers=self._get_headers_for_service("powerbi"),
                json=json_body,
                timeout=TIMEOUT,
            )
        except requests.exceptions.Timeout:
            raise ToolError(
                f"Request timed out after {TIMEOUT} seconds. "
                f"The Power BI service might be slow or unavailable. Please try again."
            )
        except requests.exceptions.ConnectionError as e:
            raise ToolError(
                f"Connection error: Unable to connect to Power BI API.\n"
                f"Details: {str(e)}\n"
                f"Suggestions:\n"
                f"  - Check your internet connection\n"
                f"  - Verify the Power BI service is accessible\n"
                f"  - Check if there are any network restrictions or firewall rules"
            )
        except requests.exceptions.RequestException as e:
            raise ToolError(f"Request error: {str(e)}")

        # Handle non-OK responses
        if not r.ok:
            error_data = None
            try:
                error_data = r.json()
            except ValueError:
                error_data = r.text

            error_message = self._build_error_message(r.status_code, error_data, path)
            raise ToolError(error_message)

        # Parse successful response; some endpoints return 202/204 with no body
        if r.status_code == 204 or not r.content:
            return {}
        try:
            return r.json()
        except ValueError:
            raise ToolError(
                "Invalid response: The Power BI API returned a non-JSON response. "
                "This might indicate a service issue."
            )

    def fabric_request(self, method: str, path: str, json_body: Dict[str, Any] | None = None) -> requests.Response:
        """Issue a request to Fabric REST API and return raw response."""
        url = f"{FABRIC_BASE_URL}{path}" if path.startswith("/") else path
        try:
            return requests.request(
                method,
                url,
                headers=self._get_headers_for_service("fabric"),
                json=json_body,
                timeout=TIMEOUT,
            )
        except requests.exceptions.RequestException as e:
            raise ToolError(f"Fabric API request error: {str(e)}")


def _extract_tmsl_model_from_definition_payload(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Extract and parse model.bim from Fabric getDefinition response.

    Returns (model_dict, error_reason).  Empty error_reason means success.
    """
    definition = payload.get("definition", {})
    parts = definition.get("parts", [])
    if not isinstance(parts, list):
        logger.warning("Fabric definition payload has invalid 'parts' format.")
        return {}, "invalid_response"

    candidate_paths: list[str] = []
    for part in parts:
        part_path = str(part.get("path", ""))
        normalized_path = part_path.lower().replace("\\", "/")
        candidate_paths.append(part_path)

        # TMSL normally contains model.bim. Accept both "model.bim" and "definition/model.bim".
        if normalized_path.endswith("model.bim"):
            payload_type = part.get("payloadType")
            if payload_type and payload_type != "InlineBase64":
                logger.warning("Unexpected payloadType for model.bim: %s", payload_type)
                return {}, "invalid_response"

            raw = part.get("payload", "")
            if not raw:
                logger.warning("model.bim part is present but payload is empty.")
                return {}, "decode_error"
            try:
                decoded = base64.b64decode(raw).decode("utf-8")
                parsed = json.loads(decoded)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                logger.warning("Failed to decode/parse model.bim payload: %s", exc)
                logger.debug("model.bim decode/parse failure details", exc_info=True)
                return {}, "decode_error"

            if not isinstance(parsed, dict):
                logger.warning("Parsed model.bim is not a JSON object.")
                return {}, "invalid_response"
            return parsed, ""

    logger.warning("Fabric definition response did not include model.bim. Paths: %s", candidate_paths)
    return {}, "model_bim_missing"


def _get_semantic_model_via_fabric_definition(
    client: PowerBIClient, workspace_id: str, dataset_id: str
) -> Tuple[Dict[str, Any], str]:
    """Get semantic model definition (TMSL) via Fabric REST API.

    Returns (model_dict, error_reason).  Empty error_reason means success.
    """
    def _safe_retry_after(value: str | None) -> int:
        if value is None:
            return DEFAULT_RETRY_AFTER_SECONDS
        try:
            return max(1, int(value))
        except ValueError:
            return DEFAULT_RETRY_AFTER_SECONDS

    def _response_summary(response: requests.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            body = response.text
        return f"status={response.status_code}, body={body}"

    path = f"/workspaces/{workspace_id}/semanticModels/{dataset_id}/getDefinition?format=TMSL"
    response = client.fabric_request("POST", path)

    # Initial 429 handling with bounded retries.
    for attempt in range(INITIAL_DEFINITION_REQUEST_RETRIES):
        if response.status_code != 429:
            break
        wait_seconds = _safe_retry_after(response.headers.get("Retry-After"))
        logger.warning(
            "Fabric getDefinition rate limited for dataset %s in workspace %s "
            "(attempt %s/%s), waiting %ss.",
            dataset_id,
            workspace_id,
            attempt + 1,
            INITIAL_DEFINITION_REQUEST_RETRIES,
            wait_seconds,
        )
        time.sleep(wait_seconds)
        response = client.fabric_request("POST", path)

    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError as exc:
            logger.warning("Fabric getDefinition returned non-JSON 200 response: %s", exc)
            logger.debug("Fabric getDefinition non-JSON body: %s", response.text)
            return {}, "invalid_response"
        return _extract_tmsl_model_from_definition_payload(payload)

    if response.status_code == 202:
        operation_url = response.headers.get("Location")
        retry_after = _safe_retry_after(response.headers.get("Retry-After"))
        if not operation_url:
            logger.warning("Fabric getDefinition returned 202 without Location header.")
            return {}, "no_location_header"

        for attempt in range(MAX_DEFINITION_RETRIES):
            time.sleep(retry_after)
            poll = client.fabric_request("GET", operation_url)

            if poll.status_code == 200:
                try:
                    payload = poll.json()
                except ValueError as exc:
                    logger.warning("Fabric LRO polling returned non-JSON 200 response: %s", exc)
                    logger.debug("Fabric LRO non-JSON body: %s", poll.text)
                    return {}, "invalid_response"
                return _extract_tmsl_model_from_definition_payload(payload)

            if poll.status_code in (401, 403):
                logger.warning(
                    "Fabric getDefinition polling unauthorized/forbidden: %s. "
                    "Possible token audience mismatch: Power BI tokens commonly use "
                    "'https://analysis.windows.net/powerbi/api', while Fabric APIs require "
                    "'https://api.fabric.microsoft.com'.",
                    _response_summary(poll),
                )
                return {}, "auth_failed"

            if poll.status_code in (202, 429):
                retry_after = _safe_retry_after(poll.headers.get("Retry-After"))
                logger.info(
                    "Fabric getDefinition still in progress/rate-limited "
                    "(attempt %s/%s, status=%s, next wait=%ss).",
                    attempt + 1,
                    MAX_DEFINITION_RETRIES,
                    poll.status_code,
                    retry_after,
                )
                continue

            logger.warning("Fabric LRO polling failed: %s", _response_summary(poll))
            return {}, "api_error"

        logger.warning(
            "Fabric getDefinition polling exceeded max retries (%s) for dataset %s in workspace %s.",
            MAX_DEFINITION_RETRIES,
            dataset_id,
            workspace_id,
        )
        return {}, "poll_timeout"

    if response.status_code in (401, 403):
        logger.warning(
            "Fabric getDefinition unauthorized/forbidden: %s. "
            "Possible token audience mismatch: Power BI tokens commonly use "
            "'https://analysis.windows.net/powerbi/api', while Fabric APIs require "
            "'https://api.fabric.microsoft.com'.",
            _response_summary(response),
        )
        return {}, "auth_failed"

    logger.warning("Fabric getDefinition failed: %s", _response_summary(response))
    return {}, "api_error"

@mcp.tool
def powerbi_list_workspaces(ctx: Context) -> Dict[str, Any]:
    """List all Power BI workspaces the user has access to.

    Returns a list of workspaces with their IDs and names. This is useful for
    identifying which workspaces you can access and work with.

    Common errors:
    - 401 Unauthorized: Token is missing or invalid
    - 403 Forbidden: Token expired or lacks required permissions
    """
    try:
        client = PowerBIClient()
        return client.request("GET", "/groups")
    except ToolError as e:
        # Re-raise with additional context for workspace listing
        error_msg = str(e)
        if "401" in error_msg or "Unauthorized" in error_msg:
            raise ToolError(
                f"{error_msg}\n\n"
                f"Additional context for listing workspaces:\n"
                f"  - This operation requires a valid Power BI access token\n"
                f"  - The token must have 'Workspace.Read.All' or 'Workspace.ReadWrite.All' scope\n"
                f"  - Ensure the Authorization header contains a valid OAuth token"
            )
        raise

@mcp.tool
def get_workspace_id(ctx: Context, workspace_name: str) -> str:
    """Get the workspace ID for a given workspace name.

    This tool is useful for finding the workspace ID when you only know the
    workspace name. The ID is required for other operations like listing datasets.

    Args:
        workspace_name: The display name of the Power BI workspace.

    Returns:
        The workspace ID as a string.

    Raises:
        ToolError: If the workspace is not found.
    """
    client = PowerBIClient()
    data = client.request("GET", "/groups")

    workspaces = data.get("value", [])
    for workspace in workspaces:
        if workspace.get("name") == workspace_name:
            return workspace.get("id")

    # Workspace not found - provide helpful error message
    available_names = [ws.get("name", "Unknown") for ws in workspaces]
    raise ToolError(
        f"Workspace '{workspace_name}' not found. "
        f"Available workspaces: {', '.join(available_names)}"
    )

def _validate_uuid(value: str, param_name: str) -> None:
    """Validate that a string is a valid UUID format.

    Args:
        value: The value to validate
        param_name: Name of the parameter for error messages

    Raises:
        ToolError: If the value is not a valid UUID
    """
    if not value or not value.strip():
        raise ToolError(
            f"Missing required parameter: {param_name}\n"
            f"Please provide a valid workspace/dataset ID (UUID format)."
        )

    # Basic UUID format validation (8-4-4-4-12 hexadecimal characters)
    uuid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if not re.match(uuid_pattern, value.strip()):
        raise ToolError(
            f"Invalid {param_name} format: '{value}'\n"
            f"Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (UUID)\n"
            f"Example: f089354e-8366-4e18-aea3-4cb4a3a50b48\n\n"
            f"Suggestion: Use 'get_workspace_id' tool to find the workspace ID by name."
        )

@mcp.tool
def list_datasets_in_workspace(ctx: Context, workspace_id: str) -> Dict[str, Any]:
    """List datasets in the specified workspace.

    Args:
        workspace_id: The unique identifier of the Power BI workspace (UUID format).

    Raises:
        ToolError: If workspace_id is missing or invalid format
    """
    _validate_uuid(workspace_id, "workspace_id")

    client = PowerBIClient()
    return client.request("GET", f"/groups/{workspace_id.strip()}/datasets")

@mcp.tool
def get_dataset_details(ctx: Context, workspace_id: str, dataset_id: str) -> Dict[str, Any]:
    """Retrieve dataset (semantic model) metadata and definition.

    Args:
        workspace_id: The unique identifier of the Power BI workspace (UUID format).
        dataset_id: The unique identifier of the dataset (UUID format).

    Raises:
        ToolError: If workspace_id or dataset_id is missing or invalid format
    """
    _validate_uuid(workspace_id, "workspace_id")
    _validate_uuid(dataset_id, "dataset_id")

    client = PowerBIClient()
    data = client.request("GET", f"/groups/{workspace_id.strip()}/datasets/{dataset_id.strip()}")
    data["semanticModel"] = {}
    data["semanticModelSource"] = "unavailable"
    try:
        semantic_model, err = _get_semantic_model_via_fabric_definition(
            client,
            workspace_id.strip(),
            dataset_id.strip(),
        )
        if semantic_model:
            data["semanticModel"] = semantic_model
            data["semanticModelSource"] = "fabric_getDefinition_tmsl"
        elif err:
            data["semanticModelSource"] = f"fabric_error:{err}"
    except ToolError as exc:
        logger.warning("Failed to retrieve semantic model definition via Fabric API: %s", exc)
        logger.debug("Fabric definition retrieval ToolError details", exc_info=True)
        data["semanticModelSource"] = "fabric_error:tool_error"
    except Exception as exc:
        logger.warning("Unexpected error retrieving semantic model definition: %s", exc)
        logger.debug("Unexpected semantic model retrieval error details", exc_info=True)
        data["semanticModelSource"] = "fabric_error:unexpected"
    return data

def _analyze_dax_error(error_msg: str, dax_query: str) -> list[str]:
    """Analyze DAX error and provide helpful suggestions.

    Args:
        error_msg: Error message from DAX execution
        dax_query: The DAX query that failed

    Returns:
        List of suggestion strings
    """
    suggestions = []
    error_lower = error_msg.lower()

    # DAX syntax errors
    if "syntax" in error_lower or "parsing" in error_lower:
        suggestions.extend([
            "Check DAX syntax - ensure EVALUATE is used for table expressions",
            "Verify parentheses and brackets are properly matched",
            "Check function parameter count and types",
            "DAX is case-insensitive for keywords but case-sensitive for object names"
        ])

    # Table reference issues
    if "table" in error_lower and ("not found" in error_lower or "doesn't exist" in error_lower or "cannot find" in error_lower):
        suggestions.extend([
            "Verify the table name exists in the dataset",
            "Check table name spelling (table names are case-sensitive)",
            "Use single quotes for table names with spaces: 'Sales Data'",
            "If the table is from another model, check the relationship"
        ])

    # Column reference issues
    if "column" in error_lower and ("not found" in error_lower or "doesn't exist" in error_lower or "cannot find" in error_lower):
        suggestions.extend([
            "Verify the column name exists in the specified table",
            "Use TableName[ColumnName] syntax for column references",
            "Check column name spelling (column names are case-sensitive)",
            "Ensure you're referencing the correct table for this column"
        ])

    # Query result limitations
    if "more than" in error_lower or "limit" in error_lower or "exceed" in error_lower:
        suggestions.extend([
            "The query exceeded Power BI limits (max 100,000 rows or 1,000,000 values)",
            "Use TOPN() to limit the number of rows returned",
            "Add filters to reduce the result set size",
            "Consider aggregating data instead of returning raw rows"
        ])

    # Function errors
    if "function" in error_lower:
        suggestions.extend([
            "Verify the function name is spelled correctly",
            "Check that the function exists in DAX (some Excel functions don't exist in DAX)",
            "Verify the number and types of function arguments",
            "Some functions require specific evaluation contexts"
        ])

    # Relationship/filter context errors
    if "relationship" in error_lower or "filter" in error_lower or "context" in error_lower:
        suggestions.extend([
            "Check if required relationships exist between tables",
            "Verify filter context is set up correctly",
            "Consider using CALCULATE to modify filter context",
            "Check for circular dependencies in relationships"
        ])

    # Dataset permission/configuration errors
    if "permission" in error_lower or "denied" in error_lower:
        suggestions.extend([
            "Verify you have read and build permissions on the dataset",
            "Check if Row-Level Security (RLS) is blocking access",
            "Ensure the dataset is published and accessible"
        ])

    # Tenant setting errors
    if "tenant" in error_lower or "admin" in error_lower:
        suggestions.append(
            "The 'Dataset Execute Queries REST API' tenant setting must be enabled "
            "(Admin Portal > Tenant settings > Integration settings)"
        )

    # No specific error detected, provide general suggestions
    if not suggestions:
        suggestions.extend([
            "Verify the DAX query syntax is correct",
            "Check all table and column references exist in the dataset",
            "Ensure the query doesn't exceed Power BI limitations",
            "Try a simpler query first to isolate the issue (e.g., EVALUATE TableName)"
        ])

    return suggestions

@mcp.tool
def execute_dax_query(ctx: Context, workspace_id: str, dataset_id: str, dax_query: str) -> Dict[str, Any]:
    """Execute a DAX query against a dataset.

    This tool executes DAX (Data Analysis Expressions) queries against Power BI datasets.
    DAX queries must use the EVALUATE keyword for table expressions.

    Args:
        workspace_id: The unique identifier of the Power BI workspace (UUID format).
        dataset_id: The unique identifier of the dataset (UUID format).
        dax_query: The DAX query text to execute. Must start with EVALUATE for table queries.

    Returns:
        Query results with tables and rows, or error information if the query fails.

    Common errors:
    - 400 Bad Request: DAX syntax errors, invalid table/column references
    - 403 Forbidden: Missing permissions or tenant setting not enabled
    - Limitations: Max 100,000 rows or 1,000,000 values per query

    Example DAX query:
        EVALUATE TOPN(10, 'Sales')

    Raises:
        ToolError: If parameters are invalid or query execution fails
    """
    _validate_uuid(workspace_id, "workspace_id")
    _validate_uuid(dataset_id, "dataset_id")

    if not dax_query or not dax_query.strip():
        raise ToolError(
            "Missing required parameter: dax_query\n"
            "Please provide a valid DAX query.\n\n"
            "Example: EVALUATE TOPN(10, 'Sales')"
        )

    try:
        client = PowerBIClient()
        body = {"queries": [{"query": dax_query.strip()}]}
        result = client.request(
            "POST",
            f"/groups/{workspace_id.strip()}/datasets/{dataset_id.strip()}/executeQueries",
            json_body=body
        )

        # Check if the result contains errors (successful HTTP 200 but with query errors)
        if isinstance(result, dict):
            # Check for top-level error
            if "error" in result and result["error"]:
                error_info = result["error"]
                error_code = error_info.get("code", "Unknown")
                error_message = error_info.get("message", str(error_info))

                suggestions = _analyze_dax_error(error_message, dax_query)

                raise ToolError(
                    f"DAX Query Error\n"
                    f"Code: {error_code}\n"
                    f"Message: {error_message}\n\n"
                    f"Query:\n{dax_query}\n\n"
                    f"Suggestions:\n" + "\n".join(f"  - {s}" for s in suggestions)
                )

            # Check for errors in query results
            if "results" in result:
                for idx, query_result in enumerate(result["results"]):
                    if "error" in query_result and query_result["error"]:
                        error_info = query_result["error"]
                        error_code = error_info.get("code", "Unknown")
                        error_message = error_info.get("message", str(error_info))

                        suggestions = _analyze_dax_error(error_message, dax_query)

                        raise ToolError(
                            f"DAX Query Execution Error (Query {idx + 1})\n"
                            f"Code: {error_code}\n"
                            f"Message: {error_message}\n\n"
                            f"Query:\n{dax_query}\n\n"
                            f"Suggestions:\n" + "\n".join(f"  - {s}" for s in suggestions)
                        )

                    # Check for table-level errors
                    if "tables" in query_result:
                        for table_idx, table in enumerate(query_result["tables"]):
                            if "error" in table and table["error"]:
                                error_info = table["error"]
                                error_code = error_info.get("code", "Unknown")
                                error_message = error_info.get("message", str(error_info))

                                raise ToolError(
                                    f"DAX Query Table Error (Query {idx + 1}, Table {table_idx + 1})\n"
                                    f"Code: {error_code}\n"
                                    f"Message: {error_message}\n\n"
                                    f"Note: This may indicate the query returned more data than allowed.\n"
                                    f"Try using TOPN() to limit results or add filters to reduce data volume."
                                )

        return result

    except ToolError:
        # Re-raise ToolErrors as-is
        raise
    except Exception as e:
        # Catch any unexpected errors
        suggestions = _analyze_dax_error(str(e), dax_query)
        raise ToolError(
            f"Unexpected error executing DAX query:\n{str(e)}\n\n"
            f"Query:\n{dax_query}\n\n"
            f"Suggestions:\n" + "\n".join(f"  - {s}" for s in suggestions)
        )

def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
