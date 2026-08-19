import requests
import json
import logging
import re
from contextvars import ContextVar, Token
from typing import Any, Callable, Dict, NamedTuple, Tuple
from fastmcp import FastMCP, Context
from fastmcp.exceptions import ToolError
from .obo_flow import ClaimsChallengeError
from fastmcp.server.dependencies import get_http_headers

BASE_URL = "https://api.powerbi.com/v1.0/myorg"
TIMEOUT = 30

# A DAX result larger than this is withheld from the caller. The limit exists
# because the caller is usually a language model: a result that does not fit
# its context window is not merely slow to read, it displaces the conversation
# that gave the query its purpose.
#
# This does not protect the server. By the time the size is known the whole
# response has been fetched and parsed, so the cost of the query has already
# been paid - what is saved is spending the caller's context on it.
#
# Written as 50 * 1024 so that it reports itself as "50.0 KB" rather than
# contradicting its own name.
MAX_RESULT_BYTES = 50 * 1024

# Power BI refuses to return more than this from one query, so a result of
# exactly this many rows has almost certainly been truncated and the caller
# cannot tell how much was cut.
_POWERBI_MAX_ROWS = 100_000

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


class PowerBIAPIError(ToolError):
    """A ToolError that also carries the HTTP status of the failed Power BI call.

    Callers that need to react to *how* a call failed (rather than just report
    it) can read status_code, error_code and details instead of
    pattern-matching the message text.
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        error_code: str = "Unknown",
        details: Dict[str, str] | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        # The code/value pairs from the "pbi.error" block, so callers can
        # branch on what failed without pattern-matching the rendered message
        # (which by then also contains our own suggestion text).
        self.details = details or {}

    def with_message(self, message: str) -> "PowerBIAPIError":
        """This error with different text, and everything else intact.

        Callers that add context to a failure used to rebuild the error by
        hand, listing the fields to carry across. Every field added since was
        one more thing to remember at each call site, and the ones that were
        forgotten failed silently - the error still looked right, it had just
        quietly lost what the layer above needed to act on it.

        Copying makes that structural rather than per-call-site: a field added
        to __init__ is carried by every caller without any of them changing.

        Builds the clone through __new__ and copies __dict__, rather than
        calling __init__ or copy.copy - both of those go back through the
        signature, which is the thing being routed around.
        """
        clone = self.__class__.__new__(self.__class__)
        clone.__dict__.update(self.__dict__)
        # args is a BaseException slot, not an entry in __dict__, and it is
        # what str() reads.
        clone.args = (message,)
        return clone


# Written by _build_error_message and split on by callers that have something
# better to say than the generic suggestions, so the two must agree.
_SUGGESTIONS_HEADING = "\nSuggestions:"


# Parse and binding failures carry a source position, e.g.
# "Query (1, 15) The table 'Sales' cannot be found". Execution failures do not.
_DAX_SOURCE_POSITION = re.compile(r"Query \(\d+,\s*\d+\)")


def _looks_like_dax_binding_error(details_message: str) -> bool:
    """True when Power BI's detail text points at the query text itself.

    Distinguishes "your DAX is wrong" from "your DAX was fine and the engine
    fell over", which need entirely different advice but share the
    DatasetExecuteQueriesError code.
    """
    if not details_message:
        return False
    if _DAX_SOURCE_POSITION.search(details_message):
        return True
    lowered = details_message.lower()
    return "syntax" in lowered or "cannot be found" in lowered or "couldn't be found" in lowered


class PowerBIClient:
    def __init__(
        self,
        token: str | None = None,
        token_provider: Callable[[], str] | None = None,
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

    def _get_auth_headers(self) -> Dict[str, str]:
        """Build auth headers for Power BI API calls."""
        if self._token_provider:
            try:
                access_token = self._token_provider()
            except ToolError:
                raise
            except ClaimsChallengeError:
                # Must reach the transport layer intact so it can be turned into
                # a 401 + WWW-Authenticate for the client to re-authenticate.
                raise
            except Exception as exc:
                raise ToolError(f"Failed to get Power BI access token: {str(exc)}")
            if not access_token:
                raise ToolError("Missing Power BI access token")
            return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        return self.headers

    @staticmethod
    def _extract_error_code(error_data: Any) -> str:
        """Pull Power BI's own error code out of a response body."""
        if isinstance(error_data, dict):
            return error_data.get("error", {}).get("code", "Unknown")
        return "Unknown"

    @staticmethod
    def _extract_error_details(error_data: Any) -> Dict[str, str]:
        """Pull the code/value pairs out of a Power BI "pbi.error" details block.

        Power BI leaves error.message unset for several error classes - notably
        DatasetExecuteQueriesError - and puts the only useful text under
        error["pbi.error"]["details"], as a list of {code, detail: {value}}
        pairs. Without reading those, the caller gets a dump of the whole
        response body and no indication of what actually failed.
        """
        if not isinstance(error_data, dict):
            return {}
        pbi_error = error_data.get("error", {}).get("pbi.error")
        if not isinstance(pbi_error, dict):
            return {}

        details: Dict[str, str] = {}
        for entry in pbi_error.get("details", []):
            if not isinstance(entry, dict):
                continue
            code = entry.get("code")
            detail = entry.get("detail")
            # Older responses inline the string; current ones wrap it in {type, value}.
            value = detail.get("value") if isinstance(detail, dict) else detail
            if code and value is not None:
                details[str(code)] = str(value)
        return details

    def _build_error_message(self, status_code: int, error_data: Any, path: str) -> str:
        """Build a detailed error message with helpful suggestions."""
        suggestions = []

        # Extract error details
        error_code = self._extract_error_code(error_data)
        details = self._extract_error_details(error_data)
        if isinstance(error_data, dict):
            # json.dumps, not str(): the latter emits a Python repr with single
            # quotes, which is neither valid JSON nor pleasant to read.
            error_message = (
                error_data.get("error", {}).get("message") or details.get("DetailsMessage") or json.dumps(error_data)
            )
        else:
            error_message = str(error_data)

        # Build context-aware suggestions based on status code and path
        if status_code == 401:
            suggestions.extend(
                [
                    "Verify the Power BI access token is valid and not expired",
                    "Check if the required permission scope is present in the token",
                    "Ensure the token has the necessary API permissions (Dataset.ReadWrite.All or Dataset.Read.All)",
                ]
            )
        elif status_code == 403:
            if "TokenExpired" in error_code:
                suggestions.append("The access token has expired - please obtain a new token")
            else:
                suggestions.extend(
                    [
                        "Verify you have access to the requested workspace",
                        "Check if you are a member or admin of the workspace",
                        "Ensure you have the required permissions for this operation",
                        "The authorization header might be incorrect - check for typos",
                    ]
                )
        elif status_code == 404:
            if "/datasets/" in path:
                suggestions.append("The specified dataset ID does not exist or you don't have access to it")
            elif "/groups/" in path:
                suggestions.append("The specified workspace ID does not exist or you don't have access to it")
            else:
                suggestions.append("The requested resource was not found")
        elif status_code == 400:
            if error_code == "DatasetExecuteQueriesError" and not _looks_like_dax_binding_error(
                details.get("DetailsMessage", "")
            ):
                # No line/column reference means the model parsed and bound the
                # query, then failed running it. Pointing at DAX syntax here
                # sends the caller looking in the wrong place.
                suggestions.extend(
                    [
                        "The model accepted the query and failed while executing it - this is not a syntax error",
                        "If the tables are DirectQuery, the failure is in the pushdown to the underlying source: "
                        "check that the gateway is online and the source (e.g. the Databricks cluster) is running",
                        "Check authorization at the source, not just in Power BI: where credentials are passed "
                        "through per-user, a caller who lacks rights on the underlying table gets this same "
                        "generic error rather than a permission message",
                        "Compare against another table in the same model - if some tables succeed, the model and "
                        "gateway are healthy and the problem is specific to this table",
                        "Confirm the semantic model has completed a successful refresh (import models only)",
                        "For import models with row-level security, note the query runs as the calling user",
                    ]
                )
            else:
                suggestions.extend(
                    [
                        "Check if all required parameters are provided",
                        "Verify parameter formats (IDs should be valid UUIDs)",
                        "For DAX queries, check syntax and table/column references",
                    ]
                )
        elif status_code == 429:
            suggestions.append("Rate limit exceeded - please wait before retrying (limit: 120 requests per minute)")

        # Build the error message
        error_parts = [f"Power BI API Error ({status_code})"]
        if error_code != "Unknown":
            error_parts.append(f"Code: {error_code}")
        error_parts.append(f"Message: {error_message}")

        # Everything else Power BI told us. AnalysisServicesErrorCode in
        # particular is the only value that distinguishes one execution
        # failure from another, so it must survive into the message.
        for code, value in details.items():
            if code != "DetailsMessage":
                error_parts.append(f"{code}: {value}")

        if suggestions:
            error_parts.append(_SUGGESTIONS_HEADING)
            for suggestion in suggestions:
                error_parts.append(f"  - {suggestion}")

        return "\n".join(error_parts)

    def request(self, method: str, path: str, json_body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        url = f"{BASE_URL}{path}"
        try:
            r = requests.request(
                method,
                url,
                headers=self._get_auth_headers(),
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
            raise PowerBIAPIError(
                error_message,
                r.status_code,
                self._extract_error_code(error_data),
                self._extract_error_details(error_data),
            )

        # Parse successful response; some endpoints return 202/204 with no body
        if r.status_code == 204 or not r.content:
            return {}
        try:
            return r.json()
        except ValueError:
            raise ToolError(
                "Invalid response: The Power BI API returned a non-JSON response. This might indicate a service issue."
            )


# The cheapest possible query: it touches no table, so it proves the model is
# loaded and the caller may query it without going anywhere near a data source.
_MODEL_REACHABILITY_PROBE = 'EVALUATE ROW("__mcp_probe", 1)'


def _describe_datasource(entry: Dict[str, Any]) -> str:
    """One line naming a data source: its kind and the host it points at."""
    details = entry.get("connectionDetails")
    details = details if isinstance(details, dict) else {}

    # datasourceType is Power BI's own label ("Extension" for anything using a
    # connector), so connectionDetails.kind is the more informative of the two.
    kind = details.get("kind") or entry.get("datasourceType") or "unknown"

    host = details.get("server") or details.get("url")
    if not host:
        # Extension data sources hide the real target in a JSON-encoded string.
        path = details.get("path")
        if isinstance(path, str):
            try:
                parsed = json.loads(path)
            except ValueError:
                host = path
            else:
                host = parsed.get("host") if isinstance(parsed, dict) else path

    description = f"{kind} ({host})" if host else str(kind)
    gateway_id = entry.get("gatewayId")
    if gateway_id:
        description += f", reached through gateway {gateway_id}"
    return description


def _diagnose_query_execution_failure(client: PowerBIClient, workspace_id: str, dataset_id: str) -> list[str]:
    """Find out whether a failed query was the model's fault or the source's.

    Power BI reports every execution failure as the same opaque
    AnalysisServicesErrorCode, whether the underlying source was stopped, the
    gateway credentials had expired, or the query timed out. It will not say
    which. Rather than guess at a cause, this establishes the facts that are
    actually observable, by re-running the discriminating test by hand:

        trivial query succeeds, table query failed
            -> the model is loaded and queryable; the failure is entirely in
               fetching data from the source
        trivial query fails too
            -> the model itself is unavailable, so no per-table conclusion holds

    Every call here is best effort and additive. A diagnosis that cannot be
    completed simply contributes fewer lines; it never replaces or masks the
    error Power BI actually returned.
    """
    findings: list[str] = []

    try:
        probe = client.request(
            "POST",
            f"/groups/{workspace_id}/datasets/{dataset_id}/executeQueries",
            json_body={"queries": [{"query": _MODEL_REACHABILITY_PROBE}]},
        )
    except ToolError:
        return [
            "A query touching no table failed as well, so the semantic model itself is not "
            "answering: check that it is not still loading, and that its capacity is not paused"
        ]

    # A 200 can still carry an error at any of three nesting levels.
    if not isinstance(probe, dict) or probe.get("error") or not probe.get("results"):
        return []

    findings.append(
        f"The model answered {_MODEL_REACHABILITY_PROBE}, so it is loaded and you are allowed to "
        "query it: the failure is in retrieving the data, not in your query or your Power BI permissions"
    )

    # Naming the source turns generic advice into something the reader can act
    # on. It needs dataset-owner or workspace-admin rights, so it often fails.
    try:
        datasources = client.request("GET", f"/groups/{workspace_id}/datasets/{dataset_id}/datasources")
    except ToolError:
        datasources = None

    described = [
        _describe_datasource(entry) for entry in (datasources or {}).get("value", []) if isinstance(entry, dict)
    ]
    if described:
        findings.append("This dataset reads from: " + "; ".join(described))

    findings.append(
        "Power BI does not report why the source failed. The usual causes are the source being "
        "stopped or paused (Databricks clusters and SQL warehouses self-terminate when idle), "
        "expired or revoked gateway credentials, a query timeout, or the gateway's identity "
        "losing rights on the table"
    )

    # Naming the person to ask is the difference between an actionable error and
    # a dead end, since the caller usually cannot inspect the gateway themselves.
    owner = None
    try:
        metadata = client.request("GET", f"/groups/{workspace_id}/datasets/{dataset_id}")
        owner = metadata.get("configuredBy") if isinstance(metadata, dict) else None
    except ToolError:
        pass

    who = f"{owner}, who configured this dataset," if owner else "a workspace admin"
    findings.append(
        f"Checking this needs gateway rights the caller usually does not have: ask {who} "
        "to check the gateway data source status and that the source is running"
    )
    return findings


# DAX INFO.VIEW.* introspection queries. These run through the Power BI Execute
# Queries API.
_INFO_INTROSPECTION_QUERIES: Dict[str, str] = {
    "tables": "EVALUATE INFO.VIEW.TABLES()",
    "columns": "EVALUATE INFO.VIEW.COLUMNS()",
    "measures": "EVALUATE INFO.VIEW.MEASURES()",
    "relationships": "EVALUATE INFO.VIEW.RELATIONSHIPS()",
}


def _normalize_info_key(key: str) -> str:
    """Normalize an Execute Queries column key like '[Name]' or 'Table[Col]' to 'Name'/'Col'."""
    key = key.strip()
    if key.endswith("]") and "[" in key:
        key = key[key.index("[") + 1 : -1]
    return key


def _normalize_info_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {_normalize_info_key(k): v for k, v in row.items()}


class IntrospectionError(NamedTuple):
    """Why an INFO.VIEW introspection query failed, and what Power BI said."""

    reason: str
    message: str


def _classify_dax_error(message: str, status_code: int | None = None) -> str:
    """Classify a failed introspection query into a coarse reason code.

    When the HTTP status is known it is authoritative. Matching the response
    body alone misfires: Analysis Services error codes are long digit strings
    that can contain "403" by coincidence.
    """
    if status_code in (401, 403):
        return "tenant_setting_or_permission"

    lowered = message.lower()
    if "tenant" in lowered or "permission" in lowered or "denied" in lowered:
        return "tenant_setting_or_permission"
    if "info" in lowered and ("not supported" in lowered or "unknown" in lowered or "cannot find" in lowered):
        return "info_functions_unsupported"
    return "api_error"


def _run_info_query(
    client: PowerBIClient, workspace_id: str, dataset_id: str, dax: str
) -> Tuple[list[Dict[str, Any]] | None, IntrospectionError | None]:
    """Run a single INFO.VIEW DAX query. Returns (rows, error).

    rows is None on failure (error set), or a (possibly empty) list on success.
    The error carries Power BI's own message, not just a classification, so the
    caller can relay something actionable to the user.
    """
    body = {"queries": [{"query": dax}], "serializerSettings": {"includeNulls": True}}
    try:
        result = client.request(
            "POST",
            f"/groups/{workspace_id}/datasets/{dataset_id}/executeQueries",
            json_body=body,
        )
    except ToolError as exc:
        message = str(exc)
        status_code = getattr(exc, "status_code", None)
        reason = _classify_dax_error(message, status_code)
        return None, IntrospectionError(reason, message)

    if not isinstance(result, dict):
        return None, IntrospectionError("invalid_response", "The Power BI API returned an unexpected response shape.")

    # An executeQueries call can report failure at three nesting levels, all
    # inside an HTTP 200.
    if result.get("error"):
        message = json.dumps(result["error"], default=str)
        return None, IntrospectionError(_classify_dax_error(message), message)

    results = result.get("results", [])
    if not results:
        return [], None
    first = results[0]
    if first.get("error"):
        message = json.dumps(first["error"], default=str)
        return None, IntrospectionError(_classify_dax_error(message), message)

    tables = first.get("tables", [])
    if not tables:
        return [], None
    table0 = tables[0]
    if table0.get("error"):
        message = json.dumps(table0["error"], default=str)
        return None, IntrospectionError(_classify_dax_error(message), message)

    rows = [_normalize_info_row(r) for r in table0.get("rows", [])]
    return rows, None


def _get_semantic_model_via_dax_introspection(
    client: PowerBIClient, workspace_id: str, dataset_id: str
) -> Tuple[Dict[str, Any], IntrospectionError | None]:
    """Reconstruct semantic model structure via DAX INFO.VIEW.* queries.

    Returns (model_dict, error).  A None error means success.

    Uses only the Power BI Execute Queries API and returns model *structure* —
    tables, columns, measures (with their DAX expressions), and relationships.
    Note this is model structure, not a full serialized TMSL definition
    (partitions/M source, roles/RLS, and data sources are not included).
    """
    tables_rows, err = _run_info_query(client, workspace_id, dataset_id, _INFO_INTROSPECTION_QUERIES["tables"])
    if tables_rows is None:
        err = err or IntrospectionError("api_error", "The tables introspection query failed without a message.")
        logger.warning(
            "DAX introspection failed on tables query for dataset %s in workspace %s (%s): %s",
            dataset_id,
            workspace_id,
            err.reason,
            err.message,
        )
        return {}, err

    # Columns/measures/relationships are best-effort; an empty measures result is
    # legitimate (model may have none). A hard failure here is not fatal, but it
    # is recorded so the caller does not present a partial model as a complete one.
    columns_rows, cerr = _run_info_query(client, workspace_id, dataset_id, _INFO_INTROSPECTION_QUERIES["columns"])
    measures_rows, merr = _run_info_query(client, workspace_id, dataset_id, _INFO_INTROSPECTION_QUERIES["measures"])
    rel_rows, rerr = _run_info_query(client, workspace_id, dataset_id, _INFO_INTROSPECTION_QUERIES["relationships"])
    incomplete: Dict[str, Any] = {}
    for label, sub_err in (("columns", cerr), ("measures", merr), ("relationships", rerr)):
        if sub_err:
            logger.warning("DAX introspection %s query returned error (%s): %s", label, sub_err.reason, sub_err.message)
            incomplete[label] = {"reason": sub_err.reason, "message": sub_err.message}

    # Assemble tables keyed by name, attaching their columns and measures.
    tables_by_name: Dict[str, Dict[str, Any]] = {}
    order: list[str] = []

    def _ensure_table(name: str) -> Dict[str, Any]:
        entry = tables_by_name.get(name)
        if entry is None:
            entry = {"name": name, "columns": [], "measures": []}
            tables_by_name[name] = entry
            order.append(name)
        return entry

    for row in tables_rows:
        name = row.get("Name")
        if name is None:
            continue
        entry = _ensure_table(name)
        entry.update(row)  # carry IsHidden, IsPrivate, DataCategory, etc.

    for row in columns_rows or []:
        table_name = row.get("Table")
        if table_name is not None:
            _ensure_table(table_name).setdefault("columns", []).append(row)
    for row in measures_rows or []:
        table_name = row.get("Table")
        if table_name is not None:
            _ensure_table(table_name).setdefault("measures", []).append(row)

    model = {
        "introspectionMethod": "dax_info_view",
        "tables": [tables_by_name[n] for n in order],
        "relationships": rel_rows or [],
    }
    if incomplete:
        model["incomplete"] = incomplete

    return model, None


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
    except PowerBIAPIError as e:
        # Add context for workspace listing, but keep the error itself. This
        # used to search the message text for "401" and rewrap the result in a
        # plain ToolError, which threw away the status the layer above needs.
        if e.status_code != 401:
            raise
        raise e.with_message(
            f"{e}\n\n"
            f"Additional context for listing workspaces:\n"
            f"  - This operation requires a valid Power BI access token\n"
            f"  - The token must have 'Workspace.Read.All' or 'Workspace.ReadWrite.All' scope\n"
            f"  - Ensure the Authorization header contains a valid OAuth token"
        )


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
    raise ToolError(f"Workspace '{workspace_name}' not found. Available workspaces: {', '.join(available_names)}")


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
            f"Missing required parameter: {param_name}\nPlease provide a valid workspace/dataset ID (UUID format)."
        )

    # Basic UUID format validation (8-4-4-4-12 hexadecimal characters)
    uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
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
    """Retrieve dataset (semantic model) metadata and structure.

    Args:
        workspace_id: The unique identifier of the Power BI workspace (UUID format).
        dataset_id: The unique identifier of the dataset (UUID format).

    Returns:
        Dataset metadata, plus:
        - semanticModel: tables, columns, measures and relationships, or {} if
          the structure could not be read.
        - semanticModelSource: how the structure was obtained.
        - semanticModelError: present only on failure, with a 'reason' and the
          message Power BI returned. When this is present the model structure is
          unavailable, NOT empty - do not tell the user the dataset has no
          tables. Relay the message instead. A reason of
          'tenant_setting_or_permission' usually means either the caller lacks
          Build permission on the dataset, or a Power BI admin has not enabled
          the 'Dataset Execute Queries REST API' tenant setting.
        - semanticModel.incomplete: present when the tables were read but some
          of the columns/measures/relationships queries failed, so those parts
          of the returned structure are missing rather than genuinely absent.

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
        semantic_model, err = _get_semantic_model_via_dax_introspection(
            client,
            workspace_id.strip(),
            dataset_id.strip(),
        )
        if semantic_model:
            data["semanticModel"] = semantic_model
            data["semanticModelSource"] = "dax_info_introspection"
        elif err:
            data["semanticModelSource"] = f"dax_error:{err.reason}"
            data["semanticModelError"] = {"reason": err.reason, "message": err.message}
    except ToolError as exc:
        logger.warning("Failed to retrieve semantic model via DAX introspection: %s", exc)
        logger.debug("Semantic model retrieval ToolError details", exc_info=True)
        data["semanticModelSource"] = "dax_error:tool_error"
        data["semanticModelError"] = {"reason": "tool_error", "message": str(exc)}
    except Exception as exc:
        logger.warning("Unexpected error retrieving semantic model via DAX introspection: %s", exc)
        logger.debug("Unexpected semantic model retrieval error details", exc_info=True)
        data["semanticModelSource"] = "dax_error:unexpected"
        data["semanticModelError"] = {"reason": "unexpected", "message": str(exc)}

    return data


def _format_bytes(count: int) -> str:
    if count >= 1_048_576:
        return f"{count / 1_048_576:.1f} MB"
    if count >= 1024:
        return f"{count / 1024:.1f} KB"
    return f"{count} bytes"


def _count_result_rows(result: Any) -> int:
    """Total rows across every table in a query result."""
    if not isinstance(result, dict):
        return 0

    rows = 0
    for query_result in result.get("results", []):
        if not isinstance(query_result, dict):
            continue
        for table in query_result.get("tables", []):
            if not isinstance(table, dict):
                continue
            table_rows = table.get("rows")
            if isinstance(table_rows, list):
                rows += len(table_rows)
    return rows


def _check_result_size(result: Any, dax_query: str) -> None:
    """Withhold a result too large for the caller to do anything useful with.

    Returning it is worse than failing: a model that receives 600 KB of rows
    has spent its context on data it did not ask for in that quantity, and the
    request that prompted the query may no longer fit alongside the answer.

    Refusing outright, rather than truncating, is deliberate. Silently handing
    back the first N rows of an un-aggregated query invites the caller to sum
    them and report a total that is wrong - a failure that looks like an
    answer. An error the caller must act on cannot be mistaken for one.
    """
    # json.dumps, not len(rows): the caller's cost is the serialised payload,
    # and a few wide rows can outweigh many narrow ones.
    size = len(json.dumps(result, default=str).encode("utf-8"))
    if size <= MAX_RESULT_BYTES:
        return

    # Deliberately no column list. The caller has usually already read the
    # schema via get_dataset_details, and can go back for it if not - repeating
    # it here spends the context this error exists to protect.
    rows = _count_result_rows(result)

    parts = [
        "DAX Query Result Too Large",
        "",
        f"The query succeeded but returned {rows:,} rows ({_format_bytes(size)}), over the "
        f"{_format_bytes(MAX_RESULT_BYTES)} limit for a single result. It has been withheld "
        f"rather than returned, because a result this size would crowd out the context it was "
        f"meant to inform.",
    ]

    if rows >= _POWERBI_MAX_ROWS:
        parts.append(
            f"\nPower BI caps a single query at {_POWERBI_MAX_ROWS:,} rows, so this result was "
            f"already truncated - the real total is higher, and unknown."
        )

    parts.extend(
        [
            f"\nQuery:\n{dax_query}",
            "\nSuggestions:",
            "  - If you want a total or a breakdown, aggregate in DAX rather than summing rows "
            "yourself: EVALUATE SUMMARIZECOLUMNS('Table'[Category], \"Total\", SUM('Table'[Amount]))",
            "  - If you only need to see what the data looks like, sample it: EVALUATE TOPN(50, 'Table')",
            "  - If you need many rows but few fields, narrow the columns with SELECTCOLUMNS",
            "  - If you need a subset, filter it: EVALUATE CALCULATETABLE('Table', 'Table'[Year] = 2026)",
            "  - To find out how big something is before fetching it: EVALUATE ROW(\"n\", COUNTROWS('Table'))",
        ]
    )
    raise ToolError("\n".join(parts))


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
        suggestions.extend(
            [
                "Check DAX syntax - ensure EVALUATE is used for table expressions",
                "Verify parentheses and brackets are properly matched",
                "Check function parameter count and types",
                "DAX is case-insensitive for keywords but case-sensitive for object names",
            ]
        )

    # Table reference issues
    if "table" in error_lower and (
        "not found" in error_lower or "doesn't exist" in error_lower or "cannot find" in error_lower
    ):
        suggestions.extend(
            [
                "Verify the table name exists in the dataset",
                "Check table name spelling (table names are case-sensitive)",
                "Use single quotes for table names with spaces: 'Sales Data'",
                "If the table is from another model, check the relationship",
            ]
        )

    # Column reference issues
    if "column" in error_lower and (
        "not found" in error_lower or "doesn't exist" in error_lower or "cannot find" in error_lower
    ):
        suggestions.extend(
            [
                "Verify the column name exists in the specified table",
                "Use TableName[ColumnName] syntax for column references",
                "Check column name spelling (column names are case-sensitive)",
                "Ensure you're referencing the correct table for this column",
            ]
        )

    # Query result limitations
    if "more than" in error_lower or "limit" in error_lower or "exceed" in error_lower:
        suggestions.extend(
            [
                "The query exceeded Power BI limits (max 100,000 rows or 1,000,000 values)",
                "Use TOPN() to limit the number of rows returned",
                "Add filters to reduce the result set size",
                "Consider aggregating data instead of returning raw rows",
            ]
        )

    # Function errors
    if "function" in error_lower:
        suggestions.extend(
            [
                "Verify the function name is spelled correctly",
                "Check that the function exists in DAX (some Excel functions don't exist in DAX)",
                "Verify the number and types of function arguments",
                "Some functions require specific evaluation contexts",
            ]
        )

    # Relationship/filter context errors
    if "relationship" in error_lower or "filter" in error_lower or "context" in error_lower:
        suggestions.extend(
            [
                "Check if required relationships exist between tables",
                "Verify filter context is set up correctly",
                "Consider using CALCULATE to modify filter context",
                "Check for circular dependencies in relationships",
            ]
        )

    # Dataset permission/configuration errors
    if "permission" in error_lower or "denied" in error_lower:
        suggestions.extend(
            [
                "Verify you have read and build permissions on the dataset",
                "Check if Row-Level Security (RLS) is blocking access",
                "Ensure the dataset is published and accessible",
            ]
        )

    # Tenant setting errors
    if "tenant" in error_lower or "admin" in error_lower:
        suggestions.append(
            "The 'Dataset Execute Queries REST API' tenant setting must be enabled "
            "(Admin Portal > Tenant settings > Integration settings)"
        )

    # No specific error detected, provide general suggestions
    if not suggestions:
        suggestions.extend(
            [
                "Verify the DAX query syntax is correct",
                "Check all table and column references exist in the dataset",
                "Ensure the query doesn't exceed Power BI limitations",
                "Try a simpler query first to isolate the issue (e.g., EVALUATE TableName)",
            ]
        )

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

    Prefer aggregating or sampling over listing every row. A result over 50 KB
    is rejected rather than returned, so an un-aggregated EVALUATE against a
    large table will fail - use SUMMARIZECOLUMNS to aggregate, TOPN to sample,
    or COUNTROWS first if you do not know how big the table is.

    Common errors:
    - 400 Bad Request: DAX syntax errors, invalid table/column references
    - 403 Forbidden: Missing permissions or tenant setting not enabled
    - Result too large: the query succeeded but returned more than 50 KB
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
        try:
            result = client.request(
                "POST", f"/groups/{workspace_id.strip()}/datasets/{dataset_id.strip()}/executeQueries", json_body=body
            )
        except PowerBIAPIError as exc:
            # The model ran the query and it failed, with no line/column
            # reference to blame the DAX. That leaves the data source, and
            # Power BI will not say more, so go and establish what we can.
            if exc.error_code == "DatasetExecuteQueriesError" and not _looks_like_dax_binding_error(
                exc.details.get("DetailsMessage", "")
            ):
                findings = _diagnose_query_execution_failure(client, workspace_id.strip(), dataset_id.strip())
                if findings:
                    # The suggestions in the raised message are hypotheses the
                    # diagnosis has now settled, so replace rather than append -
                    # printing a guess next to the measurement helps nobody.
                    # _SUGGESTIONS_HEADING is emitted by _build_error_message
                    # alone, so splitting on it cannot cut into Power BI's text.
                    stated, _, _ = str(exc).partition(_SUGGESTIONS_HEADING)
                    raise exc.with_message(
                        stated.rstrip() + "\n\nDiagnosis:\n" + "\n".join(f"  - {f}" for f in findings)
                    ) from exc
            raise

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

        # Last, so that a genuine query error is reported as itself rather than
        # as a size problem.
        _check_result_size(result, dax_query)
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
