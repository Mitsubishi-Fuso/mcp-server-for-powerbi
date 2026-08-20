"""pbi.error extraction, and telling a binding error from an execution failure.

Power BI leaves error.message unset for several error classes - notably
DatasetExecuteQueriesError - and puts the only useful text under
error["pbi.error"]["details"].
"""

import pytest

from mcp_for_powerbi.server import PowerBIClient, _looks_like_dax_binding_error


@pytest.fixture
def client():
    return PowerBIClient.__new__(PowerBIClient)


def body(code, *pairs):
    return {
        "error": {
            "code": code,
            "pbi.error": {
                "code": code,
                "details": [{"code": c, "detail": {"type": 1, "value": v}} for c, v in pairs],
            },
        }
    }


EXEC = body(
    "DatasetExecuteQueriesError",
    ("DetailsMessage", "Failed to execute the DAX query."),
    ("AnalysisServicesErrorCode", "3242524690"),
)
BIND = body("DatasetExecuteQueriesError", ("DetailsMessage", "Query (1, 15) The table 'Nope' cannot be found."))
PERM = body(
    "PowerBIEntityNotFound",
    ("DetailsMessage", "You cannot query the dataset ... or you do not have the required permissions."),
)

QUERY_PATH = "/groups/w/datasets/d/executeQueries"


def test_reads_both_detail_pairs(client):
    assert client._extract_error_details(EXEC) == {
        "DetailsMessage": "Failed to execute the DAX query.",
        "AnalysisServicesErrorCode": "3242524690",
    }


@pytest.mark.parametrize("malformed", ["boom", {"error": {"code": "X"}}, {}, None])
def test_tolerates_a_body_it_cannot_read(client, malformed):
    assert client._extract_error_details(malformed) == {}


def test_reads_a_legacy_inline_detail_string(client):
    assert client._extract_error_details({"error": {"pbi.error": {"details": [{"code": "A", "detail": "raw"}]}}}) == {
        "A": "raw"
    }


@pytest.mark.parametrize(
    ("text", "is_binding"),
    [
        ("Query (1, 15) The table 'Nope' cannot be found.", True),
        ("Query (12,  3) something", True),
        ("Failed to execute the DAX query.", False),
        ("", False),
    ],
)
def test_binding_discriminator(text, is_binding):
    assert bool(_looks_like_dax_binding_error(text)) is is_binding


def test_execution_failure_message(client):
    message = client._build_error_message(400, EXEC, QUERY_PATH)
    assert "Message: Failed to execute the DAX query." in message
    assert "AnalysisServicesErrorCode: 3242524690" in message
    assert "{'error'" not in message, "the raw body must not be dumped"
    assert "check syntax and table/column references" not in message, "nothing here points at the query"
    assert "pushdown to the underlying source" in message


def test_binding_failure_message(client):
    message = client._build_error_message(400, BIND, QUERY_PATH)
    assert "check syntax and table/column references" in message
    assert "gateway is online" not in message, "the query is at fault, not the source"


def test_permission_failure_relays_power_bis_own_prose(client):
    assert "you do not have the required permissions" in client._build_error_message(404, PERM, QUERY_PATH)


def test_unrelated_paths_still_render(client):
    rate_limited = client._build_error_message(
        429, {"error": {"code": "TooManyRequests", "message": "slow down"}}, "/groups"
    )
    assert "Message: slow down" in rate_limited
    assert "Rate limit exceeded" in rate_limited
    assert "Message: not json at all" in client._build_error_message(500, "not json at all", "/groups")


def test_empty_body_reports_the_header_instead(client):
    """Every auth failure has an empty body, so the header is all there is.

    request() falls back to r.text when the body will not parse as JSON, so an
    empty response arrives here as "", not as an empty dict.
    """
    message = client._build_error_message(403, "", QUERY_PATH, "TokenExpired")
    assert "TokenExpired (no response body)" in message
    assert client._build_error_message(403, "", QUERY_PATH).count("(no response body)") == 1
