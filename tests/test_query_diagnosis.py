"""Diagnosing a failed DAX query, with the bodies the live API actually returned.

Analysis Services error 3242524690 (0xC1450012) is a generic execution failure:
a stopped cluster, expired gateway credentials, a timeout and a source-side
permission loss all arrive as the same code. The diagnosis therefore reports
what it can establish and names who to ask, rather than picking a cause.
"""

from typing import Any, Callable

import pytest

import mcp_for_powerbi.server as server
from mcp_for_powerbi.server import (
    PowerBIAPIError,
    PowerBIClient,
    _describe_datasource,
    _diagnose_query_execution_failure,
    execute_dax_query,
)

WORKSPACE = "11111111-2222-3333-4444-555555555555"
DATASET = "66666666-7777-8888-9999-000000000000"
GATEWAY = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
HOST = "adb-000000000000000.0.azuredatabricks.net"

EXEC_FAILURE_BODY = {
    "error": {
        "code": "DatasetExecuteQueriesError",
        "pbi.error": {
            "code": "DatasetExecuteQueriesError",
            "parameters": {},
            "details": [
                {"code": "DetailsMessage", "detail": {"type": 1, "value": "Failed to execute the DAX query."}},
                {"code": "AnalysisServicesErrorCode", "detail": {"type": 1, "value": "3242524690"}},
            ],
        },
    }
}

BINDING_BODY = {
    "error": {
        "code": "DatasetExecuteQueriesError",
        "pbi.error": {
            "code": "DatasetExecuteQueriesError",
            "details": [
                {
                    "code": "DetailsMessage",
                    "detail": {"type": 1, "value": "Query (1, 15) The table 'Nope' cannot be found."},
                }
            ],
        },
    }
}

DATASOURCES = {
    "value": [
        {
            "datasourceType": "Extension",
            "gatewayId": GATEWAY,
            "datasourceId": "aaaa-bbbb",
            "connectionDetails": {
                "path": f'{{"host":"{HOST}","httpPath":"sql/protocolv1/o/000000000000000/0000-000000-example"}}',
                "kind": "Databricks",
            },
        }
    ]
}

METADATA = {"name": "SalesModel", "configuredBy": "owner@example.net"}
PROBE_OK = {"results": [{"tables": [{"rows": [{"[__mcp_probe]": 1}]}]}]}

# The tool is registered with FastMCP; .fn is the undecorated function.
tool_fn: Callable[..., Any] = execute_dax_query.fn


def error_from(body):
    """The PowerBIAPIError that request() would raise for this body."""
    blank = PowerBIClient.__new__(PowerBIClient)
    path = f"/groups/{WORKSPACE}/datasets/{DATASET}/executeQueries"
    return PowerBIAPIError(
        blank._build_error_message(400, body, path),
        400,
        "DatasetExecuteQueriesError",
        blank._extract_error_details(body),
    )


def client_returning(responses):
    """A PowerBIClient whose request() is driven by a path -> response table."""
    client = PowerBIClient.__new__(PowerBIClient)

    def request(method, path, json_body=None):
        for key, value in responses.items():
            probing = "__mcp_probe" in str(json_body)
            if key in path and (json_body is None or probing or key != "executeQueries"):
                if isinstance(value, Exception):
                    raise value
                return value
        raise AssertionError(f"unexpected call {method} {path}")

    client.request = request
    return client


def test_describe_datasource_names_what_matters():
    described = _describe_datasource(DATASOURCES["value"][0])
    assert "Databricks" in described
    assert HOST in described
    assert GATEWAY in described


def test_full_visibility():
    findings = _diagnose_query_execution_failure(
        client_returning({"executeQueries": PROBE_OK, "/datasources": DATASOURCES, f"/datasets/{DATASET}": METADATA}),
        WORKSPACE,
        DATASET,
    )
    assert any("loaded and you are allowed" in f for f in findings)
    assert any(HOST in f for f in findings)
    assert any("owner@example.net" in f for f in findings)


def test_asserts_no_single_cause():
    """3242524690 does not identify one; claiming it does sends people looking
    in the wrong place."""
    findings = _diagnose_query_execution_failure(
        client_returning({"executeQueries": PROBE_OK, "/datasources": DATASOURCES, f"/datasets/{DATASET}": METADATA}),
        WORKSPACE,
        DATASET,
    )
    assert not any("the cluster is not available" in f.lower() for f in findings)


def test_reduced_visibility_says_less_rather_than_guessing():
    denied = PowerBIAPIError("no", 401, "Unknown")
    findings = _diagnose_query_execution_failure(
        client_returning({"executeQueries": PROBE_OK, "/datasources": denied, f"/datasets/{DATASET}": denied}),
        WORKSPACE,
        DATASET,
    )
    assert any("loaded and you are allowed" in f for f in findings)
    assert any("a workspace admin" in f for f in findings)
    assert not any("reads from" in f for f in findings), "no source was readable, so none should be named"


def test_model_itself_unavailable():
    """When the probe fails too, the source is not what to blame."""
    findings = _diagnose_query_execution_failure(
        client_returning({"executeQueries": error_from(EXEC_FAILURE_BODY)}), WORKSPACE, DATASET
    )
    assert any("semantic model itself" in f for f in findings)
    assert not any("gateway credentials" in f for f in findings)


class TestEndToEnd:
    @pytest.fixture
    def attempts(self, monkeypatch):
        counter = {"n": 0}
        failure = error_from(EXEC_FAILURE_BODY)

        class FakeClient:
            def request(self, method, path, json_body=None):
                query = (json_body or {}).get("queries", [{}])[0].get("query", "")
                if "executeQueries" in path and "__mcp_probe" not in query:
                    counter["n"] += 1
                    raise failure
                if "executeQueries" in path:
                    return PROBE_OK
                if "/datasources" in path:
                    return DATASOURCES
                return METADATA

        monkeypatch.setattr(server, "PowerBIClient", FakeClient)
        return counter

    def test_appends_a_diagnosis_without_losing_the_original(self, attempts):
        with pytest.raises(PowerBIAPIError) as exc:
            tool_fn(None, WORKSPACE, DATASET, "EVALUATE TOPN(10, 'Sales')")

        assert "3242524690" in str(exc.value), "the original message must survive"
        assert "Diagnosis:" in str(exc.value)
        assert exc.value.status_code == 400
        assert exc.value.is_token_rejection() is False
        assert attempts["n"] == 1, "the failing query should not be re-run"


def test_a_binding_error_does_not_trigger_diagnosis(monkeypatch):
    """The query is at fault, so probing the model would only cost a round trip."""
    probes = {"n": 0}

    class BindingClient:
        def request(self, method, path, json_body=None):
            if "__mcp_probe" in (json_body or {}).get("queries", [{}])[0].get("query", ""):
                probes["n"] += 1
                return PROBE_OK
            raise error_from(BINDING_BODY)

    monkeypatch.setattr(server, "PowerBIClient", BindingClient)

    with pytest.raises(PowerBIAPIError) as exc:
        tool_fn(None, WORKSPACE, DATASET, "EVALUATE TOPN(10, 'Nope')")

    assert "Diagnosis:" not in str(exc.value)
    assert probes["n"] == 0
