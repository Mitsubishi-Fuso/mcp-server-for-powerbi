"""The ceiling on what execute_dax_query will hand back.

A query without a TOP or an aggregation can return more than the caller's
context window holds, so an oversized result is withheld and described.
"""

import json

from typing import Any, Callable

import pytest
from fastmcp.exceptions import ToolError

import mcp_for_powerbi.server as server
from mcp_for_powerbi.server import MAX_RESULT_BYTES, _count_result_rows, _format_bytes, execute_dax_query

WORKSPACE = "11111111-2222-3333-4444-555555555555"
DATASET = "66666666-7777-8888-9999-000000000000"
QUERY = "EVALUATE 'Sales'"

# The tool is registered with FastMCP; .fn is the undecorated function.
tool_fn: Callable[..., Any] = execute_dax_query.fn


def result_of(rows, columns=("'Sales'[OrderDate]", "'Sales'[Amount]")):
    return {"results": [{"tables": [{"rows": [{c: f"value-{i}" for c in columns} for i in range(rows)]}]}]}


def size_of(result):
    return len(json.dumps(result).encode())


@pytest.fixture
def run(monkeypatch):
    """Execute the tool against a client that returns a canned result."""

    def go(result):
        class FakeClient:
            def request(self, method, path, json_body=None):
                return result

        monkeypatch.setattr(server, "PowerBIClient", FakeClient)
        return tool_fn(None, WORKSPACE, DATASET, QUERY)

    return go


@pytest.mark.parametrize(
    ("count", "rendered"),
    [(512, "512 bytes"), (51_200, "50.0 KB"), (2_097_152, "2.0 MB")],
)
def test_format_bytes(count, rendered):
    assert _format_bytes(count) == rendered


def test_counts_rows_across_every_table():
    assert _count_result_rows({"results": [{"tables": [{"rows": [{"a": 1}]}, {"rows": [{"a": 1}, {"a": 2}]}]}]}) == 3


@pytest.mark.parametrize("malformed", ["nope", {"results": []}, {}, None])
def test_row_count_tolerates_a_shape_it_cannot_read(malformed):
    assert _count_result_rows(malformed) == 0


def test_a_small_result_passes_through_untouched(run):
    small = result_of(5)
    assert size_of(small) < MAX_RESULT_BYTES
    assert run(small) == small


def test_the_boundary(run):
    """Grow the result until it crosses, so the limit is exercised not assumed."""
    rows = 100
    while size_of(result_of(rows)) <= MAX_RESULT_BYTES:
        rows += 100

    under = result_of(rows - 100)
    assert run(under) == under

    with pytest.raises(ToolError):
        run(result_of(rows))


class TestTheMessage:
    @pytest.fixture
    def message(self, run):
        with pytest.raises(ToolError) as exc:
            run(result_of(4000))
        return str(exc.value)

    def test_says_how_much_came_back(self, message):
        assert "4,000 rows" in message
        assert "KB)" in message or "MB)" in message

    def test_states_the_limit(self, message):
        assert f"{_format_bytes(MAX_RESULT_BYTES)} limit" in message

    def test_echoes_the_query(self, message):
        assert QUERY in message

    def test_suggests_a_way_out(self, message):
        for hint in ("SUMMARIZECOLUMNS", "TOPN", "COUNTROWS"):
            assert hint in message

    def test_does_not_list_the_columns(self, message):
        """The caller has usually read the schema already; repeating it here
        spends the context this error exists to protect."""
        assert "'Sales'[Amount]" not in message

    def test_does_not_leak_the_data(self, message):
        assert "value-3999" not in message

    def test_claims_no_truncation_below_power_bis_cap(self, message):
        assert "already truncated" not in message


def test_at_power_bis_own_row_cap(run):
    with pytest.raises(ToolError) as exc:
        run({"results": [{"tables": [{"rows": [{"'S'[a]": "x" * 20} for _ in range(100_000)]}]}]})
    assert "already truncated" in str(exc.value)
    assert "100,000 rows" in str(exc.value)


def test_a_query_error_wins_over_a_size_complaint(run):
    """Reporting the size of a result that also failed would bury the failure."""
    with pytest.raises(ToolError) as exc:
        run(
            {
                "error": {"code": "DatasetExecuteQueriesError", "message": "boom"},
                "results": [{"tables": [{"rows": [{"a": "x" * 100} for _ in range(2000)]}]}],
            }
        )
    assert "DAX Query Error" in str(exc.value)
    assert "Too Large" not in str(exc.value)


def test_few_but_wide_rows_are_rejected_too(run):
    """The limit is on bytes, not rows."""
    wide = {"results": [{"tables": [{"rows": [{f"'T'[c{c}]": "x" * 500 for c in range(40)} for _ in range(5)]}]}]}
    with pytest.raises(ToolError) as exc:
        run(wide)
    assert "5 rows" in str(exc.value)
