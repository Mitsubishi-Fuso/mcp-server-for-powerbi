"""_log_tool_error: a summary at INFO, the whole thing at DEBUG.

Tool errors are written for a model that has to act on them, so they carry
suggestions and run to dozens of lines. That is the wrong size for a log line.
"""

import logging

import pytest
from fastmcp.exceptions import ToolError

LONG = (
    "DAX Query Result Too Large\n\n"
    "The query succeeded but returned 1,000 rows (2.6 MB), over the 50.0 KB limit.\n\n"
    "Suggestions:\n  - aggregate\n  - sample\n"
)


@pytest.fixture
def emit(load_server_http):
    module = load_server_http(AUTH_MODE="obo", ENTRA_CLIENT_ID="a", ENTRA_CLIENT_SECRET="b")

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.records.append(record)

    def run(message, level=logging.DEBUG):
        logger = logging.getLogger("mcp_for_powerbi.server_http")
        handler = Capture()
        logger.addHandler(handler)
        previous = logger.level
        logger.setLevel(level)
        try:
            module._log_tool_error("execute_dax_query", ToolError(message))
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous)
        return handler.records

    return run


def at(records, level):
    return [r for r in records if r.levelno == level]


def test_long_message_is_split(emit):
    records = emit(LONG)
    info = at(records, logging.INFO)
    debug = at(records, logging.DEBUG)

    assert len(info) == 1
    assert info[0].getMessage() == "Tool execute_dax_query returned an error: DAX Query Result Too Large"
    assert "\n" not in info[0].getMessage()
    assert len(debug) == 1
    assert "Suggestions:" in debug[0].getMessage()
    assert "execute_dax_query" in debug[0].getMessage()


def test_single_line_message_is_not_repeated(emit):
    records = emit("Dataset not found")
    assert len(at(records, logging.INFO)) == 1
    assert at(records, logging.INFO)[0].getMessage().endswith("Dataset not found")
    assert at(records, logging.DEBUG) == [], "nothing to add, so nothing should be logged twice"


def test_detail_costs_nothing_when_debug_is_off(emit):
    records = emit(LONG, level=logging.INFO)
    assert len(records) == 1
    assert records[0].levelno == logging.INFO


def test_formatting_is_left_to_the_handler(emit):
    """%s args rather than f-strings, so a suppressed record is never rendered."""
    record = emit(LONG)[0]
    assert record.args is not None
    assert "%s" in record.msg
