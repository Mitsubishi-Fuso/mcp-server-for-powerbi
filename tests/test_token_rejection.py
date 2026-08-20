"""is_token_rejection() against every case measured on the live API.

Power BI answers 403 when the token is the problem and 401 when it is not,
which is the opposite way round to the convention, so the predicate reads
x-powerbi-error-info and treats the status only as a fallback.
"""

import pytest

from mcp_for_powerbi.server import PowerBIAPIError

CHALLENGE = 'Bearer authorization_uri="https://login.windows.net/x", error="insufficient_claims", claims="eyJ..."'

CASES = [
    # Measured against POST .../executeQueries.
    ("no Authorization header", 403, "Unknown", None, None, True),
    ("malformed token", 403, "Unknown", "InvalidToken", None, True),
    ("well-formed but invalid JWT", 403, "Unknown", "TokenExpired", None, True),
    ("valid token, no workspace access", 401, "Unknown", "GroupNotAccessible", None, False),
    ("valid token, no Build permission", 404, "PowerBIEntityNotFound", None, None, False),
    # Other paths that must keep working.
    ("DAX execution failure", 400, "DatasetExecuteQueriesError", None, None, False),
    ("rate limited", 429, "Unknown", None, None, False),
    ("conditional access challenge", 401, "Unknown", None, CHALLENGE, True),
    ("legacy body-only TokenExpired", 403, "TokenExpired", None, None, True),
]


@pytest.mark.parametrize(
    ("status", "code", "info", "www", "expected"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_predicate(status, code, info, www, expected):
    assert PowerBIAPIError("msg", status, code, None, info, www).is_token_rejection() is expected


def test_header_beats_status():
    """A 401 that names a permission problem is not a token problem."""
    assert PowerBIAPIError("m", 401, "Unknown", None, "GroupNotAccessible").is_token_rejection() is False
    assert PowerBIAPIError("m", 403, "Unknown", None, "GroupNotAccessible").is_token_rejection() is False
