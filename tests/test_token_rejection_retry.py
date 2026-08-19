"""What happens when Power BI rejects the token a tool call was made with.

In both modes the rejected token is one this server minted, so a stale one
should cost a retry rather than a re-authentication: OBO drops the cached
exchange, custody expires the token it is holding. Only a rejection that
survives the retry means the user has to sign in again.
"""

import asyncio
import json
import types

import pytest

from cryptography.fernet import Fernet

from mcp_for_powerbi.auth_middleware import EntraIDPayload
from mcp_for_powerbi.server import PowerBIAPIError, PowerBIClient
from mcp_for_powerbi.token_store import Session

CUSTODY_ENV = {
    "AUTH_MODE": "custody",
    "ENTRA_CLIENT_ID": "server-app",
    "ENTRA_CLIENT_SECRET": "server-secret",
    "PUBLIC_URL": "https://powerbi-mcp.example.com",
    "CUSTODY_REDIRECT_URIS": "https://librechat.example.com/cb",
    "SESSION_ENCRYPTION_KEY": Fernet.generate_key().decode(),
}

WORKSPACES = {"value": [{"id": "ws-1", "name": "Sales"}]}


def rejection() -> PowerBIAPIError:
    """What PowerBIClient.request raises when Power BI refuses the token."""
    return PowerBIAPIError("Power BI rejected the token", 403, "Unknown", None, "TokenExpired", None)


def ordinary_failure() -> PowerBIAPIError:
    """A failure the model can act on, which must never become a 401."""
    return PowerBIAPIError("Dataset not found", 404, "PowerBIEntityNotFound")


class StubRequest:
    """Enough of a Starlette request for mcp_handler."""

    def __init__(self, body):
        self._body = body
        self.state = types.SimpleNamespace()
        self.state.authenticated = EntraIDPayload({"oid": "user-1", "preferred_username": "tester@example.com"})
        self.state.bearer_token = "caller-token"
        self.headers = {"authorization": "Bearer caller-token"}
        self.base_url = "https://powerbi-mcp.example.com/"

    async def json(self):
        return self._body


def call_tool(name="powerbi_list_workspaces", arguments=None):
    return StubRequest(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}
    )


@pytest.fixture
def scripted_request(monkeypatch):
    """Drive PowerBIClient.request from a list of outcomes, recording the calls."""
    calls = []

    def install(outcomes):
        def fake_request(self, method, path, json_body=None):
            calls.append((method, path))
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        monkeypatch.setattr(PowerBIClient, "request", fake_request)
        return calls

    return install


@pytest.fixture
def obo_server(load_server_http, monkeypatch):
    """server_http in OBO mode, with the cache invalidation recorded not performed."""
    module = load_server_http(AUTH_MODE="obo", ENTRA_CLIENT_ID="app-id", ENTRA_CLIENT_SECRET="app-secret")
    invalidations = []
    monkeypatch.setattr(module, "invalidate_obo_token", lambda *args: invalidations.append(args))
    return module, invalidations


def body_of(response):
    return json.loads(response.body)


def handle(module, request):
    """Run the handler to completion; pytest has no async support built in."""
    return asyncio.run(module.mcp_handler(request))


def test_obo_retries_once_and_succeeds(obo_server, scripted_request):
    module, invalidations = obo_server
    calls = scripted_request([rejection(), WORKSPACES])

    response = handle(module, call_tool())

    assert response.status_code == 200
    assert len(calls) == 2, "the call should have been retried after the token was dropped"
    assert len(invalidations) == 1, "the cached token should have been dropped exactly once"
    payload = body_of(response)
    assert "isError" not in payload["result"]
    assert "Sales" in payload["result"]["content"][0]["text"]


def test_obo_escalates_to_401_when_the_retry_also_fails(obo_server, scripted_request):
    module, invalidations = obo_server
    calls = scripted_request([rejection(), rejection()])

    response = handle(module, call_tool())

    assert response.status_code == 401
    assert len(calls) == 2, "exactly one retry, not a loop"
    assert len(invalidations) == 1
    assert "invalid_token" in response.headers["www-authenticate"]


def test_ordinary_failure_is_not_retried_and_stays_a_tool_error(obo_server, scripted_request):
    module, invalidations = obo_server
    calls = scripted_request([ordinary_failure()])

    response = handle(module, call_tool())

    assert response.status_code == 200
    assert len(calls) == 1, "a 404 is not a token problem and must not be retried"
    assert invalidations == []
    payload = body_of(response)
    assert payload["result"]["isError"] is True
    assert "Dataset not found" in payload["result"]["content"][0]["text"]


def test_custody_expires_its_cached_token_and_retries(load_server_http, scripted_request, monkeypatch):
    """Custody holds the token itself, so a rejection means renew, not re-auth."""
    module = load_server_http(**CUSTODY_ENV)
    calls = scripted_request([rejection(), WORKSPACES])

    session = Session("oid-1", "tid-1", "user@example.com", "refresh-value", "stale-token", 1e12)
    request = call_tool()
    request.state.custody_session_key = "session-key"
    request.state.custody_session = session

    response = handle(module, request)

    assert response.status_code == 200
    assert len(calls) == 2
    assert session.access_token_expires_at == 0.0, "the stale token should have been expired, not kept"


def test_401_body_carries_what_power_bi_said(obo_server, scripted_request):
    module, _ = obo_server
    scripted_request([rejection(), rejection()])

    response = handle(module, call_tool())
    payload = body_of(response)

    assert payload["error"]["data"]["powerBiStatus"] == 403
    assert payload["id"] == 7
    assert "resource_metadata=" in response.headers["www-authenticate"], "the client needs to be told where to go"
