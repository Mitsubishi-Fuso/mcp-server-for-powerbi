"""What each mode exposes, and who it lets in.

The route table and the discovery documents differ by mode, because under
custody this server issues the tokens and otherwise Entra does.
"""

import json
from urllib.parse import urlencode

import pytest
from cryptography.fernet import Fernet
from starlette.requests import Request

from mcp_for_powerbi.token_store import Session

TENANT = "11111111-2222-3333-4444-555555555555"
PUBLIC_URL = "https://powerbi-mcp.example.com"
CLIENT_REDIRECT = "https://librechat.example.com/cb"

CUSTODY_ENV = {
    "AUTH_MODE": "custody",
    "ENTRA_CLIENT_ID": "server-app",
    "ENTRA_CLIENT_SECRET": "server-secret",
    "PUBLIC_URL": PUBLIC_URL,
    "CUSTODY_REDIRECT_URIS": CLIENT_REDIRECT,
    "SESSION_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "TENANT_ID": TENANT,
}

OBO_ENV = {
    "AUTH_MODE": "obo",
    "ENTRA_CLIENT_ID": "server-app",
    "ENTRA_CLIENT_SECRET": "server-secret",
    "TENANT_ID": TENANT,
}


def run(coro):
    import asyncio

    return asyncio.run(coro)


def get(path, headers=None, **params):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "query_string": urlencode(params).encode(),
            "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
            "server": ("powerbi-mcp.example.com", 443),
            "scheme": "https",
        }
    )


def body_of(response):
    return json.loads(response.body)


def paths(app):
    return {getattr(route, "path", None) for route in app.routes}


# ── the route table ───────────────────────────────────────────────────────
def test_custody_exposes_an_authorization_server(load_server_http):
    module = load_server_http(**CUSTODY_ENV)
    exposed = paths(module.create_app())
    for path in ("/mcp", "/authorize", "/callback", "/token", "/revoke"):
        assert path in exposed
    assert "/.well-known/oauth-authorization-server" in exposed
    assert "/.well-known/oauth-protected-resource" in exposed


def test_obo_exposes_no_authorization_server(load_server_http):
    """Entra is the issuer, so advertising these here would be a lie."""
    exposed = paths(load_server_http(**OBO_ENV).create_app())
    assert "/authorize" not in exposed
    assert "/token" not in exposed
    assert "/callback" not in exposed
    assert "/.well-known/oauth-authorization-server" not in exposed
    # A resource server still says who issues its tokens.
    assert "/.well-known/oauth-protected-resource" in exposed


# ── discovery ─────────────────────────────────────────────────────────────
def test_custody_points_clients_at_itself(load_server_http):
    module = load_server_http(**CUSTODY_ENV)
    document = body_of(run(module.protected_resource_metadata(get("/.well-known/oauth-protected-resource"))))
    assert document["authorization_servers"] == [PUBLIC_URL]
    assert document["resource"] == f"{PUBLIC_URL}/mcp"
    assert document["bearer_methods_supported"] == ["header"]


def test_obo_points_clients_at_entra(load_server_http):
    module = load_server_http(**OBO_ENV)
    document = body_of(run(module.protected_resource_metadata(get("/.well-known/oauth-protected-resource"))))
    assert document["authorization_servers"] == [f"https://login.microsoftonline.com/{TENANT}/v2.0"]


def test_the_authorization_server_document_describes_what_is_implemented(load_server_http):
    module = load_server_http(**CUSTODY_ENV)
    document = body_of(run(module.authorization_server_metadata(get("/.well-known/oauth-authorization-server"))))
    assert document["issuer"] == PUBLIC_URL
    assert document["authorization_endpoint"] == f"{PUBLIC_URL}/authorize"
    assert document["token_endpoint"] == f"{PUBLIC_URL}/token"
    assert document["code_challenge_methods_supported"] == ["S256"]
    assert set(document["grant_types_supported"]) == {"authorization_code", "refresh_token"}


def test_public_url_wins_over_the_request_origin(load_server_http):
    """Behind an ingress the request's own origin is the internal one."""
    module = load_server_http(**{**CUSTODY_ENV, "PUBLIC_URL": "https://public.example.com"})
    document = body_of(run(module.protected_resource_metadata(get("/.well-known/oauth-protected-resource"))))
    assert document["resource"].startswith("https://public.example.com")


# ── who gets in ───────────────────────────────────────────────────────────
class TestCustodyAuthentication:
    def sign_in(self, module):
        """Put a session in the store and return the token that names it."""
        flow = module.CUSTODY_FLOW
        session = Session("oid-1", TENANT, "user@example.com", "refresh-value", "pbi-token", 1e12)
        response = flow._issue("session-key", session)
        return json.loads(response.body)["access_token"]

    def test_no_token_is_refused_with_a_pointer_to_the_metadata(self, load_server_http):
        module = load_server_http(**CUSTODY_ENV)
        response = run(module.custody_authenticated_mcp_handler(get("/mcp")))
        assert response.status_code == 401
        assert (
            f'resource_metadata="{PUBLIC_URL}/.well-known/oauth-protected-resource"'
            in response.headers["www-authenticate"]
        )

    def test_an_unknown_token_is_refused(self, load_server_http):
        module = load_server_http(**CUSTODY_ENV)
        response = run(
            module.custody_authenticated_mcp_handler(get("/mcp", headers={"authorization": "Bearer nope.nope"}))
        )
        assert response.status_code == 401
        assert body_of(response)["error"] == "invalid_token"

    def test_a_non_bearer_header_is_refused(self, load_server_http):
        module = load_server_http(**CUSTODY_ENV)
        response = run(module.custody_authenticated_mcp_handler(get("/mcp", headers={"authorization": "Basic abc"})))
        assert response.status_code == 401

    def test_a_live_session_is_admitted_and_names_the_user(self, load_server_http):
        module = load_server_http(**CUSTODY_ENV)
        token = self.sign_in(module)
        request = get("/mcp", headers={"authorization": f"Bearer {token}"})

        captured = {}

        async def fake_handler(req):
            captured["user"] = req.state.authenticated
            captured["session_key"] = req.state.custody_session_key
            from starlette.responses import JSONResponse

            return JSONResponse(content={"ok": True})

        module.mcp_handler = fake_handler
        response = run(module.custody_authenticated_mcp_handler(request))

        assert response.status_code == 200
        assert captured["user"].preferred_username == "user@example.com"
        assert captured["session_key"] == "session-key"

    def test_a_revoked_session_stops_working(self, load_server_http):
        module = load_server_http(**CUSTODY_ENV)
        token = self.sign_in(module)
        module.CUSTODY_FLOW.drop_session("session-key")
        response = run(
            module.custody_authenticated_mcp_handler(get("/mcp", headers={"authorization": f"Bearer {token}"}))
        )
        assert response.status_code == 401


# ── refusing to start ─────────────────────────────────────────────────────
class TestCustodyRefusesToStartWithout:
    @pytest.mark.parametrize("missing", ["SESSION_ENCRYPTION_KEY", "PUBLIC_URL", "CUSTODY_REDIRECT_URIS"])
    def test_required_setting(self, load_server_http, missing):
        env = dict(CUSTODY_ENV)
        env[missing] = ""
        with pytest.raises(SystemExit):
            load_server_http(**env)

    def test_a_key_that_is_not_a_fernet_key(self, load_server_http):
        with pytest.raises(SystemExit):
            load_server_http(**{**CUSTODY_ENV, "SESSION_ENCRYPTION_KEY": "hunter2"})
