"""Custody mode's authorization server.

The assertion this file exists for is test_no_entra_token_ever_reaches_the_client:
everything else is in service of it.
"""

import json
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from cryptography.fernet import Fernet
from starlette.requests import Request

import mcp_for_powerbi.custody_flow as custody_flow
from mcp_for_powerbi.custody_flow import CustodyError, CustodyFlow, SessionExpired, s256
from mcp_for_powerbi.token_store import InMemoryTokenStore, new_secret

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT_REDIRECT = "https://librechat.example.com/api/mcp/powerbi/oauth/callback"
PUBLIC_URL = "https://powerbi-mcp.example.com"

# What the fake Entra hands back. None of it may reach the MCP client.
ENTRA_ACCESS_TOKEN = "entra-access-token-SECRET"
ENTRA_REFRESH_TOKEN = "entra-refresh-token-SECRET"


class FakeEntra:
    """Stands in for Entra's token endpoint."""

    def __init__(self):
        self.calls = []
        self.response = {
            "access_token": ENTRA_ACCESS_TOKEN,
            "refresh_token": ENTRA_REFRESH_TOKEN,
            "expires_in": 3600,
        }
        self.status = 200

    def post(self, url, data=None, timeout=None):
        self.calls.append(data)
        payload, status = self.response, self.status

        class Response:
            ok = status == 200
            text = json.dumps(payload)

            def json(self):
                return payload

        return Response()


@pytest.fixture
def entra(monkeypatch):
    fake = FakeEntra()
    monkeypatch.setattr(custody_flow.requests, "post", fake.post)
    return fake


@pytest.fixture
def flow():
    return CustodyFlow(
        tenant_id=TENANT,
        client_id="server-app-id",
        client_secret="server-app-secret",
        public_url=PUBLIC_URL,
        redirect_uris=(CLIENT_REDIRECT,),
        store=InMemoryTokenStore(Fernet.generate_key().decode()),
        client_ids=("librechat",),
    )


# ── request helpers ───────────────────────────────────────────────────────
def get(path, **params):
    return Request(
        {"type": "http", "method": "GET", "path": path, "query_string": urlencode(params).encode(), "headers": []}
    )


def post(path, **form):
    body = urlencode(form).encode()

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "query_string": b"",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", str(len(body)).encode()),
            ],
        },
        receive,
    )


def run(coro):
    import asyncio

    return asyncio.run(coro)


def location_of(response):
    return urlparse(response.headers["location"])


def query_of(response):
    return {k: v[0] for k, v in parse_qs(location_of(response).query).items()}


def body_of(response):
    return json.loads(response.body)


# ── /authorize ────────────────────────────────────────────────────────────
class TestAuthorize:
    def test_an_unregistered_redirect_uri_is_refused_not_redirected(self, flow):
        response = run(
            flow.authorize(
                get(
                    "/authorize",
                    client_id="librechat",
                    redirect_uri="https://attacker.example.com/steal",
                    code_challenge=s256("v"),
                    code_challenge_method="S256",
                )
            )
        )
        assert response.status_code == 400
        assert "location" not in response.headers, "redirecting here is the whole attack"

    def test_a_near_miss_redirect_uri_is_refused(self, flow):
        """Exact match only; a prefix rule would accept these."""
        for hostile in (
            CLIENT_REDIRECT + "/../../evil",
            CLIENT_REDIRECT + ".attacker.com",
            CLIENT_REDIRECT.replace("https", "http"),
            CLIENT_REDIRECT + "?next=//evil",
        ):
            response = run(
                flow.authorize(
                    get(
                        "/authorize",
                        client_id="librechat",
                        redirect_uri=hostile,
                        code_challenge=s256("v"),
                        code_challenge_method="S256",
                    )
                )
            )
            assert response.status_code == 400, hostile

    def test_an_unknown_client_is_refused(self, flow):
        response = run(
            flow.authorize(
                get(
                    "/authorize",
                    client_id="not-registered",
                    redirect_uri=CLIENT_REDIRECT,
                    code_challenge=s256("v"),
                    code_challenge_method="S256",
                )
            )
        )
        assert response.status_code == 400
        assert body_of(response)["error"] == "unauthorized_client"

    @pytest.mark.parametrize(
        "pkce",
        [{}, {"code_challenge": "abc"}, {"code_challenge": "abc", "code_challenge_method": "plain"}],
    )
    def test_pkce_is_mandatory_and_must_be_s256(self, flow, pkce):
        response = run(flow.authorize(get("/authorize", client_id="librechat", redirect_uri=CLIENT_REDIRECT, **pkce)))
        assert response.status_code == 302
        assert query_of(response)["error"] == "invalid_request"

    def test_entra_is_sent_our_identity_and_our_callback(self, flow):
        client_challenge = s256("client-verifier")
        response = run(
            flow.authorize(
                get(
                    "/authorize",
                    client_id="librechat",
                    redirect_uri=CLIENT_REDIRECT,
                    code_challenge=client_challenge,
                    code_challenge_method="S256",
                    state="client-state",
                )
            )
        )
        assert response.status_code == 302
        target = location_of(response)
        params = query_of(response)

        assert target.netloc == "login.microsoftonline.com"
        assert params["client_id"] == "server-app-id"
        assert params["redirect_uri"] == f"{PUBLIC_URL}/callback"
        assert "offline_access" in params["scope"]

        # The two things that must not be forwarded.
        assert CLIENT_REDIRECT not in response.headers["location"]
        assert params["code_challenge"] != client_challenge
        assert params["state"] != "client-state"


# ── /callback ─────────────────────────────────────────────────────────────
class TestCallback:
    def test_an_unknown_state_is_refused(self, flow):
        response = run(flow.callback(get("/callback", code="x", state="never-issued")))
        assert response.status_code == 400

    def test_a_state_cannot_be_replayed(self, flow, entra):
        state = start(flow)
        assert run(flow.callback(get("/callback", code="entra-code", state=state))).status_code == 302
        assert run(flow.callback(get("/callback", code="entra-code", state=state))).status_code == 400

    def test_a_refused_sign_in_goes_back_to_the_client(self, flow):
        state = start(flow)
        response = run(flow.callback(get("/callback", state=state, error="access_denied")))
        assert response.status_code == 302
        assert location_of(response).netloc == "librechat.example.com"
        assert query_of(response)["error"] == "access_denied"

    def test_a_missing_refresh_token_is_not_papered_over(self, flow, entra):
        """Without one the user would be sent back to sign in every hour."""
        entra.response = {"access_token": ENTRA_ACCESS_TOKEN, "expires_in": 3600}
        state = start(flow)
        response = run(flow.callback(get("/callback", code="entra-code", state=state)))
        assert query_of(response)["error"] == "server_error"


def start(flow, verifier="client-verifier", client_state="client-state"):
    """Run /authorize and return the state Entra would echo back."""
    response = run(
        flow.authorize(
            get(
                "/authorize",
                client_id="librechat",
                redirect_uri=CLIENT_REDIRECT,
                code_challenge=s256(verifier),
                code_challenge_method="S256",
                state=client_state,
            )
        )
    )
    return query_of(response)["state"]


def sign_in(flow, verifier="client-verifier"):
    """Complete a whole sign-in and return (our code, every response seen)."""
    responses = []
    state = start(flow, verifier)
    callback = run(flow.callback(get("/callback", code="entra-code", state=state)))
    responses.append(callback)
    return query_of(callback)["code"], responses


# ── /token ────────────────────────────────────────────────────────────────
class TestToken:
    def test_a_code_is_exchanged_for_our_own_tokens(self, flow, entra):
        code, _ = sign_in(flow)
        response = run(
            flow.token(
                post(
                    "/token",
                    grant_type="authorization_code",
                    code=code,
                    code_verifier="client-verifier",
                    client_id="librechat",
                )
            )
        )
        assert response.status_code == 200
        payload = body_of(response)
        assert payload["token_type"] == "Bearer"
        assert payload["access_token"] and payload["refresh_token"]

    def test_a_wrong_code_verifier_is_refused(self, flow, entra):
        code, _ = sign_in(flow)
        response = run(
            flow.token(post("/token", grant_type="authorization_code", code=code, code_verifier="not-the-verifier"))
        )
        assert response.status_code == 400
        assert body_of(response)["error"] == "invalid_grant"

    def test_a_missing_code_verifier_is_refused(self, flow, entra):
        code, _ = sign_in(flow)
        response = run(flow.token(post("/token", grant_type="authorization_code", code=code)))
        assert body_of(response)["error"] == "invalid_grant"

    def test_a_code_works_only_once(self, flow, entra):
        code, _ = sign_in(flow)
        first = post("/token", grant_type="authorization_code", code=code, code_verifier="client-verifier")
        second = post("/token", grant_type="authorization_code", code=code, code_verifier="client-verifier")
        assert run(flow.token(first)).status_code == 200
        assert run(flow.token(second)).status_code == 400

    def test_a_code_cannot_be_redeemed_by_another_client(self, flow, entra):
        code, _ = sign_in(flow)
        response = run(
            flow.token(
                post(
                    "/token",
                    grant_type="authorization_code",
                    code=code,
                    code_verifier="client-verifier",
                    client_id="someone-else",
                )
            )
        )
        assert body_of(response)["error"] == "invalid_grant"

    def test_an_unsupported_grant_is_refused(self, flow):
        response = run(flow.token(post("/token", grant_type="password", username="a", password="b")))
        assert body_of(response)["error"] == "unsupported_grant_type"

    def test_refreshing_rotates_both_tokens(self, flow, entra):
        code, _ = sign_in(flow)
        first = body_of(
            run(flow.token(post("/token", grant_type="authorization_code", code=code, code_verifier="client-verifier")))
        )

        second = body_of(
            run(flow.token(post("/token", grant_type="refresh_token", refresh_token=first["refresh_token"])))
        )
        assert second["access_token"] != first["access_token"]
        assert second["refresh_token"] != first["refresh_token"]

        replayed = run(flow.token(post("/token", grant_type="refresh_token", refresh_token=first["refresh_token"])))
        assert replayed.status_code == 400, "a superseded refresh token must not work"

    def test_a_forged_token_is_refused(self, flow, entra):
        code, _ = sign_in(flow)
        issued = body_of(
            run(flow.token(post("/token", grant_type="authorization_code", code=code, code_verifier="client-verifier")))
        )
        session_key = issued["access_token"].split(".")[0]
        assert flow.resolve_access_token(f"{session_key}.{new_secret()}") is None
        assert flow.resolve_access_token(session_key) is None
        assert flow.resolve_access_token("nonsense") is None


# ── the point of the whole design ─────────────────────────────────────────
def test_no_entra_token_ever_reaches_the_client(flow, entra):
    """Everything the MCP client is handed, across an entire sign-in."""
    seen = []

    state = start(flow)
    callback = run(flow.callback(get("/callback", code="entra-code", state=state)))
    seen.append(callback.headers["location"])

    code = query_of(callback)["code"]
    issued = run(
        flow.token(post("/token", grant_type="authorization_code", code=code, code_verifier="client-verifier"))
    )
    seen.append(issued.body.decode())

    refreshed = run(
        flow.token(post("/token", grant_type="refresh_token", refresh_token=body_of(issued)["refresh_token"]))
    )
    seen.append(refreshed.body.decode())

    for surface in seen:
        assert ENTRA_ACCESS_TOKEN not in surface
        assert ENTRA_REFRESH_TOKEN not in surface


# ── the Power BI token behind the session ─────────────────────────────────
class TestPowerBIToken:
    def resolved(self, flow, entra):
        code, _ = sign_in(flow)
        issued = body_of(
            run(flow.token(post("/token", grant_type="authorization_code", code=code, code_verifier="client-verifier")))
        )
        return flow.resolve_access_token(issued["access_token"])

    def test_a_live_token_is_reused(self, flow, entra):
        session_key, session = self.resolved(flow, entra)
        before = len(entra.calls)
        assert flow.power_bi_token(session_key, session) == ENTRA_ACCESS_TOKEN
        assert len(entra.calls) == before, "a token good for an hour should not be re-fetched"

    def test_a_token_near_expiry_is_refreshed(self, flow, entra):
        session_key, session = self.resolved(flow, entra)
        session.access_token_expires_at = time.time() + 10
        entra.response = {"access_token": "second-token", "refresh_token": "second-refresh", "expires_in": 3600}

        assert flow.power_bi_token(session_key, session) == "second-token"
        assert entra.calls[-1]["grant_type"] == "refresh_token"

    def test_a_dead_refresh_token_ends_the_session(self, flow, entra):
        session_key, session = self.resolved(flow, entra)
        session.access_token_expires_at = 0
        entra.status = 400
        entra.response = {"error": "invalid_grant", "error_description": "token revoked"}

        with pytest.raises(SessionExpired):
            flow.power_bi_token(session_key, session)
        assert flow.store.get_session(session_key) is None, "leaving it would repeat the failure every call"

    def test_a_claims_challenge_ends_the_session_too(self, flow, entra):
        """Conditional access re-evaluation the user has to answer in a browser."""
        session_key, session = self.resolved(flow, entra)
        session.access_token_expires_at = 0
        entra.status = 400
        entra.response = {"error": "interaction_required", "claims": '{"access_token":{"acrs":{"essential":true}}}'}

        with pytest.raises(SessionExpired):
            flow.power_bi_token(session_key, session)

    def test_an_outage_is_not_mistaken_for_a_dead_session(self, flow, entra):
        """A 500 from Entra must not sign every user out."""
        session_key, session = self.resolved(flow, entra)
        session.access_token_expires_at = 0
        entra.status = 500
        entra.response = {"error": "temporarily_unavailable"}

        with pytest.raises(CustodyError):
            flow.power_bi_token(session_key, session)
        assert flow.store.get_session(session_key) is not None


# ── /revoke ───────────────────────────────────────────────────────────────
class TestRevoke:
    def test_revoking_ends_the_session(self, flow, entra):
        code, _ = sign_in(flow)
        issued = body_of(
            run(flow.token(post("/token", grant_type="authorization_code", code=code, code_verifier="client-verifier")))
        )
        run(flow.revoke(post("/revoke", token=issued["access_token"])))
        assert flow.resolve_access_token(issued["access_token"]) is None

    def test_an_unknown_token_is_not_an_error(self, flow):
        assert run(flow.revoke(post("/revoke", token="nonsense"))).status_code == 200


# ── configuration ─────────────────────────────────────────────────────────
class TestConfiguration:
    def build(self, **overrides):
        settings: dict[str, Any] = dict(
            tenant_id=TENANT,
            client_id="a",
            client_secret="b",
            public_url=PUBLIC_URL,
            redirect_uris=(CLIENT_REDIRECT,),
            store=InMemoryTokenStore(Fernet.generate_key().decode()),
        )
        settings.update(overrides)
        return CustodyFlow(**settings)

    def test_public_url_is_required(self):
        with pytest.raises(CustodyError) as exc:
            self.build(public_url="")
        assert "PUBLIC_URL" in str(exc.value)

    def test_a_redirect_allowlist_is_required(self):
        with pytest.raises(CustodyError) as exc:
            self.build(redirect_uris=())
        assert "CUSTODY_REDIRECT_URIS" in str(exc.value)

    def test_a_trailing_slash_does_not_double_up(self):
        assert self.build(public_url=PUBLIC_URL + "/").callback_url == f"{PUBLIC_URL}/callback"
