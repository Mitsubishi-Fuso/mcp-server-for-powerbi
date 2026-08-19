"""The store custody mode keeps its credentials in."""

import json

import pytest
from cryptography.fernet import Fernet

from mcp_for_powerbi.token_store import (
    CODE_TTL_SECONDS,
    PENDING_TTL_SECONDS,
    SESSION_ABSOLUTE_TTL_SECONDS,
    SESSION_IDLE_TTL_SECONDS,
    AuthorizationCode,
    InMemoryTokenStore,
    PendingAuthorization,
    Session,
    TokenStoreError,
    create_token_store,
    fingerprint,
    new_secret,
)


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock):
    return InMemoryTokenStore(Fernet.generate_key().decode(), now=clock)


def a_pending():
    return PendingAuthorization("librechat", "https://client/cb", "challenge", "client-state", "verifier", 0.0)


def a_code(session_key="session-1"):
    return AuthorizationCode("librechat", "https://client/cb", "challenge", session_key, 0.0)


def a_session():
    return Session("oid-1", "tid-1", "user@example.com", "refresh-token-value")


# ── construction ──────────────────────────────────────────────────────────
def test_custody_will_not_run_without_a_key():
    with pytest.raises(TokenStoreError) as exc:
        create_token_store(None)
    assert "SESSION_ENCRYPTION_KEY" in str(exc.value)


def test_a_bad_key_is_rejected_with_instructions():
    with pytest.raises(TokenStoreError) as exc:
        create_token_store("not-a-fernet-key")
    assert "Fernet" in str(exc.value)


def test_a_good_key_is_accepted():
    assert create_token_store(Fernet.generate_key().decode()) is not None


# ── single use ────────────────────────────────────────────────────────────
def test_pending_is_single_use(store):
    store.put_pending("state-1", a_pending())
    assert store.take_pending("state-1") is not None
    assert store.take_pending("state-1") is None, "a replayed state must not work twice"


def test_code_is_single_use(store):
    code = new_secret()
    store.put_code(code, a_code())
    assert store.take_code(code) is not None
    assert store.take_code(code) is None, "a replayed code must not work twice"


def test_an_unknown_code_is_simply_absent(store):
    assert store.take_code(new_secret()) is None


# ── expiry ────────────────────────────────────────────────────────────────
def test_pending_expires(store, clock):
    store.put_pending("state-1", a_pending())
    clock.advance(PENDING_TTL_SECONDS + 1)
    assert store.take_pending("state-1") is None


def test_code_expires(store, clock):
    code = new_secret()
    store.put_code(code, a_code())
    clock.advance(CODE_TTL_SECONDS + 1)
    assert store.take_code(code) is None


def test_session_idles_out(store, clock):
    store.put_session("k", a_session())
    clock.advance(SESSION_IDLE_TTL_SECONDS + 1)
    assert store.get_session("k") is None


def test_reading_a_session_keeps_it_alive(store, clock):
    store.put_session("k", a_session())
    for _ in range(4):
        clock.advance(SESSION_IDLE_TTL_SECONDS - 60)
        assert store.get_session("k") is not None, "an active session should not idle out"


def test_the_absolute_limit_still_applies(store, clock):
    """Continuous use must not extend a session indefinitely."""
    store.put_session("k", a_session())
    while clock.now < 1_000_000.0 + SESSION_ABSOLUTE_TTL_SECONDS:
        clock.advance(SESSION_IDLE_TTL_SECONDS - 60)
        store.get_session("k")
    clock.advance(SESSION_IDLE_TTL_SECONDS)
    assert store.get_session("k") is None


def test_a_deleted_session_is_gone(store):
    store.put_session("k", a_session())
    store.delete_session("k")
    assert store.get_session("k") is None


# ── what is actually held ─────────────────────────────────────────────────
def test_refresh_tokens_are_not_stored_in_plaintext(store):
    store.put_session("k", a_session())
    held = b" ".join(blob for _, blob in store._sessions.values())
    assert b"refresh-token-value" not in held
    assert b"user@example.com" not in held


def test_records_round_trip(store):
    store.put_session("k", a_session())
    loaded = store.get_session("k")
    assert loaded is not None
    assert loaded.refresh_token == "refresh-token-value"
    assert loaded.user_oid == "oid-1"


def test_codes_are_keyed_by_digest_not_by_value(store):
    """The store must not be able to hand back a usable credential."""
    code = new_secret()
    store.put_code(code, a_code())
    assert fingerprint(code) in store._codes
    assert code not in store._codes


def test_a_record_encrypted_under_another_key_is_treated_as_absent(store, clock):
    other = InMemoryTokenStore(Fernet.generate_key().decode(), now=clock)
    other.put_session("k", a_session())
    store._sessions["k"] = other._sessions["k"]
    assert store.get_session("k") is None


def test_tampering_is_not_silently_accepted(store):
    store.put_session("k", a_session())
    expires_at, blob = store._sessions["k"]
    store._sessions["k"] = (expires_at, blob[:-4] + b"AAAA")
    assert store.get_session("k") is None


def test_secrets_are_unique_and_url_safe():
    values = {new_secret() for _ in range(200)}
    assert len(values) == 200
    assert all(v == json.loads(json.dumps(v)) and "/" not in v and "+" not in v for v in values)
