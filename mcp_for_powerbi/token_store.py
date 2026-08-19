"""Storage for the credentials custody mode holds on a user's behalf.

Three kinds of record live here, each short-lived for its own reason:

  pending authorization  the half-finished sign-in, from the moment the browser
                         leaves for Entra until it comes back
  authorization code     the code handed to the MCP client, redeemable once
  session                the user's Entra refresh token and the Power BI access
                         token minted from it

Only the last is long-lived, and it is the reason this module encrypts. A
refresh token is durable access to Power BI as that user, so it is never held
in plaintext, and a deployment that has not configured a key does not get to
run custody mode at all.

The in-memory implementation is deliberately the only one here. It confines a
deployment to a single replica - a restart costs every user a fresh sign-in -
and a shared backend can be added against this interface without the callers
changing.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken

# How long a half-finished sign-in stays valid: long enough to satisfy a
# conditional access challenge, short enough that abandoned attempts do not
# accumulate.
PENDING_TTL_SECONDS = 10 * 60

# An authorization code is redeemed immediately by a client that already holds
# it, so anything longer only widens the window for a stolen code.
CODE_TTL_SECONDS = 60

SESSION_IDLE_TTL_SECONDS = 8 * 60 * 60
SESSION_ABSOLUTE_TTL_SECONDS = 7 * 24 * 60 * 60


class TokenStoreError(RuntimeError):
    """The store cannot be used as configured."""


def new_secret(nbytes: int = 32) -> str:
    """A URL-safe random string for a code, state, or opaque token."""
    return secrets.token_urlsafe(nbytes)


def fingerprint(value: str) -> str:
    """The key a secret is stored under.

    Opaque tokens are held only as digests, so the store cannot hand back a
    credential that would let its holder act as the user.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class PendingAuthorization:
    """A sign-in that has left for Entra and not yet come back."""

    client_id: str
    redirect_uri: str
    client_code_challenge: str
    client_state: Optional[str]
    entra_code_verifier: str
    created_at: float


@dataclass
class AuthorizationCode:
    """A code this server issued, redeemable exactly once."""

    client_id: str
    redirect_uri: str
    client_code_challenge: str
    session_key: str
    created_at: float


@dataclass
class Session:
    """What the server holds so it can call Power BI as this user."""

    user_oid: str
    user_tid: str
    username: str
    refresh_token: str
    access_token: Optional[str] = None
    access_token_expires_at: float = 0.0
    created_at: float = 0.0
    last_used_at: float = 0.0
    # The tokens handed to the MCP client are "<session key>.<secret>"; only
    # the digest of each secret is kept, so the store never holds a credential
    # that would let its reader act as the user. Both are rotated on every
    # refresh grant, which is what makes a replayed refresh token detectable.
    access_secret_fingerprint: Optional[str] = None
    refresh_secret_fingerprint: Optional[str] = None


class TokenStore(ABC):
    """Where custody mode keeps what it holds on a user's behalf."""

    @abstractmethod
    def put_pending(self, state: str, pending: PendingAuthorization) -> None: ...

    @abstractmethod
    def take_pending(self, state: str) -> Optional[PendingAuthorization]:
        """Return the pending authorization and remove it. Single use."""

    @abstractmethod
    def put_code(self, code: str, record: AuthorizationCode) -> None: ...

    @abstractmethod
    def take_code(self, code: str) -> Optional[AuthorizationCode]:
        """Return the code record and remove it. Single use."""

    @abstractmethod
    def put_session(self, key: str, session: Session) -> None: ...

    @abstractmethod
    def get_session(self, key: str) -> Optional[Session]: ...

    @abstractmethod
    def delete_session(self, key: str) -> None: ...


class InMemoryTokenStore(TokenStore):
    """Everything in this process, encrypted, and gone when it stops."""

    def __init__(self, encryption_key: str, *, now=time.time):
        try:
            self._fernet = Fernet(encryption_key.encode("utf-8") if isinstance(encryption_key, str) else encryption_key)
        except (ValueError, TypeError) as exc:
            raise TokenStoreError(
                "SESSION_ENCRYPTION_KEY is not a valid Fernet key. Generate one with: "
                "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            ) from exc
        self._now = now
        self._pending: Dict[str, tuple[float, bytes]] = {}
        self._codes: Dict[str, tuple[float, bytes]] = {}
        self._sessions: Dict[str, tuple[float, bytes]] = {}

    # ── encryption ────────────────────────────────────────────────────────
    def _seal(self, record: Any) -> bytes:
        return self._fernet.encrypt(json.dumps(asdict(record)).encode("utf-8"))

    def _open(self, blob: bytes, cls):
        try:
            return cls(**json.loads(self._fernet.decrypt(blob).decode("utf-8")))
        except (InvalidToken, ValueError, TypeError):
            # A record we cannot read is a record we do not have.
            return None

    # ── expiry ────────────────────────────────────────────────────────────
    def _sweep(self, bucket: Dict[str, tuple[float, bytes]]) -> None:
        now = self._now()
        for key in [k for k, (expires_at, _) in bucket.items() if expires_at <= now]:
            del bucket[key]

    def _take(self, bucket: Dict[str, tuple[float, bytes]], key: str, cls):
        self._sweep(bucket)
        entry = bucket.pop(key, None)
        return self._open(entry[1], cls) if entry else None

    # ── pending authorizations ────────────────────────────────────────────
    def put_pending(self, state: str, pending: PendingAuthorization) -> None:
        self._sweep(self._pending)
        self._pending[state] = (self._now() + PENDING_TTL_SECONDS, self._seal(pending))

    def take_pending(self, state: str) -> Optional[PendingAuthorization]:
        return self._take(self._pending, state, PendingAuthorization)

    # ── authorization codes ───────────────────────────────────────────────
    def put_code(self, code: str, record: AuthorizationCode) -> None:
        self._sweep(self._codes)
        self._codes[fingerprint(code)] = (self._now() + CODE_TTL_SECONDS, self._seal(record))

    def take_code(self, code: str) -> Optional[AuthorizationCode]:
        return self._take(self._codes, fingerprint(code), AuthorizationCode)

    # ── sessions ──────────────────────────────────────────────────────────
    def put_session(self, key: str, session: Session) -> None:
        self._sweep(self._sessions)
        now = self._now()
        if not session.created_at:
            session.created_at = now
        session.last_used_at = now
        # Whichever limit falls first ends the session.
        expires_at = min(now + SESSION_IDLE_TTL_SECONDS, session.created_at + SESSION_ABSOLUTE_TTL_SECONDS)
        self._sessions[key] = (expires_at, self._seal(session))

    def get_session(self, key: str) -> Optional[Session]:
        self._sweep(self._sessions)
        entry = self._sessions.get(key)
        if not entry:
            return None
        session = self._open(entry[1], Session)
        if session is None:
            del self._sessions[key]
            return None
        # Reading counts as use, so an active session does not idle out.
        self.put_session(key, session)
        return session

    def delete_session(self, key: str) -> None:
        self._sessions.pop(key, None)


def create_token_store(encryption_key: str | None) -> TokenStore:
    """Build the configured store, refusing to run without a key.

    Custody mode holds refresh tokens; running it with them in plaintext is not
    offered as an option, so a missing key stops the server rather than
    downgrading quietly.
    """
    if not encryption_key:
        raise TokenStoreError(
            "AUTH_MODE=custody requires SESSION_ENCRYPTION_KEY, used to encrypt the refresh tokens "
            "this server holds. Generate one with: "
            "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        )
    return InMemoryTokenStore(encryption_key)
