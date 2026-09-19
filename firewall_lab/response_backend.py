"""Fail-closed response backend with asymmetric tickets and durable replay state.

This module deliberately contains no shell, sudo, nftables, iptables, or network
calls.  The production adapter is disabled until a separately reviewed
privileged service implements the :class:`TimeoutSetAdapter` contract.  Tests
and local evidence use :class:`InMemoryTimeoutSetAdapter` only.

The security boundary is asymmetric: the decision/authorization process owns
an Ed25519 private key and issues a five-second ticket; the privileged backend
receives only the public key.  The backend derives the source and response TTL
from the signed payload, atomically consumes its nonce in SQLite, records the
desired timeout state, and then asks an adapter to apply it.  A crash between
the database commit and adapter update is recovered by ``reconcile()``.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .schema import SchemaError, safe_json_value

try:  # The rest of the project can still run in observe mode without this.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError as exc:  # pragma: no cover - exercised by dependency checks
    InvalidSignature = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    _CRYPTO_IMPORT_ERROR: ImportError | None = exc
else:
    _CRYPTO_IMPORT_ERROR = None


TICKET_SCHEMA_VERSION = "sros2-firewall-response-ticket/v2"
BACKEND_DB_SCHEMA_VERSION = 2
TICKET_LIFETIME_NS = 5_000_000_000
MAX_FUTURE_CLOCK_SKEW_NS = 1_000_000_000
MAX_RESPONSE_TTL_SEC = 300
MAX_TICKET_LENGTH = 4096
NETWORK_ACTION = "temporary_block"
NETWORK_ADAPTER = "network_helper"
NETWORK_ACTIONS = frozenset({"temporary_block"})
DEFAULT_MAX_CONSUMED_TICKETS = 100_000
DEFAULT_MAX_AUDIT_EVENTS = 200_000
RETENTION_POLICY = (
    "fail_closed_manual_archive_after_signer_stop_and_ticket_expiry"
)
_HEX = frozenset("0123456789abcdef")
_MAX_TEXT = 128


class BackendError(RuntimeError):
    """Base class for a safely rejected backend operation."""


class BackendUnavailableError(BackendError):
    """A required production capability is deliberately unavailable."""


class TicketVerificationError(BackendError):
    """An authorization ticket is missing, malformed, or untrusted."""


class TicketReplayError(BackendError):
    """A signed ticket nonce or ticket digest was already consumed."""


class BackendCapacityError(BackendError):
    """The bounded response set has reached its configured capacity."""


class BackendApplyError(BackendError):
    """The desired response is durable but the adapter has not applied it."""


def _require_crypto() -> None:
    if _CRYPTO_IMPORT_ERROR is not None:
        raise BackendUnavailableError(
            "Ed25519 response tickets require the cryptography package; "
            "live response remains disabled"
        ) from _CRYPTO_IMPORT_ERROR


def crypto_ready() -> bool:
    """Return whether the Ed25519 implementation is importable."""

    return _CRYPTO_IMPORT_ERROR is None


def _text(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TicketVerificationError(f"{name} must be text")
    result = value.strip()
    if (not result and not allow_empty) or len(result) > _MAX_TEXT:
        raise TicketVerificationError(
            f"{name} must contain 1..{_MAX_TEXT} characters"
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise TicketVerificationError(f"{name} contains control characters")
    return result


def _hex(value: Any, length: int, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(char not in _HEX for char in value)
    ):
        raise TicketVerificationError(
            f"{name} must be {length} lowercase hexadecimal characters"
        )
    return value


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TicketVerificationError(f"{name} must be a positive integer")
    return value


def _canonical_ip(value: Any) -> str:
    source = _text(value, "ticket source")
    try:
        parsed = ipaddress.ip_address(source)
    except ValueError as exc:
        raise TicketVerificationError("ticket source must be one IP address") from exc
    if parsed.version != 4 or str(parsed) != source:
        raise TicketVerificationError("ticket source must be one canonical IPv4 address")
    return source


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: Any, name: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TicketVerificationError(f"{name} has an invalid length")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TicketVerificationError(f"{name} must be ASCII") from exc
    try:
        result = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise TicketVerificationError(f"{name} is not canonical base64url") from exc
    if len(result) > maximum or _b64encode(result) != value:
        raise TicketVerificationError(f"{name} is not canonical base64url")
    return result


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class VerifiedResponseTicket:
    evidence_id: str
    source: str
    source_kind: str
    action: str
    adapter: str
    backend_id: str
    interface: str
    identity: str
    response_ttl_sec: int
    issued_at_ns: int
    expires_at_ns: int
    nonce: str
    key_id: str
    schema_version: str = TICKET_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return safe_json_value(asdict(self))


_TICKET_FIELDS = frozenset(VerifiedResponseTicket.__dataclass_fields__)


def _validate_payload(
    payload: Any,
    *,
    expected_key_id: str,
    now_ns: int,
) -> VerifiedResponseTicket:
    if not isinstance(payload, dict) or set(payload) != _TICKET_FIELDS:
        raise TicketVerificationError("authorization ticket has unexpected fields")
    if payload.get("schema_version") != TICKET_SCHEMA_VERSION:
        raise TicketVerificationError("unsupported authorization ticket schema")
    if payload.get("key_id") != expected_key_id:
        raise TicketVerificationError("authorization ticket key is not trusted")
    source_kind = _text(payload.get("source_kind"), "ticket source_kind")
    if source_kind == "network_ip":
        source = _canonical_ip(payload.get("source"))
    else:
        source = _text(payload.get("source"), "ticket source")
    values = {
        "evidence_id": _hex(payload.get("evidence_id"), 64, "ticket evidence_id"),
        "source": source,
        "source_kind": source_kind,
        "action": _text(payload.get("action"), "ticket action"),
        "adapter": _text(payload.get("adapter"), "ticket adapter"),
        "backend_id": _text(payload.get("backend_id"), "ticket backend_id"),
        "interface": _text(payload.get("interface"), "ticket interface"),
        "identity": _text(payload.get("identity"), "ticket identity"),
        "response_ttl_sec": _positive_int(
            payload.get("response_ttl_sec"), "ticket response_ttl_sec"
        ),
        "issued_at_ns": _positive_int(payload.get("issued_at_ns"), "ticket issued_at_ns"),
        "expires_at_ns": _positive_int(
            payload.get("expires_at_ns"), "ticket expires_at_ns"
        ),
        "nonce": _hex(payload.get("nonce"), 32, "ticket nonce"),
        "key_id": _hex(payload.get("key_id"), 64, "ticket key_id"),
        "schema_version": TICKET_SCHEMA_VERSION,
    }
    if values["response_ttl_sec"] > MAX_RESPONSE_TTL_SEC:
        raise TicketVerificationError("ticket response TTL is outside 1..300")
    if values["expires_at_ns"] - values["issued_at_ns"] != TICKET_LIFETIME_NS:
        raise TicketVerificationError("authorization ticket lifetime is invalid")
    if now_ns < values["issued_at_ns"] - MAX_FUTURE_CLOCK_SKEW_NS:
        raise TicketVerificationError("authorization ticket is not valid yet")
    if now_ns > values["expires_at_ns"]:
        raise TicketVerificationError("authorization ticket has expired")
    return VerifiedResponseTicket(**values)


class Ed25519TicketIssuer:
    """Private signing capability for the unprivileged authorization process."""

    __slots__ = ("_private_key", "_public_key_bytes", "key_id")

    def __init__(self, private_key_bytes: bytes | None = None):
        _require_crypto()
        if private_key_bytes is None:
            private_key = Ed25519PrivateKey.generate()
        else:
            if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
                raise ValueError("Ed25519 private key must contain exactly 32 raw bytes")
            private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._private_key = private_key
        self._public_key_bytes = public_bytes
        self.key_id = hashlib.sha256(public_bytes).hexdigest()

    @classmethod
    def generate(cls) -> "Ed25519TicketIssuer":
        return cls()

    def private_key_bytes(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_key_bytes(self) -> bytes:
        return bytes(self._public_key_bytes)

    def verifier(self) -> "Ed25519TicketVerifier":
        return Ed25519TicketVerifier(self.public_key_bytes())

    def issue(
        self,
        *,
        evidence_id: str,
        source: str,
        source_kind: str,
        action: str,
        adapter: str,
        backend_id: str,
        interface: str,
        identity: str,
        response_ttl_sec: int,
        issued_at_ns: int | None = None,
        nonce: str | None = None,
    ) -> str:
        now = time.time_ns() if issued_at_ns is None else issued_at_ns
        payload = {
            "schema_version": TICKET_SCHEMA_VERSION,
            "evidence_id": evidence_id,
            "source": source,
            "source_kind": source_kind,
            "action": action,
            "adapter": adapter,
            "backend_id": backend_id,
            "interface": interface,
            "identity": identity,
            "response_ttl_sec": response_ttl_sec,
            "issued_at_ns": now,
            "expires_at_ns": now + TICKET_LIFETIME_NS,
            "nonce": nonce or secrets.token_hex(16),
            "key_id": self.key_id,
        }
        verified = _validate_payload(payload, expected_key_id=self.key_id, now_ns=now)
        encoded = _canonical_payload(verified.to_dict())
        signature = self._private_key.sign(encoded)
        return f"{_b64encode(encoded)}.{_b64encode(signature)}"


class Ed25519TicketVerifier:
    """Public-key-only capability suitable for the privileged backend."""

    __slots__ = ("_public_key", "_public_key_bytes", "key_id")

    def __init__(self, public_key_bytes: bytes):
        _require_crypto()
        if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
            raise ValueError("Ed25519 public key must contain exactly 32 raw bytes")
        self._public_key_bytes = bytes(public_key_bytes)
        self._public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        self.key_id = hashlib.sha256(public_key_bytes).hexdigest()

    def public_key_bytes(self) -> bytes:
        return bytes(self._public_key_bytes)

    def verify(self, ticket: str, *, now_ns: int | None = None) -> VerifiedResponseTicket:
        if not isinstance(ticket, str) or not ticket or len(ticket) > MAX_TICKET_LENGTH:
            raise TicketVerificationError("authorization ticket is missing or too large")
        if ticket.count(".") != 1:
            raise TicketVerificationError("authorization ticket has an invalid format")
        encoded_payload, encoded_signature = ticket.split(".", 1)
        payload_bytes = _b64decode(encoded_payload, "ticket payload", maximum=3072)
        signature = _b64decode(encoded_signature, "ticket signature", maximum=128)
        if len(signature) != 64:
            raise TicketVerificationError("authorization ticket signature length is invalid")
        try:
            self._public_key.verify(signature, payload_bytes)
        except InvalidSignature as exc:
            raise TicketVerificationError(
                "authorization ticket signature is invalid"
            ) from exc
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TicketVerificationError("authorization ticket payload is invalid") from exc
        # JSON with duplicate keys would otherwise become ambiguous.  A
        # canonical byte comparison also rejects whitespace and alternate
        # encodings even when they were signed by a buggy issuer.
        if _canonical_payload(payload) != payload_bytes:
            raise TicketVerificationError("authorization ticket payload is not canonical")
        current = time.time_ns() if now_ns is None else now_ns
        if isinstance(current, bool) or not isinstance(current, int) or current < 1:
            raise TicketVerificationError("verification time must be a positive integer")
        return _validate_payload(payload, expected_key_id=self.key_id, now_ns=current)


@dataclass(frozen=True)
class DesiredResponse:
    source: str
    action: str
    adapter: str
    backend_id: str
    evidence_id: str
    expires_at_ns: int
    updated_at_ns: int

    def to_dict(self) -> dict[str, Any]:
        return safe_json_value(asdict(self))


@dataclass(frozen=True)
class StagedResponse:
    response: DesiredResponse
    audit_id: int


class SQLiteResponseState:
    """Durable nonce, desired-state, and audit store.

    ``BEGIN IMMEDIATE`` plus UNIQUE constraints makes ticket consumption atomic
    across threads and processes sharing the same database file.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        max_active_sources: int = 1024,
        max_consumed_tickets: int = DEFAULT_MAX_CONSUMED_TICKETS,
        max_audit_events: int = DEFAULT_MAX_AUDIT_EVENTS,
    ):
        limits = {
            "max_active_sources": (max_active_sources, 1, 65536),
            "max_consumed_tickets": (max_consumed_tickets, 1, 10_000_000),
            "max_audit_events": (max_audit_events, 1, 10_000_000),
        }
        for name, (value, minimum, maximum) in limits.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(
                    f"{name} must be an integer in {minimum}..{maximum}"
                )
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or (self.path.exists() and self.path.is_symlink()):
            raise SchemaError("response state database may not be symlinked")
        self.max_active_sources = max_active_sources
        self.max_consumed_tickets = max_consumed_tickets
        self.max_audit_events = max_audit_events
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self.path.exists() and self.path.is_symlink():
            raise SchemaError("response state database became a symlink")
        connection = sqlite3.connect(
            self.path,
            timeout=10.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS consumed_tickets (
                    nonce TEXT PRIMARY KEY,
                    ticket_sha256 TEXT NOT NULL UNIQUE,
                    evidence_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    action TEXT NOT NULL,
                    adapter TEXT NOT NULL,
                    backend_id TEXT NOT NULL,
                    consumed_at_ns INTEGER NOT NULL,
                    response_expires_at_ns INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS desired_responses (
                    source TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    adapter TEXT NOT NULL,
                    backend_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    expires_at_ns INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at_ns INTEGER NOT NULL,
                    event TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    ticket_sha256 TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    source TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_desired_expiry
                    ON desired_responses(expires_at_ns);
                CREATE INDEX IF NOT EXISTS idx_audit_time
                    ON audit_events(occurred_at_ns);
                CREATE TABLE IF NOT EXISTS backend_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, BACKEND_DB_SCHEMA_VERSION}:
                raise BackendUnavailableError(
                    f"unsupported response database schema version {version}"
                )
            connection.execute(f"PRAGMA user_version = {BACKEND_DB_SCHEMA_VERSION}")
            expected_metadata = {
                "max_active_sources": str(self.max_active_sources),
                "max_consumed_tickets": str(self.max_consumed_tickets),
                "max_audit_events": str(self.max_audit_events),
                "retention_policy": RETENTION_POLICY,
            }
            stored_metadata = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key, value FROM backend_metadata"
                ).fetchall()
            }
            if stored_metadata and stored_metadata != expected_metadata:
                raise BackendUnavailableError(
                    "response database capacity configuration does not match "
                    "its persisted metadata"
                )
            for key, value in expected_metadata.items():
                connection.execute(
                    "INSERT OR IGNORE INTO backend_metadata(key, value) VALUES (?, ?)",
                    (key, value),
                )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _audit_insert(
        connection: sqlite3.Connection,
        *,
        occurred_at_ns: int,
        event: str,
        outcome: str,
        ticket_sha256: str = "",
        nonce: str = "",
        source: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> int:
        cursor = connection.execute(
            """
            INSERT INTO audit_events(
                occurred_at_ns, event, outcome, ticket_sha256,
                nonce, source, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                occurred_at_ns,
                event[:64],
                outcome[:32],
                ticket_sha256,
                nonce,
                source,
                json.dumps(
                    safe_json_value(dict(details or {})),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ),
            ),
        )
        return int(cursor.lastrowid)

    def _require_audit_capacity(
        self,
        connection: sqlite3.Connection,
        *,
        needed: int = 1,
    ) -> None:
        current = int(
            connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        )
        if current + needed > self.max_audit_events:
            raise BackendCapacityError(
                "audit capacity is exhausted; live response fails closed until "
                "an operator archives and safely rotates the database"
            )

    def _expire_desired_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        now_ns: int,
    ) -> None:
        expired = connection.execute(
            "SELECT source FROM desired_responses WHERE expires_at_ns <= ?",
            (now_ns,),
        ).fetchall()
        self._require_audit_capacity(connection, needed=len(expired))
        connection.execute(
            "DELETE FROM desired_responses WHERE expires_at_ns <= ?", (now_ns,)
        )
        for row in expired:
            self._audit_insert(
                connection,
                occurred_at_ns=now_ns,
                event="response_expired",
                outcome="removed",
                source=str(row["source"]),
            )

    def record_audit(
        self,
        *,
        event: str,
        outcome: str,
        now_ns: int,
        ticket_sha256: str = "",
        nonce: str = "",
        source: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_audit_capacity(connection)
            self._audit_insert(
                connection,
                occurred_at_ns=now_ns,
                event=event,
                outcome=outcome,
                ticket_sha256=ticket_sha256,
                nonce=nonce,
                source=source,
                details=details,
            )
            connection.commit()

    def begin_audit(
        self,
        *,
        event: str,
        now_ns: int,
        ticket_sha256: str = "",
        nonce: str = "",
        source: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> int:
        """Reserve one durable audit row before an external adapter action."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_audit_capacity(connection)
            audit_id = self._audit_insert(
                connection,
                occurred_at_ns=now_ns,
                event=event,
                outcome="pending",
                ticket_sha256=ticket_sha256,
                nonce=nonce,
                source=source,
                details=details,
            )
            connection.commit()
            return audit_id

    def finish_audit(
        self,
        audit_id: int,
        *,
        outcome: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Update a previously reserved row without consuming new capacity."""

        if isinstance(audit_id, bool) or not isinstance(audit_id, int) or audit_id < 1:
            raise ValueError("audit_id must be a positive integer")
        encoded = json.dumps(
            safe_json_value(dict(details or {})),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE audit_events SET outcome = ?, details_json = ? WHERE id = ?",
                (outcome[:32], encoded, audit_id),
            )
            if cursor.rowcount != 1:
                raise BackendUnavailableError("reserved audit row is missing")
            connection.commit()

    def consume_and_stage(
        self,
        ticket: VerifiedResponseTicket,
        *,
        ticket_sha256: str,
        now_ns: int,
    ) -> StagedResponse:
        response_expires = now_ns + ticket.response_ttl_sec * 1_000_000_000
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_desired_in_transaction(connection, now_ns=now_ns)
            consumed_count = int(
                connection.execute("SELECT COUNT(*) FROM consumed_tickets").fetchone()[0]
            )
            if consumed_count >= self.max_consumed_tickets:
                raise BackendCapacityError(
                    "consumed-ticket capacity is exhausted; live response fails "
                    "closed until an operator archives and safely rotates the database"
                )
            self._require_audit_capacity(connection)
            existing = connection.execute(
                "SELECT expires_at_ns FROM desired_responses WHERE source = ?",
                (ticket.source,),
            ).fetchone()
            if existing is None:
                active_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM desired_responses WHERE expires_at_ns > ?",
                        (now_ns,),
                    ).fetchone()[0]
                )
                if active_count >= self.max_active_sources:
                    raise BackendCapacityError("response backend capacity is exhausted")
            try:
                connection.execute(
                    """
                    INSERT INTO consumed_tickets(
                        nonce, ticket_sha256, evidence_id, source, action,
                        adapter, backend_id, consumed_at_ns,
                        response_expires_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ticket.nonce,
                        ticket_sha256,
                        ticket.evidence_id,
                        ticket.source,
                        ticket.action,
                        ticket.adapter,
                        ticket.backend_id,
                        now_ns,
                        response_expires,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise TicketReplayError(
                    "authorization ticket nonce or digest was already consumed"
                ) from exc
            effective_expiry = max(
                response_expires,
                int(existing["expires_at_ns"]) if existing is not None else 0,
            )
            connection.execute(
                """
                INSERT INTO desired_responses(
                    source, action, adapter, backend_id, evidence_id,
                    expires_at_ns, updated_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    action=excluded.action,
                    adapter=excluded.adapter,
                    backend_id=excluded.backend_id,
                    evidence_id=excluded.evidence_id,
                    expires_at_ns=MAX(desired_responses.expires_at_ns, excluded.expires_at_ns),
                    updated_at_ns=excluded.updated_at_ns
                """,
                (
                    ticket.source,
                    ticket.action,
                    ticket.adapter,
                    ticket.backend_id,
                    ticket.evidence_id,
                    effective_expiry,
                    now_ns,
                ),
            )
            audit_id = self._audit_insert(
                connection,
                occurred_at_ns=now_ns,
                event="ticket_consumed",
                outcome="staged",
                ticket_sha256=ticket_sha256,
                nonce=ticket.nonce,
                source=ticket.source,
                details={
                    "evidence_id": ticket.evidence_id,
                    "expires_at_ns": effective_expiry,
                    "backend_id": ticket.backend_id,
                },
            )
            connection.commit()
            return StagedResponse(
                response=DesiredResponse(
                    source=ticket.source,
                    action=ticket.action,
                    adapter=ticket.adapter,
                    backend_id=ticket.backend_id,
                    evidence_id=ticket.evidence_id,
                    expires_at_ns=effective_expiry,
                    updated_at_ns=now_ns,
                ),
                audit_id=audit_id,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def active_desired(self, *, now_ns: int) -> dict[str, DesiredResponse]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_desired_in_transaction(connection, now_ns=now_ns)
            rows = connection.execute(
                """
                SELECT source, action, adapter, backend_id, evidence_id,
                       expires_at_ns, updated_at_ns
                FROM desired_responses WHERE expires_at_ns > ? ORDER BY source
                """,
                (now_ns,),
            ).fetchall()
            connection.commit()
        return {
            str(row["source"]): DesiredResponse(**dict(row))
            for row in rows
        }

    def capacity_status(self) -> dict[str, Any]:
        """Return bounded durable-state usage without deleting any evidence."""

        with self._connect() as connection:
            consumed = int(
                connection.execute("SELECT COUNT(*) FROM consumed_tickets").fetchone()[0]
            )
            audit = int(
                connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            )
            active = int(
                connection.execute("SELECT COUNT(*) FROM desired_responses").fetchone()[0]
            )
        return {
            "consumed_tickets": consumed,
            "max_consumed_tickets": self.max_consumed_tickets,
            "consumed_remaining": max(0, self.max_consumed_tickets - consumed),
            "audit_events": audit,
            "max_audit_events": self.max_audit_events,
            "audit_remaining": max(0, self.max_audit_events - audit),
            "desired_responses": active,
            "max_active_sources": self.max_active_sources,
            "retention_policy": RETENTION_POLICY,
        }

    def database_status(self) -> dict[str, Any]:
        """Checkpoint WAL and return an integrity/capacity snapshot for evidence."""

        with self._connect() as connection:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            checkpoint = tuple(
                int(value)
                for value in connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
            )
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        return {
            "integrity_check": integrity,
            "wal_checkpoint": list(checkpoint),
            "schema_version": user_version,
            "capacity": self.capacity_status(),
        }

    def audit_events(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, occurred_at_ns, event, outcome, ticket_sha256,
                       nonce, source, details_json
                FROM audit_events ORDER BY id
                """
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            value = dict(row)
            value["details"] = json.loads(value.pop("details_json"))
            result.append(safe_json_value(value))
        return result


class TimeoutSetAdapter(ABC):
    """Dedicated timeout-set namespace used by the response backend."""

    backend_id: str

    @abstractmethod
    def apply(self, response: DesiredResponse, *, now_ns: int) -> None:
        """Create or extend one source timeout without shortening it."""

    @abstractmethod
    def reconcile(
        self,
        desired: Mapping[str, DesiredResponse],
        *,
        now_ns: int,
    ) -> None:
        """Make the dedicated adapter namespace exactly match durable state."""

    @abstractmethod
    def snapshot(self, *, now_ns: int) -> dict[str, int]:
        """Return active source-to-expiry state after automatic pruning."""


class InMemoryTimeoutSetAdapter(TimeoutSetAdapter):
    """Deterministic fake kernel timeout set for tests and offline evidence."""

    def __init__(self, backend_id: str):
        self.backend_id = _text(backend_id, "backend_id")
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()
        self.apply_count = 0

    def _prune(self, now_ns: int) -> None:
        self._entries = {
            source: expiry
            for source, expiry in self._entries.items()
            if expiry > now_ns
        }

    def apply(self, response: DesiredResponse, *, now_ns: int) -> None:
        if response.backend_id != self.backend_id:
            raise BackendApplyError("adapter backend identity does not match response")
        with self._lock:
            self._prune(now_ns)
            self._entries[response.source] = max(
                response.expires_at_ns,
                self._entries.get(response.source, 0),
            )
            self.apply_count += 1

    def reconcile(
        self,
        desired: Mapping[str, DesiredResponse],
        *,
        now_ns: int,
    ) -> None:
        with self._lock:
            self._prune(now_ns)
            replacement: dict[str, int] = {}
            for source, response in desired.items():
                if response.backend_id != self.backend_id:
                    raise BackendApplyError(
                        "adapter backend identity does not match durable state"
                    )
                if response.expires_at_ns > now_ns:
                    replacement[source] = response.expires_at_ns
            self._entries = replacement

    def snapshot(self, *, now_ns: int) -> dict[str, int]:
        with self._lock:
            self._prune(now_ns)
            return dict(sorted(self._entries.items()))

    def seed_for_test(self, source: str, expires_at_ns: int) -> None:
        """Insert fake drift; intentionally unavailable on production adapters."""

        with self._lock:
            self._entries[_canonical_ip(source)] = int(expires_at_ns)

    def clear_for_test(self) -> None:
        with self._lock:
            self._entries.clear()


class DisabledProductionTimeoutSetAdapter(TimeoutSetAdapter):
    """Fail-closed placeholder: it never executes a host firewall command."""

    def __init__(self, backend_id: str):
        self.backend_id = _text(backend_id, "backend_id")

    @staticmethod
    def _disabled() -> None:
        raise BackendUnavailableError(
            "production timeout-set adapter is disabled pending privileged "
            "service installation and isolated-host acceptance testing"
        )

    def apply(self, response: DesiredResponse, *, now_ns: int) -> None:
        self._disabled()

    def reconcile(
        self,
        desired: Mapping[str, DesiredResponse],
        *,
        now_ns: int,
    ) -> None:
        self._disabled()

    def snapshot(self, *, now_ns: int) -> dict[str, int]:
        self._disabled()
        return {}  # pragma: no cover


@dataclass(frozen=True)
class BackendApplyResult:
    source: str
    evidence_id: str
    ticket_sha256: str
    expires_at_ns: int
    backend_id: str

    def to_dict(self) -> dict[str, Any]:
        return safe_json_value(asdict(self))


class ResponseBackend:
    """Verify, atomically consume, stage, apply, and recover one response."""

    def __init__(
        self,
        *,
        verifier: Ed25519TicketVerifier,
        state: SQLiteResponseState,
        timeout_set: TimeoutSetAdapter,
        backend_id: str,
        authorized_sources: Iterable[str],
        protected_sources: Iterable[str] = (),
        network_action: str = NETWORK_ACTION,
    ):
        if type(verifier) is not Ed25519TicketVerifier:
            raise TypeError("backend requires a public-key-only Ed25519 verifier")
        if not isinstance(state, SQLiteResponseState):
            raise TypeError("backend requires SQLiteResponseState")
        if not isinstance(timeout_set, TimeoutSetAdapter):
            raise TypeError("backend requires a TimeoutSetAdapter")
        self.verifier = verifier
        self.state = state
        self.timeout_set = timeout_set
        self.backend_id = _text(backend_id, "backend_id")
        if not isinstance(network_action, str) or network_action not in NETWORK_ACTIONS:
            raise ValueError("network_action must be temporary_block")
        self.network_action = network_action
        if timeout_set.backend_id != self.backend_id:
            raise ValueError("timeout adapter backend_id does not match backend")
        self.authorized_networks = self._networks(authorized_sources, required=True)
        self.protected_networks = self._networks(protected_sources, required=False)

    @staticmethod
    def _networks(values: Iterable[str], *, required: bool) -> tuple[ipaddress.IPv4Network, ...]:
        try:
            networks = tuple(ipaddress.ip_network(value, strict=True) for value in values)
        except (TypeError, ValueError) as exc:
            raise ValueError("response scopes must contain canonical IPv4 CIDRs") from exc
        if required and not networks:
            raise ValueError("at least one authorized source network is required")
        if any(network.version != 4 for network in networks):
            raise ValueError("response backend supports IPv4 scope only")
        return networks  # type: ignore[return-value]

    @staticmethod
    def _is_special(address: ipaddress.IPv4Address) -> bool:
        return bool(
            address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or address.is_link_local
            or address.is_reserved
        )

    def _check_scope(self, ticket: VerifiedResponseTicket) -> None:
        if ticket.source_kind != "network_ip":
            raise TicketVerificationError("network backend requires network_ip evidence")
        if ticket.action != self.network_action or ticket.adapter != NETWORK_ADAPTER:
            raise TicketVerificationError(
                "network backend action/adapter does not match its fixed signed contract"
            )
        if ticket.backend_id != self.backend_id:
            raise TicketVerificationError("ticket is bound to another backend")
        address = ipaddress.ip_address(ticket.source)
        if self._is_special(address):
            raise TicketVerificationError("special-use source addresses are never blocked")
        if not any(address in network for network in self.authorized_networks):
            raise TicketVerificationError("ticket source is outside backend-owned scope")
        if any(address in network for network in self.protected_networks):
            raise TicketVerificationError("ticket source belongs to a protected scope")

    def apply_ticket(self, ticket: str, *, now_ns: int | None = None) -> BackendApplyResult:
        current = time.time_ns() if now_ns is None else now_ns
        if isinstance(current, bool) or not isinstance(current, int) or current < 1:
            raise TicketVerificationError("backend time must be a positive integer")
        digest = hashlib.sha256(ticket.encode("utf-8")).hexdigest() if isinstance(ticket, str) else ""
        try:
            verified = self.verifier.verify(ticket, now_ns=current)
            self._check_scope(verified)
        except (TicketVerificationError, UnicodeEncodeError) as exc:
            self.state.record_audit(
                event="ticket_rejected",
                outcome="rejected",
                now_ns=current,
                ticket_sha256=digest,
                details={"reason": str(exc)},
            )
            raise
        try:
            staged = self.state.consume_and_stage(
                verified,
                ticket_sha256=digest,
                now_ns=current,
            )
        except (TicketReplayError, BackendCapacityError) as exc:
            self.state.record_audit(
                event="ticket_rejected",
                outcome="rejected",
                now_ns=current,
                ticket_sha256=digest,
                nonce=verified.nonce,
                source=verified.source,
                details={"reason": str(exc)},
            )
            raise
        desired = staged.response
        try:
            self.timeout_set.apply(desired, now_ns=current)
        except BackendError as exc:
            self.state.finish_audit(
                staged.audit_id,
                outcome="pending_recovery",
                details={"reason": str(exc), "expires_at_ns": desired.expires_at_ns},
            )
            raise BackendApplyError(
                "response was staged durably but adapter apply failed; restart "
                "reconciliation is required"
            ) from exc
        self.state.finish_audit(
            staged.audit_id,
            outcome="applied",
            details={"expires_at_ns": desired.expires_at_ns},
        )
        return BackendApplyResult(
            source=desired.source,
            evidence_id=desired.evidence_id,
            ticket_sha256=digest,
            expires_at_ns=desired.expires_at_ns,
            backend_id=desired.backend_id,
        )

    def reconcile(self, *, now_ns: int | None = None) -> dict[str, int]:
        current = time.time_ns() if now_ns is None else now_ns
        if isinstance(current, bool) or not isinstance(current, int) or current < 1:
            raise TicketVerificationError("backend time must be a positive integer")
        desired = self.state.active_desired(now_ns=current)
        audit_id = self.state.begin_audit(
            event="restart_reconcile",
            now_ns=current,
            details={"desired_count": len(desired)},
        )
        try:
            self.timeout_set.reconcile(desired, now_ns=current)
            snapshot = self.timeout_set.snapshot(now_ns=current)
        except BackendError as exc:
            self.state.finish_audit(
                audit_id,
                outcome="failed_closed",
                details={"reason": str(exc), "desired_count": len(desired)},
            )
            raise
        expected = {
            source: response.expires_at_ns for source, response in desired.items()
        }
        if snapshot != expected:
            self.state.finish_audit(
                audit_id,
                outcome="failed_closed",
                details={"reason": "adapter snapshot differs from durable state"},
            )
            raise BackendApplyError("adapter snapshot differs from durable desired state")
        self.state.finish_audit(
            audit_id,
            outcome="reconciled",
            details={"active_count": len(snapshot)},
        )
        return snapshot
