"""Strict, dependency-free schemas for firewall experiment sessions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "sros2-firewall-session/v1"
EVENT_SCHEMA_VERSION = "sros2-firewall-event/v1"
LABEL_SCHEMA_VERSION = "sros2-firewall-label/v1"
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SECURITY_MODES = frozenset({"permissive", "enforce"})
SESSION_STATUSES = frozenset({"created", "running", "complete", "failed"})
SECRET_KEYWORDS = (
    "secret",
    "token",
    "password",
    "private_key",
    "credential",
)


class SchemaError(ValueError):
    """A catalog, manifest, event, or label violates the canonical schema."""


def require_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise SchemaError(
            f"{field_name} must match {IDENTIFIER_RE.pattern!r}"
        )
    return value


def require_finite_number(
    value: Any,
    field_name: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchemaError(f"{field_name} must be a number")
    numeric = float(value)
    if not minimum <= numeric <= maximum:
        raise SchemaError(
            f"{field_name} must be in {minimum}..{maximum}"
        )
    return numeric


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def new_session_id(scenario_id: str) -> str:
    require_identifier(scenario_id, "scenario_id")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}_{scenario_id}_{secrets.token_hex(4)}"


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_json(path: str | Path, value: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                value,
                handle,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _bounded_text(value: Any, maximum: int = 1024) -> str:
    try:
        text = str(value)
    except Exception:
        text = f"<{type(value).__name__}>"
    return "".join(
        character if character.isprintable() else "�"
        for character in text
    )[:maximum]


def safe_json_value(value: Any, *, depth: int = 0) -> Any:
    """Bound untrusted evidence before it reaches JSONL or model features."""
    if depth > 4:
        return "<depth-limit>"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _bounded_text(value)
    if isinstance(value, dict):
        result = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 64:
                break
            safe_key = _bounded_text(key, 96)
            if any(secret in safe_key.lower() for secret in SECRET_KEYWORDS):
                result[safe_key] = "<redacted>"
            else:
                result[safe_key] = safe_json_value(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set)):
        return [
            safe_json_value(item, depth=depth + 1)
            for item in list(value)[:128]
        ]
    return _bounded_text(value)


@dataclass
class SessionManifest:
    session_id: str
    scenario_id: str
    attack_class: str
    binary_label: str
    security_mode: str
    ros_domain_id: int
    seed: int
    origin: str
    training_eligible: bool
    expected_action: str
    policy_sha256: str
    code_revision: str
    created_utc: str = field(default_factory=utc_now)
    started_utc: str | None = None
    ended_utc: str | None = None
    status: str = "created"
    randomization: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SchemaError("unsupported manifest schema_version")
        if not re.fullmatch(
            r"[0-9]{8}T[0-9]{12}Z_[a-z][a-z0-9_]{0,63}_[0-9a-f]{8}",
            self.session_id,
        ):
            raise SchemaError("invalid generated session_id")
        require_identifier(self.scenario_id, "scenario_id")
        require_identifier(self.attack_class, "attack_class")
        if self.binary_label not in {"normal", "attack"}:
            raise SchemaError("binary_label must be normal or attack")
        if self.security_mode not in SECURITY_MODES:
            raise SchemaError("invalid security_mode")
        if (
            isinstance(self.ros_domain_id, bool)
            or not isinstance(self.ros_domain_id, int)
            or not 0 <= self.ros_domain_id <= 232
        ):
            raise SchemaError("ros_domain_id must be an integer in 0..232")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise SchemaError("seed must be an integer")
        if self.origin not in {"live_lab", "simulated_smoke"}:
            raise SchemaError("invalid origin")
        if self.training_eligible and self.origin != "live_lab":
            raise SchemaError("simulated_smoke sessions may not be trainable")
        if self.status not in SESSION_STATUSES:
            raise SchemaError("invalid session status")
        if (
            self.policy_sha256
            and not re.fullmatch(r"[0-9a-f]{64}", self.policy_sha256)
        ):
            raise SchemaError("policy_sha256 must be lowercase SHA-256 hex")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return safe_json_value(asdict(self))

    def write(self, path: str | Path) -> None:
        atomic_write_json(path, self.to_dict())


def make_event(
    *,
    session_id: str,
    sequence: int,
    event_type: str,
    phase: str,
    attack_class: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    require_identifier(event_type, "event_type")
    require_identifier(phase, "phase")
    require_identifier(attack_class, "attack_class")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise SchemaError("event sequence must be a non-negative integer")
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "session_id": session_id,
        "sequence": sequence,
        "event_id": secrets.token_hex(8),
        "ts_unix_ns": time.time_ns(),
        "monotonic_ns": time.monotonic_ns(),
        "event_type": event_type,
        "phase": phase,
        "attack_class": attack_class,
        "details": safe_json_value(details or {}),
    }


def make_label(
    *,
    session_id: str,
    attack_class: str,
    start_unix_ns: int,
    end_unix_ns: int,
    source: str,
    scope: str = "session_window",
) -> dict[str, Any]:
    require_identifier(attack_class, "attack_class")
    require_identifier(scope, "scope")
    if (
        isinstance(start_unix_ns, bool)
        or isinstance(end_unix_ns, bool)
        or not isinstance(start_unix_ns, int)
        or not isinstance(end_unix_ns, int)
        or start_unix_ns <= 0
        or end_unix_ns < start_unix_ns
    ):
        raise SchemaError("invalid label interval")
    return {
        "schema_version": LABEL_SCHEMA_VERSION,
        "session_id": session_id,
        "attack_class": attack_class,
        "binary": "normal" if attack_class == "normal" else "attack",
        "start_unix_ns": start_unix_ns,
        "end_unix_ns": end_unix_ns,
        "source": _bounded_text(source, 128),
        "scope": scope,
    }
