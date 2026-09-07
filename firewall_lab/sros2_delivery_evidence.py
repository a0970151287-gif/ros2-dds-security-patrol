#!/usr/bin/env python3
"""Verify bounded, two-ended SROS2 direct-delivery evidence.

This module is deliberately offline.  It never imports ``rclpy``, starts a ROS
participant, sends a packet, changes a policy, or invokes a response backend.
It verifies two already-sealed JSONL archives:

* the application publisher's attempted canary sequence; and
* the protected application's received canary sequence.

The contract pins both files by byte count and SHA-256 and binds every record
to the same session, mode, policy, enclaves, source identity, topic and UTC
window.  Archive sequence numbers must be continuous, so a missing received
canary can be interpreted as non-delivery only when both collectors prove a
healthy, gap-free archive covering the full window.

Vendor security logs may be useful diagnostics, but they are intentionally not
accepted as delivery ground truth here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from .schema import SchemaError, require_identifier, sha256_file, utc_now


CONTRACT_SCHEMA = "sros2-firewall-direct-delivery-contract/v2"
ARCHIVE_RECORD_SCHEMA = "sros2-firewall-direct-delivery-record/v1"
REPORT_SCHEMA = "sros2-firewall-direct-delivery-report/v2"
AGGREGATE_SCHEMA = "sros2-firewall-direct-delivery-aggregate/v2"

SESSION_RE = re.compile(
    r"[0-9]{8}T[0-9]{12}Z_[a-z][a-z0-9_]{0,63}_[0-9a-f]{8}"
)
HEX64_RE = re.compile(r"[0-9a-f]{64}")
ROS_PATH_RE = re.compile(r"/(?:[A-Za-z0-9_][A-Za-z0-9_-]*)(?:/[A-Za-z0-9_][A-Za-z0-9_-]*)*")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}")

SECURITY_MODES = frozenset({"permissive", "enforce"})
ARCHIVE_ROLES = frozenset({"attempted", "protected_received"})
AUTHORIZATION_CASES = frozenset(
    {
        "authorized_publisher",
        "uncredentialed_publisher",
        "invalid_credential_publisher",
        "acl_denied_publisher",
    }
)
CREDENTIAL_STATES = frozenset({"security_disabled", "valid", "absent", "invalid"})
PERMISSION_STATES = frozenset({"not_enforced", "allow", "deny", "not_reached"})
MAX_CONTRACT_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_JSONL_LINES = 8194
MAX_JSONL_LINE_BYTES = 16 * 1024
MAX_ATTEMPTS = 4096
MAX_WINDOW_SECONDS = 60.0

_COMMON_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "archive_sequence",
        "role",
        "session_id",
        "trial_id",
        "security_mode",
        "policy_sha256",
        "source_id",
        "source_enclave",
        "protected_sink_id",
        "protected_enclave",
        "canary_topic",
        "collector_id",
        "collector_boot_id",
        "ts_utc",
    }
)


class _ArchiveStateMachine:
    """Fail-closed open -> data* -> close parser with a gap-free cursor."""

    def __init__(self, role: str) -> None:
        self.role = role
        self.body_type = (
            "attempted_canary" if role == "attempted" else "protected_received_canary"
        )
        self.state = "expect_open"
        self.next_archive_sequence = 0

    def consume(self, record: dict[str, Any]) -> str:
        sequence = _bounded_int(
            record.get("archive_sequence"),
            "archive_sequence",
            0,
            MAX_JSONL_LINES - 1,
        )
        if sequence != self.next_archive_sequence:
            raise SchemaError(
                f"{self.role} archive sequence is duplicated, missing, or reordered"
            )
        self.next_archive_sequence += 1
        record_type = record.get("record_type")
        if self.state == "expect_open":
            if record_type != "archive_open":
                raise SchemaError(f"{self.role} archive did not start with archive_open")
            self.state = "collecting"
            return "open"
        if self.state == "collecting" and record_type == self.body_type:
            return "body"
        if self.state == "collecting" and record_type == "collector_heartbeat":
            return "heartbeat"
        if self.state == "collecting" and record_type == "archive_close":
            self.state = "closed"
            return "close"
        raise SchemaError(f"invalid {self.role} archive state transition")

    def finish(self) -> None:
        if self.state != "closed":
            raise SchemaError(f"{self.role} archive is truncated before archive_close")


def _expect_exact_keys(value: Any, expected: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise SchemaError(f"{label} has unexpected keys")
    return value


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SchemaError(f"{label} must be an integer in {minimum}..{maximum}")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise SchemaError(f"{label} must be a bounded UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaError(f"{label} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SchemaError(f"{label} must include a UTC offset")
    return parsed


def _ros_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or not ROS_PATH_RE.fullmatch(value):
        raise SchemaError(f"{label} must be a bounded absolute ROS path")
    return value


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise SchemaError(f"{label} must be lowercase SHA-256 hex")
    return value


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise SchemaError(f"{label} must be a bounded collector token")
    return value


def _regular_below(root: Path, relative_value: Any, *, label: str) -> tuple[Path, str]:
    if (
        not isinstance(relative_value, str)
        or not relative_value
        or len(relative_value) > 256
        or "\\" in relative_value
    ):
        raise SchemaError(f"{label} must be a bounded POSIX relative path")
    relative = PurePosixPath(relative_value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SchemaError(f"{label} must stay below the contract directory")
    root_resolved = root.resolve(strict=True)
    path = root.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        raise SchemaError(f"{label} is missing or symlinked")
    resolved = path.resolve(strict=True)
    if resolved.parent != root_resolved and root_resolved not in resolved.parents:
        raise SchemaError(f"{label} escaped the contract directory")
    return path, relative.as_posix()


def _read_json_object(path: Path, *, maximum_bytes: int, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SchemaError(f"{label} must be a regular non-symlink file")
    size = path.stat().st_size
    if not 0 < size <= maximum_bytes:
        raise SchemaError(f"{label} exceeds its size bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot parse {label}") from exc
    if not isinstance(value, dict):
        raise SchemaError(f"{label} must contain one JSON object")
    return value


def _normalize_authorization(
    value: Any,
    *,
    security_mode: str,
    source_enclave: str,
    canary_topic: str,
) -> dict[str, str | bool]:
    """Validate the five inputs that determine expected delivery.

    A contract assertion is not a hardware trust root, so the context carries
    an explicit attestation flag.  The verifier still refuses internally
    inconsistent combinations instead of inferring authorization from a node
    name, directory order, or the security mode alone.
    """

    raw = _expect_exact_keys(
        value,
        {
            "authorization_case",
            "credential_state",
            "permission_state",
            "subject_enclave",
            "topic",
            "context_attested",
        },
        "publisher authorization",
    )
    authorization_case = raw["authorization_case"]
    if authorization_case not in AUTHORIZATION_CASES:
        raise SchemaError("publisher authorization_case is invalid")
    credential_state = raw["credential_state"]
    if credential_state not in CREDENTIAL_STATES:
        raise SchemaError("publisher credential_state is invalid")
    permission_state = raw["permission_state"]
    if permission_state not in PERMISSION_STATES:
        raise SchemaError("publisher permission_state is invalid")
    subject_enclave = _ros_path(raw["subject_enclave"], "publisher subject_enclave")
    topic = _ros_path(raw["topic"], "publisher authorization topic")
    if subject_enclave != source_enclave:
        raise SchemaError("publisher authorization is bound to a different source enclave")
    if topic != canary_topic:
        raise SchemaError("publisher authorization is bound to a different canary topic")
    if not isinstance(raw["context_attested"], bool):
        raise SchemaError("publisher context_attested must be bool")

    if security_mode == "permissive":
        if credential_state != "security_disabled" or permission_state != "not_enforced":
            raise SchemaError(
                "permissive authorization must declare security_disabled/not_enforced"
            )
        expected_delivery = "full_delivery"
        expected_reason = "security_disabled_in_permissive_control"
    else:
        expected_by_case = {
            "authorized_publisher": ("valid", "allow", "full_delivery"),
            "uncredentialed_publisher": ("absent", "not_reached", "zero_delivery"),
            "invalid_credential_publisher": ("invalid", "not_reached", "zero_delivery"),
            "acl_denied_publisher": ("valid", "deny", "zero_delivery"),
        }
        expected_credential, expected_permission, expected_delivery = expected_by_case[
            authorization_case
        ]
        if (credential_state, permission_state) != (
            expected_credential,
            expected_permission,
        ):
            raise SchemaError(
                "enforce authorization fields contradict the authorization_case"
            )
        expected_reason = f"enforce_{authorization_case}"

    return {
        "authorization_case": authorization_case,
        "credential_state": credential_state,
        "permission_state": permission_state,
        "subject_enclave": subject_enclave,
        "topic": topic,
        "context_attested": raw["context_attested"],
        "expected_delivery": expected_delivery,
        "expected_reason": expected_reason,
    }


def _load_contract(path_value: str | Path) -> tuple[Path, dict[str, Any]]:
    path = Path(path_value)
    raw = _read_json_object(path, maximum_bytes=MAX_CONTRACT_BYTES, label="delivery contract")
    expected = {
        "schema_version",
        "pair_id",
        "pairing_attested",
        "trial_id",
        "session_id",
        "security_mode",
        "policy_sha256",
        "source_id",
        "source_enclave",
        "protected_sink_id",
        "protected_enclave",
        "canary_topic",
        "publisher_authorization",
        "window",
        "expected_first_sequence",
        "expected_attempt_count",
        "collector_requirements",
        "archives",
    }
    _expect_exact_keys(raw, expected, "delivery contract")
    if raw["schema_version"] != CONTRACT_SCHEMA:
        raise SchemaError("unsupported delivery contract schema")
    pair_id = require_identifier(raw["pair_id"], "pair_id")
    pairing_attested = raw["pairing_attested"]
    if not isinstance(pairing_attested, bool):
        raise SchemaError("pairing_attested must be bool")
    trial_id = require_identifier(raw["trial_id"], "trial_id")
    if pairing_attested and pair_id != trial_id:
        raise SchemaError("attested pair_id must equal the archive-bound trial_id")
    session_id = raw["session_id"]
    if not isinstance(session_id, str) or not SESSION_RE.fullmatch(session_id):
        raise SchemaError("invalid delivery session_id")
    mode = raw["security_mode"]
    if mode not in SECURITY_MODES:
        raise SchemaError("security_mode must be permissive or enforce")
    policy_sha256 = _hex64(raw["policy_sha256"], "policy_sha256")
    source_id = require_identifier(raw["source_id"], "source_id")
    protected_sink_id = require_identifier(raw["protected_sink_id"], "protected_sink_id")
    if source_id == protected_sink_id:
        raise SchemaError("source and protected sink identities must be distinct")
    source_enclave = _ros_path(raw["source_enclave"], "source_enclave")
    protected_enclave = _ros_path(raw["protected_enclave"], "protected_enclave")
    if source_enclave == protected_enclave:
        raise SchemaError("source and protected sink enclaves must be distinct")
    canary_topic = _ros_path(raw["canary_topic"], "canary_topic")
    authorization = _normalize_authorization(
        raw["publisher_authorization"],
        security_mode=mode,
        source_enclave=source_enclave,
        canary_topic=canary_topic,
    )

    window = _expect_exact_keys(raw["window"], {"start_utc", "end_utc"}, "delivery window")
    start = _utc(window["start_utc"], "window.start_utc")
    end = _utc(window["end_utc"], "window.end_utc")
    duration = (end - start).total_seconds()
    if not 0 < duration <= MAX_WINDOW_SECONDS:
        raise SchemaError(f"delivery window must be in (0, {MAX_WINDOW_SECONDS}] seconds")

    first = _bounded_int(raw["expected_first_sequence"], "expected_first_sequence", 0, 2**63 - 1)
    count = _bounded_int(raw["expected_attempt_count"], "expected_attempt_count", 1, MAX_ATTEMPTS)
    if first + count - 1 > 2**63 - 1:
        raise SchemaError("expected canary sequence exceeds its bound")

    requirements = _expect_exact_keys(
        raw["collector_requirements"],
        {"minimum_heartbeats", "maximum_heartbeat_gap_ms"},
        "collector requirements",
    )
    minimum_heartbeats = _bounded_int(
        requirements["minimum_heartbeats"], "minimum_heartbeats", 2, 10_000
    )
    maximum_gap = _bounded_int(
        requirements["maximum_heartbeat_gap_ms"],
        "maximum_heartbeat_gap_ms",
        1,
        60_000,
    )

    archives = _expect_exact_keys(raw["archives"], ARCHIVE_ROLES, "delivery archives")
    normalized_archives: dict[str, dict[str, Any]] = {}
    resolved_paths: set[Path] = set()
    for role in sorted(ARCHIVE_ROLES):
        descriptor = _expect_exact_keys(
            archives[role], {"path", "sha256", "bytes"}, f"{role} archive descriptor"
        )
        archive_path, relative = _regular_below(path.parent, descriptor["path"], label=f"{role} archive")
        size = _bounded_int(descriptor["bytes"], f"{role} archive bytes", 1, MAX_ARCHIVE_BYTES)
        if archive_path.stat().st_size != size:
            raise SchemaError(f"{role} archive byte count mismatch")
        digest = _hex64(descriptor["sha256"], f"{role} archive sha256")
        if sha256_file(archive_path) != digest:
            raise SchemaError(f"{role} archive SHA-256 mismatch")
        resolved = archive_path.resolve(strict=True)
        if resolved in resolved_paths:
            raise SchemaError("attempted and received archives must be distinct files")
        resolved_paths.add(resolved)
        normalized_archives[role] = {
            "path": archive_path,
            "relative_path": relative,
            "sha256": digest,
            "bytes": size,
        }

    normalized = {
        **raw,
        "pair_id": pair_id,
        "pairing_attested": pairing_attested,
        "trial_id": trial_id,
        "session_id": session_id,
        "security_mode": mode,
        "policy_sha256": policy_sha256,
        "source_id": source_id,
        "source_enclave": source_enclave,
        "protected_sink_id": protected_sink_id,
        "protected_enclave": protected_enclave,
        "canary_topic": canary_topic,
        "publisher_authorization": authorization,
        "window": {
            "start_utc": window["start_utc"],
            "end_utc": window["end_utc"],
            "start": start,
            "end": end,
        },
        "expected_first_sequence": first,
        "expected_attempt_count": count,
        "collector_requirements": {
            "minimum_heartbeats": minimum_heartbeats,
            "maximum_heartbeat_gap_ms": maximum_gap,
        },
        "archives": normalized_archives,
    }
    return path, normalized


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise SchemaError(f"cannot read delivery archive: {path.name}") from exc
    if not payload or len(payload) > MAX_ARCHIVE_BYTES:
        raise SchemaError("delivery archive exceeds its size bound")
    if not payload.endswith(b"\n"):
        raise SchemaError("delivery archive is not cleanly newline-terminated")
    lines = payload.splitlines()
    if not 2 <= len(lines) <= MAX_JSONL_LINES:
        raise SchemaError("delivery archive line count is outside its bound")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line or len(line) > MAX_JSONL_LINE_BYTES:
            raise SchemaError(f"invalid delivery archive line {line_number}")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SchemaError(f"invalid delivery JSON at line {line_number}") from exc
        if not isinstance(value, dict):
            raise SchemaError(f"delivery line {line_number} must be an object")
        records.append(value)
    return records


def _common_binding(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": contract["session_id"],
        "trial_id": contract["trial_id"],
        "security_mode": contract["security_mode"],
        "policy_sha256": contract["policy_sha256"],
        "source_id": contract["source_id"],
        "source_enclave": contract["source_enclave"],
        "protected_sink_id": contract["protected_sink_id"],
        "protected_enclave": contract["protected_enclave"],
        "canary_topic": contract["canary_topic"],
    }


def _validate_health(
    value: Any,
    *,
    contract: dict[str, Any],
    record_count: int,
    open_time: datetime,
    close_time: datetime,
    heartbeat_times: Sequence[datetime],
) -> dict[str, Any]:
    expected = {
        "status",
        "clean_shutdown",
        "truncated",
        "parse_errors",
        "write_errors",
        "dropped_records",
        "monotonic_regressions",
        "heartbeat_count",
        "first_heartbeat_utc",
        "last_heartbeat_utc",
        "maximum_observed_heartbeat_gap_ms",
        "records_written",
    }
    health = _expect_exact_keys(value, expected, "collector health")
    if health["status"] != "healthy":
        raise SchemaError("collector status is not healthy")
    if health["clean_shutdown"] is not True or health["truncated"] is not False:
        raise SchemaError("collector did not close a complete archive")
    for field in ("parse_errors", "write_errors", "dropped_records", "monotonic_regressions"):
        if _bounded_int(health[field], field, 0, 1_000_000) != 0:
            raise SchemaError(f"collector health reports non-zero {field}")
    heartbeats = _bounded_int(health["heartbeat_count"], "heartbeat_count", 0, 1_000_000)
    if heartbeats != len(heartbeat_times):
        raise SchemaError("collector heartbeat_count does not match heartbeat records")
    if heartbeats < contract["collector_requirements"]["minimum_heartbeats"]:
        raise SchemaError("collector heartbeat count is insufficient")
    observed_gap = health["maximum_observed_heartbeat_gap_ms"]
    if (
        isinstance(observed_gap, bool)
        or not isinstance(observed_gap, (int, float))
        or not math.isfinite(float(observed_gap))
        or not 0 <= float(observed_gap)
        <= contract["collector_requirements"]["maximum_heartbeat_gap_ms"]
    ):
        raise SchemaError("collector heartbeat gap exceeds its contract")
    first_heartbeat = _utc(health["first_heartbeat_utc"], "first_heartbeat_utc")
    last_heartbeat = _utc(health["last_heartbeat_utc"], "last_heartbeat_utc")
    if not heartbeat_times or heartbeat_times != sorted(heartbeat_times):
        raise SchemaError("collector heartbeat records are missing or reordered")
    if first_heartbeat != heartbeat_times[0] or last_heartbeat != heartbeat_times[-1]:
        raise SchemaError("collector heartbeat endpoints do not match heartbeat records")
    derived_gaps = [
        (right - left).total_seconds() * 1000.0
        for left, right in zip(heartbeat_times, heartbeat_times[1:])
    ]
    derived_maximum_gap = max(derived_gaps, default=0.0)
    if not math.isclose(float(observed_gap), derived_maximum_gap, rel_tol=0.0, abs_tol=1e-6):
        raise SchemaError("collector heartbeat gap does not match heartbeat records")
    start = contract["window"]["start"]
    end = contract["window"]["end"]
    if not (open_time <= first_heartbeat <= start <= end <= last_heartbeat <= close_time):
        raise SchemaError("collector heartbeats do not bracket the full evidence window")
    if _bounded_int(health["records_written"], "records_written", 2, MAX_JSONL_LINES) != record_count:
        raise SchemaError("collector records_written does not match the archive")
    return {
        **health,
        "maximum_observed_heartbeat_gap_ms": float(observed_gap),
    }


def _validate_archive(role: str, contract: dict[str, Any]) -> dict[str, Any]:
    if role not in ARCHIVE_ROLES:
        raise SchemaError("unsupported delivery archive role")
    archive = contract["archives"][role]
    records = _read_jsonl(archive["path"])
    machine = _ArchiveStateMachine(role)
    binding = _common_binding(contract)
    collector_id: str | None = None
    collector_boot_id: str | None = None
    timestamps: list[datetime] = []
    heartbeat_times: list[datetime] = []
    body: list[dict[str, Any]] = []

    for index, record in enumerate(records):
        kind = machine.consume(record)
        if kind == "open":
            expected_keys = _COMMON_RECORD_KEYS
        elif kind == "close":
            expected_keys = _COMMON_RECORD_KEYS | {"data_record_count", "collector_health"}
        elif kind == "body":
            expected_keys = _COMMON_RECORD_KEYS | {"sequence", "payload_sha256"}
        else:
            expected_keys = _COMMON_RECORD_KEYS
        _expect_exact_keys(record, expected_keys, f"{role} archive record {index}")
        if record["schema_version"] != ARCHIVE_RECORD_SCHEMA:
            raise SchemaError("unsupported delivery archive record schema")
        if record["role"] != role:
            raise SchemaError(f"cross-role record in {role} archive")
        for field, expected_value in binding.items():
            if record[field] != expected_value:
                raise SchemaError(f"cross-{field} record in {role} archive")
        current_collector = _token(record["collector_id"], "collector_id")
        current_boot = _token(record["collector_boot_id"], "collector_boot_id")
        if collector_id is None:
            collector_id, collector_boot_id = current_collector, current_boot
        elif (current_collector, current_boot) != (collector_id, collector_boot_id):
            raise SchemaError(f"collector identity changed inside {role} archive")
        timestamp = _utc(record["ts_utc"], "record ts_utc")
        timestamps.append(timestamp)
        if kind == "body":
            if not contract["window"]["start"] <= timestamp <= contract["window"]["end"]:
                raise SchemaError(f"{role} canary record is outside the UTC window")
            body.append(
                {
                    "sequence": _bounded_int(record["sequence"], "canary sequence", 0, 2**63 - 1),
                    "payload_sha256": _hex64(record["payload_sha256"], "payload_sha256"),
                }
            )
        elif kind == "heartbeat":
            heartbeat_times.append(timestamp)

    machine.finish()
    if timestamps != sorted(timestamps):
        raise SchemaError(f"{role} archive timestamps regress")
    if timestamps[0] > contract["window"]["start"] or timestamps[-1] < contract["window"]["end"]:
        raise SchemaError(f"{role} archive does not cover the full UTC window")

    close = records[-1]
    if _bounded_int(close["data_record_count"], "data_record_count", 0, MAX_ATTEMPTS) != len(body):
        raise SchemaError(f"{role} data_record_count mismatch")
    health = _validate_health(
        close["collector_health"],
        contract=contract,
        record_count=len(records),
        open_time=timestamps[0],
        close_time=timestamps[-1],
        heartbeat_times=heartbeat_times,
    )

    canary_sequences = [item["sequence"] for item in body]
    if len(canary_sequences) != len(set(canary_sequences)) or canary_sequences != sorted(canary_sequences):
        raise SchemaError(f"{role} canary sequence is duplicated or reordered")
    if role == "attempted":
        first = contract["expected_first_sequence"]
        count = contract["expected_attempt_count"]
        if canary_sequences != list(range(first, first + count)):
            raise SchemaError("attempted canary sequence is missing, duplicated, or truncated")

    return {
        "role": role,
        "collector_id": collector_id,
        "collector_boot_id": collector_boot_id,
        "records": body,
        "health": health,
        "archive": {
            "path": archive["relative_path"],
            "sha256": archive["sha256"],
            "bytes": archive["bytes"],
            "record_count": len(records),
            "data_record_count": len(body),
        },
    }


def _attempt_set_sha256(records: Sequence[dict[str, Any]]) -> str:
    canonical = json.dumps(
        list(records), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _expected_canary_sha256(trial_id: str, sequence: int) -> str:
    return hashlib.sha256(f"{trial_id}:{sequence}".encode("utf-8")).hexdigest()


def _normalized_stimulus_sha256(sequences: Sequence[int]) -> str:
    canonical = json.dumps(
        list(sequences), separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _build_report(contract_path: Path, contract: dict[str, Any]) -> dict[str, Any]:
    attempted = _validate_archive("attempted", contract)
    received = _validate_archive("protected_received", contract)
    if (
        attempted["collector_id"] == received["collector_id"]
        or attempted["collector_boot_id"] == received["collector_boot_id"]
    ):
        raise SchemaError("attempt and receipt archives require independent collectors")

    attempt_by_sequence = {item["sequence"]: item["payload_sha256"] for item in attempted["records"]}
    received_by_sequence = {item["sequence"]: item["payload_sha256"] for item in received["records"]}
    for sequence, digest in attempt_by_sequence.items():
        if digest != _expected_canary_sha256(contract["trial_id"], sequence):
            raise SchemaError("attempted canary does not match the deterministic payload scheme")
    unexpected = sorted(set(received_by_sequence) - set(attempt_by_sequence))
    if unexpected:
        raise SchemaError("received archive contains a canary that was never attempted")
    for sequence, digest in received_by_sequence.items():
        if attempt_by_sequence[sequence] != digest:
            raise SchemaError("received canary payload digest does not match its attempt")

    attempted_sequences = sorted(attempt_by_sequence)
    delivered_sequences = sorted(received_by_sequence)
    undelivered_sequences = sorted(set(attempted_sequences) - set(delivered_sequences))
    attempted_count = len(attempted_sequences)
    delivered_count = len(delivered_sequences)
    blocked_count = len(undelivered_sequences)
    if delivered_count == 0:
        observed = "zero_delivery"
    elif delivered_count == attempted_count:
        observed = "full_delivery"
    else:
        observed = "partial_delivery"
    authorization = contract["publisher_authorization"]
    expected = authorization["expected_delivery"]
    passed = observed == expected

    if expected == "zero_delivery":
        confusion = {"tp": blocked_count, "fn": delivered_count, "fp": 0, "tn": 0}
    else:
        confusion = {"tp": 0, "fn": 0, "fp": blocked_count, "tn": delivered_count}

    return {
        "schema_version": REPORT_SCHEMA,
        "created_utc": utc_now(),
        "pair_id": contract["pair_id"],
        "pairing_attested": contract["pairing_attested"],
        "trial_id": contract["trial_id"],
        "session_id": contract["session_id"],
        "security_mode": contract["security_mode"],
        "policy_sha256": contract["policy_sha256"],
        "bindings": {
            "source_id": contract["source_id"],
            "source_enclave": contract["source_enclave"],
            "protected_sink_id": contract["protected_sink_id"],
            "protected_enclave": contract["protected_enclave"],
            "canary_topic": contract["canary_topic"],
            "window_start_utc": contract["window"]["start_utc"],
            "window_end_utc": contract["window"]["end_utc"],
        },
        "publisher_authorization": dict(authorization),
        "integrity": {
            "contract_sha256": sha256_file(contract_path),
            "attempt_set_sha256": _attempt_set_sha256(attempted["records"]),
            "normalized_stimulus_sha256": _normalized_stimulus_sha256(
                attempted_sequences
            ),
            "payload_scheme": "trial_id_colon_sequence/v1",
            "attempted_archive": attempted["archive"],
            "protected_received_archive": received["archive"],
            "archive_sequences_continuous": True,
            "collector_health_verified": True,
        },
        "evidence_basis": {
            "attempt_source": "publisher_application_canary_archive",
            "receipt_source": "protected_subscriber_application_canary_archive",
            "vendor_security_log_used_as_ground_truth": False,
            "claim_scope": "direct_canary_delivery_only",
            "collector_authenticity_attested": False,
            "publisher_authorization_context_attested": authorization[
                "context_attested"
            ],
            "pairing_attested": contract["pairing_attested"],
        },
        "classification_semantics": {
            "positive_condition": "policy_expected_zero_delivery",
            "negative_condition": "policy_expected_full_delivery",
            "tp": "expected_zero_and_canary_not_received",
            "fn": "expected_zero_but_canary_received",
            "fp": "expected_full_but_canary_not_received",
            "tn": "expected_full_and_canary_received",
        },
        "result": {
            "evaluable": True,
            "expected": expected,
            "expected_reason": authorization["expected_reason"],
            "observed": observed,
            "passed": passed,
            "attempted_count": attempted_count,
            "delivered_count": delivered_count,
            "blocked_count": blocked_count,
            "attempted_sequences": attempted_sequences,
            "delivered_sequences": delivered_sequences,
            "undelivered_sequences": undelivered_sequences,
        },
        "confusion_matrix": confusion,
        "safety": {
            "offline_verification_only": True,
            "network_activity_performed": False,
            "network_action_performed": False,
            "source_ip_attribution_verified": False,
            "automatic_ip_block_authorized": False,
            "deployment_eligible": False,
            "executable": False,
            "adapter": "none",
        },
    }


def _write_json_refuse_overwrite(path_value: str | Path, value: Any) -> None:
    """Atomically publish JSON without ever replacing an existing path."""

    destination = Path(path_value)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing output: {destination}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError:
            raise FileExistsError(f"refusing to overwrite existing output: {destination}") from None
    finally:
        temporary.unlink(missing_ok=True)


def verify_delivery_evidence(
    contract_path: str | Path,
    *,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Verify one two-ended evidence contract without any live action."""

    path, contract = _load_contract(contract_path)
    report = _build_report(path, contract)
    if output_path is not None:
        _write_json_refuse_overwrite(output_path, report)
    return report


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def aggregate_delivery_evidence(
    contract_paths: Iterable[str | Path],
    *,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Re-verify paired contracts and aggregate message-level TP/FN/FP/TN."""

    paths = [Path(path) for path in contract_paths]
    if not paths:
        raise SchemaError("at least one delivery contract is required")
    reports = [verify_delivery_evidence(path) for path in paths]
    if len({report["session_id"] for report in reports}) != len(reports):
        raise SchemaError("aggregate contains a duplicate session_id")
    if len({report["integrity"]["contract_sha256"] for report in reports}) != len(reports):
        raise SchemaError("aggregate contains a duplicate delivery contract")

    by_pair: dict[str, dict[str, dict[str, Any]]] = {}
    for report in reports:
        mode_map = by_pair.setdefault(report["pair_id"], {})
        if report["security_mode"] in mode_map:
            raise SchemaError("each pair must contain exactly one session per security mode")
        mode_map[report["security_mode"]] = report
    for pair_id, mode_map in by_pair.items():
        if set(mode_map) != SECURITY_MODES:
            raise SchemaError(f"pair {pair_id} is not a complete permissive/enforce pair")
        permissive = mode_map["permissive"]
        enforce = mode_map["enforce"]
        for field in (
            "policy_sha256",
            "bindings",
        ):
            left = permissive[field]
            right = enforce[field]
            if field == "bindings":
                left = {key: value for key, value in left.items() if not key.startswith("window_")}
                right = {key: value for key, value in right.items() if not key.startswith("window_")}
            if left != right:
                raise SchemaError(f"paired evidence {pair_id} has mismatched {field}")
        for field in ("authorization_case", "subject_enclave", "topic"):
            if permissive["publisher_authorization"][field] != enforce[
                "publisher_authorization"
            ][field]:
                raise SchemaError(
                    f"paired evidence {pair_id} has mismatched authorization {field}"
                )
        if permissive["integrity"]["normalized_stimulus_sha256"] != enforce[
            "integrity"
        ]["normalized_stimulus_sha256"]:
            raise SchemaError(f"paired evidence {pair_id} did not attempt the same canaries")

    confusion = {
        key: sum(report["confusion_matrix"][key] for report in reports)
        for key in ("tp", "fn", "fp", "tn")
    }
    total = sum(confusion.values())
    tpr = _safe_ratio(confusion["tp"], confusion["tp"] + confusion["fn"])
    tnr = _safe_ratio(confusion["tn"], confusion["tn"] + confusion["fp"])
    metrics = {
        "true_positive_rate": tpr,
        "false_negative_rate": _safe_ratio(confusion["fn"], confusion["tp"] + confusion["fn"]),
        "true_negative_rate": tnr,
        "false_positive_rate": _safe_ratio(confusion["fp"], confusion["fp"] + confusion["tn"]),
        "accuracy": _safe_ratio(confusion["tp"] + confusion["tn"], total),
        "balanced_accuracy": None if tpr is None or tnr is None else (tpr + tnr) / 2.0,
    }
    result = {
        "schema_version": AGGREGATE_SCHEMA,
        "created_utc": utc_now(),
        "evidence_basis": {
            "ground_truth": "paired_direct_application_delivery",
            "vendor_security_log_used_as_ground_truth": False,
            "all_inputs_reverified": True,
            "all_sessions_paired": True,
            "publisher_authorization_contexts_all_attested": all(
                report["publisher_authorization"]["context_attested"]
                for report in reports
            ),
            "all_pairings_attested": all(
                report["pairing_attested"] for report in reports
            ),
        },
        "classification_semantics": {
            "positive_condition": "policy_expected_zero_delivery",
            "negative_condition": "policy_expected_full_delivery",
            "tp": "expected_zero_and_canary_not_received",
            "fn": "expected_zero_but_canary_received",
            "fp": "expected_full_but_canary_not_received",
            "tn": "expected_full_and_canary_received",
        },
        "counts": {
            "pairs": len(by_pair),
            "trials": len(reports),
            "sessions": len(reports),
            "messages": total,
            "passed_sessions": sum(1 for report in reports if report["result"]["passed"]),
        },
        "confusion_matrix": confusion,
        "metrics": metrics,
        "sessions": [
            {
                "trial_id": report["trial_id"],
                "pair_id": report["pair_id"],
                "pairing_attested": report["pairing_attested"],
                "session_id": report["session_id"],
                "security_mode": report["security_mode"],
                "contract_sha256": report["integrity"]["contract_sha256"],
                "observed": report["result"]["observed"],
                "passed": report["result"]["passed"],
            }
            for report in sorted(reports, key=lambda item: (item["pair_id"], item["security_mode"]))
        ],
        "safety": {
            "offline_verification_only": True,
            "network_activity_performed": False,
            "network_action_performed": False,
            "source_ip_attribution_verified": False,
            "automatic_ip_block_authorized": False,
            "deployment_eligible": False,
            "executable": False,
            "adapter": "none",
        },
    }
    if output_path is not None:
        _write_json_refuse_overwrite(output_path, result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="verify one sealed two-ended contract")
    verify.add_argument("--contract", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    aggregate = subparsers.add_parser("aggregate", help="verify and aggregate paired contracts")
    aggregate.add_argument("--contract", type=Path, action="append", required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify":
        report = verify_delivery_evidence(args.contract, output_path=args.output)
        summary = {
            "output": str(args.output),
            "session_id": report["session_id"],
            "observed": report["result"]["observed"],
            "passed": report["result"]["passed"],
            "executable": False,
        }
    else:
        report = aggregate_delivery_evidence(args.contract, output_path=args.output)
        summary = {
            "output": str(args.output),
            "pairs": report["counts"]["pairs"],
            "sessions": report["counts"]["sessions"],
            "confusion_matrix": report["confusion_matrix"],
            "executable": False,
        }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
