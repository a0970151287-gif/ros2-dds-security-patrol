#!/usr/bin/env python3
"""Collect bounded, secret-free telemetry events for one firewall session.

The collector is deliberately independent from ROS so it can be tested without
starting Gazebo or sending DDS traffic.  Runtime producers send small JSON
records through stdin (or a local file); this process validates and persists a
canonical append-only JSONL stream.  It never accepts commands, credentials, or
arbitrary feature names.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import socket
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterable, TextIO

from .evidence import JsonlWriter
from .schema import SchemaError, require_identifier, safe_json_value


TELEMETRY_EVENT_SCHEMA_VERSION = "sros2-firewall-live-telemetry-event/v1"
TELEMETRY_INPUT_SCHEMA_VERSION = "sros2-firewall-telemetry-input/v1"
SESSION_ID_RE = re.compile(
    r"[0-9]{8}T[0-9]{12}Z_[a-z][a-z0-9_]{0,63}_[0-9a-f]{8}"
)
MAX_COUNTER = 10_000_000
MAX_HEARTBEAT_GAP_SEC = 300.0
MAX_GRAPH_NODE_COUNT = 100_000
MAX_RUNTIME_DATAGRAM_BYTES = 4096
MAX_RUNTIME_TIMESTAMP_SKEW_NS = 5_000_000_000
MAX_RUNTIME_EVENTS_PER_SEC = 128
RUNTIME_TELEMETRY_SCHEMA_VERSION = "sros2-firewall-runtime-telemetry/v1"

HMAC_REASONS = frozenset(
    {
        "accepted",
        "invalid_configuration",
        "invalid_input",
        "malformed_envelope",
        "invalid_signature",
        "malformed_body",
        "channel_mismatch",
        "timestamp_violation",
        "nonce_reuse_or_capacity",
    }
)
DETECTORS = frozenset({"d1", "d2", "d3", "d4", "d5", "d6"})
DETECTOR_STATES = frozenset({"incident", "recovery"})
HEARTBEAT_STATES = frozenset({"gap", "recovery"})
GRAPH_STATES = frozenset({"fault", "overflow", "recovery"})
SROS2_DENY_KINDS = frozenset({"authentication", "permission", "governance"})
PROBE_TOPICS = frozenset({"scan", "odom", "imu", "cmd_vel"})
DELIVERY_PROBES = frozenset(
    {
        "unauthorized_participant",
        "hmac_forgery",
        "replay",
        "oversized_input",
        "valid_input",
    }
)
GUARD_STATES = frozenset({"locked", "released"})
GUARD_REASONS = frozenset(
    {
        "none",
        "monitor_lease_missing",
        "monitor_fault",
        "generic_alert",
        "source_none",
        "stale_command",
    }
)
AUTHENTICATED_ACTIONS = frozenset(
    {"heartbeat", "guard_lock", "guard_clear"}
)
PROCESS_STATES = frozenset({"healthy", "unhealthy"})
OUTCOME_MARKER_STAGES = {
    "normal_traffic_preserved": frozenset({"baseline"}),
    "unauthorized_participant_denied": frozenset({"trigger", "protected", "recovery"}),
    "hmac_forgery_dropped": frozenset({"trigger", "protected", "recovery"}),
    "replay_dropped": frozenset({"trigger", "protected", "recovery"}),
    "oversized_input_dropped": frozenset({"trigger", "protected", "recovery"}),
    "parameter_unchanged": frozenset({"baseline", "trigger", "protected", "recovery"}),
    "velocity_guard_zeroed": frozenset({"trigger", "protected"}),
    "velocity_guard_recovered": frozenset({"baseline", "trigger", "recovery"}),
    "graph_failure_fail_safe": frozenset({"trigger", "protected", "recovery"}),
}
CONTROLLED_FAULT_KINDS = frozenset({"graph_inspection"})
CONTROLLED_FAULT_STATES = frozenset({"trigger", "recovery"})


EVENT_DETAIL_KEYS: dict[str, frozenset[str]] = {
    "collector_tick": frozenset(),
    "sros_auth_failure": frozenset({"count"}),
    "sros_permission_denied": frozenset({"count"}),
    "participant_change": frozenset({"count"}),
    "unknown_node": frozenset({"count"}),
    "hmac_validation": frozenset(
        {
            "count",
            "valid_count",
            "nonce_reuse_count",
            "channel_mismatch_count",
            "timestamp_violation_count",
        }
    ),
    "publisher_observation": frozenset({"count", "violation_count"}),
    "parameter_call": frozenset({"count"}),
    "message_validation": frozenset({"count", "oversized_count"}),
    "qos_delivery": frozenset({"expected_count", "delivered_count"}),
    "heartbeat_observation": frozenset({"gap_sec"}),
    "control_observation": frozenset({"count", "conflict_count"}),
    "scan_observation": frozenset({"count", "static_count"}),
    "odom_cmd_observation": frozenset({"count", "mismatch_count"}),
    "alert_observation": frozenset({"count", "reflection_count"}),
    "log_reject": frozenset({"count"}),
    "hmac_result": frozenset({"outcome", "reason"}),
    "detector_state": frozenset({"detector", "state"}),
    "authenticated_heartbeat_state": frozenset({"state", "gap_sec"}),
    "graph_state": frozenset({"state", "node_count"}),
    "sros2_deny": frozenset({"kind", "count"}),
    # The following records are intentionally semantic but not verdicts.  A
    # dedicated read-only local probe and the velocity guard emit raw counts,
    # samples, transitions and digests; local_outcome_probe re-derives the nine
    # pass/fail facts from their ordered windows.
    "topic_probe": frozenset(
        {
            "topic",
            "message_count",
            "publisher_count",
            "authorized_publisher_count",
        }
    ),
    "delivery_probe": frozenset({"probe", "observed_count"}),
    "state_digest": frozenset({"name", "sha256"}),
    "parameter_digest": frozenset({"node", "parameter", "sha256"}),
    "process_health": frozenset({"node", "state"}),
    "guard_state": frozenset({"state", "reason"}),
    "authenticated_action": frozenset({"action"}),
    "guard_input": frozenset({"accepted_count"}),
    "guard_output": frozenset({"linear_x", "angular_z", "blocked"}),
    "parameter_veto": frozenset({"count"}),
    "outcome_marker": frozenset({"check_id", "stage", "boundary"}),
    "controlled_fault_injection": frozenset({"kind", "state"}),
}


def _require_session_id(value: Any) -> str:
    if not isinstance(value, str) or not SESSION_ID_RE.fullmatch(value):
        raise SchemaError("invalid telemetry session_id")
    return value


def _require_counter(value: Any, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_COUNTER
    ):
        raise SchemaError(f"{name} must be an integer in 0..{MAX_COUNTER}")
    return value


def _require_timestamp(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SchemaError(f"{name} must be a positive integer")
    return value


def _validate_details(event_type: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SchemaError("telemetry details must be an object")
    expected = EVENT_DETAIL_KEYS[event_type]
    if set(value) != expected:
        raise SchemaError(
            f"unexpected detail keys for {event_type}: "
            f"expected={sorted(expected)}"
        )
    if event_type in {"heartbeat_observation", "authenticated_heartbeat_state"}:
        gap = value["gap_sec"]
        if (
            isinstance(gap, bool)
            or not isinstance(gap, (int, float))
            or not math.isfinite(float(gap))
            or not 0.0 <= float(gap) <= MAX_HEARTBEAT_GAP_SEC
        ):
            raise SchemaError(
                "heartbeat gap_sec must be finite and in 0..300"
            )
        if event_type == "heartbeat_observation":
            return {"gap_sec": float(gap)}
        state = value["state"]
        if state not in HEARTBEAT_STATES:
            raise SchemaError("unsupported authenticated heartbeat state")
        return {"state": state, "gap_sec": float(gap)}

    if event_type == "hmac_result":
        outcome = value["outcome"]
        reason = value["reason"]
        if outcome not in {"accepted", "rejected"} or reason not in HMAC_REASONS:
            raise SchemaError("unsupported HMAC outcome or reason")
        if (outcome == "accepted") != (reason == "accepted"):
            raise SchemaError("HMAC outcome and reason disagree")
        return {"outcome": outcome, "reason": reason}

    if event_type == "detector_state":
        detector = value["detector"]
        state = value["state"]
        if detector not in DETECTORS or state not in DETECTOR_STATES:
            raise SchemaError("unsupported detector or detector state")
        return {"detector": detector, "state": state}

    if event_type == "graph_state":
        state_value = value["state"]
        node_count = value["node_count"]
        if state_value not in GRAPH_STATES:
            raise SchemaError("unsupported graph state")
        if (
            isinstance(node_count, bool)
            or not isinstance(node_count, int)
            or not -1 <= node_count <= MAX_GRAPH_NODE_COUNT
        ):
            raise SchemaError("graph node_count must be in -1..100000")
        if state_value == "fault" and node_count != -1:
            raise SchemaError("graph fault must use node_count=-1")
        if state_value != "fault" and node_count < 0:
            raise SchemaError("graph overflow/recovery requires node_count >= 0")
        return {"state": state_value, "node_count": node_count}

    if event_type == "sros2_deny":
        kind = value["kind"]
        if kind not in SROS2_DENY_KINDS:
            raise SchemaError("unsupported SROS2 deny kind")
        return {
            "kind": kind,
            "count": _require_counter(value["count"], "details.count"),
        }

    if event_type == "topic_probe":
        topic = value["topic"]
        if topic not in PROBE_TOPICS:
            raise SchemaError("unsupported probe topic")
        result = {
            "topic": topic,
            "message_count": _require_counter(
                value["message_count"], "details.message_count"
            ),
            "publisher_count": _require_counter(
                value["publisher_count"], "details.publisher_count"
            ),
            "authorized_publisher_count": _require_counter(
                value["authorized_publisher_count"],
                "details.authorized_publisher_count",
            ),
        }
        if result["authorized_publisher_count"] > result["publisher_count"]:
            raise SchemaError(
                "authorized publisher count may not exceed publisher count"
            )
        return result

    if event_type == "delivery_probe":
        probe = value["probe"]
        if probe not in DELIVERY_PROBES:
            raise SchemaError("unsupported delivery probe")
        return {
            "probe": probe,
            "observed_count": _require_counter(
                value["observed_count"], "details.observed_count"
            ),
        }

    if event_type in {"state_digest", "parameter_digest"}:
        digest = value["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SchemaError(f"{event_type} requires lowercase SHA-256")
        if event_type == "state_digest":
            return {
                "name": require_identifier(value["name"], "state digest name"),
                "sha256": digest,
            }
        return {
            "node": require_identifier(value["node"], "parameter node"),
            "parameter": require_identifier(
                value["parameter"], "parameter name"
            ),
            "sha256": digest,
        }

    if event_type == "process_health":
        state_value = value["state"]
        if state_value not in PROCESS_STATES:
            raise SchemaError("unsupported process health state")
        return {
            "node": require_identifier(value["node"], "process node"),
            "state": state_value,
        }

    if event_type == "guard_state":
        state_value = value["state"]
        reason = value["reason"]
        if state_value not in GUARD_STATES or reason not in GUARD_REASONS:
            raise SchemaError("unsupported guard state or reason")
        if state_value == "released" and reason != "none":
            raise SchemaError("released guard state must use reason=none")
        if state_value == "locked" and reason == "none":
            raise SchemaError("locked guard state requires a blocking reason")
        return {"state": state_value, "reason": reason}

    if event_type == "authenticated_action":
        action = value["action"]
        if action not in AUTHENTICATED_ACTIONS:
            raise SchemaError("unsupported authenticated action")
        return {"action": action}

    if event_type == "guard_input":
        return {
            "accepted_count": _require_counter(
                value["accepted_count"], "details.accepted_count"
            )
        }

    if event_type == "guard_output":
        linear_x = value["linear_x"]
        angular_z = value["angular_z"]
        if any(
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            or abs(float(item)) > 1_000.0
            for item in (linear_x, angular_z)
        ):
            raise SchemaError("guard output must contain bounded finite values")
        if not isinstance(value["blocked"], bool):
            raise SchemaError("guard output blocked must be boolean")
        return {
            "linear_x": float(linear_x),
            "angular_z": float(angular_z),
            "blocked": value["blocked"],
        }

    if event_type == "parameter_veto":
        return {
            "count": _require_counter(value["count"], "details.count")
        }

    if event_type == "outcome_marker":
        check_id = value["check_id"]
        stage = value["stage"]
        boundary = value["boundary"]
        if (
            check_id not in OUTCOME_MARKER_STAGES
            or stage not in OUTCOME_MARKER_STAGES[check_id]
            or boundary not in {"start", "end"}
        ):
            raise SchemaError("unsupported local outcome marker")
        return {"check_id": check_id, "stage": stage, "boundary": boundary}

    if event_type == "controlled_fault_injection":
        kind = value["kind"]
        state_value = value["state"]
        if kind not in CONTROLLED_FAULT_KINDS or state_value not in CONTROLLED_FAULT_STATES:
            raise SchemaError("unsupported controlled fault injection event")
        return {"kind": kind, "state": state_value}

    result = {
        key: _require_counter(value[key], f"details.{key}")
        for key in expected
    }
    denominator_pairs = {
        "hmac_validation": (
            "count",
            (
                "valid_count",
                "nonce_reuse_count",
                "channel_mismatch_count",
                "timestamp_violation_count",
            ),
        ),
        "publisher_observation": ("count", ("violation_count",)),
        "message_validation": ("count", ("oversized_count",)),
        "qos_delivery": ("expected_count", ("delivered_count",)),
        "control_observation": ("count", ("conflict_count",)),
        "scan_observation": ("count", ("static_count",)),
        "odom_cmd_observation": ("count", ("mismatch_count",)),
        "alert_observation": ("count", ("reflection_count",)),
    }
    pair = denominator_pairs.get(event_type)
    if pair is not None:
        denominator, numerators = pair
        if any(result[name] > result[denominator] for name in numerators):
            raise SchemaError(
                f"{event_type} numerator may not exceed {denominator}"
            )
    return result


def validate_telemetry_event(value: Any) -> dict[str, Any]:
    """Validate one canonical event and return a normalized safe copy."""
    expected = {
        "schema_version",
        "session_id",
        "sequence",
        "ts_unix_ns",
        "monotonic_ns",
        "source",
        "event_type",
        "details",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise SchemaError("telemetry event has unexpected keys")
    if value.get("schema_version") != TELEMETRY_EVENT_SCHEMA_VERSION:
        raise SchemaError("unsupported telemetry event schema")
    session_id = _require_session_id(value.get("session_id"))
    sequence = _require_counter(value.get("sequence"), "sequence")
    timestamp = _require_timestamp(value.get("ts_unix_ns"), "ts_unix_ns")
    monotonic = _require_timestamp(value.get("monotonic_ns"), "monotonic_ns")
    source = require_identifier(value.get("source"), "telemetry source")
    event_type = require_identifier(
        value.get("event_type"), "telemetry event_type"
    )
    if event_type not in EVENT_DETAIL_KEYS:
        raise SchemaError(f"unsupported telemetry event_type: {event_type}")
    details = _validate_details(event_type, value.get("details"))
    return safe_json_value(
        {
            "schema_version": TELEMETRY_EVENT_SCHEMA_VERSION,
            "session_id": session_id,
            "sequence": sequence,
            "ts_unix_ns": timestamp,
            "monotonic_ns": monotonic,
            "source": source,
            "event_type": event_type,
            "details": details,
        }
    )


def make_telemetry_event(
    *,
    session_id: str,
    sequence: int,
    source: str,
    event_type: str,
    details: dict[str, Any],
    ts_unix_ns: int | None = None,
    monotonic_ns: int | None = None,
) -> dict[str, Any]:
    return validate_telemetry_event(
        {
            "schema_version": TELEMETRY_EVENT_SCHEMA_VERSION,
            "session_id": session_id,
            "sequence": sequence,
            "ts_unix_ns": time.time_ns() if ts_unix_ns is None else ts_unix_ns,
            "monotonic_ns": (
                time.monotonic_ns() if monotonic_ns is None else monotonic_ns
            ),
            "source": source,
            "event_type": event_type,
            "details": details,
        }
    )


def validate_runtime_record(value: Any) -> dict[str, Any]:
    """Validate one producer datagram without trusting its timestamps/source."""
    expected = {
        "schema_version",
        "ts_unix_ns",
        "monotonic_ns",
        "source",
        "event_type",
        "details",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise SchemaError("runtime telemetry record has unexpected keys")
    if value.get("schema_version") != RUNTIME_TELEMETRY_SCHEMA_VERSION:
        raise SchemaError("unsupported runtime telemetry schema")
    source = require_identifier(value.get("source"), "telemetry source")
    event_type = require_identifier(
        value.get("event_type"), "telemetry event_type"
    )
    if event_type not in EVENT_DETAIL_KEYS:
        raise SchemaError(f"unsupported telemetry event_type: {event_type}")
    if event_type in {"collector_tick", "log_reject"}:
        raise SchemaError(f"runtime producer may not emit {event_type}")
    return safe_json_value(
        {
            "schema_version": RUNTIME_TELEMETRY_SCHEMA_VERSION,
            "ts_unix_ns": _require_timestamp(value.get("ts_unix_ns"), "ts_unix_ns"),
            "monotonic_ns": _require_timestamp(
                value.get("monotonic_ns"), "monotonic_ns"
            ),
            "source": source,
            "event_type": event_type,
            "details": _validate_details(event_type, value.get("details")),
        }
    )


class TelemetryCollector:
    """Single-writer collector for one session's append-only evidence."""

    def __init__(self, path: str | Path, *, session_id: str, source: str):
        self.path = Path(path)
        _require_session_id(session_id)
        require_identifier(source, "telemetry source")
        if self.path.exists() and self.path.is_symlink():
            raise SchemaError("telemetry output may not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink():
            raise SchemaError("telemetry output parent may not be a symlink")
        self.session_id = session_id
        self.source = source
        self.sequence = 0
        self._last_ts_unix_ns = 0
        self._last_monotonic_ns = 0
        self.writer = JsonlWriter(self.path)

    def emit(
        self,
        event_type: str,
        details: dict[str, Any],
        *,
        ts_unix_ns: int | None = None,
        monotonic_ns: int | None = None,
    ) -> dict[str, Any]:
        return self.emit_from(
            self.source,
            event_type,
            details,
            ts_unix_ns=ts_unix_ns,
            monotonic_ns=monotonic_ns,
        )

    def emit_from(
        self,
        source: str,
        event_type: str,
        details: dict[str, Any],
        *,
        ts_unix_ns: int | None = None,
        monotonic_ns: int | None = None,
    ) -> dict[str, Any]:
        """Append one event while the collector remains the only writer."""
        wall = time.time_ns() if ts_unix_ns is None else ts_unix_ns
        monotonic = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
        wall = _require_timestamp(wall, "ts_unix_ns")
        monotonic = _require_timestamp(monotonic, "monotonic_ns")
        # Multiple processes can create events in order A,B but the datagrams
        # arrive B,A.  Clamp by one nanosecond so canonical sequence and time
        # never disagree while preserving the observed wall-clock window.
        wall = max(wall, self._last_ts_unix_ns + 1)
        monotonic = max(monotonic, self._last_monotonic_ns + 1)
        event = make_telemetry_event(
            session_id=self.session_id,
            sequence=self.sequence,
            source=source,
            event_type=event_type,
            details=details,
            ts_unix_ns=wall,
            monotonic_ns=monotonic,
        )
        self.writer.append(event)
        self.sequence += 1
        self._last_ts_unix_ns = wall
        self._last_monotonic_ns = monotonic
        return event


def collect_records(
    records: Iterable[str],
    *,
    collector: TelemetryCollector,
) -> int:
    """Validate simple producer records and append canonical events."""
    count = 0
    for line_number, line in enumerate(records, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SchemaError(
                f"invalid telemetry input JSON at line {line_number}"
            ) from exc
        expected = {"schema_version", "event_type", "details"}
        optional = {"ts_unix_ns", "monotonic_ns"}
        if (
            not isinstance(value, dict)
            or not expected <= set(value)
            or not set(value) <= expected | optional
            or value.get("schema_version") != TELEMETRY_INPUT_SCHEMA_VERSION
        ):
            raise SchemaError(
                f"invalid telemetry input record at line {line_number}"
            )
        collector.emit(
            value["event_type"],
            value["details"],
            ts_unix_ns=value.get("ts_unix_ns"),
            monotonic_ns=value.get("monotonic_ns"),
        )
        count += 1
    return count


def ingest_runtime_datagram(
    payload: bytes,
    *,
    collector: TelemetryCollector,
) -> dict[str, Any]:
    """Validate one bounded datagram and append its canonical event."""
    if not isinstance(payload, bytes) or not payload:
        raise SchemaError("runtime telemetry datagram must be non-empty bytes")
    if len(payload) > MAX_RUNTIME_DATAGRAM_BYTES:
        raise SchemaError("runtime telemetry datagram exceeds size limit")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SchemaError("invalid runtime telemetry JSON") from exc
    record = validate_runtime_record(value)
    if (
        abs(int(record["ts_unix_ns"]) - time.time_ns())
        > MAX_RUNTIME_TIMESTAMP_SKEW_NS
        or abs(int(record["monotonic_ns"]) - time.monotonic_ns())
        > MAX_RUNTIME_TIMESTAMP_SKEW_NS
    ):
        raise SchemaError("runtime telemetry timestamp is outside local freshness bound")
    return collector.emit_from(
        record["source"],
        record["event_type"],
        record["details"],
        ts_unix_ns=record["ts_unix_ns"],
        monotonic_ns=record["monotonic_ns"],
    )


def _reclaim_stale_socket(path: Path) -> bool:
    """Remove a leftover socket file only when nothing is bound to it.

    Sessions share one fixed socket path, so a collector can start while the
    previous session's collector is still unlinking its socket.  On the
    2026-08-06 Permissive sweep that race failed two of nine sessions outright.

    Refusing every pre-existing path is too strict, but blindly unlinking would
    let one collector steal a live socket from another.  Probe it instead: a
    datagram socket with no listener refuses the connect, and only then is the
    file safe to remove.  Anything that is not a plain socket, or that answers,
    is left alone and still aborts startup.
    """
    try:
        info = path.lstat()
    except OSError:
        return False
    if not stat.S_ISSOCK(info.st_mode):
        return False
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        probe.settimeout(0.2)
        probe.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError):
        pass  # nothing bound -> stale
    except OSError:
        return False  # in use, or undecidable: do not touch it
    else:
        return False  # a live collector answered
    finally:
        probe.close()
    try:
        path.unlink()
    except OSError:
        return False
    return True


def _safe_remove_bound_socket(path: Path, inode: int) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(current.st_mode) and current.st_ino == inode:
        path.unlink()


def serve_runtime_socket(
    *,
    collector: TelemetryCollector,
    socket_path: str | Path,
    stop_event: threading.Event,
    tick_sec: float = 1.0,
    idle_timeout_sec: float = 0.0,
) -> int:
    """Receive local datagrams, rejecting malformed input without exiting."""
    if (
        isinstance(tick_sec, bool)
        or not isinstance(tick_sec, (int, float))
        or not math.isfinite(float(tick_sec))
        or not 0.1 <= float(tick_sec) <= 60.0
    ):
        raise ValueError("tick_sec must be finite and in 0.1..60")
    if (
        isinstance(idle_timeout_sec, bool)
        or not isinstance(idle_timeout_sec, (int, float))
        or not math.isfinite(float(idle_timeout_sec))
        or not 0.0 <= float(idle_timeout_sec) <= 86_400.0
    ):
        raise ValueError("idle_timeout_sec must be finite and in 0..86400")

    path = Path(socket_path)
    if path.is_symlink():
        raise SchemaError("telemetry socket path already exists")
    if path.exists() and not _reclaim_stale_socket(path):
        raise SchemaError("telemetry socket path already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise SchemaError("telemetry socket parent may not be a symlink")

    accepted = 0
    pending_rejects = 0
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    bound_inode = -1
    try:
        old_umask = os.umask(0o177)
        try:
            server.bind(str(path))
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)
        bound_inode = path.lstat().st_ino
        server.settimeout(min(0.2, float(tick_sec)))
        last_activity = time.monotonic()
        next_tick = last_activity
        rate_window_start = last_activity
        accepted_in_rate_window = 0

        while not stop_event.is_set():
            now = time.monotonic()
            if now >= next_tick:
                if pending_rejects:
                    collector.emit_from(
                        "telemetry_collector",
                        "log_reject",
                        {"count": pending_rejects},
                    )
                    pending_rejects = 0
                collector.emit_from("telemetry_collector", "collector_tick", {})
                next_tick = now + float(tick_sec)
            if now - rate_window_start >= 1.0:
                rate_window_start = now
                accepted_in_rate_window = 0
            if idle_timeout_sec and now - last_activity >= idle_timeout_sec:
                break
            try:
                payload, _ = server.recvfrom(MAX_RUNTIME_DATAGRAM_BYTES + 1)
            except socket.timeout:
                continue
            except OSError:
                if stop_event.is_set():
                    break
                raise
            last_activity = time.monotonic()
            if accepted_in_rate_window >= MAX_RUNTIME_EVENTS_PER_SEC:
                pending_rejects = min(MAX_COUNTER, pending_rejects + 1)
                continue
            try:
                ingest_runtime_datagram(payload, collector=collector)
            except SchemaError:
                pending_rejects = min(MAX_COUNTER, pending_rejects + 1)
                continue
            accepted += 1
            accepted_in_rate_window += 1
    finally:
        if pending_rejects:
            collector.emit_from(
                "telemetry_collector",
                "log_reject",
                {"count": pending_rejects},
            )
        server.close()
        if bound_inode >= 0:
            _safe_remove_bound_socket(path, bound_inode)
    return accepted


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and persist one local telemetry JSONL stream"
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--input",
        type=Path,
        default=None,
        help="producer JSONL; omit to read stdin",
    )
    source.add_argument(
        "--socket",
        type=Path,
        default=None,
        help="local Unix datagram socket for non-blocking runtime producers",
    )
    parser.add_argument("--tick-sec", type=float, default=1.0)
    parser.add_argument("--idle-timeout-sec", type=float, default=0.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    collector = TelemetryCollector(
        args.output,
        session_id=args.session_id,
        source=args.source,
    )
    if args.socket is not None:
        stop_event = threading.Event()

        def request_stop(_signum, _frame) -> None:
            stop_event.set()

        previous_term = signal.signal(signal.SIGTERM, request_stop)
        previous_int = signal.signal(signal.SIGINT, request_stop)
        try:
            count = serve_runtime_socket(
                collector=collector,
                socket_path=args.socket,
                stop_event=stop_event,
                tick_sec=args.tick_sec,
                idle_timeout_sec=args.idle_timeout_sec,
            )
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            signal.signal(signal.SIGINT, previous_int)
        print(f"telemetry_events={count} output={collector.path}")
        return 0
    handle: TextIO
    should_close = False
    if args.input is None:
        handle = sys.stdin
    else:
        if not args.input.is_file() or args.input.is_symlink():
            raise SystemExit("--input must be a regular non-symlink file")
        handle = args.input.open("r", encoding="utf-8")
        should_close = True
    try:
        count = collect_records(handle, collector=collector)
    finally:
        if should_close:
            handle.close()
    print(f"telemetry_events={count} output={collector.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
