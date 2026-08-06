#!/usr/bin/env python3
"""Build leak-resistant firewall features from generated session evidence."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .live_telemetry_collector import validate_telemetry_event
from .schema import (
    LABEL_SCHEMA_VERSION,
    SCHEMA_VERSION,
    SchemaError,
    atomic_write_json,
)


SESSION_COLUMNS = [
    "session_id",
    "group_id",
    "scenario_id",
    "attack_class",
    "binary",
    "security_mode",
    "ros_domain_id",
    "seed",
    "origin",
    "training_eligible",
    "status",
    "intensity",
    "label_duration_sec",
    "event_count",
    "resource_samples",
    "load1_mean",
    "load1_max",
    "pcap_bytes",
    "attack_stdout_lines",
    "attack_stderr_lines",
    "auth_failure_mentions",
    "permission_deny_mentions",
    "attack_return_code",
    "expected_action",
    "policy_sha256",
]
NETWORK_COLUMNS = [
    "session_id",
    "group_id",
    "capture_id",
    "scenario_id",
    "security_mode",
    "ros_domain_id",
    "origin",
    "source",
    "window",
    "window_start_unix",
    "conn_count",
    "conn_rate",
    "uniq_dst_ports",
    "uniq_dst_hosts",
    "spdp_ratio",
    "meta_ratio",
    "userdata_ratio",
    "mcast_ratio",
    "dst_port_entropy",
    "interarrival_cv",
    "burstiness",
    "dominant_port_ratio",
    "dominant_host_ratio",
    "tuple_repeat_ratio",
    "label",
    "binary",
    "label_scope",
    "training_eligible",
    "evaluation_eligible",
    "policy_sha256",
]
TELEMETRY_FEATURES = [
    "sros_auth_fail_rate",
    "sros_permission_deny_rate",
    "participant_churn_rate",
    "unknown_node_rate",
    "hmac_failure_rate",
    "nonce_reuse_ratio",
    "channel_mismatch_ratio",
    "timestamp_violation_ratio",
    "publisher_violation_ratio",
    "parameter_call_rate",
    "oversized_message_ratio",
    "qos_drop_ratio",
    "heartbeat_gap_sec",
    "control_conflict_ratio",
    "scan_static_ratio",
    "odom_cmd_mismatch_ratio",
    "alert_reflection_ratio",
    "log_reject_rate",
]
TELEMETRY_COLUMNS = [
    "session_id",
    "group_id",
    "scenario_id",
    "security_mode",
    "ros_domain_id",
    "origin",
    "window",
    "window_start_unix",
    "telemetry_event_count",
    "collector_tick_count",
    *TELEMETRY_FEATURES,
    "label",
    "binary",
    "label_scope",
    "training_eligible",
    "evaluation_eligible",
    "policy_sha256",
]
FUSION_COLUMNS = NETWORK_COLUMNS + TELEMETRY_FEATURES
OBSERVATION_COLUMNS = [
    "session_id",
    "group_id",
    "scenario_id",
    "security_mode",
    "sample_index",
    "participant_count",
    "spdp_rate",
    "data_rate",
    "auth_failures",
    "permission_denies",
    "label",
    "binary",
    "training_eligible",
]


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SchemaError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    result = []
    if not path.is_file():
        return result
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SchemaError(
                    f"invalid JSONL at {path}:{line_number}"
                ) from exc
            if not isinstance(value, dict):
                raise SchemaError(
                    f"JSONL row must be object at {path}:{line_number}"
                )
            result.append(value)
    return result


def discover_sessions(dataset_root: str | Path) -> list[Path]:
    root = Path(dataset_root)
    if not root.is_dir() or root.is_symlink():
        raise FileNotFoundError(f"invalid dataset root: {root}")
    sessions = []
    for manifest in sorted(root.glob("*/manifest.json")):
        session_dir = manifest.parent
        if session_dir.is_symlink() or manifest.is_symlink():
            raise SchemaError(f"session evidence may not be symlinked: {session_dir}")
        sessions.append(session_dir)
    return sessions


def load_manifest(session_dir: Path) -> dict[str, Any]:
    manifest = _read_json(session_dir / "manifest.json")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise SchemaError(
            f"unsupported manifest schema in {session_dir.name}"
        )
    if manifest.get("session_id") != session_dir.name:
        raise SchemaError(
            f"session directory/name mismatch: {session_dir.name}"
        )
    return manifest


def load_label_intervals(session_dir: Path) -> list[dict[str, Any]]:
    labels = _read_jsonl(session_dir / "labels.jsonl")
    for label in labels:
        if label.get("schema_version") != LABEL_SCHEMA_VERSION:
            raise SchemaError(f"invalid label schema in {session_dir.name}")
        start = label.get("start_unix_ns")
        end = label.get("end_unix_ns")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start <= 0
            or end < start
        ):
            raise SchemaError(f"invalid label interval in {session_dir.name}")
    return labels


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for _ in handle)


def _security_mentions(session_dir: Path) -> tuple[int, int]:
    auth_pattern = re.compile(
        r"auth(?:entication)?\s*(?:failed|failure)|"
        r"couldn.?t find security files|unauthenticated",
        re.IGNORECASE,
    )
    deny_pattern = re.compile(
        r"permission(?:s)?\s*(?:denied|deny|rejected)|"
        r"access control|not allowed",
        re.IGNORECASE,
    )
    auth = 0
    deny = 0
    for path in session_dir.rglob("*.log"):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= 200_000:
                    break
                auth += int(bool(auth_pattern.search(line)))
                deny += int(bool(deny_pattern.search(line)))
    return auth, deny


def _resource_features(session_dir: Path) -> tuple[int, float, float]:
    samples = _read_jsonl(session_dir / "resources.jsonl")
    load1 = []
    for sample in samples:
        values = sample.get("load_average")
        if (
            isinstance(values, list)
            and values
            and isinstance(values[0], (int, float))
            and not isinstance(values[0], bool)
            and math.isfinite(float(values[0]))
        ):
            load1.append(float(values[0]))
    return (
        len(samples),
        round(statistics.fmean(load1), 6) if load1 else 0.0,
        round(max(load1), 6) if load1 else 0.0,
    )


def build_session_row(
    session_dir: Path,
    manifest: dict[str, Any],
    labels: list[dict[str, Any]],
) -> dict[str, Any]:
    event_count = len(_read_jsonl(session_dir / "events.jsonl"))
    resource_count, load_mean, load_max = _resource_features(session_dir)
    auth_mentions, deny_mentions = _security_mentions(session_dir)
    pcap = session_dir / "traffic.pcapng"
    label_duration = sum(
        max(0, label["end_unix_ns"] - label["start_unix_ns"])
        for label in labels
    ) / 1_000_000_000
    attack_process = (
        manifest.get("result", {}).get("attack_process")
        if isinstance(manifest.get("result"), dict)
        else None
    )
    return {
        "session_id": manifest["session_id"],
        "group_id": manifest["session_id"],
        "scenario_id": manifest["scenario_id"],
        "attack_class": manifest["attack_class"],
        "binary": manifest["binary_label"],
        "security_mode": manifest["security_mode"],
        "ros_domain_id": manifest["ros_domain_id"],
        "seed": manifest["seed"],
        "origin": manifest["origin"],
        "training_eligible": bool(manifest["training_eligible"]),
        "status": manifest["status"],
        "intensity": manifest.get("randomization", {}).get("intensity", 0.0),
        "label_duration_sec": round(label_duration, 6),
        "event_count": event_count,
        "resource_samples": resource_count,
        "load1_mean": load_mean,
        "load1_max": load_max,
        "pcap_bytes": pcap.stat().st_size if pcap.is_file() else 0,
        "attack_stdout_lines": _line_count(
            session_dir / "attack.stdout.log"
        ),
        "attack_stderr_lines": _line_count(
            session_dir / "attack.stderr.log"
        ),
        "auth_failure_mentions": auth_mentions,
        "permission_deny_mentions": deny_mentions,
        "attack_return_code": (
            attack_process.get("return_code")
            if isinstance(attack_process, dict)
            else ""
        ),
        "expected_action": manifest["expected_action"],
        "policy_sha256": manifest["policy_sha256"],
    }


def _is_multicast(address: str) -> bool:
    try:
        first = int(address.split(".", 1)[0])
    except (ValueError, IndexError):
        return False
    return 224 <= first <= 239


def _entropy(counts: Iterable[int]) -> float:
    values = list(counts)
    total = sum(values)
    if total <= 0:
        return 0.0
    result = 0.0
    for count in values:
        if count > 0:
            probability = count / total
            result -= probability * math.log2(probability)
    return result


def _temporal_shape(timestamps: list[float]) -> tuple[float, float]:
    ordered = sorted(timestamps)
    deltas = [
        later - earlier
        for earlier, later in zip(ordered, ordered[1:])
        if later >= earlier
    ]
    if not deltas:
        return 0.0, 0.0
    mean = statistics.fmean(deltas)
    deviation = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
    coefficient = deviation / mean if mean > 0 else 0.0
    denominator = deviation + mean
    burstiness = (
        (deviation - mean) / denominator if denominator > 0 else 0.0
    )
    return min(coefficient, 1_000_000.0), burstiness


def _load_zeek_conn(path: Path) -> list[dict[str, str]]:
    fields = None
    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("#fields"):
                fields = line.rstrip("\r\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if fields is None:
                raise SchemaError(f"Zeek conn.log has no #fields header: {path}")
            values = line.rstrip("\r\n").split("\t")
            if len(values) != len(fields):
                continue
            rows.append(dict(zip(fields, values)))
    return rows


def _label_at(
    midpoint_unix_ns: int,
    intervals: list[dict[str, Any]],
) -> tuple[str, str]:
    for label in intervals:
        if label["start_unix_ns"] <= midpoint_unix_ns <= label["end_unix_ns"]:
            return str(label["attack_class"]), str(label["scope"])
    return "normal", "session_window"


def build_network_rows(
    session_dir: Path,
    manifest: dict[str, Any],
    labels: list[dict[str, Any]],
    *,
    window_sec: float,
) -> list[dict[str, Any]]:
    conn_path = session_dir / "zeek" / "conn.log"
    if not conn_path.is_file():
        return []
    rows = _load_zeek_conn(conn_path)
    parsed = []
    for row in rows:
        try:
            timestamp = float(row["ts"])
            source = row["id.orig_h"]
            destination = row["id.resp_h"]
            port = int(row["id.resp_p"])
        except (KeyError, TypeError, ValueError):
            continue
        if not math.isfinite(timestamp) or not source:
            continue
        parsed.append((timestamp, source, destination, port))
    if not parsed:
        return []

    t0 = min(item[0] for item in parsed)
    grouped: dict[tuple[str, int], list[tuple[float, str, str, int]]] = (
        defaultdict(list)
    )
    for item in parsed:
        window = int((item[0] - t0) // window_sec)
        grouped[(item[1], window)].append(item)

    domain = int(manifest["ros_domain_id"])
    base_port = 7400 + 250 * domain
    spdp_port = base_port
    meta_ports = {base_port + 10, base_port + 11, base_port + 12}
    userdata_low = base_port + 13
    userdata_high = base_port + 249
    result = []
    for (source, window), group in sorted(grouped.items()):
        ports = [item[3] for item in group]
        destinations = [item[2] for item in group]
        timestamps = [item[0] for item in group]
        count = len(group)
        midpoint_seconds = statistics.fmean(item[0] for item in group)
        midpoint_ns = int(midpoint_seconds * 1_000_000_000)
        label, label_scope = _label_at(midpoint_ns, labels)
        port_counts = Counter(ports)
        host_counts = Counter(destinations)
        tuple_counts = Counter(
            (item[2], item[3]) for item in group
        )
        interarrival_cv, burstiness = _temporal_shape(timestamps)
        result.append(
            {
                "session_id": manifest["session_id"],
                "group_id": manifest["session_id"],
                "capture_id": manifest["session_id"],
                "scenario_id": manifest["scenario_id"],
                "security_mode": manifest["security_mode"],
                "ros_domain_id": domain,
                "origin": manifest["origin"],
                "source": source,
                "window": window,
                "window_start_unix": round(t0 + window * window_sec, 6),
                "conn_count": count,
                "conn_rate": round(count / window_sec, 6),
                "uniq_dst_ports": len(set(ports)),
                "uniq_dst_hosts": len(set(destinations)),
                "spdp_ratio": round(ports.count(spdp_port) / count, 6),
                "meta_ratio": round(
                    sum(port in meta_ports for port in ports) / count, 6
                ),
                "userdata_ratio": round(
                    sum(
                        userdata_low <= port <= userdata_high
                        for port in ports
                    )
                    / count,
                    6,
                ),
                "mcast_ratio": round(
                    sum(_is_multicast(item) for item in destinations) / count,
                    6,
                ),
                "dst_port_entropy": round(
                    _entropy(port_counts.values()), 6
                ),
                "interarrival_cv": round(interarrival_cv, 6),
                "burstiness": round(burstiness, 6),
                "dominant_port_ratio": round(
                    max(port_counts.values()) / count, 6
                ),
                "dominant_host_ratio": round(
                    max(host_counts.values()) / count, 6
                ),
                "tuple_repeat_ratio": round(
                    sum(
                        max(repetitions - 1, 0)
                        for repetitions in tuple_counts.values()
                    )
                    / count,
                    6,
                ),
                "label": label,
                "binary": "normal" if label == "normal" else "attack",
                "label_scope": label_scope,
                "training_eligible": bool(manifest["training_eligible"]),
                "evaluation_eligible": bool(
                    manifest["training_eligible"]
                    and manifest["origin"] == "live_lab"
                ),
                "policy_sha256": manifest["policy_sha256"],
            }
        )
    return result


def load_telemetry_events(session_dir: Path) -> list[dict[str, Any]]:
    """Load one canonical, ordered telemetry stream for a session."""
    path = session_dir / "telemetry_events.jsonl"
    if not path.is_file():
        return []
    events = [validate_telemetry_event(item) for item in _read_jsonl(path)]
    if any(item["session_id"] != session_dir.name for item in events):
        raise SchemaError(
            f"telemetry session_id mismatch in {session_dir.name}"
        )
    sequences = [int(item["sequence"]) for item in events]
    if sequences != list(range(len(events))):
        raise SchemaError(
            f"telemetry sequence gap or reorder in {session_dir.name}"
        )
    timestamps = [int(item["ts_unix_ns"]) for item in events]
    if timestamps != sorted(timestamps):
        raise SchemaError(
            f"telemetry timestamps are not monotonic in {session_dir.name}"
        )
    return events


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return min(1.0, max(0.0, numerator / denominator))


def _new_telemetry_accumulator() -> dict[str, float]:
    return defaultdict(float)


# Event types the collector accepts and live ROS nodes really emit, but which
# do not currently feed any of the 18 telemetry features.  They belong to the
# local-outcome / evidence workflow rather than the model input.
#
# Before this set existed the dispatcher below raised on anything it did not
# recognise, on the assumption that the collector had already rejected it.  The
# 2026-08-06 loopback pilot disproved that: velocity_guard_node emits
# ``guard_input`` on its very first accepted command, so every live feature
# build died with "unsupported telemetry event_type: guard_input" before a
# single row was written.  Naming the non-contributing types explicitly keeps
# the fail-closed guarantee for genuinely unknown types while letting live
# sessions build.
#
# ``guard_input``, ``guard_output`` and ``authenticated_action`` are parked here
# only until their feature semantics are agreed; step 1 of the contract
# alignment moves them out and maps them onto real feature accumulators.
NON_FEATURE_TELEMETRY_EVENTS = frozenset(
    {
        "authenticated_action",
        "controlled_fault_injection",
        "delivery_probe",
        "guard_input",
        "guard_output",
        "guard_state",
        "outcome_marker",
        "parameter_digest",
        "parameter_veto",
        "process_health",
        "state_digest",
        "topic_probe",
    }
)


def _accumulate_telemetry(
    accumulator: dict[str, float],
    event: dict[str, Any],
) -> None:
    event_type = event["event_type"]
    details = event["details"]
    accumulator["telemetry_event_count"] += 1
    if event_type == "collector_tick":
        accumulator["collector_tick_count"] += 1
    elif event_type == "sros_auth_failure":
        accumulator["sros_auth_failures"] += details["count"]
    elif event_type == "sros_permission_denied":
        accumulator["sros_permission_denies"] += details["count"]
    elif event_type == "participant_change":
        accumulator["participant_changes"] += details["count"]
    elif event_type == "unknown_node":
        accumulator["unknown_nodes"] += details["count"]
    elif event_type == "hmac_validation":
        accumulator["hmac_count"] += details["count"]
        accumulator["hmac_valid"] += details["valid_count"]
        accumulator["nonce_reuse"] += details["nonce_reuse_count"]
        accumulator["channel_mismatch"] += details[
            "channel_mismatch_count"
        ]
        accumulator["timestamp_violation"] += details[
            "timestamp_violation_count"
        ]
    elif event_type == "publisher_observation":
        accumulator["publisher_count"] += details["count"]
        accumulator["publisher_violation"] += details["violation_count"]
    elif event_type == "parameter_call":
        accumulator["parameter_calls"] += details["count"]
    elif event_type == "message_validation":
        accumulator["message_count"] += details["count"]
        accumulator["oversized_messages"] += details["oversized_count"]
    elif event_type == "qos_delivery":
        accumulator["qos_expected"] += details["expected_count"]
        accumulator["qos_delivered"] += details["delivered_count"]
    elif event_type == "heartbeat_observation":
        accumulator["heartbeat_gap_sec"] = max(
            accumulator["heartbeat_gap_sec"], details["gap_sec"]
        )
    elif event_type == "control_observation":
        accumulator["control_count"] += details["count"]
        accumulator["control_conflicts"] += details["conflict_count"]
    elif event_type == "scan_observation":
        accumulator["scan_count"] += details["count"]
        accumulator["scan_static"] += details["static_count"]
    elif event_type == "odom_cmd_observation":
        accumulator["odom_cmd_count"] += details["count"]
        accumulator["odom_cmd_mismatch"] += details["mismatch_count"]
    elif event_type == "alert_observation":
        accumulator["alert_count"] += details["count"]
        accumulator["alert_reflection"] += details["reflection_count"]
    elif event_type == "log_reject":
        accumulator["log_rejects"] += details["count"]
    elif event_type == "hmac_result":
        accumulator["hmac_count"] += 1
        if details["outcome"] == "accepted":
            accumulator["hmac_valid"] += 1
        elif details["reason"] == "nonce_reuse_or_capacity":
            accumulator["nonce_reuse"] += 1
        elif details["reason"] == "channel_mismatch":
            accumulator["channel_mismatch"] += 1
        elif details["reason"] == "timestamp_violation":
            accumulator["timestamp_violation"] += 1
    elif event_type == "detector_state":
        # Transition evidence is intentionally sparse.  Incidents contribute a
        # positive observation; recovery remains present in raw JSONL evidence
        # without inflating the feature numerator.
        incident = details["state"] == "incident"
        detector = details["detector"]
        if detector in {"d1", "d2"}:
            accumulator["control_count"] += 1
            accumulator["control_conflicts"] += int(incident)
        elif detector == "d3":
            accumulator["scan_count"] += 1
            accumulator["scan_static"] += int(incident)
        elif detector == "d4":
            accumulator["publisher_count"] += 1
            accumulator["publisher_violation"] += int(incident)
        elif detector == "d6":
            accumulator["odom_cmd_count"] += 1
            accumulator["odom_cmd_mismatch"] += int(incident)
    elif event_type == "authenticated_heartbeat_state":
        accumulator["heartbeat_gap_sec"] = max(
            accumulator["heartbeat_gap_sec"], details["gap_sec"]
        )
    elif event_type == "graph_state":
        if details["state"] in {"fault", "overflow"}:
            accumulator["log_rejects"] += 1
    elif event_type == "sros2_deny":
        if details["kind"] == "authentication":
            accumulator["sros_auth_failures"] += details["count"]
        else:
            accumulator["sros_permission_denies"] += details["count"]
    elif event_type in NON_FEATURE_TELEMETRY_EVENTS:
        # Counted in telemetry_event_count above, but contributes no feature.
        return
    else:
        # Reached when the collector gains an event type that no one taught the
        # feature builder about.  Fail closed rather than silently dropping a
        # signal the model may depend on.
        raise SchemaError(f"unsupported telemetry event_type: {event_type}")


def _telemetry_feature_values(
    accumulator: dict[str, float],
    *,
    window_sec: float,
) -> dict[str, float]:
    hmac_count = accumulator["hmac_count"]
    hmac_failures = max(0.0, hmac_count - accumulator["hmac_valid"])
    qos_expected = accumulator["qos_expected"]
    qos_dropped = max(
        0.0, qos_expected - accumulator["qos_delivered"]
    )
    return {
        "sros_auth_fail_rate": round(
            accumulator["sros_auth_failures"] / window_sec, 6
        ),
        "sros_permission_deny_rate": round(
            accumulator["sros_permission_denies"] / window_sec, 6
        ),
        "participant_churn_rate": round(
            accumulator["participant_changes"] / window_sec, 6
        ),
        "unknown_node_rate": round(
            accumulator["unknown_nodes"] / window_sec, 6
        ),
        "hmac_failure_rate": round(hmac_failures / window_sec, 6),
        "nonce_reuse_ratio": round(
            _safe_ratio(accumulator["nonce_reuse"], hmac_count), 6
        ),
        "channel_mismatch_ratio": round(
            _safe_ratio(accumulator["channel_mismatch"], hmac_count), 6
        ),
        "timestamp_violation_ratio": round(
            _safe_ratio(accumulator["timestamp_violation"], hmac_count), 6
        ),
        "publisher_violation_ratio": round(
            _safe_ratio(
                accumulator["publisher_violation"],
                accumulator["publisher_count"],
            ),
            6,
        ),
        "parameter_call_rate": round(
            accumulator["parameter_calls"] / window_sec, 6
        ),
        "oversized_message_ratio": round(
            _safe_ratio(
                accumulator["oversized_messages"],
                accumulator["message_count"],
            ),
            6,
        ),
        "qos_drop_ratio": round(
            _safe_ratio(qos_dropped, qos_expected), 6
        ),
        "heartbeat_gap_sec": round(
            accumulator["heartbeat_gap_sec"], 6
        ),
        "control_conflict_ratio": round(
            _safe_ratio(
                accumulator["control_conflicts"],
                accumulator["control_count"],
            ),
            6,
        ),
        "scan_static_ratio": round(
            _safe_ratio(
                accumulator["scan_static"], accumulator["scan_count"]
            ),
            6,
        ),
        "odom_cmd_mismatch_ratio": round(
            _safe_ratio(
                accumulator["odom_cmd_mismatch"],
                accumulator["odom_cmd_count"],
            ),
            6,
        ),
        "alert_reflection_ratio": round(
            _safe_ratio(
                accumulator["alert_reflection"],
                accumulator["alert_count"],
            ),
            6,
        ),
        "log_reject_rate": round(
            accumulator["log_rejects"] / window_sec, 6
        ),
    }


def build_telemetry_rows(
    session_dir: Path,
    manifest: dict[str, Any],
    network_rows: list[dict[str, Any]],
    *,
    window_sec: float,
) -> list[dict[str, Any]]:
    """Aggregate raw events into the exact network session/window grid."""
    events = load_telemetry_events(session_dir)
    if not events or not network_rows:
        return []
    windows = sorted({int(row["window"]) for row in network_rows})
    starts: dict[int, set[float]] = defaultdict(set)
    labels: dict[int, set[tuple[str, str, str]]] = defaultdict(set)
    for row in network_rows:
        window = int(row["window"])
        starts[window].add(float(row["window_start_unix"]))
        labels[window].add(
            (str(row["label"]), str(row["binary"]), str(row["label_scope"]))
        )
    if any(len(values) != 1 for values in starts.values()):
        raise SchemaError(
            f"network window start disagreement in {session_dir.name}"
        )
    if any(len(values) != 1 for values in labels.values()):
        raise SchemaError(
            f"network label disagreement in {session_dir.name}"
        )
    t0_values = {
        next(iter(starts[window])) - window * window_sec
        for window in windows
    }
    if len({round(value, 6) for value in t0_values}) != 1:
        raise SchemaError(f"network window grid drift in {session_dir.name}")
    t0 = min(t0_values)
    accumulators = {
        window: _new_telemetry_accumulator() for window in windows
    }
    for event in events:
        event_seconds = int(event["ts_unix_ns"]) / 1_000_000_000
        window = math.floor((event_seconds - t0) / window_sec)
        if window in accumulators:
            _accumulate_telemetry(accumulators[window], event)

    result = []
    for window in windows:
        accumulator = accumulators[window]
        label, binary, label_scope = next(iter(labels[window]))
        result.append(
            {
                "session_id": manifest["session_id"],
                "group_id": manifest["session_id"],
                "scenario_id": manifest["scenario_id"],
                "security_mode": manifest["security_mode"],
                "ros_domain_id": manifest["ros_domain_id"],
                "origin": manifest["origin"],
                "window": window,
                "window_start_unix": round(next(iter(starts[window])), 6),
                "telemetry_event_count": int(
                    accumulator["telemetry_event_count"]
                ),
                "collector_tick_count": int(
                    accumulator["collector_tick_count"]
                ),
                **_telemetry_feature_values(
                    accumulator, window_sec=window_sec
                ),
                "label": label,
                "binary": binary,
                "label_scope": label_scope,
                "training_eligible": bool(manifest["training_eligible"]),
                "evaluation_eligible": bool(
                    manifest["training_eligible"]
                    and manifest["origin"] == "live_lab"
                ),
                "policy_sha256": manifest["policy_sha256"],
            }
        )
    return result


def build_fusion_rows(
    network_rows: list[dict[str, Any]],
    telemetry_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_key = {
        (row["session_id"], int(row["window"])): row
        for row in telemetry_rows
    }
    if len(by_key) != len(telemetry_rows):
        raise SchemaError("duplicate telemetry session/window key")
    result = []
    for network in network_rows:
        telemetry = by_key.get(
            (network["session_id"], int(network["window"]))
        )
        if telemetry is None:
            continue
        for name in ("label", "binary", "security_mode", "policy_sha256"):
            if telemetry[name] != network[name]:
                raise SchemaError(
                    "network/telemetry metadata mismatch for "
                    f"{network['session_id']} window={network['window']}"
                )
        result.append(
            {
                **network,
                **{name: telemetry[name] for name in TELEMETRY_FEATURES},
            }
        )
    return result


def validate_multimodal_quality(
    network_rows: list[dict[str, Any]],
    telemetry_rows: list[dict[str, Any]],
    fusion_rows: list[dict[str, Any]],
) -> None:
    """Fail closed when an eligible live session has incomplete alignment."""
    expected_keys = {
        (row["session_id"], int(row["window"])) for row in network_rows
    }
    actual_keys = {
        (row["session_id"], int(row["window"])) for row in telemetry_rows
    }
    if expected_keys != actual_keys:
        raise SchemaError(
            "telemetry does not cover every network session/window"
        )
    if len(fusion_rows) != len(network_rows):
        raise SchemaError("fusion row count does not match network row count")
    ratio_features = {
        "nonce_reuse_ratio",
        "channel_mismatch_ratio",
        "timestamp_violation_ratio",
        "publisher_violation_ratio",
        "oversized_message_ratio",
        "qos_drop_ratio",
        "control_conflict_ratio",
        "scan_static_ratio",
        "odom_cmd_mismatch_ratio",
        "alert_reflection_ratio",
    }
    for row in telemetry_rows:
        if int(row["collector_tick_count"]) <= 0:
            raise SchemaError(
                "telemetry window has no collector_tick evidence"
            )
        for name in TELEMETRY_FEATURES:
            value = row[name]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0.0
                or (name in ratio_features and float(value) > 1.0)
            ):
                raise SchemaError(f"invalid live telemetry feature: {name}")


def build_observation_rows(
    session_dir: Path,
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    observations = _read_jsonl(
        session_dir / "smoke_observations.jsonl"
    )
    result = []
    for item in observations:
        label = str(item.get("label", "normal"))
        result.append(
            {
                "session_id": manifest["session_id"],
                "group_id": manifest["session_id"],
                "scenario_id": manifest["scenario_id"],
                "security_mode": manifest["security_mode"],
                "sample_index": item.get("sample_index", 0),
                "participant_count": item.get("participant_count", 0),
                "spdp_rate": item.get("spdp_rate", 0.0),
                "data_rate": item.get("data_rate", 0.0),
                "auth_failures": item.get("auth_failures", 0),
                "permission_denies": item.get("permission_denies", 0),
                "label": label,
                "binary": "normal" if label == "normal" else "attack",
                # Smoke observations remain false even with
                # --include-nontrainable.
                "training_eligible": False,
            }
        )
    return result


def _write_csv(
    path: Path,
    columns: list[str],
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=columns,
            extrasaction="raise",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def build_features(
    *,
    dataset_root: str | Path,
    output_dir: str | Path,
    include_nontrainable: bool = False,
    window_sec: float = 8.0,
    require_multimodal: bool = False,
) -> dict[str, int]:
    if (
        isinstance(window_sec, bool)
        or not isinstance(window_sec, (int, float))
        or not math.isfinite(float(window_sec))
        or not 0.5 <= float(window_sec) <= 300
    ):
        raise ValueError("window_sec must be finite and in 0.5..300")
    session_rows = []
    network_rows = []
    telemetry_rows = []
    fusion_rows = []
    observation_rows = []
    skipped = 0
    missing_multimodal_sessions = 0
    for session_dir in discover_sessions(dataset_root):
        manifest = load_manifest(session_dir)
        if manifest.get("status") != "complete":
            skipped += 1
            continue
        if not include_nontrainable and not manifest.get("training_eligible"):
            skipped += 1
            continue
        labels = load_label_intervals(session_dir)
        if len(labels) != 1:
            raise SchemaError(
                f"{session_dir.name} must have exactly one canonical interval"
            )
        session_rows.append(
            build_session_row(session_dir, manifest, labels)
        )
        session_network = build_network_rows(
            session_dir,
            manifest,
            labels,
            window_sec=float(window_sec),
        )
        network_rows.extend(session_network)
        session_telemetry = build_telemetry_rows(
            session_dir,
            manifest,
            session_network,
            window_sec=float(window_sec),
        )
        session_fusion = build_fusion_rows(
            session_network, session_telemetry
        )
        telemetry_rows.extend(session_telemetry)
        fusion_rows.extend(session_fusion)
        eligible_live = bool(
            manifest.get("training_eligible")
            and manifest.get("origin") == "live_lab"
        )
        if eligible_live and (
            not session_network or not session_telemetry
        ):
            missing_multimodal_sessions += 1
        if require_multimodal and eligible_live:
            if not session_network:
                raise SchemaError(
                    f"eligible live session has no network rows: "
                    f"{session_dir.name}"
                )
            validate_multimodal_quality(
                session_network,
                session_telemetry,
                session_fusion,
            )
        if include_nontrainable:
            observation_rows.extend(
                build_observation_rows(session_dir, manifest)
            )

    output = Path(output_dir)
    _write_csv(output / "session_features.csv", SESSION_COLUMNS, session_rows)
    _write_csv(output / "network_features.csv", NETWORK_COLUMNS, network_rows)
    _write_csv(
        output / "telemetry_features.csv",
        TELEMETRY_COLUMNS,
        telemetry_rows,
    )
    _write_csv(output / "fusion_features.csv", FUSION_COLUMNS, fusion_rows)
    _write_csv(
        output / "smoke_observation_features.csv",
        OBSERVATION_COLUMNS,
        observation_rows,
    )
    summary = {
        "schema_version": "sros2-firewall-feature-build/v1",
        "session_rows": len(session_rows),
        "network_rows": len(network_rows),
        "telemetry_rows": len(telemetry_rows),
        "fusion_rows": len(fusion_rows),
        "smoke_observation_rows": len(observation_rows),
        "skipped_sessions": skipped,
        "missing_multimodal_sessions": missing_multimodal_sessions,
        "include_nontrainable": include_nontrainable,
        "require_multimodal": require_multimodal,
        "window_sec": float(window_sec),
        "grouping": "session_id",
    }
    atomic_write_json(output / "feature_build.json", summary)
    return {
        "session_rows": len(session_rows),
        "network_rows": len(network_rows),
        "telemetry_rows": len(telemetry_rows),
        "fusion_rows": len(fusion_rows),
        "observation_rows": len(observation_rows),
        "skipped_sessions": skipped,
        "missing_multimodal_sessions": missing_multimodal_sessions,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build session-grouped SROS2 firewall features"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path(__file__).resolve().parent / "dataset",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "features",
    )
    parser.add_argument("--window-sec", type=float, default=8.0)
    parser.add_argument(
        "--include-nontrainable",
        action="store_true",
        help="QA only; smoke rows remain training_eligible=false",
    )
    parser.add_argument(
        "--require-multimodal",
        action="store_true",
        help=(
            "fail if any eligible live session lacks aligned telemetry/fusion"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    result = build_features(
        dataset_root=args.dataset,
        output_dir=args.output,
        include_nontrainable=args.include_nontrainable,
        window_sec=args.window_sec,
        require_multimodal=args.require_multimodal,
    )
    print(
        "✅ 特徵輸出完成："
        f"session={result['session_rows']}，"
        f"network={result['network_rows']}，"
        f"telemetry={result['telemetry_rows']}，"
        f"fusion={result['fusion_rows']}，"
        f"smoke={result['observation_rows']}，"
        f"skipped={result['skipped_sessions']}"
    )
    print("所有模型切分必須使用 group_id=session_id。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
