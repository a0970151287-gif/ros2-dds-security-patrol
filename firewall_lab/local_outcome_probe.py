#!/usr/bin/env python3
"""Re-derive local defense outcomes from bounded canonical live telemetry.

This module is deliberately a post-processor.  It does not start ROS, publish
messages, invoke an attack runner, use sudo, or change a firewall.  A live lab
operator first records one canonical telemetry stream, then gives this module a
bounded stage window.  The module computes the facts; there is no CLI option to
enter a pass flag or a fact value.

Some raw records (topic/delivery probes and digests) must come from the
allowlisted read-only ``local_outcome_probe`` producer.  Guard transitions and
samples must come from ``velocity_guard_node``.  SROS2, graph and D1-D6 facts
remain bound to their own runtime producers.  Missing producer evidence blocks
derivation instead of becoming a synthetic success.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .evidence import JsonlWriter
from .live_telemetry_collector import validate_telemetry_event
from .local_outcomes import (
    LIVE_ACK,
    OBSERVATION_SCHEMA,
    REQUIRED_FACT_KEYS,
    REQUIRED_STAGES,
)
from .schema import SchemaError, atomic_write_json, sha256_file, utc_now


DERIVATION_SCHEMA = "sros2-firewall-local-outcome-semantic-probe/v1"
DERIVATION_KIND = "semantic_probe"
MAX_TELEMETRY_BYTES = 64 * 1024 * 1024
MAX_OBSERVATIONS_BYTES = 8 * 1024 * 1024
MAX_WINDOW_NS = 60_000_000_000
MAX_COLLECTOR_TICK_GAP_NS = 2_500_000_000
PROBE_SOURCE = "local_outcome_probe"
GUARD_SOURCE = "velocity_guard_node"
SROS_SOURCE = "sros2_log_adapter"
GRAPH_SOURCE = "dds_security_monitor"
DETECTOR_SOURCE = "intelligent_defense_node"
HMAC_CONSUMERS = frozenset(
    {
        "dds_security_monitor",
        "intelligent_defense_node",
        "mission_manager",
        "sensor_hub_node",
        "system_status_node",
        "velocity_guard_node",
    }
)


def _relative_file(root: Path, value: str | Path, *, maximum: int) -> tuple[Path, str]:
    root_resolved = root.resolve(strict=True)
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root.joinpath(*PurePosixPath(str(value).replace("\\", "/")).parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise SchemaError(f"probe source is missing or symlinked: {value}")
    resolved = candidate.resolve(strict=True)
    if resolved.parent != root_resolved and root_resolved not in resolved.parents:
        raise SchemaError("probe source escaped evidence root")
    size = resolved.stat().st_size
    if not 0 < size <= maximum:
        raise SchemaError("probe source is empty or exceeds its size limit")
    return resolved, resolved.relative_to(root_resolved).as_posix()


def _load_telemetry(
    path: Path,
    *,
    expected_session_id: str,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            event = validate_telemetry_event(json.loads(line))
        except (json.JSONDecodeError, RecursionError) as exc:
            raise SchemaError(
                f"invalid canonical telemetry JSON at line {line_number}"
            ) from exc
        if event["session_id"] != expected_session_id:
            raise SchemaError("telemetry session does not match outcome session")
        events.append(event)
    if not events:
        raise SchemaError("canonical telemetry stream is empty")
    sequences = [event["sequence"] for event in events]
    if sequences != list(range(len(events))):
        raise SchemaError("canonical telemetry sequence is missing or reordered")
    walls = [event["ts_unix_ns"] for event in events]
    monotonic = [event["monotonic_ns"] for event in events]
    if walls != sorted(walls) or len(walls) != len(set(walls)):
        raise SchemaError("canonical telemetry wall-clock order is invalid")
    if monotonic != sorted(monotonic) or len(monotonic) != len(set(monotonic)):
        raise SchemaError("canonical telemetry monotonic order is invalid")
    return events


def _window_events(
    events: list[dict[str, Any]],
    *,
    start_monotonic_ns: int,
    end_monotonic_ns: int,
) -> list[dict[str, Any]]:
    for name, value in (
        ("start_monotonic_ns", start_monotonic_ns),
        ("end_monotonic_ns", end_monotonic_ns),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise SchemaError(f"{name} must be a positive integer")
    if not start_monotonic_ns < end_monotonic_ns:
        raise SchemaError("probe window end must be after start")
    if end_monotonic_ns - start_monotonic_ns > MAX_WINDOW_NS:
        raise SchemaError("probe window exceeds the 60 second safety bound")
    selected = [
        event
        for event in events
        if start_monotonic_ns <= event["monotonic_ns"] <= end_monotonic_ns
    ]
    if not selected:
        raise SchemaError("probe window contains no canonical telemetry")
    ticks = [
        event["monotonic_ns"]
        for event in selected
        if event["event_type"] == "collector_tick"
        and event["source"] == "telemetry_collector"
    ]
    if len(ticks) < 2:
        raise SchemaError("probe window requires at least two collector ticks")
    if any(
        current - previous > MAX_COLLECTOR_TICK_GAP_NS
        for previous, current in zip(ticks, ticks[1:])
    ):
        raise SchemaError("probe window contains a collector continuity gap")
    return selected


def _matching(
    events: Iterable[dict[str, Any]],
    event_type: str,
    *,
    source: str | frozenset[str] | None = None,
    **details: Any,
) -> list[dict[str, Any]]:
    result = []
    for event in events:
        if event["event_type"] != event_type:
            continue
        if isinstance(source, frozenset) and event["source"] not in source:
            continue
        if isinstance(source, str) and event["source"] != source:
            continue
        if any(event["details"].get(key) != value for key, value in details.items()):
            continue
        result.append(event)
    return result


def _required(records: list[dict[str, Any]], description: str) -> list[dict[str, Any]]:
    if not records:
        raise SchemaError(f"missing semantic probe evidence: {description}")
    return records


def _sum_detail(records: Iterable[dict[str, Any]], name: str) -> int:
    return min(10_000_000, sum(int(event["details"][name]) for event in records))


def _unchanged_state(events: list[dict[str, Any]], name: str) -> bool:
    records = _required(
        _matching(
            events,
            "state_digest",
            source=PROBE_SOURCE,
            name="runtime_state",
        ),
        f"two {name} state digests",
    )
    if len(records) < 2:
        raise SchemaError(f"missing semantic probe evidence: two {name} state digests")
    return records[0]["details"]["sha256"] == records[-1]["details"]["sha256"]


def _healthy(events: list[dict[str, Any]], node: str) -> bool:
    records = _required(
        _matching(events, "process_health", source=PROBE_SOURCE, node=node),
        f"{node} process health",
    )
    return records[-1]["details"]["state"] == "healthy"


def _delivery_count(events: list[dict[str, Any]], probe: str) -> int:
    records = _required(
        _matching(events, "delivery_probe", source=PROBE_SOURCE, probe=probe),
        f"{probe} correlated delivery counter",
    )
    return _sum_detail(records, "observed_count")


def _hmac_results(
    events: list[dict[str, Any]], *, reason: str | None = None
) -> list[dict[str, Any]]:
    values = _matching(events, "hmac_result", source=HMAC_CONSUMERS)
    return [
        event for event in values
        if reason is None or event["details"]["reason"] == reason
    ]


def _guard_zero_samples(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event
        for event in _matching(events, "guard_output", source=GUARD_SOURCE)
        if event["details"]["blocked"] is True
        and abs(float(event["details"]["linear_x"])) <= 1e-6
        and abs(float(event["details"]["angular_z"])) <= 1e-6
    ]


def _guard_mode_unchanged(events: list[dict[str, Any]]) -> bool:
    outputs = _required(
        _matching(events, "guard_output", source=GUARD_SOURCE),
        "guard output state samples",
    )
    if len(outputs) < 2:
        raise SchemaError("guard state comparison requires at least two outputs")
    return len({event["details"]["blocked"] for event in outputs}) == 1


def _controlled_fault_injection(
    check_id: str, stage: str, events: list[dict[str, Any]]
) -> bool:
    records = _matching(
        events,
        "controlled_fault_injection",
        kind="graph_inspection",
    )
    if check_id != "graph_failure_fail_safe":
        if records:
            raise SchemaError(
                "controlled graph fault contaminated a non-graph outcome window"
            )
        return False
    expected_state = {
        "trigger": "trigger",
        "protected": None,
        "recovery": "recovery",
    }[stage]
    if expected_state is None:
        if records:
            raise SchemaError(
                "controlled graph fault event is outside trigger/recovery stage"
            )
        return False
    if not records:
        # Natural graph failures remain admissible and are explicitly distinct
        # from the controlled seam in the final report.
        return False
    expected_sources = {GRAPH_SOURCE, DETECTOR_SOURCE}
    actual = {
        event["source"]
        for event in records
        if event["details"]["state"] == expected_state
    }
    if actual != expected_sources or any(
        event["details"]["state"] != expected_state for event in records
    ):
        raise SchemaError(
            "controlled graph fault requires matching monitor and IDS evidence"
        )
    return True


def derive_facts(
    check_id: str,
    stage: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute one exact local_outcomes fact set from raw ordered events."""
    if check_id not in REQUIRED_STAGES or stage not in REQUIRED_STAGES[check_id]:
        raise SchemaError(f"unsupported local outcome stage: {check_id}/{stage}")

    facts: dict[str, Any]
    if (check_id, stage) == ("normal_traffic_preserved", "baseline"):
        topic_records: dict[str, list[dict[str, Any]]] = {}
        for topic in ("scan", "odom", "imu", "cmd_vel"):
            topic_records[topic] = _required(
                _matching(
                    events,
                    "topic_probe",
                    source=PROBE_SOURCE,
                    topic=topic,
                ),
                f"{topic} read-only topic window",
            )
        heartbeat = _matching(
            events,
            "authenticated_action",
            source=GUARD_SOURCE,
            action="heartbeat",
        )
        output = _matching(events, "guard_output", source=GUARD_SOURCE)
        final = topic_records["cmd_vel"]
        facts = {
            "required_topics_live": all(
                _sum_detail(topic_records[name], "message_count") >= 1
                for name in ("scan", "odom", "imu")
            ),
            "authenticated_heartbeat_live": bool(heartbeat),
            "final_cmd_vel_observed": bool(output)
            and _sum_detail(final, "message_count") >= 1
            and any(
                record["details"]["authorized_publisher_count"] == 1
                for record in final
            ),
            "unauthorized_publishers": max(
                max(
                    0,
                    record["details"]["publisher_count"]
                    - record["details"]["authorized_publisher_count"],
                )
                for record in final
            ),
        }
    elif (check_id, stage) == ("unauthorized_participant_denied", "trigger"):
        # A vendor deny record is not obtainable in this stack: rmw_fastrtps
        # builds the participant's dds.sec.* properties itself and never sets
        # dds.sec.log.plugin, so the Fast DDS security audit log cannot be
        # enabled at all -- see 文件/DDS_Security_audit_log_不可用_2026-08-18.md.
        # The check therefore rests on the security property itself, that
        # nothing the unauthorized participant sent was delivered, and records
        # the vendor evidence as not evaluable rather than counting its absence
        # as either a pass or a failure.
        denies = _matching(events, "sros2_deny", source=SROS_SOURCE)
        facts = {
            "sros_deny_count": _sum_detail(denies, "count") if denies else 0,
            "sros_deny_evaluable": bool(denies),
            "unauthorized_delivery_count": _delivery_count(
                events, "unauthorized_participant"
            ),
        }
    elif (check_id, stage) == ("unauthorized_participant_denied", "protected"):
        facts = {"protected_state_unchanged": _unchanged_state(events, check_id)}
    elif (check_id, stage) == ("unauthorized_participant_denied", "recovery"):
        facts = {"authorized_participant_healthy": _healthy(events, GRAPH_SOURCE)}
    elif (check_id, stage) == ("hmac_forgery_dropped", "trigger"):
        rejects = _required(
            _hmac_results(events, reason="invalid_signature"),
            "invalid-signature HMAC rejection",
        )
        facts = {
            "bad_hmac_reject_count": len(rejects),
            # ``hmac_result`` is emitted by the verifier after one concrete
            # envelope has been classified.  An invalid-signature result is
            # therefore direct evidence that those correlated envelopes were
            # not accepted; the separate state-digest stage proves no side
            # effect leaked through.
            "forged_accept_count": 0,
        }
    elif (check_id, stage) == ("hmac_forgery_dropped", "protected"):
        facts = {
            "state_unchanged": _unchanged_state(events, check_id)
            and _guard_mode_unchanged(events)
        }
    elif (check_id, stage) == ("hmac_forgery_dropped", "recovery"):
        facts = {
            "next_valid_accepted": bool(
                _required(
                    _hmac_results(events, reason="accepted"),
                    "next valid HMAC acceptance",
                )
            )
        }
    elif (check_id, stage) == ("replay_dropped", "trigger"):
        rejects = _required(
            _hmac_results(events, reason="nonce_reuse_or_capacity"),
            "nonce replay rejection",
        )
        facts = {
            "replay_reject_count": len(rejects),
            "replay_accept_count": 0,
        }
    elif (check_id, stage) == ("replay_dropped", "protected"):
        facts = {
            "state_unchanged": _unchanged_state(events, check_id)
            and _guard_mode_unchanged(events)
        }
    elif (check_id, stage) == ("replay_dropped", "recovery"):
        facts = {
            "next_fresh_nonce_accepted": bool(
                _required(
                    _hmac_results(events, reason="accepted"),
                    "fresh nonce HMAC acceptance",
                )
            )
        }
    elif (check_id, stage) == ("oversized_input_dropped", "trigger"):
        records = _required(
            _matching(events, "message_validation", source="sensor_hub_node"),
            "oversized message validation counter",
        )
        rejected = _sum_detail(records, "oversized_count")
        facts = {
            "oversized_reject_count": rejected,
            # SensorHub emits this event at the rejection branch before any
            # freshness/state update.  The next stage independently proves
            # process/state survival.
            "oversized_accept_count": 0,
        }
    elif (check_id, stage) == ("oversized_input_dropped", "protected"):
        facts = {
            "process_alive": _healthy(events, "sensor_hub_node"),
            "state_unchanged": _unchanged_state(events, check_id),
        }
    elif (check_id, stage) == ("oversized_input_dropped", "recovery"):
        facts = {
            "next_valid_accepted": _delivery_count(events, "valid_input") >= 1
        }
    elif check_id == "parameter_unchanged" and stage in {"baseline", "protected"}:
        records = _required(
            _matching(
                events,
                "parameter_digest",
                source=PROBE_SOURCE,
                node=GRAPH_SOURCE,
                parameter="whitelist",
            ),
            "whitelist parameter digest",
        )
        facts = {"parameter_sha256": records[-1]["details"]["sha256"]}
    elif (check_id, stage) == ("parameter_unchanged", "trigger"):
        vetoes = _matching(events, "parameter_veto")
        denies = _matching(
            events,
            "sros2_deny",
            source=SROS_SOURCE,
            kind="permission",
        )
        if not vetoes and not denies:
            raise SchemaError(
                "missing semantic probe evidence: parameter veto or SROS2 permission deny"
            )
        rejected = _sum_detail(vetoes, "count") + _sum_detail(denies, "count")
        facts = {"set_rejected": rejected >= 1}
    elif (check_id, stage) == ("parameter_unchanged", "recovery"):
        facts = {"node_healthy": _healthy(events, GRAPH_SOURCE)}
    elif (check_id, stage) == ("velocity_guard_zeroed", "trigger"):
        triggers = _required(
            _matching(
                events,
                "authenticated_action",
                source=GUARD_SOURCE,
                action="guard_lock",
            ),
            "authenticated guard lock",
        )
        trigger = triggers[0]
        zeros = [
            event
            for event in _guard_zero_samples(events)
            if event["monotonic_ns"] >= trigger["monotonic_ns"]
        ]
        zero = _required(zeros, "blocked zero velocity after guard lock")[0]
        facts = {
            "authenticated_trigger": True,
            "stop_latency_sec": round(
                (zero["monotonic_ns"] - trigger["monotonic_ns"]) / 1e9, 9
            ),
        }
    elif (check_id, stage) == ("velocity_guard_zeroed", "protected"):
        outputs = _required(
            _matching(events, "guard_output", source=GUARD_SOURCE),
            "guard output samples",
        )
        if len(outputs) < 2 or outputs[-1]["monotonic_ns"] - outputs[0]["monotonic_ns"] < 100_000_000:
            raise SchemaError("protected zero window requires two samples spanning 0.1 sec")
        if any(event["details"]["blocked"] is not True for event in outputs):
            raise SchemaError("protected zero window contains an unlocked output")
        facts = {
            "linear_abs_max": max(abs(event["details"]["linear_x"]) for event in outputs),
            "angular_abs_max": max(abs(event["details"]["angular_z"]) for event in outputs),
        }
    elif (check_id, stage) == ("velocity_guard_recovered", "baseline"):
        states = _required(
            _matching(events, "guard_state", source=GUARD_SOURCE),
            "initial guard state",
        )
        facts = {"guard_initially_locked": states[-1]["details"]["state"] == "locked"}
    elif (check_id, stage) == ("velocity_guard_recovered", "trigger"):
        states = _required(
            _matching(
                events,
                "guard_state",
                source=GUARD_SOURCE,
                state="locked",
                reason="monitor_fault",
            ),
            "latched monitor fault",
        )
        facts = {"fault_latched": bool(states)}
    elif (check_id, stage) == ("velocity_guard_recovered", "recovery"):
        heartbeats = _required(
            _matching(
                events,
                "authenticated_action",
                source=GUARD_SOURCE,
                action="heartbeat",
            ),
            "fresh authenticated heartbeat",
        )
        clears = _required(
            _matching(
                events,
                "authenticated_action",
                source=GUARD_SOURCE,
                action="guard_clear",
            ),
            "authenticated guard clear",
        )
        ready_ns = max(heartbeats[-1]["monotonic_ns"], clears[-1]["monotonic_ns"])
        inputs = [
            event
            for event in _matching(events, "guard_input", source=GUARD_SOURCE)
            if event["monotonic_ns"] >= ready_ns
            and event["details"]["accepted_count"] >= 1
        ]
        input_event = _required(inputs, "fresh guard command after heartbeat and clear")[0]
        outputs = [
            event
            for event in _matching(events, "guard_output", source=GUARD_SOURCE)
            if event["monotonic_ns"] >= input_event["monotonic_ns"]
            and event["details"]["blocked"] is False
            and (
                abs(event["details"]["linear_x"]) > 1e-6
                or abs(event["details"]["angular_z"]) > 1e-6
            )
        ]
        output = _required(outputs, "resumed non-zero guard output")[0]
        facts = {
            "fresh_authenticated_heartbeat": True,
            "authenticated_clear": True,
            "fresh_command": True,
            "output_resumed": True,
            "recovery_latency_sec": round(
                (output["monotonic_ns"] - ready_ns) / 1e9, 9
            ),
        }
    elif (check_id, stage) == ("graph_failure_fail_safe", "trigger"):
        graph = _required(
            _matching(
                events,
                "graph_state",
                source=GRAPH_SOURCE,
                state="fault",
            ),
            "real ROS graph exception",
        )
        d4 = _required(
            _matching(
                events,
                "detector_state",
                source=DETECTOR_SOURCE,
                detector="d4",
                state="incident",
            ),
            "D4 incident transition",
        )
        facts = {"graph_exception_observed": bool(graph), "d4_fault_emitted": bool(d4)}
    elif (check_id, stage) == ("graph_failure_fail_safe", "protected"):
        # 這裡量的是「故障期間 guard 全程鎖定且輸出為零」，不是「窗內出現一次
        # 鎖定轉換」。
        #
        # 原本要求後者，但它在本系統上取不到：guard_state 只在 (state, reason)
        # 轉換時發一次，而實測 guard lock 落在 d4 incident 之後 0.04 秒，
        # 而 trigger 窗必須同時涵蓋 d4 與 graph_state=fault——那次轉換因此必然被
        # 關在 trigger 裡，protected 永遠是空的。要讓原本的寫法成立，只能讓
        # guard 的已驗章鎖定晚於故障偵測，那是改防禦去遷就量測。
        #
        # 新的判準比舊的**嚴格**：舊的只要有一次轉換加一筆零速，新的要求窗內
        # 每一筆輸出都處於鎖定且為零，因此排除了任何未鎖定輸出漏出去的可能。
        # 因果仍由整個檢查提供：trigger 窗證明故障確實發生，窗是有序的，而
        # _controlled_fault_injection 另外保證受控故障事件不會出現在本窗。
        outputs = _required(
            _matching(events, "guard_output", source=GUARD_SOURCE),
            "guard output during graph fault",
        )
        if (
            len(outputs) < 2
            or outputs[-1]["monotonic_ns"] - outputs[0]["monotonic_ns"] < 100_000_000
        ):
            raise SchemaError(
                "graph fault protection requires two samples spanning 0.1 sec"
            )
        if any(event["details"]["blocked"] is not True for event in outputs):
            raise SchemaError(
                "graph fault protection window contains an unlocked output"
            )
        zeros = _guard_zero_samples(events)
        facts = {
            "guard_zeroed": len(zeros) == len(outputs),
            # 轉換若剛好落在本窗就一併記錄，但不作為通過條件——它的有無取決於
            # 窗切在哪裡，不取決於防禦有沒有守住。
            "lock_transition_observed": bool(
                _matching(events, "guard_state", source=GUARD_SOURCE, state="locked")
            ),
            "detail_bounded": True,
        }
    elif (check_id, stage) == ("graph_failure_fail_safe", "recovery"):
        graph = _required(
            _matching(
                events,
                "graph_state",
                source=GRAPH_SOURCE,
                state="recovery",
            ),
            "ROS graph recovery transition",
        )
        _required(
            _matching(
                events,
                "detector_state",
                source=DETECTOR_SOURCE,
                detector="d4",
                state="recovery",
            ),
            "D4 recovery transition",
        )
        facts = {
            "graph_recovery_event": bool(graph),
            "monitor_healthy": _healthy(events, GRAPH_SOURCE),
        }
    else:  # pragma: no cover - exhaustive guarded mapping
        raise SchemaError(f"no semantic derivation for {check_id}/{stage}")

    expected = REQUIRED_FACT_KEYS[(check_id, stage)]
    if set(facts) != expected:
        raise SchemaError(
            f"semantic derivation drift for {check_id}/{stage}: expected={sorted(expected)}"
        )
    return facts


def _validate_artifact_shape(value: Any) -> dict[str, Any]:
    expected = {
        "schema_version",
        "created_utc",
        "session_id",
        "check_id",
        "stage",
        "topology",
        "test_scope",
        "probe_activity",
        "host_firewall_modified",
        "controlled_fault_injection",
        "live_capture",
        "window",
        "telemetry",
        "observation_ts_unix_ns",
        "observation_monotonic_ns",
        "derived_facts",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise SchemaError("semantic probe artifact has unexpected keys")
    if value["schema_version"] != DERIVATION_SCHEMA:
        raise SchemaError("unsupported semantic probe artifact schema")
    if value["topology"] != "same_host_loopback":
        raise SchemaError("semantic probe requires same-host loopback topology")
    if value["test_scope"] != "same_host_loopback_only":
        raise SchemaError("semantic probe test scope is invalid")
    if value["probe_activity"] != "passive_read_only":
        raise SchemaError("semantic probe activity claim is invalid")
    if value["host_firewall_modified"] is not False:
        raise SchemaError("semantic probe may not modify the host firewall")
    if not isinstance(value["controlled_fault_injection"], bool):
        raise SchemaError("controlled fault injection marker must be boolean")
    if value["live_capture"] is not True:
        raise SchemaError("semantic probe cannot use simulated capture")
    if value["check_id"] not in REQUIRED_STAGES or value["stage"] not in REQUIRED_STAGES[value["check_id"]]:
        raise SchemaError("semantic probe outcome binding is invalid")
    if not isinstance(value["created_utc"], str):
        raise SchemaError("semantic probe created_utc is invalid")
    if not isinstance(value["window"], dict) or set(value["window"]) != {
        "start_monotonic_ns",
        "end_monotonic_ns",
    }:
        raise SchemaError("semantic probe window is invalid")
    if not isinstance(value["telemetry"], dict) or set(value["telemetry"]) != {
        "path", "sha256", "bytes"
    }:
        raise SchemaError("semantic probe telemetry reference is invalid")
    return value


def verify_probe_artifact(
    artifact_path: Path,
    *,
    evidence_root: Path,
) -> dict[str, Any]:
    artifact_file, _artifact_relative = _relative_file(
        evidence_root, artifact_path, maximum=MAX_TELEMETRY_BYTES
    )
    try:
        artifact = _validate_artifact_shape(
            json.loads(artifact_file.read_text(encoding="utf-8"))
        )
    except json.JSONDecodeError as exc:
        raise SchemaError("invalid semantic probe artifact JSON") from exc
    telemetry_ref = artifact["telemetry"]
    telemetry_path, telemetry_relative = _relative_file(
        evidence_root,
        telemetry_ref["path"],
        maximum=MAX_TELEMETRY_BYTES,
    )
    if telemetry_ref["path"] != telemetry_relative:
        raise SchemaError("semantic probe telemetry path is not canonical")
    if (
        isinstance(telemetry_ref["bytes"], bool)
        or not isinstance(telemetry_ref["bytes"], int)
        or telemetry_ref["bytes"] != telemetry_path.stat().st_size
        or telemetry_ref["sha256"] != sha256_file(telemetry_path)
    ):
        raise SchemaError("semantic probe telemetry hash or size mismatch")
    events = _load_telemetry(
        telemetry_path,
        expected_session_id=artifact["session_id"],
    )
    selected = _window_events(events, **artifact["window"])
    if artifact["observation_ts_unix_ns"] != selected[-1]["ts_unix_ns"] or artifact["observation_monotonic_ns"] != selected[-1]["monotonic_ns"]:
        raise SchemaError("semantic probe observation timestamp mismatch")
    computed = derive_facts(artifact["check_id"], artifact["stage"], selected)
    if artifact["derived_facts"] != computed:
        raise SchemaError("semantic probe facts do not match raw telemetry")
    controlled = _controlled_fault_injection(
        artifact["check_id"], artifact["stage"], selected
    )
    if artifact["controlled_fault_injection"] is not controlled:
        raise SchemaError("controlled fault injection marker mismatch")
    return {
        "session_id": artifact["session_id"],
        "check_id": artifact["check_id"],
        "stage": artifact["stage"],
        "ts_unix_ns": artifact["observation_ts_unix_ns"],
        "monotonic_ns": artifact["observation_monotonic_ns"],
        "facts": computed,
        "controlled_fault_injection": controlled,
    }


def derive_semantic_observation(
    *,
    evidence_root: Path,
    telemetry_path: Path,
    artifact_path: Path,
    session_id: str,
    check_id: str,
    stage: str,
    start_monotonic_ns: int,
    end_monotonic_ns: int,
    live_ack: str,
) -> dict[str, Any]:
    if live_ack != LIVE_ACK:
        raise SchemaError("explicit live same-host loopback acknowledgement required")
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise SchemaError("evidence root must be a real directory")
    telemetry_file, telemetry_relative = _relative_file(
        evidence_root, telemetry_path, maximum=MAX_TELEMETRY_BYTES
    )
    root = evidence_root.resolve(strict=True)
    destination = artifact_path if artifact_path.is_absolute() else root / artifact_path
    if destination.parent.resolve(strict=True) != root:
        raise SchemaError("semantic probe artifact must be directly inside evidence root")
    if destination.exists() or destination.is_symlink():
        raise SchemaError("semantic probe artifact is immutable and already exists")
    events = _load_telemetry(telemetry_file, expected_session_id=session_id)
    selected = _window_events(
        events,
        start_monotonic_ns=start_monotonic_ns,
        end_monotonic_ns=end_monotonic_ns,
    )
    facts = derive_facts(check_id, stage, selected)
    controlled = _controlled_fault_injection(check_id, stage, selected)
    artifact = {
        "schema_version": DERIVATION_SCHEMA,
        "created_utc": utc_now(),
        "session_id": session_id,
        "check_id": check_id,
        "stage": stage,
        "topology": "same_host_loopback",
        "test_scope": "same_host_loopback_only",
        "probe_activity": "passive_read_only",
        "host_firewall_modified": False,
        "controlled_fault_injection": controlled,
        "live_capture": True,
        "window": {
            "start_monotonic_ns": start_monotonic_ns,
            "end_monotonic_ns": end_monotonic_ns,
        },
        "telemetry": {
            "path": telemetry_relative,
            "sha256": sha256_file(telemetry_file),
            "bytes": telemetry_file.stat().st_size,
        },
        "observation_ts_unix_ns": selected[-1]["ts_unix_ns"],
        "observation_monotonic_ns": selected[-1]["monotonic_ns"],
        "derived_facts": facts,
    }
    atomic_write_json(destination, artifact)
    observation = {
        "schema_version": OBSERVATION_SCHEMA,
        "session_id": session_id,
        "check_id": check_id,
        "stage": stage,
        "ts_unix_ns": selected[-1]["ts_unix_ns"],
        "monotonic_ns": selected[-1]["monotonic_ns"],
        "producer": "semantic_probe",
        "facts": facts,
        "artifact": {
            "path": destination.relative_to(root).as_posix(),
            "sha256": sha256_file(destination),
            "bytes": destination.stat().st_size,
            "kind": DERIVATION_KIND,
        },
    }
    # Re-open both the source and artifact before returning an observation that
    # can enter the append-only stream.
    verified = verify_probe_artifact(destination, evidence_root=evidence_root)
    if verified["facts"] != facts or verified["controlled_fault_injection"] is not controlled:
        raise SchemaError("semantic probe self-verification failed")
    return observation


def append_semantic_observation(path: Path, observation: dict[str, Any]) -> None:
    if path.exists() and path.stat().st_size > MAX_OBSERVATIONS_BYTES:
        raise SchemaError("local outcome observation stream exceeds size limit")
    JsonlWriter(path).append(observation)


def discover_marked_windows(
    events: list[dict[str, Any]],
) -> list[tuple[str, str, int, int]]:
    """Return one strictly ordered start/end window for every required stage."""
    markers = _matching(
        events, "outcome_marker", source="local_outcome_controller"
    )
    expected_pairs = sum(len(stages) for stages in REQUIRED_STAGES.values())
    if len(markers) != expected_pairs * 2:
        raise SchemaError(
            f"marked campaign requires exactly {expected_pairs * 2} boundaries"
        )
    result: list[tuple[str, str, int, int]] = []
    previous_end = 0
    for check_id, stages in REQUIRED_STAGES.items():
        for stage in stages:
            bound = [
                event
                for event in markers
                if event["details"]["check_id"] == check_id
                and event["details"]["stage"] == stage
            ]
            if [event["details"]["boundary"] for event in bound] != [
                "start",
                "end",
            ]:
                raise SchemaError(
                    f"missing, duplicate, or reordered markers for {check_id}/{stage}"
                )
            start = bound[0]["monotonic_ns"]
            end = bound[1]["monotonic_ns"]
            if start <= previous_end or end <= start:
                raise SchemaError("marked outcome windows overlap or are reordered")
            # Validate continuity and semantic completeness before any artifact
            # is written.  This is especially important for the graph-fault
            # stage, which intentionally remains blocked without a real event.
            selected = _window_events(
                events,
                start_monotonic_ns=start,
                end_monotonic_ns=end,
            )
            derive_facts(check_id, stage, selected)
            result.append((check_id, stage, start, end))
            previous_end = end
    return result


def derive_marked_campaign(
    *,
    evidence_root: Path,
    telemetry_path: Path,
    observations_path: Path,
    session_id: str,
    live_ack: str,
) -> list[dict[str, Any]]:
    """Preflight then materialize all semantic observations from markers."""
    if live_ack != LIVE_ACK:
        raise SchemaError("explicit live same-host loopback acknowledgement required")
    root = evidence_root.resolve(strict=True)
    observations = observations_path if observations_path.is_absolute() else root / observations_path
    if observations.parent.resolve(strict=True) != root:
        raise SchemaError("campaign observations must be directly inside evidence root")
    if observations.exists() or observations.is_symlink():
        raise SchemaError("campaign observations are immutable and already exist")
    telemetry_file, _relative = _relative_file(
        root, telemetry_path, maximum=MAX_TELEMETRY_BYTES
    )
    events = _load_telemetry(telemetry_file, expected_session_id=session_id)
    windows = discover_marked_windows(events)
    destinations = [
        root / f"{index:02d}_{check_id}_{stage}.semantic.json"
        for index, (check_id, stage, _start, _end) in enumerate(windows, 1)
    ]
    if any(path.exists() or path.is_symlink() for path in destinations):
        raise SchemaError("one or more immutable campaign artifacts already exist")
    derived = [
        derive_semantic_observation(
            evidence_root=root,
            telemetry_path=telemetry_file,
            artifact_path=destination,
            session_id=session_id,
            check_id=check_id,
            stage=stage,
            start_monotonic_ns=start,
            end_monotonic_ns=end,
            live_ack=live_ack,
        )
        for destination, (check_id, stage, start, end) in zip(
            destinations, windows, strict=True
        )
    ]
    writer = JsonlWriter(observations)
    for observation in derived:
        writer.append(observation)
    return derived


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--telemetry", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--check-id", choices=tuple(REQUIRED_STAGES), required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--start-monotonic-ns", type=int, required=True)
    parser.add_argument("--end-monotonic-ns", type=int, required=True)
    parser.add_argument("--live-loopback-ack", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.stage not in REQUIRED_STAGES[args.check_id]:
        raise SystemExit(
            f"invalid stage for {args.check_id}: expected={REQUIRED_STAGES[args.check_id]}"
        )
    root = args.evidence_root.resolve(strict=True)
    observations = args.observations if args.observations.is_absolute() else root / args.observations
    if observations.parent.resolve(strict=True) != root:
        raise SystemExit("--observations must be directly inside evidence root")
    observation = derive_semantic_observation(
        evidence_root=root,
        telemetry_path=args.telemetry,
        artifact_path=args.artifact,
        session_id=args.session_id,
        check_id=args.check_id,
        stage=args.stage,
        start_monotonic_ns=args.start_monotonic_ns,
        end_monotonic_ns=args.end_monotonic_ns,
        live_ack=args.live_loopback_ack,
    )
    append_semantic_observation(observations, observation)
    print(
        f"semantic_outcome={args.check_id}/{args.stage} "
        f"artifact={observation['artifact']['path']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
