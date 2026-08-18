"""Strict local defense outcome evidence tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall_lab.cross_host_admission import _check_outcome_report
from firewall_lab.local_outcomes import (
    LIVE_ACK,
    OBSERVATION_SCHEMA,
    REQUIRED_FACT_KEYS,
    REQUIRED_STAGES,
    assemble_local_outcomes,
    verify_local_outcome_report,
)
from firewall_lab.live_telemetry_collector import make_telemetry_event
from firewall_lab.local_outcome_probe import (
    derive_facts,
    derive_semantic_observation,
    discover_marked_windows,
)
from firewall_lab.schema import SchemaError, sha256_file


SESSION_ID = "20260803T120000000000Z_local_outcomes_1234abcd"


def _stage_records(
    check_id: str,
    stage: str,
    *,
    controlled_graph_stages: frozenset[str],
):
    probe = "local_outcome_probe"
    guard = "velocity_guard_node"
    monitor = "dds_security_monitor"
    ids = "intelligent_defense_node"
    key = (check_id, stage)
    records = {
        ("normal_traffic_preserved", "baseline"): [
            *[(probe, "topic_probe", {"topic": topic, "message_count": 3, "publisher_count": 1, "authorized_publisher_count": 1}) for topic in ("scan", "odom", "imu", "cmd_vel")],
            (guard, "authenticated_action", {"action": "heartbeat"}),
            (guard, "guard_output", {"linear_x": 0.1, "angular_z": 0.0, "blocked": False}),
        ],
        ("unauthorized_participant_denied", "trigger"): [
            ("sros2_log_adapter", "sros2_deny", {"kind": "permission", "count": 1}),
            (probe, "delivery_probe", {"probe": "unauthorized_participant", "observed_count": 0}),
        ],
        ("unauthorized_participant_denied", "protected"): [
            (probe, "state_digest", {"name": "runtime_state", "sha256": "1" * 64}),
            (probe, "state_digest", {"name": "runtime_state", "sha256": "1" * 64}),
        ],
        ("unauthorized_participant_denied", "recovery"): [(probe, "process_health", {"node": monitor, "state": "healthy"})],
        ("hmac_forgery_dropped", "trigger"): [
            (guard, "hmac_result", {"outcome": "rejected", "reason": "invalid_signature"}),
            (probe, "delivery_probe", {"probe": "hmac_forgery", "observed_count": 0}),
        ],
        ("hmac_forgery_dropped", "protected"): [
            (probe, "state_digest", {"name": "runtime_state", "sha256": "2" * 64}),
            (probe, "state_digest", {"name": "runtime_state", "sha256": "2" * 64}),
            (guard, "guard_output", {"linear_x": 0.1, "angular_z": 0.0, "blocked": False}),
            (guard, "guard_output", {"linear_x": 0.1, "angular_z": 0.0, "blocked": False}),
        ],
        ("hmac_forgery_dropped", "recovery"): [(guard, "hmac_result", {"outcome": "accepted", "reason": "accepted"})],
        ("replay_dropped", "trigger"): [
            (guard, "hmac_result", {"outcome": "rejected", "reason": "nonce_reuse_or_capacity"}),
            (probe, "delivery_probe", {"probe": "replay", "observed_count": 0}),
        ],
        ("replay_dropped", "protected"): [
            (probe, "state_digest", {"name": "runtime_state", "sha256": "3" * 64}),
            (probe, "state_digest", {"name": "runtime_state", "sha256": "3" * 64}),
            (guard, "guard_output", {"linear_x": 0.1, "angular_z": 0.0, "blocked": False}),
            (guard, "guard_output", {"linear_x": 0.1, "angular_z": 0.0, "blocked": False}),
        ],
        ("replay_dropped", "recovery"): [(guard, "hmac_result", {"outcome": "accepted", "reason": "accepted"})],
        ("oversized_input_dropped", "trigger"): [
            ("sensor_hub_node", "message_validation", {"count": 1, "oversized_count": 1}),
        ],
        ("oversized_input_dropped", "protected"): [
            (probe, "process_health", {"node": "sensor_hub_node", "state": "healthy"}),
            (probe, "state_digest", {"name": "runtime_state", "sha256": "4" * 64}),
            (probe, "state_digest", {"name": "runtime_state", "sha256": "4" * 64}),
        ],
        ("oversized_input_dropped", "recovery"): [(probe, "delivery_probe", {"probe": "valid_input", "observed_count": 1})],
        ("parameter_unchanged", "baseline"): [(probe, "parameter_digest", {"node": monitor, "parameter": "whitelist", "sha256": "a" * 64})],
        ("parameter_unchanged", "trigger"): [(monitor, "parameter_veto", {"count": 1})],
        ("parameter_unchanged", "protected"): [(probe, "parameter_digest", {"node": monitor, "parameter": "whitelist", "sha256": "a" * 64})],
        ("parameter_unchanged", "recovery"): [(probe, "process_health", {"node": monitor, "state": "healthy"})],
        ("velocity_guard_zeroed", "trigger"): [
            (guard, "authenticated_action", {"action": "guard_lock"}),
            (guard, "guard_output", {"linear_x": 0.0, "angular_z": 0.0, "blocked": True}),
        ],
        ("velocity_guard_zeroed", "protected"): [
            (guard, "guard_output", {"linear_x": 0.0, "angular_z": 0.0, "blocked": True}),
            (guard, "guard_output", {"linear_x": 0.0, "angular_z": 0.0, "blocked": True}),
        ],
        ("velocity_guard_recovered", "baseline"): [(guard, "guard_state", {"state": "locked", "reason": "stale_command"})],
        ("velocity_guard_recovered", "trigger"): [(guard, "guard_state", {"state": "locked", "reason": "monitor_fault"})],
        ("velocity_guard_recovered", "recovery"): [
            (guard, "authenticated_action", {"action": "heartbeat"}),
            (guard, "authenticated_action", {"action": "guard_clear"}),
            (guard, "guard_input", {"accepted_count": 1}),
            (guard, "guard_output", {"linear_x": 0.1, "angular_z": 0.0, "blocked": False}),
        ],
        ("graph_failure_fail_safe", "trigger"): [
            (monitor, "graph_state", {"state": "fault", "node_count": -1}),
            (ids, "detector_state", {"detector": "d4", "state": "incident"}),
        ],
        ("graph_failure_fail_safe", "protected"): [
            (guard, "guard_state", {"state": "locked", "reason": "generic_alert"}),
            (guard, "guard_output", {"linear_x": 0.0, "angular_z": 0.0, "blocked": True}),
        ],
        ("graph_failure_fail_safe", "recovery"): [
            (monitor, "graph_state", {"state": "recovery", "node_count": 12}),
            (ids, "detector_state", {"detector": "d4", "state": "recovery"}),
            (probe, "process_health", {"node": monitor, "state": "healthy"}),
        ],
    }[key]
    if (
        check_id == "graph_failure_fail_safe"
        and stage in controlled_graph_stages
    ):
        records.extend(
            (
                source,
                "controlled_fault_injection",
                {"kind": "graph_inspection", "state": stage},
            )
            for source in (monitor, ids)
        )
    return records


def _fixture(
    tmp_path: Path,
    *,
    controlled_graph_stages: frozenset[str] = frozenset(
        {"trigger", "recovery"}
    ),
) -> tuple[Path, Path, list[dict[str, object]]]:
    root = tmp_path / "evidence"
    root.mkdir()
    telemetry = root / "telemetry.jsonl"
    raw_events = []
    windows = []
    sequence = 0
    cursor = 1_000_000_000
    wall_base = 1_800_000_000_000_000_000
    for check_id, stages in REQUIRED_STAGES.items():
        for stage in stages:
            start = cursor
            offsets = [10_000_000, 50_000_000]
            payloads = [
                ("local_outcome_controller", "outcome_marker", {"check_id": check_id, "stage": stage, "boundary": "start"}),
                ("telemetry_collector", "collector_tick", {}),
            ]
            stage_payloads = _stage_records(
                check_id,
                stage,
                controlled_graph_stages=controlled_graph_stages,
            )
            for index, payload in enumerate(stage_payloads, 1):
                offsets.append(200_000_000 + index * 150_000_000)
                payloads.append(payload)
            offsets.append(1_500_000_000)
            payloads.append(("telemetry_collector", "collector_tick", {}))
            offsets.append(1_900_000_000)
            payloads.append(("local_outcome_controller", "outcome_marker", {"check_id": check_id, "stage": stage, "boundary": "end"}))
            for offset, (source, event_type, details) in zip(offsets, payloads, strict=True):
                monotonic = cursor + offset
                raw_events.append(make_telemetry_event(
                    session_id=SESSION_ID,
                    sequence=sequence,
                    source=source,
                    event_type=event_type,
                    details=details,
                    ts_unix_ns=wall_base + monotonic,
                    monotonic_ns=monotonic,
                ))
                sequence += 1
            windows.append((check_id, stage, start, cursor + 2_000_000_000))
            cursor += 3_000_000_000
    telemetry.write_text("\n".join(json.dumps(item) for item in raw_events) + "\n", encoding="utf-8")
    records: list[dict[str, object]] = []
    for number, (check_id, stage, start, end) in enumerate(windows, 1):
        records.append(derive_semantic_observation(
            evidence_root=root,
            telemetry_path=telemetry,
            artifact_path=root / f"{number:02d}_{check_id}_{stage}.json",
            session_id=SESSION_ID,
            check_id=check_id,
            stage=stage,
            start_monotonic_ns=start,
            end_monotonic_ns=end,
            live_ack=LIVE_ACK,
        ))
    observations = root / "observations.jsonl"
    observations.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")
    return root, observations, records


def _assemble(tmp_path: Path, root: Path, observations: Path):
    return assemble_local_outcomes(
        observations_path=observations,
        evidence_root=root,
        output_path=root / "report.json",
        live_ack=LIVE_ACK,
    )


def test_complete_ordered_hashed_outcomes_are_assembled(tmp_path):
    root, observations, _records = _fixture(tmp_path)
    report = _assemble(tmp_path, root, observations)

    assert report["evidence_origin"] == "live_loopback_probes"
    assert report["network_activity"] == "same_host_loopback_only"
    assert report["host_firewall_modified"] is False
    assert report["controlled_fault_injection"] is True
    assert len(report["checks"]) == 9
    assert all(check["passed"] for check in report["checks"])
    assert verify_local_outcome_report(root / "report.json") == (
        True,
        "9 hashed live loopback outcomes proven",
    )
    assert _check_outcome_report(root / "report.json")[0]


def test_natural_graph_fault_is_explicitly_not_controlled(tmp_path):
    root, observations, _records = _fixture(
        tmp_path, controlled_graph_stages=frozenset()
    )

    report = _assemble(tmp_path, root, observations)

    assert report["controlled_fault_injection"] is False
    assert verify_local_outcome_report(root / "report.json")[0]


def test_half_controlled_graph_fault_campaign_fails_closed(tmp_path):
    root, observations, _records = _fixture(
        tmp_path, controlled_graph_stages=frozenset({"trigger"})
    )

    with pytest.raises(SchemaError, match="trigger/recovery evidence is incomplete"):
        _assemble(tmp_path, root, observations)


def test_fact_free_markers_discover_all_stage_windows(tmp_path):
    root, _observations, _records = _fixture(tmp_path)
    events = [
        json.loads(line)
        for line in (root / "telemetry.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    windows = discover_marked_windows(events)
    assert [(check_id, stage) for check_id, stage, _start, _end in windows] == [
        (check_id, stage)
        for check_id, stages in REQUIRED_STAGES.items()
        for stage in stages
    ]


def test_missing_recovery_stage_fails_closed(tmp_path):
    root, observations, records = _fixture(tmp_path)
    records = [
        item
        for item in records
        if not (item["check_id"] == "replay_dropped" and item["stage"] == "recovery")
    ]
    observations.write_text("\n".join(json.dumps(item) for item in records), encoding="utf-8")

    with pytest.raises(SchemaError, match="incomplete stages"):
        _assemble(tmp_path, root, observations)


def test_failed_safety_fact_cannot_be_reported_passed(tmp_path):
    root, observations, records = _fixture(tmp_path)
    for item in records:
        if item["check_id"] == "velocity_guard_zeroed" and item["stage"] == "protected":
            item["facts"]["linear_abs_max"] = 0.1
    observations.write_text("\n".join(json.dumps(item) for item in records), encoding="utf-8")

    with pytest.raises(SchemaError, match="semantic probe evidence|linear_abs_max"):
        _assemble(tmp_path, root, observations)


def test_tampered_raw_artifact_is_rejected(tmp_path):
    root, observations, records = _fixture(tmp_path)
    artifact = root / records[0]["artifact"]["path"]
    artifact.write_text("tampered", encoding="utf-8")

    with pytest.raises(SchemaError, match="size mismatch|SHA-256 mismatch"):
        _assemble(tmp_path, root, observations)


def test_explicit_live_ack_is_required(tmp_path):
    root, observations, _records = _fixture(tmp_path)

    with pytest.raises(SchemaError, match="acknowledgement"):
        assemble_local_outcomes(
            observations_path=observations,
            evidence_root=root,
            output_path=root / "report.json",
            live_ack="dry_run",
        )


def test_report_boolean_cannot_be_forged_after_assembly(tmp_path):
    root, observations, _records = _fixture(tmp_path)
    _assemble(tmp_path, root, observations)
    report_path = root / "report.json"
    value = json.loads(report_path.read_text(encoding="utf-8"))
    value["checks"][0]["stages"][0]["facts"]["unauthorized_publishers"] = 4
    report_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        SchemaError, match="semantic probe evidence|unauthorized_publishers"
    ):
        verify_local_outcome_report(report_path)


def test_arbitrary_hashed_probe_log_cannot_enter_local_admission(tmp_path):
    root, observations, records = _fixture(tmp_path)
    arbitrary = root / "caller_supplied.json"
    arbitrary.write_text(
        json.dumps({"passed": True, "facts": records[0]["facts"]}),
        encoding="utf-8",
    )
    records[0]["artifact"] = {
        "path": arbitrary.name,
        "sha256": sha256_file(arbitrary),
        "bytes": arbitrary.stat().st_size,
        "kind": "probe_log",
    }
    observations.write_text(
        "\n".join(json.dumps(item) for item in records) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SchemaError, match="semantic_probe"):
        _assemble(tmp_path, root, observations)


def test_semantic_artifact_reopens_raw_telemetry(tmp_path):
    root, observations, _records = _fixture(tmp_path)
    telemetry = root / "telemetry.jsonl"
    telemetry.write_text(
        telemetry.read_text(encoding="utf-8") + "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(SchemaError, match="telemetry hash or size mismatch"):
        _assemble(tmp_path, root, observations)


def _ua_trigger_facts(records):
    """Derive the unauthorized_participant_denied trigger facts from raw events."""
    events = []
    for index, (source, event_type, details) in enumerate(records):
        events.append(
            make_telemetry_event(
                session_id=SESSION_ID,
                source=source,
                event_type=event_type,
                details=details,
                sequence=index,
            )
        )
    return derive_facts(
        check_id="unauthorized_participant_denied",
        stage="trigger",
        events=events,
    )


def test_absent_vendor_deny_is_not_evaluable_rather_than_a_failure():
    """rmw_fastrtps cannot enable the Fast DDS security audit log at all.

    It assembles the participant's dds.sec.* properties from the keystore and
    never sets dds.sec.log.plugin, so no vendor denial record is obtainable in
    this stack. Requiring one made this outcome permanently unreachable, and
    treating its absence as proof of denial would be worse. The check now rests
    on the security property itself.
    """
    facts = _ua_trigger_facts([
        ("local_outcome_probe", "delivery_probe",
         {"probe": "unauthorized_participant", "observed_count": 0}),
    ])
    assert facts["sros_deny_evaluable"] is False
    assert facts["sros_deny_count"] == 0
    assert facts["unauthorized_delivery_count"] == 0


def test_delivery_still_binds_when_the_vendor_record_is_unavailable():
    """The relaxation must not make the outcome easier to satisfy.

    With no vendor record and traffic actually delivered, the participant was
    not denied, and the check has to fail exactly as it did before.
    """
    from firewall_lab.local_outcomes import _assert_outcome

    stages = {
        "trigger": {"facts": {
            "sros_deny_count": 0,
            "sros_deny_evaluable": False,
            "unauthorized_delivery_count": 3,
        }},
        "protected": {"facts": {"protected_state_unchanged": True}},
        "recovery": {"facts": {"authorized_participant_healthy": True}},
    }
    with pytest.raises(SchemaError, match="unauthorized_delivery_count"):
        _assert_outcome("unauthorized_participant_denied", stages)

    stages["trigger"]["facts"]["unauthorized_delivery_count"] = 0
    _assert_outcome("unauthorized_participant_denied", stages)


def test_a_claimed_vendor_record_still_has_to_show_a_denial():
    """If a sink ever does exist, an evaluable-but-empty record must fail."""
    from firewall_lab.local_outcomes import _assert_outcome

    stages = {
        "trigger": {"facts": {
            "sros_deny_count": 0,
            "sros_deny_evaluable": True,
            "unauthorized_delivery_count": 0,
        }},
        "protected": {"facts": {"protected_state_unchanged": True}},
        "recovery": {"facts": {"authorized_participant_healthy": True}},
    }
    with pytest.raises(SchemaError, match="sros_deny_count"):
        _assert_outcome("unauthorized_participant_denied", stages)
