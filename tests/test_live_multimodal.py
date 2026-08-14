import csv
import json

import pytest

from firewall_lab.features import (
    TELEMETRY_FEATURES,
    build_features,
)
from firewall_lab.live_telemetry_collector import (
    TELEMETRY_INPUT_SCHEMA_VERSION,
    TelemetryCollector,
    collect_records,
    make_telemetry_event,
)
from firewall_lab.local_simulation import load_simulation_rows
from firewall_lab.schema import (
    SchemaError,
    SessionManifest,
    make_label,
    new_session_id,
)


def _write_live_session(tmp_path):
    session_id = new_session_id("cmd_vel_injection")
    session = tmp_path / session_id
    (session / "zeek").mkdir(parents=True)
    base_seconds = 1_800_000_000.0
    base_ns = int(base_seconds * 1_000_000_000)
    manifest = SessionManifest(
        session_id=session_id,
        scenario_id="cmd_vel_injection",
        attack_class="command_injection",
        binary_label="attack",
        security_mode="enforce",
        ros_domain_id=30,
        seed=22,
        origin="live_lab",
        training_eligible=True,
        expected_action="lock_velocity",
        policy_sha256="a" * 64,
        code_revision="b" * 40,
        status="complete",
    )
    manifest.write(session / "manifest.json")
    label = make_label(
        session_id=session_id,
        attack_class="command_injection",
        start_unix_ns=base_ns + 8_000_000_000,
        end_unix_ns=base_ns + 16_000_000_000,
        source="allowlisted_runner",
    )
    (session / "labels.jsonl").write_text(
        json.dumps(label) + "\n", encoding="utf-8"
    )
    (session / "events.jsonl").write_text("", encoding="utf-8")
    (session / "resources.jsonl").write_text("", encoding="utf-8")
    conn = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
        f"{base_seconds + 1:.6f}\t127.0.0.1\t239.255.0.1\t14900\tudp\n"
        f"{base_seconds + 9:.6f}\t127.0.0.1\t127.0.0.1\t14913\tudp\n"
    )
    (session / "zeek" / "conn.log").write_text(conn, encoding="utf-8")
    return session, base_ns


def _emit_window_baseline(collector, timestamp):
    records = [
        ("collector_tick", {}),
        (
            "hmac_validation",
            {
                "count": 4,
                "valid_count": 4,
                "nonce_reuse_count": 0,
                "channel_mismatch_count": 0,
                "timestamp_violation_count": 0,
            },
        ),
        ("publisher_observation", {"count": 4, "violation_count": 0}),
        ("message_validation", {"count": 4, "oversized_count": 0}),
        ("qos_delivery", {"expected_count": 4, "delivered_count": 4}),
        ("heartbeat_observation", {"gap_sec": 0.2}),
        ("control_observation", {"count": 4, "conflict_count": 0}),
        ("scan_observation", {"count": 4, "static_count": 0}),
        ("odom_cmd_observation", {"count": 4, "mismatch_count": 0}),
        ("alert_observation", {"count": 0, "reflection_count": 0}),
    ]
    for offset, (event_type, details) in enumerate(records):
        collector.emit(
            event_type,
            details,
            ts_unix_ns=timestamp + offset,
        )


def _emit_attack_window(collector, timestamp):
    records = [
        ("collector_tick", {}),
        ("sros_auth_failure", {"count": 8}),
        ("sros_permission_denied", {"count": 4}),
        ("participant_change", {"count": 2}),
        ("unknown_node", {"count": 4}),
        (
            "hmac_validation",
            {
                "count": 4,
                "valid_count": 1,
                "nonce_reuse_count": 2,
                "channel_mismatch_count": 1,
                "timestamp_violation_count": 1,
            },
        ),
        ("publisher_observation", {"count": 4, "violation_count": 3}),
        ("parameter_call", {"count": 16}),
        ("message_validation", {"count": 4, "oversized_count": 2}),
        ("qos_delivery", {"expected_count": 4, "delivered_count": 2}),
        ("heartbeat_observation", {"gap_sec": 5.0}),
        ("control_observation", {"count": 4, "conflict_count": 3}),
        ("scan_observation", {"count": 4, "static_count": 3}),
        ("odom_cmd_observation", {"count": 4, "mismatch_count": 2}),
        ("alert_observation", {"count": 4, "reflection_count": 1}),
        ("log_reject", {"count": 8}),
    ]
    for offset, (event_type, details) in enumerate(records):
        collector.emit(
            event_type,
            details,
            ts_unix_ns=timestamp + offset,
        )


def test_collector_canonicalizes_input_and_rejects_unsafe_details(tmp_path):
    session_id = new_session_id("normal_patrol")
    collector = TelemetryCollector(
        tmp_path / "events.jsonl",
        session_id=session_id,
        source="monitor_node",
    )
    record = {
        "schema_version": TELEMETRY_INPUT_SCHEMA_VERSION,
        "event_type": "collector_tick",
        "details": {},
        "ts_unix_ns": 1_800_000_000_000_000_000,
        "monotonic_ns": 100,
    }
    assert collect_records(
        [json.dumps(record)], collector=collector
    ) == 1
    stored = json.loads(
        (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    )
    assert stored["session_id"] == session_id
    assert stored["sequence"] == 0

    with pytest.raises(SchemaError, match="unexpected detail keys"):
        collector.emit("collector_tick", {"token": "must-not-be-stored"})
    with pytest.raises(SchemaError, match="numerator may not exceed"):
        make_telemetry_event(
            session_id=session_id,
            sequence=1,
            source="monitor_node",
            event_type="publisher_observation",
            details={"count": 1, "violation_count": 2},
        )


def test_live_network_and_telemetry_build_exact_aligned_fusion(tmp_path):
    session, base_ns = _write_live_session(tmp_path)
    collector = TelemetryCollector(
        session / "telemetry_events.jsonl",
        session_id=session.name,
        source="telemetry_collector",
    )
    _emit_window_baseline(collector, base_ns + 1_500_000_000)
    _emit_attack_window(collector, base_ns + 9_500_000_000)

    output = tmp_path / "features"
    result = build_features(
        dataset_root=tmp_path,
        output_dir=output,
        require_multimodal=True,
    )
    assert result["network_rows"] == 2
    assert result["telemetry_rows"] == 2
    assert result["fusion_rows"] == 2
    assert result["missing_multimodal_sessions"] == 0

    with (output / "telemetry_features.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        telemetry = list(csv.DictReader(handle))
    with (output / "fusion_features.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        fusion = list(csv.DictReader(handle))
    assert [row["label"] for row in telemetry] == [
        "normal",
        "command_injection",
    ]
    assert float(telemetry[1]["sros_auth_fail_rate"]) == 1.0
    assert float(telemetry[1]["hmac_failure_rate"]) == 0.375
    assert float(telemetry[1]["nonce_reuse_ratio"]) == 0.5
    assert float(telemetry[1]["qos_drop_ratio"]) == 0.5
    assert float(telemetry[1]["heartbeat_gap_sec"]) == 5.0
    assert len(fusion) == 2
    assert all(name in fusion[0] for name in TELEMETRY_FEATURES)


def test_runtime_semantic_events_feed_existing_fusion_features(tmp_path):
    session, base_ns = _write_live_session(tmp_path)
    collector = TelemetryCollector(
        session / "telemetry_events.jsonl",
        session_id=session.name,
        source="telemetry_collector",
    )
    collector.emit("collector_tick", {}, ts_unix_ns=base_ns + 1_000_000_000)
    collector.emit_from(
        "velocity_guard_node",
        "hmac_result",
        {"outcome": "accepted", "reason": "accepted"},
        ts_unix_ns=base_ns + 1_100_000_000,
    )
    attack_time = base_ns + 9_000_000_000
    collector.emit("collector_tick", {}, ts_unix_ns=attack_time)
    for offset, reason in enumerate(
        ("nonce_reuse_or_capacity", "channel_mismatch", "timestamp_violation"),
        start=1,
    ):
        collector.emit_from(
            "velocity_guard_node",
            "hmac_result",
            {"outcome": "rejected", "reason": reason},
            ts_unix_ns=attack_time + offset,
        )
    for offset, detector in enumerate(("d1", "d3", "d4", "d6"), start=10):
        collector.emit_from(
            "intelligent_defense_node",
            "detector_state",
            {"detector": detector, "state": "incident"},
            ts_unix_ns=attack_time + offset,
        )
    collector.emit_from(
        "intelligent_defense_node",
        "authenticated_heartbeat_state",
        {"state": "gap", "gap_sec": 12.0},
        ts_unix_ns=attack_time + 20,
    )
    collector.emit_from(
        "dds_security_monitor",
        "graph_state",
        {"state": "overflow", "node_count": 300},
        ts_unix_ns=attack_time + 21,
    )
    collector.emit_from(
        "sros2_log_adapter",
        "sros2_deny",
        {"kind": "authentication", "count": 2},
        ts_unix_ns=attack_time + 22,
    )
    collector.emit_from(
        "sros2_log_adapter",
        "sros2_deny",
        {"kind": "permission", "count": 3},
        ts_unix_ns=attack_time + 23,
    )

    build_features(
        dataset_root=tmp_path,
        output_dir=tmp_path / "features",
        require_multimodal=True,
    )
    with (tmp_path / "features" / "telemetry_features.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        rows = list(csv.DictReader(handle))
    attack = rows[1]
    assert float(attack["hmac_failure_rate"]) == 0.375
    assert float(attack["nonce_reuse_ratio"]) == pytest.approx(1 / 3, abs=1e-6)
    assert float(attack["control_conflict_ratio"]) == 1.0
    assert float(attack["scan_static_ratio"]) == 1.0
    assert float(attack["publisher_violation_ratio"]) == 1.0
    assert float(attack["odom_cmd_mismatch_ratio"]) == 1.0
    assert float(attack["heartbeat_gap_sec"]) == 12.0
    assert float(attack["sros_auth_fail_rate"]) == 0.25
    assert float(attack["sros_permission_deny_rate"]) == 0.375
    assert float(attack["log_reject_rate"]) == 0.125


def test_multimodal_quality_fails_closed_without_collector_ticks(tmp_path):
    session, base_ns = _write_live_session(tmp_path)
    collector = TelemetryCollector(
        session / "telemetry_events.jsonl",
        session_id=session.name,
        source="telemetry_collector",
    )
    collector.emit(
        "heartbeat_observation",
        {"gap_sec": 0.1},
        ts_unix_ns=base_ns + 1_500_000_000,
    )
    collector.emit(
        "heartbeat_observation",
        {"gap_sec": 0.2},
        ts_unix_ns=base_ns + 9_500_000_000,
    )
    with pytest.raises(SchemaError, match="no collector_tick"):
        build_features(
            dataset_root=tmp_path,
            output_dir=tmp_path / "features",
            require_multimodal=True,
        )


def test_multimodal_quality_fails_closed_when_stream_is_missing(tmp_path):
    _write_live_session(tmp_path)
    with pytest.raises(SchemaError, match="does not cover every"):
        build_features(
            dataset_root=tmp_path,
            output_dir=tmp_path / "features",
            require_multimodal=True,
        )


def test_local_simulation_uses_held_out_synthetic_rows_only(tmp_path):
    path = tmp_path / "network_features.csv"
    columns = [
        "session_id",
        "label",
        "binary",
        "origin",
        "training_eligible",
        "evaluation_eligible",
        "split",
        *[
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
        ],
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for index, label in enumerate(("normal", "service_dos") * 2):
            writer.writerow(
                {
                    "session_id": f"session_{index}",
                    "label": label,
                    "binary": "normal" if label == "normal" else "attack",
                    "origin": "synthetic_pretrain",
                    "training_eligible": "True",
                    "evaluation_eligible": "False",
                    "split": "test",
                    **{
                        name: 1.0
                        for name in columns
                        if name
                        not in {
                            "session_id",
                            "label",
                            "binary",
                            "origin",
                            "training_eligible",
                            "evaluation_eligible",
                            "split",
                        }
                    },
                }
            )
    selected = load_simulation_rows(
        path, split="test", samples=4, seed=1
    )
    assert {row["label"] for row in selected} == {"normal", "service_dos"}

    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    rows[0]["evaluation_eligible"] = "True"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(SchemaError, match="non-evaluation"):
        load_simulation_rows(path, split="test", samples=1, seed=1)


def test_non_feature_events_are_skipped_not_fatal():
    """The live stack emits event types that feed no feature; they must not crash.

    Regression for the 2026-08-06 loopback pilot: velocity_guard_node emits
    ``guard_input`` on its first accepted command, and the dispatcher's
    catch-all ``raise`` killed every live feature build before a single row was
    written.  Skipping must stay explicit so a genuinely unknown type still
    fails closed.
    """
    from firewall_lab.features import (
        NON_FEATURE_TELEMETRY_EVENTS,
        _accumulate_telemetry,
        _new_telemetry_accumulator,
    )

    observed_in_pilot = {"guard_input", "guard_output", "authenticated_action"}
    assert observed_in_pilot <= NON_FEATURE_TELEMETRY_EVENTS

    accumulator = _new_telemetry_accumulator()
    for event_type in sorted(NON_FEATURE_TELEMETRY_EVENTS):
        _accumulate_telemetry(accumulator, {"event_type": event_type, "details": {}})

    # Counted as telemetry volume, but contributing nothing else.
    assert accumulator["telemetry_event_count"] == len(NON_FEATURE_TELEMETRY_EVENTS)
    assert set(accumulator) == {"telemetry_event_count"}


def test_unknown_telemetry_event_still_fails_closed():
    from firewall_lab.features import _accumulate_telemetry, _new_telemetry_accumulator
    from firewall_lab.schema import SchemaError

    with pytest.raises(SchemaError, match="unsupported telemetry event_type"):
        _accumulate_telemetry(
            _new_telemetry_accumulator(),
            {"event_type": "a_type_nobody_declared", "details": {}},
        )


def test_skip_list_only_covers_event_types_the_collector_accepts():
    """Never skip something the collector would reject anyway - that would hide
    a producer/collector schema break behind the feature builder."""
    from firewall_lab.features import NON_FEATURE_TELEMETRY_EVENTS
    from firewall_lab.live_telemetry_collector import EVENT_DETAIL_KEYS

    assert NON_FEATURE_TELEMETRY_EVENTS <= set(EVENT_DETAIL_KEYS)


def test_zeek_udp_timeout_is_below_the_feature_window():
    """Long-lived DDS flows must be re-logged inside every 8s feature window.

    Zeek writes one conn.log record per closed UDP flow, stamped with the
    flow's first packet.  At the 60s default a whole DDS session collapses into
    window 0: the 2026-08-06 loopback pilot produced 1 window per session and
    zero attack-labelled windows, discarding all attack-interval signal.  The
    timeout must stay strictly below the feature window for any flow still
    carrying traffic to appear in that window.
    """
    from firewall_lab.features import build_features
    from firewall_lab.orchestrator import ZEEK_UDP_INACTIVITY_TIMEOUT_SEC
    from firewall_lab.synthetic_dataset import DEFAULT_WINDOW_SEC
    import inspect

    assert 0 < ZEEK_UDP_INACTIVITY_TIMEOUT_SEC < DEFAULT_WINDOW_SEC
    # The live builder's own default window must agree with the synthetic one,
    # otherwise the bound above is checked against the wrong number.
    live_window = inspect.signature(build_features).parameters["window_sec"].default
    assert live_window == DEFAULT_WINDOW_SEC
    assert ZEEK_UDP_INACTIVITY_TIMEOUT_SEC < live_window


def test_offline_zeek_actually_passes_the_timeout_override():
    import inspect

    from firewall_lab import orchestrator

    source = inspect.getsource(orchestrator._run_offline_zeek)
    assert "udp_inactivity_timeout" in source
    assert "ZEEK_UDP_INACTIVITY_TIMEOUT_SEC" in source


def test_blue_team_capture_uses_the_same_zeek_timeout():
    """The blue-team analyser and the orchestrator must not disagree, or the
    same PCAP would yield different window counts depending on who ran Zeek."""
    from pathlib import Path

    from firewall_lab.orchestrator import ZEEK_UDP_INACTIVITY_TIMEOUT_SEC

    script = (
        Path(__file__).resolve().parents[1] / "firewall_lab" / "blue_team_capture.sh"
    ).read_text(encoding="utf-8")
    assert f"ZEEK_UDP_TIMEOUT_SEC={ZEEK_UDP_INACTIVITY_TIMEOUT_SEC}" in script
    assert "udp_inactivity_timeout" in script


def test_newly_produced_events_actually_move_their_features_off_zero():
    """Prove event -> feature wiring for the four producers added on 2026-08-06.

    The loopback pilot cannot demonstrate this on its own: a clean session has
    no graph churn, no parameter calls and no reflection attempts, so the
    features stay legitimately zero and a broken mapping would look identical
    to a quiet system.  Drive the accumulator directly instead.
    """
    from firewall_lab.features import (
        _accumulate_telemetry,
        _new_telemetry_accumulator,
        _telemetry_feature_values,
    )

    cases = {
        "participant_churn_rate": [
            ("participant_change", {"count": 4}),
        ],
        "unknown_node_rate": [
            ("unknown_node", {"count": 2}),
        ],
        "parameter_call_rate": [
            ("parameter_call", {"count": 3}),
        ],
        "alert_reflection_ratio": [
            ("alert_observation", {"count": 4, "reflection_count": 3}),
        ],
    }

    for feature, events in cases.items():
        accumulator = _new_telemetry_accumulator()
        for event_type, details in events:
            _accumulate_telemetry(
                accumulator, {"event_type": event_type, "details": details}
            )
        values = _telemetry_feature_values(accumulator, window_sec=8.0)
        assert values[feature] > 0.0, f"{feature} stayed zero despite its events"

    # A quiet window must still produce zeros, so the features stay meaningful.
    quiet = _telemetry_feature_values(_new_telemetry_accumulator(), window_sec=8.0)
    assert all(quiet[feature] == 0.0 for feature in cases)


def test_every_telemetry_feature_now_has_a_live_producer():
    """All five features that were structurally zero on 2026-08-06 are wired.

    qos_delivery was the last one; it needed rclpy message-lost QoS events,
    which sensor_hub_node now installs on its BEST_EFFORT /scan and /imu
    subscriptions.
    """
    import ast
    from pathlib import Path

    producer_src = (
        Path(__file__).resolve().parents[1]
        / "src/dds_security_monitor/dds_security_monitor/runtime_telemetry.py"
    ).read_text(encoding="utf-8")
    produced = {
        node.args[0].value
        for node in ast.walk(ast.parse(producer_src))
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", None) == "_emit"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }
    for now_produced in (
        "participant_change",
        "unknown_node",
        "parameter_call",
        "alert_observation",
        "qos_delivery",
    ):
        assert now_produced in produced


def test_sensor_hub_installs_message_lost_events_and_resets_counters():
    """Loss must be reported as a per-interval delta, not a running total.

    QoSMessageLostInfo.total_count is cumulative for the subscription's
    lifetime; using it directly would make every later window inherit all
    earlier loss and inflate qos_drop_ratio monotonically.
    """
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1]
        / "src/dds_security_monitor/dds_security_monitor/sensor_hub_node.py"
    ).read_text(encoding="utf-8")
    assert "SubscriptionEventCallbacks" in source
    assert "message_lost=self._on_message_lost" in source
    assert "total_count_change" in source
    # The cumulative field must not be the one being accumulated.
    assert "self._qos_lost += max(0, int(info.total_count_change))" in source
    # Counters are cleared when reported so each window stands alone.
    assert "self._qos_delivered = 0" in source
    assert "self._qos_lost = 0" in source


def test_qos_delivery_events_move_qos_drop_ratio_off_zero():
    from firewall_lab.features import (
        _accumulate_telemetry,
        _new_telemetry_accumulator,
        _telemetry_feature_values,
    )

    accumulator = _new_telemetry_accumulator()
    _accumulate_telemetry(
        accumulator,
        {
            "event_type": "qos_delivery",
            "details": {"expected_count": 10, "delivered_count": 7},
        },
    )
    values = _telemetry_feature_values(accumulator, window_sec=8.0)
    assert values["qos_drop_ratio"] == pytest.approx(0.3)

    clean = _new_telemetry_accumulator()
    _accumulate_telemetry(
        clean,
        {
            "event_type": "qos_delivery",
            "details": {"expected_count": 10, "delivered_count": 10},
        },
    )
    assert _telemetry_feature_values(clean, window_sec=8.0)["qos_drop_ratio"] == 0.0


def test_every_bounded_attack_runner_tolerates_orchestrator_shutdown():
    """A clean attack must not exit non-zero just because it was stopped.

    The orchestrator ends each attack phase with SIGTERM.  rclpy normally
    raises ExternalShutdownException, but when the context is torn down between
    operations it raises RCLError instead.  An escaped RCLError becomes a
    traceback and a non-zero exit, and the verifier then marks the entire
    session non-trainable even though the attack completed -- observed on
    N24 in the 2026-08-06 Permissive sweep, which sent all 82 oversized scans
    and still lost the session.  Timing-dependent, so across 1,100 sessions it
    would appear as random unexplained data loss.
    """
    from pathlib import Path

    poc = Path(__file__).resolve().parents[1] / "紅隊測試" / "PoC腳本"
    bounded_runners = [
        "N1_heartbeat_replay.py",
        "N3_alert_replay_dos.py",
        "N6_sensor_status_spoof.py",
        "N9_cmd_vel_race.py",
        "N14_param_whitelist_hijack.py",
        "N19_param_service_flood.py",
        "N24_oversized_scan.py",
    ]
    missing = []
    for name in bounded_runners:
        source = (poc / name).read_text(encoding="utf-8")
        if "RCLError" not in source:
            missing.append(name)
    assert not missing, f"runners that would die on a clean stop: {missing}"


def test_window_straddling_the_attack_boundary_gets_one_label_per_window(tmp_path):
    """Two sources in one window must never disagree about its label.

    Network rows are grouped by (source, window) and were labelled from the
    mean timestamp of each group's own conns. When a window straddles the start
    or end of the attack interval those means fall on opposite sides of it: in
    session 20260807T082401902811Z_parameter_tamper_cedeb73f the attack began
    3.6s into window 0 and three sources' means landed 1 ms apart across the
    boundary, so the window was both normal and parameter_tamper at once.
    build_telemetry_rows requires a single label per window and rejected the
    session, which blocked the feature build for all 550 sessions.
    """
    from firewall_lab.features import build_features

    session_id = new_session_id("parameter_tamper")
    session = tmp_path / session_id
    (session / "zeek").mkdir(parents=True)
    base = 1_800_000_000.0
    base_ns = int(base * 1_000_000_000)

    manifest = SessionManifest(
        session_id=session_id,
        scenario_id="parameter_tamper",
        attack_class="parameter_tamper",
        binary_label="attack",
        security_mode="enforce",
        ros_domain_id=30,
        seed=1,
        origin="live_lab",
        training_eligible=True,
        expected_action="deny_participant",
        policy_sha256="a" * 64,
        code_revision="b" * 40,
        status="complete",
    )
    manifest.write(session / "manifest.json")

    # Attack starts 3.6s into window 0, exactly the shape that broke.
    (session / "labels.jsonl").write_text(
        json.dumps(
            make_label(
                session_id=session_id,
                attack_class="parameter_tamper",
                start_unix_ns=base_ns + 3_600_000_000,
                end_unix_ns=base_ns + 30_000_000_000,
                source="allowlisted_runner",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (session / "events.jsonl").write_text("", encoding="utf-8")
    (session / "resources.jsonl").write_text("", encoding="utf-8")

    # Two sources whose window-0 conn means straddle that 3.6s boundary.
    tab = "\t"
    lines = [
        "#separator \\x09",
        tab.join(["#fields", "ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto"]),
    ]

    def conn(offset: float, source: str) -> str:
        return tab.join(
            [f"{base + offset:.6f}", source, "127.0.0.1", "14913", "udp"]
        )

    for offset in (0.2, 0.4, 1.0):          # mean 0.53 -> before the boundary
        lines.append(conn(offset, "127.0.0.1"))
    for offset in (6.0, 7.0, 7.5):          # mean 6.83 -> after the boundary
        lines.append(conn(offset, "10.255.255.254"))
    for offset in (9.0, 12.0, 14.0):        # window 1, both sources
        lines.append(conn(offset, "127.0.0.1"))
        lines.append(conn(offset, "10.255.255.254"))
    (session / "zeek" / "conn.log").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    collector = TelemetryCollector(
        session / "telemetry_events.jsonl",
        session_id=session_id,
        source="telemetry_collector",
    )
    for window_offset in (1_000_000_000, 9_000_000_000):
        collector.emit("collector_tick", {}, ts_unix_ns=base_ns + window_offset)

    output = tmp_path / "features"
    # Before the fix this raised SchemaError("network label disagreement").
    result = build_features(dataset_root=tmp_path, output_dir=output)
    assert result["telemetry_rows"] > 0

    with (output / "network_features.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    per_window = {}
    for row in rows:
        per_window.setdefault(int(row["window"]), set()).add(row["label"])
    for window, labels in per_window.items():
        assert len(labels) == 1, (
            f"window {window} carries multiple labels {labels}; the label must "
            "be a property of the time window, not of which source sent traffic"
        )
