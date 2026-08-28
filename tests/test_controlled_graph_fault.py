"""Tests for the inert-by-default one-shot graph inspection fault seam."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from firewall_lab.local_graph_fault_control import (
    GRAPH_FAULT_ACK,
    HEARTBEAT_SUPPRESS_ACK,
    LIVE_ACK,
    MAX_HOLD_SEC,
    arm_once,
    prepare_directory,
)
from firewall_lab.schema import SchemaError
from dds_security_monitor import test_fault_seam
from dds_security_monitor.test_fault_seam import (
    ControlledGraphFaultSeam,
    GRAPH_FAULT_ACK_ENV,
    GRAPH_FAULT_DIR_ENV,
    LIVE_ACK_ENV,
)


pytestmark = pytest.mark.skipif(
    not hasattr(os, "getuid"),
    reason="the controlled fault seam is intentionally Linux-only",
)


class _Telemetry:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def emit_controlled_fault_injection(self, kind: str, state: str) -> bool:
        self.events.append((kind, state))
        return True


def _gated_environment(monkeypatch, runtime: Path, *, graph_ack: bool = True):
    monkeypatch.setenv("ROS_LOCALHOST_ONLY", "1")
    monkeypatch.setenv("ROS_SECURITY_ENABLE", "true")
    monkeypatch.setenv("ROS_SECURITY_STRATEGY", "Enforce")
    monkeypatch.setenv(LIVE_ACK_ENV, LIVE_ACK)
    monkeypatch.setenv(GRAPH_FAULT_DIR_ENV, str(runtime))
    if graph_ack:
        monkeypatch.setenv(GRAPH_FAULT_ACK_ENV, GRAPH_FAULT_ACK)
    else:
        monkeypatch.delenv(GRAPH_FAULT_ACK_ENV, raising=False)


def _prepared_runtime(tmp_path: Path, monkeypatch) -> Path:
    tmp_path.chmod(0o700)
    runtime = tmp_path / "controlled_graph_fault"
    _gated_environment(monkeypatch, runtime)
    return prepare_directory(
        runtime,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )


def test_seam_is_inert_without_second_ack(tmp_path, monkeypatch):
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=5.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    _gated_environment(monkeypatch, runtime, graph_ack=False)
    telemetry = _Telemetry()

    seam = ControlledGraphFaultSeam.from_environment("monitor", telemetry)

    assert seam.enabled is False
    assert seam.consume_if_armed() is False
    assert (runtime / "monitor.arm").is_file()
    assert telemetry.events == []


def test_each_role_consumes_once_and_labels_trigger_recovery(tmp_path, monkeypatch):
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    result = arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=1.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    assert result["controlled_fault_injection"] is True

    captured: dict[str, list[tuple[str, str]]] = {}
    for role in ("monitor", "ids"):
        # In production these are separate supervised processes and each gets
        # one environment copy.  Resetting the acknowledgement here models
        # those independent process environments.
        _gated_environment(monkeypatch, runtime)
        telemetry = _Telemetry()
        seam = ControlledGraphFaultSeam.from_environment(role, telemetry)
        assert GRAPH_FAULT_ACK_ENV not in os.environ
        assert seam.enabled is True
        assert seam.consume_if_armed() is True
        # The hold keeps reporting the fault without consuming anything else,
        # then expires on the monotonic clock and never fires again.
        assert seam.consume_if_armed() is True
        seam._hold_until_ns = time.monotonic_ns() - 1
        assert seam.consume_if_armed() is False
        seam.record_normal_graph()
        seam.record_normal_graph()
        captured[role] = telemetry.events

    assert captured == {
        "monitor": [
            ("graph_inspection", "trigger"),
            ("graph_inspection", "recovery"),
        ],
        "ids": [
            ("graph_inspection", "trigger"),
            ("graph_inspection", "recovery"),
        ],
    }
    assert not list(runtime.glob("*.arm"))
    assert not list(runtime.glob(".*.claim"))


def test_expired_arm_record_is_consumed_but_never_triggered(
    tmp_path, monkeypatch
):
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    result = arm_once(
        runtime,
        ttl_sec=5.0,
        hold_sec=5.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    monkeypatch.setattr(
        test_fault_seam.time,
        "time_ns",
        lambda: int(result["expires_unix_ns"]) + 1,
    )
    _gated_environment(monkeypatch, runtime)
    telemetry = _Telemetry()

    seam = ControlledGraphFaultSeam.from_environment("monitor", telemetry)

    assert seam.consume_if_armed() is False
    assert not (runtime / "monitor.arm").exists()
    assert telemetry.events == []


def test_production_launch_and_config_expose_no_fault_control():
    root = Path(__file__).resolve().parents[1]
    values = [
        (root / "src/dds_security_monitor/launch/full_system.launch.py").read_text(
            encoding="utf-8"
        ),
        (root / "src/dds_security_monitor/config/config.yaml").read_text(
            encoding="utf-8"
        ),
    ]
    forbidden = ("controlled_graph_fault", "graph_fault_ack", "fault_injection")
    assert all(
        marker not in value.lower()
        for value in values
        for marker in forbidden
    )


def test_hold_sustains_the_fault_across_repeated_checks(tmp_path, monkeypatch):
    """The whole point of v2: one arm, a fault that stays open.

    A v1 arm healed on the consumer's next graph check, so the trigger, the
    guard lock and the recovery all landed inside ~2 seconds and could not be
    split across the three bounded windows local_outcomes requires.
    """
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=10.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    _gated_environment(monkeypatch, runtime)
    telemetry = _Telemetry()
    seam = ControlledGraphFaultSeam.from_environment("monitor", telemetry)

    assert seam.consume_if_armed() is True
    for _ in range(20):
        assert seam.consume_if_armed() is True
    # Exactly one trigger, however many times the consumer asked.
    assert telemetry.events == [("graph_inspection", "trigger")]

    seam._hold_until_ns = time.monotonic_ns() - 1
    assert seam.consume_if_armed() is False
    seam.record_normal_graph()
    assert telemetry.events == [
        ("graph_inspection", "trigger"),
        ("graph_inspection", "recovery"),
    ]


def test_hold_cannot_be_extended_by_arming_again(tmp_path, monkeypatch):
    """A second arm must not stretch a hold that is already running."""
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=2.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    _gated_environment(monkeypatch, runtime)
    seam = ControlledGraphFaultSeam.from_environment("monitor", _Telemetry())
    assert seam.consume_if_armed() is True
    deadline = seam._hold_until_ns

    # arm_once refuses while any role file is still present, which is itself
    # the guard against re-arming mid-run; clear the untouched ids file so the
    # test can actually put a longer arm in front of the holding monitor seam.
    (runtime / "ids.arm").unlink()
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=25.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    assert seam.consume_if_armed() is True
    assert seam._hold_until_ns == deadline
    # While holding, the seam never touches the directory, so the new arm is
    # still sitting there untouched rather than silently swallowed.
    assert (runtime / "monitor.arm").exists()


def test_consumer_rejects_a_hold_beyond_its_own_cap(tmp_path, monkeypatch):
    """The consumer's cap is independent of whatever the arm record claims."""
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=10.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    target = runtime / "monitor.arm"
    record = json.loads(target.read_text(encoding="utf-8"))
    record["hold_ns"] = test_fault_seam.MAX_HOLD_NS + 1
    target.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    target.chmod(0o600)

    _gated_environment(monkeypatch, runtime)
    telemetry = _Telemetry()
    seam = ControlledGraphFaultSeam.from_environment("monitor", telemetry)

    assert seam.consume_if_armed() is False
    assert telemetry.events == []


def test_writer_refuses_an_out_of_range_hold(tmp_path, monkeypatch):
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    for value in (0.0, -1.0, MAX_HOLD_SEC + 1.0, True):
        with pytest.raises(SchemaError):
            arm_once(
                runtime,
                ttl_sec=20.0,
                hold_sec=value,
                live_ack=LIVE_ACK,
                graph_fault_ack=GRAPH_FAULT_ACK,
            )
    assert not list(runtime.glob("*.arm"))



# ── 心跳抑制接縫 ────────────────────────────────────────────────────────────


def _heartbeat_environment(monkeypatch, runtime: Path, *, ack: bool = True):
    monkeypatch.setenv("ROS_LOCALHOST_ONLY", "1")
    monkeypatch.setenv("ROS_SECURITY_ENABLE", "true")
    monkeypatch.setenv("ROS_SECURITY_STRATEGY", "Enforce")
    monkeypatch.setenv(LIVE_ACK_ENV, LIVE_ACK)
    monkeypatch.setenv(GRAPH_FAULT_DIR_ENV, str(runtime))
    if ack:
        monkeypatch.setenv(
            test_fault_seam.HEARTBEAT_SUPPRESS_ACK_ENV,
            test_fault_seam.HEARTBEAT_SUPPRESS_ACK,
        )
    else:
        monkeypatch.delenv(
            test_fault_seam.HEARTBEAT_SUPPRESS_ACK_ENV, raising=False
        )


def test_graph_acknowledgement_does_not_enable_heartbeat_suppression(
    tmp_path, monkeypatch
):
    """The two seams are separate powers and must not imply one another."""
    tmp_path.chmod(0o700)
    runtime = tmp_path / "controlled_graph_fault"
    _gated_environment(monkeypatch, runtime)  # graph ack only
    prepare_directory(
        runtime,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )

    seam = test_fault_seam.ControlledHeartbeatSuppressSeam.from_environment(
        "monitor", _Telemetry()
    )

    assert seam.enabled is False
    assert seam.suppress_if_armed() is False


def test_heartbeat_suppression_holds_then_reports_recovery(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    runtime = tmp_path / "controlled_graph_fault"
    _heartbeat_environment(monkeypatch, runtime)
    prepare_directory(
        runtime,
        live_ack=LIVE_ACK,
        graph_fault_ack=HEARTBEAT_SUPPRESS_ACK,
        kind="heartbeat_suppression",
    )
    result = arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=14.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=HEARTBEAT_SUPPRESS_ACK,
        kind="heartbeat_suppression",
    )
    assert result["kind"] == "heartbeat_suppression"
    assert result["roles"] == ["monitor"]
    assert (runtime / "monitor.heartbeat.arm").is_file()
    # The graph seam's own arm files are not created by a heartbeat arm.
    assert not (runtime / "monitor.arm").exists()

    _heartbeat_environment(monkeypatch, runtime)
    telemetry = _Telemetry()
    seam = test_fault_seam.ControlledHeartbeatSuppressSeam.from_environment(
        "monitor", telemetry
    )

    assert seam.suppress_if_armed() is True
    for _ in range(10):
        assert seam.suppress_if_armed() is True
    assert telemetry.events == [("heartbeat_suppression", "trigger")]

    seam._hold_until_ns = time.monotonic_ns() - 1
    assert seam.suppress_if_armed() is False
    seam.record_normal_heartbeat()
    assert telemetry.events == [
        ("heartbeat_suppression", "trigger"),
        ("heartbeat_suppression", "recovery"),
    ]


def test_heartbeat_seam_refuses_a_graph_arm_record(tmp_path, monkeypatch):
    """An arm of the wrong kind must not be honoured by the other seam."""
    tmp_path.chmod(0o700)
    runtime = tmp_path / "controlled_graph_fault"
    _gated_environment(monkeypatch, runtime)
    prepare_directory(
        runtime,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=5.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    # Rename a graph arm into the heartbeat seam's slot: the file is valid and
    # correctly owned, only its declared kind is wrong.
    (runtime / "monitor.arm").rename(runtime / "monitor.heartbeat.arm")

    _heartbeat_environment(monkeypatch, runtime)
    telemetry = _Telemetry()
    seam = test_fault_seam.ControlledHeartbeatSuppressSeam.from_environment(
        "monitor", telemetry
    )

    assert seam.suppress_if_armed() is False
    assert telemetry.events == []


def test_a_second_arm_after_the_hold_expires_names_why_it_was_refused(
    tmp_path, monkeypatch
):
    """The one-shot refusal must be attributable, not silent.

    This is the shape C2C-018 saw and could not diagnose: the arm file is
    written, the seam never consumes it, and nothing anywhere says why. The
    refusal reason has to survive to the caller.
    """
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=5.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    _gated_environment(monkeypatch, runtime)
    seam = ControlledGraphFaultSeam.from_environment("monitor", _Telemetry())
    assert seam.consume_if_armed() is True
    assert seam.take_refusal() is None

    # Retire the hold the way time would, without waiting for it.
    seam._hold_until_ns = None

    (runtime / "ids.arm").unlink()
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=5.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    assert seam.consume_if_armed() is False
    assert seam.last_refusal == "already_triggered"
    assert seam.take_refusal() == "already_triggered"
    # The arm file is left on disk, which is exactly how the driver's rm -f
    # erased the evidence that would have identified this.
    assert (runtime / "monitor.arm").exists()


def test_a_reportable_refusal_is_reported_once_not_every_poll(tmp_path, monkeypatch):
    """Edge-triggered, so a per-heartbeat caller cannot flood the log."""
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    arm_once(
        runtime,
        ttl_sec=20.0,
        hold_sec=5.0,
        live_ack=LIVE_ACK,
        graph_fault_ack=GRAPH_FAULT_ACK,
    )
    _gated_environment(monkeypatch, runtime)
    seam = ControlledGraphFaultSeam.from_environment("monitor", _Telemetry())
    assert seam.consume_if_armed() is True
    seam._hold_until_ns = None

    assert seam.consume_if_armed() is False
    assert seam.take_refusal() == "already_triggered"
    for _ in range(5):
        assert seam.consume_if_armed() is False
        assert seam.take_refusal() is None


def test_resting_refusals_are_recorded_but_never_reported(tmp_path, monkeypatch):
    """An unarmed seam refuses on every poll; that must stay quiet.

    Reporting the resting state would bury the refusals that mean an arm was
    thrown away, which is the only thing this instrumentation exists to find.
    """
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    _gated_environment(monkeypatch, runtime)
    seam = ControlledGraphFaultSeam.from_environment("monitor", _Telemetry())

    assert seam.consume_if_armed() is False
    assert seam.last_refusal == "no_arm_file"
    assert seam.take_refusal() is None

    disabled = ControlledGraphFaultSeam(
        role="monitor", telemetry=_Telemetry(), directory=None, enabled=False
    )
    assert disabled.consume_if_armed() is False
    assert disabled.last_refusal == "seam_disabled"
    assert disabled.take_refusal() is None
    assert test_fault_seam.QUIET_REFUSALS == {"seam_disabled", "no_arm_file"}


def test_a_rejected_arm_record_names_the_field_that_failed(tmp_path, monkeypatch):
    """A malformed arm must be distinguishable from an absent one."""
    runtime = _prepared_runtime(tmp_path, monkeypatch)
    _gated_environment(monkeypatch, runtime)
    seam = ControlledGraphFaultSeam.from_environment("monitor", _Telemetry())

    target = runtime / "monitor.arm"
    target.write_text("{not json", encoding="utf-8")
    target.chmod(0o600)
    assert seam.consume_if_armed() is False
    assert seam.last_refusal == "arm_not_json"
    assert seam.take_refusal() == "arm_not_json"
    # Rejecting an arm still consumes it: a bad record must not be retried.
    assert not target.exists()


def test_emitter_and_collector_controlled_fault_vocabularies_match():
    """The two sides must be widened together, never one alone.

    heartbeat_suppression was added to the collector when the second seam was
    written and not to the emitter.  The emitter then rejected its own event,
    the seam swallowed the ValueError, and the suppression ran while emitting
    nothing -- which was read for ten days as the seam never being consumed.
    Nothing anywhere compared the two sets.
    """
    from dds_security_monitor import runtime_telemetry
    from firewall_lab import live_telemetry_collector

    assert (
        runtime_telemetry.CONTROLLED_FAULT_KINDS
        == live_telemetry_collector.CONTROLLED_FAULT_KINDS
    )
    assert (
        runtime_telemetry.CONTROLLED_FAULT_STATES
        == live_telemetry_collector.CONTROLLED_FAULT_STATES
    )


def test_every_seam_kind_is_emittable():
    """A seam whose own KIND the emitter rejects can never report anything."""
    from dds_security_monitor import runtime_telemetry
    from dds_security_monitor.test_fault_seam import (
        ControlledGraphFaultSeam,
        ControlledHeartbeatSuppressSeam,
    )

    for seam in (ControlledGraphFaultSeam, ControlledHeartbeatSuppressSeam):
        assert seam.KIND in runtime_telemetry.CONTROLLED_FAULT_KINDS, seam.KIND


def test_a_failed_emit_is_recorded_rather_than_discarded():
    """The seam survives a telemetry fault, but stops hiding it."""
    from dds_security_monitor.test_fault_seam import ControlledGraphFaultSeam

    class _Exploding:
        def emit_controlled_fault_injection(self, kind, state):
            raise ValueError("unsupported controlled fault kind")

    seam = ControlledGraphFaultSeam(
        role="monitor", telemetry=_Exploding(), directory=None, enabled=False
    )
    seam._emit("trigger")
    error = seam.take_emit_error()
    assert error is not None
    assert "trigger" in error and "ValueError" in error
    # Reported once, then cleared.
    assert seam.take_emit_error() is None


def test_a_missing_telemetry_callback_is_also_recorded():
    from dds_security_monitor.test_fault_seam import ControlledGraphFaultSeam

    seam = ControlledGraphFaultSeam(
        role="monitor", telemetry=object(), directory=None, enabled=False
    )
    seam._emit("recovery")
    assert "no telemetry callback" in (seam.take_emit_error() or "")
