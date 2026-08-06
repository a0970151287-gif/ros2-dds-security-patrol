"""Tests for the inert-by-default one-shot graph inspection fault seam."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from firewall_lab.local_graph_fault_control import (
    GRAPH_FAULT_ACK,
    LIVE_ACK,
    arm_once,
    prepare_directory,
)
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
