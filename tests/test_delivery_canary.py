"""The canary must produce archives the delivery verifier accepts.

Format agreement between a producer and a verifier written separately is the
kind of thing that only fails at the moment it matters, so this drives the real
writer and hands the result to the real verifier. No ROS is involved: the node's
archive writer is exercised directly, which is the part the verifier cares
about.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from firewall_lab.schema import SchemaError, sha256_file
from firewall_lab.sros2_delivery_evidence import (
    CONTRACT_SCHEMA,
    verify_delivery_evidence,
)

SESSION_ID = "20260818T120000000000Z_delivery_canary_1234abcd"
TRIAL = "canary_trial_0001"
POLICY = "a" * 64
TOPIC = "/security/delivery_canary"


def _writer(path, role):
    """Build the node's archive writer without importing rclpy."""
    import importlib.util
    import sys
    import types

    name = "dds_security_monitor.delivery_canary"
    if name in sys.modules:
        return sys.modules[name]._ArchiveWriter, sys.modules[name]

    # rclpy and std_msgs are not installed in the ML test venv; the archive
    # writer does not use them, so stand them in to import the module.
    for missing, attrs in (
        ("rclpy", {"init": lambda *a, **k: None, "ok": lambda: False,
                   "shutdown": lambda: None, "spin": lambda *a: None}),
        ("rclpy.node", {"Node": type("Node", (), {"__init__": lambda self, *a, **k: None})}),
        ("rclpy.qos", {"QoSProfile": object, "ReliabilityPolicy": type("R", (), {"RELIABLE": 1})}),
        ("rclpy.utilities", {"remove_ros_args": lambda argv: argv}),
        ("std_msgs.msg", {"String": type("String", (), {"data": ""})}),
        ("std_msgs", {}),
    ):
        if missing not in sys.modules:
            module = types.ModuleType(missing)
            for key, value in attrs.items():
                setattr(module, key, value)
            sys.modules[missing] = module

    source = (
        Path(__file__).resolve().parents[1]
        / "src" / "dds_security_monitor" / "dds_security_monitor" / "delivery_canary.py"
    )
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module._ArchiveWriter, module


def _binding(mode, role):
    # The verifier refuses archives that share a collector: the attacker's own
    # record of what it sent must not come from the same collector as the
    # protected sink's record of what arrived.
    return {
        "session_id": SESSION_ID,
        "trial_id": TRIAL,
        "security_mode": mode,
        "policy_sha256": POLICY,
        "source_id": "canary_source",
        "source_enclave": "/canary_source",
        "protected_sink_id": "canary_sink",
        "protected_enclave": "/canary_sink",
        "canary_topic": TOPIC,
        "collector_id": f"pytest_collector_{role}",
        "collector_boot_id": ("b" if role == "attempted" else "c") * 32,
    }


def _write_pair(tmp_path, mode, attempted_sequences, received_sequences):
    """Write both archives interleaved, the way two live nodes would.

    Written one after the other they do not overlap in time, and the verifier
    requires both archives to bracket the same window, so no valid window
    would exist. Interleaving mirrors the real run.
    """
    ArchiveWriter, module = _writer(tmp_path, "attempted")
    paths = {
        "attempted": tmp_path / "attempted.jsonl",
        "protected_received": tmp_path / "protected_received.jsonl",
    }
    writers = {
        role: ArchiveWriter(paths[role], binding=_binding(mode, role), role=role)
        for role in paths
    }
    for writer in writers.values():
        writer.open_archive()
    for writer in writers.values():
        writer.heartbeat()
    for sequence in attempted_sequences:
        writers["attempted"].canary(sequence, module._payload(TRIAL, sequence))
    for sequence in received_sequences:
        writers["protected_received"].canary(sequence, module._payload(TRIAL, sequence))
    for _ in range(2):
        for writer in writers.values():
            writer.heartbeat()
    for writer in writers.values():
        writer.close_archive()
    return paths["attempted"], paths["protected_received"]


def _contract(tmp_path, mode, attempted, received, *, attempts):
    # The verifier requires open <= first_heartbeat <= start <= end <=
    # Both archives must bracket the same window, so take the intersection:
    # start at the later first heartbeat, end at the earlier last one.
    def beats(path):
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        return [r["ts_utc"] for r in rows if r["record_type"] == "collector_heartbeat"]

    a, b = beats(attempted), beats(received)
    start = max(a[0], b[0])
    end = min(a[-1], b[-1])
    contract = {
        "schema_version": CONTRACT_SCHEMA,
        "pair_id": TRIAL,
        "pairing_attested": True,
        "trial_id": TRIAL,
        "session_id": SESSION_ID,
        "security_mode": mode,
        "policy_sha256": POLICY,
        "source_id": "canary_source",
        "source_enclave": "/canary_source",
        "protected_sink_id": "canary_sink",
        "protected_enclave": "/canary_sink",
        "canary_topic": TOPIC,
        "publisher_authorization": {
            "authorization_case": "uncredentialed_publisher",
            "credential_state": (
                "security_disabled" if mode == "permissive" else "absent"
            ),
            "permission_state": (
                "not_enforced" if mode == "permissive" else "not_reached"
            ),
            "subject_enclave": "/canary_source",
            "topic": TOPIC,
            "context_attested": False,
        },
        "window": {"start_utc": start, "end_utc": end},
        "expected_first_sequence": 0,
        "expected_attempt_count": attempts,
        "collector_requirements": {
            "minimum_heartbeats": 2,
            "maximum_heartbeat_gap_ms": 60_000,
        },
        "archives": {
            role: {
                "path": path.name,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for role, path in (
                ("attempted", attempted),
                ("protected_received", received),
            )
        },
    }
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    return contract_path


def test_enforce_archives_show_attempts_with_no_delivery(tmp_path):
    """The Enforce claim: traffic was attempted and none of it arrived."""
    attempted, received = _write_pair(tmp_path, "enforce", range(10), [])
    report = verify_delivery_evidence(_contract(tmp_path, "enforce", attempted, received, attempts=10))
    result = report["result"]
    assert result["attempted_count"] == 10
    assert result["delivered_count"] == 0
    assert result["blocked_count"] == 10
    assert result["passed"] is True
    # Enforce: every blocked attempt is a true positive, nothing got through.
    assert report["confusion_matrix"] == {"tp": 10, "fn": 0, "fp": 0, "tn": 0}


def test_permissive_archives_show_the_same_traffic_arriving(tmp_path):
    """Without the control, an Enforce zero could just mean a broken canary."""
    attempted, received = _write_pair(tmp_path, "permissive", range(10), range(10))
    report = verify_delivery_evidence(_contract(tmp_path, "permissive", attempted, received, attempts=10))
    result = report["result"]
    assert result["attempted_count"] == 10
    assert result["delivered_count"] == 10
    assert result["passed"] is True
    # Permissive is the control: the same traffic must arrive, otherwise an
    # Enforce zero would only show the canary was broken.
    assert report["confusion_matrix"] == {"tp": 0, "fn": 0, "fp": 0, "tn": 10}


def test_a_truncated_archive_is_refused(tmp_path):
    """An interrupted run must not read as a clean prevention result."""
    attempted, received = _write_pair(tmp_path, "enforce", range(10), [])
    contract_path = _contract(tmp_path, "enforce", attempted, received, attempts=10)

    lines = attempted.read_text(encoding="utf-8").splitlines()
    attempted.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract["archives"]["attempted"]["sha256"] = sha256_file(attempted)
    contract["archives"]["attempted"]["bytes"] = attempted.stat().st_size
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    with pytest.raises(SchemaError):
        verify_delivery_evidence(contract_path)
