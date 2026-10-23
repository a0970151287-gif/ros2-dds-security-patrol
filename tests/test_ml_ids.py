"""Focused safety tests for the standalone ML response engine."""
from __future__ import annotations

import importlib.util
import math
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from firewall_lab.decision import FirewallDecision
from firewall_lab.evidence import EvidenceAuthority, feature_sha256
from firewall_lab.response_authorizer import ResponseAuthorizer


ROOT = Path(__file__).resolve().parents[1]
ML_DIR = ROOT / "ML防禦"
MODEL_HASH = "3" * 64
POLICY_HASH = "4" * 64
BACKEND_ID = "pytest-ml-nft-timeout-set"


def _load_response_module():
    spec = importlib.util.spec_from_file_location(
        "ml_response_engine_under_test", ML_DIR / "回應引擎.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_ml_utils():
    spec = importlib.util.spec_from_file_location(
        "ml_utils_under_test", ML_DIR / "ml_utils.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_ml_script(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, ML_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    sys.path.insert(0, str(ML_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(ML_DIR))
    return module


def _authority():
    return EvidenceAuthority(b"ml-response-test-secret" * 2, collector_id="pytest-ml")


def _live_authorizer(authority):
    return ResponseAuthorizer(
        protected_sources={"10.10.10.2/32"},
        authorized_sources={"10.10.10.0/24"},
        evidence_verifier=authority.verifier(),
        model_deployment_eligible=True,
        model_artifact_sha256=MODEL_HASH,
        policy_verified=True,
        policy_sha256=POLICY_HASH,
        network_backend_kind="nftables_timeout_set",
        network_backend_id=BACKEND_ID,
        network_backend_capacity_ready=True,
        network_backend_recovery_verified=True,
    )


def _authorized_dos(response, authority, source="10.10.10.3"):
    decision = FirewallDecision(
        predicted_class="service_dos",
        confidence=0.99,
        anomaly=True,
        action="temporary_block",
        adapter="network_helper",
        executable=True,
        reason="test response intent",
    )
    envelope = authority.issue(
        source=source,
        source_kind="network_ip",
        interface="eth-test",
        identity=f"dds:{source}",
        feature_digest=feature_sha256({"packet_rate": 99.0}),
        session_id="pytest-ml",
        window_id=f"window:{source}",
        model_sha256=MODEL_HASH,
        policy_sha256=POLICY_HASH,
        backend_id=BACKEND_ID,
        attribution_confidence=0.99,
        signals={"network": 0.99, "host": 0.90},
        source_shared=False,
        confirmation_windows=2,
        decision=decision,
    )
    return response.Detection(
        "dos",
        source,
        0.99,
        evidence_envelope=envelope,
    )


@pytest.fixture(scope="module")
def response():
    return _load_response_module()


@pytest.fixture(scope="module")
def ml_utils():
    pytest.importorskip("joblib")
    return _load_ml_utils()


@pytest.fixture(scope="module")
def baseline_training():
    pytest.importorskip("pandas")
    pytest.importorskip("sklearn")
    return _load_ml_script("ml_baseline_training_under_test", "訓練.py")


@pytest.fixture(scope="module")
def rtps_training():
    pytest.importorskip("pandas")
    pytest.importorskip("sklearn")
    return _load_ml_script("ml_rtps_training_under_test", "RTPS資料集_訓練.py")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mode": "unsafe"},
        {"confidence_min": math.nan},
        {"confidence_min": "0.7"},
        {"confidence_min": True},
        {"confidence_min": 1.1},
        {"action_cooldown": -1.0},
        {"action_cooldown": "30"},
        {"enable_firewall": "false"},
        {"max_cooldown_entries": 0},
        {"max_log_entries": True},
    ],
)
def test_engine_rejects_invalid_configuration(response, kwargs):
    with pytest.raises(ValueError):
        response.ResponseEngine(**kwargs)


@pytest.mark.parametrize("confidence", [math.nan, math.inf, -0.1, 1.1, True])
def test_invalid_confidence_fails_closed(response, confidence):
    engine = response.ResponseEngine(
        mode="live", enable_firewall=True, game_allowlist=()
    )
    with patch.object(response.subprocess, "run") as run:
        record = engine.respond(
            response.Detection("dos", "10.10.10.3", confidence)
        )
    assert not record.executed
    assert "無效信心值" in record.action
    run.assert_not_called()


def test_normal_label_does_not_bypass_malformed_confidence(response):
    engine = response.ResponseEngine()
    record = engine.respond(response.Detection("normal", "local", math.nan))
    assert "無效信心值" in record.action


@pytest.mark.parametrize(
    "source",
    [
        "10.10.10.3 --delete-all",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "10.10.10.2",  # protected robot/target address
    ],
)
def test_firewall_never_runs_for_invalid_or_protected_source(response, source):
    engine = response.ResponseEngine(
        mode="live", enable_firewall=True, game_allowlist=()
    )
    with patch.object(response.subprocess, "run") as run:
        record = engine.respond(response.Detection("dos", source, 0.99))
    assert not record.executed
    run.assert_not_called()


def test_firewall_uses_argv_and_checks_return_code(response, tmp_path):
    block_script = tmp_path / "block_source.sh"
    block_script.write_text("#!/bin/sh\n")
    authority = _authority()
    engine = response.ResponseEngine(
        mode="live",
        enable_firewall=True,
        game_allowlist=(),
        response_authorizer=_live_authorizer(authority),
    )

    failed = subprocess.CompletedProcess([], 9, stdout="", stderr="denied")
    with (
        patch.object(response, "BLOCK_SOURCE", block_script),
        patch.object(engine, "_trusted_firewall_helper", return_value=True),
        patch.object(response.subprocess, "run", return_value=failed) as run,
    ):
        record = engine.respond(_authorized_dos(response, authority))

    assert not record.executed
    argv = run.call_args.args[0]
    assert argv == [
        "sudo", "-n", str(block_script), "apply", "--ticket-stdin"
    ]
    assert "10.10.10.3" not in argv
    ticket = run.call_args.kwargs["input"]
    assert ticket
    _live_authorizer(authority).evidence_verifier.verify_ticket(
        ticket,
        source="10.10.10.3",
        action="temporary_block",
        adapter="network_helper",
        evidence_id=record.evidence_id,
        backend_id=BACKEND_ID,
        interface="eth-test",
        identity="dds:10.10.10.3",
        ttl_sec=300,
    )
    assert ticket not in record.command
    assert record.authorization_ticket_sha256
    assert run.call_args.kwargs["check"] is False
    assert run.call_args.kwargs["timeout"] == 10


def test_live_firewall_refuses_untrusted_workspace_helper(response, tmp_path):
    helper = tmp_path / "block_source.sh"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o755)
    authority = _authority()
    engine = response.ResponseEngine(
        mode="live",
        enable_firewall=True,
        game_allowlist=(),
        response_authorizer=_live_authorizer(authority),
    )
    with (
        patch.object(response, "BLOCK_SOURCE", helper),
        patch.object(response.subprocess, "run") as run,
    ):
        record = engine.respond(_authorized_dos(response, authority))
    assert not record.executed
    assert "不可信" in record.action
    run.assert_not_called()


def test_firewall_global_capacity_bounds_high_cardinality_sources(response):
    authority = _authority()
    engine = response.ResponseEngine(
        mode="live",
        enable_firewall=True,
        game_allowlist=(),
        action_cooldown=0,
        firewall_actions_per_minute=1,
        max_active_blocks=1,
        response_authorizer=_live_authorizer(authority),
    )
    succeeded = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with (
        patch.object(engine, "_trusted_firewall_helper", return_value=True),
        patch.object(response.subprocess, "run", return_value=succeeded) as run,
    ):
        first = engine.respond(
            _authorized_dos(response, authority, "10.10.10.3")
        )
        second = engine.respond(
            _authorized_dos(response, authority, "10.10.10.4")
        )
    assert first.executed
    assert not second.executed
    assert run.call_count == 1


def test_live_firewall_requires_bound_fresh_multisignal_evidence(response):
    engine = response.ResponseEngine(
        mode="live", enable_firewall=True, game_allowlist=()
    )
    with patch.object(response.subprocess, "run") as run:
        record = engine.respond(
            response.Detection("dos", "10.10.10.3", 0.99)
        )
    assert not record.executed
    assert "雙證據" in record.action
    run.assert_not_called()


def test_ml_engine_cannot_swap_signed_source_a_to_source_b(response):
    authority = _authority()
    engine = response.ResponseEngine(
        mode="live",
        enable_firewall=True,
        game_allowlist=(),
        response_authorizer=_live_authorizer(authority),
    )
    detection = _authorized_dos(response, authority, "10.10.10.3")
    detection.source = "10.10.10.99"
    with patch.object(response.subprocess, "run") as run:
        record = engine.respond(detection)
    assert not record.executed
    assert "雙證據" in record.action
    assert "does not match signed evidence" in record.note
    run.assert_not_called()


def test_helper_failure_does_not_consume_success_cooldown(response):
    authority = _authority()
    engine = response.ResponseEngine(
        mode="live",
        enable_firewall=True,
        game_allowlist=(),
        response_authorizer=_live_authorizer(authority),
    )
    failed = subprocess.CompletedProcess([], 9, stdout="", stderr="denied")
    succeeded = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with (
        patch.object(engine, "_trusted_firewall_helper", return_value=True),
        patch.object(
            response.subprocess,
            "run",
            side_effect=[failed, succeeded],
        ) as run,
    ):
        detection = _authorized_dos(response, authority)
        first = engine.respond(detection)
        second = engine.respond(detection)
    assert not first.executed
    assert "失敗" in first.action
    assert second.executed
    assert run.call_count == 2


def test_response_log_stores_bounded_detection_copy(response):
    engine = response.ResponseEngine(max_log_entries=1)
    huge = "x" * 100_000
    record = engine.respond(
        response.Detection("recon", huge, 0.99, evidence=huge)
    )
    assert len(record.detection.source) <= 128
    assert len(record.detection.evidence) <= 512


def test_invalid_attack_class_does_not_crash_formatter(response):
    engine = response.ResponseEngine()
    record = engine.respond(response.Detection(["dos"], "10.10.10.3", 0.99))
    assert not record.executed
    assert "無效攻擊類別" in record.action


def test_attacker_cardinality_cannot_grow_engine_state_without_bound(response):
    engine = response.ResponseEngine(
        action_cooldown=3600,
        max_cooldown_entries=3,
        max_log_entries=2,
    )
    for i in range(10):
        engine.respond(response.Detection("recon", f"10.10.20.{i}", 0.99))
    assert len(engine._last_action) == 3
    assert len(engine.log) == 2


def test_authenticated_joblib_round_trip_and_tamper_rejection(ml_utils, tmp_path):
    secret = b"k" * 32
    artifact = tmp_path / "model.joblib"
    ml_utils.atomic_joblib_dump({"features": ["x"], "version": 1}, artifact,
                                secret=secret)

    assert ml_utils.signature_path(artifact).is_file()
    assert ml_utils.verified_joblib_load(artifact, secret=secret)["version"] == 1

    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(ml_utils.ArtifactIntegrityError):
        ml_utils.verified_joblib_load(artifact, secret=secret)


def test_unsigned_joblib_is_never_deserialized(ml_utils, tmp_path, monkeypatch):
    artifact = tmp_path / "legacy.joblib"
    artifact.write_bytes(b"not safe pickle")
    import joblib

    called = False

    def fake_load(_path):
        nonlocal called
        called = True
        raise AssertionError("joblib.load must not run before verification")

    monkeypatch.setattr(joblib, "load", fake_load)
    with pytest.raises(ml_utils.ArtifactIntegrityError):
        ml_utils.verified_joblib_load(artifact, secret=b"k" * 32)
    assert not called


def test_verified_joblib_load_uses_fixed_filelike_snapshot(
    ml_utils, tmp_path, monkeypatch
):
    secret = b"k" * 32
    original = b"authenticated-joblib-bytes"
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(original)
    ml_utils.sign_artifact(artifact, secret)
    import joblib

    seen = {}

    def fake_load(snapshot):
        seen["snapshot"] = snapshot
        assert hasattr(snapshot, "read")
        assert hasattr(snapshot, "seek")
        assert not isinstance(snapshot, (str, bytes, Path))

        # Replace the source only after it was authenticated and copied.  A
        # vulnerable verify(path) -> load(path) flow would read these bytes.
        artifact.write_bytes(b"attacker-replacement")
        snapshot.seek(0)
        return snapshot.read()

    monkeypatch.setattr(joblib, "load", fake_load)
    loaded = ml_utils.verified_joblib_load(artifact, secret=secret)

    assert loaded == original
    assert seen["snapshot"].closed


def test_temporal_group_holdout_has_zero_overlap(baseline_training):
    import numpy as np

    groups = np.repeat([f"capture-{i}" for i in range(6)], 2)
    y = np.tile([0, 1], 6)
    X = np.arange(len(y) * 2, dtype=float).reshape(len(y), 2)
    train, test = baseline_training.grouped_holdout(X, y, groups)

    assert set(groups[train]).isdisjoint(set(groups[test]))
    assert set(y[train]) == {0, 1}
    assert set(y[test]) == {0, 1}


def test_firewall_session_id_takes_priority_over_time_blocks(
        baseline_training):
    import pandas as pd

    df = pd.DataFrame(
        {
            "group_id": ["session-a", "session-a", "session-b"],
            "source": ["same"] * 3,
            "window": [0, 999, 0],
        }
    )
    groups = baseline_training.temporal_groups(df, block_windows=1)
    assert groups.tolist() == ["session-a", "session-a", "session-b"]


def test_rtps_single_capture_falls_back_to_disjoint_blocks(rtps_training):
    import numpy as np
    import pandas as pd

    df = pd.DataFrame({"capture": ["one.csv"] * 16})
    groups = rtps_training.capture_groups(df, fallback_block_rows=4)
    y = np.tile([0, 1, 0, 1], 4)
    X = np.arange(len(y) * 2, dtype=float).reshape(len(y), 2)
    train, test = rtps_training.grouped_holdout(X, y, groups)

    assert len(set(groups)) == 4
    assert set(groups[train]).isdisjoint(set(groups[test]))
