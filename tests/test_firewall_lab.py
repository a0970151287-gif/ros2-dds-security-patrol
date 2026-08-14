"""Regression tests for the SROS2 firewall dataset factory."""

from __future__ import annotations

import re

import csv
import json
import math
import time
from types import SimpleNamespace
from pathlib import Path

import pytest

from firewall_lab import campaign as campaign_module
from firewall_lab.campaign import (
    _ensure_minimum_free_space,
    _validate_minimum_free_gib,
    create_campaign_plan,
    execute_campaign,
    load_campaign_plan,
    validate_campaign_plan,
)
from firewall_lab.catalog import (
    ALLOWED_RUNNERS,
    CATALOG_SCHEMA_VERSION,
    load_catalog,
)
from firewall_lab.decision import DecisionPolicy
from firewall_lab.features import build_features
from firewall_lab.formal_preflight import (
    ISOLATED_LAB_ACK,
    LIVE_MULTIMODAL_CONTRACT_SCHEMA,
    LOCALHOST_ACK,
    _live_multimodal_contract_check,
    _topology_check,
)
from firewall_lab.orchestrator import main as orchestrator_main
from firewall_lab.orchestrator import _attack_process_succeeded, run_session
from firewall_lab.runners import attacker_environment, build_attack_argv
from firewall_lab.schema import (
    SchemaError,
    SessionManifest,
    atomic_write_json,
    make_label,
    new_session_id,
    safe_json_value,
)
from firewall_lab.synthetic_dataset import (
    FUSION_FEATURES,
    TELEMETRY_FEATURES,
    generate_synthetic_dataset,
    load_synthetic_scenarios,
    verify_synthetic_dataset,
)
from firewall_lab.train import FEATURES, load_training_frame


def test_catalog_is_command_free_and_allowlisted():
    catalog = load_catalog()
    assert len(catalog) >= 8
    assert {item.runner for item in catalog.values()} <= ALLOWED_RUNNERS
    assert catalog["normal_patrol"].attack_class == "normal"
    assert all("command" not in vars(item) for item in catalog.values())


def test_catalog_rejects_arbitrary_runner(tmp_path):
    catalog = {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "scenarios": [
            {
                "id": "bad_runner",
                "attack_class": "injection",
                "runner": "shell",
                "description": "must be rejected",
                "default_security_mode": "enforce",
                "duration_sec": 5,
                "warmup_sec": 1,
                "cooldown_sec": 1,
                "intensity_min": 0,
                "intensity_max": 1,
                "expected_action": "drop_message",
                "requires_gazebo": False,
            }
        ],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    with pytest.raises(SchemaError, match="allowlisted"):
        load_catalog(path)


def test_smoke_manifest_can_never_be_trainable():
    manifest = SessionManifest(
        session_id=new_session_id("normal_patrol"),
        scenario_id="normal_patrol",
        attack_class="normal",
        binary_label="normal",
        security_mode="enforce",
        ros_domain_id=30,
        seed=1,
        origin="simulated_smoke",
        training_eligible=True,
        expected_action="allow",
        policy_sha256="",
        code_revision="unknown",
    )
    with pytest.raises(SchemaError, match="may not be trainable"):
        manifest.to_dict()


def test_evidence_redacts_secret_like_keys():
    safe = safe_json_value(
        {
            "token": "do-not-log",
            "nested": {"private_key": "key", "value": "ok"},
        }
    )
    assert safe["token"] == "<redacted>"
    assert safe["nested"]["private_key"] == "<redacted>"
    assert safe["nested"]["value"] == "ok"


def test_attacker_environment_does_not_inherit_credentials():
    env = attacker_environment(
        domain_id=99,
        base={
            "PATH": "/usr/bin",
            "DDS_ALERT_SECRET": "secret",
            "LINE_CHANNEL_TOKEN": "token",
            "ROS_SECURITY_KEYSTORE": "/keys",
            "ROS_SECURITY_ENABLE": "true",
            "ROS_SECURITY_STRATEGY": "Enforce",
            "ROS_SECURITY_ENCLAVE_OVERRIDE": "/admin",
        },
    )
    assert env["ROS_DOMAIN_ID"] == "99"
    assert env["PATH"] == "/usr/bin"
    for key in (
        "DDS_ALERT_SECRET",
        "LINE_CHANNEL_TOKEN",
        "ROS_SECURITY_KEYSTORE",
        "ROS_SECURITY_ENABLE",
        "ROS_SECURITY_STRATEGY",
        "ROS_SECURITY_ENCLAVE_OVERRIDE",
    ):
        assert key not in env


def test_attack_runner_uses_fixed_argv_and_bounded_payload():
    scenario = load_catalog()["oversized_scan"]
    argv = build_attack_argv(
        scenario,
        workspace_root=Path(__file__).resolve().parents[1],
        duration_sec=10,
        intensity=99,
    )
    assert argv is not None
    assert isinstance(argv, list)
    assert "shell" not in " ".join(argv).lower()
    assert int(argv[-3]) == 50_000
    assert float(argv[-2]) == 3.0
    assert float(argv[-1]) == 10.0


def test_smoke_session_is_complete_but_excluded_from_training(tmp_path):
    scenario = load_catalog()["cmd_vel_injection"]
    session_dir = run_session(
        scenario=scenario,
        output_root=tmp_path,
        mode="smoke",
        security_mode="enforce",
        domain_id=30,
        seed=7,
        duration_override=1.0,
        capture_interface=None,
        ros_snapshots=False,
    )
    manifest = json.loads(
        (session_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "complete"
    assert manifest["origin"] == "simulated_smoke"
    assert manifest["training_eligible"] is False
    labels = [
        json.loads(line)
        for line in (session_dir / "labels.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(labels) == 1
    assert labels[0]["attack_class"] == "command_injection"
    events = [
        json.loads(line)
        for line in (session_dir / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [event["sequence"] for event in events] == list(range(len(events)))

    excluded = build_features(
        dataset_root=tmp_path,
        output_dir=tmp_path / "features_excluded",
    )
    assert excluded["session_rows"] == 0
    included = build_features(
        dataset_root=tmp_path,
        output_dir=tmp_path / "features_included",
        include_nontrainable=True,
    )
    assert included["session_rows"] == 1
    assert included["observation_rows"] == 12
    with (tmp_path / "features_included" /
          "smoke_observation_features.csv").open(
              encoding="utf-8", newline=""
          ) as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert {row["training_eligible"] for row in rows} == {"False"}


def test_live_network_features_use_session_ground_truth(tmp_path):
    session_id = new_session_id("parameter_flood")
    session = tmp_path / session_id
    (session / "zeek").mkdir(parents=True)
    now = time.time_ns()
    label = make_label(
        session_id=session_id,
        attack_class="service_dos",
        start_unix_ns=now,
        end_unix_ns=now + 10_000_000_000,
        source="allowlisted_runner",
    )
    (session / "labels.jsonl").write_text(
        json.dumps(label) + "\n",
        encoding="utf-8",
    )
    (session / "events.jsonl").write_text("", encoding="utf-8")
    (session / "resources.jsonl").write_text("", encoding="utf-8")
    timestamp = now / 1_000_000_000 + 1
    conn = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
        f"{timestamp:.6f}\t10.10.10.1\t239.255.0.1\t14900\tudp\n"
        f"{timestamp + 0.1:.6f}\t10.10.10.1\t10.10.10.2\t14913\tudp\n"
    )
    (session / "zeek" / "conn.log").write_text(conn, encoding="utf-8")
    manifest = SessionManifest(
        session_id=session_id,
        scenario_id="parameter_flood",
        attack_class="service_dos",
        binary_label="attack",
        security_mode="enforce",
        ros_domain_id=30,
        seed=11,
        origin="live_lab",
        training_eligible=True,
        expected_action="rate_limit",
        policy_sha256="a" * 64,
        code_revision="unknown",
        status="complete",
    )
    manifest.write(session / "manifest.json")

    result = build_features(
        dataset_root=tmp_path,
        output_dir=tmp_path / "features",
    )
    assert result["network_rows"] == 1
    with (tmp_path / "features" / "network_features.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["group_id"] == session_id
    assert rows[0]["label"] == "service_dos"
    assert rows[0]["binary"] == "attack"
    assert rows[0]["training_eligible"] == "True"
    assert rows[0]["evaluation_eligible"] == "True"
    assert rows[0]["origin"] == "live_lab"
    assert rows[0]["policy_sha256"] == "a" * 64
    assert all(math.isfinite(float(rows[0][name])) for name in FEATURES)


def test_live_cli_requires_explicit_isolated_lab_confirmation(tmp_path):
    with pytest.raises(SystemExit, match="live mode refused"):
        orchestrator_main(
            [
                "--mode",
                "live",
                "--scenario",
                "normal_patrol",
                "--output",
                str(tmp_path),
            ]
        )


def test_default_campaign_is_1100_balanced_live_sessions():
    plan = create_campaign_plan()
    assert plan["experiment_mode"] == "live"
    assert len(plan["entries"]) == 1100
    assert len({entry["entry_id"] for entry in plan["entries"]}) == 1100
    assert len({entry["seed"] for entry in plan["entries"]}) == 1100
    assert {entry["status"] for entry in plan["entries"]} == {"pending"}
    assert {entry["domain_id"] for entry in plan["entries"]} == {30}
    for counts in plan["requested_counts"].values():
        assert counts["permissive"] == counts["enforce"]
        assert counts["total"] == counts["permissive"] + counts["enforce"]
    assert plan["requested_counts"]["normal_patrol"]["total"] == 300
    for scenario_id, counts in plan["requested_counts"].items():
        if scenario_id != "normal_patrol":
            assert counts["total"] == 100


def test_campaign_rejects_plan_tampering():
    plan = create_campaign_plan(
        normal_sessions=2,
        attack_sessions_per_scenario=2,
        seed=9,
    )
    plan["entries"][0]["scenario_id"] = "arbitrary_shell"
    with pytest.raises(SchemaError, match="unknown campaign scenario"):
        validate_campaign_plan(plan)


def test_campaign_rejects_catalog_drift():
    plan = create_campaign_plan(
        normal_sessions=2,
        attack_sessions_per_scenario=2,
        seed=10,
    )
    plan["catalog_sha256"] = "0" * 64
    with pytest.raises(SchemaError, match="does not match"):
        validate_campaign_plan(plan)


def test_completed_legacy_campaign_remains_verifiable_but_not_resumable():
    plan = create_campaign_plan(
        normal_sessions=2,
        attack_sessions_per_scenario=2,
        seed=10,
    )
    plan["catalog_sha256"] = (
        "e1d376e2633e000183e0f1e644d9f9969c2f8dc5d91a0535c5cd6a98da6dfe9b"
    )
    for entry in plan["entries"]:
        entry["status"] = "complete"
        entry["session_id"] = f"legacy_{entry['entry_id']}"
        if entry["scenario_id"] == "parameter_flood":
            entry["expected_action"] = "rate_limit"

    assert validate_campaign_plan(plan)["catalog_sha256"] == plan["catalog_sha256"]

    plan["entries"][0]["status"] = "pending"
    with pytest.raises(SchemaError, match="verification-only"):
        validate_campaign_plan(plan)


@pytest.mark.parametrize(
    "value",
    [0, -1, math.nan, math.inf, True, 1024.1, "8"],
)
def test_campaign_rejects_invalid_disk_reserve(value):
    with pytest.raises(ValueError, match="minimum_free_gib"):
        _validate_minimum_free_gib(value)


def test_campaign_disk_reserve_accepts_exact_threshold(
    tmp_path,
    monkeypatch,
):
    threshold = 8 * 1024**3
    monkeypatch.setattr(
        campaign_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=threshold),
    )
    assert _ensure_minimum_free_space(tmp_path, 8) == threshold


def _write_small_campaign(path):
    plan = create_campaign_plan(
        normal_sessions=2,
        attack_sessions_per_scenario=2,
        seed=20260728,
    )
    atomic_write_json(path, plan)
    return plan


def _fake_completed_session(output_root, calls, **_kwargs):
    calls.append(len(calls) + 1)
    session = output_root / f"test_session_{len(calls):02d}"
    session.mkdir()
    (session / "manifest.json").write_text(
        json.dumps(
            {
                "status": "complete",
                "origin": "live_lab",
                "training_eligible": True,
            }
        ),
        encoding="utf-8",
    )
    return session


def test_campaign_low_disk_keeps_entry_pending_and_releases_lock(
    tmp_path,
    monkeypatch,
):
    plan_path = tmp_path / "campaign.json"
    _write_small_campaign(plan_path)
    dataset = tmp_path / "dataset"
    calls = []
    monkeypatch.setattr(
        campaign_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=1024**3),
    )
    monkeypatch.setattr(
        campaign_module,
        "run_session",
        lambda **kwargs: _fake_completed_session(
            kwargs["output_root"],
            calls,
        ),
    )

    with pytest.raises(RuntimeError, match="free_bytes"):
        execute_campaign(
            plan_path=plan_path,
            dataset_root=dataset,
            security_mode="enforce",
            capture_interface="lo",
            limit=1,
            confirm_isolated_lab=True,
            minimum_free_gib=8,
        )

    assert calls == []
    assert {
        entry["status"] for entry in load_campaign_plan(plan_path)["entries"]
    } == {"pending"}
    assert not plan_path.with_suffix(".json.lock").exists()


def test_campaign_rechecks_disk_before_every_session(
    tmp_path,
    monkeypatch,
):
    plan_path = tmp_path / "campaign.json"
    _write_small_campaign(plan_path)
    dataset = tmp_path / "dataset"
    calls = []
    free_values = iter([16 * 1024**3, 1024**3])
    monkeypatch.setattr(
        campaign_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=next(free_values)),
    )
    monkeypatch.setattr(
        campaign_module,
        "run_session",
        lambda **kwargs: _fake_completed_session(
            kwargs["output_root"],
            calls,
        ),
    )

    with pytest.raises(RuntimeError, match="free_bytes"):
        execute_campaign(
            plan_path=plan_path,
            dataset_root=dataset,
            security_mode="enforce",
            capture_interface="lo",
            limit=2,
            confirm_isolated_lab=True,
            minimum_free_gib=8,
        )

    entries = [
        entry
        for entry in load_campaign_plan(plan_path)["entries"]
        if entry["security_mode"] == "enforce"
    ]
    assert calls == [1]
    assert sum(entry["status"] == "complete" for entry in entries) == 1
    assert sum(entry["status"] == "pending" for entry in entries) == (
        len(entries) - 1
    )
    assert not plan_path.with_suffix(".json.lock").exists()


def test_attack_process_gate_rejects_crashed_runner():
    catalog = load_catalog()
    regular = catalog["oversized_scan"]
    assert _attack_process_succeeded(
        regular,
        {"return_code": 0, "terminated_by_factory": True},
    )
    assert not _attack_process_succeeded(
        regular,
        {"return_code": 1, "terminated_by_factory": False},
    )

    participant = catalog["unauthorized_participant"]
    assert _attack_process_succeeded(
        participant,
        {"return_code": -15, "terminated_by_factory": True},
    )
    assert not _attack_process_succeeded(
        participant,
        {"return_code": -15, "terminated_by_factory": False},
    )
    assert _attack_process_succeeded(catalog["normal_patrol"], None)


def test_formal_preflight_requires_topology_specific_isolation():
    local_ok, _, local_claim = _topology_check(
        topology="same_host_loopback",
        capture_interface="lo",
        isolation_ack=LOCALHOST_ACK,
        environment={"ROS_LOCALHOST_ONLY": "1"},
    )
    assert local_ok is True
    assert local_claim == "local_adversary_only_not_cross_host"

    local_bad, _, _ = _topology_check(
        topology="same_host_loopback",
        capture_interface="eth0",
        isolation_ack=LOCALHOST_ACK,
        environment={"ROS_LOCALHOST_ONLY": "1"},
    )
    assert local_bad is False

    cross_ok, _, cross_claim = _topology_check(
        topology="isolated_cross_host",
        capture_interface="eth0",
        isolation_ack=ISOLATED_LAB_ACK,
        environment={},
    )
    assert cross_ok is True
    assert cross_claim == "owned_isolated_cross_host_lab"

    cross_bad, _, _ = _topology_check(
        topology="isolated_cross_host",
        capture_interface="eth0",
        isolation_ack=ISOLATED_LAB_ACK,
        environment={"ROS_LOCALHOST_ONLY": "1"},
    )
    assert cross_bad is False


def test_formal_preflight_fails_closed_until_live_multimodal_is_validated(
    tmp_path,
):
    contract = {
        "schema_version": LIVE_MULTIMODAL_CONTRACT_SCHEMA,
        "status": "blocked",
        "blockers": ["collector missing"],
    }
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    passed, detail = _live_multimodal_contract_check(
        contract_path,
        workspace_root=tmp_path,
    )
    assert passed is False
    assert "collector missing" in detail


def test_live_multimodal_contract_requires_artifacts_and_exact_schema(
    tmp_path,
):
    from firewall_lab.synthetic_dataset import TELEMETRY_FEATURES

    artifacts = [
        "firewall_lab/live_telemetry_collector.py",
        "firewall_lab/features.py",
        "tests/test_live_multimodal.py",
    ]
    for relative_name in artifacts:
        path = tmp_path / relative_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# contract test\n", encoding="utf-8")
    contract = {
        "schema_version": LIVE_MULTIMODAL_CONTRACT_SCHEMA,
        "status": "validated",
        "network_feature_count": 14,
        "telemetry_features": TELEMETRY_FEATURES,
        "alignment_keys": ["session_id", "window"],
        "required_outputs": [
            "network_features.csv",
            "telemetry_features.csv",
            "fusion_features.csv",
        ],
        "implementation_artifacts": artifacts,
        "blockers": [],
    }
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    passed, detail = _live_multimodal_contract_check(
        contract_path,
        workspace_root=tmp_path,
    )
    assert passed is True
    assert "14 network + 18 telemetry" in detail


def test_decision_policy_only_executes_high_confidence_allowlisted_adapter():
    policy = DecisionPolicy.load()
    accepted = policy.decide(
        predicted_class="command_injection",
        confidence=0.91,
        anomaly=False,
    )
    assert accepted.action == "lock_velocity"
    assert accepted.adapter == "velocity_guard"
    assert accepted.executable is True

    low_confidence = policy.decide(
        predicted_class="command_injection",
        confidence=0.69,
        anomaly=False,
    )
    assert low_confidence.action == "alert"
    assert low_confidence.adapter == "none"
    assert low_confidence.executable is False


def test_decision_policy_fails_closed_on_invalid_or_disagreeing_model():
    policy = DecisionPolicy.load()
    invalid = policy.decide(
        predicted_class="service_dos",
        confidence=float("nan"),
        anomaly=True,
    )
    assert invalid.action == "alert"
    assert invalid.executable is False

    disagreement = policy.decide(
        predicted_class="normal",
        confidence=0.99,
        anomaly=True,
    )
    assert disagreement.action == "quarantine"
    assert disagreement.adapter == "none"
    assert disagreement.executable is False


def test_synthetic_pretraining_dataset_is_grouped_and_reproducible(tmp_path):
    plan = create_campaign_plan(
        normal_sessions=6,
        attack_sessions_per_scenario=6,
        seed=1234,
    )
    plan_path = tmp_path / "plan.json"
    atomic_write_json(plan_path, plan)
    first = tmp_path / "first"
    second = tmp_path / "second"
    result = generate_synthetic_dataset(
        plan_path=plan_path,
        output_dir=first,
        windows_per_session=12,
        split_seed=77,
        extra_sessions_per_scenario=2,
    )
    generate_synthetic_dataset(
        plan_path=plan_path,
        output_dir=second,
        windows_per_session=12,
        split_seed=77,
        extra_sessions_per_scenario=2,
    )
    assert result["sessions"] == 82
    assert result["rows"] == 984
    assert result["classes"] == 23
    assert result["quality_passed"] is True
    verified = verify_synthetic_dataset(first)
    assert verified["valid"] is True
    assert verified["rows"] == 984
    assert (first / "network_features.csv").read_bytes() == (
        second / "network_features.csv"
    ).read_bytes()

    with (first / "network_features.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        rows = list(csv.DictReader(handle))
    assert {row["origin"] for row in rows} == {"synthetic_pretrain"}
    assert {row["training_eligible"] for row in rows} == {"True"}
    assert {row["evaluation_eligible"] for row in rows} == {"False"}
    assert {row["ros_domain_id"] for row in rows} == {"30"}
    group_splits = {}
    for row in rows:
        group_splits.setdefault(row["group_id"], set()).add(row["split"])
        assert all(math.isfinite(float(row[name])) for name in FEATURES)
    assert all(len(splits) == 1 for splits in group_splits.values())

    with (first / "fusion_features.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        fusion_rows = list(csv.DictReader(handle))
    assert len(fusion_rows) == 984
    assert {
        row["scenario_origin"] for row in fusion_rows
    } == {"live_runner_backed", "synthetic_only"}
    assert all(
        math.isfinite(float(row[name]))
        for row in fusion_rows
        for name in FUSION_FEATURES
    )
    assert all(name in fusion_rows[0] for name in TELEMETRY_FEATURES)

    pytest.importorskip("pandas")
    frame = load_training_frame(
        first / "network_features.csv",
        data_tier="synthetic-pretrain",
    )
    assert len(frame) == 984
    with pytest.raises(ValueError, match="live training requires"):
        load_training_frame(
            first / "network_features.csv",
            data_tier="live",
        )


def test_synthetic_attack_catalog_matches_multimodal_profiles():
    scenarios = load_synthetic_scenarios()
    assert len(scenarios) == 14
    assert {scenario["attack_class"] for scenario in scenarios.values()} >= {
        "discovery_recon",
        "spdp_flood",
        "cross_channel_relay",
        "cmd_vel_race",
        "scan_drift",
        "odom_spoof",
        "verify_flood",
        "confused_deputy",
    }


def test_managed_process_stop_kills_descendants_not_just_the_child(tmp_path):
    """A wrapper's grandchildren must die with it.

    The unauthorized_participant runner is `ros2 run demo_nodes_cpp talker`,
    where `ros2 run` is a CLI wrapper that spawns the real talker.  stop() used
    to signal only the direct child, so the 2026-08-07 ten-session batch left a
    talker alive.  Across the 50 such sessions in one 550-session arm those
    survivors would keep publishing on domain 30 and contaminate the network
    features of later, supposedly attack-free sessions.
    """
    import os
    import subprocess
    import time

    from firewall_lab.evidence import ManagedProcess

    marker = tmp_path / "grandchild.pid"
    # A shell parent with a backgrounded child: the same shape as `ros2 run`
    # exec'ing the real node, without nesting Python quoting three deep.
    process = ManagedProcess(
        argv=["/bin/sh", "-c", f"sleep 300 & echo $! > {marker}; wait"],
        cwd=tmp_path,
        env=dict(os.environ),
        stdout_path=tmp_path / "out.log",
        stderr_path=tmp_path / "err.log",
    )
    process.start()
    for _ in range(100):
        if marker.is_file() and marker.read_text().strip():
            break
        time.sleep(0.1)
    assert marker.is_file() and marker.read_text().strip(), (
        "test setup failed; stderr: "
        + (tmp_path / "err.log").read_text(encoding="utf-8")[:400]
    )
    grandchild = int(marker.read_text().strip())

    def alive(pid: int) -> bool:
        try:
            state = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(pid)],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
        except Exception:
            return False
        # A zombie has exited; only a real running state counts as alive.
        return bool(state) and not state.startswith("Z")

    assert alive(grandchild), "test setup failed: grandchild never ran"
    process.stop()
    for _ in range(60):
        if not alive(grandchild):
            break
        time.sleep(0.1)
    assert not alive(grandchild), (
        "grandchild survived stop(); the process group was not signalled"
    )


def test_collector_startup_deadline_has_real_margin():
    """A slow start must not be mistaken for a failure.

    The collector spawns an interpreter and imports this package, which costs
    ~0.8s from the WSL 9p mount. Measured socket-bind time is 0.9-1.1s idle and
    1.9s under campaign load. The original 2.0s deadline left 50-120ms of
    margin, so the Permissive arm completed 856 sessions and then lost the
    whole batch when session 857 landed on the wrong side of it.

    Waiting longer is free: the loop returns as soon as the socket appears.
    """
    import inspect

    from firewall_lab import orchestrator

    source = inspect.getsource(orchestrator._start_runtime_telemetry)
    deadlines = re.findall(r"time\.monotonic\(\) \+ ([0-9.]+)", source)
    assert deadlines, "no startup deadline found"
    assert min(float(v) for v in deadlines) >= 15.0, (
        "startup deadline is too tight against a measured 1.9s worst case"
    )


def test_collector_wait_stops_early_when_the_process_dies():
    """Tolerating a slow start must not make real failures slow to report."""
    import inspect

    from firewall_lab import orchestrator

    source = inspect.getsource(orchestrator._start_runtime_telemetry)
    assert "process.poll()" in source, (
        "the wait loop must notice a dead collector instead of sitting out the "
        "deadline"
    )
    assert "stderr" in source, "the failure must surface the collector's stderr"


def test_managed_process_poll_reports_exit_without_reaping(tmp_path):
    import os
    import time

    from firewall_lab.evidence import ManagedProcess

    process = ManagedProcess(
        argv=["/bin/sh", "-c", "exit 7"],
        cwd=tmp_path,
        env=dict(os.environ),
        stdout_path=tmp_path / "o.log",
        stderr_path=tmp_path / "e.log",
    )
    process.start()
    for _ in range(100):
        if process.poll() is not None:
            break
        time.sleep(0.05)
    assert process.poll() == 7
    assert process.stop().return_code == 7
