from __future__ import annotations

import json
import time
from pathlib import Path

from firewall_lab.campaign import CAMPAIGN_SCHEMA_VERSION
from firewall_lab.evidence import evidence_inventory
from firewall_lab.schema import (
    SessionManifest,
    atomic_write_json,
    make_label,
    new_session_id,
    sha256_file,
)
from firewall_lab.verify_live_dataset import verify_live_dataset


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def _normal_session(
    root: Path,
    *,
    mode: str,
    seed: int,
    code_revision: str = "a" * 40,
) -> str:
    session_id = new_session_id("normal_patrol")
    session = root / session_id
    (session / "zeek").mkdir(parents=True)
    (session / "traffic.pcapng").write_bytes(bytes([seed]) * 256)
    (session / "capture.stderr.log").write_text(
        "Packets captured: 100\n"
        "Packets received/dropped on interface 'any': 100/0 "
        "(pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n",
        encoding="utf-8",
    )
    (session / "capture.stdout.log").write_text("", encoding="utf-8")
    (session / "resources.jsonl").write_text("", encoding="utf-8")
    (session / "zeek" / "conn.log").write_text(
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
        "1.0\t127.0.0.1\t239.255.0.1\t7400\tudp\n",
        encoding="utf-8",
    )
    now = time.time_ns()
    _write_jsonl(
        session / "labels.jsonl",
        [
            make_label(
                session_id=session_id,
                attack_class="normal",
                start_unix_ns=now,
                end_unix_ns=now + 1_000_000_000,
                source="allowlisted_runner",
            )
        ],
    )
    _write_jsonl(
        session / "events.jsonl",
        [
            {"sequence": 0, "event_type": "session_started"},
            {"sequence": 1, "event_type": "attack_started"},
            {"sequence": 2, "event_type": "attack_completed"},
            {"sequence": 3, "event_type": "session_completed"},
        ],
    )
    manifest = SessionManifest(
        session_id=session_id,
        scenario_id="normal_patrol",
        attack_class="normal",
        binary_label="normal",
        security_mode=mode,
        ros_domain_id=30,
        seed=seed,
        origin="live_lab",
        training_eligible=True,
        expected_action="allow",
        policy_sha256="a" * 64,
        code_revision=code_revision,
        status="complete",
        result={
            "attack_process": None,
            "capture_process": {"return_code": 0},
            "zeek": {
                "status": "complete",
                "return_code": 0,
                "conn_log": True,
            },
        },
    )
    manifest.evidence = evidence_inventory(session)
    manifest.write(session / "manifest.json")
    return session_id


def test_live_verifier_passes_then_detects_evidence_tampering(tmp_path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    permissive_id = _normal_session(dataset, mode="permissive", seed=1)
    enforce_id = _normal_session(dataset, mode="enforce", seed=2)
    plan = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": "campaign_test",
        "created_utc": "2026-01-01T00:00:00+00:00",
        "experiment_mode": "live",
        "catalog_sha256": sha256_file(
            Path(__file__).parents[1]
            / "firewall_lab"
            / "scenarios.json"
        ),
        "seed": 1,
        "requested_counts": {
            "normal_patrol": {
                "total": 2,
                "permissive": 1,
                "enforce": 1,
            }
        },
        "entries": [
            {
                "entry_id": "run_00001",
                "scenario_id": "normal_patrol",
                "attack_class": "normal",
                "security_mode": "permissive",
                "domain_id": 30,
                "seed": 1,
                "expected_action": "allow",
                "status": "complete",
                "session_id": permissive_id,
                "error": None,
            },
            {
                "entry_id": "run_00002",
                "scenario_id": "normal_patrol",
                "attack_class": "normal",
                "security_mode": "enforce",
                "domain_id": 30,
                "seed": 2,
                "expected_action": "allow",
                "status": "complete",
                "session_id": enforce_id,
                "error": None,
            },
        ],
    }
    plan_path = tmp_path / "plan.json"
    atomic_write_json(plan_path, plan)

    passed = verify_live_dataset(
        dataset_root=dataset,
        plan_path=plan_path,
    )
    assert passed["passed"] is True
    assert passed["active_dataset"]["sessions"] == 2
    assert passed["active_dataset"]["dropped_packets"] == 0

    pcap = dataset / enforce_id / "traffic.pcapng"
    pcap.write_bytes(pcap.read_bytes() + b"tamper")
    failed = verify_live_dataset(
        dataset_root=dataset,
        plan_path=plan_path,
    )
    assert failed["passed"] is False
    assert any(
        "evidence size mismatch: traffic.pcapng" in error
        for error in failed["errors"]
    )


def test_live_verifier_rejects_mixed_or_unfrozen_code_revisions(tmp_path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    permissive_id = _normal_session(
        dataset,
        mode="permissive",
        seed=1,
        code_revision="a" * 40,
    )
    enforce_id = _normal_session(
        dataset,
        mode="enforce",
        seed=2,
        code_revision="b" * 40,
    )
    plan = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": "campaign_revision_test",
        "created_utc": "2026-01-01T00:00:00+00:00",
        "experiment_mode": "live",
        "catalog_sha256": sha256_file(
            Path(__file__).parents[1]
            / "firewall_lab"
            / "scenarios.json"
        ),
        "seed": 1,
        "requested_counts": {
            "normal_patrol": {
                "total": 2,
                "permissive": 1,
                "enforce": 1,
            }
        },
        "entries": [
            {
                "entry_id": "run_00001",
                "scenario_id": "normal_patrol",
                "attack_class": "normal",
                "security_mode": "permissive",
                "domain_id": 30,
                "seed": 1,
                "expected_action": "allow",
                "status": "complete",
                "session_id": permissive_id,
                "error": None,
            },
            {
                "entry_id": "run_00002",
                "scenario_id": "normal_patrol",
                "attack_class": "normal",
                "security_mode": "enforce",
                "domain_id": 30,
                "seed": 2,
                "expected_action": "allow",
                "status": "complete",
                "session_id": enforce_id,
                "error": None,
            },
        ],
    }
    plan_path = tmp_path / "plan.json"
    atomic_write_json(plan_path, plan)

    mixed = verify_live_dataset(
        dataset_root=dataset,
        plan_path=plan_path,
    )
    assert mixed["passed"] is False
    assert "active sessions span multiple code revisions" in mixed["errors"]

    for session_id in (permissive_id, enforce_id):
        manifest_path = dataset / session_id / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["code_revision"] = "unknown"
        manifest.pop("evidence", None)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest["evidence"] = evidence_inventory(dataset / session_id)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    unfrozen = verify_live_dataset(
        dataset_root=dataset,
        plan_path=plan_path,
    )
    assert unfrozen["passed"] is False
    assert (
        "active sessions do not have a frozen Git revision"
        in unfrozen["errors"]
    )
