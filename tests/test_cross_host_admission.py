from __future__ import annotations

import json

from firewall_lab.backend_acceptance import run_backend_acceptance
from firewall_lab.cross_host_admission import (
    BACKEND_SCHEMA,
    OUTCOME_SCHEMA,
    REQUIRED_BACKEND_CHECKS,
    REQUIRED_LOCAL_OUTCOMES,
    TOPOLOGY_SCHEMA,
    _check_backend_report,
    _check_defense_coverage,
    _check_outcome_report,
    _check_policy_alignment,
    _check_response_authorizer,
    _check_sros2_policy,
    _check_topology,
    evaluate_admission,
)


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_current_static_defense_contract_is_internally_aligned():
    assert _check_policy_alignment()[0]
    assert _check_defense_coverage()[0]
    assert _check_sros2_policy()[0]
    assert _check_response_authorizer()[0]


def test_missing_live_evidence_blocks_cross_host_and_auto_blocking(tmp_path):
    report = evaluate_admission(report_path=tmp_path / "report.json")
    assert report["static_defense_ready"] is True
    assert report["cross_host_test_ready"] is False
    assert report["autonomous_ip_block_ready"] is False
    assert report["effective_mode"] == "observe_or_dry_run_only"
    assert {
        "live_multimodal",
        "local_defense_outcomes",
        "response_backend_recovery",
        "isolated_cross_host_topology",
        "deployment_model",
    } <= set(report["blockers"])


def test_local_outcome_report_rejects_unhashed_self_assertions(tmp_path):
    checks = [
        {"id": check_id, "passed": True, "evidence": f"trace/{check_id}.json"}
        for check_id in REQUIRED_LOCAL_OUTCOMES
    ]
    path = _write(
        tmp_path / "outcomes.json",
        {
            "schema_version": OUTCOME_SCHEMA,
            "topology": "same_host_loopback",
            "checks": checks,
        },
    )
    assert not _check_outcome_report(path)[0]
    checks[0]["evidence"] = ""
    _write(path, {"schema_version": OUTCOME_SCHEMA, "topology": "same_host_loopback", "checks": checks})
    assert not _check_outcome_report(path)[0]


def test_legacy_backend_report_cannot_unlock_gate_with_self_asserted_checks(tmp_path):
    path = _write(
        tmp_path / "backend.json",
        {
            "schema_version": BACKEND_SCHEMA,
            "backend": "nftables_timeout_set",
            "checks": [
                {"id": check_id, "passed": True, "evidence": "verified"}
                for check_id in REQUIRED_BACKEND_CHECKS
            ],
        },
    )
    passed, detail = _check_backend_report(path)
    assert not passed
    assert "self-asserted" in detail


def test_offline_backend_acceptance_is_valid_but_never_cross_host_evidence(tmp_path):
    output = tmp_path / "backend-acceptance"
    run_backend_acceptance(output, adapter_mode="in-memory")

    passed, detail = _check_backend_report(output / "summary.json")
    assert not passed
    assert "never production evidence" in detail


def test_topology_rejects_unhashed_self_assertions(tmp_path):
    value = {
        "schema_version": TOPOLOGY_SCHEMA,
        "attacker_ip": "10.10.10.1",
        "target_ip": "10.10.10.2",
        "attacker_owned": True,
        "target_owned": True,
        "same_physical_host": False,
        "default_route_present": False,
        "internet_reachable": False,
        "network_mode": "owned_isolated_switch",
        "capture_interface": "eth1",
        "scope_ack": "I_CONFIRM_OWNED_ISOLATED_LAB",
    }
    path = _write(tmp_path / "topology.json", value)
    assert not _check_topology(path)[0]
    value["target_ip"] = value["attacker_ip"]
    _write(path, value)
    assert not _check_topology(path)[0]
