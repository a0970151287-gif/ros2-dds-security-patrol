from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from firewall_lab.backend_acceptance import (
    ACCEPTANCE_SCHEMA_VERSION,
    DISABLED_PRODUCTION_BACKEND,
    SIMULATION_BACKEND,
    SIMULATION_CHECKS,
    main,
    run_backend_acceptance,
    verify_backend_acceptance,
)


def _rewrite_summary(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name("summary.json.sha256").write_text(
        f"{digest}  summary.json\n", encoding="ascii"
    )


def test_in_memory_acceptance_writes_hashed_recomputable_simulation_artifacts(tmp_path):
    output = tmp_path / "simulation"
    summary = run_backend_acceptance(output, adapter_mode="in-memory")
    assert summary["schema_version"] == ACCEPTANCE_SCHEMA_VERSION
    assert summary["backend"] == SIMULATION_BACKEND
    assert summary["adapter_class"] == "InMemoryTimeoutSetAdapter"
    assert summary["simulation_only"] is True
    assert summary["production_ready"] is False
    assert summary["production_admission_eligible"] is False
    assert summary["outcome"] == "simulation_passed"
    assert summary["checks_passed"] is True
    assert {item["id"] for item in summary["checks"]} == SIMULATION_CHECKS
    assert all(item["passed"] is True for item in summary["checks"])
    assert set(summary["artifacts"]["databases"]) == {
        "response_state",
        "capacity_state",
    }
    assert (output / "acceptance_events.jsonl").is_file()
    assert (output / "response_state.sqlite3").is_file()
    assert (output / "capacity_state.sqlite3").is_file()
    assert (output / "summary.json.sha256").is_file()

    verification = verify_backend_acceptance(output / "summary.json")
    assert verification["artifact_valid"] is True
    assert verification["accepted"] is True
    assert verification["production_admission_eligible"] is False
    assert verification["recomputed"]["checks_passed"] is True
    assert verification["recomputed"]["events"]["records"] == len(
        SIMULATION_CHECKS
    )
    assert verification["recomputed"]["databases"]["response_state"][
        "database_status"
    ]["integrity_check"] == "ok"


def test_simulation_report_is_always_rejected_for_production_admission(tmp_path):
    output = tmp_path / "simulation"
    run_backend_acceptance(output, adapter_mode="in-memory")
    verification = verify_backend_acceptance(
        output / "summary.json", purpose="production_admission"
    )
    assert verification["artifact_valid"] is True
    assert verification["accepted"] is False
    assert verification["production_admission_eligible"] is False
    assert "never production evidence" in " ".join(verification["blockers"])


def test_forged_simulation_flags_fail_even_when_summary_hash_is_recomputed(tmp_path):
    output = tmp_path / "simulation"
    run_backend_acceptance(output, adapter_mode="in-memory")
    path = output / "summary.json"
    summary = json.loads(path.read_text(encoding="utf-8"))
    summary["simulation_only"] = False
    summary["production_ready"] = True
    summary["production_admission_eligible"] = True
    summary["backend"] = "nftables_timeout_set"
    _rewrite_summary(path, summary)
    verification = verify_backend_acceptance(path)
    assert verification["artifact_valid"] is False
    assert verification["accepted"] is False


def test_disabled_production_adapter_generates_valid_but_blocked_report(tmp_path):
    output = tmp_path / "disabled"
    summary = run_backend_acceptance(output, adapter_mode="production-disabled")
    assert summary["backend"] == DISABLED_PRODUCTION_BACKEND
    assert summary["adapter_class"] == "DisabledProductionTimeoutSetAdapter"
    assert summary["simulation_only"] is False
    assert summary["production_ready"] is False
    assert summary["outcome"] == "blocked"
    assert summary["checks"][0]["id"] == "production_adapter_blocked"
    assert summary["checks"][0]["passed"] is True

    verification = verify_backend_acceptance(output / "summary.json")
    assert verification["artifact_valid"] is True
    assert verification["accepted"] is False
    assert "disabled" in " ".join(verification["blockers"])
    connection = sqlite3.connect(output / "response_state.sqlite3")
    try:
        outcomes = {
            row[0] for row in connection.execute("SELECT outcome FROM audit_events")
        }
    finally:
        connection.close()
    assert "pending_recovery" in outcomes


def test_artifact_tamper_is_detected_from_recomputed_jsonl_and_database_hashes(tmp_path):
    output = tmp_path / "simulation"
    run_backend_acceptance(output, adapter_mode="in-memory")
    events = output / "acceptance_events.jsonl"
    events.write_text(events.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")
    assert verify_backend_acceptance(output / "summary.json")["artifact_valid"] is False

    output2 = tmp_path / "simulation2"
    run_backend_acceptance(output2, adapter_mode="in-memory")
    database = output2 / "response_state.sqlite3"
    with database.open("ab") as handle:
        handle.write(b"tamper")
    assert verify_backend_acceptance(output2 / "summary.json")["artifact_valid"] is False


def test_acceptance_refuses_to_overwrite_existing_evidence_directory(tmp_path):
    output = tmp_path / "evidence"
    output.mkdir()
    (output / "keep.txt").write_text("user evidence", encoding="utf-8")
    with pytest.raises(ValueError, match="new or empty"):
        run_backend_acceptance(output, adapter_mode="in-memory")
    assert (output / "keep.txt").read_text(encoding="utf-8") == "user evidence"


def test_cli_defaults_to_disabled_production_and_returns_blocked_exit(tmp_path, capsys):
    code = main(["--output", str(tmp_path / "default")])
    assert code == 2
    value = json.loads(capsys.readouterr().out)
    assert value["summary"]["backend"] == DISABLED_PRODUCTION_BACKEND
    assert value["verification"]["artifact_valid"] is True
    assert value["verification"]["accepted"] is False

