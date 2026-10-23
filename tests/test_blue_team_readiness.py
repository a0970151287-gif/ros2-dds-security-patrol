"""Safety and integrity checks for the pre-red-team readiness bundle."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall_lab import blue_team_readiness as readiness


def test_readiness_contains_no_attack_executable(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness, "ROOT", Path(__file__).resolve().parents[1])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    checks = readiness.build_checks(run_dir)

    assert checks
    for check in checks:
        readiness.validate_check(check)
        assert Path(check.argv[0]).name.lower() not in {
            "msfconsole",
            "msfvenom",
            "nmap",
            "hydra",
            "masscan",
            "ros2",
        }


def test_readiness_rejects_attack_command():
    check = readiness.Check(
        "bad",
        ("msfconsole", "-q"),
        True,
        readiness.ROOT,
    )
    with pytest.raises(ValueError, match="attack executable forbidden"):
        readiness.validate_check(check)


def test_readiness_output_must_stay_in_workspace(tmp_path):
    with pytest.raises(ValueError, match="inside the workspace"):
        readiness._safe_output_root(tmp_path)


def test_host_risk_count_parser():
    assert readiness._host_risk_count("風險暴露項： 2（目標）") == 2
    assert readiness._host_risk_count("no summary") is None


def test_generated_manifest_is_explicitly_not_training_data(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(readiness, "ROOT", tmp_path)
    (tmp_path / "展示指令").mkdir()
    (tmp_path / "Zeek監控").mkdir()
    (tmp_path / "展示指令" / "sros2_policy_least_privilege.xml").write_text(
        "<policy/>", encoding="utf-8"
    )
    (tmp_path / "Zeek監控" / "dds_monitor.zeek").write_text(
        "# test", encoding="utf-8"
    )
    monkeypatch.setattr(readiness, "build_checks", lambda _run_dir: [])

    run_dir, manifest = readiness.create_readiness_bundle(
        output_root=tmp_path / "evidence"
    )

    assert manifest["training_eligible"] is False
    assert manifest["origin"] == "read_only_blue_team_baseline"
    persisted = json.loads(
        (run_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert persisted["evidence"] == {}


def test_external_capture_is_bounded_and_never_auto_blocks():
    script = (
        Path(__file__).resolve().parents[1]
        / "firewall_lab"
        / "blue_team_capture.sh"
    ).read_text(encoding="utf-8")

    assert "-b filesize:20480 -b files:10" in script
    assert "tcp and host 127.0.0.1" in script
    assert "udp portrange 14900-15150" in script
    assert "-f \"$CAPTURE_FILTER\"" in script
    assert "DURATION_SEC >= 60 && DURATION_SEC <= 1800" in script
    assert "BLUE_TEAM_CAPTURE_FILTER" not in script
    assert "BLUE_TEAM_CAPTURE_IFACE" not in script
    assert "DOS_BLOCK_ENABLED=F" in script
    assert "sudo " not in script
    assert "msfconsole" not in script
    assert "nmap " not in script
