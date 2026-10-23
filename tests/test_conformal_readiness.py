import csv
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "工具腳本" / "audit_conformal_readiness.py"
SPEC = importlib.util.spec_from_file_location("audit_conformal_readiness", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def _fixture(tmp_path, *, calibration_normal=19, calibration_attack=19):
    groups = {
        "selection_groups": ["selection_normal", "selection_attack"],
        "calibration_groups": [],
        "threshold_groups": ["threshold_normal", "threshold_attack"],
    }
    rows = []
    for index in range(calibration_normal):
        group = f"cal_normal_{index:03d}"
        groups["calibration_groups"].append(group)
        rows.append((group, "normal"))
    for index in range(calibration_attack):
        group = f"cal_attack_{index:03d}"
        groups["calibration_groups"].append(group)
        rows.append((group, "identity_abuse"))
    rows.extend(
        [
            ("selection_normal", "normal"),
            ("selection_attack", "identity_abuse"),
            ("threshold_normal", "normal"),
            ("threshold_attack", "identity_abuse"),
        ]
    )
    csv_path = tmp_path / "features.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["group_id", "label", "split", "security_mode"],
        )
        writer.writeheader()
        for group, label in rows:
            writer.writerow(
                {
                    "group_id": group,
                    "label": label,
                    "split": "validation",
                    "security_mode": "enforce",
                }
            )
    metrics_path = tmp_path / "metrics.json"
    metrics_path.write_text(
        json.dumps(
            {"security_mode": "enforce", "validation_protocol": groups}
        ),
        encoding="utf-8",
    )
    return csv_path, metrics_path


def test_readiness_uses_sessions_and_reports_resolution(tmp_path):
    features, metrics = _fixture(
        tmp_path, calibration_normal=22, calibration_attack=15
    )
    report = MODULE.evaluate(
        features, metrics, normal_alpha=0.02, known_attack_alpha=0.05
    )
    normal = report["registered_calibration_partition"]["references"]["normality"]
    attack = report["registered_calibration_partition"]["references"]["known_attack"]
    assert normal["calibration_sessions"] == 22
    assert normal["required_sessions"] == 49
    assert normal["additional_sessions_required"] == 27
    assert attack["calibration_sessions"] == 15
    assert attack["additional_sessions_required"] == 4
    assert report["status"] == "blocked_insufficient_calibration_sessions"
    assert report["protocol"]["test_rows_used"] == 0
    assert report["deployment_eligible"] is False


def test_readiness_can_pass_only_the_development_resolution_check(tmp_path):
    features, metrics = _fixture(
        tmp_path, calibration_normal=49, calibration_attack=19
    )
    report = MODULE.evaluate(
        features, metrics, normal_alpha=0.02, known_attack_alpha=0.05
    )
    assert report["status"] == "ready_for_development_fit"
    assert report["independent_final_test"] is False
    assert report["automatic_ip_block_authorized"] is False


def test_readiness_rejects_overlapping_protocol_groups(tmp_path):
    features, metrics = _fixture(tmp_path)
    value = json.loads(metrics.read_text(encoding="utf-8"))
    value["validation_protocol"]["threshold_groups"].append(
        value["validation_protocol"]["calibration_groups"][0]
    )
    metrics.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="overlap"):
        MODULE.evaluate(
            features, metrics, normal_alpha=0.02, known_attack_alpha=0.05
        )
