from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from firewall_lab.development_evaluation import (
    FEATURE_SET_NAMES,
    MODEL_NAMES,
    build_candidates,
    evaluate_development_contract,
    feature_set_columns,
    load_development_frame,
    load_frozen_contract,
    measure_inference_cost,
    probability_metrics,
    session_bootstrap_confidence_intervals,
)
from firewall_lab.hierarchical_model import (
    DEFAULT_LIVE_SOURCE_AVAILABILITY,
    EXPANDED_FEATURES,
    RAW_FEATURES,
    SOURCE_MASK_FEATURES,
)
from firewall_lab.train import FEATURES


def _write_fixture(tmp_path: Path) -> tuple[Path, Path, dict[str, list[str]]]:
    pd = pytest.importorskip("pandas")
    phase_groups = {
        "selection": ["selection_normal", "selection_attack"],
        "calibration": ["calibration_normal", "calibration_attack"],
        "threshold": [
            "threshold_normal_0",
            "threshold_normal_1",
            "threshold_attack_0",
            "threshold_attack_1",
        ],
    }
    sessions: list[tuple[str, str, str]] = [
        ("train_normal_0", "train", "normal"),
        ("train_normal_1", "train", "normal"),
        ("train_attack_0", "train", "identity_abuse"),
        ("train_attack_1", "train", "identity_abuse"),
        ("train_novelty", "train", "sensor_spoof"),
        ("validation_novelty", "validation", "sensor_spoof"),
        ("test_normal", "test", "normal"),
    ]
    for phase, groups in phase_groups.items():
        for group in groups:
            label = "normal" if "normal" in group else "identity_abuse"
            sessions.append((group, "validation", label))

    rows = []
    for session_index, (session_id, split, label) in enumerate(sessions):
        for window in range(2):
            row = {name: 0.0 for name in RAW_FEATURES}
            if split == "test":
                # A conversion attempt would fail, proving the loader's test
                # guard precedes every feature access.
                row = {name: "MUST_NOT_BE_PARSED" for name in RAW_FEATURES}
            else:
                row["conn_count"] = 2.0 + session_index + window
                row["conn_rate"] = 0.5 + session_index / 10.0
                if label == "identity_abuse":
                    row["participant_churn_rate"] = 0.7
                if label == "sensor_spoof":
                    row["hmac_failure_rate"] = 0.6
            rows.append(
                {
                    **row,
                    "session_id": session_id,
                    "group_id": session_id,
                    "source": "127.0.0.1",
                    "window": window,
                    "security_mode": "permissive",
                    "split": split,
                    "label": "MUST_NOT_BE_READ" if split == "test" else label,
                }
            )
    feature_csv = tmp_path / "features.csv"
    pd.DataFrame(rows).to_csv(feature_csv, index=False, quoting=csv.QUOTE_MINIMAL)
    contract = {
        "schema_version": "sros2-firewall-hierarchical-metrics/v1",
        "security_mode": "permissive",
        "deployment_eligible": False,
        "independent_final_test": False,
        "test_metrics": None,
        "test_prediction_passes": 0,
        "rows_after_exclusion": len(rows),
        "sessions_after_exclusion": len(sessions),
        "applicable_excluded_sessions": [],
        "source_availability": dict(DEFAULT_LIVE_SOURCE_AVAILABILITY),
        "novelty_protocol": {
            "holdout_labels": ["sensor_spoof"],
            "supervised_train_rows_used": 0,
            "selection_rows_used": 0,
            "calibration_rows_used": 0,
            "threshold_rows_used": 0,
        },
        "validation_protocol": {
            "selection_groups": phase_groups["selection"],
            "calibration_groups": phase_groups["calibration"],
            "threshold_groups": phase_groups["threshold"],
            "pairwise_overlap": 0,
        },
    }
    metrics = tmp_path / "training_metrics.json"
    metrics.write_text(json.dumps(contract), encoding="utf-8")
    return feature_csv, metrics, phase_groups


def test_frozen_contract_rejects_deployment_or_prior_test_use(tmp_path):
    _, metrics, _ = _write_fixture(tmp_path)
    raw = json.loads(metrics.read_text(encoding="utf-8"))
    raw["deployment_eligible"] = True
    metrics.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="non-deployable"):
        load_frozen_contract(metrics)

    raw["deployment_eligible"] = False
    raw["test_prediction_passes"] = 1
    metrics.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="historical test"):
        load_frozen_contract(metrics)


def test_ablation_definitions_are_fixed_and_source_aware():
    sets = feature_set_columns()
    assert tuple(sets) == FEATURE_SET_NAMES
    assert sets["network"] == tuple(FEATURES)
    assert set(SOURCE_MASK_FEATURES) <= set(sets["telemetry"])
    assert set(SOURCE_MASK_FEATURES) <= set(sets["fusion"])
    assert sets["causal_temporal"] == tuple(EXPANDED_FEATURES)
    assert len(sets["current_only"]) == len(RAW_FEATURES)
    assert len(sets["causal_temporal"]) > len(sets["fusion"])


def test_loader_skips_test_features_before_numeric_conversion(tmp_path):
    features, metrics, groups = _write_fixture(tmp_path)
    contract = load_frozen_contract(metrics, expected_security_mode="permissive")
    frame, audit = load_development_frame(features, contract)
    assert audit["test_not_read"] is True
    assert audit["test_rows_seen_metadata_only"] == 2
    assert audit["test_label_or_feature_fields_accessed"] == 0
    assert audit["test_feature_numeric_conversions"] == 0
    assert audit["test_rows_predicted"] == 0
    assert "test_normal" not in set(frame["group_id"])
    assert "train_novelty" not in set(frame["group_id"])
    assert "validation_novelty" not in set(frame["group_id"])
    assert set(frame.loc[frame["phase"] == "selection", "group_id"]) == set(
        groups["selection"]
    )


def test_probability_metrics_and_session_bootstrap_are_deterministic():
    np = pytest.importorskip("numpy")
    y = np.asarray(["normal", "normal", "attack", "attack"])
    probability = np.asarray(
        [[0.95, 0.05], [0.80, 0.20], [0.10, 0.90], [0.20, 0.80]]
    )
    classes = ["normal", "attack"]
    metrics = probability_metrics(y, probability, classes, ece_bins=5)
    assert metrics["macro_f1"] == 1.0
    assert metrics["pr_auc_macro_ovr"] == 1.0
    assert 0.0 < metrics["ece"] < 0.2
    assert metrics["brier_score"] == pytest.approx(0.023125)
    assert metrics["per_class"]["attack"]["recall"] == 1.0

    sessions = ["normal_0", "normal_1", "attack_0", "attack_1"]
    first = session_bootstrap_confidence_intervals(
        y,
        probability,
        classes,
        sessions,
        replicates=25,
        seed=17,
    )
    second = session_bootstrap_confidence_intervals(
        y,
        probability,
        classes,
        sessions,
        replicates=25,
        seed=17,
    )
    assert first == second
    assert first["method"] == "session_cluster_percentile_bootstrap"
    assert 0 < first["intervals"]["macro_f1"]["valid_replicates"] <= 25


def test_candidate_registry_includes_all_required_baselines():
    pytest.importorskip("sklearn")
    assert tuple(build_candidates(seed=7, n_estimators=20)) == MODEL_NAMES
    with pytest.raises(ValueError, match="20..500"):
        build_candidates(seed=7, n_estimators=19)


class _FixedProbabilityEstimator:
    classes_ = ["normal", "attack"]

    def predict_proba(self, rows):
        np = pytest.importorskip("numpy")
        return np.tile([[0.75, 0.25]], (len(rows), 1))


def test_latency_reports_p50_p95_and_non_peak_rss():
    np = pytest.importorskip("numpy")
    ticks = iter(range(0, 10_000_000, 1_000_000))
    rss = iter([1000, 1400])
    result = measure_inference_cost(
        _FixedProbabilityEstimator(),
        np.zeros((4, 3)),
        single_iterations=2,
        batch_iterations=2,
        batch_size=3,
        clock_ns=lambda: next(ticks),
        rss_reader=lambda: next(rss),
    )
    assert result["single_sample_ms"] == {"p50": 1.0, "p95": 1.0}
    assert result["batch_call_ms"] == {"p50": 1.0, "p95": 1.0}
    assert result["observed_inference_rss_delta_bytes"] == 400
    assert result["rss_is_peak_measurement"] is False


def test_end_to_end_output_is_development_only_and_refuses_overwrite(tmp_path):
    pytest.importorskip("sklearn")
    features, metrics, _ = _write_fixture(tmp_path)
    output = tmp_path / "evaluation"
    result = evaluate_development_contract(
        features,
        metrics,
        output,
        security_mode="permissive",
        tasks=("binary",),
        feature_sets=("network",),
        models=("dummy_prior",),
        bootstrap_replicates=20,
        n_estimators=20,
        latency_single_iterations=2,
        latency_batch_iterations=2,
        latency_batch_size=4,
    )
    assert result["development_only"] is True
    assert result["deployment"] is False
    assert result["test_not_read"] is True
    document = json.loads(
        (output / "development_evaluation.json").read_text(encoding="utf-8")
    )
    assert document["deployment_eligible"] is False
    assert document["executable"] is False
    assert document["independent_final_test"] is False
    assert document["test_prediction_passes"] == 0
    assert document["data_audit"]["test_label_or_feature_fields_accessed"] == 0
    assert document["data_audit"]["test_feature_numeric_conversions"] == 0
    assert len(document["results"]) == 1
    assert document["results"][0]["task"] == "binary"

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        evaluate_development_contract(
            features,
            metrics,
            output,
            security_mode="permissive",
            tasks=("binary",),
            feature_sets=("network",),
            models=("dummy_prior",),
            bootstrap_replicates=20,
            n_estimators=20,
            latency_single_iterations=2,
            latency_batch_iterations=2,
        )
