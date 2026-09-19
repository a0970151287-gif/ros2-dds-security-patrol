from __future__ import annotations

import csv
import json

import pytest


class _Classifier:
    classes_ = ["normal", "service_dos"]

    def predict_proba(self, rows):
        return [[0.8 - row[0] * 0.1, 0.2 + row[0] * 0.1] for row in rows]


class _Anomaly:
    def predict(self, rows):
        return [1 if row[0] < 5 else -1 for row in rows]


def test_policy_rebind_changes_only_policy_hash(tmp_path):
    pytest.importorskip("joblib")
    from firewall_lab.rebind_model_policy import rebind_model_policy
    from firewall_lab.train import MODEL_SCHEMA_VERSION
    import sys
    from firewall_lab.train import ML_DIR

    sys.path.insert(0, str(ML_DIR))
    try:
        from ml_utils import atomic_joblib_dump, verified_joblib_load
    finally:
        sys.path.remove(str(ML_DIR))

    secret = b"r" * 32
    old_hash = "1" * 64
    source = tmp_path / "source.joblib"
    output = tmp_path / "rebound" / "model.joblib"
    bundle = {
        "schema_version": MODEL_SCHEMA_VERSION,
        "classifier": _Classifier(),
        "anomaly_detector": _Anomaly(),
        "features": ["conn_count"],
        "classes": ["normal", "service_dos"],
        "training": {
            "action_policy_sha256": old_hash,
            "deployment_eligible": False,
            "test_prediction_passes": 1,
        },
        "metrics": {"balanced_accuracy": 0.9},
    }
    atomic_joblib_dump(bundle, source, secret=secret)
    policy = tmp_path / "action_policy.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": "sros2-firewall-action-policy/v1",
                "default_action": "alert",
                "unknown_anomaly_action": "quarantine",
                "rules": {
                    "normal": {
                        "action": "allow",
                        "min_confidence": 0.6,
                        "adapter": "none",
                    },
                    "service_dos": {
                        "action": "temporary_block",
                        "min_confidence": 0.8,
                        "adapter": "network_helper",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    metrics = tmp_path / "training_metrics.json"
    metrics.write_bytes(b'{"test":"unchanged"}\n')
    canary = tmp_path / "canary.csv"
    with canary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["split", "group_id", "window", "conn_count"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "split": "train",
                "group_id": "train_session_1",
                "window": "0",
                "conn_count": "1",
            }
        )
        writer.writerow(
            {
                "split": "test",
                "group_id": "test_session_1",
                "window": "0",
                "conn_count": "9",
            }
        )

    report = rebind_model_policy(
        source_model=source,
        output_model=output,
        action_policy=policy,
        metrics_path=metrics,
        canary_csv=canary,
        report_path=tmp_path / "rebound" / "report.json",
        canary_rows=1,
        signing_secret=secret,
    )
    rebound = verified_joblib_load(output, secret=secret)
    assert rebound["training"]["action_policy_sha256"] != old_hash
    assert report["estimator_unchanged"] is True
    assert report["canary"]["prediction_unchanged"] is True
    assert report["test_predictions_recomputed"] is False
    assert report["test_metrics_unchanged"] is True
    assert report["test_prediction_passes"] == 1
    assert (output.parent / metrics.name).read_bytes() == metrics.read_bytes()
