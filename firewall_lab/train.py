#!/usr/bin/env python3
"""Train the known-attack and unknown-anomaly firewall models."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from .schema import atomic_write_json, sha256_file, utc_now


FEATURES = [
    "conn_count",
    "conn_rate",
    "uniq_dst_ports",
    "uniq_dst_hosts",
    "spdp_ratio",
    "meta_ratio",
    "userdata_ratio",
    "mcast_ratio",
    "dst_port_entropy",
    "interarrival_cv",
    "burstiness",
    "dominant_port_ratio",
    "dominant_host_ratio",
    "tuple_repeat_ratio",
]
MODEL_SCHEMA_VERSION = "sros2-intelligent-firewall-model/v1"
WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
ML_DIR = WORKSPACE_ROOT / "ML防禦"
ACTION_POLICY_PATH = Path(__file__).with_name("action_policy.json")
LEGACY_TRAINER_DEPLOYMENT_ELIGIBLE = False
LEGACY_TRAINER_BLOCK_REASON = (
    "legacy trainer has no immutable validation/calibration/final-test or live "
    "response gates; use grouped or hierarchical training"
)


def _boolean_series(series):
    text = series.astype(str).str.strip().str.lower()
    unknown = sorted(set(text) - {"true", "false", "1", "0"})
    if unknown:
        raise ValueError(
            f"training_eligible contains invalid values: {unknown}"
        )
    return text.isin({"true", "1"})


def load_training_frame(
    path: str | Path,
    *,
    data_tier: str = "live",
    feature_names: list[str] | tuple[str, ...] | None = None,
    extra_columns: list[str] | tuple[str, ...] | None = None,
    optional_columns: list[str] | tuple[str, ...] | None = None,
):
    import numpy as np
    import pandas as pd

    selected_features = list(FEATURES if feature_names is None else feature_names)
    if not selected_features or len(selected_features) != len(set(selected_features)):
        raise ValueError("feature_names must be a non-empty unique sequence")
    required = set(
        selected_features
        + [
            "label",
            "binary",
            "group_id",
            "training_eligible",
            "evaluation_eligible",
            "origin",
            "policy_sha256",
        ]
    )
    if extra_columns is None:
        frame = pd.read_csv(path)
    else:
        requested_extra = set(extra_columns)
        available = set(pd.read_csv(path, nrows=0).columns)
        missing_extra = requested_extra - available
        if missing_extra:
            raise ValueError(
                f"network feature data is missing {sorted(missing_extra)}"
            )
        optional = set(optional_columns or ()) & available
        frame = pd.read_csv(
            path,
            usecols=sorted(required | requested_extra | optional),
        )
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"network feature data is missing {sorted(missing)}")
    eligible = _boolean_series(frame["training_eligible"])
    if not bool(eligible.all()):
        raise ValueError(
            "non-trainable/smoke rows are present; rebuild features without "
            "--include-nontrainable"
        )
    evaluation_eligible = _boolean_series(frame["evaluation_eligible"])
    origins = set(frame["origin"].astype(str))
    if data_tier == "live":
        if origins != {"live_lab"} or not bool(evaluation_eligible.all()):
            raise ValueError(
                "live training requires only evaluation-eligible live_lab rows"
            )
    elif data_tier == "synthetic-pretrain":
        if origins != {"synthetic_pretrain"}:
            raise ValueError(
                "synthetic pretraining requires only synthetic_pretrain rows"
            )
        if bool(evaluation_eligible.any()):
            raise ValueError(
                "synthetic rows may never be marked evaluation_eligible"
            )
    else:
        raise ValueError("data_tier must be live or synthetic-pretrain")
    if frame["group_id"].isna().any() or frame["label"].isna().any():
        raise ValueError("group_id and label may not be empty")
    if (frame["group_id"].astype(str).str.len() == 0).any():
        raise ValueError("group_id may not be empty")
    unknown_binary = sorted(set(frame["binary"].astype(str)) - {"normal", "attack"})
    if unknown_binary:
        raise ValueError(f"invalid binary labels: {unknown_binary}")
    numeric = frame[selected_features].apply(pd.to_numeric, errors="coerce")
    matrix = numeric.to_numpy(dtype=np.float64)
    if not np.isfinite(matrix).all():
        raise ValueError("network features contain NaN or Infinity")
    frame = frame.copy()
    frame[selected_features] = numeric
    return frame


def choose_grouped_split(frame):
    import numpy as np
    from sklearn.model_selection import StratifiedGroupKFold

    labels = frame["label"].astype(str).to_numpy()
    groups = frame["group_id"].astype(str).to_numpy()
    group_counts = [
        len(set(groups[labels == label])) for label in sorted(set(labels))
    ]
    n_splits = min(5, *group_counts)
    if n_splits < 2:
        raise ValueError(
            "each class needs at least two independent sessions for "
            "leak-resistant evaluation"
        )
    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=42,
    )
    candidates = []
    dummy = np.zeros((len(frame), 1), dtype=float)
    for train_index, test_index in splitter.split(dummy, labels, groups):
        train_labels = set(labels[train_index])
        test_labels = set(labels[test_index])
        if train_labels != set(labels) or test_labels != set(labels):
            continue
        score = abs(len(test_index) / len(frame) - 0.25)
        candidates.append((score, train_index, test_index))
    if not candidates:
        raise ValueError(
            "unable to build a grouped holdout containing every class"
        )
    _, train_index, test_index = min(candidates, key=lambda item: item[0])
    if not set(groups[train_index]).isdisjoint(set(groups[test_index])):
        raise RuntimeError("internal split error: session leakage")
    return train_index, test_index, groups


def train_model(
    feature_csv: str | Path,
    output_dir: str | Path,
    *,
    data_tier: str = "live",
) -> dict:
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import (
        balanced_accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
    )

    sys.path.insert(0, str(ML_DIR))
    try:
        from ml_utils import atomic_joblib_dump
    finally:
        sys.path.remove(str(ML_DIR))

    frame = load_training_frame(feature_csv, data_tier=data_tier)
    if len(frame) < 20:
        raise ValueError("at least 20 network windows are required")
    if frame["label"].nunique() < 2 or "normal" not in set(frame["label"]):
        raise ValueError("training requires normal plus at least one attack class")

    train_index, test_index, groups = choose_grouped_split(frame)
    matrix = frame[FEATURES].to_numpy(dtype=np.float64)
    labels = frame["label"].astype(str).to_numpy()
    binary = (frame["binary"].astype(str) == "attack").astype(int).to_numpy()
    train_x, test_x = matrix[train_index], matrix[test_index]
    train_y, test_y = labels[train_index], labels[test_index]

    classifier = RandomForestClassifier(
        n_estimators=400,
        max_depth=18,
        class_weight="balanced_subsample",
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    classifier.fit(train_x, train_y)
    predicted = classifier.predict(test_x)
    probability = classifier.predict_proba(test_x)
    if not np.isfinite(probability).all():
        raise RuntimeError("classifier emitted invalid probability")

    normal_train = train_x[train_y == "normal"]
    if len(normal_train) < 2:
        raise ValueError("at least two normal training windows are required")
    anomaly = IsolationForest(
        n_estimators=300,
        contamination=0.02,
        random_state=42,
        n_jobs=-1,
    )
    anomaly.fit(normal_train)
    anomaly_flag = (anomaly.predict(test_x) == -1).astype(int)
    test_binary = binary[test_index]
    attack_mask = test_binary == 1
    normal_mask = test_binary == 0
    anomaly_recall = (
        float(anomaly_flag[attack_mask].mean())
        if attack_mask.any()
        else 0.0
    )
    anomaly_fpr = (
        float(anomaly_flag[normal_mask].mean())
        if normal_mask.any()
        else 0.0
    )

    classes = [str(item) for item in classifier.classes_]
    policy_hashes = sorted(
        hash_value
        for hash_value in set(frame["policy_sha256"].astype(str))
        if len(hash_value) == 64
    )
    train_groups = sorted(set(groups[train_index]))
    test_groups = sorted(set(groups[test_index]))
    metrics = {
        "schema_version": "sros2-firewall-training-metrics/v1",
        "trained_utc": utc_now(),
        "data_tier": data_tier,
        "deployment_eligible": LEGACY_TRAINER_DEPLOYMENT_ELIGIBLE,
        "deployment_block_reason": LEGACY_TRAINER_BLOCK_REASON,
        "rows": len(frame),
        "sessions": len(set(groups)),
        "train_rows": len(train_index),
        "test_rows": len(test_index),
        "train_sessions": len(train_groups),
        "test_sessions": len(test_groups),
        "session_overlap": 0,
        "classes": classes,
        "balanced_accuracy": float(
            balanced_accuracy_score(test_y, predicted)
        ),
        "macro_f1": float(
            f1_score(test_y, predicted, average="macro", zero_division=0)
        ),
        "classification_report": classification_report(
            test_y,
            predicted,
            labels=classes,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(
            test_y,
            predicted,
            labels=classes,
        ).tolist(),
        "anomaly_recall": anomaly_recall,
        "anomaly_fpr": anomaly_fpr,
        "policy_sha256_values": policy_hashes,
    }
    bundle = {
        "schema_version": MODEL_SCHEMA_VERSION,
        "classifier": classifier,
        "anomaly_detector": anomaly,
        "features": FEATURES,
        "classes": classes,
        "training": {
            "grouping": "session_id",
            "data_tier": data_tier,
            "deployment_eligible": LEGACY_TRAINER_DEPLOYMENT_ELIGIBLE,
            "deployment_block_reason": LEGACY_TRAINER_BLOCK_REASON,
            "train_sessions": train_groups,
            "test_sessions": test_groups,
            "policy_sha256_values": policy_hashes,
            "action_policy_sha256": sha256_file(ACTION_POLICY_PATH),
        },
        "metrics": {
            "balanced_accuracy": metrics["balanced_accuracy"],
            "macro_f1": metrics["macro_f1"],
            "anomaly_recall": anomaly_recall,
            "anomaly_fpr": anomaly_fpr,
        },
    }
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    model_path = output / "firewall_model.joblib"
    atomic_joblib_dump(bundle, model_path)
    atomic_write_json(output / "training_metrics.json", metrics)
    return {
        "model": str(model_path),
        "metrics": str(output / "training_metrics.json"),
        "rows": len(frame),
        "sessions": len(set(groups)),
        "classes": classes,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train session-grouped SROS2 firewall models"
    )
    parser.add_argument(
        "--features",
        type=Path,
        default=Path(__file__).resolve().parent
        / "features"
        / "network_features.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "model",
    )
    parser.add_argument(
        "--data-tier",
        choices=("live", "synthetic-pretrain"),
        default="live",
        help=(
            "synthetic-pretrain is prototype-only and may not be reported "
            "as live evaluation"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = train_model(
        args.features,
        args.output,
        data_tier=args.data_tier,
    )
    print(
        f"✅ 防火牆模型完成：{result['rows']} windows / "
        f"{result['sessions']} sessions / {len(result['classes'])} classes"
    )
    print(f"模型：{result['model']}")
    print("模型已附 HMAC sidecar；部署端必須驗章後載入同一份 snapshot。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
