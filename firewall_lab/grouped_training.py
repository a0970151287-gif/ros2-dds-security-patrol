#!/usr/bin/env python3
"""Leak-resistant model selection for the SROS2 intelligent firewall.

The original prototype trained one RandomForest on a newly-created grouped
80/20 split.  This module consumes the dataset's immutable session split,
uses only validation data for model selection/calibration/abstention tuning,
and evaluates the test split exactly once at the final stage.

Synthetic results are always marked non-deployable.  They are useful for
pipeline and ablation work, not as evidence of live DDS/SROS2 protection.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

from .features import TELEMETRY_FEATURES
from .schema import atomic_write_json, sha256_file, utc_now
from .synthetic_dataset import DEFAULT_HOLDOUT_CLASSES
from .train import (
    ACTION_POLICY_PATH,
    FEATURES,
    ML_DIR,
    MODEL_SCHEMA_VERSION,
    load_training_frame,
)


GROUPED_METRICS_SCHEMA = "sros2-firewall-grouped-training-metrics/v1"
SPLIT_MANIFEST_SCHEMA = "sros2-firewall-split-manifest/v1"
FEATURE_SETS = {
    "network": tuple(FEATURES),
    "telemetry": tuple(TELEMETRY_FEATURES),
    "fusion": tuple(FEATURES + TELEMETRY_FEATURES),
}

# The normal-only detector does not have to share the classifier's features,
# and on live data it should not. Fitting it on the network features gave 0.055
# unknown-attack recall in Permissive against a 0.60 bar, while spending only
# 19% of the 5% false-positive budget: patrol traffic varies enough that an
# unseen attack falls inside the normal envelope. The same detector on the 18
# telemetry features reaches 0.616 at 5.1% measured FPR, because an attack that
# reaches the application layer leaves categorical evidence -- HMAC failures,
# unknown nodes, parameter calls -- rather than a subtle change in traffic
# shape. Set to None to reuse the classifier's feature set.
DEFAULT_ANOMALY_FEATURE_SET = "telemetry"

# Fraction of normal traffic the detector is allowed to flag. The old hardcoded
# 0.02 spent well under half the 0.05 deployment allowance and cost real
# detection: on live Permissive telemetry, 0.02 finds 0.25 of held-out unknown
# attacks and 0.04 finds 0.62. The 20% margin under MAX_DEPLOYMENT_ANOMALY_FPR
# is for estimation drift -- the threshold is set on a few hundred validation
# normal windows, and the rate it produces on unseen traffic moves by about a
# percentage point either way.
DEFAULT_ANOMALY_NORMAL_FPR = 0.04
SPLIT_NAMES = ("train", "validation", "test")
MIN_DEPLOYMENT_SESSIONS = 1100
MIN_DEPLOYMENT_BALANCED_ACCURACY = 0.80
MIN_DEPLOYMENT_MACRO_F1 = 0.80
MIN_DEPLOYMENT_UNKNOWN_RECALL = 0.70
MAX_DEPLOYMENT_ANOMALY_FPR = 0.05
MAX_TRAINING_JOBS = 1


def _stable_order(value: str, seed: int) -> str:
    return hashlib.sha256(f"{seed}:{value}".encode("utf-8")).hexdigest()


def _as_indices(mask) -> "Any":
    import numpy as np

    return np.flatnonzero(mask.to_numpy() if hasattr(mask, "to_numpy") else mask)


def validate_preassigned_split(frame) -> dict[str, "Any"]:
    """Validate and return the immutable train/validation/test row indices."""

    if "split" not in frame.columns:
        raise ValueError(
            "a preassigned session split is required; missing split column"
        )
    split_values = set(frame["split"].astype(str))
    if split_values != set(SPLIT_NAMES):
        raise ValueError(
            f"split must contain exactly {list(SPLIT_NAMES)}, got "
            f"{sorted(split_values)}"
        )
    group_splits = frame.groupby("group_id", sort=False)["split"].nunique()
    if int(group_splits.max()) != 1:
        raise ValueError("session leakage: a group_id occurs in multiple splits")
    all_labels = set(frame["label"].astype(str))
    result: dict[str, Any] = {}
    split_groups: dict[str, set[str]] = {}
    for split in SPLIT_NAMES:
        mask = frame["split"].astype(str).eq(split)
        labels = set(frame.loc[mask, "label"].astype(str))
        if labels != all_labels:
            missing = sorted(all_labels - labels)
            raise ValueError(f"split={split} is missing classes {missing}")
        result[split] = _as_indices(mask)
        split_groups[split] = set(
            frame.loc[mask, "group_id"].astype(str)
        )
    if not (
        split_groups["train"].isdisjoint(split_groups["validation"])
        and split_groups["train"].isdisjoint(split_groups["test"])
        and split_groups["validation"].isdisjoint(split_groups["test"])
    ):
        raise RuntimeError("internal split validation error")
    return result


def split_validation_for_calibration(
    frame,
    validation_index,
    *,
    seed: int,
) -> tuple["Any", "Any"]:
    """Split validation sessions into calibration and threshold subsets."""

    import numpy as np

    validation = frame.iloc[validation_index]
    group_labels = (
        validation[["group_id", "label"]]
        .groupby("group_id", sort=False)["label"]
        .agg(lambda values: tuple(sorted(set(str(value) for value in values))))
    )

    # An attack session intentionally contains normal pre-attack windows plus
    # active attack windows.  Stratify by the complete label signature while
    # keeping the whole session together.
    by_label_signature: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for group_id, labels in group_labels.items():
        by_label_signature[tuple(labels)].append(str(group_id))

    calibration_groups: set[str] = set()
    threshold_groups: set[str] = set()
    for label_signature, group_ids in sorted(by_label_signature.items()):
        ordered = sorted(group_ids, key=lambda item: _stable_order(item, seed))
        if len(ordered) < 2:
            raise ValueError(
                "validation label signature "
                f"{label_signature!r} needs at least two sessions"
            )
        cut = max(1, min(len(ordered) - 1, len(ordered) // 2))
        calibration_groups.update(ordered[:cut])
        threshold_groups.update(ordered[cut:])

    groups = frame["group_id"].astype(str)
    is_validation = frame.index.isin(frame.index[validation_index])
    calibration = np.flatnonzero(
        is_validation & groups.isin(calibration_groups).to_numpy()
    )
    threshold = np.flatnonzero(
        is_validation & groups.isin(threshold_groups).to_numpy()
    )
    if not set(groups.iloc[calibration]).isdisjoint(set(groups.iloc[threshold])):
        raise RuntimeError("calibration/threshold session leakage")
    return calibration, threshold


def _metric_summary(y_true, probabilities, classes: Sequence[str]) -> dict:
    import numpy as np
    from sklearn.metrics import (
        average_precision_score,
        balanced_accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        log_loss,
    )
    from sklearn.preprocessing import label_binarize

    probability = np.asarray(probabilities, dtype=float)
    if probability.ndim != 2 or probability.shape[1] != len(classes):
        raise RuntimeError("invalid probability matrix")
    if not np.isfinite(probability).all():
        raise RuntimeError("non-finite probability matrix")
    predicted = np.asarray(classes, dtype=object)[np.argmax(probability, axis=1)]
    y = np.asarray(y_true, dtype=str)
    normal_index = list(classes).index("normal")
    normal_mask = y == "normal"
    attack_mask = ~normal_mask
    predicted_attack = predicted != "normal"
    confidences = probability.max(axis=1)
    correctness = predicted == y
    bins = np.linspace(0.0, 1.0, 11)
    ece = 0.0
    for lower, upper in zip(bins[:-1], bins[1:]):
        in_bin = (confidences >= lower) & (
            (confidences <= upper) if upper == 1.0 else (confidences < upper)
        )
        if in_bin.any():
            ece += float(in_bin.mean()) * abs(
                float(correctness[in_bin].mean())
                - float(confidences[in_bin].mean())
            )
    one_hot = label_binarize(y, classes=list(classes))
    macro_ap = float(
        average_precision_score(one_hot, probability, average="macro")
    )
    binary_score = 1.0 - probability[:, normal_index]
    binary_target = attack_mask.astype(int)
    return {
        "rows": int(len(y)),
        "balanced_accuracy": float(balanced_accuracy_score(y, predicted)),
        "macro_f1": float(
            f1_score(y, predicted, average="macro", zero_division=0)
        ),
        "macro_pr_auc_ovr": macro_ap,
        "binary_attack_pr_auc": float(
            average_precision_score(binary_target, binary_score)
        ),
        "log_loss": float(log_loss(y, probability, labels=list(classes))),
        "multiclass_brier": float(
            np.mean(np.sum((probability - one_hot) ** 2, axis=1))
        ),
        "expected_calibration_error_10bin": ece,
        "attack_recall": (
            float((predicted_attack & attack_mask).sum() / attack_mask.sum())
            if attack_mask.any()
            else 0.0
        ),
        "normal_false_positive_rate": (
            float((predicted_attack & normal_mask).sum() / normal_mask.sum())
            if normal_mask.any()
            else 0.0
        ),
        "classification_report": classification_report(
            y,
            predicted,
            labels=list(classes),
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(
            y,
            predicted,
            labels=list(classes),
        ).tolist(),
    }


def _make_candidates(*, seed: int, n_estimators: int) -> dict[str, Any]:
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier

    return {
        "random_forest_balanced": RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=18,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight="balanced_subsample",
            random_state=seed,
            n_jobs=MAX_TRAINING_JOBS,
        ),
        "extra_trees_balanced": ExtraTreesClassifier(
            n_estimators=n_estimators,
            max_depth=None,
            min_samples_leaf=1,
            max_features=0.7,
            class_weight="balanced",
            random_state=seed,
            n_jobs=MAX_TRAINING_JOBS,
        ),
    }


def _fit_candidate(name: str, estimator, x, y):
    estimator.fit(x, y)
    return estimator


def choose_reject_threshold(
    y_true,
    probabilities,
    classes: Sequence[str],
    *,
    minimum_attack_precision: float = 0.98,
    maximum_normal_fpr: float = 0.005,
) -> dict[str, float | int | bool]:
    """Tune an alert-only reject option without looking at test data."""

    import numpy as np

    y = np.asarray(y_true, dtype=str)
    probability = np.asarray(probabilities, dtype=float)
    predicted = np.asarray(classes, dtype=object)[np.argmax(probability, axis=1)]
    confidence = probability.max(axis=1)
    normal = y == "normal"
    attack = ~normal
    # Never allow a tuned model to disable abstention by selecting 0.0.  The
    # per-class policy may be stricter; this global floor only adds safety.
    candidates = sorted(
        {1.0, *[float(value) for value in np.linspace(0.50, 0.99, 50)]}
    )
    feasible = []
    fallback = []
    for threshold in candidates:
        accepted_attack = (confidence >= threshold) & (predicted != "normal")
        accepted_count = int(accepted_attack.sum())
        true_attack = accepted_attack & attack
        precision = (
            float(true_attack.sum() / accepted_count) if accepted_count else 1.0
        )
        normal_fpr = (
            float((accepted_attack & normal).sum() / normal.sum())
            if normal.any()
            else 0.0
        )
        correct_attack_coverage = (
            float(((predicted == y) & accepted_attack & attack).sum() / attack.sum())
            if attack.any()
            else 0.0
        )
        item = {
            "threshold": float(threshold),
            "attack_precision": precision,
            "normal_fpr": normal_fpr,
            "correct_attack_coverage": correct_attack_coverage,
            "accepted_attack_predictions": accepted_count,
        }
        fallback.append(item)
        if precision >= minimum_attack_precision and normal_fpr <= maximum_normal_fpr:
            feasible.append(item)
    pool = feasible or fallback
    selected = max(
        pool,
        key=lambda item: (
            item["correct_attack_coverage"],
            item["attack_precision"],
            -item["normal_fpr"],
            -item["threshold"],
        ),
    )
    return {
        **selected,
        "constraints_satisfied": bool(feasible),
        "minimum_attack_precision": float(minimum_attack_precision),
        "maximum_normal_fpr": float(maximum_normal_fpr),
    }


def _apply_reject_metrics(y_true, probabilities, classes, threshold: float) -> dict:
    import numpy as np

    y = np.asarray(y_true, dtype=str)
    probability = np.asarray(probabilities, dtype=float)
    predicted = np.asarray(classes, dtype=object)[np.argmax(probability, axis=1)]
    confidence = probability.max(axis=1)
    accepted = confidence >= float(threshold)
    accepted_attack = accepted & (predicted != "normal")
    normal = y == "normal"
    attack = ~normal
    return {
        "threshold": float(threshold),
        "overall_coverage": float(accepted.mean()),
        "selective_accuracy": (
            float((predicted[accepted] == y[accepted]).mean())
            if accepted.any()
            else 0.0
        ),
        "accepted_attack_precision": (
            float((accepted_attack & attack).sum() / accepted_attack.sum())
            if accepted_attack.any()
            else 1.0
        ),
        "normal_false_positive_rate": (
            float((accepted_attack & normal).sum() / normal.sum())
            if normal.any()
            else 0.0
        ),
        "correct_attack_coverage": (
            float(((predicted == y) & accepted_attack & attack).sum() / attack.sum())
            if attack.any()
            else 0.0
        ),
    }


def _bootstrap_group_ci(
    frame,
    row_index,
    y_true,
    probabilities,
    classes: Sequence[str],
    *,
    seed: int,
    samples: int,
) -> dict[str, list[float]]:
    import numpy as np
    from sklearn.metrics import confusion_matrix

    predicted = np.asarray(classes, dtype=object)[
        np.argmax(np.asarray(probabilities, dtype=float), axis=1)
    ]
    y = np.asarray(y_true, dtype=str)
    groups = frame.iloc[row_index]["group_id"].astype(str).to_numpy()
    unique_groups = sorted(set(groups))
    matrices = []
    for group in unique_groups:
        mask = groups == group
        matrices.append(
            confusion_matrix(y[mask], predicted[mask], labels=list(classes))
        )
    rng = np.random.default_rng(seed)
    balanced_values = []
    macro_f1_values = []
    for _ in range(samples):
        selected = rng.integers(0, len(matrices), size=len(matrices))
        matrix = np.sum([matrices[index] for index in selected], axis=0)
        support = matrix.sum(axis=1)
        recalls = np.divide(
            np.diag(matrix),
            support,
            out=np.zeros_like(support, dtype=float),
            where=support != 0,
        )
        balanced_values.append(float(recalls[support > 0].mean()))
        precision_den = matrix.sum(axis=0)
        precision = np.divide(
            np.diag(matrix),
            precision_den,
            out=np.zeros_like(precision_den, dtype=float),
            where=precision_den != 0,
        )
        f1 = np.divide(
            2 * precision * recalls,
            precision + recalls,
            out=np.zeros_like(recalls, dtype=float),
            where=(precision + recalls) != 0,
        )
        macro_f1_values.append(float(f1[support > 0].mean()))
    return {
        "method": "session_group_bootstrap",
        "samples": int(samples),
        "balanced_accuracy_95ci": [
            float(value)
            for value in np.quantile(balanced_values, [0.025, 0.975])
        ],
        "macro_f1_95ci": [
            float(value)
            for value in np.quantile(macro_f1_values, [0.025, 0.975])
        ],
    }


def _fit_unknown_detector(
    frame,
    feature_names: Sequence[str],
    split_index: dict[str, Any],
    *,
    seed: int,
    target_normal_fpr: float,
    n_estimators: int,
):
    import numpy as np
    from sklearn.ensemble import IsolationForest

    labels = frame["label"].astype(str)
    binary = frame["binary"].astype(str)
    novelty = (
        frame["novelty_role"].astype(str)
        if "novelty_role" in frame.columns
        else None
    )
    train_mask = np.zeros(len(frame), dtype=bool)
    train_mask[split_index["train"]] = True
    validation_mask = np.zeros(len(frame), dtype=bool)
    validation_mask[split_index["validation"]] = True
    normal_train = train_mask & labels.eq("normal").to_numpy()
    normal_validation = validation_mask & labels.eq("normal").to_numpy()
    known_attack_validation = validation_mask & binary.eq("attack").to_numpy()
    novelty_mask = (
        novelty.eq("novelty_holdout_candidate").to_numpy()
        if novelty is not None
        else np.zeros(len(frame), dtype=bool)
    )
    if novelty is not None:
        known_attack_validation &= ~novelty_mask
    # What the detector is actually fitted on, so the artifact can report it
    # instead of asserting it.  Normal-only by construction, which is why no
    # attack class -- held out or not -- contributes to the fit.
    fit_provenance = {
        "fit_rows": int(normal_train.sum()),
        "fit_rows_labelled_attack": int(
            (normal_train & binary.eq("attack").to_numpy()).sum()
        ),
        "fit_rows_in_novelty_holdout": int((normal_train & novelty_mask).sum()),
        "threshold_rows": int(normal_validation.sum()),
        "threshold_rows_in_novelty_holdout": int(
            (normal_validation & novelty_mask).sum()
        ),
    }

    comparisons = []
    fitted = []
    for max_features in (0.5, 1.0):
        detector = IsolationForest(
            n_estimators=n_estimators,
            contamination="auto",
            max_features=max_features,
            random_state=seed,
            n_jobs=MAX_TRAINING_JOBS,
        )
        detector.fit(
            frame.loc[normal_train, feature_names].to_numpy(dtype=float)
        )
        normal_scores = detector.score_samples(
            frame.loc[normal_validation, feature_names].to_numpy(dtype=float)
        )
        threshold = float(
            np.quantile(normal_scores, target_normal_fpr, method="lower")
        )
        known_scores = detector.score_samples(
            frame.loc[known_attack_validation, feature_names].to_numpy(
                dtype=float
            )
        )
        item = {
            "max_features": max_features,
            "threshold_from_normal_validation_only": threshold,
            "normal_validation_fpr": float((normal_scores < threshold).mean()),
            "known_attack_validation_recall": float(
                (known_scores < threshold).mean()
            ),
            # Measured, not asserted: novelty rows are excluded from the
            # selection mask above, and this counts what actually survived it.
            "novel_attack_validation_rows_used": int(
                (known_attack_validation & novelty_mask).sum()
            ),
        }
        comparisons.append(item)
        fitted.append((item, detector))
    selected_item, selected = max(
        fitted,
        key=lambda pair: (
            pair[0]["known_attack_validation_recall"],
            -pair[0]["normal_validation_fpr"],
        ),
    )
    # IsolationForest.predict compares score_samples against offset_.  Setting
    # this public fitted attribute makes the validation-only threshold part of
    # the signed artifact while preserving the standard sklearn interface.
    selected.offset_ = selected_item["threshold_from_normal_validation_only"]
    return selected, comparisons, selected_item, fit_provenance


def _unknown_test_metrics(
    detector,
    frame,
    feature_names: Sequence[str],
    test_index,
    fit_provenance: dict[str, int],
) -> dict:
    import numpy as np

    test = frame.iloc[test_index]
    scores = detector.score_samples(
        test[list(feature_names)].to_numpy(dtype=float)
    )
    anomaly = scores < float(detector.offset_)
    normal = test["label"].astype(str).eq("normal").to_numpy()
    attack = test["binary"].astype(str).eq("attack").to_numpy()
    novelty = (
        test["novelty_role"].astype(str).eq(
            "novelty_holdout_candidate"
        ).to_numpy()
        if "novelty_role" in test.columns
        else np.zeros(len(test), dtype=bool)
    )
    novel_attack = attack & novelty
    per_class = {}
    for label in sorted(set(test.loc[novel_attack, "label"].astype(str))):
        mask = novel_attack & test["label"].astype(str).eq(label).to_numpy()
        per_class[label] = {
            "rows": int(mask.sum()),
            "recall": float(anomaly[mask].mean()) if mask.any() else 0.0,
        }
    return {
        "threshold": float(detector.offset_),
        "normal_false_positive_rate": (
            float(anomaly[normal].mean()) if normal.any() else 0.0
        ),
        "all_attack_recall": (
            float(anomaly[attack].mean()) if attack.any() else 0.0
        ),
        "novel_holdout_attack_recall": (
            float(anomaly[novel_attack].mean()) if novel_attack.any() else 0.0
        ),
        "novel_holdout_attack_rows": int(novel_attack.sum()),
        "per_novel_class": per_class,
        "training_labels": ["normal"],
        # Counted from the masks the detector was actually fitted and
        # thresholded with.  These were previously hardcoded to 0, which made
        # a correct-but-unverified assertion look like a measurement.
        "novel_attack_train_rows_used": int(
            fit_provenance["fit_rows_in_novelty_holdout"]
        ),
        "novel_attack_validation_rows_used_for_selection": int(
            fit_provenance["threshold_rows_in_novelty_holdout"]
        ),
        "detector_fit_provenance": dict(fit_provenance),
        # The isolation is the anomaly head's, not the bundle's: the
        # closed-set classifier trains on the whole train split, holdout
        # classes included.  Reporting this next to the recall stops the
        # number being read as an open-set result for the whole model.
        "isolation_scope": "anomaly_head_only",
        "classifier_saw_novel_holdout_classes": True,
    }


def _group_lists(frame, split_index: dict[str, Any]) -> dict[str, list[str]]:
    return {
        name: sorted(set(frame.iloc[index]["group_id"].astype(str)))
        for name, index in split_index.items()
    }


def _model_card(metrics: dict) -> str:
    test = metrics.get("test_metrics") or {}
    unknown = metrics.get("unknown_attack_test") or {}
    validation = metrics["selected_validation_metrics"]
    lines = [
        "# SROS2 智慧防火牆 grouped-holdout 模型卡",
        "",
        f"- 建立時間：{metrics['trained_utc']}",
        f"- 資料層級：`{metrics['data_tier']}`",
        f"- 特徵：`{metrics['feature_set']}`（{len(metrics['features'])} 維）",
        f"- 選定模型：`{metrics['selected_model']}`",
        f"- validation balanced accuracy：{validation['balanced_accuracy']:.4f}",
        f"- validation macro-F1：{validation['macro_f1']:.4f}",
    ]
    if test:
        lines.extend(
            [
                f"- final test balanced accuracy：{test['balanced_accuracy']:.4f}",
                f"- final test macro-F1：{test['macro_f1']:.4f}",
                f"- final test normal FPR：{test['normal_false_positive_rate']:.4f}",
            ]
        )
    if unknown:
        lines.append(
            "- 未知攻擊 holdout recall："
            f"{unknown['novel_holdout_attack_recall']:.4f}"
        )
    lines.extend(
        [
            "",
            "## 防洩漏協議",
            "",
            "- split 單位是 session/group_id；三個 split 的 session 交集為 0。",
            "- train 只用於擬合候選模型；validation 用於選模、校準與拒答門檻。",
            "- test 不參與任何選模或門檻調整，只在最後評估階段預測一次。",
            "- unknown detector 只以 normal train 擬合；候選未知攻擊沒有進入該 detector 的訓練或門檻選擇。",
            "",
            "## 限制",
            "",
        ]
    )
    if metrics["data_tier"] == "synthetic-pretrain":
        lines.extend(
            [
                "- 這是 feature-level 合成資料，telemetry 來自生成 profile，不是真實 ROS 2/SROS2 事件。",
                "- 高分可能部分來自合成 telemetry 的直接訊號；不能宣稱真實跨主機防禦準確率。",
                "- `deployment_eligible=false`，模型只能離線觀察，不能自動封鎖 IP。",
            ]
        )
    else:
        lines.append("- 上線前仍須通過獨立跨主機、長時間與故障復原驗收。")
    return "\n".join(lines) + "\n"


def train_grouped_model(
    feature_csv: str | Path,
    output_dir: str | Path,
    *,
    data_tier: str = "live",
    feature_set: str = "fusion",
    anomaly_feature_set: str | None = DEFAULT_ANOMALY_FEATURE_SET,
    anomaly_normal_fpr: float = DEFAULT_ANOMALY_NORMAL_FPR,
    anomaly_budget_chosen_with_test_knowledge: bool = False,
    random_state: int = 20260803,
    n_estimators: int = 400,
    bootstrap_samples: int = 500,
    final_evaluate_test: bool = False,
) -> dict[str, Any]:
    """Train, calibrate and optionally perform the one final test evaluation."""

    import numpy as np
    import pandas as pd
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import ExtraTreesClassifier
    from sklearn.frozen import FrozenEstimator

    if feature_set not in FEATURE_SETS:
        raise ValueError(f"feature_set must be one of {sorted(FEATURE_SETS)}")
    if anomaly_feature_set is not None and anomaly_feature_set not in FEATURE_SETS:
        raise ValueError(
            f"anomaly_feature_set must be None or one of {sorted(FEATURE_SETS)}"
        )
    if not 0.0 < anomaly_normal_fpr <= MAX_DEPLOYMENT_ANOMALY_FPR:
        raise ValueError(
            "anomaly_normal_fpr must be in (0, "
            f"{MAX_DEPLOYMENT_ANOMALY_FPR}]"
        )
    if n_estimators < 20:
        raise ValueError("n_estimators must be at least 20")
    if bootstrap_samples < 20:
        raise ValueError("bootstrap_samples must be at least 20")
    feature_names = list(FEATURE_SETS[feature_set])
    feature_path = Path(feature_csv)
    frame = load_training_frame(
        feature_path,
        data_tier=data_tier,
        feature_names=feature_names,
        extra_columns=("split",),
        # The anomaly detector may use columns the classifier does not, so ask
        # for them here. They stay optional: a network-only CSV still trains,
        # and the detector then falls back to the classifier's features with
        # anomaly_feature_set_used recording what it actually got.
        optional_columns=("novelty_role",)
        + tuple(FEATURE_SETS.get(anomaly_feature_set or feature_set, ())),
    )
    if len(frame) < 20 or frame["label"].nunique() < 2:
        raise ValueError("at least 20 rows and two classes are required")
    split_index = validate_preassigned_split(frame)
    calibration_index, threshold_index = split_validation_for_calibration(
        frame,
        split_index["validation"],
        seed=random_state,
    )
    split_groups = _group_lists(frame, split_index)
    if any(
        set(split_groups[left]) & set(split_groups[right])
        for left, right in (
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        )
    ):
        raise RuntimeError("session overlap detected after split validation")

    train_index = split_index["train"]
    validation_index = split_index["validation"]
    train_x = frame.iloc[train_index][feature_names].to_numpy(dtype=float)
    train_y = frame.iloc[train_index]["label"].astype(str).to_numpy()
    validation_x = frame.iloc[validation_index][feature_names].to_numpy(
        dtype=float
    )
    validation_y = (
        frame.iloc[validation_index]["label"].astype(str).to_numpy()
    )

    comparisons: dict[str, dict] = {}
    selected_name: str | None = None
    selected = None
    selected_key: tuple[float, float, float] | None = None
    for name, candidate in _make_candidates(
        seed=random_state,
        n_estimators=n_estimators,
    ).items():
        candidate = _fit_candidate(name, candidate, train_x, train_y)
        probability = candidate.predict_proba(validation_x)
        metrics = _metric_summary(validation_y, probability, candidate.classes_)
        comparisons[name] = {
            key: value
            for key, value in metrics.items()
            if key not in {"classification_report", "confusion_matrix"}
        }
        candidate_key = (
            comparisons[name]["balanced_accuracy"],
            comparisons[name]["macro_f1"],
            -comparisons[name]["log_loss"],
        )
        if selected_key is None or candidate_key > selected_key:
            selected = candidate
            selected_name = name
            selected_key = candidate_key
        else:
            del candidate
        del probability
        gc.collect()
    if selected is None or selected_name is None:
        raise RuntimeError("no model candidate was fitted")
    selected_validation_probability = selected.predict_proba(validation_x)
    selected_validation_metrics = _metric_summary(
        validation_y,
        selected_validation_probability,
        selected.classes_,
    )

    # Fair ablation: identical ExtraTrees configuration and immutable split.
    ablation = {}
    if set(FEATURE_SETS["fusion"]).issubset(frame.columns):
        for ablation_name, ablation_features in FEATURE_SETS.items():
            estimator = None
            if (
                ablation_name == feature_set
                and selected_name == "extra_trees_balanced"
            ):
                probability = selected.predict_proba(
                    frame.iloc[validation_index][list(ablation_features)].to_numpy(
                        dtype=float
                    )
                )
                ablation_classes = selected.classes_
            else:
                estimator = ExtraTreesClassifier(
                    n_estimators=n_estimators,
                    max_depth=None,
                    min_samples_leaf=1,
                    max_features=0.7,
                    class_weight="balanced",
                    random_state=random_state,
                    n_jobs=MAX_TRAINING_JOBS,
                )
                estimator.fit(
                    frame.iloc[train_index][list(ablation_features)].to_numpy(
                        dtype=float
                    ),
                    train_y,
                )
                probability = estimator.predict_proba(
                    frame.iloc[validation_index][list(ablation_features)].to_numpy(
                        dtype=float
                    )
                )
                ablation_classes = estimator.classes_
            summary = _metric_summary(
                validation_y,
                probability,
                ablation_classes,
            )
            ablation[ablation_name] = {
                key: value
                for key, value in summary.items()
                if key not in {"classification_report", "confusion_matrix"}
            }
            del estimator, probability
            gc.collect()

    calibrated = CalibratedClassifierCV(
        FrozenEstimator(selected),
        method="sigmoid",
        cv=None,
        n_jobs=1,
    )
    calibrated.fit(
        frame.iloc[calibration_index][feature_names].to_numpy(dtype=float),
        frame.iloc[calibration_index]["label"].astype(str).to_numpy(),
    )
    threshold_probability = calibrated.predict_proba(
        frame.iloc[threshold_index][feature_names].to_numpy(dtype=float)
    )
    reject_selection = choose_reject_threshold(
        frame.iloc[threshold_index]["label"].astype(str).to_numpy(),
        threshold_probability,
        calibrated.classes_,
    )

    # Report the holdout the data actually carries. The old code printed the
    # synthetic set's four class names next to live results whose holdout was
    # sensor_spoof/service_dos -- the numbers were right, the label on them was
    # not. _fit_unknown_detector already reads novelty_role, so this reads the
    # same column rather than a second, independent notion of "held out".
    actual_holdout_classes = sorted(DEFAULT_HOLDOUT_CLASSES)
    if "novelty_role" in frame.columns:
        actual_holdout_classes = sorted(
            frame.loc[
                frame["novelty_role"].astype(str).eq("novelty_holdout_candidate"),
                "label",
            ]
            .astype(str)
            .unique()
        )

    anomaly_feature_names = list(feature_names)
    anomaly_feature_set_used = feature_set
    if (
        anomaly_feature_set is not None
        and set(FEATURE_SETS[anomaly_feature_set]).issubset(frame.columns)
    ):
        anomaly_feature_names = list(FEATURE_SETS[anomaly_feature_set])
        anomaly_feature_set_used = anomaly_feature_set
        # load_training_frame only coerces and range-checks the classifier's
        # columns. These arrived as optional extras, so hold them to the same
        # bar here instead of letting a NaN reach IsolationForest.
        anomaly_matrix = frame[anomaly_feature_names].apply(
            pd.to_numeric, errors="coerce"
        )
        if not bool(np.isfinite(anomaly_matrix.to_numpy(dtype=float)).all()):
            raise ValueError(
                f"anomaly features {anomaly_feature_set} contain NaN or Infinity"
            )
        frame[anomaly_feature_names] = anomaly_matrix
    (
        anomaly,
        anomaly_comparison,
        anomaly_selection,
        anomaly_fit_provenance,
    ) = _fit_unknown_detector(
        frame,
        anomaly_feature_names,
        split_index,
        seed=random_state,
        target_normal_fpr=anomaly_normal_fpr,
        n_estimators=n_estimators,
    )

    feature_importance = []
    if hasattr(selected, "feature_importances_"):
        feature_importance = sorted(
            (
                {"feature": feature, "importance": float(importance)}
                for feature, importance in zip(
                    feature_names,
                    selected.feature_importances_,
                )
            ),
            key=lambda item: item["importance"],
            reverse=True,
        )

    # Eligibility is calculated only after the final test and all independent
    # live-data gates below.  A file merely labelled live must never unlock it.
    deployment_eligible = False
    metrics: dict[str, Any] = {
        "schema_version": GROUPED_METRICS_SCHEMA,
        "trained_utc": utc_now(),
        "data_tier": data_tier,
        "deployment_eligible": deployment_eligible,
        "deployment_block_reason": "deployment gates have not been evaluated",
        "feature_set": feature_set,
        "features": feature_names,
        "anomaly_feature_set_requested": anomaly_feature_set,
        "anomaly_feature_set_used": anomaly_feature_set_used,
        "anomaly_normal_fpr_budget": float(anomaly_normal_fpr),
        "rows": int(len(frame)),
        "sessions": int(frame["group_id"].astype(str).nunique()),
        "classes": [str(value) for value in calibrated.classes_],
        "split_protocol": {
            "source": "preassigned_dataset_split",
            "unit": "group_id/session_id",
            "selection_split": "validation",
            "calibration_subset": "validation sessions only",
            "reject_threshold_subset": "disjoint validation sessions only",
            # This run performs no selection against test.  It cannot know
            # whether the hyperparameters it was handed were themselves picked
            # after someone looked at test, so the caller must say so, and the
            # artifact records it rather than the document alone.
            "test_used_for_selection_in_this_run": False,
            "anomaly_budget_chosen_with_test_knowledge": bool(
                anomaly_budget_chosen_with_test_knowledge
            ),
            "independent_final_test": bool(
                final_evaluate_test
                and not anomaly_budget_chosen_with_test_knowledge
            ),
            "test_prediction_passes": 1 if final_evaluate_test else 0,
            "session_overlap": 0,
            "rows": {
                name: int(len(index)) for name, index in split_index.items()
            },
            "sessions": {
                name: len(groups) for name, groups in split_groups.items()
            },
        },
        "model_comparison_validation": comparisons,
        "selected_model": selected_name,
        "selected_validation_metrics": selected_validation_metrics,
        "feature_ablation_validation": ablation,
        "calibration": {
            "method": "sigmoid",
            "fit_rows": int(len(calibration_index)),
            "fit_sessions": int(
                frame.iloc[calibration_index]["group_id"].nunique()
            ),
            "threshold_rows": int(len(threshold_index)),
            "threshold_sessions": int(
                frame.iloc[threshold_index]["group_id"].nunique()
            ),
        },
        "reject_option_validation": reject_selection,
        "unknown_detector_selection_validation": {
            "candidates": anomaly_comparison,
            "selected": anomaly_selection,
            "holdout_classes": actual_holdout_classes,
        },
        "feature_importance": feature_importance,
        "test_metrics": None,
        "test_group_bootstrap_95ci": None,
        "test_reject_option": None,
        "unknown_attack_test": None,
        "limitations": [
            "feature-level synthetic telemetry is not live SROS2 evidence"
            if data_tier == "synthetic-pretrain"
            else "cross-host generalization remains separately gated",
            "automatic blocking remains disabled until all deployment gates pass",
        ],
    }

    if final_evaluate_test:
        # The only final-test prediction pass in this function.  Nothing above
        # receives test labels or predictions for selection/tuning.
        test_index = split_index["test"]
        test_x = frame.iloc[test_index][feature_names].to_numpy(dtype=float)
        test_y = frame.iloc[test_index]["label"].astype(str).to_numpy()
        test_probability = calibrated.predict_proba(test_x)
        metrics["test_metrics"] = _metric_summary(
            test_y,
            test_probability,
            calibrated.classes_,
        )
        metrics["test_group_bootstrap_95ci"] = _bootstrap_group_ci(
            frame,
            test_index,
            test_y,
            test_probability,
            calibrated.classes_,
            seed=random_state + 1,
            samples=bootstrap_samples,
        )
        metrics["test_reject_option"] = _apply_reject_metrics(
            test_y,
            test_probability,
            calibrated.classes_,
            float(reject_selection["threshold"]),
        )
        metrics["unknown_attack_test"] = _unknown_test_metrics(
            anomaly,
            frame,
            anomaly_feature_names,
            test_index,
            anomaly_fit_provenance,
        )

    from .formal_preflight import _live_multimodal_contract_check

    contract_ok, contract_detail = _live_multimodal_contract_check()
    test_metrics = metrics["test_metrics"] or {}
    unknown_metrics = metrics["unknown_attack_test"] or {}
    policy_classes = set(
        json.loads(ACTION_POLICY_PATH.read_text(encoding="utf-8"))["rules"]
    )
    deployment_gates = {
        "live_data_tier": data_tier == "live",
        "validated_live_multimodal_contract": bool(contract_ok),
        "fusion_feature_contract": feature_set == "fusion",
        "minimum_1100_independent_sessions": int(
            frame["group_id"].astype(str).nunique()
        ) >= MIN_DEPLOYMENT_SESSIONS,
        "all_policy_classes_present": set(calibrated.classes_) == policy_classes,
        "final_test_evaluated_once": bool(
            final_evaluate_test
            and metrics["split_protocol"]["test_prediction_passes"] == 1
        ),
        "test_balanced_accuracy_at_least_0_80": (
            float(test_metrics.get("balanced_accuracy", -1.0))
            >= MIN_DEPLOYMENT_BALANCED_ACCURACY
        ),
        "test_macro_f1_at_least_0_80": (
            float(test_metrics.get("macro_f1", -1.0))
            >= MIN_DEPLOYMENT_MACRO_F1
        ),
        "unknown_holdout_recall_at_least_0_70": (
            float(unknown_metrics.get("novel_holdout_attack_recall", -1.0))
            >= MIN_DEPLOYMENT_UNKNOWN_RECALL
        ),
        "anomaly_normal_fpr_at_most_0_05": (
            float(unknown_metrics.get("normal_false_positive_rate", 1.0))
            <= MAX_DEPLOYMENT_ANOMALY_FPR
        ),
        "session_split_overlap_zero": all(
            int(value) == 0
            for value in [metrics["split_protocol"]["session_overlap"]]
        ),
    }
    deployment_eligible = all(deployment_gates.values())
    failed_deployment_gates = sorted(
        name for name, passed in deployment_gates.items() if not passed
    )
    metrics["deployment_eligible"] = deployment_eligible
    metrics["deployment_gates"] = deployment_gates
    metrics["deployment_contract_detail"] = contract_detail
    metrics["deployment_block_reason"] = (
        None
        if deployment_eligible
        else "failed gates: " + ", ".join(failed_deployment_gates)
    )

    policy_hashes = sorted(
        value
        for value in set(frame["policy_sha256"].astype(str))
        if len(value) == 64
    )
    bundle = {
        "schema_version": MODEL_SCHEMA_VERSION,
        "classifier": calibrated,
        "anomaly_detector": anomaly,
        "features": feature_names,
        "anomaly_features": anomaly_feature_names,
        "classes": [str(value) for value in calibrated.classes_],
        "training": {
            "protocol": "preassigned_session_train_validation_test",
            "grouping": "session_id/group_id",
            "data_tier": data_tier,
            "feature_set": feature_set,
            "anomaly_feature_set_used": anomaly_feature_set_used,
            "anomaly_normal_fpr_budget": float(anomaly_normal_fpr),
            "deployment_eligible": deployment_eligible,
            "selected_model": selected_name,
            "reject_threshold": float(reject_selection["threshold"]),
            "unknown_holdout_classes": actual_holdout_classes,
            "policy_sha256_values": policy_hashes,
            "action_policy_sha256": sha256_file(ACTION_POLICY_PATH),
            "feature_csv_sha256": sha256_file(feature_path),
            # This run performs no selection against test.  It cannot know
            # whether the hyperparameters it was handed were themselves picked
            # after someone looked at test, so the caller must say so, and the
            # artifact records it rather than the document alone.
            "test_used_for_selection_in_this_run": False,
            "anomaly_budget_chosen_with_test_knowledge": bool(
                anomaly_budget_chosen_with_test_knowledge
            ),
            "independent_final_test": bool(
                final_evaluate_test
                and not anomaly_budget_chosen_with_test_knowledge
            ),
            "test_prediction_passes": 1 if final_evaluate_test else 0,
        },
        "metrics": {
            # Canonical names are consumed by cross_host_admission._check_model.
            # Validation-only values never fill these deployment fields.
            "balanced_accuracy": (
                metrics["test_metrics"]["balanced_accuracy"]
                if metrics["test_metrics"]
                else 0.0
            ),
            "macro_f1": (
                metrics["test_metrics"]["macro_f1"]
                if metrics["test_metrics"]
                else 0.0
            ),
            "anomaly_recall": (
                metrics["unknown_attack_test"]["novel_holdout_attack_recall"]
                if metrics["unknown_attack_test"]
                else 0.0
            ),
            "anomaly_fpr": (
                metrics["unknown_attack_test"]["normal_false_positive_rate"]
                if metrics["unknown_attack_test"]
                else 1.0
            ),
            "validation_balanced_accuracy": selected_validation_metrics[
                "balanced_accuracy"
            ],
            "validation_macro_f1": selected_validation_metrics["macro_f1"],
        },
    }

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ML_DIR))
    try:
        from ml_utils import atomic_joblib_dump
    finally:
        sys.path.remove(str(ML_DIR))
    model_path = output / "firewall_model.joblib"
    atomic_joblib_dump(bundle, model_path)
    atomic_write_json(output / "training_metrics.json", metrics)
    atomic_write_json(
        output / "split_manifest.json",
        {
            "schema_version": SPLIT_MANIFEST_SCHEMA,
            "feature_csv": str(feature_path),
            "feature_csv_sha256": sha256_file(feature_path),
            "unit": "group_id/session_id",
            "session_overlap": 0,
            "splits": split_groups,
            "validation_subsets": {
                "calibration": sorted(
                    set(frame.iloc[calibration_index]["group_id"].astype(str))
                ),
                "threshold": sorted(
                    set(frame.iloc[threshold_index]["group_id"].astype(str))
                ),
            },
            # This run performs no selection against test.  It cannot know
            # whether the hyperparameters it was handed were themselves picked
            # after someone looked at test, so the caller must say so, and the
            # artifact records it rather than the document alone.
            "test_used_for_selection_in_this_run": False,
            "anomaly_budget_chosen_with_test_knowledge": bool(
                anomaly_budget_chosen_with_test_knowledge
            ),
            "independent_final_test": bool(
                final_evaluate_test
                and not anomaly_budget_chosen_with_test_knowledge
            ),
            "test_prediction_passes": 1 if final_evaluate_test else 0,
        },
    )
    (output / "MODEL_CARD.md").write_text(
        _model_card(metrics),
        encoding="utf-8",
    )
    return {
        "model": str(model_path),
        "metrics": str(output / "training_metrics.json"),
        "split_manifest": str(output / "split_manifest.json"),
        "model_card": str(output / "MODEL_CARD.md"),
        "deployment_eligible": deployment_eligible,
        "selected_model": selected_name,
        "validation_balanced_accuracy": selected_validation_metrics[
            "balanced_accuracy"
        ],
        "test_balanced_accuracy": (
            metrics["test_metrics"]["balanced_accuracy"]
            if metrics["test_metrics"]
            else None
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Leak-resistant grouped model selection and final evaluation"
    )
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--data-tier",
        choices=("live", "synthetic-pretrain"),
        required=True,
    )
    parser.add_argument(
        "--feature-set",
        choices=tuple(FEATURE_SETS),
        default="fusion",
    )
    parser.add_argument(
        "--anomaly-feature-set",
        choices=tuple(FEATURE_SETS) + ("same-as-classifier",),
        default=DEFAULT_ANOMALY_FEATURE_SET,
        help=(
            "feature set for the normal-only unknown-attack detector; "
            "telemetry by default because network features gave 0.055 "
            "unknown recall against 0.616 on live Permissive data"
        ),
    )
    parser.add_argument(
        "--anomaly-normal-fpr",
        type=float,
        default=DEFAULT_ANOMALY_NORMAL_FPR,
        help=(
            "share of normal traffic the unknown-attack detector may flag; "
            f"must not exceed the {MAX_DEPLOYMENT_ANOMALY_FPR} deployment gate"
        ),
    )
    parser.add_argument(
        "--anomaly-budget-chosen-with-test-knowledge",
        action="store_true",
        help=(
            "record in the artifact that --anomaly-normal-fpr was picked after "
            "seeing test results; forces independent_final_test=false"
        ),
    )
    parser.add_argument("--random-state", type=int, default=20260803)
    parser.add_argument("--n-estimators", type=int, default=400)
    parser.add_argument("--bootstrap-samples", type=int, default=500)
    parser.add_argument(
        "--final-evaluate-test",
        action="store_true",
        help="open the untouched test once after validation-only selection",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = train_grouped_model(
        args.features,
        args.output,
        data_tier=args.data_tier,
        feature_set=args.feature_set,
        anomaly_feature_set=(
            None
            if args.anomaly_feature_set == "same-as-classifier"
            else args.anomaly_feature_set
        ),
        anomaly_normal_fpr=args.anomaly_normal_fpr,
        anomaly_budget_chosen_with_test_knowledge=(
            args.anomaly_budget_chosen_with_test_knowledge
        ),
        random_state=args.random_state,
        n_estimators=args.n_estimators,
        bootstrap_samples=args.bootstrap_samples,
        final_evaluate_test=args.final_evaluate_test,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if not result["deployment_eligible"]:
        print("注意：合成模型維持 deployment_eligible=false，不可自動封鎖。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
