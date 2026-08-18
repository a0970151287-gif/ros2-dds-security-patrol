"""Development-only, session-grouped evaluation for the hierarchical model.

This module deliberately cannot produce a deployable artifact.  It reuses the
frozen train/selection/calibration/threshold session contract written by
``hierarchical_training.py`` and never accesses, converts, or predicts a
historical test label/feature field.  Test split metadata is inspected only to
prove exclusion.  The CSV reader necessarily tokenizes each physical row in a
mixed-split source file; ``test_not_read`` means no semantic test field enters
the evaluation, not that the storage device skipped those bytes.

The resulting comparison is intended to answer engineering questions such as
"does causal context help?" and "is a tree model worth its memory/latency?".
It is not an independent final test and must not be used to enable a response
adapter or IP-blocking backend.
"""

from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import json
import math
import os
import sys
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .hierarchical_model import (
    DEFAULT_LIVE_SOURCE_AVAILABILITY,
    EXPANDED_FEATURES,
    RAW_FEATURES,
    SOURCE_MASK_FEATURES,
    family_for_label,
    normalize_source_availability,
)
from .hierarchical_training import (
    _expanded_matrix,
    _session_equal_weights,
)
from .schema import atomic_write_json, utc_now
from .train import FEATURES


DEVELOPMENT_EVALUATION_SCHEMA = "sros2-firewall-development-evaluation/v1"
SUPPORTED_CONTRACT_SCHEMAS = frozenset(
    {
        # r2 artifacts are v1.  v2 adds weighted development statistics while
        # preserving the same frozen session-list fields consumed here.
        "sros2-firewall-hierarchical-metrics/v1",
        "sros2-firewall-hierarchical-metrics/v2",
    }
)
MODEL_NAMES = (
    "dummy_prior",
    "logistic_balanced",
    "random_forest_balanced",
    "extra_trees_balanced",
    "hist_gradient_boosting_balanced",
)
TASK_NAMES = ("binary", "family", "leaf")
FEATURE_SET_NAMES = (
    "current_only",
    "network",
    "telemetry",
    "fusion",
    "causal_temporal",
)
PHASE_NAMES = ("train", "selection", "calibration", "threshold")
MAX_TRAINING_JOBS = 1


@dataclass(frozen=True)
class FrozenDevelopmentContract:
    """Validated subset of a hierarchical-r2 metrics contract."""

    path: Path
    sha256: str
    schema_version: str
    security_mode: str
    selection_groups: frozenset[str]
    calibration_groups: frozenset[str]
    threshold_groups: frozenset[str]
    novelty_holdout_labels: frozenset[str]
    excluded_sessions: frozenset[str]
    expected_rows_after_exclusion: int
    expected_sessions_after_exclusion: int
    source_availability: Mapping[str, bool]

    @property
    def development_groups(self) -> frozenset[str]:
        return frozenset().union(
            self.selection_groups,
            self.calibration_groups,
            self.threshold_groups,
        )

    @property
    def phase_by_group(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for phase, groups in (
            ("selection", self.selection_groups),
            ("calibration", self.calibration_groups),
            ("threshold", self.threshold_groups),
        ):
            result.update({group: phase for group in groups})
        return result


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _string_set(value: Any, field: str, *, allow_empty: bool = False) -> frozenset[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{field} must be a list of non-empty strings")
    result = frozenset(value)
    if len(result) != len(value):
        raise ValueError(f"{field} contains duplicate session ids")
    if not result and not allow_empty:
        raise ValueError(f"{field} may not be empty")
    return result


def load_frozen_contract(
    metrics_path: str | Path,
    *,
    expected_security_mode: str | None = None,
) -> FrozenDevelopmentContract:
    """Load and fail-close the existing hierarchical-r2 development split."""

    path = Path(metrics_path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read frozen development contract: {path}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") not in SUPPORTED_CONTRACT_SCHEMAS:
        raise ValueError("unsupported hierarchical metrics contract")
    if raw.get("deployment_eligible") is not False:
        raise ValueError("frozen contract must be non-deployable")
    if raw.get("independent_final_test") is not False:
        raise ValueError("frozen contract must not claim an independent final test")
    if raw.get("test_metrics") is not None or raw.get("test_prediction_passes") != 0:
        raise ValueError("frozen contract has already evaluated the historical test")
    security_mode = raw.get("security_mode")
    if security_mode not in {"permissive", "enforce"}:
        raise ValueError("frozen contract security_mode is invalid")
    if expected_security_mode is not None and security_mode != expected_security_mode:
        raise ValueError("frozen contract security_mode does not match the request")

    protocol = raw.get("validation_protocol")
    if not isinstance(protocol, dict) or protocol.get("pairwise_overlap") != 0:
        raise ValueError("frozen validation protocol is missing or overlapping")
    selection = _string_set(protocol.get("selection_groups"), "selection_groups")
    calibration = _string_set(protocol.get("calibration_groups"), "calibration_groups")
    threshold = _string_set(protocol.get("threshold_groups"), "threshold_groups")
    if not (
        selection.isdisjoint(calibration)
        and selection.isdisjoint(threshold)
        and calibration.isdisjoint(threshold)
    ):
        raise ValueError("frozen validation session groups overlap")

    novelty = raw.get("novelty_protocol")
    if not isinstance(novelty, dict):
        raise ValueError("frozen novelty protocol is missing")
    holdout = _string_set(novelty.get("holdout_labels"), "holdout_labels")
    for field in (
        "supervised_train_rows_used",
        "selection_rows_used",
        "calibration_rows_used",
        "threshold_rows_used",
    ):
        if novelty.get(field) != 0:
            raise ValueError(f"novelty leakage recorded in {field}")

    excluded = _string_set(
        raw.get("applicable_excluded_sessions"),
        "applicable_excluded_sessions",
        allow_empty=True,
    )
    rows = raw.get("rows_after_exclusion")
    sessions = raw.get("sessions_after_exclusion")
    if not isinstance(rows, int) or isinstance(rows, bool) or rows <= 0:
        raise ValueError("rows_after_exclusion must be a positive integer")
    if not isinstance(sessions, int) or isinstance(sessions, bool) or sessions <= 0:
        raise ValueError("sessions_after_exclusion must be a positive integer")
    availability = normalize_source_availability(raw.get("source_availability", {}))
    return FrozenDevelopmentContract(
        path=path,
        sha256=_sha256_file(path),
        schema_version=str(raw["schema_version"]),
        security_mode=security_mode,
        selection_groups=selection,
        calibration_groups=calibration,
        threshold_groups=threshold,
        novelty_holdout_labels=holdout,
        excluded_sessions=excluded,
        expected_rows_after_exclusion=rows,
        expected_sessions_after_exclusion=sessions,
        source_availability=availability,
    )


def feature_set_columns() -> dict[str, tuple[str, ...]]:
    """Return the fixed ablation definitions used by every estimator."""

    network = tuple(FEATURES)
    telemetry = tuple(name for name in RAW_FEATURES if name not in network)
    masks = tuple(SOURCE_MASK_FEATURES)
    result = {
        # Strictly the observed values at t; no mask and no historical context.
        "current_only": tuple(RAW_FEATURES),
        "network": network,
        # Telemetry includes availability masks so unavailable is not silently
        # interpreted as a trustworthy measured zero.
        "telemetry": telemetry + masks,
        "fusion": tuple(RAW_FEATURES) + masks,
        "causal_temporal": tuple(EXPANDED_FEATURES),
    }
    if tuple(result) != FEATURE_SET_NAMES:
        raise RuntimeError("feature ablation order drifted")
    expanded = set(EXPANDED_FEATURES)
    for name, columns in result.items():
        if not columns or len(columns) != len(set(columns)):
            raise RuntimeError(f"invalid {name} feature definition")
        if not set(columns) <= expanded:
            raise RuntimeError(f"unknown feature in {name} definition")
    return result


def feature_set_indices() -> dict[str, tuple[int, ...]]:
    positions = {name: index for index, name in enumerate(EXPANDED_FEATURES)}
    return {
        name: tuple(positions[column] for column in columns)
        for name, columns in feature_set_columns().items()
    }


def _metadata_pass(
    feature_csv: Path,
    contract: FrozenDevelopmentContract,
) -> tuple[dict[str, dict[str, set[str]]], dict[str, int]]:
    required = {
        "session_id",
        "group_id",
        "split",
        "label",
        "security_mode",
        "source",
        "window",
        *RAW_FEATURES,
    }
    groups: dict[str, dict[str, set[str]]] = {}
    counters = {
        "rows_seen": 0,
        "rows_after_exclusion": 0,
        "test_rows_seen_metadata_only": 0,
    }
    try:
        handle = feature_csv.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise ValueError(f"cannot read feature CSV: {feature_csv}") from exc
    with handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"feature CSV columns are missing: {sorted(missing)}")
        for row in reader:
            counters["rows_seen"] += 1
            group = str(row["group_id"])
            session = str(row["session_id"])
            split = str(row["split"])
            mode = str(row["security_mode"])
            if not group or not session:
                raise ValueError("session_id and group_id may not be empty")
            if split not in {"train", "validation", "test"}:
                raise ValueError(f"invalid split {split!r}")
            if mode != contract.security_mode:
                raise ValueError("feature CSV contains a different security mode")
            if session in contract.excluded_sessions:
                continue
            counters["rows_after_exclusion"] += 1
            item = groups.setdefault(
                group,
                {"splits": set(), "labels": set(), "sessions": set()},
            )
            item["splits"].add(split)
            item["sessions"].add(session)
            if split == "test":
                # Do not access the test label or any test feature column.
                counters["test_rows_seen_metadata_only"] += 1
                continue
            item["labels"].add(str(row["label"]))
    return groups, counters


def load_development_frame(
    feature_csv: str | Path,
    contract: FrozenDevelopmentContract,
):
    """Load train plus frozen validation rows without materialising test values.

    A first pass accesses only split/session metadata.  On the second pass a
    row is rejected before any numeric feature is accessed when it belongs to
    the historical test.  This makes ``test_not_read`` an auditable property:
    the CSV reader tokenizes the physical row, but evaluation code never
    accesses a test label/feature field, converts it, places it in the returned
    frame, or passes it to an estimator.
    """

    import pandas as pd

    path = Path(feature_csv)
    groups, counters = _metadata_pass(path, contract)
    if counters["rows_after_exclusion"] != contract.expected_rows_after_exclusion:
        raise ValueError("feature CSV row count no longer matches frozen r2 contract")
    if len(groups) != contract.expected_sessions_after_exclusion:
        raise ValueError("feature CSV session count no longer matches frozen r2 contract")
    for group, metadata in groups.items():
        if len(metadata["splits"]) != 1:
            raise ValueError(f"session leakage across splits: {group}")

    holdout_groups = {
        group
        for group, metadata in groups.items()
        if metadata["labels"] & contract.novelty_holdout_labels
    }
    phase_by_group = contract.phase_by_group
    if contract.development_groups & holdout_groups:
        raise ValueError("frozen development groups include a novelty holdout")
    actual_known_validation = {
        group
        for group, metadata in groups.items()
        if metadata["splits"] == {"validation"} and group not in holdout_groups
    }
    if actual_known_validation != contract.development_groups:
        missing = sorted(contract.development_groups - actual_known_validation)
        extra = sorted(actual_known_validation - contract.development_groups)
        raise ValueError(
            "validation sessions differ from frozen r2 contract; "
            f"missing={missing}, extra={extra}"
        )
    train_groups = {
        group
        for group, metadata in groups.items()
        if metadata["splits"] == {"train"} and group not in holdout_groups
    }
    if not train_groups:
        raise ValueError("no supervised train sessions remain")
    allowed_groups = train_groups | set(contract.development_groups)

    records: list[dict[str, Any]] = []
    test_rows_loaded = 0
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            # This guard intentionally precedes every RAW_FEATURES access.
            if str(row["split"]) == "test":
                continue
            session = str(row["session_id"])
            group = str(row["group_id"])
            if session in contract.excluded_sessions or group not in allowed_groups:
                continue
            split = str(row["split"])
            phase = "train" if split == "train" else phase_by_group.get(group)
            if phase not in PHASE_NAMES:
                raise ValueError(f"row is outside the frozen phase contract: {group}")
            record: dict[str, Any] = {
                "session_id": session,
                "group_id": group,
                "source": str(row["source"]),
                "window": _finite_float(row["window"], "window"),
                "security_mode": str(row["security_mode"]),
                "split": split,
                "phase": phase,
                "label": str(row["label"]),
            }
            for feature in RAW_FEATURES:
                record[feature] = _finite_float(row[feature], feature)
            records.append(record)
    if test_rows_loaded:
        raise RuntimeError("historical test values entered the development frame")
    frame = pd.DataFrame.from_records(records)
    if frame.empty:
        raise ValueError("development frame is empty")
    observed_phases = set(frame["phase"].astype(str))
    if observed_phases != set(PHASE_NAMES):
        raise ValueError(f"development phases are incomplete: {sorted(observed_phases)}")
    if set(frame["group_id"].astype(str)) & {
        group
        for group, metadata in groups.items()
        if metadata["splits"] == {"test"}
    }:
        raise RuntimeError("test session entered the development frame")
    phase_group_ids = {
        phase: sorted(
            set(
                frame.loc[
                    frame["phase"].astype(str).eq(phase), "group_id"
                ].astype(str)
            )
        )
        for phase in PHASE_NAMES
    }
    audit = {
        "test_not_read": True,
        "test_definition": (
            "test split/session metadata inspected only to prove exclusion; "
            "the CSV reader tokenizes mixed-file rows, but zero test label or "
            "feature fields are accessed, converted, returned or predicted"
        ),
        "test_rows_seen_metadata_only": counters["test_rows_seen_metadata_only"],
        "test_rows_loaded": 0,
        "test_label_or_feature_fields_accessed": 0,
        "test_feature_numeric_conversions": 0,
        "test_rows_predicted": 0,
        "train_sessions": len(train_groups),
        "novelty_holdout_sessions_excluded": len(holdout_groups),
        "development_sessions": len(contract.development_groups),
        "rows_loaded": len(frame),
        "phase_rows": {
            phase: int(frame["phase"].astype(str).eq(phase).sum())
            for phase in PHASE_NAMES
        },
        "phase_sessions": {
            phase: len(phase_group_ids[phase]) for phase in PHASE_NAMES
        },
        "phase_group_ids": phase_group_ids,
        "phase_group_ids_sha256": {
            phase: hashlib.sha256(
                json.dumps(
                    phase_group_ids[phase],
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            for phase in PHASE_NAMES
        },
    }
    return frame, audit


def _finite_float(value: Any, name: str) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(numeric):
        raise ValueError(f"{name} must be finite")
    return numeric


def build_candidates(*, seed: int, n_estimators: int) -> dict[str, Any]:
    """Construct fixed, CPU-bounded candidates for a fair comparison."""

    from sklearn.dummy import DummyClassifier
    from sklearn.ensemble import (
        ExtraTreesClassifier,
        HistGradientBoostingClassifier,
        RandomForestClassifier,
    )
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    if not isinstance(n_estimators, int) or isinstance(n_estimators, bool):
        raise ValueError("n_estimators must be an integer")
    if not 20 <= n_estimators <= 500:
        raise ValueError("n_estimators must be in 20..500")
    candidates = {
        "dummy_prior": DummyClassifier(strategy="prior", random_state=seed),
        "logistic_balanced": Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        class_weight="balanced",
                        max_iter=2000,
                        random_state=seed,
                    ),
                ),
            ]
        ),
        "random_forest_balanced": RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=16,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight="balanced_subsample",
            random_state=seed,
            n_jobs=MAX_TRAINING_JOBS,
        ),
        "extra_trees_balanced": ExtraTreesClassifier(
            n_estimators=n_estimators,
            max_depth=16,
            min_samples_leaf=2,
            max_features=0.7,
            class_weight="balanced",
            random_state=seed,
            n_jobs=MAX_TRAINING_JOBS,
        ),
        "hist_gradient_boosting_balanced": HistGradientBoostingClassifier(
            learning_rate=0.08,
            max_iter=max(80, n_estimators),
            max_leaf_nodes=31,
            min_samples_leaf=10,
            l2_regularization=0.1,
            class_weight="balanced",
            random_state=seed,
        ),
    }
    if tuple(candidates) != MODEL_NAMES:
        raise RuntimeError("candidate registry order drifted")
    return candidates


def _fit_estimator(estimator: Any, x, y, weights):
    from sklearn.pipeline import Pipeline

    if isinstance(estimator, Pipeline):
        estimator.fit(x, y, classifier__sample_weight=weights)
    else:
        estimator.fit(x, y, sample_weight=weights)
    return estimator


def _calibrate_estimator(estimator: Any, x, y, sample_weight):
    import numpy as np
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.frozen import FrozenEstimator

    _, class_counts = np.unique(np.asarray(y, dtype=str), return_counts=True)
    if not len(class_counts) or int(class_counts.min()) < 2:
        raise ValueError("calibration requires at least two rows per class")
    folds = min(5, int(class_counts.min()))
    calibrated = CalibratedClassifierCV(
        FrozenEstimator(estimator), method="sigmoid", cv=folds, n_jobs=1
    )
    # FrozenEstimator is intentionally not refitted.  sklearn warns that its
    # wrapper does not accept sample_weight even though those weights are
    # correctly consumed by the sigmoid calibrator.  Suppress only that exact
    # misleading warning and keep every other warning visible.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=(
                "Since FrozenEstimator does not appear to accept sample_weight, "
                "sample weights will only be used for the calibration itself.*"
            ),
            category=UserWarning,
        )
        calibrated.fit(x, y, sample_weight=sample_weight)
    return calibrated


def task_targets(frame, task: str):
    import numpy as np

    if task not in TASK_NAMES:
        raise ValueError(f"unsupported task: {task}")
    labels = frame["label"].astype(str).to_numpy()
    if task == "binary":
        target = np.where(labels == "normal", "normal", "attack")
        eligible = np.ones(len(frame), dtype=bool)
    elif task == "family":
        target = np.asarray([family_for_label(label) for label in labels], dtype=str)
        eligible = labels != "normal"
    else:
        target = labels
        eligible = labels != "normal"
    return target, eligible


def probability_metrics(
    y_true: Sequence[str],
    probability,
    classes: Sequence[str],
    *,
    ece_bins: int = 10,
    sample_weight=None,
) -> dict[str, Any]:
    """Compute discrimination and calibration metrics from probabilities."""

    import numpy as np
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        balanced_accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
    )

    if not isinstance(ece_bins, int) or isinstance(ece_bins, bool) or ece_bins < 2:
        raise ValueError("ece_bins must be an integer >= 2")
    y = np.asarray(y_true, dtype=str)
    matrix = np.asarray(probability, dtype=float)
    labels = [str(value) for value in classes]
    if not len(y) or matrix.shape != (len(y), len(labels)):
        raise ValueError("probability matrix shape does not match labels")
    if len(labels) < 2 or len(labels) != len(set(labels)):
        raise ValueError("classes must contain at least two unique labels")
    if not np.isfinite(matrix).all() or (matrix < 0.0).any() or (matrix > 1.0).any():
        raise ValueError("probabilities must be finite and in 0..1")
    if not np.allclose(matrix.sum(axis=1), 1.0, atol=1e-6):
        raise ValueError("probability rows must sum to one")
    if not set(y) <= set(labels):
        raise ValueError("y_true contains a class absent from probability columns")
    if sample_weight is None:
        weights = np.ones(len(y), dtype=float)
        weighting = "uniform_rows"
    else:
        weights = np.asarray(sample_weight, dtype=float)
        if (
            weights.shape != (len(y),)
            or not np.isfinite(weights).all()
            or (weights <= 0.0).any()
        ):
            raise ValueError("sample_weight must be finite, positive and row-aligned")
        weighting = "provided_sample_weight"

    predicted = np.asarray(labels, dtype=object)[np.argmax(matrix, axis=1)]
    precision, recall, f1, support = precision_recall_fscore_support(
        y,
        predicted,
        labels=labels,
        zero_division=0,
        sample_weight=weights,
    )
    one_hot = np.column_stack([(y == label).astype(float) for label in labels])
    per_class: dict[str, dict[str, Any]] = {}
    valid_ap: list[float] = []
    for index, label in enumerate(labels):
        positives = one_hot[:, index]
        if 0 < int(positives.sum()) < len(positives):
            pr_auc = float(
                average_precision_score(
                    positives, matrix[:, index], sample_weight=weights
                )
            )
            valid_ap.append(pr_auc)
        else:
            pr_auc = None
        per_class[label] = {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": float(support[index]),
            "raw_support": int((y == label).sum()),
            "pr_auc": pr_auc,
        }

    confidence = matrix.max(axis=1)
    correct = (predicted == y).astype(float)
    ece = 0.0
    bin_edges = np.linspace(0.0, 1.0, ece_bins + 1)
    for bin_index in range(ece_bins):
        lower = bin_edges[bin_index]
        upper = bin_edges[bin_index + 1]
        in_bin = (confidence >= lower) & (
            confidence <= upper if bin_index == ece_bins - 1 else confidence < upper
        )
        if in_bin.any():
            bin_weight = weights[in_bin]
            ece += float(bin_weight.sum() / weights.sum()) * abs(
                float(np.average(correct[in_bin], weights=bin_weight))
                - float(np.average(confidence[in_bin], weights=bin_weight))
            )
    if set(labels) == {"normal", "attack"}:
        attack_index = labels.index("attack")
        brier = float(
            np.average(
                (matrix[:, attack_index] - (y == "attack")) ** 2,
                weights=weights,
            )
        )
        brier_definition = "binary_attack_probability_mean_squared_error"
    else:
        brier = float(
            np.average(np.sum((matrix - one_hot) ** 2, axis=1), weights=weights)
        )
        brier_definition = "multiclass_sum_squared_probability_error"
    all_classes_observed = set(y) == set(labels)
    balanced_accuracy = (
        float(balanced_accuracy_score(y, predicted, sample_weight=weights))
        if all_classes_observed
        else None
    )
    return {
        "rows": int(len(y)),
        "weighting": weighting,
        "weight_sum": float(weights.sum()),
        "all_classes_observed": all_classes_observed,
        "accuracy": float(accuracy_score(y, predicted, sample_weight=weights)),
        "balanced_accuracy": balanced_accuracy,
        "macro_f1": float(
            f1_score(
                y,
                predicted,
                labels=labels,
                average="macro",
                zero_division=0,
                sample_weight=weights,
            )
        ),
        "pr_auc_macro_ovr": float(sum(valid_ap) / len(valid_ap)) if valid_ap else None,
        "ece": float(ece),
        "ece_bins": ece_bins,
        "brier_score": brier,
        "brier_definition": brier_definition,
        "per_class": per_class,
        "confusion_matrix_raw": confusion_matrix(
            y, predicted, labels=labels
        ).tolist(),
        "confusion_matrix_weighted": confusion_matrix(
            y, predicted, labels=labels, sample_weight=weights
        ).tolist(),
    }


def _bootstrap_scalar_values(metrics: Mapping[str, Any]) -> dict[str, float]:
    values: dict[str, float] = {}
    names = ["ece", "brier_score"]
    if metrics.get("all_classes_observed") is True:
        names.extend(
            ["accuracy", "balanced_accuracy", "macro_f1", "pr_auc_macro_ovr"]
        )
    for name in names:
        value = metrics.get(name)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
            values[name] = float(value)
    per_class = metrics.get("per_class", {})
    if isinstance(per_class, Mapping):
        for label, class_metrics in per_class.items():
            if not isinstance(class_metrics, Mapping):
                continue
            if class_metrics.get("raw_support") == 0:
                continue
            for name in ("precision", "recall", "f1", "pr_auc"):
                value = class_metrics.get(name)
                if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
                    values[f"per_class.{label}.{name}"] = float(value)
    return values


def session_bootstrap_confidence_intervals(
    y_true: Sequence[str],
    probability,
    classes: Sequence[str],
    session_ids: Sequence[str],
    *,
    replicates: int = 500,
    confidence: float = 0.95,
    seed: int = 20260817,
    ece_bins: int = 10,
) -> dict[str, Any]:
    """Percentile CI from resampling whole sessions with replacement."""

    import numpy as np

    if not isinstance(replicates, int) or isinstance(replicates, bool) or replicates < 20:
        raise ValueError("bootstrap replicates must be an integer >= 20")
    if not 0.5 < float(confidence) < 1.0:
        raise ValueError("confidence must be in (0.5, 1.0)")
    y = np.asarray(y_true, dtype=str)
    matrix = np.asarray(probability, dtype=float)
    sessions = np.asarray(session_ids, dtype=str)
    if len(sessions) != len(y) or not len(y):
        raise ValueError("session_ids must align with non-empty y_true")
    unique_sessions = np.asarray(sorted(set(sessions)), dtype=object)
    if len(unique_sessions) < 2:
        raise ValueError("session bootstrap requires at least two sessions")
    indices_by_session = {
        session: np.flatnonzero(sessions == session)
        for session in unique_sessions
    }
    rng = np.random.default_rng(seed)
    samples: dict[str, list[float]] = {}
    for _ in range(replicates):
        chosen = rng.choice(unique_sessions, size=len(unique_sessions), replace=True)
        pieces = [indices_by_session[str(session)] for session in chosen]
        index = np.concatenate(pieces)
        # Each sampled session occurrence contributes total weight 1, even if
        # sessions contain different numbers of windows.
        bootstrap_weights = np.concatenate(
            [np.full(len(piece), 1.0 / len(piece), dtype=float) for piece in pieces]
        )
        metrics = probability_metrics(
            y[index],
            matrix[index],
            classes,
            ece_bins=ece_bins,
            sample_weight=bootstrap_weights,
        )
        for name, value in _bootstrap_scalar_values(metrics).items():
            samples.setdefault(name, []).append(value)
    alpha = (1.0 - float(confidence)) / 2.0
    intervals: dict[str, Any] = {}
    for name, values in sorted(samples.items()):
        array = np.asarray(values, dtype=float)
        intervals[name] = {
            "lower": float(np.quantile(array, alpha)),
            "upper": float(np.quantile(array, 1.0 - alpha)),
            "valid_replicates": int(len(array)),
        }
    return {
        "method": "session_cluster_percentile_bootstrap",
        "confidence": float(confidence),
        "replicates_requested": replicates,
        "sessions": int(len(unique_sessions)),
        "intervals": intervals,
    }


def _process_rss_bytes() -> int | None:
    try:
        import psutil

        return int(psutil.Process(os.getpid()).memory_info().rss)
    except (ImportError, OSError, ValueError):
        return None


def _rss_delta(before: int | None, after: int | None) -> int | None:
    if before is None or after is None:
        return None
    return max(0, int(after) - int(before))


def _percentiles_ms(samples_ns: Sequence[int]) -> dict[str, float]:
    import numpy as np

    values = np.asarray(samples_ns, dtype=float) / 1_000_000.0
    return {
        "p50": float(np.percentile(values, 50)),
        "p95": float(np.percentile(values, 95)),
    }


def measure_inference_cost(
    estimator: Any,
    matrix,
    *,
    single_iterations: int = 200,
    batch_iterations: int = 40,
    batch_size: int = 64,
    clock_ns: Callable[[], int] = time.perf_counter_ns,
    rss_reader: Callable[[], int | None] = _process_rss_bytes,
) -> dict[str, Any]:
    """Measure warmed predict_proba latency and observed process RSS delta."""

    import numpy as np

    x = np.asarray(matrix, dtype=float)
    if x.ndim != 2 or not len(x):
        raise ValueError("latency matrix must be a non-empty 2-D array")
    for name, value in (
        ("single_iterations", single_iterations),
        ("batch_iterations", batch_iterations),
        ("batch_size", batch_size),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    actual_batch = min(batch_size, len(x))
    batch = x[:actual_batch]
    estimator.predict_proba(x[:1])
    estimator.predict_proba(batch)
    rss_before = rss_reader()
    single_samples: list[int] = []
    for index in range(single_iterations):
        row = x[index % len(x) : index % len(x) + 1]
        started = clock_ns()
        estimator.predict_proba(row)
        single_samples.append(clock_ns() - started)
    batch_samples: list[int] = []
    for _ in range(batch_iterations):
        started = clock_ns()
        estimator.predict_proba(batch)
        batch_samples.append(clock_ns() - started)
    rss_after = rss_reader()
    batch_ms = _percentiles_ms(batch_samples)
    return {
        "single_sample_ms": _percentiles_ms(single_samples),
        "batch_call_ms": batch_ms,
        "batch_per_row_ms": {
            name: value / actual_batch for name, value in batch_ms.items()
        },
        "single_iterations": single_iterations,
        "batch_iterations": batch_iterations,
        "batch_size": actual_batch,
        "observed_inference_rss_delta_bytes": _rss_delta(rss_before, rss_after),
        "rss_is_peak_measurement": False,
    }


def _stable_seed(base: int, *parts: str) -> int:
    payload = ":".join((str(base), *parts)).encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest()[:4], "big")


def software_versions() -> dict[str, str | None]:
    import numpy
    import pandas
    import sklearn

    try:
        import psutil

        psutil_version: str | None = str(psutil.__version__)
    except ImportError:
        psutil_version = None
    return {
        "python": sys.version.split()[0],
        "numpy": str(numpy.__version__),
        "pandas": str(pandas.__version__),
        "scikit_learn": str(sklearn.__version__),
        "psutil": psutil_version,
    }


def _phase_index(frame, eligible, phase: str):
    import numpy as np

    mask = frame["phase"].astype(str).eq(phase).to_numpy() & eligible
    return np.flatnonzero(mask)


def _predict_probability(estimator: Any, x) -> tuple[list[str], Any]:
    import numpy as np

    classes = [str(value) for value in estimator.classes_]
    matrix = np.asarray(estimator.predict_proba(x), dtype=float)
    if matrix.shape != (len(x), len(classes)) or not np.isfinite(matrix).all():
        raise RuntimeError("estimator emitted invalid probabilities")
    return classes, matrix


def _validate_task_phases(frame, target, eligible, task: str) -> None:
    train_classes: set[str] | None = None
    phase_groups: list[set[str]] = []
    for phase in PHASE_NAMES:
        index = _phase_index(frame, eligible, phase)
        if not len(index):
            raise ValueError(f"{task} {phase} rows are empty")
        classes = set(str(value) for value in target[index])
        if phase == "train":
            train_classes = classes
            if len(classes) < 2:
                raise ValueError(f"{task} train requires at least two classes")
        elif classes != train_classes:
            raise ValueError(
                f"{task} {phase} classes differ from frozen train classes"
            )
        phase_groups.append(set(frame.iloc[index]["group_id"].astype(str)))
    for left in range(len(phase_groups)):
        for right in range(left + 1, len(phase_groups)):
            if phase_groups[left] & phase_groups[right]:
                raise RuntimeError(f"{task} sessions overlap across phases")


def evaluate_development_contract(
    feature_csv: str | Path,
    contract_metrics: str | Path,
    output_dir: str | Path,
    *,
    security_mode: str,
    tasks: Sequence[str] = TASK_NAMES,
    feature_sets: Sequence[str] = FEATURE_SET_NAMES,
    models: Sequence[str] = MODEL_NAMES,
    bootstrap_replicates: int = 500,
    confidence: float = 0.95,
    ece_bins: int = 10,
    n_estimators: int = 120,
    latency_single_iterations: int = 200,
    latency_batch_iterations: int = 40,
    latency_batch_size: int = 64,
    random_state: int = 20260817,
) -> dict[str, Any]:
    """Run a non-deployable fair benchmark and write a new result directory."""

    output = Path(output_dir)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite evaluation directory: {output}")
    task_order = _validate_requested_names(tasks, TASK_NAMES, "task")
    feature_order = _validate_requested_names(
        feature_sets, FEATURE_SET_NAMES, "feature set"
    )
    model_order = _validate_requested_names(models, MODEL_NAMES, "model")
    contract = load_frozen_contract(
        contract_metrics, expected_security_mode=security_mode
    )
    frame, test_audit = load_development_frame(feature_csv, contract)
    expanded = _expanded_matrix(frame, contract.source_availability)
    ablations = feature_set_indices()
    results: list[dict[str, Any]] = []

    for task in task_order:
        target, eligible = task_targets(frame, task)
        _validate_task_phases(frame, target, eligible, task)
        phase_index = {
            phase: _phase_index(frame, eligible, phase) for phase in PHASE_NAMES
        }
        train_index = phase_index["train"]
        train_weights = _session_equal_weights(frame, train_index)
        for feature_name in feature_order:
            columns = ablations[feature_name]
            matrix = expanded[:, columns]
            for model_name in model_order:
                seed = _stable_seed(random_state, task, feature_name, model_name)
                estimator = build_candidates(
                    seed=seed, n_estimators=n_estimators
                )[model_name]
                gc.collect()
                rss_before_fit = _process_rss_bytes()
                started = time.perf_counter_ns()
                estimator = _fit_estimator(
                    estimator,
                    matrix[train_index],
                    target[train_index],
                    train_weights,
                )
                fit_ms = (time.perf_counter_ns() - started) / 1_000_000.0
                rss_after_fit = _process_rss_bytes()

                selection_index = phase_index["selection"]
                selection_classes, selection_probability = _predict_probability(
                    estimator, matrix[selection_index]
                )
                selection_metrics = probability_metrics(
                    target[selection_index],
                    selection_probability,
                    selection_classes,
                    ece_bins=ece_bins,
                    sample_weight=_session_equal_weights(frame, selection_index),
                )

                calibration_index = phase_index["calibration"]
                calibrated = _calibrate_estimator(
                    estimator,
                    matrix[calibration_index],
                    target[calibration_index],
                    _session_equal_weights(frame, calibration_index),
                )
                threshold_index = phase_index["threshold"]
                classes, probability = _predict_probability(
                    calibrated, matrix[threshold_index]
                )
                threshold_metrics = probability_metrics(
                    target[threshold_index],
                    probability,
                    classes,
                    ece_bins=ece_bins,
                    sample_weight=_session_equal_weights(frame, threshold_index),
                )
                bootstrap = session_bootstrap_confidence_intervals(
                    target[threshold_index],
                    probability,
                    classes,
                    frame.iloc[threshold_index]["group_id"].astype(str).to_numpy(),
                    replicates=bootstrap_replicates,
                    confidence=confidence,
                    seed=_stable_seed(seed, "bootstrap"),
                    ece_bins=ece_bins,
                )
                latency = measure_inference_cost(
                    calibrated,
                    matrix[threshold_index],
                    single_iterations=latency_single_iterations,
                    batch_iterations=latency_batch_iterations,
                    batch_size=latency_batch_size,
                )
                results.append(
                    {
                        "task": task,
                        "feature_set": feature_name,
                        "feature_count": len(columns),
                        "model": model_name,
                        "seed": seed,
                        "fit_ms": float(fit_ms),
                        "observed_fit_rss_delta_bytes": _rss_delta(
                            rss_before_fit, rss_after_fit
                        ),
                        "selection_uncalibrated": selection_metrics,
                        "threshold_calibrated": threshold_metrics,
                        "threshold_session_bootstrap_ci95": bootstrap,
                        "inference_cost": latency,
                    }
                )

    document: dict[str, Any] = {
        "schema_version": DEVELOPMENT_EVALUATION_SCHEMA,
        "created_utc": utc_now(),
        "development_only": True,
        "deployment": False,
        "deployment_eligible": False,
        "executable": False,
        "test_not_read": True,
        "test_prediction_passes": 0,
        "independent_final_test": False,
        "security_mode": security_mode,
        "implementation": {
            "path": str(Path(__file__)),
            "sha256": _sha256_file(Path(__file__)),
            "software_versions": software_versions(),
        },
        "feature_source": {
            "path": str(Path(feature_csv)),
            "full_file_sha256_computed": False,
            "reason": (
                "the mixed-split CSV is matched to the frozen contract by exact "
                "post-exclusion row/session counts; no full-file digest is used "
                "as a substitute for test isolation"
            ),
        },
        "frozen_contract": {
            "path": str(contract.path),
            "sha256": contract.sha256,
            "schema_version": contract.schema_version,
            "selection_groups": sorted(contract.selection_groups),
            "calibration_groups": sorted(contract.calibration_groups),
            "threshold_groups": sorted(contract.threshold_groups),
            "pairwise_overlap": 0,
            "novelty_holdout_labels": sorted(contract.novelty_holdout_labels),
            "excluded_sessions": sorted(contract.excluded_sessions),
        },
        "data_audit": test_audit,
        "protocol": {
            "fit": "frozen train sessions with session-equal sample weights",
            "comparison": "frozen selection sessions; no candidate auto-selected",
            "calibration": (
                "sigmoid calibration on frozen calibration sessions with "
                "session-equal sample weights"
            ),
            "development_estimate": (
                "frozen threshold sessions with session-equal point metrics"
            ),
            "confidence_interval": "session-cluster percentile bootstrap",
            "feature_sets": {
                name: list(feature_set_columns()[name]) for name in feature_order
            },
            "tasks": list(task_order),
            "models": list(model_order),
            "bootstrap_replicates": bootstrap_replicates,
            "confidence": confidence,
            "ece_bins": ece_bins,
            "rss_definition": (
                "non-negative observed process RSS delta; not an isolated peak "
                "and may be affected by allocator reuse"
            ),
            "matches_2026_campaign_default_source_profile": (
                dict(contract.source_availability)
                == dict(DEFAULT_LIVE_SOURCE_AVAILABILITY)
            ),
        },
        "results": results,
        "limitations": [
            "historical test labels and feature values were not evaluated",
            "the historical test already informed earlier architecture decisions",
            "all reported scores are development validation, not final test scores",
            "RSS is an in-process observed delta rather than an isolated peak measurement",
            "latency is host-specific and is not Raspberry Pi 5 evidence",
            "no trusted attacker-IP attribution or live blocking outcome is established",
            "this evaluation cannot enable an adapter or backend",
        ],
    }
    # Validate the safety fields immediately before committing any output.
    if not (
        document["development_only"] is True
        and document["deployment"] is False
        and document["deployment_eligible"] is False
        and document["executable"] is False
        and document["test_not_read"] is True
        and document["test_prediction_passes"] == 0
    ):
        raise RuntimeError("development evaluation safety metadata drifted")
    output.mkdir(parents=True, exist_ok=False)
    result_path = output / "development_evaluation.json"
    atomic_write_json(result_path, document)
    readme_path = output / "README.md"
    with readme_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(_evaluation_readme(document))
    return {
        "result": str(result_path),
        "readme": str(readme_path),
        "development_only": True,
        "deployment": False,
        "test_not_read": True,
        "comparisons": len(results),
    }


def _validate_requested_names(
    requested: Sequence[str], allowed: Sequence[str], field: str
) -> tuple[str, ...]:
    if isinstance(requested, (str, bytes)):
        raise ValueError(f"{field} request must be a sequence")
    values = tuple(str(value) for value in requested)
    if not values or len(values) != len(set(values)):
        raise ValueError(f"{field} request is empty or duplicated")
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise ValueError(f"unknown {field}: {unknown}")
    return tuple(name for name in allowed if name in values)


def _evaluation_readme(document: Mapping[str, Any]) -> str:
    return "\n".join(
        [
            "# Development-only model evaluation",
            "",
            "- `development_only=true`",
            "- `deployment=false`",
            "- `test_not_read=true`",
            "- Historical test predictions: **0**",
            f"- Security mode: `{document['security_mode']}`",
            f"- Comparisons: {len(document['results'])}",
            "",
            "This directory contains model-selection research only. It is not a ",
            "final test, a Raspberry Pi benchmark, an IP-attribution result, or ",
            "authorization to execute a firewall response.",
            "",
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a frozen, development-only hierarchical model benchmark"
    )
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--contract-metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--security-mode", choices=("permissive", "enforce"), required=True
    )
    parser.add_argument("--task", action="append", choices=TASK_NAMES)
    parser.add_argument("--feature-set", action="append", choices=FEATURE_SET_NAMES)
    parser.add_argument("--model", action="append", choices=MODEL_NAMES)
    parser.add_argument("--bootstrap-replicates", type=int, default=500)
    parser.add_argument("--confidence", type=float, default=0.95)
    parser.add_argument("--ece-bins", type=int, default=10)
    parser.add_argument("--n-estimators", type=int, default=120)
    parser.add_argument("--latency-single-iterations", type=int, default=200)
    parser.add_argument("--latency-batch-iterations", type=int, default=40)
    parser.add_argument("--latency-batch-size", type=int, default=64)
    parser.add_argument("--seed", type=int, default=20260817)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = evaluate_development_contract(
        args.features,
        args.contract_metrics,
        args.output,
        security_mode=args.security_mode,
        tasks=args.task or TASK_NAMES,
        feature_sets=args.feature_set or FEATURE_SET_NAMES,
        models=args.model or MODEL_NAMES,
        bootstrap_replicates=args.bootstrap_replicates,
        confidence=args.confidence,
        ece_bins=args.ece_bins,
        n_estimators=args.n_estimators,
        latency_single_iterations=args.latency_single_iterations,
        latency_batch_iterations=args.latency_batch_iterations,
        latency_batch_size=args.latency_batch_size,
        random_state=args.seed,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
