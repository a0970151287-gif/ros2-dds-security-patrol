"""Validation-only training for the hierarchical SROS2 firewall candidate.

The current final test has already informed earlier model decisions, so this
trainer intentionally does not expose a final-test switch.  It creates an
authenticated, observe-only candidate from train and three disjoint validation
subsets: model selection, probability calibration and threshold selection.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from .hierarchical_model import (
    ARCHITECTURE_NAME,
    DEFAULT_LIVE_SOURCE_AVAILABILITY,
    EXPANDED_FEATURES,
    FAMILY_BY_LABEL,
    HIERARCHICAL_MODEL_SCHEMA,
    RAW_FEATURES,
    build_temporal_row,
    conditional_leaf_candidate,
    family_for_label,
    family_map_sha256,
    normalize_policy_sha256,
    normalize_source_availability,
)
from .ood_scorers import MahalanobisNoveltyDetector
from .schema import atomic_write_json, sha256_file, utc_now
from .train import ACTION_POLICY_PATH, ML_DIR, WORKSPACE_ROOT, load_training_frame

# 未知攻擊評分器。預設維持 isolation_forest，讓既有 artifact 逐位可重現；
# mahalanobis 是量測後的改良版，必須明示選用。
ATTACK_OOD_SCORERS = ("isolation_forest", "mahalanobis")


HIERARCHICAL_METRICS_SCHEMA = "sros2-firewall-hierarchical-metrics/v2"
EXCLUSION_SCHEMA = "sros2-firewall-dataset-exclusions/v1"
DEFAULT_EXCLUSIONS = Path(__file__).with_name("dataset_exclusions.v1.json")
DEFAULT_DATASET_ROOT = Path(__file__).with_name("dataset_live")
MAX_TRAINING_JOBS = 1


def _stable_order(value: str, seed: int) -> str:
    return hashlib.sha256(f"{seed}:{value}".encode("utf-8")).hexdigest()


def _file_size_and_sha256(path: Path) -> tuple[int, str]:
    return path.stat().st_size, sha256_file(path)


def _atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_basename(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ValueError(f"{field} is invalid")
    candidate = Path(value)
    if candidate.name != value or candidate.is_absolute():
        raise ValueError(f"{field} must be a safe basename")
    return value


def _ensure_output_outside_dataset(output_dir: str | Path, dataset_root: str | Path) -> None:
    output = Path(output_dir).resolve(strict=False)
    root = Path(dataset_root).resolve(strict=True)
    if output == root or root in output.parents:
        raise ValueError("output_dir must be outside the immutable dataset_root")


def load_verified_exclusions(
    registry_path: str | Path,
    dataset_root: str | Path,
) -> tuple[set[str], dict[str, Any]]:
    """Load the external registry only when every pinned mismatch still agrees."""

    path = Path(registry_path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read dataset exclusion registry: {path}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != EXCLUSION_SCHEMA:
        raise ValueError("unsupported dataset exclusion registry")
    campaign = value.get("campaign")
    if not isinstance(campaign, dict):
        raise ValueError("exclusion registry campaign pin is missing")
    campaign_path = WORKSPACE_ROOT / str(campaign.get("path", ""))
    expected_campaign_sha = campaign.get("sha256")
    if (
        not campaign_path.is_file()
        or not isinstance(expected_campaign_sha, str)
        or sha256_file(campaign_path) != expected_campaign_sha
    ):
        raise ValueError("campaign does not match the exclusion registry pin")
    try:
        campaign_value = json.loads(campaign_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("campaign pin is not readable JSON") from exc
    campaign_entries = campaign_value.get("entries") if isinstance(campaign_value, dict) else None
    if not isinstance(campaign_entries, list):
        raise ValueError("campaign pin has no entries list")
    campaign_by_session: dict[str, dict[str, Any]] = {}
    for campaign_entry in campaign_entries:
        if not isinstance(campaign_entry, dict):
            raise ValueError("campaign entry must be an object")
        campaign_session = _safe_basename(
            campaign_entry.get("session_id"), field="campaign session_id"
        )
        if campaign_session in campaign_by_session:
            raise ValueError("campaign contains duplicated session_id")
        campaign_by_session[campaign_session] = campaign_entry

    entries = value.get("exclusions")
    if not isinstance(entries, list) or not entries:
        raise ValueError("exclusion registry must contain at least one entry")

    root = Path(dataset_root)
    excluded: set[str] = set()
    verified_entries: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("exclusion entry must be an object")
        session_id = _safe_basename(entry.get("session_id"), field="exclusion session_id")
        if session_id in excluded:
            raise ValueError("exclusion session_id is invalid or duplicated")
        expected_split = entry.get("split")
        if expected_split not in {"train", "validation", "test"}:
            raise ValueError(f"exclusion split is invalid for {session_id}")
        campaign_entry = campaign_by_session.get(session_id)
        if campaign_entry is None:
            raise ValueError(f"excluded session is absent from campaign: {session_id}")
        if (
            campaign_entry.get("security_mode") != entry.get("security_mode")
            or campaign_entry.get("attack_class") != entry.get("attack_class")
            or campaign_entry.get("status") != "complete"
        ):
            raise ValueError(f"campaign identity mismatch for exclusion {session_id}")
        if entry.get("disposition") != (
            "exclude_from_training_calibration_selection_and_evaluation"
        ):
            raise ValueError("exclusion disposition is not fail-closed")
        session_dir = root / session_id
        manifest_path = session_dir / "manifest.json"
        manifest_pin = entry.get("manifest")
        artifact_pin = entry.get("artifact")
        if not isinstance(manifest_pin, dict) or not isinstance(artifact_pin, dict):
            raise ValueError(f"exclusion pins are missing for {session_id}")
        manifest_bytes, manifest_sha = _file_size_and_sha256(manifest_path)
        if (
            manifest_bytes != manifest_pin.get("bytes")
            or manifest_sha != manifest_pin.get("sha256")
        ):
            raise ValueError(f"manifest no longer matches exclusion pin: {session_id}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (
            manifest.get("session_id") != session_id
            or manifest.get("security_mode") != entry.get("security_mode")
            or manifest.get("attack_class") != entry.get("attack_class")
        ):
            raise ValueError(f"manifest identity mismatch for exclusion {session_id}")
        artifact_name = artifact_pin.get("path")
        if not isinstance(artifact_name, str) or Path(artifact_name).name != artifact_name:
            raise ValueError(f"unsafe artifact path in exclusion {session_id}")
        recorded = manifest.get("evidence", {}).get(artifact_name)
        if not isinstance(recorded, dict):
            raise ValueError(f"manifest evidence pin is absent for {session_id}")
        if (
            recorded.get("bytes") != artifact_pin.get("manifest_bytes")
            or recorded.get("sha256") != artifact_pin.get("manifest_sha256")
        ):
            raise ValueError(f"manifest evidence changed for exclusion {session_id}")
        artifact_path = session_dir / artifact_name
        observed_bytes, observed_sha = _file_size_and_sha256(artifact_path)
        if (
            observed_bytes != artifact_pin.get("observed_bytes")
            or observed_sha != artifact_pin.get("observed_sha256")
            or (
                observed_bytes == artifact_pin.get("manifest_bytes")
                and observed_sha == artifact_pin.get("manifest_sha256")
            )
        ):
            raise ValueError(f"artifact mismatch is not the pinned one: {session_id}")
        excluded.add(session_id)
        verified_entries.append(
            {
                "session_id": session_id,
                "security_mode": entry["security_mode"],
                "attack_class": entry["attack_class"],
                "split": expected_split,
                "reason": entry.get("reason"),
            }
        )
    return excluded, {
        "registry": str(path),
        "registry_sha256": sha256_file(path),
        "campaign": str(campaign_path),
        "campaign_sha256": expected_campaign_sha,
        "verified_entries": verified_entries,
    }


def _validate_split(frame) -> dict[str, Any]:
    import numpy as np

    if "split" not in frame.columns:
        raise ValueError("preassigned split column is required")
    if set(frame["split"].astype(str)) != {"train", "validation", "test"}:
        raise ValueError("split must contain exactly train, validation and test")
    group_splits = frame.groupby("group_id", sort=False)["split"].nunique()
    if int(group_splits.max()) != 1:
        raise ValueError("session leakage: one group_id occurs in multiple splits")
    unknown_labels = sorted(set(frame["label"].astype(str)) - set(FAMILY_BY_LABEL))
    if unknown_labels:
        raise ValueError(f"labels have no attack-family mapping: {unknown_labels}")
    result: dict[str, Any] = {}
    groups: dict[str, set[str]] = {}
    for split in ("train", "validation", "test"):
        mask = frame["split"].astype(str).eq(split).to_numpy()
        result[split] = np.flatnonzero(mask)
        groups[split] = set(frame.loc[mask, "group_id"].astype(str))
    if not (
        groups["train"].isdisjoint(groups["validation"])
        and groups["train"].isdisjoint(groups["test"])
        and groups["validation"].isdisjoint(groups["test"])
    ):
        raise ValueError("session leakage remains after split validation")
    result["groups"] = groups
    return result


def _resolve_holdout_labels(
    frame,
    requested: Sequence[str] | None,
) -> tuple[list[str], set[str]]:
    if requested:
        labels = sorted(set(str(value) for value in requested))
    elif "novelty_role" in frame.columns:
        labels = sorted(
            set(
                frame.loc[
                    frame["novelty_role"].astype(str).eq(
                        "novelty_holdout_candidate"
                    ),
                    "label",
                ].astype(str)
            )
        )
    else:
        raise ValueError("novelty holdout labels must be explicit")
    if not labels or "normal" in labels:
        raise ValueError("novelty holdout must contain attack labels only")
    missing = sorted(set(labels) - set(frame["label"].astype(str)))
    if missing:
        raise ValueError(f"novelty holdout labels are absent: {missing}")
    holdout_groups = set(
        frame.loc[frame["label"].astype(str).isin(labels), "group_id"].astype(str)
    )
    if not holdout_groups:
        raise ValueError("novelty holdout has no independent sessions")
    return labels, holdout_groups


def _validation_partitions(
    frame,
    *,
    allowed_groups: set[str],
    seed: int,
) -> dict[str, Any]:
    import numpy as np

    validation = frame[
        frame["split"].astype(str).eq("validation")
        & frame["group_id"].astype(str).isin(allowed_groups)
    ]
    signatures = (
        validation.groupby("group_id", sort=False)["label"]
        .agg(lambda values: tuple(sorted(set(str(value) for value in values))))
    )
    by_signature: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for group_id, signature in signatures.items():
        by_signature[signature].append(str(group_id))
    partitions = {"selection": set(), "calibration": set(), "threshold": set()}
    names = tuple(partitions)
    for signature, groups in sorted(by_signature.items()):
        ordered = sorted(groups, key=lambda value: _stable_order(value, seed))
        if len(ordered) < 3:
            raise ValueError(
                f"validation signature {signature!r} needs at least three sessions "
                "for independent selection/calibration/threshold subsets"
            )
        for offset, group_id in enumerate(ordered):
            partitions[names[offset % len(names)]].add(group_id)
    if any(not groups for groups in partitions.values()):
        raise ValueError("validation partitions may not be empty")
    result: dict[str, Any] = {"groups": partitions}
    group_values = frame["group_id"].astype(str)
    for name, groups in partitions.items():
        result[name] = np.flatnonzero(group_values.isin(groups).to_numpy())
    return result


def _session_equal_weights(frame, index) -> Any:
    import numpy as np

    groups = frame.iloc[index]["group_id"].astype(str)
    counts = groups.value_counts()
    weights = groups.map(lambda value: 1.0 / float(counts[value])).to_numpy(float)
    if not np.isfinite(weights).all() or not (weights > 0.0).all():
        raise ValueError("invalid session-equal sample weights")
    return weights / weights.mean()


def _expanded_matrix(
    frame,
    availability: Mapping[str, bool],
) -> Any:
    import numpy as np

    normalized = normalize_source_availability(availability)
    missing = (set(RAW_FEATURES) | {"group_id", "source", "window"}) - set(
        frame.columns
    )
    if missing:
        raise ValueError(f"temporal training columns are missing: {sorted(missing)}")
    windows = frame["window"].apply(lambda value: float(value)).to_numpy()
    if not np.isfinite(windows).all():
        raise ValueError("window values must be finite")
    expanded = np.empty((len(frame), len(EXPANDED_FEATURES)), dtype=float)
    filled = np.zeros(len(frame), dtype=bool)
    for _, index_values in frame.groupby(
        ["group_id", "source"], sort=False
    ).groups.items():
        ordered = sorted(index_values, key=lambda index: (windows[index], index))
        ordered_windows = [windows[index] for index in ordered]
        if len(ordered_windows) != len(set(ordered_windows)):
            raise ValueError(
                "(group_id, source, window) must be unique for causal features"
            )
        history: list[dict[str, float]] = []
        for index in ordered:
            raw = {
                name: float(frame.at[index, name]) for name in RAW_FEATURES
            }
            expanded[index] = build_temporal_row(
                raw,
                normalized,
                history=history[-2:],
            )
            filled[index] = True
            history.append(raw)
    if not bool(filled.all()) or not np.isfinite(expanded).all():
        raise RuntimeError("causal temporal feature construction was incomplete")
    return expanded


def _make_candidates(*, seed: int, n_estimators: int) -> dict[str, Any]:
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    return {
        "logistic_balanced": Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        class_weight="balanced",
                        max_iter=1500,
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
    }


def _fit_candidate(estimator, x, y, weights):
    from sklearn.pipeline import Pipeline

    if isinstance(estimator, Pipeline):
        estimator.fit(x, y, classifier__sample_weight=weights)
    else:
        estimator.fit(x, y, sample_weight=weights)
    return estimator


def _probability_for_class(estimator, x, label: str):
    import numpy as np

    classes = [str(value) for value in estimator.classes_]
    if label not in classes:
        raise ValueError(f"estimator has no probability for {label}")
    probability = np.asarray(estimator.predict_proba(x), dtype=float)
    if (
        probability.ndim != 2
        or probability.shape[1] != len(classes)
        or not np.isfinite(probability).all()
    ):
        raise RuntimeError("estimator emitted invalid probabilities")
    return probability[:, classes.index(label)]


def _classification_metrics(
    y_true,
    estimator,
    x,
    *,
    sample_weight=None,
) -> dict[str, float]:
    import numpy as np
    from sklearn.metrics import balanced_accuracy_score, f1_score

    probability = np.asarray(estimator.predict_proba(x), dtype=float)
    classes = np.asarray([str(value) for value in estimator.classes_], dtype=object)
    predicted = classes[np.argmax(probability, axis=1)]
    y = np.asarray(y_true, dtype=str)
    return {
        "balanced_accuracy": float(
            balanced_accuracy_score(y, predicted, sample_weight=sample_weight)
        ),
        "macro_f1": float(
            f1_score(
                y,
                predicted,
                average="macro",
                zero_division=0,
                sample_weight=sample_weight,
            )
        ),
    }


def _binary_metrics(y_true, estimator, x, *, sample_weight=None) -> dict[str, float]:
    import numpy as np
    from sklearn.metrics import average_precision_score, balanced_accuracy_score, f1_score

    y = np.asarray(y_true, dtype=str)
    score = _probability_for_class(estimator, x, "attack")
    predicted = np.where(score >= 0.5, "attack", "normal")
    normal = y == "normal"
    attack = y == "attack"
    return {
        "binary_pr_auc": float(
            average_precision_score(
                attack.astype(int), score, sample_weight=sample_weight
            )
        ),
        "balanced_accuracy": float(
            balanced_accuracy_score(y, predicted, sample_weight=sample_weight)
        ),
        "macro_f1": float(
            f1_score(
                y,
                predicted,
                average="macro",
                zero_division=0,
                sample_weight=sample_weight,
            )
        ),
        "attack_recall": _weighted_rate(
            predicted[attack] == "attack",
            None if sample_weight is None else sample_weight[attack],
        ),
        "normal_fpr": _weighted_rate(
            predicted[normal] == "attack",
            None if sample_weight is None else sample_weight[normal],
        ),
    }


def _select_estimator(
    *,
    task: str,
    train_x,
    train_y,
    train_weights,
    selection_x,
    selection_y,
    selection_weights,
    seed: int,
    n_estimators: int,
) -> tuple[str, Any, dict[str, dict[str, float]]]:
    comparisons: dict[str, dict[str, float]] = {}
    selected_name = ""
    selected = None
    selected_key: tuple[float, ...] | None = None
    for name, estimator in _make_candidates(seed=seed, n_estimators=n_estimators).items():
        estimator = _fit_candidate(estimator, train_x, train_y, train_weights)
        if task == "binary":
            metrics = _binary_metrics(
                selection_y,
                estimator,
                selection_x,
                sample_weight=selection_weights,
            )
            key = (
                metrics["binary_pr_auc"],
                metrics["balanced_accuracy"],
                metrics["macro_f1"],
            )
        else:
            metrics = _classification_metrics(
                selection_y,
                estimator,
                selection_x,
                sample_weight=selection_weights,
            )
            key = (metrics["macro_f1"], metrics["balanced_accuracy"])
        comparisons[name] = metrics
        if selected_key is None or key > selected_key:
            selected_name = name
            selected = estimator
            selected_key = key
    if selected is None:
        raise RuntimeError(f"no {task} candidate was fitted")
    return selected_name, selected, comparisons


def _calibrate(estimator, x, y, weights):
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.frozen import FrozenEstimator

    calibrated = CalibratedClassifierCV(
        FrozenEstimator(estimator), method="sigmoid", cv=None, n_jobs=1
    )
    calibrated.fit(x, y, sample_weight=weights)
    return calibrated


def _validated_weights(sample_weight, length: int):
    import numpy as np

    if sample_weight is None:
        return np.ones(length, dtype=float)
    weights = np.asarray(sample_weight, dtype=float)
    if weights.shape != (length,) or not np.isfinite(weights).all() or (weights <= 0).any():
        raise ValueError("sample_weight must be finite, positive and row-aligned")
    return weights


def _weighted_rate(mask, weights) -> float:
    import numpy as np

    values = np.asarray(mask, dtype=bool)
    if not len(values):
        return 0.0
    normalized = _validated_weights(weights, len(values))
    return float(normalized[values].sum() / normalized.sum())


def choose_binary_threshold(
    y_true,
    attack_probability,
    *,
    maximum_normal_fpr: float,
    minimum_attack_precision: float = 0.90,
    minimum_attack_recall: float = 0.85,
    sample_weight=None,
) -> dict[str, Any]:
    import numpy as np

    y = np.asarray(y_true, dtype=str)
    score = np.asarray(attack_probability, dtype=float)
    normal = y == "normal"
    attack = y == "attack"
    if not normal.any() or not attack.any():
        raise ValueError("binary threshold selection requires normal and attack rows")
    weights = _validated_weights(sample_weight, len(y))
    candidates = sorted({0.0, 1.0, *[float(value) for value in score]})
    feasible: list[dict[str, Any]] = []
    for threshold in candidates:
        predicted = score >= threshold
        positives = int(predicted.sum())
        precision = (
            float(weights[predicted & attack].sum() / weights[predicted].sum())
            if positives
            else 0.0
        )
        fpr = _weighted_rate(predicted[normal], weights[normal])
        recall = _weighted_rate(predicted[attack], weights[attack])
        item = {
            "threshold": float(threshold),
            "normal_fpr": fpr,
            "attack_precision": precision,
            "attack_recall": recall,
        }
        if (
            positives
            and fpr <= maximum_normal_fpr
            and precision >= minimum_attack_precision
            and recall >= minimum_attack_recall
        ):
            feasible.append(item)
    if not feasible:
        return {
            "threshold": 1.0,
            "normal_fpr": 0.0,
            "attack_precision": 0.0,
            "attack_recall": 0.0,
            "constraints_satisfied": False,
            "maximum_normal_fpr": maximum_normal_fpr,
            "minimum_attack_precision": minimum_attack_precision,
            "minimum_attack_recall": minimum_attack_recall,
        }
    selected = max(
        feasible,
        key=lambda item: (
            item["attack_recall"],
            item["attack_precision"],
            -item["normal_fpr"],
            item["threshold"],
        ),
    )
    return {
        **selected,
        "constraints_satisfied": True,
        "maximum_normal_fpr": maximum_normal_fpr,
        "minimum_attack_precision": minimum_attack_precision,
        "minimum_attack_recall": minimum_attack_recall,
    }


def choose_selective_threshold(
    y_true,
    probability,
    classes: Sequence[str],
    *,
    minimum_precision: float = 0.90,
    minimum_coverage: float = 0.10,
    minimum_accepted_rows: int = 5,
    minimum_accepted_groups: int = 3,
    sample_weight=None,
    groups=None,
    predicted_override=None,
    confidence_override=None,
    eligible_mask=None,
) -> dict[str, Any]:
    import numpy as np

    matrix = np.asarray(probability, dtype=float)
    labels = np.asarray(list(classes), dtype=object)
    predicted = (
        labels[np.argmax(matrix, axis=1)]
        if predicted_override is None
        else np.asarray(predicted_override, dtype=object)
    )
    confidence = (
        matrix.max(axis=1)
        if confidence_override is None
        else np.asarray(confidence_override, dtype=float)
    )
    y = np.asarray(y_true, dtype=str)
    if predicted.shape != y.shape or confidence.shape != y.shape:
        raise ValueError("selective predictions/confidence must be row-aligned")
    weights = _validated_weights(sample_weight, len(y))
    eligible = (
        np.ones(len(y), dtype=bool)
        if eligible_mask is None
        else np.asarray(eligible_mask, dtype=bool)
    )
    if eligible.shape != y.shape:
        raise ValueError("eligible_mask must be row-aligned")
    group_values = (
        np.asarray([str(index) for index in range(len(y))], dtype=object)
        if groups is None
        else np.asarray(groups, dtype=object)
    )
    if group_values.shape != y.shape:
        raise ValueError("groups must be row-aligned")
    candidates = sorted({0.0, 1.0, *[float(value) for value in confidence]})
    feasible: list[dict[str, Any]] = []
    for threshold in candidates:
        accepted = eligible & (confidence >= threshold)
        count = int(accepted.sum())
        precision = (
            _weighted_rate(predicted[accepted] == y[accepted], weights[accepted])
            if count
            else 0.0
        )
        coverage = float(weights[accepted].sum() / weights.sum())
        accepted_groups = int(len(set(group_values[accepted])))
        item = {
            "threshold": float(threshold),
            "accepted_precision": precision,
            "coverage": coverage,
            "accepted_rows": count,
            "accepted_groups": accepted_groups,
        }
        if (
            precision >= minimum_precision
            and coverage >= minimum_coverage
            and count >= minimum_accepted_rows
            and accepted_groups >= minimum_accepted_groups
        ):
            feasible.append(item)
    if not feasible:
        return {
            "threshold": 1.0,
            "accepted_precision": 0.0,
            "coverage": 0.0,
            "accepted_rows": 0,
            "accepted_groups": 0,
            "constraints_satisfied": False,
            "minimum_precision": minimum_precision,
            "minimum_coverage": minimum_coverage,
            "minimum_accepted_rows": minimum_accepted_rows,
            "minimum_accepted_groups": minimum_accepted_groups,
        }
    selected = max(
        feasible,
        key=lambda item: (
            item["coverage"],
            item["accepted_precision"],
            item["threshold"],
        ),
    )
    return {
        **selected,
        "constraints_satisfied": True,
        "minimum_precision": minimum_precision,
        "minimum_coverage": minimum_coverage,
        "minimum_accepted_rows": minimum_accepted_rows,
        "minimum_accepted_groups": minimum_accepted_groups,
    }


def _conditional_leaf_threshold(
    y_true,
    family_probability,
    family_classes: Sequence[str],
    leaf_probability,
    leaf_classes: Sequence[str],
    *,
    family_threshold: float,
    sample_weight,
    groups,
) -> dict[str, Any]:
    import numpy as np

    family_matrix = np.asarray(family_probability, dtype=float)
    leaf_matrix = np.asarray(leaf_probability, dtype=float)
    families = [str(value) for value in family_classes]
    leaves = [str(value) for value in leaf_classes]
    family_index = np.argmax(family_matrix, axis=1)
    predicted_families = [families[index] for index in family_index]
    family_confidence = family_matrix.max(axis=1)
    predicted_leaf: list[str] = []
    leaf_confidence: list[float] = []
    consistent: list[bool] = []
    for predicted_family, row in zip(predicted_families, leaf_matrix):
        label, confidence, is_consistent = conditional_leaf_candidate(
            predicted_family,
            leaves,
            row,
        )
        predicted_leaf.append(label)
        leaf_confidence.append(confidence)
        consistent.append(is_consistent)
    selection = choose_selective_threshold(
        y_true,
        leaf_matrix,
        leaves,
        sample_weight=sample_weight,
        groups=groups,
        predicted_override=predicted_leaf,
        confidence_override=leaf_confidence,
        eligible_mask=np.asarray(consistent, dtype=bool)
        & (family_confidence >= float(family_threshold)),
    )
    selection["semantics"] = "runtime_conditional_leaf_after_family_gate"
    return selection


def _event_metrics(frame, index, predicted_attack, predicted_block) -> dict[str, Any]:
    """Aggregate row decisions into session/source event rates.

    These are provisional because the campaign lacks trusted attacker-IP
    attribution.  They must never be interpreted as measured block accuracy.
    """

    import numpy as np

    subset = frame.iloc[index][["group_id", "session_id", "source", "label"]].copy()
    subset["predicted_attack"] = np.asarray(predicted_attack, dtype=bool)
    subset["predicted_block"] = np.asarray(predicted_block, dtype=bool)
    subset["is_attack"] = subset["label"].astype(str).ne("normal")
    subset["is_network_block"] = subset["label"].astype(str).map(family_for_label).eq(
        "network_block"
    )

    def aggregate(keys):
        grouped = subset.groupby(keys, sort=False).agg(
            is_attack=("is_attack", "max"),
            is_network_block=("is_network_block", "max"),
            attack_event=("predicted_attack", "max"),
            block_event=("predicted_block", "max"),
        )
        normal = ~grouped["is_attack"]
        attack = grouped["is_attack"]
        network_block = grouped["is_network_block"]
        def rate_or_none(values):
            array = values.to_numpy()
            return _weighted_rate(array, None) if len(array) else None

        return {
            "units": int(len(grouped)),
            "normal_units": int(normal.sum()),
            "attack_units": int(attack.sum()),
            "network_block_units": int(network_block.sum()),
            "any_attack_false_event_rate": rate_or_none(
                grouped.loc[normal, "attack_event"]
            ),
            "any_attack_detection_rate": rate_or_none(
                grouped.loc[attack, "attack_event"]
            ),
            "network_block_false_event_rate": rate_or_none(
                grouped.loc[normal, "block_event"]
            ),
            "network_block_detection_rate": rate_or_none(
                grouped.loc[network_block, "block_event"]
            ),
            "network_block_detection_evaluable": bool(network_block.any()),
        }

    return {
        "source_level": aggregate(["group_id", "source"]),
        "session_level": aggregate(["group_id"]),
        "attribution_verified": False,
        "deployment_eligible": False,
    }


def _fit_isolation_detector(x, weights, *, seed: int, n_estimators: int):
    from sklearn.ensemble import IsolationForest

    detector = IsolationForest(
        n_estimators=n_estimators,
        contamination="auto",
        max_features=1.0,
        random_state=seed,
        n_jobs=MAX_TRAINING_JOBS,
    )
    detector.fit(x, sample_weight=weights)
    return detector


def _quantile_threshold(scores, false_reject_budget: float) -> float:
    import numpy as np

    values = np.asarray(scores, dtype=float)
    if not len(values) or not np.isfinite(values).all():
        raise ValueError("threshold scores must be finite and non-empty")
    return float(np.quantile(values, false_reject_budget, method="lower"))


def _model_card(metrics: dict[str, Any]) -> str:
    binary = metrics["threshold_selection"]["binary"]
    family = metrics["threshold_selection"]["family"]
    return "\n".join(
        [
            "# SROS2 智慧防火牆：分層候選模型卡",
            "",
            f"- 建立時間：{metrics['trained_utc']}",
            f"- security mode：`{metrics['security_mode']}`",
            f"- 架構：`{ARCHITECTURE_NAME}`",
            f"- dataset session（排除後，含未用 test／novelty）：{metrics['sessions_after_exclusion']}",
            f"- supervised train session：{metrics['session_counts']['supervised_train']}",
            f"- novelty holdout：{', '.join(metrics['novelty_protocol']['holdout_labels'])}",
            f"- binary validation recall：{binary['attack_recall']:.4f}",
            f"- binary validation FPR：{binary['normal_fpr']:.4f}",
            f"- family accepted precision：{family['accepted_precision']:.4f}",
            "",
            "## 安全狀態",
            "",
            "- `deployment_eligible=false`。",
            "- `independent_final_test=false`。",
            "- 所有推論固定 `action=alert`、`adapter=none`、`executable=false`。",
            "- 舊 final test 已影響架構決策，因此本候選只報三段 validation。",
            "- 必須取得新 sealed holdout、九項 live outcome 與 kernel acceptance 後，才可另建部署 artifact。",
            "",
        ]
    )


def train_hierarchical_candidate(
    feature_csv: str | Path,
    output_dir: str | Path,
    *,
    security_mode: str,
    exclusions: str | Path = DEFAULT_EXCLUSIONS,
    dataset_root: str | Path = DEFAULT_DATASET_ROOT,
    holdout_labels: Sequence[str] | None = None,
    source_availability: Mapping[str, bool] = DEFAULT_LIVE_SOURCE_AVAILABILITY,
    random_state: int = 20260817,
    n_estimators: int = 160,
    maximum_normal_fpr: float = 0.02,
    maximum_known_attack_ood_fpr: float = 0.05,
    attack_ood_scorer: str = "isolation_forest",
    signing_secret: bytes | None = None,
) -> dict[str, Any]:
    import numpy as np

    if security_mode not in {"permissive", "enforce"}:
        raise ValueError("security_mode must be permissive or enforce")
    if n_estimators < 20 or n_estimators > 500:
        raise ValueError("n_estimators must be in 20..500")
    for name, value in (
        ("maximum_normal_fpr", maximum_normal_fpr),
        ("maximum_known_attack_ood_fpr", maximum_known_attack_ood_fpr),
    ):
        if isinstance(value, bool) or not 0.0 < float(value) <= 0.10:
            raise ValueError(f"{name} must be in (0, 0.10]")
    if attack_ood_scorer not in ATTACK_OOD_SCORERS:
        raise ValueError(
            f"attack_ood_scorer must be one of {sorted(ATTACK_OOD_SCORERS)}"
        )

    _ensure_output_outside_dataset(output_dir, dataset_root)
    output = Path(output_dir)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(
            f"refusing to reuse non-empty hierarchical output directory: {output}"
        )
    feature_path = Path(feature_csv)
    frame = load_training_frame(
        feature_path,
        data_tier="live",
        feature_names=list(RAW_FEATURES),
        extra_columns=("split", "security_mode", "session_id", "source", "window"),
        optional_columns=("novelty_role",),
    )
    modes = set(frame["security_mode"].astype(str))
    if modes != {security_mode}:
        raise ValueError(
            f"mode-specific training expected {security_mode}, got {sorted(modes)}"
        )
    policy_values = set(frame["policy_sha256"].astype(str))
    if len(policy_values) != 1:
        raise ValueError("mode-specific feature CSV must contain one policy_sha256")
    data_policy_sha256 = normalize_policy_sha256(next(iter(policy_values)))
    action_policy_sha256 = normalize_policy_sha256(sha256_file(ACTION_POLICY_PATH))
    if not frame["session_id"].astype(str).equals(frame["group_id"].astype(str)):
        raise ValueError("session_id must equal group_id for every feature row")

    excluded_sessions, exclusion_lineage = load_verified_exclusions(
        exclusions, dataset_root
    )
    excluded_rows = frame["session_id"].astype(str).isin(excluded_sessions)
    applicable_excluded = sorted(
        set(frame.loc[excluded_rows, "session_id"].astype(str))
    )
    verified_by_session = {
        str(entry["session_id"]): entry
        for entry in exclusion_lineage["verified_entries"]
    }
    for session_id in applicable_excluded:
        session_rows = frame.loc[frame["session_id"].astype(str).eq(session_id)]
        expected = verified_by_session[session_id]
        if set(session_rows["split"].astype(str)) != {str(expected["split"])}:
            raise ValueError(f"feature split does not match exclusion pin: {session_id}")
        if set(session_rows["security_mode"].astype(str)) != {
            str(expected["security_mode"])
        }:
            raise ValueError(f"feature mode does not match exclusion pin: {session_id}")
        session_labels = set(session_rows["label"].astype(str))
        expected_attack = str(expected["attack_class"])
        if expected_attack not in session_labels or not session_labels <= {
            "normal",
            expected_attack,
        }:
            raise ValueError(f"feature label does not match exclusion pin: {session_id}")
    frame = frame.loc[~excluded_rows].reset_index(drop=True)
    if frame.empty:
        raise ValueError("all training rows were excluded")
    split = _validate_split(frame)
    availability = normalize_source_availability(source_availability)
    matrix = _expanded_matrix(frame, availability)

    novelty_labels, novelty_groups = _resolve_holdout_labels(frame, holdout_labels)
    selection_groups = set(frame["group_id"].astype(str)) - novelty_groups
    partitions = _validation_partitions(
        frame, allowed_groups=selection_groups, seed=random_state
    )
    train_index = np.flatnonzero(
        frame["split"].astype(str).eq("train").to_numpy()
        & ~frame["group_id"].astype(str).isin(novelty_groups).to_numpy()
    )
    if not len(train_index):
        raise ValueError("no supervised train rows remain after novelty holdout")

    labels = frame["label"].astype(str).to_numpy()
    binary = np.where(labels == "normal", "normal", "attack")
    families = np.asarray([family_for_label(label) for label in labels], dtype=object)
    known_attack = (binary == "attack") & ~np.isin(labels, novelty_labels)

    novelty_group_mask = frame["group_id"].astype(str).isin(novelty_groups).to_numpy()
    novelty_usage = {
        "supervised_train_rows_used": int(novelty_group_mask[train_index].sum()),
        "selection_rows_used": int(
            novelty_group_mask[partitions["selection"]].sum()
        ),
        "calibration_rows_used": int(
            novelty_group_mask[partitions["calibration"]].sum()
        ),
        "threshold_rows_used": int(
            novelty_group_mask[partitions["threshold"]].sum()
        ),
    }
    if any(novelty_usage.values()):
        raise RuntimeError(
            "novelty holdout session leaked into train/validation processing"
        )

    supervised_train_labels = sorted(set(labels[train_index]))
    if set(novelty_labels) & set(supervised_train_labels):
        raise RuntimeError("novelty labels leaked into supervised train rows")
    if set(binary[train_index]) != {"normal", "attack"}:
        raise ValueError("binary train requires normal and known attacks")
    if len(set(families[train_index][binary[train_index] == "attack"])) < 2:
        raise ValueError("family train requires at least two attack families")
    if len(set(labels[train_index][binary[train_index] == "attack"])) < 2:
        raise ValueError("leaf train requires at least two known attack labels")

    task_specs = {
        "binary": {
            "train_index": train_index,
            "target": binary,
            "selection_index": partitions["selection"],
        },
        "family": {
            "train_index": train_index[known_attack[train_index]],
            "target": families,
            "selection_index": partitions["selection"][
                known_attack[partitions["selection"]]
            ],
        },
        "leaf": {
            "train_index": train_index[known_attack[train_index]],
            "target": labels,
            "selection_index": partitions["selection"][
                known_attack[partitions["selection"]]
            ],
        },
    }
    selected_models: dict[str, Any] = {}
    selected_names: dict[str, str] = {}
    comparisons: dict[str, Any] = {}
    for offset, (task, spec) in enumerate(task_specs.items()):
        task_train = spec["train_index"]
        task_selection = spec["selection_index"]
        if not len(task_selection):
            raise ValueError(f"{task} selection subset is empty")
        name, model, task_comparison = _select_estimator(
            task=task,
            train_x=matrix[task_train],
            train_y=spec["target"][task_train],
            train_weights=_session_equal_weights(frame, task_train),
            selection_x=matrix[task_selection],
            selection_y=spec["target"][task_selection],
            selection_weights=_session_equal_weights(frame, task_selection),
            seed=random_state + offset,
            n_estimators=n_estimators,
        )
        selected_names[task] = name
        selected_models[task] = model
        comparisons[task] = task_comparison

    calibration_index = partitions["calibration"]
    binary_model = _calibrate(
        selected_models["binary"],
        matrix[calibration_index],
        binary[calibration_index],
        _session_equal_weights(frame, calibration_index),
    )
    family_calibration = calibration_index[known_attack[calibration_index]]
    family_model = _calibrate(
        selected_models["family"],
        matrix[family_calibration],
        families[family_calibration],
        _session_equal_weights(frame, family_calibration),
    )
    leaf_model = _calibrate(
        selected_models["leaf"],
        matrix[family_calibration],
        labels[family_calibration],
        _session_equal_weights(frame, family_calibration),
    )

    threshold_index = partitions["threshold"]
    binary_selection = choose_binary_threshold(
        binary[threshold_index],
        _probability_for_class(binary_model, matrix[threshold_index], "attack"),
        maximum_normal_fpr=float(maximum_normal_fpr),
        sample_weight=_session_equal_weights(frame, threshold_index),
    )
    family_threshold_index = threshold_index[known_attack[threshold_index]]
    family_probability = family_model.predict_proba(matrix[family_threshold_index])
    family_selection = choose_selective_threshold(
        families[family_threshold_index],
        family_probability,
        [str(value) for value in family_model.classes_],
        sample_weight=_session_equal_weights(frame, family_threshold_index),
        groups=frame.iloc[family_threshold_index]["group_id"].astype(str).to_numpy(),
    )
    leaf_probability = leaf_model.predict_proba(matrix[family_threshold_index])
    leaf_selection = _conditional_leaf_threshold(
        labels[family_threshold_index],
        family_probability,
        [str(value) for value in family_model.classes_],
        leaf_probability,
        [str(value) for value in leaf_model.classes_],
        family_threshold=float(family_selection["threshold"]),
        sample_weight=_session_equal_weights(frame, family_threshold_index),
        groups=frame.iloc[family_threshold_index]["group_id"].astype(str).to_numpy(),
    )

    threshold_attack_score = _probability_for_class(
        binary_model, matrix[threshold_index], "attack"
    )
    threshold_family_probability = family_model.predict_proba(matrix[threshold_index])
    threshold_family_classes = [str(value) for value in family_model.classes_]
    threshold_family_index = np.argmax(threshold_family_probability, axis=1)
    threshold_family_candidate = np.asarray(
        [threshold_family_classes[index] for index in threshold_family_index],
        dtype=object,
    )
    threshold_family_confidence = threshold_family_probability.max(axis=1)
    event_metrics = _event_metrics(
        frame,
        threshold_index,
        threshold_attack_score >= float(binary_selection["threshold"]),
        (threshold_attack_score >= float(binary_selection["threshold"]))
        & (threshold_family_candidate == "network_block")
        & (threshold_family_confidence >= float(family_selection["threshold"])),
    )

    normal_train = train_index[binary[train_index] == "normal"]
    attack_train = train_index[known_attack[train_index]]
    normality_detector = _fit_isolation_detector(
        matrix[normal_train],
        _session_equal_weights(frame, normal_train),
        seed=random_state + 10,
        n_estimators=n_estimators,
    )
    if attack_ood_scorer == "mahalanobis":
        # 判別式評分：量到最近的已知攻擊類別中心的距離。IsolationForest 是
        # 密度式的，只認得比已知更「極端」的樣本，認不得只是「不一樣」的樣本
        # ——用 leave-one-known-class-out 量到 Permissive 六類 macro AUC 僅
        # 0.5381，其中四類低於 0.5。詳見 firewall_lab/ood_scorers.py。
        attack_ood_detector = MahalanobisNoveltyDetector().fit(
            matrix[attack_train], labels[attack_train]
        )
    else:
        attack_ood_detector = _fit_isolation_detector(
            matrix[attack_train],
            _session_equal_weights(frame, attack_train),
            seed=random_state + 11,
            n_estimators=n_estimators,
        )
    normal_threshold_rows = threshold_index[binary[threshold_index] == "normal"]
    known_attack_threshold_rows = threshold_index[
        known_attack[threshold_index]
    ]
    normality_threshold = _quantile_threshold(
        normality_detector.score_samples(matrix[normal_threshold_rows]),
        float(maximum_normal_fpr),
    )
    attack_ood_threshold = _quantile_threshold(
        attack_ood_detector.score_samples(matrix[known_attack_threshold_rows]),
        float(maximum_known_attack_ood_fpr),
    )

    # The old test has already informed architecture and hyperparameters.  No
    # test row is predicted here; all three reported subsets are validation.
    training_metadata = {
        "protocol": "session_grouped_three_way_validation_candidate",
        "data_tier": "live",
        "deployment_eligible": False,
        "independent_final_test": False,
        "historical_test_informed_architecture": True,
        "test_used_for_selection": False,
        "test_prediction_passes": 0,
        "executable": False,
        "source_attribution_required_for_network_block": True,
        "source_attribution_verified": False,
        "data_policy_sha256": data_policy_sha256,
        "action_policy_sha256": action_policy_sha256,
        "novelty_holdout_labels": novelty_labels,
        "novelty_holdout_groups": sorted(novelty_groups),
        "supervised_train_labels": supervised_train_labels,
        "excluded_sessions": applicable_excluded,
        "feature_csv_sha256": sha256_file(feature_path),
        "exclusion_registry_sha256": exclusion_lineage["registry_sha256"],
    }
    bundle = {
        "schema_version": HIERARCHICAL_MODEL_SCHEMA,
        "architecture": ARCHITECTURE_NAME,
        "security_mode": security_mode,
        "data_policy_sha256": data_policy_sha256,
        "action_policy_sha256": action_policy_sha256,
        "raw_features": list(RAW_FEATURES),
        "expanded_features": list(EXPANDED_FEATURES),
        "source_availability": availability,
        "policy_lineage": {
            "data_policy_sha256": data_policy_sha256,
            "action_policy_sha256": action_policy_sha256,
        },
        "family_map_sha256": family_map_sha256(),
        "binary_classifier": binary_model,
        "family_classifier": family_model,
        "leaf_classifier": leaf_model,
        "normality_detector": normality_detector,
        "attack_ood_detector": attack_ood_detector,
        "binary_threshold": float(binary_selection["threshold"]),
        "family_threshold": float(family_selection["threshold"]),
        "leaf_threshold": float(leaf_selection["threshold"]),
        "normality_threshold": normality_threshold,
        "attack_ood_threshold": attack_ood_threshold,
        "training": training_metadata,
    }

    metrics: dict[str, Any] = {
        "schema_version": HIERARCHICAL_METRICS_SCHEMA,
        "trained_utc": utc_now(),
        "architecture": ARCHITECTURE_NAME,
        "security_mode": security_mode,
        "deployment_eligible": False,
        "independent_final_test": False,
        "test_metrics": None,
        "test_prediction_passes": 0,
        "rows_after_exclusion": int(len(frame)),
        "sessions_after_exclusion": int(frame["group_id"].astype(str).nunique()),
        "session_counts": {
            "dataset_after_exclusion": int(frame["group_id"].astype(str).nunique()),
            "supervised_train": int(
                frame.iloc[train_index]["group_id"].astype(str).nunique()
            ),
            "selection_validation": int(
                frame.iloc[partitions["selection"]]["group_id"].astype(str).nunique()
            ),
            "calibration_validation": int(
                frame.iloc[partitions["calibration"]]["group_id"].astype(str).nunique()
            ),
            "threshold_validation": int(
                frame.iloc[partitions["threshold"]]["group_id"].astype(str).nunique()
            ),
            "novelty_holdout_deferred": int(len(novelty_groups)),
            "historical_test_not_evaluated": int(
                frame.loc[frame["split"].astype(str).eq("test"), "group_id"]
                .astype(str)
                .nunique()
            ),
        },
        "exclusion_lineage": exclusion_lineage,
        "applicable_excluded_sessions": applicable_excluded,
        "feature_input": {
            "path": str(feature_path),
            "sha256": sha256_file(feature_path),
        },
        "source_availability": availability,
        "novelty_protocol": {
            "unit": "entire_session_if_any_row_has_holdout_label",
            "holdout_labels": novelty_labels,
            "holdout_groups": len(novelty_groups),
            **novelty_usage,
            "test_evaluation_deferred": True,
        },
        "validation_protocol": {
            "selection_groups": sorted(partitions["groups"]["selection"]),
            "calibration_groups": sorted(partitions["groups"]["calibration"]),
            "threshold_groups": sorted(partitions["groups"]["threshold"]),
            "pairwise_overlap": 0,
        },
        "weighting": {
            "estimator_fit": "session_equal",
            "candidate_selection": "session_equal",
            "calibration": "session_equal",
            "threshold_selection": "session_equal",
        },
        "selected_models": selected_names,
        "model_comparison_selection_validation": comparisons,
        "threshold_selection": {
            "binary": binary_selection,
            "family": family_selection,
            "leaf": leaf_selection,
            "normality_threshold": normality_threshold,
            "normality_false_reject_budget": float(maximum_normal_fpr),
            "attack_ood_threshold": attack_ood_threshold,
            "known_attack_false_unknown_budget": float(
                maximum_known_attack_ood_fpr
            ),
            "attack_ood_scorer": attack_ood_scorer,
        },
        "event_level_development_metrics": event_metrics,
        "limitations": [
            "the historical test informed this architecture; no independent final metric is claimed",
            "source-unavailable telemetry is represented by a mask and cannot be treated as a measured zero",
            "the candidate is observe-only and cannot call any response adapter",
            "the current dataset has no trusted attacker-IP attribution ground truth",
            "new paired crossover and sealed holdout sessions are still required",
        ],
    }

    model_path = output / "hierarchical_model.joblib"
    metrics_path = output / "training_metrics.json"
    card_path = output / "MODEL_CARD.md"
    release_path = output / "release_manifest.json"
    for destination in (model_path, metrics_path, card_path, release_path):
        if destination.exists():
            raise FileExistsError(
                f"refusing to overwrite hierarchical candidate: {destination}"
            )
    output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ML_DIR))
    try:
        from ml_utils import (
            atomic_joblib_dump,
            load_hmac_secret,
            sign_artifact,
            signature_path,
        )
    finally:
        sys.path.remove(str(ML_DIR))
    effective_secret = load_hmac_secret() if signing_secret is None else signing_secret
    atomic_joblib_dump(bundle, model_path, secret=effective_secret)
    atomic_write_json(metrics_path, metrics)
    _atomic_write_text(card_path, _model_card(metrics))
    model_signature = signature_path(model_path)
    release = {
        "schema_version": "sros2-firewall-hierarchical-release/v1",
        "created_utc": utc_now(),
        "security_mode": security_mode,
        "deployment_eligible": False,
        "independent_final_test": False,
        "data_policy_sha256": data_policy_sha256,
        "action_policy_sha256": action_policy_sha256,
        "feature_csv_sha256": sha256_file(feature_path),
        "source_code": {
            "hierarchical_model.py": sha256_file(Path(__file__).with_name("hierarchical_model.py")),
            "hierarchical_training.py": sha256_file(Path(__file__)),
            "dataset_exclusions.v1.json": exclusion_lineage["registry_sha256"],
        },
        "environment": {
            "python": sys.version.split()[0],
            **{
                package: importlib.metadata.version(package)
                for package in ("numpy", "pandas", "scikit-learn", "joblib")
            },
        },
        "files": {
            path.name: {
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in (model_path, model_signature, metrics_path, card_path)
        },
    }
    atomic_write_json(release_path, release)
    release_signature = sign_artifact(release_path, effective_secret)
    return {
        "model": str(model_path),
        "metrics": str(metrics_path),
        "model_card": str(card_path),
        "release_manifest": str(release_path),
        "release_manifest_hmac": str(release_signature),
        "deployment_eligible": False,
        "independent_final_test": False,
        "security_mode": security_mode,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train an observe-only hierarchical firewall candidate"
    )
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--security-mode", choices=("permissive", "enforce"), required=True
    )
    parser.add_argument("--exclusions", type=Path, default=DEFAULT_EXCLUSIONS)
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--holdout-label", action="append", default=None)
    parser.add_argument("--seed", type=int, default=20260817)
    parser.add_argument("--n-estimators", type=int, default=160)
    parser.add_argument("--maximum-normal-fpr", type=float, default=0.02)
    parser.add_argument(
        "--maximum-known-attack-ood-fpr", type=float, default=0.05
    )
    parser.add_argument(
        "--attack-ood-scorer",
        choices=sorted(ATTACK_OOD_SCORERS),
        default="isolation_forest",
        help="未知攻擊評分器。預設維持 isolation_forest，改動必須是明示的。",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    result = train_hierarchical_candidate(
        args.features,
        args.output,
        security_mode=args.security_mode,
        exclusions=args.exclusions,
        dataset_root=args.dataset_root,
        holdout_labels=args.holdout_label,
        random_state=args.seed,
        n_estimators=args.n_estimators,
        maximum_normal_fpr=args.maximum_normal_fpr,
        maximum_known_attack_ood_fpr=args.maximum_known_attack_ood_fpr,
        attack_ood_scorer=args.attack_ood_scorer,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
