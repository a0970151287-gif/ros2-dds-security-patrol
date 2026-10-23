#!/usr/bin/env python3
"""Session-grouped leave-one-family-out evaluation for P1 parallel gating.

This is development evidence only.  It uses train rows for fitting and the
already-designated validation partitions for thresholds/reference evaluation;
test rows and the official novelty-holdout sessions are never touched.  Each
fold removes every session containing one attack family before fitting any
binary, normality or known-attack OOD head.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.hierarchical_model import (  # noqa: E402
    PARALLEL_GATE_CONTRACT,
    RAW_FEATURES,
    family_for_label,
)
from firewall_lab.ood_scorers import MahalanobisNoveltyDetector  # noqa: E402
from firewall_lab.schema import sha256_file  # noqa: E402


SCHEMA = "sros2-firewall-parallel-gate-family-loo/v1"


def _weighted_rate(frame, index, mask) -> float:
    import numpy as np

    from firewall_lab.hierarchical_training import _session_equal_weights

    values = np.asarray(mask, dtype=bool)
    if len(index) != len(values) or not len(index):
        raise ValueError("weighted-rate inputs must be non-empty and row-aligned")
    weights = _session_equal_weights(frame, index)
    return float(np.average(values.astype(float), weights=weights))


def _event_rate(frame, index, mask) -> float:
    import pandas as pd

    if not len(index):
        raise ValueError("event-rate inputs must be non-empty")
    subset = pd.DataFrame(
        {
            "group_id": frame.iloc[index]["group_id"].astype(str).to_numpy(),
            "flagged": mask,
        }
    )
    return float(subset.groupby("group_id", sort=False)["flagged"].max().mean())


def _probability(estimator, matrix, label: str):
    import numpy as np

    classes = [str(value) for value in estimator.classes_]
    if label not in classes:
        raise ValueError(f"classifier does not contain {label!r}")
    values = np.asarray(estimator.predict_proba(matrix), dtype=float)
    return values[:, classes.index(label)]


def _fit_attack_ood(name, x, y, weights, *, seed: int, n_estimators: int):
    if name == "mahalanobis":
        return MahalanobisNoveltyDetector().fit(x, y)
    if name != "isolation_forest":
        raise ValueError("attack_ood_scorer must be isolation_forest or mahalanobis")
    from firewall_lab.hierarchical_training import _fit_isolation_detector

    return _fit_isolation_detector(
        x, weights, seed=seed, n_estimators=n_estimators
    )


def evaluate(
    feature_csv: Path,
    metrics_path: Path,
    *,
    attack_ood_scorer: str,
    n_estimators: int,
    seed: int,
    maximum_normal_fpr: float,
    maximum_known_attack_ood_fpr: float,
    minimum_unknown_recall: float,
) -> dict:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    from firewall_lab.hierarchical_training import (
        _expanded_matrix,
        _fit_isolation_detector,
        _quantile_threshold,
        _session_equal_weights,
        choose_binary_threshold,
    )

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    frame = pd.read_csv(feature_csv)
    required = set(RAW_FEATURES) | {
        "group_id",
        "session_id",
        "source",
        "window",
        "label",
        "split",
        "security_mode",
    }
    missing = required - set(frame)
    if missing:
        raise ValueError(f"feature CSV is missing columns: {sorted(missing)}")
    if not frame["session_id"].astype(str).equals(frame["group_id"].astype(str)):
        raise ValueError("session_id must equal group_id")
    if set(frame["security_mode"].astype(str)) != {metrics["security_mode"]}:
        raise ValueError("feature mode differs from training metrics")
    excluded_sessions = set(metrics.get("applicable_excluded_sessions", []))
    if excluded_sessions:
        frame = frame.loc[
            ~frame["group_id"].astype(str).isin(excluded_sessions)
        ].reset_index(drop=True)
    matrix = _expanded_matrix(frame, metrics["source_availability"])
    labels = frame["label"].astype(str).to_numpy()
    groups = frame["group_id"].astype(str).to_numpy()
    split = frame["split"].astype(str).to_numpy()
    families = np.asarray([family_for_label(label) for label in labels], dtype=object)

    official_holdout_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    official_holdout_groups = set(
        frame.loc[
            frame["label"].astype(str).isin(official_holdout_labels), "group_id"
        ].astype(str)
    )
    official_mask = np.isin(groups, list(official_holdout_groups))
    attack_mask = labels != "normal"
    base_train = (split == "train") & ~official_mask
    validation = (split == "validation") & ~official_mask
    known_families = sorted(set(families[base_train & attack_mask]))
    if len(known_families) < 3:
        raise ValueError("family LOO requires at least three known attack families")

    threshold_groups = set(metrics["validation_protocol"]["threshold_groups"])
    reference_groups = set(metrics["validation_protocol"]["selection_groups"])
    if threshold_groups & reference_groups:
        raise ValueError("threshold and reference validation groups overlap")
    threshold_group_mask = np.isin(groups, list(threshold_groups))
    reference_group_mask = np.isin(groups, list(reference_groups))

    folds: list[dict] = []
    for offset, held_family in enumerate(known_families):
        held_groups = set(groups[base_train & attack_mask & (families == held_family)])
        held_groups.update(
            groups[validation & attack_mask & (families == held_family)]
        )
        held_group_mask = np.isin(groups, list(held_groups))
        fit_index = np.flatnonzero(base_train & ~held_group_mask)
        threshold_index = np.flatnonzero(
            validation & threshold_group_mask & ~held_group_mask
        )
        unknown_index = np.flatnonzero(
            validation & held_group_mask & attack_mask & (families == held_family)
        )
        normal_index = np.flatnonzero(
            validation & reference_group_mask & ~held_group_mask & ~attack_mask
        )
        known_index = np.flatnonzero(
            validation & reference_group_mask & ~held_group_mask & attack_mask
        )
        if any(
            not len(index)
            for index in (
                fit_index,
                threshold_index,
                unknown_index,
                normal_index,
                known_index,
            )
        ):
            raise ValueError(f"fold {held_family} has an empty protocol partition")

        fit_binary = np.where(labels[fit_index] == "normal", "normal", "attack")
        if set(fit_binary) != {"normal", "attack"}:
            raise ValueError(f"fold {held_family} lacks a binary fit class")
        binary_model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=16,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight="balanced_subsample",
            random_state=seed + offset,
            n_jobs=1,
        )
        binary_model.fit(
            matrix[fit_index],
            fit_binary,
            sample_weight=_session_equal_weights(frame, fit_index),
        )
        normal_fit = fit_index[labels[fit_index] == "normal"]
        attack_fit = fit_index[labels[fit_index] != "normal"]
        normality = _fit_isolation_detector(
            matrix[normal_fit],
            _session_equal_weights(frame, normal_fit),
            seed=seed + 100 + offset,
            n_estimators=n_estimators,
        )
        attack_ood = _fit_attack_ood(
            attack_ood_scorer,
            matrix[attack_fit],
            labels[attack_fit],
            _session_equal_weights(frame, attack_fit),
            seed=seed + 200 + offset,
            n_estimators=n_estimators,
        )

        threshold_binary = np.where(
            labels[threshold_index] == "normal", "normal", "attack"
        )
        binary_selection = choose_binary_threshold(
            threshold_binary,
            _probability(binary_model, matrix[threshold_index], "attack"),
            maximum_normal_fpr=maximum_normal_fpr,
            sample_weight=_session_equal_weights(frame, threshold_index),
        )
        normal_threshold_rows = threshold_index[labels[threshold_index] == "normal"]
        attack_threshold_rows = threshold_index[labels[threshold_index] != "normal"]
        normality_threshold = _quantile_threshold(
            normality.score_samples(matrix[normal_threshold_rows]), maximum_normal_fpr
        )
        attack_ood_threshold = _quantile_threshold(
            attack_ood.score_samples(matrix[attack_threshold_rows]),
            maximum_known_attack_ood_fpr,
        )

        def decisions(index):
            binary_attack = (
                _probability(binary_model, matrix[index], "attack")
                >= float(binary_selection["threshold"])
            )
            abnormal = (
                normality.score_samples(matrix[index]) < normality_threshold
            )
            attack_rejected = (
                attack_ood.score_samples(matrix[index]) < attack_ood_threshold
            )
            normal_eligible = ~binary_attack & ~abnormal
            unknown = attack_rejected & (binary_attack | abnormal)
            return binary_attack, normal_eligible, unknown

        held_binary, _held_normal, held_unknown = decisions(unknown_index)
        _normal_binary, normal_eligible, normal_unknown = decisions(normal_index)
        _known_binary, _known_normal, known_unknown = decisions(known_index)
        recovered = held_unknown & ~held_binary
        fold = {
            "held_family": held_family,
            "held_labels": sorted(set(labels[unknown_index])),
            "held_groups": len(set(groups[unknown_index])),
            "fit_groups": len(set(groups[fit_index])),
            "threshold_groups": len(set(groups[threshold_index])),
            "reference_groups": len(set(groups[normal_index]) | set(groups[known_index])),
            "rows": {
                "fit": int(len(fit_index)),
                "threshold": int(len(threshold_index)),
                "unknown": int(len(unknown_index)),
                "normal_reference": int(len(normal_index)),
                "known_attack_reference": int(len(known_index)),
            },
            "thresholds": {
                "binary": float(binary_selection["threshold"]),
                "normality": float(normality_threshold),
                "attack_ood": float(attack_ood_threshold),
            },
            "metrics": {
                "binary_unknown_recall": _weighted_rate(
                    frame, unknown_index, held_binary
                ),
                "parallel_unknown_recall": _weighted_rate(
                    frame, unknown_index, held_unknown
                ),
                "parallel_unknown_session_recall": _event_rate(
                    frame, unknown_index, held_unknown
                ),
                "binary_miss_recovered_rate": _weighted_rate(
                    frame, unknown_index, recovered
                ),
                "normal_false_unknown_rate": _weighted_rate(
                    frame, normal_index, normal_unknown
                ),
                "normal_false_unknown_session_rate": _event_rate(
                    frame, normal_index, normal_unknown
                ),
                "normal_not_eligible_rate": _weighted_rate(
                    frame, normal_index, ~normal_eligible
                ),
                "known_attack_false_unknown_rate": _weighted_rate(
                    frame, known_index, known_unknown
                ),
            },
        }
        folds.append(fold)

    macro_unknown = float(
        sum(fold["metrics"]["parallel_unknown_recall"] for fold in folds)
        / len(folds)
    )
    worst_unknown = min(
        fold["metrics"]["parallel_unknown_recall"] for fold in folds
    )
    worst_normal = max(
        fold["metrics"]["normal_false_unknown_rate"] for fold in folds
    )
    worst_known = max(
        fold["metrics"]["known_attack_false_unknown_rate"] for fold in folds
    )
    constraints = {
        "macro_unknown_recall": macro_unknown >= minimum_unknown_recall,
        "worst_family_unknown_recall": worst_unknown >= minimum_unknown_recall,
        "normal_false_unknown_budget": worst_normal <= maximum_normal_fpr,
        "known_attack_false_unknown_budget": (
            worst_known <= maximum_known_attack_ood_fpr
        ),
    }
    return {
        "schema_version": SCHEMA,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "decision_contract": PARALLEL_GATE_CONTRACT,
        "security_mode": metrics["security_mode"],
        "attack_ood_scorer": attack_ood_scorer,
        "protocol": {
            "name": "session_grouped_leave_one_attack_family_out",
            "fit_split": "train",
            "threshold_split": "validation.threshold_groups",
            "reference_split": "validation.selection_groups",
            "unknown_split": "all validation rows from the held family",
            "entire_held_family_sessions_removed_before_fit": True,
            "official_novelty_holdout_labels_excluded": sorted(
                official_holdout_labels
            ),
            "official_novelty_holdout_groups_excluded": len(
                official_holdout_groups
            ),
            "official_novelty_holdout_rows_used": 0,
            "test_rows_used": 0,
            "known_family_head_role": (
                "advisory after the parallel gate; it cannot accept normal traffic"
            ),
            "historical_validation_reused_for_development": True,
        },
        "budgets": {
            "minimum_unknown_recall": minimum_unknown_recall,
            "maximum_normal_fpr": maximum_normal_fpr,
            "maximum_known_attack_ood_fpr": maximum_known_attack_ood_fpr,
        },
        "folds": folds,
        "summary": {
            "families": len(folds),
            "macro_unknown_recall": macro_unknown,
            "worst_family_unknown_recall": worst_unknown,
            "worst_normal_false_unknown_rate": worst_normal,
            "worst_known_attack_false_unknown_rate": worst_known,
            "constraints": constraints,
            "all_constraints_satisfied": all(constraints.values()),
        },
        "artifacts": {
            "features": {
                "path": str(feature_csv),
                "sha256": sha256_file(feature_csv),
            },
            "training_metrics": {
                "path": str(metrics_path),
                "sha256": sha256_file(metrics_path),
            },
            "evaluator_sha256": sha256_file(Path(__file__)),
        },
        "safety": {
            "development_only": True,
            "independent_final_test": False,
            "deployment_eligible": False,
            "automatic_ip_block_authorized": False,
            "network_activity_performed": False,
            "executable": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--attack-ood-scorer",
        choices=("isolation_forest", "mahalanobis"),
        default="isolation_forest",
    )
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--seed", type=int, default=20260825)
    parser.add_argument("--maximum-normal-fpr", type=float, default=0.02)
    parser.add_argument(
        "--maximum-known-attack-ood-fpr", type=float, default=0.05
    )
    parser.add_argument("--minimum-unknown-recall", type=float, default=0.70)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {args.output}")
    if not 20 <= args.n_estimators <= 500:
        raise ValueError("n_estimators must be in 20..500")
    for name, value in (
        ("maximum_normal_fpr", args.maximum_normal_fpr),
        ("maximum_known_attack_ood_fpr", args.maximum_known_attack_ood_fpr),
        ("minimum_unknown_recall", args.minimum_unknown_recall),
    ):
        if not 0.0 < value < 1.0:
            raise ValueError(f"{name} must be in (0, 1)")
    report = evaluate(
        args.features,
        args.metrics,
        attack_ood_scorer=args.attack_ood_scorer,
        n_estimators=args.n_estimators,
        seed=args.seed,
        maximum_normal_fpr=args.maximum_normal_fpr,
        maximum_known_attack_ood_fpr=args.maximum_known_attack_ood_fpr,
        minimum_unknown_recall=args.minimum_unknown_recall,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "security_mode": report["security_mode"],
                "attack_ood_scorer": report["attack_ood_scorer"],
                **report["summary"],
                "deployment_eligible": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
