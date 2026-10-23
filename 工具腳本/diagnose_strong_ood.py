#!/usr/bin/env python3
"""Test whether a strong known-attack OOD rejection can stand on its own.

C2C-042 proposed splitting the attack-OOD threshold into strong and weak, so a
confident rejection could declare "unknown" without the second signal the gate
currently demands.  That proposal has a problem its author did not check:
hierarchical_model states, in the rule itself, that "normal traffic is expected
to be outside the known-attack reference distribution".  If that is true
numerically, then the most strongly rejected rows are the most *normal* rows,
and letting a strong rejection stand alone would fire preferentially on benign
traffic -- the worst possible failure direction.

This measures it instead of arguing it.  For each leave-one-family-out fold the
attack-OOD head is refit without the held family, and the raw scores of three
disjoint validation groups are compared:

  unknown : the held-out family (a genuinely unseen attack)
  normal  : benign rows
  known   : attack rows from families that stayed in training

The decisive quantity is the separation between unknown and normal.  A strong
threshold is only usable if unknown rows sit below normal rows; if normal rows
sit lower, no threshold on this score alone can work.

Protocol is inherited from diagnose_gate_veto: the official novelty holdout and
the test split are never touched, and thresholds come from validation rows that
exclude the held family.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.hierarchical_model import (  # noqa: E402
    RAW_FEATURES,
    family_for_label,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from diagnose_gate_veto import _fit_attack_ood  # noqa: E402
from firewall_lab.schema import sha256_file  # noqa: E402

SCHEMA = "sros2-firewall-strong-ood-diagnosis/v1"
# Quantiles of the known-attack score distribution.  0.05 is the shipped
# budget; everything below it is "stronger than what ships".
DEFAULT_STRONG_SWEEP = (0.05, 0.02, 0.01, 0.005, 0.001)


def balanced_precision(unknown_rate: float, normal_rate: float):
    """Share of strong rejections that are the unseen family, at equal prior.

    The unknown and normal groups have different row counts, so a raw share
    would mostly report how many normal rows happen to exist.  Both are
    expressed as rates first, which is the reweighting.  Returns None when
    neither group fires, because a precision over nothing is not 0.0.
    """
    total = unknown_rate + normal_rate
    if total <= 0:
        return None
    return float(unknown_rate / total)


def aggregate_macro(folds: list[dict], strong_sweep: tuple[float, ...]) -> list[dict]:
    """Macro-average the sweep so every family counts once."""
    macro = []
    for position, budget in enumerate(strong_sweep):
        entries = [fold["strong_threshold_sweep"][position] for fold in folds]
        row = {"known_attack_budget": float(budget)}
        for key in ("unknown_below_rate", "normal_below_rate", "known_below_rate"):
            row[f"macro_{key}"] = float(
                sum(entry[key] for entry in entries) / len(entries)
            )
        usable = [
            entry["balanced_precision_vs_normal"] for entry in entries
            if entry["balanced_precision_vs_normal"] is not None
        ]
        row["macro_balanced_precision_vs_normal"] = (
            float(sum(usable) / len(usable)) if usable else None
        )
        row["folds_where_unknown_beats_normal"] = int(
            sum(
                1 for entry in entries
                if entry["unknown_below_rate"] > entry["normal_below_rate"]
            )
        )
        macro.append(row)
    return macro


def evaluate(
    feature_csv: Path,
    metrics_path: Path,
    *,
    attack_ood_scorer: str,
    n_estimators: int,
    seed: int,
    strong_sweep: tuple[float, ...],
) -> dict:
    import numpy as np
    import pandas as pd

    from firewall_lab.hierarchical_training import (
        _expanded_matrix,
        _quantile_threshold,
        _session_equal_weights,
    )

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    frame = pd.read_csv(feature_csv)
    required = set(RAW_FEATURES) | {
        "group_id", "session_id", "source", "window",
        "label", "split", "security_mode",
    }
    missing = required - set(frame)
    if missing:
        raise ValueError(f"feature CSV is missing columns: {sorted(missing)}")
    if set(frame["security_mode"].astype(str)) != {metrics["security_mode"]}:
        raise ValueError("feature mode differs from training metrics")

    excluded = set(metrics.get("applicable_excluded_sessions", []))
    if excluded:
        frame = frame.loc[
            ~frame["group_id"].astype(str).isin(excluded)
        ].reset_index(drop=True)

    matrix = _expanded_matrix(frame, metrics["source_availability"])
    labels = frame["label"].astype(str).to_numpy()
    groups = frame["group_id"].astype(str).to_numpy()
    split = frame["split"].astype(str).to_numpy()
    families = np.asarray([family_for_label(x) for x in labels], dtype=object)

    official_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    official_groups = set(
        frame.loc[frame["label"].astype(str).isin(official_labels), "group_id"]
        .astype(str)
    )
    official_mask = np.isin(groups, list(official_groups))

    attack_mask = labels != "normal"
    base_train = (split == "train") & ~official_mask
    validation = (split == "validation") & ~official_mask
    known_families = sorted(set(families[base_train & attack_mask]))
    if len(known_families) < 3:
        raise ValueError("family LOO requires at least three known families")

    threshold_groups = set(metrics["validation_protocol"]["threshold_groups"])
    reference_groups = set(metrics["validation_protocol"]["selection_groups"])
    if threshold_groups & reference_groups:
        raise ValueError("threshold and reference validation groups overlap")
    threshold_mask = np.isin(groups, list(threshold_groups))
    reference_mask = np.isin(groups, list(reference_groups))

    folds = []
    for offset, held in enumerate(known_families):
        held_groups = set(groups[base_train & attack_mask & (families == held)])
        held_groups.update(groups[validation & attack_mask & (families == held)])
        held_mask = np.isin(groups, list(held_groups))

        fit_index = np.flatnonzero(base_train & ~held_mask)
        threshold_index = np.flatnonzero(validation & threshold_mask & ~held_mask)
        unknown_index = np.flatnonzero(
            validation & held_mask & attack_mask & (families == held)
        )
        normal_index = np.flatnonzero(
            validation & reference_mask & ~held_mask & ~attack_mask
        )
        known_index = np.flatnonzero(
            validation & reference_mask & ~held_mask & attack_mask
        )
        partitions = (fit_index, threshold_index, unknown_index,
                      normal_index, known_index)
        if any(len(index) == 0 for index in partitions):
            raise ValueError(f"fold {held} has an empty protocol partition")

        attack_fit = fit_index[labels[fit_index] != "normal"]
        attack_ood = _fit_attack_ood(
            attack_ood_scorer, matrix[attack_fit], labels[attack_fit],
            _session_equal_weights(frame, attack_fit),
            seed=seed + 200 + offset, n_estimators=n_estimators,
        )

        attack_threshold_rows = threshold_index[
            labels[threshold_index] != "normal"
        ]
        threshold_scores = attack_ood.score_samples(matrix[attack_threshold_rows])

        scores = {
            "unknown": attack_ood.score_samples(matrix[unknown_index]),
            "normal": attack_ood.score_samples(matrix[normal_index]),
            "known": attack_ood.score_samples(matrix[known_index]),
        }

        def describe(values):
            return {
                "n": int(len(values)),
                "median": float(np.median(values)),
                "p10": float(np.quantile(values, 0.10)),
                "p90": float(np.quantile(values, 0.90)),
            }

        sweep = []
        for budget in strong_sweep:
            cut = _quantile_threshold(threshold_scores, budget)
            entry = {"known_attack_budget": float(budget), "threshold": float(cut)}
            for name, values in scores.items():
                entry[f"{name}_below_rate"] = float(np.mean(values < cut))
            sweep.append(entry)

        # Does a strong rejection point at an unknown attack or at normal
        # traffic?  Among every row the strong threshold fires on, this is the
        # share that is actually the unseen family.  Normal and unknown groups
        # are different sizes, so the shares are reweighted to equal prior --
        # otherwise the answer would just reflect how many normal rows exist.
        for entry in sweep:
            entry["balanced_precision_vs_normal"] = balanced_precision(
                entry["unknown_below_rate"], entry["normal_below_rate"]
            )

        folds.append({
            "held_family": held,
            "score_distribution": {
                name: describe(values) for name, values in scores.items()
            },
            "strong_threshold_sweep": sweep,
        })

    macro = aggregate_macro(folds, strong_sweep)

    median_gap = [
        {
            "held_family": fold["held_family"],
            "unknown_median": fold["score_distribution"]["unknown"]["median"],
            "normal_median": fold["score_distribution"]["normal"]["median"],
            "unknown_scores_lower_than_normal": bool(
                fold["score_distribution"]["unknown"]["median"]
                < fold["score_distribution"]["normal"]["median"]
            ),
        }
        for fold in folds
    ]

    return {
        "schema_version": SCHEMA,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "security_mode": metrics["security_mode"],
        "attack_ood_scorer": attack_ood_scorer,
        "inputs": {
            "features": str(feature_csv),
            "features_sha256": sha256_file(feature_csv),
            "metrics": str(metrics_path),
            "metrics_sha256": sha256_file(metrics_path),
        },
        "protocol": {
            "official_novelty_holdout_rows_used": 0,
            "test_rows_used": 0,
            "changes_shipped_defaults": False,
            "note": (
                "leave-one-family-out with refit; the official novelty holdout "
                "and the test split are excluded throughout"
            ),
        },
        "folds": folds,
        "macro": macro,
        "median_gap": median_gap,
        "folds_total": len(folds),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--attack-ood-scorer",
                        choices=("isolation_forest", "mahalanobis"),
                        default="mahalanobis")
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--seed", type=int, default=20260828)
    parser.add_argument("--strong-sweep", type=float, nargs="+",
                        default=list(DEFAULT_STRONG_SWEEP))
    args = parser.parse_args(argv)

    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {args.output}")
    sweep = tuple(sorted(set(args.strong_sweep), reverse=True))
    if not sweep or any(not 0.0 < value < 1.0 for value in sweep):
        raise ValueError("every strong sweep value must be in (0, 1)")

    report = evaluate(
        args.features, args.metrics,
        attack_ood_scorer=args.attack_ood_scorer,
        n_estimators=args.n_estimators,
        seed=args.seed,
        strong_sweep=sweep,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"mode={report['security_mode']} scorer={report['attack_ood_scorer']}")
    print(f"folds={report['folds_total']}")
    lower = sum(1 for row in report["median_gap"]
                if row["unknown_scores_lower_than_normal"])
    print(f"folds where unknown median scores lower than normal: "
          f"{lower}/{report['folds_total']}")
    print()
    print("budget   unknown  normal   known    bal.prec  folds_u>n")
    for row in report["macro"]:
        precision = row["macro_balanced_precision_vs_normal"]
        precision_text = "n/a" if precision is None else f"{precision:.4f}"
        print(
            f"{row['known_attack_budget']:<8.3f} "
            f"{row['macro_unknown_below_rate']:.4f}   "
            f"{row['macro_normal_below_rate']:.4f}   "
            f"{row['macro_known_below_rate']:.4f}   "
            f"{precision_text:<9} "
            f"{row['folds_where_unknown_beats_normal']}/{report['folds_total']}"
        )
    print(f"\nwrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
