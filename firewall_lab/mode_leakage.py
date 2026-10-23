#!/usr/bin/env python3
"""Reject a dataset whose network features encode the SROS2 security mode.

RQ3 asks whether the model learns attack behaviour or merely memorises which
security mode produced a session.  That only means something if the two arms
are indistinguishable apart from the attacks themselves, and twice already the
lab has failed that quietly:

  * Permissive ran over shared memory while Enforce was forced onto UDP by DDS
    Security, so "are there any packets at all" separated the arms perfectly.
  * After that was fixed, Enforce still contributed a source address that
    Permissive never produced.

Both were found by hand.  This module replaces the eyeballing with a test the
data has to pass: fit a classifier on the feature columns alone and ask it to
predict ``security_mode``.  If it can, the arms differ in something other than
the security policy and the dataset must not be used to answer RQ3.

Fail-closed by design -- anything that prevents a trustworthy measurement is a
failure, not a pass.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .schema import atomic_write_json, utc_now

REPORT_SCHEMA_VERSION = "sros2-firewall-mode-leakage/v1"

# An honest split is a coin flip (0.5).  0.70 leaves room for the small,
# genuine differences a security policy causes downstream (blocked handshakes
# do change traffic shape) while still catching an arm that is simply
# identifiable.  Anything at or above this cannot support an RQ3 claim.
DEFAULT_MAX_AUC = 0.70

# Below this there is not enough independent evidence for the number to mean
# anything, and a small sample is exactly where a lucky 0.5 would be most
# misleading.
MIN_SESSIONS_PER_MODE = 4
MIN_ROWS_PER_MODE = 20


class LeakageError(RuntimeError):
    """The dataset cannot be shown to be free of security-mode leakage."""


def _load(features_csv: Path):
    import pandas as pd

    frame = pd.read_csv(features_csv)
    for column in ("security_mode", "session_id", "scenario_id"):
        if column not in frame.columns:
            raise LeakageError(f"features are missing the {column} column")
    return frame


def _feature_columns(frame) -> list[str]:
    from .train import FEATURES

    missing = [name for name in FEATURES if name not in frame.columns]
    if missing:
        raise LeakageError(f"features are missing columns: {missing}")
    return list(FEATURES)


def _check_paired(frame) -> dict[str, list[str]]:
    """Scenarios must appear in both arms, or scenario differences masquerade
    as mode differences and the measurement means nothing."""
    per_mode = {
        str(mode): sorted(set(part["scenario_id"].astype(str)))
        for mode, part in frame.groupby("security_mode")
    }
    if set(per_mode) != {"permissive", "enforce"}:
        raise LeakageError(
            f"expected both security modes, found {sorted(per_mode)}"
        )
    only_p = set(per_mode["permissive"]) - set(per_mode["enforce"])
    only_e = set(per_mode["enforce"]) - set(per_mode["permissive"])
    if only_p or only_e:
        raise LeakageError(
            "scenarios are not paired across modes; unpaired scenarios would "
            f"be scored as mode signal (permissive-only={sorted(only_p)}, "
            f"enforce-only={sorted(only_e)})"
        )
    return per_mode


def measure(features_csv: Path, *, max_auc: float = DEFAULT_MAX_AUC) -> dict:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import StratifiedGroupKFold

    frame = _load(features_csv)
    columns = _feature_columns(frame)
    _check_paired(frame)

    counts = frame.groupby("security_mode").agg(
        rows=("session_id", "size"),
        sessions=("session_id", lambda values: values.nunique()),
    )
    for mode, row in counts.iterrows():
        if row["sessions"] < MIN_SESSIONS_PER_MODE:
            raise LeakageError(
                f"{mode} has {row['sessions']} sessions; at least "
                f"{MIN_SESSIONS_PER_MODE} are needed for a grouped split"
            )
        if row["rows"] < MIN_ROWS_PER_MODE:
            raise LeakageError(
                f"{mode} has {row['rows']} rows; at least {MIN_ROWS_PER_MODE} "
                "are needed"
            )

    features = frame[columns].to_numpy(dtype=float)
    if not np.isfinite(features).all():
        raise LeakageError("feature matrix contains NaN or infinity")
    target = (frame["security_mode"].astype(str) == "enforce").to_numpy(int)
    groups = frame["session_id"].astype(str).to_numpy()

    # Grouped folds: windows from one session must never be split across
    # train and test, or the classifier scores session identity, not mode.
    folds = min(5, int(min(counts["sessions"])))
    splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=0)
    scores = np.zeros(len(target), dtype=float)
    for train_idx, test_idx in splitter.split(features, target, groups):
        model = RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=0,
            n_jobs=1,
        )
        model.fit(features[train_idx], target[train_idx])
        scores[test_idx] = model.predict_proba(features[test_idx])[:, 1]

    auc = float(roc_auc_score(target, scores))
    # Direction does not matter: a classifier that is reliably wrong is just as
    # informative about the arm as one that is reliably right.
    separability = max(auc, 1.0 - auc)

    model = RandomForestClassifier(
        n_estimators=200, class_weight="balanced", random_state=0, n_jobs=1
    )
    model.fit(features, target)
    ranked = sorted(
        zip(columns, (float(v) for v in model.feature_importances_)),
        key=lambda item: item[1],
        reverse=True,
    )

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "created_utc": utc_now(),
        "features_csv": str(features_csv),
        "rows": int(len(frame)),
        "sessions": int(frame["session_id"].nunique()),
        "rows_per_mode": {str(k): int(v) for k, v in counts["rows"].items()},
        "sessions_per_mode": {
            str(k): int(v) for k, v in counts["sessions"].items()
        },
        "folds": int(folds),
        "roc_auc": round(auc, 6),
        "separability": round(separability, 6),
        "max_separability": float(max_auc),
        "passed": bool(separability < max_auc),
        "top_features": [
            {"feature": name, "importance": round(value, 6)}
            for name, value in ranked[:5]
        ],
        "interpretation": (
            "separability near 0.5 means the arms are indistinguishable from "
            "the features alone, which is what an RQ3 claim requires"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail a dataset whose features reveal the security mode"
    )
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--max-auc", type=float, default=DEFAULT_MAX_AUC)
    args = parser.parse_args(argv)

    try:
        report = measure(args.features, max_auc=args.max_auc)
    except LeakageError as exc:
        print(f"mode-leakage check BLOCKED: {exc}", file=sys.stderr)
        return 2

    if args.report is not None:
        atomic_write_json(args.report, report)

    print(
        f"separability={report['separability']:.4f} "
        f"(limit {report['max_separability']:.2f}) "
        f"rows={report['rows']} sessions={report['sessions']}"
    )
    for item in report["top_features"]:
        print(f"  {item['feature']:24} {item['importance']:.4f}")
    if not report["passed"]:
        print(
            "FAILED: the security mode is predictable from the features alone; "
            "the arms differ in something besides the security policy",
            file=sys.stderr,
        )
        return 1
    print("passed: security mode is not recoverable from the features")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
