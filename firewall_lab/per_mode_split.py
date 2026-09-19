#!/usr/bin/env python3
"""Split the live fusion features into one dataset per SROS2 security mode.

The 1,100-session campaign cannot answer RQ3 as originally posed: a classifier
recovers the security mode from the 14 network features at 0.945 separability,
and 10 of the 14 do so on their own, so any cross-mode model can score by
recognising the arm rather than the attack.  Dropping the offenders does not
help -- cutting to the six cleanest still leaves 0.857 while attack detection
falls from 0.950 to 0.748.

That separation is a real effect, not a collection defect: DDS Security
encrypts discovery, adds a handshake and refuses unauthorised peers, so the
traffic genuinely looks different.  The response is therefore to stop asking a
single model to span both arms, and instead evaluate each arm on its own:
"can attacks be detected under this security policy" is answerable and honest,
and the paired campaign supports asking it twice.

Splits are grouped by session and stratified by label, so no session's windows
straddle train/validation/test.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .schema import atomic_write_json, utc_now

SPLIT_SCHEMA_VERSION = "sros2-firewall-per-mode-split/v1"
MODES = ("permissive", "enforce")
DEFAULT_RATIOS = {"train": 0.70, "validation": 0.15, "test": 0.15}

# grouped_training splits validation again for calibration and threshold
# selection, and needs at least two sessions of each label signature there.
MIN_VALIDATION_SESSIONS = 2
# Below this a 70/15/15 split cannot give validation its two sessions, so the
# signature is kept in train rather than allowed to break calibration.
MIN_SESSIONS_PER_SIGNATURE = 14


def _assign_sessions(frame, *, seed: int, ratios: dict[str, float]):
    """Assign whole sessions to splits, keeping every class in every split.

    Sessions are the unit because windows from one session are near-duplicates;
    splitting inside a session would let the model memorise a run rather than
    learn the attack.
    """
    import pandas as pd

    # Stratify by the session's label signature, not just its scenario.
    #
    # Downstream calibration splits validation again by signature and needs at
    # least two sessions per signature. Most attack sessions carry both a
    # normal warmup window and attack windows, but a few are attack-only
    # because the boundary fell outside every window centre. Those rare
    # signatures exist once or twice in the whole arm, and stratifying by
    # scenario alone let one land in validation by itself, which failed the
    # split with "label signature needs at least two sessions".
    signatures = (
        frame.groupby("session_id")["label"]
        .apply(lambda s: ",".join(sorted(set(s.astype(str)))))
        .rename("signature")
    )
    sessions = (
        frame.groupby("session_id")
        .agg(scenario_id=("scenario_id", "first"))
        .join(signatures)
        .reset_index()
    )
    # A signature too rare to appear in every split goes wholly to train, where
    # it still teaches the model without breaking calibration.
    #
    # The floor is set by what calibration needs downstream: it splits
    # validation again by signature and requires at least two sessions there.
    # With 70/15/15 a signature needs ~14 sessions before rounding leaves two
    # in validation, so anything smaller is kept out of the split entirely
    # rather than being allowed to land there alone.
    signature_counts = sessions["signature"].value_counts()
    rare = set(signature_counts[signature_counts < MIN_SESSIONS_PER_SIGNATURE].index)

    assignments: dict[str, str] = {}
    for sid, sig in zip(sessions["session_id"], sessions["signature"]):
        if sig in rare:
            assignments[str(sid)] = "train"

    common = sessions[~sessions["signature"].isin(rare)]
    for scenario, part in common.groupby("signature", sort=True):
        ids = sorted(part["session_id"].astype(str))
        # Deterministic shuffle: same seed and scenario always give the same
        # partition, so a rerun reproduces the split exactly.
        rng = __import__("random").Random(f"{seed}:{scenario}")
        rng.shuffle(ids)
        n = len(ids)
        # Validation needs two sessions per signature or the calibration split
        # fails; test needs one. Give those their floor first, then let train
        # take the remainder, so rounding can never starve a split.
        n_val = max(MIN_VALIDATION_SESSIONS, round(n * ratios["validation"]))
        n_test = max(1, round(n * ratios["test"]))
        n_train = n - n_val - n_test
        for i, sid in enumerate(ids):
            if i < n_train:
                assignments[sid] = "train"
            elif i < n_train + n_val:
                assignments[sid] = "validation"
            else:
                assignments[sid] = "test"
    return pd.Series(assignments, name="split")


# Classes withheld from the known-attack classifier so the anomaly detector can
# be scored on attacks it was never trained on. Two different families rather
# than two variants of one: sensor_spoof forges application-layer sensor state,
# service_dos exhausts a service. Holding out two look-alikes would flatter the
# result, because whatever generalises to one would trivially cover the other.
DEFAULT_NOVELTY_HOLDOUT = ("sensor_spoof", "service_dos")


def build_per_mode_datasets(
    fusion_csv: str | Path,
    output_dir: str | Path,
    *,
    seed: int = 20260816,
    ratios: dict[str, float] | None = None,
    novelty_holdout: tuple[str, ...] = DEFAULT_NOVELTY_HOLDOUT,
) -> dict:
    import pandas as pd

    ratios = dict(ratios or DEFAULT_RATIOS)
    frame = pd.read_csv(fusion_csv)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    report: dict = {
        "schema_version": SPLIT_SCHEMA_VERSION,
        "created_utc": utc_now(),
        "source": str(fusion_csv),
        "seed": seed,
        "ratios": ratios,
        "reason": (
            "cross-mode training cannot support an RQ3 claim: security mode is "
            "recoverable from the network features at 0.945 separability"
        ),
        "modes": {},
    }

    for mode in MODES:
        part = frame[frame["security_mode"].astype(str) == mode].copy()
        if part.empty:
            raise ValueError(f"no rows for security_mode={mode}")

        assignments = _assign_sessions(part, seed=seed, ratios=ratios)
        part["split"] = part["session_id"].astype(str).map(assignments)
        if part["split"].isna().any():
            raise RuntimeError(f"unassigned sessions in {mode}")

        # Every class must appear in every split, or downstream training cannot
        # report per-class metrics on the test set.
        labels = set(part["label"].astype(str))
        for split in ("train", "validation", "test"):
            present = set(part.loc[part["split"] == split, "label"].astype(str))
            missing = labels - present
            if missing:
                raise ValueError(
                    f"{mode}/{split} is missing classes {sorted(missing)}; "
                    "increase the session count or adjust the ratios"
                )

        # No session may straddle splits.
        per_session = part.groupby("session_id")["split"].nunique()
        if int(per_session.max()) != 1:
            raise RuntimeError(f"session leakage inside {mode}")

        # Mark the withheld classes so grouped_training keeps them out of the
        # known-attack classifier and out of anomaly-threshold selection, then
        # scores them on the test set as attacks the model never saw.
        part["novelty_role"] = part["label"].astype(str).map(
            lambda lab: "novelty_holdout_candidate"
            if lab in novelty_holdout
            else "known"
        )

        path = output / f"fusion_features_{mode}.csv"
        part.to_csv(path, index=False)

        counts = part.groupby("split").size().to_dict()
        session_counts = (
            part.groupby("split")["session_id"].nunique().to_dict()
        )
        report["modes"][mode] = {
            "path": str(path),
            "rows": int(len(part)),
            "sessions": int(part["session_id"].nunique()),
            "rows_per_split": {k: int(v) for k, v in counts.items()},
            "sessions_per_split": {
                k: int(v) for k, v in session_counts.items()
            },
            "classes": sorted(labels),
            "rows_per_label": {
                str(k): int(v)
                for k, v in part.groupby("label").size().to_dict().items()
            },
            "novelty_holdout": list(novelty_holdout),
            "novelty_holdout_rows": int(
                (part["novelty_role"] == "novelty_holdout_candidate").sum()
            ),
        }

    atomic_write_json(output / "per_mode_split_report.json", report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Split live fusion features into one dataset per security mode"
    )
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260816)
    args = parser.parse_args(argv)

    report = build_per_mode_datasets(args.features, args.output, seed=args.seed)
    for mode, info in report["modes"].items():
        print(
            f"{mode:11} rows={info['rows']:6d} sessions={info['sessions']:4d} "
            f"splits={info['sessions_per_split']}"
        )
    print(json.dumps(report["modes"]["enforce"]["rows_per_label"], indent=None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
