#!/usr/bin/env python3
"""Audit session-level conformal finite-sample readiness without fitting models."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.schema import atomic_write_json, sha256_file, utc_now  # noqa: E402
from firewall_lab.session_conformal import conformal_resolution  # noqa: E402


SCHEMA = "sros2-firewall-conformal-readiness-audit/v1"


def _group_labels(feature_csv: Path) -> tuple[dict[str, set[str]], set[str]]:
    grouped: dict[str, set[str]] = {}
    modes: set[str] = set()
    with feature_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"group_id", "label", "split", "security_mode"}
        if reader.fieldnames is None or not required <= set(reader.fieldnames):
            raise ValueError("feature CSV lacks group_id/label/split/security_mode")
        for row in reader:
            if row["split"] != "validation":
                continue
            group = row["group_id"]
            label = row["label"]
            mode = row["security_mode"]
            if not group or not label or not mode:
                raise ValueError("validation rows contain empty protocol fields")
            grouped.setdefault(group, set()).add(label)
            modes.add(mode)
    if not grouped:
        raise ValueError("feature CSV has no validation groups")
    return grouped, modes


def _reference_counts(grouped: dict[str, set[str]], groups: set[str]) -> dict[str, int]:
    unknown = groups - set(grouped)
    if unknown:
        raise ValueError(f"metrics reference absent validation groups: {sorted(unknown)[:3]}")
    return {
        "normality": sum("normal" in grouped[group] for group in groups),
        "known_attack": sum(
            any(label != "normal" for label in grouped[group]) for group in groups
        ),
    }


def evaluate(
    feature_csv: Path,
    metrics_path: Path,
    *,
    normal_alpha: float,
    known_attack_alpha: float,
) -> dict:
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    if not isinstance(metrics, dict):
        raise ValueError("training metrics must be an object")
    protocol = metrics.get("validation_protocol")
    if not isinstance(protocol, dict):
        raise ValueError("training metrics lack validation_protocol")
    named = {}
    for key in ("selection_groups", "calibration_groups", "threshold_groups"):
        values = protocol.get(key)
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value for value in values
        ):
            raise ValueError(f"validation_protocol.{key} is invalid")
        named[key] = set(values)
    keys = list(named)
    for index, left in enumerate(keys):
        for right in keys[index + 1 :]:
            if named[left] & named[right]:
                raise ValueError(f"validation groups overlap: {left}/{right}")
    grouped, modes = _group_labels(feature_csv)
    if modes != {metrics.get("security_mode")}:
        raise ValueError("feature security_mode differs from training metrics")

    calibration = _reference_counts(grouped, named["calibration_groups"])
    expanded_groups = named["calibration_groups"] | named["threshold_groups"]
    expanded = _reference_counts(grouped, expanded_groups)
    alphas = {"normality": normal_alpha, "known_attack": known_attack_alpha}

    def assess(counts: dict[str, int]) -> dict:
        references = {
            name: conformal_resolution(alphas[name], counts[name])
            for name in sorted(alphas)
        }
        return {
            "references": references,
            "all_finite_sample_resolutions_sufficient": all(
                value["finite_sample_resolution_sufficient"]
                for value in references.values()
            ),
        }

    calibration_assessment = assess(calibration)
    expanded_assessment = assess(expanded)
    return {
        "schema_version": SCHEMA,
        "created_utc": utc_now(),
        "security_mode": metrics["security_mode"],
        "method": "session_max_split_conformal",
        "artifacts": {
            "features": {"path": str(feature_csv), "sha256": sha256_file(feature_csv)},
            "training_metrics": {
                "path": str(metrics_path),
                "sha256": sha256_file(metrics_path),
            },
        },
        "protocol": {
            "calibration_groups": len(named["calibration_groups"]),
            "threshold_groups": len(named["threshold_groups"]),
            "selection_groups": len(named["selection_groups"]),
            "pairwise_overlap": 0,
            "test_rows_used": 0,
            "historical_validation_reused_for_development": True,
        },
        "registered_calibration_partition": calibration_assessment,
        "expanded_calibration_plus_threshold_development_pool": {
            **expanded_assessment,
            "shares_groups_with_binary_threshold_selection": True,
            "eligible_as_independent_confirmation": False,
        },
        "status": (
            "ready_for_development_fit"
            if calibration_assessment["all_finite_sample_resolutions_sufficient"]
            else "blocked_insufficient_calibration_sessions"
        ),
        "development_only": True,
        "independent_final_test": False,
        "deployment_eligible": False,
        "automatic_ip_block_authorized": False,
        "network_activity_performed": False,
        "executable": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--normal-alpha", type=float, default=0.02)
    parser.add_argument("--known-attack-alpha", type=float, default=0.05)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing to overwrite report: {args.output}")
    report = evaluate(
        args.features,
        args.metrics,
        normal_alpha=args.normal_alpha,
        known_attack_alpha=args.known_attack_alpha,
    )
    atomic_write_json(args.output, report)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "security_mode": report["security_mode"],
                "status": report["status"],
                "deployment_eligible": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
