#!/usr/bin/env python3
"""Offline attack/defense rehearsal with a verified local model.

This module never sends packets and never changes the host firewall.  It reads
held-out synthetic feature rows, performs authenticated model inference, maps
the result through the constrained action policy, and records what a temporary
response *would* do.  The report is prototype evidence only.
"""

from __future__ import annotations

import argparse
import hashlib
import csv
import math
import random
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any

from .decision import FirewallDecision
from .evidence import EvidenceAuthority, feature_sha256
from .inference import FirewallModel
from .response_authorizer import ResponseAuthorizer, ResponseContext
from .schema import SchemaError, atomic_write_json, sha256_file, utc_now
from .train import FEATURES


SIMULATION_SCHEMA_VERSION = "sros2-firewall-local-simulation/v1"
DEFAULT_FEATURES = (
    Path(__file__).resolve().parent
    / "pretrain_dataset"
    / "network_features.csv"
)
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parent
    / "simulation_evidence"
    / "local_dry_run.json"
)


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1"}


def load_simulation_rows(
    path: str | Path,
    *,
    split: str,
    samples: int,
    seed: int,
) -> list[dict[str, str]]:
    """Select a deterministic, class-covering held-out synthetic sample."""
    if split not in {"validation", "test"}:
        raise ValueError("simulation split must be validation or test")
    if isinstance(samples, bool) or not 1 <= samples <= 10_000:
        raise ValueError("samples must be in 1..10000")
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise FileNotFoundError(f"invalid simulation feature file: {source}")
    with source.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = set(FEATURES) | {
            "session_id",
            "label",
            "binary",
            "origin",
            "training_eligible",
            "evaluation_eligible",
            "split",
        }
        if reader.fieldnames is None or not required <= set(reader.fieldnames):
            raise SchemaError("simulation feature file has an incomplete schema")
        by_class: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in reader:
            if row["split"] != split:
                continue
            if (
                row["origin"] != "synthetic_pretrain"
                or not _is_true(row["training_eligible"])
                or _is_true(row["evaluation_eligible"])
            ):
                raise SchemaError(
                    "local rehearsal accepts synthetic non-evaluation rows only"
                )
            by_class[row["label"]].append(row)
    if not by_class:
        raise SchemaError(f"no rows found for split={split}")

    rng = random.Random(seed)
    for rows in by_class.values():
        rng.shuffle(rows)
    ordered_classes = sorted(by_class)
    selected = []
    positions = {label: 0 for label in ordered_classes}
    while len(selected) < samples:
        progressed = False
        for label in ordered_classes:
            position = positions[label]
            rows = by_class[label]
            if position >= len(rows):
                continue
            selected.append(rows[position])
            positions[label] += 1
            progressed = True
            if len(selected) >= samples:
                break
        if not progressed:
            break
    if len(selected) < samples:
        raise SchemaError(
            f"requested {samples} rows but only {len(selected)} are available"
        )
    return selected


def run_local_simulation(
    *,
    model_path: str | Path,
    feature_csv: str | Path,
    output_path: str | Path,
    split: str = "test",
    samples: int = 46,
    seed: int = 20260803,
) -> dict[str, Any]:
    model = FirewallModel(model_path)
    training = model.bundle.get("training")
    if (
        not isinstance(training, dict)
        or training.get("data_tier") != "synthetic-pretrain"
        or training.get("deployment_eligible") is not False
    ):
        raise SchemaError(
            "offline rehearsal requires a non-deployable synthetic model"
        )
    rows = load_simulation_rows(
        feature_csv,
        split=split,
        samples=samples,
        seed=seed,
    )
    records = []
    # This deterministic key is intentionally scoped to an offline rehearsal.
    # It exercises the signed-envelope path but is never accepted by a live
    # authorizer or exported as a deployment secret.
    authority = EvidenceAuthority(
        hashlib.sha256(f"offline-simulation:{seed}".encode("utf-8")).digest(),
        collector_id="offline-simulation",
    )
    authorizer = ResponseAuthorizer(evidence_verifier=authority.verifier())
    model_hash = sha256_file(model_path)
    policy_hash = str(training["action_policy_sha256"])
    correct = 0
    simulated_blocks = 0
    for index, row in enumerate(rows):
        values = {}
        for name in FEATURES:
            try:
                value = float(row[name])
            except (TypeError, ValueError) as exc:
                raise SchemaError(f"invalid simulation feature: {name}") from exc
            if not math.isfinite(value):
                raise SchemaError(f"non-finite simulation feature: {name}")
            values[name] = value
        prediction = model.predict(values)
        decision_object = FirewallDecision(**prediction["decision"])
        source = str(row.get("source", "unknown"))
        signed_evidence = authority.issue(
            source=source,
            source_kind="network_ip",
            interface="offline-synthetic",
            identity=f"synthetic:{row['session_id']}",
            feature_digest=feature_sha256(values),
            session_id=str(row["session_id"]),
            window_id=str(row.get("window") or f"sample-{index}"),
            model_sha256=model_hash,
            policy_sha256=policy_hash,
            backend_id="offline-none",
            attribution_confidence=0.50,
            signals={"network": prediction["confidence"]},
            source_shared=False,
            confirmation_windows=1,
            decision=decision_object,
        )
        decision_object = replace(
            decision_object, evidence_id=signed_evidence.evidence_id
        )
        decision = decision_object.to_dict()
        authorization = authorizer.authorize(
            decision_object,
            ResponseContext(
                requested_mode="dry_run",
                source=source,
                source_kind="network_ip",
                requested_ttl_sec=300,
                evidence=signed_evidence,
            ),
        )
        predicted = prediction["predicted_class"]
        expected = row["label"]
        correct += int(predicted == expected)
        temporary_block = bool(
            authorization.adapter == "network_helper"
            and authorization.effective_mode == "dry_run"
        )
        simulated_blocks += int(temporary_block)
        records.append(
            {
                "sample_index": index,
                "session_id": row["session_id"],
                "expected_class": expected,
                "predicted_class": predicted,
                "correct": predicted == expected,
                "confidence": prediction["confidence"],
                "anomaly": prediction["anomaly"],
                "decision": decision,
                "authorization": authorization.to_dict(),
                "response_mode": "dry_run_intent_only",
                "temporary_ip_block_simulated": temporary_block,
                "simulated_ttl_sec": 300 if temporary_block else 0,
                "host_state_changed": False,
            }
        )
    report = {
        "schema_version": SIMULATION_SCHEMA_VERSION,
        "created_utc": utc_now(),
        "claim_scope": (
            "offline_synthetic_local_simulation_not_live_or_cross_host_evidence"
        ),
        "network_activity": "none",
        "host_firewall_modified": False,
        "model_path": str(Path(model_path)),
        "feature_csv": str(Path(feature_csv)),
        "split": split,
        "seed": seed,
        "samples": len(records),
        "classes_seen": sorted({item["expected_class"] for item in records}),
        "sample_accuracy": correct / len(records),
        "simulated_temporary_blocks": simulated_blocks,
        "records": records,
    }
    destination = Path(output_path)
    if destination.exists() and destination.is_symlink():
        raise SchemaError("simulation report may not overwrite a symlink")
    atomic_write_json(destination, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run an offline, no-packet firewall decision rehearsal"
    )
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--split", choices=("validation", "test"), default="test")
    parser.add_argument("--samples", type=int, default=46)
    parser.add_argument("--seed", type=int, default=20260803)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_local_simulation(
        model_path=args.model,
        feature_csv=args.features,
        output_path=args.output,
        split=args.split,
        samples=args.samples,
        seed=args.seed,
    )
    print(
        "local_simulation "
        f"samples={report['samples']} "
        f"classes={len(report['classes_seen'])} "
        f"accuracy={report['sample_accuracy']:.3f} "
        f"simulated_blocks={report['simulated_temporary_blocks']}"
    )
    print("network_activity=none host_firewall_modified=false")
    print(f"report={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
