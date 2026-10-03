#!/usr/bin/env python3
"""Derive the adaptive attacker's blindness for sessions already on disk.

## Why this exists separately from the manifest

`orchestrator.py` now records `adaptive_observer` in the manifest, but two
project rules mean that does not cover what is already on disk:

* **Existing manifests are not back-filled** (C2C-069, C2C-085). A manifest
  records the verdict that was made at the time; rewriting it would put it out
  of step with its own `code_revision`.
* The running campaign imported `orchestrator` when it started, so the new
  field only appears after the next restart -- and restarting to add a field
  would cost live progress for no evidence.

The evidence is already in `attack.stdout.log`, so derive it read-only instead.
This is the same shape as `zeek_checksum_fixed/` (C2C-050) and `crosscheck_v2.json`
(C2C-079): a parallel artifact, originals untouched.

## What it is for

Measured across dataset_mega on 2026-10-03: `insider_parameter_write` 22/22
and `insider_hmac_forgery` 17/17 ran blind, every other scenario 0/790. So the
label "adaptive attacker" has never held for the two credentialed-insider
classes -- and those are the two that only exist under Enforce, that carry the
`identity signal = 0 implies normal` blind spot, and that the whole insider
threat-model argument rests on.

The blindness itself is the threat model working: a thief of node X's
credentials cannot also be `n37_probe`, so the observer's secure node creation
fails closed. Partial credentials are stricter than none at all -- an external
attacker has no keystore, so security never engages and `Node()` succeeds.

## What it deliberately does not do

* **It does not write to any session directory.** Originals stay byte-identical.
* **It does not re-implement the parser.** It imports
  `_read_adaptive_blindness` from the orchestrator, so the audit cannot drift
  from what the manifest will record (the failure mode C2C-060 names: a second
  implementation that slowly disagrees with the first).
* **It does not judge eligibility.** `blind` is an observation; whether it
  should affect the training gate is a decision about pass criteria.

Usage:

    python3 工具腳本/audit_adaptive_blindness.py \\
        --dataset ~/dataset_mega \\
        --output 文件/自適應盲打稽核_<date>.json
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from firewall_lab.orchestrator import _read_adaptive_blindness  # noqa: E402

SCHEMA = "sros2-firewall-adaptive-blindness-audit/v1"


def _scenario_of(manifest: dict) -> str:
    return str(
        manifest.get("scenario_id")
        or manifest.get("attack_class")
        or "unknown"
    )


def audit(dataset: Path) -> dict:
    """Walk a dataset and derive the flag for every complete session."""
    per_scenario: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    per_mode: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    reasons: collections.Counter = collections.Counter()
    blind_sessions: list[dict] = []
    sessions = 0

    for path in sorted(dataset.glob("*/manifest.json")):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            reasons["unreadable_manifest"] += 1
            continue
        if manifest.get("status") != "complete":
            continue
        sessions += 1

        scenario = _scenario_of(manifest)
        mode = str(manifest.get("security_mode") or "unknown")

        # The flag lives at manifest["randomization"]["adaptive"], not at the
        # top level -- the first version of this tool read the top level and
        # reported "not_adaptive" for all 2,053 sessions, which is the same
        # failure this whole exercise is about: a lookup that cannot succeed
        # returning the reassuring answer.
        #
        # So an absent field is `unknown`, never `not_adaptive`. The two mean
        # different things: one is "this runner has no decision trace by
        # construction", the other is "the record moved and we cannot tell".
        randomization = manifest.get("randomization")
        if not isinstance(randomization, dict) or "adaptive" not in randomization:
            per_scenario[scenario]["unknown"] += 1
            per_mode[mode]["unknown"] += 1
            reasons["adaptive_flag_absent_from_manifest"] += 1
            continue
        adaptive = bool(randomization["adaptive"])

        attack_result = (manifest.get("result") or {}).get("attack_process")
        verdict = _read_adaptive_blindness(
            path.parent, adaptive=adaptive, attack_result=attack_result
        )
        status = str(verdict["status"])
        per_scenario[scenario][status] += 1
        per_mode[mode][status] += 1
        if status == "observed":
            key = "blind" if verdict["blind"] else "sighted"
            per_scenario[scenario][key] += 1
            per_mode[mode][key] += 1
            if verdict["blind"]:
                blind_sessions.append({
                    "session": path.parent.name,
                    "scenario": scenario,
                    "security_mode": mode,
                    "blind_steps": verdict.get("blind_steps"),
                    "total_steps": verdict.get("total_steps"),
                    "observer_error": verdict.get("observer_error"),
                })
        else:
            reasons[str(verdict.get("reason"))] += 1

    observed = sum(c["observed"] for c in per_scenario.values())
    blind = sum(c["blind"] for c in per_scenario.values())
    return {
        "schema": SCHEMA,
        "dataset": str(dataset),
        "sessions_complete": sessions,
        "determinable": observed,
        "blind": blind,
        "blind_rate_of_determinable": (
            round(blind / observed, 4) if observed else None
        ),
        # Kept explicit: these are the sessions we cannot tell about, and that
        # count is the honest limit on every claim made from this audit.
        "undeterminable": sessions - observed,
        "undeterminable_reasons": dict(sorted(reasons.items())),
        "per_scenario": {
            name: dict(sorted(counts.items()))
            for name, counts in sorted(per_scenario.items())
        },
        "per_security_mode": {
            name: dict(sorted(counts.items()))
            for name, counts in sorted(per_mode.items())
        },
        "blind_sessions": blind_sessions,
        "wrote_to_session_directories": False,
        "affects_training_gate": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if not args.dataset.is_dir():
        parser.error(f"dataset not found: {args.dataset}")
    if args.output.exists():
        parser.error(
            f"output already exists: {args.output}. "
            "Refusing to overwrite an audit someone may have cited."
        )

    report = audit(args.dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"complete sessions   : {report['sessions_complete']}")
    print(f"determinable        : {report['determinable']}")
    print(f"blind               : {report['blind']}"
          f"  ({report['blind_rate_of_determinable']} of determinable)")
    print(f"undeterminable      : {report['undeterminable']}")
    for reason, count in report["undeterminable_reasons"].items():
        print(f"    {reason:<28} {count}")
    print("\nscenarios with any blind session:")
    for name, counts in report["per_scenario"].items():
        if counts.get("blind"):
            print(f"    {name:<28} blind {counts['blind']}"
                  f"/{counts.get('observed', 0)}")
    print(f"\nwrote: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
