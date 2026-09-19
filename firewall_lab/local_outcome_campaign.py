#!/usr/bin/env python3
"""Build all semantic local outcome observations from fact-free markers."""

from __future__ import annotations

import argparse
from pathlib import Path

from .local_outcome_probe import derive_marked_campaign


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--telemetry", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--live-loopback-ack", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    observations = derive_marked_campaign(
        evidence_root=args.evidence_root,
        telemetry_path=args.telemetry,
        observations_path=args.observations,
        session_id=args.session_id,
        live_ack=args.live_loopback_ack,
    )
    print(
        f"semantic_campaign_observations={len(observations)} "
        f"output={args.observations}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
