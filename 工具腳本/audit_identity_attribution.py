#!/usr/bin/env python3
"""Create a passive, fail-closed identity-attribution readiness report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.identity_attribution import (  # noqa: E402
    audit_identity_attribution_readiness,
)
from firewall_lab.schema import atomic_write_json  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing to overwrite report: {args.output}")
    report = audit_identity_attribution_readiness(args.dataset)
    atomic_write_json(args.output, report)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": report["status"],
                "sessions": report["counts"]["sessions"],
                "source_ip_attribution_verified": False,
                "deployment_eligible": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
