#!/usr/bin/env python3
"""Report how long the most recent sessions took, for the supervisor to watch.

The mega campaign's 2026-09-19 run degraded from a ~95s session to a ~385s one
and stayed there for 103 sessions, about ten hours. The supervisor's existing
circuit breaker could not see it: that breaker counts sessions produced, and a
degraded campaign still produces sessions -- just four times slower. "Nothing is
being produced" and "everything is being produced too slowly" are different
failures, and only the first one was being watched.

This prints the median wall clock of the newest sessions so the supervisor can
watch the second. It is read-only and deliberately tiny: it reuses
``measure_campaign_throughput.load_sessions`` rather than re-deriving how a
manifest records its timestamps, because two parsers of the same field is how
the two halves of a measurement drift apart.

Exit codes are the interface:

* ``0`` -- the pace is within bounds, or there are not yet enough sessions to
  judge. Not enough data is not a failure, but it is also not a pass, so the
  reason is printed either way.
* ``4`` -- the median exceeds ``--slow-threshold-sec``.
* ``2`` -- the dataset could not be read at all.
"""

from __future__ import annotations

import argparse
import pathlib
import statistics
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL = _ROOT / "工具腳本" / "measure_campaign_throughput.py"


def _load_sessions(dataset: pathlib.Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("_campaign_throughput", _TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_sessions(dataset)


def recent_pace(dataset: pathlib.Path, window: int) -> dict:
    sessions, skipped = _load_sessions(dataset)
    recent = sessions[-window:] if window > 0 else sessions
    durations = [session["inside_sec"] for session in recent]
    return {
        "sessions_total": len(sessions),
        "sessions_considered": len(recent),
        "skipped": skipped,
        "median_sec": round(statistics.median(durations), 1) if durations else None,
        "max_sec": round(max(durations), 1) if durations else None,
        "modes": sorted({s["security_mode"] for s in recent if s["security_mode"]}),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument(
        "--window", type=int, default=10, help="how many of the newest sessions to judge"
    )
    parser.add_argument(
        "--slow-threshold-sec",
        type=float,
        default=200.0,
        help=(
            "median above this is a degraded campaign. The healthy medians are "
            "~90s enforce and ~99s permissive; the observed degraded median was "
            "385s, so 200s sits well clear of both."
        ),
    )
    parser.add_argument(
        "--minimum-sessions",
        type=int,
        default=5,
        help="below this many, report the pace but never call it slow",
    )
    args = parser.parse_args(argv)

    dataset = pathlib.Path(args.dataset).expanduser()
    if not dataset.is_dir():
        print(f"pace: dataset not found: {dataset}")
        return 2

    pace = recent_pace(dataset, args.window)
    if pace["median_sec"] is None:
        print("pace: no timed sessions yet")
        return 0

    modes = ",".join(pace["modes"]) or "unknown"
    line = (
        f"pace: newest {pace['sessions_considered']} of {pace['sessions_total']} "
        f"median={pace['median_sec']}s max={pace['max_sec']}s modes={modes} "
        f"threshold={args.slow_threshold_sec:g}s"
    )

    if pace["sessions_considered"] < args.minimum_sessions:
        print(f"{line} (too few to judge)")
        return 0
    if pace["median_sec"] > args.slow_threshold_sec:
        print(f"{line} SLOW")
        return 4
    print(f"{line} ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
