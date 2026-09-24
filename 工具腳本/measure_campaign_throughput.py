#!/usr/bin/env python3
"""Measure where a campaign's wall clock goes, and what the row ceiling is.

The working hypothesis recorded on 2026-09-20 -- never measured -- was that
roughly 60% of the campaign's wall clock was per-session overhead, and that
cutting it would get the run to 100,000 feature rows. This tool replaces that
guess with a decomposition, and the guess does not survive it.

It is read-only: it reads each session's ``manifest.json`` and the artefacts
already on disk, and never re-runs, re-times or modifies a session.

What it separates
-----------------
*Between* sessions, from ``ended_utc`` to the next ``started_utc``. Gaps longer
than ``--stall-threshold-sec`` are reported apart from the rest, because a stack
restart or a supervisor stall is not per-session overhead and averaging it in is
exactly what inflates an overhead estimate. The threshold defaults to 60s, which
is longer than the longest nominal session in the shipping catalog (53s), so no
ordinary between-session work can reach it.

*Inside* a session, from ``started_utc`` to ``ended_utc``, split into the span
that actually produced observations and the part that did not. Observed span
comes from the telemetry stream and the packet capture rather than from the
catalog, because the catalog states the intent and the streams state what
happened.

Why rows and not sessions
-------------------------
The target is a row count, so the figure that matters is rows per hour. Feature
rows are fixed-width windows, so a session yields roughly its observed span
divided by the window size. That makes the ceiling arithmetic rather than
engineering: with an 8-second window, no amount of tuning beats one row per
8 seconds of observation. The report states that ceiling next to the observed
rate so the gap between them -- the only part optimisation can reach -- is
visible instead of assumed.

Sessions are grouped by ``code_revision`` as well, because a campaign that was
repaired mid-run contains more than one regime and a single median over all of
them describes none of them.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import gzip
import json
import pathlib
import statistics
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

SCHEMA = "sros2-firewall-campaign-throughput/v2"

# The live telemetry schema records wall-clock time as ts_unix_ns.
TELEMETRY_TIME_KEY = "ts_unix_ns"
PCAP_TIME_COLUMN = "frame.time_epoch"


def parse_utc(value: str) -> dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def summarise(values) -> dict:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {"count": 0}
    return {
        "count": len(ordered),
        "min": round(ordered[0], 3),
        "p25": round(ordered[len(ordered) // 4], 3),
        "median": round(statistics.median(ordered), 3),
        "p75": round(ordered[(3 * len(ordered)) // 4], 3),
        "max": round(ordered[-1], 3),
        "total": round(sum(ordered), 3),
    }


def load_sessions(dataset: pathlib.Path) -> tuple[list[dict], dict]:
    """Read every manifest that records both a start and an end."""

    sessions: list[dict] = []
    skipped: collections.Counter = collections.Counter()
    for manifest_path in sorted(dataset.glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            skipped["unreadable_manifest"] += 1
            continue
        started, ended = manifest.get("started_utc"), manifest.get("ended_utc")
        if not started or not ended:
            skipped["no_timestamps"] += 1
            continue
        try:
            start_at, end_at = parse_utc(started), parse_utc(ended)
        except ValueError:
            skipped["unparsable_timestamps"] += 1
            continue
        sessions.append({
            "session_id": manifest.get("session_id", manifest_path.parent.name),
            "directory": manifest_path.parent,
            "scenario_id": manifest.get("scenario_id"),
            "attack_class": manifest.get("attack_class"),
            "security_mode": manifest.get("security_mode"),
            "code_revision": manifest.get("code_revision"),
            "status": manifest.get("status"),
            "started": start_at,
            "ended": end_at,
            "inside_sec": (end_at - start_at).total_seconds(),
        })
    sessions.sort(key=lambda item: item["started"])
    return sessions, dict(skipped)


def telemetry_span(path: pathlib.Path) -> tuple[float, float] | None:
    """First and last telemetry event, in epoch seconds."""

    first = last = None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                value = event.get(TELEMETRY_TIME_KEY)
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    continue
                seconds = float(value) / 1_000_000_000.0
                if first is None:
                    first = seconds
                last = seconds
    except OSError:
        return None
    if first is None or last is None:
        return None
    return first, last


def pcap_span(path: pathlib.Path) -> tuple[float, float] | None:
    """First and last captured packet, in epoch seconds."""

    first = last = None
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            header = handle.readline().rstrip("\n").split("\t")
            if PCAP_TIME_COLUMN not in header:
                return None
            column = header.index(PCAP_TIME_COLUMN)
            for line in handle:
                fields = line.rstrip("\n").split("\t")
                if len(fields) <= column:
                    continue
                try:
                    value = float(fields[column])
                except ValueError:
                    continue
                if first is None:
                    first = value
                last = value
    except OSError:
        return None
    if first is None or last is None:
        return None
    return first, last


def classify_gaps(sessions: list[dict], stall_threshold_sec: float) -> dict:
    """Split inter-session gaps into routine overhead and stalls.

    An absolute threshold is used rather than a multiple of the median. The
    median gap in a healthy campaign is a fraction of a second, so any
    multiplicative rule classifies ordinary jitter as a restart and makes the
    overhead figure meaningless. A fixed bound longer than the longest nominal
    session cannot be reached by ordinary between-session work.
    """

    routine: list[float] = []
    stalls: list[dict] = []
    for index, (earlier, later) in enumerate(zip(sessions, sessions[1:])):
        seconds = (later["started"] - earlier["ended"]).total_seconds()
        if seconds > stall_threshold_sec:
            stalls.append({
                "after_index": index,
                "seconds": round(seconds, 3),
                "resumed_at_utc": later["started"].isoformat(),
            })
        else:
            routine.append(seconds)
    return {
        "threshold_sec": stall_threshold_sec,
        "routine_sec": routine,
        "stalls": stalls,
    }


def measure_observation(
    sessions: list[dict], sample: int, window_sec: float
) -> dict:
    """Split inside-session time into observed span and everything else."""

    inside, observed, lead, tail, captured, windows = [], [], [], [], [], []
    measured = 0
    for session in sessions[:sample] if sample > 0 else sessions:
        inside.append(session["inside_sec"])
        span = telemetry_span(session["directory"] / "telemetry_events.jsonl")
        if span is not None:
            first, last = span
            observed.append(last - first)
            lead.append(first - session["started"].timestamp())
            tail.append(session["ended"].timestamp() - last)
            windows.append((last - first) / window_sec)
            measured += 1
        capture = pcap_span(session["directory"] / "packet_windows" / "packets.tsv.gz")
        if capture is not None:
            captured.append(capture[1] - capture[0])
    return {
        "sampled_sessions": len(inside),
        "sessions_with_telemetry_span": measured,
        "inside_sec": summarise(inside),
        "telemetry_observed_sec": summarise(observed),
        "lead_in_sec": summarise(lead),
        "tail_after_last_event_sec": summarise(tail),
        "pcap_observed_sec": summarise(captured),
        "windows_per_session": summarise(windows),
    }


def throughput(observation: dict, window_sec: float, targets: list[int]) -> dict:
    inside = observation["inside_sec"].get("median")
    windows = observation["windows_per_session"].get("median")
    if not inside or not windows:
        return {"measurable": False}
    observed = observation["telemetry_observed_sec"].get("median") or 0.0
    rows_per_hour = windows / (inside / 3600.0)
    ceiling = 3600.0 / window_sec
    return {
        "measurable": True,
        "window_sec": window_sec,
        "observed_share_of_wall_clock": round(observed / inside, 4),
        "rows_per_session": round(windows, 2),
        "rows_per_hour": round(rows_per_hour, 1),
        "rows_per_hour_ceiling": round(ceiling, 1),
        "fraction_of_ceiling_reached": round(rows_per_hour / ceiling, 4),
        "targets": {
            str(target): {
                "hours_at_observed_rate": round(target / rows_per_hour, 1),
                "days_at_observed_rate": round(target / rows_per_hour / 24.0, 2),
                "hours_at_ceiling": round(target / ceiling, 1),
            }
            for target in targets
        },
    }


def per_revision(sessions: list[dict]) -> dict:
    """Group by code_revision, in order of first appearance.

    A campaign repaired mid-run contains more than one regime; a single median
    over all of them describes none of them.
    """

    order: list[str] = []
    grouped: dict[str, list[dict]] = collections.defaultdict(list)
    for index, session in enumerate(sessions):
        revision = session["code_revision"] or "unknown"
        if revision not in grouped:
            order.append(revision)
        grouped[revision].append({"index": index, **session})
    result = {}
    for revision in order:
        entries = grouped[revision]
        by_mode = {}
        for mode in sorted({e["security_mode"] for e in entries if e["security_mode"]}):
            by_mode[mode] = summarise(
                e["inside_sec"] for e in entries if e["security_mode"] == mode
            )
        result[revision] = {
            "first_index": entries[0]["index"],
            "last_index": entries[-1]["index"],
            "sessions": len(entries),
            "inside_sec": summarise(e["inside_sec"] for e in entries),
            "inside_sec_by_mode": by_mode,
        }
    return result


def build_report(
    dataset: pathlib.Path,
    *,
    window_sec: float,
    stall_threshold_sec: float,
    sample: int,
    targets: list[int],
) -> dict:
    sessions, skipped = load_sessions(dataset)
    if len(sessions) < 2:
        raise SystemExit("need at least two timed sessions to measure overhead")

    gaps = classify_gaps(sessions, stall_threshold_sec)
    inside_total = sum(session["inside_sec"] for session in sessions)
    routine_total = sum(gaps["routine_sec"])
    stall_total = sum(stall["seconds"] for stall in gaps["stalls"])
    span = (sessions[-1]["ended"] - sessions[0]["started"]).total_seconds()

    observation = measure_observation(sessions, sample, window_sec)

    return {
        "schema_version": SCHEMA,
        "dataset": str(dataset),
        "sessions_measured": len(sessions),
        "sessions_skipped": skipped,
        "first_started_utc": sessions[0]["started"].isoformat(),
        "last_ended_utc": sessions[-1]["ended"].isoformat(),
        "wall_clock": {
            "span_sec": round(span, 3),
            "inside_sessions_sec": round(inside_total, 3),
            "routine_between_sessions_sec": round(routine_total, 3),
            "stalls_sec": round(stall_total, 3),
            "unattributed_sec": round(span - inside_total - routine_total - stall_total, 3),
            "inside_share": round(inside_total / span, 4) if span else None,
            "routine_between_sessions_share": round(routine_total / span, 4) if span else None,
            "stall_share": round(stall_total / span, 4) if span else None,
        },
        "inside_session_sec": summarise(s["inside_sec"] for s in sessions),
        "routine_gap_sec": summarise(gaps["routine_sec"]),
        "stalls": {
            "threshold_sec": gaps["threshold_sec"],
            "count": len(gaps["stalls"]),
            "longest_sec": max((s["seconds"] for s in gaps["stalls"]), default=0.0),
            "detail": gaps["stalls"][:50],
        },
        "observation": observation,
        "throughput": throughput(observation, window_sec, targets),
        "per_code_revision": per_revision(sessions),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--window-sec",
        type=float,
        default=8.0,
        help="feature window size; must match features.py --window-sec",
    )
    parser.add_argument(
        "--stall-threshold-sec",
        type=float,
        default=60.0,
        help="a gap longer than this is a stall or restart, not per-session overhead",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=60,
        help="sessions to read artefacts from; 0 reads them all (slow)",
    )
    parser.add_argument("--target", type=int, action="append", default=[])
    args = parser.parse_args(argv)

    dataset = pathlib.Path(args.dataset).expanduser()
    if not dataset.is_dir():
        raise SystemExit(f"dataset directory not found: {dataset}")
    if args.window_sec <= 0:
        raise SystemExit("--window-sec must be positive")

    report = build_report(
        dataset,
        window_sec=args.window_sec,
        stall_threshold_sec=args.stall_threshold_sec,
        sample=args.sample,
        targets=args.target or [100_000],
    )

    output = pathlib.Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(f"report: {output}")
    print(json.dumps(report["wall_clock"], indent=2, sort_keys=True))
    print(json.dumps(report["throughput"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
