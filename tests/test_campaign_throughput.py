"""Bounds for the campaign throughput measurement.

The figure this tool replaces -- "60% of the wall clock is per-session
overhead", recorded on 2026-09-20 -- came from comparing two medians by eye and
was wrong by an order of magnitude. The tests here exist so the replacement
cannot drift back into a story: each one fixes a number that a plausible-looking
reimplementation would get wrong.

Two of them matter more than the rest:

* a multiplicative outlier rule is wrong here, because the median gap in a
  healthy campaign is a fraction of a second and three times nearly nothing is
  still nearly nothing. The threshold has to be absolute.
* the row ceiling is arithmetic, not engineering: with a fixed window size, no
  amount of tuning yields more than one row per window-length of observation.
  A tool that reports a rate without that ceiling invites the same mistake
  again.
"""

from __future__ import annotations

import datetime as dt
import gzip
import importlib.util
import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL_PATH = _ROOT / "工具腳本" / "measure_campaign_throughput.py"


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("_campaign_throughput", _TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EPOCH = dt.datetime(2026, 9, 24, 0, 0, 0, tzinfo=dt.timezone.utc)


def _write_session(
    root: pathlib.Path,
    name: str,
    *,
    start_offset: float,
    inside_sec: float,
    observed_sec: float | None = None,
    lead_in_sec: float = 0.3,
    mode: str = "enforce",
    revision: str = "rev-a",
    event_count: int = 5,
) -> pathlib.Path:
    """Create one synthetic session directory the tool can read."""

    start = EPOCH + dt.timedelta(seconds=start_offset)
    end = start + dt.timedelta(seconds=inside_sec)
    directory = root / name
    (directory / "packet_windows").mkdir(parents=True)

    (directory / "manifest.json").write_text(
        json.dumps({
            "session_id": name,
            "started_utc": start.isoformat().replace("+00:00", "Z"),
            "ended_utc": end.isoformat().replace("+00:00", "Z"),
            "security_mode": mode,
            "code_revision": revision,
            "attack_class": "normal",
            "scenario_id": "normal_patrol",
            "status": "complete",
        }),
        encoding="utf-8",
    )

    if observed_sec is not None:
        first = start.timestamp() + lead_in_sec
        step = observed_sec / max(event_count - 1, 1)
        lines = [
            json.dumps({
                "event_type": "collector_tick",
                "ts_unix_ns": int((first + index * step) * 1_000_000_000),
            })
            for index in range(event_count)
        ]
        (directory / "telemetry_events.jsonl").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )

        packets = directory / "packet_windows" / "packets.tsv.gz"
        with gzip.open(packets, "wt", encoding="utf-8") as handle:
            handle.write("frame.time_epoch\tip.src\tframe.len\n")
            for index in range(event_count):
                handle.write(f"{first + index * step:.6f}\t10.0.0.1\t100\n")

    return directory


# ── the gap classifier ───────────────────────────────────────────────────────


def test_sub_second_gaps_are_routine_not_restarts(tool, tmp_path):
    """The defect a multiplicative rule would reintroduce.

    A healthy campaign's median gap is ~0.24s. Under a "three times the median"
    rule the threshold lands under a second and ordinary jitter is booked as a
    stack restart, which is how a 1% overhead becomes a 60% one.
    """
    sessions = []
    offset = 0.0
    for index in range(6):
        sessions.append(_write_session(
            tmp_path, f"s{index:02d}", start_offset=offset, inside_sec=90.0,
            observed_sec=87.0,
        ))
        # Gaps of 0.2s, 0.9s, 0.2s ... all ordinary, none a restart.
        offset += 90.0 + (0.9 if index % 2 else 0.2)

    loaded, _ = tool.load_sessions(tmp_path)
    gaps = tool.classify_gaps(loaded, stall_threshold_sec=60.0)
    assert gaps["stalls"] == []
    assert len(gaps["routine_sec"]) == 5
    assert max(gaps["routine_sec"]) < 1.0


def test_a_real_stall_is_separated_out(tool, tmp_path):
    _write_session(tmp_path, "s00", start_offset=0.0, inside_sec=90.0, observed_sec=87.0)
    _write_session(tmp_path, "s01", start_offset=90.3, inside_sec=90.0, observed_sec=87.0)
    # 40 minutes of nothing: a supervisor stall, not per-session overhead.
    _write_session(tmp_path, "s02", start_offset=2580.0, inside_sec=90.0, observed_sec=87.0)

    loaded, _ = tool.load_sessions(tmp_path)
    gaps = tool.classify_gaps(loaded, stall_threshold_sec=60.0)
    assert len(gaps["stalls"]) == 1
    assert gaps["stalls"][0]["seconds"] == pytest.approx(2400.0, abs=1.0)
    assert len(gaps["routine_sec"]) == 1


def test_the_threshold_exceeds_the_longest_nominal_session(tool):
    """60s is chosen so ordinary between-session work cannot reach it.

    The shipping catalog's longest session is warmup + duration + cooldown =
    53s, so a 60s gap cannot be a session running long.
    """
    catalog = json.loads(
        (_ROOT / "firewall_lab" / "scenarios.json").read_text(encoding="utf-8")
    )
    scenarios = catalog["scenarios"] if isinstance(catalog, dict) else catalog
    longest = max(
        s["warmup_sec"] + s["duration_sec"] + s["cooldown_sec"] for s in scenarios
    )
    parser_default = 60.0
    assert longest < parser_default, f"catalog now reaches {longest}s"


# ── the row ceiling is arithmetic ────────────────────────────────────────────


def test_rows_per_hour_cannot_exceed_one_window_per_window_length(tool, tmp_path):
    """A session observed end to end still yields only span / window_sec rows."""
    _write_session(
        tmp_path, "s00", start_offset=0.0, inside_sec=80.0, observed_sec=80.0,
        lead_in_sec=0.0, event_count=9,
    )
    _write_session(
        tmp_path, "s01", start_offset=80.0, inside_sec=80.0, observed_sec=80.0,
        lead_in_sec=0.0, event_count=9,
    )
    report = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )
    throughput = report["throughput"]
    assert throughput["rows_per_session"] == pytest.approx(10.0, abs=0.01)
    assert throughput["rows_per_hour_ceiling"] == 450.0
    assert throughput["rows_per_hour"] <= throughput["rows_per_hour_ceiling"] + 1e-6
    assert throughput["fraction_of_ceiling_reached"] == pytest.approx(1.0, abs=0.01)


def test_halving_the_window_doubles_the_ceiling(tool, tmp_path):
    """Stated explicitly because it is the one lever that looks free and is not.

    More rows from a shorter window are more correlated rows, not more evidence.
    """
    _write_session(
        tmp_path, "s00", start_offset=0.0, inside_sec=80.0, observed_sec=80.0,
        lead_in_sec=0.0, event_count=9,
    )
    _write_session(
        tmp_path, "s01", start_offset=80.0, inside_sec=80.0, observed_sec=80.0,
        lead_in_sec=0.0, event_count=9,
    )
    eight = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["throughput"]
    four = tool.build_report(
        tmp_path, window_sec=4.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["throughput"]
    assert four["rows_per_hour_ceiling"] == 2 * eight["rows_per_hour_ceiling"]
    assert four["rows_per_session"] == pytest.approx(2 * eight["rows_per_session"], rel=0.01)


def test_overhead_lowers_the_rate_below_the_ceiling(tool, tmp_path):
    """A session that spends time not observing falls short, measurably."""
    for index in range(2):
        _write_session(
            tmp_path, f"s{index:02d}", start_offset=index * 100.0,
            inside_sec=100.0, observed_sec=80.0, lead_in_sec=0.0, event_count=9,
        )
    throughput = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["throughput"]
    assert throughput["observed_share_of_wall_clock"] == pytest.approx(0.8, abs=0.01)
    assert throughput["rows_per_hour"] == pytest.approx(360.0, rel=0.02)


# ── the observation split ────────────────────────────────────────────────────


def test_lead_in_and_tail_are_measured_separately(tool, tmp_path):
    _write_session(
        tmp_path, "s00", start_offset=0.0, inside_sec=100.0, observed_sec=80.0,
        lead_in_sec=2.0, event_count=9,
    )
    _write_session(
        tmp_path, "s01", start_offset=100.0, inside_sec=100.0, observed_sec=80.0,
        lead_in_sec=2.0, event_count=9,
    )
    observation = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["observation"]
    assert observation["lead_in_sec"]["median"] == pytest.approx(2.0, abs=0.05)
    assert observation["tail_after_last_event_sec"]["median"] == pytest.approx(18.0, abs=0.05)


def test_a_session_without_telemetry_does_not_depress_the_rate(tool, tmp_path):
    """A missing file must not silently count as zero rows."""
    _write_session(
        tmp_path, "s00", start_offset=0.0, inside_sec=90.0, observed_sec=88.0,
        lead_in_sec=0.0, event_count=9,
    )
    _write_session(tmp_path, "s01", start_offset=90.0, inside_sec=90.0, observed_sec=None)
    observation = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["observation"]
    assert observation["sampled_sessions"] == 2
    assert observation["sessions_with_telemetry_span"] == 1
    assert observation["windows_per_session"]["count"] == 1
    assert observation["windows_per_session"]["median"] == pytest.approx(11.0, abs=0.01)


def test_pcap_and_telemetry_spans_are_reported_independently(tool, tmp_path):
    """Two sources for the same quantity; disagreement should be visible."""
    for index in range(2):
        _write_session(
            tmp_path, f"s{index:02d}", start_offset=index * 90.0, inside_sec=90.0,
            observed_sec=80.0, lead_in_sec=0.0, event_count=9,
        )
    observation = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["observation"]
    assert observation["telemetry_observed_sec"]["median"] == pytest.approx(80.0, abs=0.1)
    assert observation["pcap_observed_sec"]["median"] == pytest.approx(80.0, abs=0.1)


# ── regimes must not be averaged together ────────────────────────────────────


def test_revisions_are_reported_separately(tool, tmp_path):
    """A campaign repaired mid-run holds two regimes; one median describes neither."""
    for index in range(4):
        _write_session(
            tmp_path, f"a{index:02d}", start_offset=index * 400.0, inside_sec=380.0,
            observed_sec=370.0, revision="rev-slow",
        )
    for index in range(4):
        _write_session(
            tmp_path, f"b{index:02d}", start_offset=1600.0 + index * 100.0,
            inside_sec=90.0, observed_sec=87.0, revision="rev-fast",
        )
    revisions = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["per_code_revision"]
    assert list(revisions) == ["rev-slow", "rev-fast"]
    assert revisions["rev-slow"]["inside_sec"]["median"] == pytest.approx(380.0, abs=0.1)
    assert revisions["rev-fast"]["inside_sec"]["median"] == pytest.approx(90.0, abs=0.1)
    assert revisions["rev-slow"]["last_index"] < revisions["rev-fast"]["first_index"]


def test_modes_are_split_within_a_revision(tool, tmp_path):
    """Enforce and permissive differed by 2.5x in the real data."""
    for index in range(3):
        _write_session(
            tmp_path, f"e{index:02d}", start_offset=index * 250.0, inside_sec=230.0,
            observed_sec=225.0, mode="enforce",
        )
    for index in range(3):
        _write_session(
            tmp_path, f"p{index:02d}", start_offset=750.0 + index * 110.0,
            inside_sec=100.0, observed_sec=95.0, mode="permissive",
        )
    by_mode = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["per_code_revision"]["rev-a"]["inside_sec_by_mode"]
    assert by_mode["enforce"]["median"] == pytest.approx(230.0, abs=0.1)
    assert by_mode["permissive"]["median"] == pytest.approx(100.0, abs=0.1)


# ── the tool must not touch the dataset ──────────────────────────────────────


def test_the_measurement_is_read_only(tool, tmp_path):
    for index in range(2):
        _write_session(
            tmp_path, f"s{index:02d}", start_offset=index * 90.0, inside_sec=90.0,
            observed_sec=87.0,
        )
    before = {
        path: (path.stat().st_size, path.stat().st_mtime_ns)
        for path in sorted(tmp_path.rglob("*")) if path.is_file()
    }
    tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )
    after = {
        path: (path.stat().st_size, path.stat().st_mtime_ns)
        for path in sorted(tmp_path.rglob("*")) if path.is_file()
    }
    assert before == after


def test_a_dataset_with_one_session_is_refused(tool, tmp_path):
    _write_session(tmp_path, "s00", start_offset=0.0, inside_sec=90.0, observed_sec=87.0)
    with pytest.raises(SystemExit, match="at least two"):
        tool.build_report(
            tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
        )


def test_unreadable_manifests_are_counted_not_ignored(tool, tmp_path):
    for index in range(2):
        _write_session(
            tmp_path, f"s{index:02d}", start_offset=index * 90.0, inside_sec=90.0,
            observed_sec=87.0,
        )
    broken = tmp_path / "s99"
    broken.mkdir()
    (broken / "manifest.json").write_text("{not json", encoding="utf-8")
    no_times = tmp_path / "s98"
    no_times.mkdir()
    (no_times / "manifest.json").write_text(json.dumps({"session_id": "s98"}), encoding="utf-8")

    report = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )
    assert report["sessions_measured"] == 2
    assert report["sessions_skipped"] == {"unreadable_manifest": 1, "no_timestamps": 1}


def test_wall_clock_shares_account_for_the_whole_span(tool, tmp_path):
    """Nothing may be quietly dropped; unattributed time is reported as such."""
    _write_session(tmp_path, "s00", start_offset=0.0, inside_sec=90.0, observed_sec=87.0)
    _write_session(tmp_path, "s01", start_offset=90.5, inside_sec=90.0, observed_sec=87.0)
    _write_session(tmp_path, "s02", start_offset=1000.0, inside_sec=90.0, observed_sec=87.0)
    wall = tool.build_report(
        tmp_path, window_sec=8.0, stall_threshold_sec=60.0, sample=0, targets=[100]
    )["wall_clock"]
    assert wall["unattributed_sec"] == pytest.approx(0.0, abs=0.01)
    total = (
        wall["inside_share"] + wall["routine_between_sessions_share"] + wall["stall_share"]
    )
    assert total == pytest.approx(1.0, abs=0.001)
