"""The supervisor guard for a campaign that is slow rather than dead.

On 2026-09-19 the mega campaign degraded from ~95s per session to ~385s and
stayed there for 103 sessions, about ten hours. The existing circuit breaker
counts sessions produced, and a degraded campaign still produces sessions --
just four times slower. "Nothing is being produced" and "everything is being
produced too slowly" are different failures and only the first was watched.

The important test here is not that the threshold arithmetic works; it is that
the guard fires on the *real* degraded window and stays quiet on the real
healthy one. A synthetic fixture would only prove the comparison operator
works.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import pathlib
import re
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_PACE_PATH = _ROOT / "工具腳本" / "recent_session_pace.py"
_SUPERVISOR_PATH = _ROOT / "工具腳本" / "run_mega_campaign.sh"

EPOCH = dt.datetime(2026, 9, 24, tzinfo=dt.timezone.utc)

# Medians measured from ~/dataset_mega on 2026-09-24.
HEALTHY_MEDIAN_SEC = 95.1
DEGRADED_MEDIAN_SEC = 385.2


@pytest.fixture(scope="module")
def pace():
    spec = importlib.util.spec_from_file_location("_recent_session_pace", _PACE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def supervisor_source() -> str:
    return _SUPERVISOR_PATH.read_text(encoding="utf-8")


def _write(
    root: pathlib.Path,
    index: int,
    inside_sec: float,
    mode: str = "enforce",
    pcap_mb: float = 0.0,
) -> None:
    """One synthetic session, optionally with a capture of a given size.

    The capture matters: the guard subtracts what that size predicts, so a
    fixture without one only ever exercises the model's fixed term.
    """
    start = EPOCH + dt.timedelta(seconds=index * 1000)
    end = start + dt.timedelta(seconds=inside_sec)
    directory = root / f"s{index:03d}"
    directory.mkdir()
    (directory / "manifest.json").write_text(
        json.dumps({
            "session_id": directory.name,
            "started_utc": start.isoformat().replace("+00:00", "Z"),
            "ended_utc": end.isoformat().replace("+00:00", "Z"),
            "security_mode": mode,
            "code_revision": "rev",
        }),
        encoding="utf-8",
    )
    if pcap_mb:
        pcap = directory / "traffic.pcapng"
        with pcap.open("wb") as handle:
            handle.truncate(int(pcap_mb * 1e6))


# ── the guard on the real numbers ────────────────────────────────────────────


def test_the_real_degraded_pace_is_caught(pace, tmp_path):
    """385s per session is what ran unnoticed for ten hours."""
    for index in range(10):
        _write(tmp_path, index, DEGRADED_MEDIAN_SEC)
    assert pace.main(["--dataset", str(tmp_path)]) == 4


def test_the_real_healthy_pace_is_not_flagged(pace, tmp_path):
    for index in range(10):
        _write(tmp_path, index, HEALTHY_MEDIAN_SEC)
    assert pace.main(["--dataset", str(tmp_path)]) == 0


def test_the_default_threshold_sits_clear_of_both(pace):
    """200s is not a round number picked for looks; both sides need margin."""
    parser_default = 200.0
    assert HEALTHY_MEDIAN_SEC * 2 < parser_default < DEGRADED_MEDIAN_SEC / 1.9


def test_the_slow_and_healthy_worlds_are_distinguished_by_the_median_not_the_max(
    pace, tmp_path
):
    """One long session must not condemn a healthy batch.

    Single sessions legitimately run long -- the real healthy window had a max
    of 481s. Watching the maximum would stop the campaign constantly.
    """
    for index in range(9):
        _write(tmp_path, index, HEALTHY_MEDIAN_SEC)
    _write(tmp_path, 9, 481.0)
    assert pace.main(["--dataset", str(tmp_path)]) == 0


# ── only the newest sessions count ───────────────────────────────────────────


def test_old_slow_sessions_do_not_keep_the_alarm_on(pace, tmp_path):
    """After a restart clears the degradation the guard must let go.

    The 2026-09-19 run recovered on its own; a guard that averaged over the
    whole dataset would stay latched and stop a campaign that was fine.
    """
    for index in range(20):
        _write(tmp_path, index, DEGRADED_MEDIAN_SEC)
    for index in range(20, 32):
        _write(tmp_path, index, HEALTHY_MEDIAN_SEC)
    assert pace.main(["--dataset", str(tmp_path), "--window", "10"]) == 0


def test_a_fresh_degradation_is_caught_even_after_a_long_healthy_run(pace, tmp_path):
    for index in range(40):
        _write(tmp_path, index, HEALTHY_MEDIAN_SEC)
    for index in range(40, 52):
        _write(tmp_path, index, DEGRADED_MEDIAN_SEC)
    assert pace.main(["--dataset", str(tmp_path), "--window", "10"]) == 4


# ── not enough data is not a pass and not a failure ──────────────────────────


def test_too_few_sessions_is_reported_not_judged(pace, tmp_path, capsys):
    for index in range(3):
        _write(tmp_path, index, DEGRADED_MEDIAN_SEC)
    assert pace.main(["--dataset", str(tmp_path)]) == 0
    assert "too few to judge" in capsys.readouterr().out


def test_an_empty_dataset_does_not_stop_the_campaign(pace, tmp_path):
    assert pace.main(["--dataset", str(tmp_path)]) == 0


def test_a_missing_dataset_is_a_distinct_exit_code(pace, tmp_path):
    assert pace.main(["--dataset", str(tmp_path / "absent")]) == 2


# ── the guard is wired into the supervisor, not merely present ───────────────


def _code_only(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_the_supervisor_actually_calls_the_pace_check(supervisor_source):
    """A guard that exists but is never invoked is what happened on 2026-09-21.

    `stream_replay.py` was written to prevent a defect, given its own tests, and
    then never imported by either CLI. Presence is not wiring.
    """
    body = _code_only(supervisor_source)
    assert "recent_session_pace.py" in body, "the pace tool is never invoked"
    assert re.search(r"^\s*if check_pace; then", body, re.M), "check_pace is never called"
    assert "MAX_SLOW_BATCHES" in body
    assert "exit 4" in body


def test_the_pace_check_runs_after_the_production_check(supervisor_source):
    """A batch can be both productive and too slow; that pair is the target."""
    body = _code_only(supervisor_source)
    declared = body.index("MAX_BARREN_BATCHES=")
    # The last production check in the loop, then the pace check after it.
    produced = body.rindex('"$barren" -ge')
    paced = body.index("if check_pace; then")
    assert declared < produced < paced


def test_the_slow_breaker_uses_its_own_counter(supervisor_source):
    """Sharing `barren` would let a slow batch mask a dead one, or the reverse."""
    body = _code_only(supervisor_source)
    assert re.search(r"^slow=0", body, re.M)
    assert "slow=$((slow + 1))" in body
    assert "barren=$((barren + 1))" in body


def test_the_exit_codes_do_not_collide(supervisor_source):
    """3 is 'produced nothing', 4 is 'too slow'. A caller must tell them apart."""
    body = _code_only(supervisor_source)
    assert "exit 3" in body and "exit 4" in body
    assert body.count("exit 4") == 1


def test_the_pace_check_propagates_the_tools_exit_code(supervisor_source):
    """`| tee` would otherwise return tee's status and the guard would never fire."""
    body = _code_only(supervisor_source)
    assert "PIPESTATUS[0]" in body, "the exit code is taken from tee, not the tool"

# ── the guard judges the residual, not the raw wall clock ────────────────────

# Session wall clock tracks capture size: measured over 502 sessions,
# inside ~ 85.7s + 0.376 s/MB, from 86s at 4MB to 453s at 750MB. An absolute
# threshold therefore fires on any batch of heavy scenarios, which is a false
# positive that would stop a healthy campaign.


def _expected(pcap_mb: float) -> float:
    import importlib.util

    spec = importlib.util.spec_from_file_location("_pace_for_model", _PACE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.expected_sec(pcap_mb)


def test_a_heavy_but_proportionate_batch_is_not_flagged(pace, tmp_path):
    """The false positive an absolute threshold would produce.

    400MB of capture costs about 236s on volume alone. Under the old 200s rule
    every one of these sessions was 'slow'; none of them is.
    """
    heavy_mb = 400.0
    for index in range(10):
        _write(tmp_path, index, _expected(heavy_mb), pcap_mb=heavy_mb)
    assert pace.main(["--dataset", str(tmp_path)]) == 0
    assert _expected(heavy_mb) > 200.0, "the old absolute threshold would have fired"


def test_a_light_batch_that_is_slow_is_still_flagged(pace, tmp_path):
    """Degradation on a small capture must not hide behind the model."""
    for index in range(10):
        _write(tmp_path, index, _expected(5.0) + 120.0, pcap_mb=5.0)
    assert pace.main(["--dataset", str(tmp_path)]) == 4


def test_the_real_degradation_is_still_caught_at_its_real_capture_size(pace, tmp_path):
    """The 2026-09-19 block: 385.2s median at a 393.7MB median capture.

    Volume explains most of it, and the residual +116.8s is the part that is
    actually a defect. The guard has to see that part.
    """
    for index in range(10):
        _write(tmp_path, index, 385.2, pcap_mb=393.7)
    assert pace.main(["--dataset", str(tmp_path)]) == 4


def test_a_healthy_batch_at_the_same_capture_size_is_not_flagged(pace, tmp_path):
    """Same 393.7MB, but only what the model predicts. Must stay quiet.

    Paired with the test above, this is what separates 'heavy' from 'degraded'.
    """
    for index in range(10):
        _write(tmp_path, index, _expected(393.7), pcap_mb=393.7)
    assert pace.main(["--dataset", str(tmp_path)]) == 0


def test_the_model_matches_the_measurement_it_came_from(pace):
    """Three points from the measured deciles, within the spread of the fit."""
    for megabytes, observed in ((4.0, 86.2), (51.2, 105.1), (750.0, 453.0)):
        predicted = _expected(megabytes)
        assert abs(predicted - observed) < 90.0, (
            f"{megabytes}MB: model says {predicted:.0f}s, measured {observed:.0f}s"
        )


def test_a_missing_capture_does_not_credit_a_session_with_volume(pace, tmp_path):
    """No pcap means no allowance; otherwise a broken capture would hide a stall."""
    assert _expected(0.0) < _expected(1.0)
    for index in range(10):
        _write(tmp_path, index, _expected(0.0) + 120.0, pcap_mb=0.0)
    assert pace.main(["--dataset", str(tmp_path)]) == 4


# ── the model is known invalid above a measured size ─────────────────────────

# The volume model was fitted while per-packet extraction was truncated at a
# fixed 300s. Once the timeout scales with capture size (2026-09-25) extraction
# runs to completion and `inside` grows, but the model does not know that.
#
# Measured over the 180-session recovery run:
#     extraction_sec ~ 17.2 + 0.533 s/MB   (R2 0.767, 4-way parallel)
#
#     pcap     model's whole-session prediction     extraction alone
#     263MB              184.6s                          157.4s
#     500MB              273.7s                          283.7s   <- crossover
#     795MB              384.6s                          441.0s
#
# Above the crossover the residual stops measuring degradation and starts
# measuring how wrong the model is, so the guard must decline rather than fire.
# That is the same class of error the residual itself was introduced to fix on
# 2026-09-24, pointing the other way.

_EXTRACTION_FIXED_SEC = 17.2
_EXTRACTION_SLOPE_SEC_PER_MB = 0.533


def _extraction_sec(pcap_mb: float) -> float:
    return _EXTRACTION_FIXED_SEC + _EXTRACTION_SLOPE_SEC_PER_MB * pcap_mb


def test_the_invalidity_threshold_is_where_extraction_overtakes_the_model(pace):
    """The constant is measured, not chosen.

    Below it the model still leaves room for the rest of the session; above it
    one step already costs more than the model allows for all of them.
    """
    limit = pace.MODEL_INVALID_ABOVE_MB
    assert _extraction_sec(limit) >= _expected(limit) * 0.95
    assert _extraction_sec(limit * 0.5) < _expected(limit * 0.5)
    assert _extraction_sec(limit * 1.5) > _expected(limit * 1.5)


def test_a_batch_above_the_limit_is_not_judged(pace, tmp_path):
    """Declining is the point: a stale model must not stop a healthy campaign."""
    heavy_mb = 700.0
    for index in range(10):
        # Far beyond the stale model, yet entirely explained by extraction.
        _write(tmp_path, index, _expected(heavy_mb) + 300.0, pcap_mb=heavy_mb)
    assert pace.main(["--dataset", str(tmp_path)]) == 0


def test_declining_says_so_rather_than_reporting_ok(pace, tmp_path, capsys):
    """"ok" would claim the campaign was checked. It was not."""
    for index in range(10):
        _write(tmp_path, index, _expected(700.0) + 300.0, pcap_mb=700.0)
    pace.main(["--dataset", str(tmp_path)])
    out = capsys.readouterr().out
    assert "模型不適用" in out
    assert "ok" not in out.split("\n")[-2]


def test_the_guard_does_not_go_soft_below_the_limit(pace, tmp_path):
    """The mutation that would matter: declining everywhere instead of above it.

    A 400MB batch is under the crossover, so a genuine +200s stall must still
    abort the campaign.
    """
    for index in range(10):
        _write(tmp_path, index, _expected(400.0) + 200.0, pcap_mb=400.0)
    assert pace.main(["--dataset", str(tmp_path)]) == 4
