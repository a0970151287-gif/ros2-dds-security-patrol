"""The supervisor's slow threshold must be in the same units as the guard.

On 2026-09-24 the guard was changed from an absolute median to a *residual*
against a capture-volume model, because session wall clock tracks pcap size
(`inside ~ 85.7s + 0.376 s/MB`) and an absolute threshold fires on any batch of
heavy scenarios. The tool's default moved 200s -> 60s.

The supervisor passes the threshold explicitly, and that line was left at 200.
Nothing broke: the guard kept running and kept reporting, just against a bound
three times looser than intended -- loose enough to miss the very degradation it
was built for, whose residual was +116.8s.

A number that silently changes meaning while keeping its value is the failure
mode this project keeps recording. These tests hold the two sides together.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_SUPERVISOR = _ROOT / "工具腳本" / "run_mega_campaign.sh"
_PACE = _ROOT / "工具腳本" / "recent_session_pace.py"

# Measured 2026-09-24 over 503 sessions.
HEALTHY_RESIDUAL_SEC = -2.8
HEALTHY_P75_RESIDUAL_SEC = 6.3
DEGRADED_RESIDUAL_SEC = 116.8


def _pace_module():
    spec = importlib.util.spec_from_file_location("_pace_units", _PACE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _supervisor_default() -> float:
    body = _SUPERVISOR.read_text(encoding="utf-8")
    match = re.search(r'SLOW_SESSION_SEC="\$\{SLOW_SESSION_SEC:-([0-9.]+)\}"', body)
    assert match, "the supervisor no longer sets SLOW_SESSION_SEC"
    return float(match.group(1))


def _tool_default() -> float:
    body = _PACE.read_text(encoding="utf-8")
    match = re.search(
        r'"--slow-threshold-sec",\s*type=float,\s*default=([0-9.]+)', body, re.S
    )
    assert match, "the pace tool no longer declares a threshold default"
    return float(match.group(1))


def test_the_supervisor_and_the_tool_agree():
    """The supervisor passes the value, so a drift here is silent."""
    assert _supervisor_default() == _tool_default()


def test_the_threshold_separates_healthy_from_the_measured_degradation():
    threshold = _supervisor_default()
    assert HEALTHY_P75_RESIDUAL_SEC < threshold < DEGRADED_RESIDUAL_SEC, (
        f"{threshold}s does not sit between a healthy p75 of "
        f"{HEALTHY_P75_RESIDUAL_SEC}s and the measured degradation of "
        f"{DEGRADED_RESIDUAL_SEC}s"
    )


def test_the_old_absolute_threshold_would_now_miss_the_degradation():
    """Why the stale 200 mattered, stated as arithmetic.

    Carried over unchanged it would have needed a residual of 200s to fire,
    while the degradation it exists to catch sat at 116.8s.
    """
    stale_absolute = 200.0
    assert stale_absolute > DEGRADED_RESIDUAL_SEC
    assert _supervisor_default() < DEGRADED_RESIDUAL_SEC


def test_the_guard_reads_a_residual_not_a_wall_clock():
    """If the comparison ever goes back to raw duration, the units diverge again."""
    body = _PACE.read_text(encoding="utf-8")
    assert 'pace["median_residual_sec"] > args.slow_threshold_sec' in body
    assert 'pace["median_sec"] > args.slow_threshold_sec' not in body


def test_a_heavy_batch_is_not_slow_by_volume_alone():
    """300MB costs 198s on volume; under the stale absolute rule that was 'slow'."""
    pace = _pace_module()
    heavy = pace.expected_sec(300.0)
    assert heavy > 190.0, "the volume model no longer predicts what this test assumes"
    assert heavy - pace.expected_sec(300.0) == 0.0  # residual of a healthy heavy batch
    assert 0.0 < _supervisor_default() < heavy, (
        "the threshold must be a residual, not something a heavy batch reaches"
    )
