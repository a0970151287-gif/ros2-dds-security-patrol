"""The factory names the deadline; the attacker does not guess at it.

Measured 2026-09-24 over 33 adaptive sessions that printed their own elapsed:

    N37 self-reported finish          budget - 4.7s median, 0/33 late
    factory duration - N37's elapsed  4.85s on clean exits, 7.80s on killed ones

N37 finished its work early by its own clock and was killed anyway, because the
two clocks start in different places: the factory's at `Popen()`, N37's at the
first line of the module. Between them sit the CPython boot and reading the
script off /mnt/c -- 4.85s, more than the whole 4.0s teardown reserve. No
rearrangement inside the module can see that time; the module is not running.

A duration cannot express an instant that has already partly elapsed. An
absolute CLOCK_MONOTONIC deadline can, and on Linux every process agrees on it.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import time

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from firewall_lab import orchestrator  # noqa: E402

_N37 = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"

posix_only = pytest.mark.skipif(os.name != "posix", reason="CLOCK_MONOTONIC handoff")


@pytest.fixture(scope="module")
def n37():
    spec = importlib.util.spec_from_file_location("_n37_deadline", _N37)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── the two sides agree on the variable name ─────────────────────────────────


def test_both_sides_use_the_same_variable(n37):
    """Duplicated deliberately -- the PoC must not import the pipeline -- so a
    test has to hold the two copies together."""
    assert n37.ATTACK_DEADLINE_ENV == orchestrator.ATTACK_DEADLINE_ENV


def test_the_orchestrator_sets_it_only_for_the_adaptive_driver():
    """A catalog runner takes a duration and would ignore it; setting it anyway
    would imply a contract that runner does not honour."""
    source = (_ROOT / "firewall_lab" / "orchestrator.py").read_text(encoding="utf-8")
    marker = source.index("attack_env[ATTACK_DEADLINE_ENV]")
    guard = source.rindex("if adaptive:", 0, marker)
    assert marker - guard < 2000, "the assignment is not inside the adaptive branch"


def test_the_deadline_is_taken_next_to_the_launch():
    """Computed far from `Popen()` it would describe a different instant."""
    source = (_ROOT / "firewall_lab" / "orchestrator.py").read_text(encoding="utf-8")
    assign = source.index("attack_env[ATTACK_DEADLINE_ENV]")
    start = source.index("attack_process.start()", assign)
    assert start - assign < 800, "too much happens between naming the deadline and starting"


# ── the attacker honours it, and refuses nonsense ────────────────────────────


@posix_only
def test_a_deadline_in_the_future_is_used(n37, monkeypatch):
    monkeypatch.setenv(n37.ATTACK_DEADLINE_ENV, repr(time.monotonic() + 60.0))
    deadline = n37._factory_deadline()
    assert deadline is not None
    assert 55.0 < deadline - time.monotonic() <= 60.0


@posix_only
def test_an_expired_deadline_is_refused(n37, monkeypatch, capsys):
    """Falling back beats running against a number that is already wrong."""
    monkeypatch.setenv(n37.ATTACK_DEADLINE_ENV, repr(time.monotonic() - 5.0))
    assert n37._factory_deadline() is None
    assert "不合理的期限" in capsys.readouterr().out


@posix_only
def test_an_absurdly_distant_deadline_is_refused(n37, monkeypatch):
    """A garbled handoff must not license a 10-hour attack run."""
    monkeypatch.setenv(
        n37.ATTACK_DEADLINE_ENV, repr(time.monotonic() + n37.MAX_DURATION_SEC + 60)
    )
    assert n37._factory_deadline() is None


@posix_only
def test_a_malformed_deadline_is_refused(n37, monkeypatch):
    for junk in ("", "soon", "NaN-ish", "1e"):
        monkeypatch.setenv(n37.ATTACK_DEADLINE_ENV, junk)
        assert n37._factory_deadline() is None


def test_no_deadline_falls_back_to_the_duration(n37, monkeypatch):
    """A PoC run by hand, outside the orchestrator, must still work."""
    monkeypatch.delenv(n37.ATTACK_DEADLINE_ENV, raising=False)
    assert n37._factory_deadline() is None


# ── the arithmetic this replaced ─────────────────────────────────────────────


def test_the_measured_boot_exceeded_the_whole_teardown_reserve(n37):
    """Stated so the reason for the handoff stays legible after the fix."""
    measured_boot_sec = 4.85
    assert measured_boot_sec > n37.TEARDOWN_RESERVE_SEC, (
        f"boot {measured_boot_sec}s vs reserve {n37.TEARDOWN_RESERVE_SEC}s: the "
        "reserve was spent before N37's clock started"
    )


def test_stop_by_is_derived_from_the_deadline_not_from_t0():
    """The defect: `stop_by = t0 + duration - reserve`, with t0 after the boot."""
    body = _N37.read_text(encoding="utf-8")
    assert "stop_by = deadline - TEARDOWN_RESERVE_SEC" in body
    assert "stop_by = t0 + duration - TEARDOWN_RESERVE_SEC" not in body


def test_the_watchdog_is_armed_from_the_deadline_too():
    """Armed from `duration` it would inherit the same blind spot."""
    body = _N37.read_text(encoding="utf-8")
    assert "deadline - WATCHDOG_MARGIN_SEC - time.monotonic()" in body
    assert "duration - WATCHDOG_MARGIN_SEC - startup_cost" not in body


def test_the_boot_cost_is_reported():
    """It was invisible for three rounds of fixes; now it prints every session."""
    body = _N37.read_text(encoding="utf-8")
    assert "boot_cost" in body
    assert "開機 {boot_cost:.2f}s" in body


@posix_only
def test_monotonic_is_comparable_across_processes():
    """The whole handoff rests on this being true on Linux.

    If CLOCK_MONOTONIC were per-process, the child would read an instant that
    means nothing to it, and the deadline would be silently wrong rather than
    loudly broken.
    """
    import subprocess

    here = time.monotonic()
    there = float(
        subprocess.run(
            [sys.executable, "-c", "import time; print(time.monotonic())"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    assert abs(there - here) < 30.0, (
        f"monotonic differs by {there - here:.1f}s between processes; the "
        "absolute deadline handoff is not safe on this platform"
    )
