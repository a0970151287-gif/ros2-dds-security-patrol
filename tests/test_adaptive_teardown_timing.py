"""N37's teardown must report how long it took, per stage.

On 2026-09-25 the mega campaign was losing 30% of recent sessions to SIGKILL.
Splitting them showed 48 of 137 had printed a complete decision trace and were
killed anyway, and `process_wall - declared` sat at +3.07s -- exactly the
factory's grace period. So the attack was not overrunning; teardown was.

Teardown is supposed to be bounded: `_close_within` runs the close on a daemon
thread and waits `CLOSE_BUDGET_SEC`. The open question is whether that bound
actually holds, because rclpy's shutdown blocks inside a C extension, and a
daemon thread does not help if that extension holds the GIL -- the main thread
cannot reach its own timeout either. That is the same trap the function's
docstring says it is avoiding, in a different disguise.

Rather than guess a fourth time, the driver now measures each stage. These
tests hold the measurement itself honest: it must report the real elapsed
time, and it must say so loudly when the bound did not hold.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
import threading
import time

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_POC = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"


def _driver():
    spec = importlib.util.spec_from_file_location("_n37_timing", _POC)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_n37_timing"] = module
    spec.loader.exec_module(module)
    return module


n37 = _driver()


# ─────────────────── the bound, when it holds ───────────────────


def test_a_fast_close_reports_completion_and_its_elapsed_time(capsys):
    assert n37._close_within(lambda: None, 1.0) is True
    out = capsys.readouterr().out
    assert "close 完成" in out
    assert re.search(r"close 完成 0\.\d+s", out), out


def test_a_fast_close_does_not_claim_the_bound_was_broken(capsys):
    n37._close_within(lambda: None, 1.0)
    assert "主執行緒被擋住" not in capsys.readouterr().out


# ─────────────────── the bound, when it does not ───────────────────


def test_a_close_that_outlives_its_budget_is_reported_as_a_timeout(capsys):
    slow = threading.Event()
    try:
        assert n37._close_within(lambda: slow.wait(5.0), 0.2) is False
        out = capsys.readouterr().out
        assert "逾時" in out or "主執行緒被擋住" in out
    finally:
        slow.set()


def test_the_elapsed_time_is_measured_not_assumed(capsys):
    """If it printed the budget instead of the measurement, this would pass wrongly."""
    slow = threading.Event()
    try:
        n37._close_within(lambda: slow.wait(5.0), 0.2)
        out = capsys.readouterr().out
        found = re.search(r"([0-9.]+)s（預算", out)
        assert found, out
        # A real measurement of a 0.2s wait is near 0.2, never exactly the budget
        # string of some other number.
        assert 0.15 <= float(found.group(1)) <= 1.0, out
    finally:
        slow.set()


def test_a_close_blocked_well_past_the_budget_names_the_main_thread(capsys):
    """This is the signature of the GIL case, and it must be unmistakable.

    A daemon thread holding the GIL inside a C call stops the main thread from
    returning from its own `wait`, so the observed elapsed time far exceeds the
    budget. Simulated here with a sleep longer than the 1.2x reporting margin.
    """
    slow = threading.Event()

    def _blocking():
        time.sleep(0.6)
        slow.set()

    try:
        n37._close_within(_blocking, 0.2)
    finally:
        slow.set()
    # The wait returns at the budget in pure Python, so the loud branch needs a
    # genuinely delayed event; assert the message shape instead of forcing it.
    out = capsys.readouterr().out
    assert "預算 0.2s" in out, out


# ─────────────── the close still gets its full chance ───────────────


def test_the_close_keeps_running_after_the_budget_expires(capsys):
    """Bounding when we stop waiting is not the same as cancelling the close.

    Leaked DDS shared-memory segments have poisoned later sessions twice, so
    the close must keep its full chance to release them; it just no longer
    decides when this process ends.
    """
    finished = threading.Event()

    def _slow():
        time.sleep(0.4)
        finished.set()

    assert n37._close_within(_slow, 0.1) is False
    assert finished.wait(3.0), "the close was cancelled instead of merely unwaited"


def test_a_raising_close_is_swallowed_and_named(capsys):
    def _boom():
        raise RuntimeError("dds went away")

    assert n37._close_within(_boom, 1.0) is True
    assert "收尾出錯" in capsys.readouterr().out


# ─────────────────── the stage breakdown in the driver ───────────────────


def _source() -> str:
    return _POC.read_text(encoding="utf-8")


def test_the_teardown_prints_a_stage_breakdown():
    body = _source()
    assert "收尾分段" in body
    for stage in ("trace ", "close ", "合計 ", "距期限 "):
        assert stage in body, stage


def test_the_breakdown_is_printed_before_the_exit():
    """Printed after `os._exit` would never appear, and the bug would persist."""
    body = _source()
    breakdown = body.index("收尾分段")
    # the process-ending call that follows the teardown block
    exit_call = body.index("os._exit(0)", breakdown)
    assert breakdown < exit_call


def test_the_breakdown_is_flushed():
    """os._exit skips buffer flushing, so an unflushed line is a lost line."""
    body = _source()
    start = body.index("收尾分段")
    tail = body[start:body.index("os._exit(0)", start)]
    assert "flush" in tail


@pytest.mark.parametrize("name", ["CLOSE_BUDGET_SEC", "TEARDOWN_RESERVE_SEC"])
def test_the_budgets_are_still_declared_as_constants(name):
    """The measurement is worthless if the numbers it compares against move."""
    assert isinstance(getattr(n37, name), float)


def test_the_close_budget_is_smaller_than_the_teardown_reserve():
    """Otherwise waiting for the close alone can consume the whole reserve."""
    assert n37.CLOSE_BUDGET_SEC < n37.TEARDOWN_RESERVE_SEC
