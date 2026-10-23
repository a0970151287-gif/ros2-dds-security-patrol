"""What the teardown prints, and what it must never wait for.

This file used to test `_close_within`: a daemon thread running the close while
the main thread waited out a budget. Measurement retired it. rclpy's shutdown
blocks inside a C extension holding the GIL, so the waiting thread needs the
same lock and cannot return from its own timeout either -- the function's own
docstring named that trap for signals while doing it with threads.

Raising the reserve to 12s and wrapping the wait in a kernel-enforced stop was
tried first and measured: SIGKILL fell from 25.3% to 15.9%, the hard stop
contributed 29.5% of its own, and the training-eligible rate went
**74.4% -> 54.5%**. A bounded overrun is still an overrun.

So the parent stopped waiting. What remains to test here is the evidence it
leaves behind, because that is what makes the session usable at all.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

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


def _source() -> str:
    return _POC.read_text(encoding="utf-8")


def _index(needle: str, body: str) -> int:
    at = body.find(needle)
    assert at != -1, f"anchor vanished from N37: {needle!r}"
    return at


# ─────────────────────── the evidence, in order ───────────────────────


def test_the_trace_is_emitted_first(n37_body=None):
    """The decision trace is the session. Everything after it is cleanup.

    C2C-074 moved it ahead of the close after 14 sessions lost their trace
    entirely to a close that never returned.
    """
    body = _source()
    trace = _index("_emit_trace(step,", body)
    reap = _index("_reap_observer_out_of_process(observer.close)", body)
    assert trace < reap


def test_the_teardown_reports_its_own_cost_and_the_remaining_margin():
    body = _source()
    at = _index("⏱ 收尾：", body)
    line = body[at:at + 300]
    assert "trace " in line
    assert "距期限" in line


def test_the_teardown_line_is_flushed():
    """os._exit skips buffer flushing, so an unflushed line is a lost line."""
    body = _source()
    at = _index("⏱ 收尾：", body)
    assert "flush=True" in body[at:at + 300]


def test_the_margin_is_reported_against_the_factory_deadline():
    """A negative margin means the factory had already sent SIGTERM."""
    body = _source()
    at = _index("⏱ 收尾：", body)
    window = body[max(0, at - 400):at]
    assert "deadline - time.monotonic()" in window


# ─────────────────── nothing in the parent waits on rclpy ───────────────────


def test_the_parent_has_no_in_process_wait_for_the_close():
    """`_close_within` is gone, and it must not come back under another name."""
    body = _source()
    assert "_close_within" not in body
    reap = _index("_reap_observer_out_of_process(observer.close)", body)
    tail = body[reap:reap + 300]
    for waiter in ("join(", ".wait(", "sleep("):
        assert waiter not in tail, f"the parent waits again via {waiter!r}"


def test_the_parent_exits_zero_whatever_the_close_did():
    """rc is what the training gate reads; cleanup must not be able to set it."""
    body = _source()
    reap = _index("_reap_observer_out_of_process(observer.close)", body)
    assert "os._exit(0)" in body[reap:reap + 200]


# ─────────────────────── the budgets that remain ───────────────────────


@pytest.mark.parametrize("name", ["CLOSE_BUDGET_SEC", "TEARDOWN_RESERVE_SEC"])
def test_the_budgets_are_still_declared_as_constants(name):
    """The measurements above compare against these; a silent move invalidates them."""
    assert isinstance(getattr(n37, name), float)


def test_the_child_budget_is_smaller_than_the_parent_reserve():
    assert n37.CLOSE_BUDGET_SEC < n37.TEARDOWN_RESERVE_SEC


def test_the_reserve_still_covers_the_burst_reap():
    """The one thing the parent genuinely still has to finish in time."""
    assert n37.TEARDOWN_RESERVE_SEC > n37.BURST_EXIT_RESERVE_SEC
