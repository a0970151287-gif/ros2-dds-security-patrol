"""The only deadline that survives a GIL-holding C call.

Measured 2026-09-25 across 29 instrumented sessions: 12 never reached the last
line of teardown, and every one of them had `observer.ok == True` -- a real
rclpy node to close. Of the 17 that did reach it, 10 had no observer at all and
closed in 0.00s. Their `wall - declared` was +3.14s, exactly the factory's
grace period, so they were still inside `observer.close()` when the deadline
passed and were SIGKILLed after it.

`_close_within` was supposed to bound that. It cannot: it puts the close on a
daemon thread and waits, but rclpy's shutdown blocks inside a C extension
holding the GIL, so the main thread cannot return from its own `Event.wait()`
either. The docstring named the SIGALRM version of this trap while the thread
version was doing the same thing.

SIGALRM at `SIG_DFL` is different in kind. Its default action is to terminate
the process, and the kernel performs that -- no bytecode has to run. So the
process can still honour a deadline while Python is completely stopped.

The cost is stated where it is paid: a fired alarm exits with signal 14, which
still fails the training gate. But that session was going to be SIGKILLed with
-9 *after* the factory's deadline, and it is the overrun, not the exit code,
that aborts the whole batch.
"""

from __future__ import annotations

import importlib.util
import pathlib
import signal
import subprocess
import sys
import textwrap

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_POC = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"

posix_only = pytest.mark.skipif(
    not hasattr(signal, "setitimer"), reason="POSIX interval timers only"
)


def _driver():
    spec = importlib.util.spec_from_file_location("_n37_hardstop", _POC)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_n37_hardstop"] = module
    spec.loader.exec_module(module)
    return module


n37 = _driver()


# ─────────────────────── arming and disarming ───────────────────────


@posix_only
def test_arming_reports_success_and_can_be_cancelled():
    assert n37._arm_kernel_hard_stop(30.0) is True
    n37._disarm_kernel_hard_stop()
    # restore a handler so a stray alarm cannot kill the test process
    signal.signal(signal.SIGALRM, signal.SIG_IGN)


@posix_only
@pytest.mark.parametrize("bad", [0.0, -1.0, -0.001])
def test_a_deadline_already_past_is_refused(bad):
    """Arming with a non-positive delay would fire immediately and kill us."""
    assert n37._arm_kernel_hard_stop(bad) is False


@posix_only
def test_disarming_is_safe_when_nothing_was_armed():
    n37._disarm_kernel_hard_stop()
    n37._disarm_kernel_hard_stop()


@posix_only
def test_arming_sets_the_default_disposition_not_a_python_handler():
    """A Python handler is exactly what cannot run while the GIL is held."""
    previous = signal.getsignal(signal.SIGALRM)
    try:
        n37._arm_kernel_hard_stop(30.0)
        assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
    finally:
        n37._disarm_kernel_hard_stop()
        signal.signal(signal.SIGALRM, previous if callable(previous) else signal.SIG_IGN)


# ─────────── it really kills a process that Python cannot interrupt ───────────


@posix_only
def test_the_kernel_stop_kills_a_process_blocked_outside_python():
    """The decisive property, exercised end to end in a child process.

    `time.sleep` in CPython releases the GIL, so it is not a faithful stand-in
    for a blocked C extension. `os.read` on an empty pipe blocks in a syscall
    with no timeout and no Python frames to return to, which is the closest
    portable equivalent: nothing in the interpreter can end this wait.
    """
    program = textwrap.dedent(
        """
        import importlib.util, os, sys
        spec = importlib.util.spec_from_file_location("n37", sys.argv[1])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["n37"] = mod
        spec.loader.exec_module(mod)

        assert mod._arm_kernel_hard_stop(1.0) is True
        read_fd, _write_fd = os.pipe()
        os.read(read_fd, 1)          # blocks forever; nothing will write
        print("SHOULD NEVER PRINT", flush=True)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(_POC)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == -signal.SIGALRM, (
        f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr[-400:]!r}"
    )
    assert "SHOULD NEVER PRINT" not in result.stdout


@posix_only
def test_a_disarmed_stop_lets_the_process_finish():
    """Cancelling must really cancel, or every clean session dies on the timer."""
    program = textwrap.dedent(
        """
        import importlib.util, sys, time
        spec = importlib.util.spec_from_file_location("n37", sys.argv[1])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["n37"] = mod
        spec.loader.exec_module(mod)

        mod._arm_kernel_hard_stop(0.5)
        mod._disarm_kernel_hard_stop()
        time.sleep(1.5)
        print("SURVIVED", flush=True)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(_POC)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr[-400:]
    assert "SURVIVED" in result.stdout


# ─────────────────────── wiring into the teardown ───────────────────────


def _source() -> str:
    return _POC.read_text(encoding="utf-8")


def test_the_hard_stop_is_armed_before_the_close():
    """Armed after the close would be armed after the thing it has to bound."""
    body = _source()
    armed = body.index("_armed = _arm_kernel_hard_stop")
    closed = body.index("_close_within(observer.close", armed - 2000)
    assert armed < closed


def test_the_hard_stop_is_disarmed_when_the_close_returns():
    body = _source()
    closed = body.index("_close_within(observer.close")
    assert "_disarm_kernel_hard_stop()" in body[closed:closed + 500]


def test_the_hard_stop_lands_before_the_factory_deadline():
    """Dying at our own deadline is the whole point; dying after it is the bug."""
    body = _source()
    assert "deadline - EXIT_MARGIN_SEC" in body
    assert n37.EXIT_MARGIN_SEC > 0


def test_the_exit_margin_is_smaller_than_the_teardown_reserve():
    """Otherwise the stop would fire before the close ever had a chance."""
    assert n37.EXIT_MARGIN_SEC < n37.TEARDOWN_RESERVE_SEC


def test_the_trace_is_emitted_before_the_hard_stop_is_armed():
    """Evidence first. An alarm that fires mid-trace would lose the session."""
    body = _source()
    trace = body.index("_emit_trace(step,")
    armed = body.index("_armed = _arm_kernel_hard_stop")
    assert trace < armed


# ─────────────────────── the reserve this replaced ───────────────────────


def test_the_reserve_covers_the_measured_overrun():
    """12 sessions needed more than reserve + grace; the reserve now exceeds it.

    reserve(4.0) + factory grace(3.07 measured) = 7.07s and they were still
    inside the close, so anything at or below that is known to be too small.
    """
    known_insufficient_sec = 7.07
    assert n37.TEARDOWN_RESERVE_SEC > known_insufficient_sec


def test_the_reserve_still_leaves_a_usable_window_on_the_shortest_session():
    """A reserve is only free until it eats the experiment."""
    shortest_observed_session_sec = 48.0
    window = shortest_observed_session_sec - n37.TEARDOWN_RESERVE_SEC
    assert window / shortest_observed_session_sec > 0.7
