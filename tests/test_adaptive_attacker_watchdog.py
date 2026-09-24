"""N37 must leave before the factory kills it, and must leave its trace behind.

Measured 2026-09-24 over the 25 adaptive sessions since the campaign restart:

    SIGKILLed   14   reached the line printed after observer.close(): 0
    clean exit  11   reached DECISION_TRACE:                          11/11

The hang is in `observer.close()` -- the rclpy shutdown C2C-024 already recorded
as able to block -- and every one of those 14 runs lost its whole decision trace
to nothing but print order: the trace came after the close.

Three layers are tested here, and the important one is the last. The loop checks
the clock at fixed points, so anything that blocks between two checks blows the
budget, and enumerating every such place is a losing game. An interval timer
does not care where the program is.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import subprocess
import sys
import textwrap

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_N37 = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"

posix_only = pytest.mark.skipif(
    os.name != "posix", reason="setitimer/SIGALRM is POSIX only"
)


@pytest.fixture(scope="module")
def n37():
    spec = importlib.util.spec_from_file_location("_n37_watchdog", _N37)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source() -> str:
    return _N37.read_text(encoding="utf-8")


# ── the budget arithmetic ────────────────────────────────────────────────────


def test_the_watchdog_fires_after_the_normal_path_should_have_finished(n37):
    """It is a backstop. Firing before the loop's own deadline would mask bugs.

    The loop targets `duration - TEARDOWN_RESERVE_SEC`; the watchdog sits later,
    at `duration - WATCHDOG_MARGIN_SEC`.
    """
    assert n37.WATCHDOG_MARGIN_SEC < n37.TEARDOWN_RESERVE_SEC


def test_the_watchdog_fires_before_the_factory_kills(n37):
    """ManagedProcess.stop sends SIGTERM then SIGKILL after its grace.

    The margin plus that grace is the whole window for printing the trace, so it
    has to be read from the factory rather than written down twice.
    """
    import inspect

    from firewall_lab.evidence import ManagedProcess

    grace = inspect.signature(ManagedProcess.stop).parameters["grace_sec"].default
    assert n37.WATCHDOG_MARGIN_SEC > 0
    assert n37.WATCHDOG_MARGIN_SEC + grace >= 2.0, (
        "too little room to print the trace before SIGKILL"
    )


def test_the_close_budget_fits_inside_the_watchdog_margin_plus_grace(n37):
    import inspect

    from firewall_lab.evidence import ManagedProcess

    grace = inspect.signature(ManagedProcess.stop).parameters["grace_sec"].default
    assert n37.CLOSE_BUDGET_SEC <= n37.WATCHDOG_MARGIN_SEC + grace + 1.0


# ── evidence is printed before anything is released ──────────────────────────


def test_the_trace_is_printed_before_the_shutdown(n37):
    """The defect: `observer.close()` came first and could hang forever."""
    body = _source()
    emit = body.index("_emit_trace(step,")
    close = body.index("observer.close()", emit - 4000)
    assert emit < close, "the trace must be printed before the shutdown is attempted"


def test_the_shutdown_is_still_attempted(n37):
    """Skipping it would leak DDS shared memory, which poisons later sessions.

    The campaign has already been brought down twice by accumulated segments, so
    the fix bounds the close rather than removing it.
    """
    assert "observer.close()" in _source()
    assert "CLOSE_BUDGET_SEC" in _source()


def test_emitting_the_trace_twice_prints_it_once(n37, capsys):
    """Both the watchdog and the `finally` block call it; only one may print."""
    n37._TRACE_PRINTED = False
    n37._TRACE.clear()
    n37._TRACE.append({"step": 1, "decision": "escalate"})

    n37._emit_trace(1, 12.5)
    first = capsys.readouterr().out
    n37._emit_trace(1, 12.5)
    second = capsys.readouterr().out

    assert first.count("DECISION_TRACE") == 1
    assert "escalate" in first
    assert second == ""
    n37._TRACE_PRINTED = False
    n37._TRACE.clear()


def test_the_handler_reads_the_same_list_main_appends_to(n37):
    """A local `trace` in main() would leave the handler printing an empty one."""
    body = _source()
    assert re.search(r"^\s*trace = _TRACE\s*$", body, re.M), (
        "main must alias the module-level list, not shadow it"
    )
    assert not re.search(r"^\s*trace: list\[dict\] = \[\]\s*$", body, re.M)


# ── the watchdog actually fires, in a real process ───────────────────────────


_PRELUDE = f"""
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("n37", {str(_N37)!r})
    n37 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(n37)
"""


def _run(body: str, timeout: float = 25.0) -> subprocess.CompletedProcess:
    """Run a fragment against N37 in a real child process.

    Each part is dedented on its own: `textwrap.dedent` strips the *common*
    prefix, so joining a 4-space prelude to an 8-space body leaves the body
    indented and the child dies with IndentationError. That looks exactly like
    a hang resolving instantly, which is how the mutation test below first
    passed for the wrong reason.
    """
    script = textwrap.dedent(_PRELUDE) + textwrap.dedent(body)
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(_ROOT),
    )
    assert "Error" not in result.stderr, (
        f"the child crashed instead of running:\n{result.stderr[:400]}"
    )
    return result


@posix_only
def test_the_watchdog_escapes_a_hang_that_no_clock_check_would_catch():
    """The real failure: blocked in a call that never looks at the clock.

    `time.sleep(60)` stands in for the rclpy shutdown. Without the timer this
    process would still be there when the factory's SIGKILL arrived, and its
    trace would be gone.
    """
    result = _run("""
        import time
        n37._TRACE.append({"step": 1, "decision": "escalate"})
        n37._arm_watchdog(1.0, reason="test hang")
        time.sleep(60)
        print("REACHED_THE_END_ANYWAY")
    """)
    assert result.returncode == 0
    assert "REACHED_THE_END_ANYWAY" not in result.stdout
    assert "DECISION_TRACE" in result.stdout
    assert "escalate" in result.stdout
    assert "test hang" in result.stdout


@posix_only
def test_without_the_watchdog_that_hang_would_not_resolve():
    """The mutation: same script, timer never armed. Must not finish in time."""
    with pytest.raises(subprocess.TimeoutExpired):
        _run("""
            import time
            n37._TRACE.append({"step": 1, "decision": "escalate"})
            time.sleep(60)
        """, timeout=6.0)


@posix_only
def test_the_watchdog_does_not_fire_when_the_work_finishes_first():
    """A backstop that fires on healthy runs would be worse than none."""
    result = _run("""
        import time
        n37._TRACE.append({"step": 1, "decision": "back off"})
        n37._arm_watchdog(10.0, reason="should not fire")
        time.sleep(0.2)
        n37._emit_trace(1, 0.2)
    """)
    assert result.returncode == 0
    assert "should not fire" not in result.stdout
    assert result.stdout.count("DECISION_TRACE") == 1


@posix_only
def test_an_already_expired_deadline_fires_immediately():
    """A start-up slow enough to consume the whole budget must still exit clean.

    `setitimer(0)` disarms the timer rather than firing it, so a non-positive
    delay has to be clamped, not passed through.
    """
    result = _run("""
        import time
        n37._TRACE.append({"step": 0, "decision": "none"})
        n37._arm_watchdog(-5.0, reason="already late")
        time.sleep(30)
        print("TIMER_WAS_DISARMED")
    """, timeout=15.0)
    assert result.returncode == 0
    assert "TIMER_WAS_DISARMED" not in result.stdout
    assert "already late" in result.stdout


@posix_only
def test_the_trace_survives_even_with_an_empty_decision_list():
    """A run killed before its first burst still has to say so."""
    result = _run("""
        import time
        n37._arm_watchdog(0.5, reason="early kill")
        time.sleep(30)
    """)
    assert result.returncode == 0
    assert "DECISION_TRACE []" in result.stdout

# ── the shutdown is bounded by a thread, because a signal cannot reach it ────

# Measured 2026-09-24, 16 adaptive sessions after the watchdog landed: the trace
# survived (0/28 -> 7/11 of the killed runs) and the residual fell from +210.9s
# to +6.2s, but 11/16 were still SIGKILLed and the watchdog fired in none of
# them. Python runs signal handlers between bytecodes, and rclpy's shutdown
# blocks inside a C extension holding the GIL, so the SIGALRM was never
# delivered. A timer cannot bound a call that stops the interpreter from running
# timers.


def test_a_prompt_shutdown_reports_success(n37):
    calls = []
    assert n37._close_within(lambda: calls.append("closed"), 5.0) is True
    assert calls == ["closed"]


def test_a_hung_shutdown_gives_up_and_says_so(n37):
    import time

    started = time.monotonic()
    assert n37._close_within(lambda: time.sleep(30), 0.5) is False
    assert time.monotonic() - started < 5.0, "it waited for the hung close"


def test_a_shutdown_that_raises_is_not_allowed_to_propagate(n37):
    """Teardown must never turn into an exception that skips the exit."""

    def explode():
        raise RuntimeError("rclpy said no")

    assert n37._close_within(explode, 5.0) is True


def test_the_finally_block_no_longer_relies_on_a_signal_for_the_close():
    """The mutation this replaced: `_arm_watchdog` around `observer.close()`."""
    body = _source()
    assert "_close_within(observer.close" in body
    assert '_arm_watchdog(CLOSE_BUDGET_SEC' not in body, (
        "a SIGALRM cannot interrupt a C call that holds the GIL"
    )


def test_the_close_runs_on_a_daemon_thread(n37):
    """A non-daemon thread would keep the interpreter alive past os._exit."""
    body = _source()
    assert "daemon=True" in body


@posix_only
def test_the_process_exits_on_time_even_when_the_shutdown_never_returns():
    """The end-to-end case, in a real child.

    A C-level hang cannot be simulated from Python, so this uses `time.sleep`,
    which a signal *could* interrupt. The test is therefore about the ordering
    and the exit path, not about proving GIL behaviour: the process must leave
    on its own, with a non-empty trace, without anything killing it.
    """
    result = _run("""
        import time
        n37._TRACE.append({"step": 3, "decision": "escalate"})
        n37._emit_trace(3, 42.0)
        ok = n37._close_within(lambda: time.sleep(60), 1.0)
        print("CLOSE_RETURNED", ok)
        import os, sys
        sys.stdout.flush()
        os._exit(0)
    """, timeout=20.0)
    assert result.returncode == 0
    assert "CLOSE_RETURNED False" in result.stdout
    assert "DECISION_TRACE" in result.stdout
    assert "escalate" in result.stdout


@posix_only
def test_without_the_bound_the_same_shutdown_would_hold_the_process():
    """The mutation: call the hanging close directly. Must not finish in time."""
    with pytest.raises(subprocess.TimeoutExpired):
        _run("""
            import time
            n37._TRACE.append({"step": 3, "decision": "escalate"})
            n37._emit_trace(3, 42.0)
            time.sleep(60)
        """, timeout=6.0)
