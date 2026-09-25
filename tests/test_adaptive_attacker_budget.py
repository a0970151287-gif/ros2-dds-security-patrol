"""N37 must finish inside the budget the session factory grants it.

`attack_process.duration_sec` measures the *factory's* window, not N37's exit:
the orchestrator sleeps for the granted duration and only then stops the
process, so a clean exit records ~duration whether N37 finished early or late.
An earlier version of this file inferred the margin from that number, which it
cannot show.

What the data does show, measured 2026-09-24 across 406 adaptive sessions:

* 58 sessions were SIGKILLed, overshooting by a median of **+2.81s**. That
  overshoot is `stop()` escalating SIGTERM -> wait -> SIGKILL, which only
  happens when the process is still running at the deadline;
* the fix's own new telemetry then showed why: start-up costs **2.79s** of the
  **4.0s** `TEARDOWN_RESERVE_SEC`, because the budget clock started after
  argument parsing and the `firewall_lab` imports, off /mnt/c where reads are
  slow. That leaves ~1.2s against a child reap that can take 2 x
  CHILD_REAP_SEC.

14.3% of adaptive sessions died this way, and because `execute_campaign` raised
on the first one, a 40-session batch survived with probability 0.857^40 -- about
0.2%.

These are source-level assertions. Only a live run confirms the timing holds,
and the numbers above say what to look for: the start-up line in
attack.stdout.log, and an ineligible rate back near 1.7%.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_N37 = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"


def _source() -> str:
    return _N37.read_text(encoding="utf-8")


def _tree() -> ast.Module:
    return ast.parse(_source())


def _module():
    """Import N37 for its constants.

    Reading them back out of the AST meant re-implementing Python's own
    evaluation for a derived value, and getting it wrong. Importing gives the
    values the running script actually uses; N37 imports only the standard
    library at module level, so this is cheap and has no side effects beyond a
    sys.path entry.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("_n37_budget", _N37)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _constant(name: str) -> float:
    return getattr(_module(), name)


_constant_raw = _constant


# ── the budget clock starts at process start ─────────────────────────────────


def test_the_budget_clock_is_taken_before_any_expensive_work():
    """`_PROCESS_START` must precede the imports it is meant to account for."""
    tree = _tree()
    start_line = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "_PROCESS_START":
                    start_line = node.lineno
    assert start_line is not None, "_PROCESS_START is not defined"

    later_imports = [
        node.lineno
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node.lineno > start_line
    ]
    assert later_imports, (
        "nothing is imported after _PROCESS_START, so it is not buying anything"
    )


def test_the_budget_is_never_measured_from_where_main_happens_to_be():
    """Two defects, fixed in two steps; both are pinned here.

    First `t0 = time.monotonic()` sat inside main() after the imports, which put
    the whole reserve on the wrong side of start-up. Moving it to
    `_PROCESS_START` fixed that but not the interpreter boot before the module
    runs -- measured at 4.85s, more than the reserve itself. The budget now
    comes from an absolute deadline the factory names; see
    tests/test_attack_deadline_handoff.py.
    """
    body = _source()
    assert re.search(r"^\s*t0 = _PROCESS_START\s*$", body, re.M)
    assert not re.search(r"^\s*t0 = time\.monotonic\(\)\s*$", body, re.M)
    assert "stop_by = deadline - TEARDOWN_RESERVE_SEC" in body, (
        "the budget must come from the factory's deadline, not from t0"
    )
    assert "stop_by = t0 + duration - TEARDOWN_RESERVE_SEC" not in body


def test_the_startup_cost_is_reported():
    """It was invisible before, which is why it went unnoticed for two runs."""
    body = _source()
    assert "startup_cost" in body
    assert "startup_cost >= TEARDOWN_RESERVE_SEC" in body, (
        "a start-up that eats the whole reserve must say so"
    )


# ── a burst must leave room to reap its child ────────────────────────────────


def test_burst_sizing_reserves_the_reap():
    """`burst = min(uniform(...), remaining)` left nothing for the reap.

    `observer.pump(burst)` then finished exactly at `stop_by`, and the reap took
    up to another 2s past it.
    """
    body = _source()
    assert "remaining = stop_by - time.monotonic() - BURST_EXIT_RESERVE_SEC" in body
    assert not re.search(
        r"^\s*remaining = stop_by - time\.monotonic\(\)\s*$", body, re.M
    ), "the reap reserve was removed from the burst sizing"


def test_the_burst_reserve_covers_both_reap_waits():
    """The reap is wait -> kill -> wait, so two CHILD_REAP_SEC, not one."""
    reap = _constant_raw("CHILD_REAP_SEC")
    reserve = _constant("BURST_EXIT_RESERVE_SEC")
    assert reserve == 2 * reap


def test_the_reap_reserve_fits_inside_the_teardown_reserve():
    """Otherwise the burst loop would spend the cushion the exit path needs."""
    teardown = _constant_raw("TEARDOWN_RESERVE_SEC")
    reserve = _constant("BURST_EXIT_RESERVE_SEC")
    assert reserve < teardown, (
        f"the burst reserve ({reserve}s) must leave room inside the teardown "
        f"reserve ({teardown}s) for rclpy shutdown and the decision trace"
    )


def test_the_child_reap_budget_still_fits_the_factory_grace():
    """Read from ManagedProcess.stop's own signature, not written down twice."""
    import inspect

    from firewall_lab.evidence import ManagedProcess

    default = inspect.signature(ManagedProcess.stop).parameters["grace_sec"].default
    assert 2 * _constant_raw("CHILD_REAP_SEC") <= default


# ── the measured numbers that motivated the change ───────────────────────────


def test_the_old_margin_was_smaller_than_the_reap_it_had_to_absorb():
    """The arithmetic that actually explains the SIGKILLs.

    Not the clean exits' +0.01s -- that is the factory's fixed sleep and says
    nothing about N37. The margin comes from the measured start-up cost against
    the declared reserve, and it was smaller than the worst-case reap.
    """
    measured_startup_sec = 2.79
    reserve_at_the_time = 4.0
    reap_worst_case = 2 * _constant_raw("CHILD_REAP_SEC")

    margin_before = reserve_at_the_time - measured_startup_sec
    assert margin_before < reap_worst_case, (
        f"the old margin was {margin_before:.2f}s against a {reap_worst_case}s "
        "reap, which is why the process was still alive at the deadline"
    )

    # After the fix the clock starts at process start, so the full reserve is
    # margin again and the burst loop additionally stops short of the reap.
    # ⚠️ `reserve_at_the_time` is a literal, not the live constant. This test
    # records why the reserve was raised; reading the raised value would make
    # the fix delete its own justification (it did, on 2026-09-25).
    margin_after = _constant_raw("TEARDOWN_RESERVE_SEC")
    assert margin_after > reap_worst_case
    assert margin_after > reserve_at_the_time, (
        "the reserve should only ever grow while teardown stays unbounded"
    )


def test_the_script_still_parses():
    """A PoC that cannot be parsed reports as 'the attack did not run'.

    `N20_verify_flood.py` carried a SyntaxError through three smoke rounds on
    2026-09-19 for exactly this reason.
    """
    ast.parse(_source())
