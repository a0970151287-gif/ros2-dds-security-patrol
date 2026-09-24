"""N37 must finish inside the budget the session factory grants it.

Measured on 2026-09-24 across 406 adaptive sessions:

* clean exits overshot the granted budget by a median of **+0.01s**, not the
  -4.0s that `TEARDOWN_RESERVE_SEC` promises. The entire cushion was being spent
  on start-up, because the budget clock started after argument parsing and the
  `firewall_lab` imports -- and this repository lives on /mnt/c, where those
  reads are slow;
* the 58 sessions that were SIGKILLed overshot by a median of **+2.81s**, which
  is the child reap (up to 2 x CHILD_REAP_SEC) landing on top of a zero margin.

14.3% of adaptive sessions died this way, and because `execute_campaign` raised
on the first one, a 40-session batch survived with probability 0.857^40 -- about
0.2%.

These are source-level assertions. A live run is the only thing that can confirm
the timing actually holds, and the numbers above say what to look for.
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


def test_stop_by_is_measured_from_process_start_not_from_main():
    """The defect: `t0 = time.monotonic()` inside main(), after the imports.

    That put the whole 4-second reserve on the wrong side of start-up, so a
    clean exit landed exactly on the factory's deadline instead of 4s short.
    """
    body = _source()
    assert re.search(r"^\s*t0 = _PROCESS_START\s*$", body, re.M), (
        "t0 must be the process start, not the moment main() reached this line"
    )
    assert not re.search(r"^\s*t0 = time\.monotonic\(\)\s*$", body, re.M)
    assert "stop_by = t0 + duration - TEARDOWN_RESERVE_SEC" in body


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


def test_the_observed_overshoot_exceeded_the_old_effective_margin():
    """Stated as arithmetic so the reason stays legible after the fix.

    Clean exits landed at +0.01s, i.e. the effective margin was zero; the killed
    ones overshot by a median of 2.81s, which is the reap.
    """
    effective_margin_before = 0.01
    killed_overshoot_median = 2.81
    reap_worst_case = 2 * _constant_raw("CHILD_REAP_SEC")
    assert killed_overshoot_median > effective_margin_before
    assert killed_overshoot_median > reap_worst_case * 0.5, (
        "the overshoot should be the same order as the reap it is blamed on"
    )


def test_the_script_still_parses():
    """A PoC that cannot be parsed reports as 'the attack did not run'.

    `N20_verify_flood.py` carried a SyntaxError through three smoke rounds on
    2026-09-19 for exactly this reason.
    """
    ast.parse(_source())
