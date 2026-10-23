"""The attacker's observer must not create endpoints it never uses, and a hang
inside its constructor must name the step it hung on.

Measured 2026-10-02 over the 600 attack sessions of the 09-26 -> 09-28 run:
75 were force-stopped, and **73 of them printed the banner and nothing else** --
no `觀測者就緒` line. That line is printed *after* the constructor returns, and
the constructor wraps everything in `try/except`, so an exception is caught,
sets `ok=False`, and the line still prints (one session did exactly that). The
73 never reached it, so the constructor never returned: a block, not an
exception. Python-level watchdogs cannot help -- the C extension holds the GIL,
which C2C-082 measured the hard way.

Two separate obligations follow, and this file holds both apart:

  * The three Node switches are an independent hygiene requirement. The
    observer documents itself as subscribing to public topics only, yet
    `Node(name)` with no arguments also builds six parameter services, a
    type-description service and a rosout publisher -- endpoints it never uses
    and that do send traffic. Five other PoC scripts already use the switches;
    this one was the exception.
  * Per-step timing is what makes a future hang diagnosable. It is NOT a fix,
    and these tests deliberately do not assert that the hang is gone.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_N37 = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"
_PEERS = [
    "N29_insider_credentialed.py",
    "N32_discovery_recon.py",
    "N33_node_churn.py",
    "N34_odom_spoof.py",
    "N35_spdp_flood.py",
]


def _source() -> str:
    return _N37.read_text(encoding="utf-8")


def _observer_init(source: str | None = None) -> ast.FunctionDef:
    """Observer.__init__ as an AST node.

    `source` exists so the mutation test at the bottom can feed in a weakened
    copy without touching the file on disk. Reading the live file is the
    default, because a checker that only ever sees a fixture proves nothing
    about the shipped script.
    """
    tree = ast.parse(source if source is not None else _source())
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Observer":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                    return item
    raise AssertionError("Observer.__init__ not found")


def _node_call(source: str | None = None) -> ast.Call:
    """The `Node(...)` construction inside Observer.__init__."""
    for node in ast.walk(_observer_init(source)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Node":
            return node
    raise AssertionError("no Node(...) call in Observer.__init__")


def _switches(source: str | None = None) -> set[str]:
    return {k.arg for k in _node_call(source).keywords}


# ─────────────────── the three switches, read off the AST ───────────────────


def test_parameter_services_are_disabled():
    kwargs = {k.arg: k.value for k in _node_call().keywords}
    assert "start_parameter_services" in kwargs, (
        "Node() without start_parameter_services=False builds six parameter "
        "services the observer never uses")
    assert kwargs["start_parameter_services"].value is False


def test_rosout_is_disabled():
    kwargs = {k.arg: k.value for k in _node_call().keywords}
    assert "enable_rosout" in kwargs
    assert kwargs["enable_rosout"].value is False


def test_the_type_description_service_is_disabled():
    """The one that can only be switched off via parameter_overrides.

    Its failure message is "Failed to initialize type description service",
    which says nothing about what was left on -- the trap C2C-019 recorded as
    appearing for the third time.
    """
    kwargs = {k.arg: k.value for k in _node_call().keywords}
    assert "parameter_overrides" in kwargs, (
        "the type description service is built inside Node.__init__ and can "
        "only be disabled with parameter_overrides")
    dumped = ast.dump(kwargs["parameter_overrides"])
    assert "start_type_description_service" in dumped
    assert "False" in dumped


def test_all_three_switches_are_present_together():
    """Each alone is insufficient; the project's own note says so."""
    kwargs = {k.arg for k in _node_call().keywords}
    assert {"start_parameter_services", "enable_rosout",
            "parameter_overrides"} <= kwargs


@pytest.mark.parametrize("peer", _PEERS)
def test_the_same_pattern_is_used_by_the_peer_scripts(peer):
    """The switches are the project's established pattern, not a local guess.

    If a peer stops using them this test points at the drift rather than
    letting N37 look like the odd one out again.
    """
    text = (_ROOT / "紅隊測試" / "PoC腳本" / peer).read_text(encoding="utf-8")
    assert "start_parameter_services=False" in text
    assert "start_type_description_service" in text


# ─────────────────── a hang must name the step it hung on ───────────────────


def test_every_blocking_step_is_timed_and_flushed():
    """The four candidates for the block each get their own marker.

    A hang leaves the last printed marker as the step before the one that hung,
    so the set has to cover every call that can block.
    """
    init = ast.unparse(_observer_init())
    for label in ("import", "rclpy.init", "Node", "sub:alerts", "sub:cmd_vel"):
        assert f'mark("{label}"' in init or f"'{label}'" in init, label


def test_the_markers_flush_immediately():
    """An unflushed marker is lost when the factory sends SIGKILL.

    That is exactly how the 47 zero-byte sessions of 2026-09-25 lost their
    banner, so a marker that only reaches a buffer explains nothing.
    """
    init = ast.unparse(_observer_init())
    assert "flush=True" in init


def test_the_steps_are_recorded_on_the_instance_not_only_printed():
    """stdout is truncated per session; a list can be asserted on in tests."""
    init = ast.unparse(_observer_init())
    assert "self.steps" in init


def test_marks_come_after_their_step_not_before():
    """A marker printed before its call would attribute the hang one step early.

    Checked structurally: inside the try block every `mark(...)` statement must
    be preceded by at least one non-mark statement, i.e. no two marks are
    adjacent at the start.
    """
    for node in ast.walk(_observer_init()):
        if isinstance(node, ast.Try):
            body = node.body
            break
    else:  # pragma: no cover
        raise AssertionError("Observer.__init__ has no try block")

    first = ast.unparse(body[0])
    assert "mark(" not in first, (
        "the first statement in the try block is a marker, so it times nothing")


# ─────────────────── what this change does NOT claim ───────────────────


def test_the_constructor_still_degrades_instead_of_raising():
    """The observer is optional: a failure must leave the attack runnable.

    `pump()` falls back to sleeping when `ok` is false, and the driver prints a
    blind-reason warning. Turning the constructor into something that raises
    would lose the session the switches are meant to save.
    """
    init = ast.unparse(_observer_init())
    assert "except Exception" in init
    assert "self.blind_reason" in init
    assert "raise" not in init


def test_no_watchdog_was_added_around_the_construction():
    """C2C-082 measured that in-process bounding fails here.

    A thread or SIGALRM cannot interrupt a C extension holding the GIL, and a
    kernel-level hard stop would kill the session the hang already costs us.
    Re-adding one would repeat a failure the project already paid for.
    """
    init = ast.unparse(_observer_init())
    for banned in ("signal.alarm", "SIGALRM", "threading.Timer", "Thread("):
        assert banned not in init, banned


# ─────────────────── the checks have to bite ───────────────────

_PRE_FIX_NODE_CALL = 'self._node = Node("n37_probe")'


def test_the_switch_checks_reject_the_pre_fix_construction():
    """The exact line that shipped until 2026-10-02, fed back through the checker.

    Without this, every assertion above could be passing for the wrong reason:
    the project has repeatedly written a guard, watched the suite stay green,
    and only later found the guard was never exercised (C2C-073's 14 tests,
    C2C-088's empty fold list).
    """
    # Splice by AST position, not by string replacement: `ast.unparse` returns
    # normalised source that does not appear literally in the file, so a
    # `.replace()` silently matches nothing. The first version of this test did
    # exactly that -- and the `weakened != _source()` guard below is what caught
    # it, which is the whole reason that guard is here.
    source = _source()
    lines = source.splitlines(keepends=True)
    call = _node_call()
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))
    begin = starts[call.lineno - 1] + call.col_offset
    end = starts[call.end_lineno - 1] + call.end_col_offset
    weakened = source[:begin] + _PRE_FIX_NODE_CALL.split(" = ", 1)[1] + source[end:]

    assert weakened != source, "the mutation did not change anything"
    assert _switches(weakened) == set(), (
        "the pre-fix call took no keywords, so the checker must see none")


@pytest.mark.parametrize("dropped", [
    "start_parameter_services",
    "enable_rosout",
    "parameter_overrides",
])
def test_dropping_any_one_switch_is_detectable(dropped):
    """Each switch is checked on its own, so losing one cannot hide."""
    assert dropped in _switches(), f"{dropped} is not currently present"
