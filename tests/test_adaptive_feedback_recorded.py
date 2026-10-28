"""The attacker records not just whether its observer was *alive* but whether
it *received anything*, as two separable fields.

Why (2026-10-28, C2C-129): `blind` only records whether `Observer()` returned.
Under Enforce an unauthenticated observer constructs fine (blind=False) yet
receives no messages because the handshake is blocked -- 1,357 enforce sessions
were recorded as "observer fine" while both channels were zero across all
9,196 bursts. From the old trace, "robot at full speed" and "received nothing"
look identical, because zero_fraction defaults to 0.0 when cmd_total == 0 and
the trace did not record cmd_total.

Same three-valued discipline as blind (C2C-098): a trace without cmd_total
reads as None, never False -- "could not tell" must not read as "received
nothing", nor the reverse.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from firewall_lab.orchestrator import _read_adaptive_blindness

_ATTACK_RESULT = {"return_code": 0}


def _trace(steps: list[dict]) -> str:
    return "DECISION_TRACE " + json.dumps(steps, ensure_ascii=False) + "\n"


def _session(tmp_path: pathlib.Path, stdout: str) -> pathlib.Path:
    directory = tmp_path / "session"
    directory.mkdir(exist_ok=True)
    (directory / "attack.stdout.log").write_text(stdout, encoding="utf-8")
    return directory


def _read(tmp_path, steps):
    directory = _session(tmp_path, _trace(steps))
    return _read_adaptive_blindness(
        directory, adaptive=True, attack_result=_ATTACK_RESULT)


def test_received_feedback_is_recorded(tmp_path):
    out = _read(tmp_path, [
        {"step": 1, "blind": False, "cmd_total": 40, "alerts": 2},
        {"step": 2, "blind": False, "cmd_total": 38, "alerts": 0},
    ])
    assert out["feedback_received"] is True
    assert out["feedback_steps"] == 2
    assert out["cmd_received_total"] == 78
    assert out["alerts_received_total"] == 2


def test_alive_but_received_nothing_is_the_enforce_case(tmp_path):
    out = _read(tmp_path, [
        {"step": 1, "blind": False, "cmd_total": 0, "alerts": 0},
        {"step": 2, "blind": False, "cmd_total": 0, "alerts": 0},
    ])
    assert out["blind"] is False, "observer constructed fine"
    assert out["feedback_received"] is False, (
        "alive and receiving-nothing are different facts -- this is the whole "
        "point of C2C-129"
    )
    assert out["cmd_received_total"] == 0
    assert out["alerts_received_total"] == 0


def test_a_single_channel_counts_as_feedback(tmp_path):
    out = _read(tmp_path, [
        {"step": 1, "blind": False, "cmd_total": 0, "alerts": 3},
    ])
    assert out["feedback_received"] is True
    assert out["feedback_steps"] == 1


def test_a_trace_without_cmd_total_is_none_not_false(tmp_path):
    """The old sessions have no cmd_total. That must read as unknown, never as
    "received nothing" -- the same defect C2C-098 fixed for blind, reappearing
    one field over."""
    out = _read(tmp_path, [
        {"step": 1, "blind": False, "alerts": 2},
    ])
    assert out["feedback_received"] is None, (
        "an absent cmd_total must not read as received-nothing"
    )
    assert out["feedback_steps"] is None
    assert out["cmd_received_total"] is None
    assert out["feedback_reason"] == "steps_missing_cmd_total"


def test_missing_alerts_is_also_none(tmp_path):
    out = _read(tmp_path, [
        {"step": 1, "blind": False, "cmd_total": 10},
    ])
    assert out["feedback_received"] is None
    assert out["feedback_reason"] == "steps_missing_alerts"


@pytest.mark.parametrize("bad", [
    {"step": 1, "blind": False, "cmd_total": -1, "alerts": 0},
    {"step": 1, "blind": False, "cmd_total": True, "alerts": 0},
    {"step": 1, "blind": False, "cmd_total": 1.5, "alerts": 0},
])
def test_malformed_counts_read_as_unknown_never_as_zero(tmp_path, bad):
    out = _read(tmp_path, [bad])
    assert out["feedback_received"] is None


def test_blind_and_feedback_are_independent_fields(tmp_path):
    """A blind session can still carry feedback fields, and they do not
    overwrite the blind verdict."""
    out = _read(tmp_path, [
        {"step": 1, "blind": True, "cmd_total": 0, "alerts": 0},
    ])
    assert out["blind"] is True
    assert out["feedback_received"] is False
    assert "blind_steps" in out and out["blind_steps"] == 1
