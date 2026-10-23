"""The adaptive attacker's blindness flag must be recorded, and must never
read as "sighted" when it could not be determined.

N37 already recorded it three times over -- the recon line's blind marker, a
"blind" key on every step of the decision trace, and a warning line carrying
the underlying RCLError -- and nothing downstream read any of them. Measured
across the whole of dataset_mega: insider_parameter_write 22/22 and
insider_hmac_forgery 17/17 ran blind, every other scenario 0/790. So the label
"adaptive attacker" has never held for the two credentialed-insider classes,
and no artifact said so.

The blindness itself is the threat model working: a thief of node X's
credentials cannot also be n37_probe, so the observer's secure node creation
fails closed. The defect was purely that it went unrecorded -- and the fix is
recording, not granting the attacker an enclave it should not have.

These tests pin the three decisions that make the recording trustworthy:

  1. three-valued, so an absent trace reads as None and never as False
  2. outside the training gate, so recording is not a relaxation
  3. never raises, so a malformed log cannot destroy a live session
"""
from __future__ import annotations

import json
import pathlib

import pytest

from firewall_lab.orchestrator import (
    _BLIND_WARNING_MARKER,
    _read_adaptive_blindness,
)

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_ORCH = _ROOT / "firewall_lab" / "orchestrator.py"

_ATTACK_RESULT = {"return_code": 0}
_GATE_NAMES = (
    "pcap", "zeek", "packet_windows",
    "capture_process", "attack_process", "runtime_telemetry",
)


def _trace(*blind_flags: bool) -> str:
    steps = [
        {"step": i + 1, "burst_sec": 5.0, "intensity": 0.3, "rc": 0,
         "alerts": 0, "decision": "x", "blind": flag}
        for i, flag in enumerate(blind_flags)
    ]
    return "DECISION_TRACE " + json.dumps(steps, ensure_ascii=False) + "\n"


def _session(tmp_path: pathlib.Path, stdout: str | None) -> pathlib.Path:
    directory = tmp_path / "session"
    directory.mkdir(exist_ok=True)
    if stdout is not None:
        (directory / "attack.stdout.log").write_text(stdout, encoding="utf-8")
    return directory


def _gate_block() -> str:
    source = _ORCH.read_text(encoding="utf-8")
    start = source.index("gate_failures = [")
    return source[start:source.index("if not passed", start)]


# ------------------- decision 1: three-valued -------------------

def test_a_blind_trace_is_recorded_as_blind(tmp_path):
    directory = _session(tmp_path, "banner\n" + _trace(True, True, True))
    out = _read_adaptive_blindness(
        directory, adaptive=True, attack_result=_ATTACK_RESULT)
    assert out["status"] == "observed"
    assert out["blind"] is True
    assert out["blind_steps"] == 3
    assert out["total_steps"] == 3


def test_a_sighted_trace_is_recorded_as_not_blind(tmp_path):
    directory = _session(tmp_path, "banner\n" + _trace(False, False))
    out = _read_adaptive_blindness(
        directory, adaptive=True, attack_result=_ATTACK_RESULT)
    assert out["status"] == "observed"
    assert out["blind"] is False
    assert out["blind_steps"] == 0
    assert out["total_steps"] == 2


def test_a_mixture_is_blind_but_the_counts_stay_visible(tmp_path):
    """observer.ok is fixed at construction so the steps should agree.

    If they ever disagree, "was blind at some point" is the conservative read
    -- but collapsing a mixture into one boolean would hide exactly the kind
    of heterogeneity this whole exercise was about, so the counts are recorded
    alongside it.
    """
    directory = _session(tmp_path, _trace(False, True, False))
    out = _read_adaptive_blindness(
        directory, adaptive=True, attack_result=_ATTACK_RESULT)
    assert out["blind"] is True
    assert (out["blind_steps"], out["total_steps"]) == (1, 3)


@pytest.mark.parametrize(
    "stdout, reason",
    [
        (None, "missing_stdout_log"),
        ("banner only, the driver died before the trace\n", "no_decision_trace"),
        ("DECISION_TRACE not-json-at-all\n", "decision_trace_not_json"),
        ("DECISION_TRACE []\n", "decision_trace_empty"),
        ('DECISION_TRACE [{"step": 1}]\n', "steps_missing_blind_flag"),
    ],
)
def test_an_undeterminable_trace_is_unknown_and_never_sighted(
    tmp_path, stdout, reason
):
    """This is the test that matters most.

    The failure this whole finding is about is a property that went unrecorded
    and therefore read as fine. If blind defaulted to False whenever the trace
    could not be parsed, the record would assert "the observer worked" on
    exactly the sessions where we cannot tell -- reproducing the original
    defect inside its own fix.
    """
    directory = _session(tmp_path, stdout)
    out = _read_adaptive_blindness(
        directory, adaptive=True, attack_result=_ATTACK_RESULT)
    assert out["status"] == "unknown"
    assert out["reason"] == reason
    assert out["blind"] is None, (
        "an undeterminable flag must not read as sighted -- that is the "
        "original defect wearing the clothes of its own fix"
    )


def test_not_applicable_is_distinct_from_unknown(tmp_path):
    """A non-adaptive runner has no decision trace by construction.

    Recording that as unknown would put it in the same bucket as a session
    whose trace was lost, and then "how many sessions could we not tell about"
    becomes unanswerable.
    """
    directory = _session(tmp_path, None)
    out = _read_adaptive_blindness(
        directory, adaptive=False, attack_result=_ATTACK_RESULT)
    assert out == {"status": "not_applicable", "reason": "not_adaptive",
                   "blind": None}

    out = _read_adaptive_blindness(
        directory, adaptive=True, attack_result=None)
    assert out["status"] == "not_applicable"
    assert out["reason"] == "no_attack_process"


def test_the_observer_error_is_kept_because_it_names_the_mechanism(tmp_path):
    """The RCLError text is what identified the cause, so keep it.

    The fixture builds its warning line from the module's own marker rather
    than a copy of it. A hand-written copy is how a test drifts away from the
    code it is supposed to pin: the first version of this test spelled the
    marker in English, passed nothing to the parser, and failed for a reason
    that had nothing to do with the behaviour under test.
    """
    warning = (
        "   observer saw nothing (RCLError: error creating node: couldn't "
        "find all security files!) -- " + _BLIND_WARNING_MARKER
        + ". Expected under Enforce."
    )
    directory = _session(tmp_path, warning + "\n" + _trace(True))
    out = _read_adaptive_blindness(
        directory, adaptive=True, attack_result=_ATTACK_RESULT)
    assert out["blind"] is True
    assert "security files" in (out["observer_error"] or "")


# ------------------- decision 2: outside the gate -------------------

def test_blindness_is_not_a_gate_condition():
    """Recording is not relaxing, and it is not tightening either.

    A blind session's attack really executed -- the HMAC forgery and the
    parameter write both happened -- so failing it would discard real
    evidence. Whether it should affect the gate is a separate decision about
    pass criteria, and this test pins that this change did not quietly make it.
    """
    block = _gate_block()
    assert "adaptive_observer" not in block
    assert "blind" not in block


def test_the_gate_still_has_exactly_its_six_conditions():
    block = _gate_block()
    present = [name for name in _GATE_NAMES if f'("{name}", ' in block]
    assert present == list(_GATE_NAMES)
    assert block.count('("') == len(_GATE_NAMES), (
        "the number of gate conditions changed -- that is a change to the "
        "pass criteria, not a recording change"
    )


def test_the_flag_is_actually_wired_into_the_manifest():
    """A reader that is never wired up is the defect, not the fix.

    stream_replay.py was written, tested, and then imported by nobody for a
    month (C2C-038), so assert the call site exists -- not just the helper.
    """
    source = _ORCH.read_text(encoding="utf-8")
    assert "adaptive_observer = _read_adaptive_blindness(" in source
    assert '"adaptive_observer": adaptive_observer,' in source


def test_the_adaptive_claim_is_qualified_where_it_is_made():
    """"Adaptive attacker" is unqualified in two places, and false in both.

    N37's own docstring said it "watches the defence and changes behaviour",
    and the campaign supervisor described the whole run as adaptive. Measured
    across dataset_mega, the two credentialed-insider scenarios are 22/22 and
    17/17 blind while every other scenario is 0/790 -- so the claim has never
    held for them. The recording now makes that auditable per session, but an
    unqualified claim at the top of the file is what the next reader sees
    first. Pin the qualification where the claim is made.
    """
    for path in (_ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py",
                 _ROOT / "工具腳本" / "run_mega_campaign.sh"):
        head = path.read_text(encoding="utf-8")[:4000]
        assert "insider" in head, f"{path.name} 沒有提到內鬼的例外"
        assert "adaptive_observer" in head, (
            f"{path.name} 沒有指向逐場記錄的那個欄位"
        )


# ------------------- decision 3: never raises -------------------

@pytest.mark.parametrize("stdout", [
    "DECISION_TRACE " + "{" * 500,
    "DECISION_TRACE " + json.dumps({"not": "a list"}),
    "DECISION_TRACE " + json.dumps([None, 3, "x"]),
    "\x00\x01\x02 DECISION_TRACE [",
    "DECISION_TRACE ",
])
def test_a_malformed_log_never_raises(tmp_path, stdout):
    directory = _session(tmp_path, stdout)
    out = _read_adaptive_blindness(
        directory, adaptive=True, attack_result=_ATTACK_RESULT)
    assert out["status"] == "unknown"
    assert out["blind"] is None
