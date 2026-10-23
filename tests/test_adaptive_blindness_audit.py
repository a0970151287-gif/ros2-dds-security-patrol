"""The blindness audit must read the flag where it actually lives, and an
absent flag must never read as "not adaptive".

The first version of this tool read `manifest["adaptive"]` while the flag
lives at `manifest["randomization"]["adaptive"]`. It reported "not_adaptive"
for all 2,053 sessions -- a lookup that could not succeed returning the
reassuring answer, which is the same failure the audit exists to expose. With
the path fixed: 113 blind sessions, every one of them an insider scenario
(`insider_hmac_forgery` 55/55, `insider_parameter_write` 58/58), and zero
across the other 1,411 determinable sessions.

So these tests pin the lookup itself, not just the arithmetic around it.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TOOL = _ROOT / "工具腳本" / "audit_adaptive_blindness.py"


def _load():
    spec = importlib.util.spec_from_file_location("_blind_audit", _TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _trace(*blind_flags: bool) -> str:
    steps = [
        {"step": i + 1, "rc": 0, "alerts": 0, "decision": "x", "blind": flag}
        for i, flag in enumerate(blind_flags)
    ]
    return "DECISION_TRACE " + json.dumps(steps) + "\n"


def _session(
    dataset: pathlib.Path,
    name: str,
    *,
    manifest: dict,
    stdout: str | None = None,
) -> pathlib.Path:
    directory = dataset / name
    directory.mkdir(parents=True)
    (directory / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    if stdout is not None:
        (directory / "attack.stdout.log").write_text(stdout, encoding="utf-8")
    return directory


def _manifest(**overrides) -> dict:
    base = {
        "status": "complete",
        "scenario_id": "insider_hmac_forgery",
        "security_mode": "enforce",
        "randomization": {"adaptive": True},
        "result": {"attack_process": {"return_code": 0}},
    }
    base.update(overrides)
    return base


def test_the_adaptive_flag_is_read_from_its_real_nesting(tmp_path):
    """The exact bug: the flag is nested, and reading the top level fails."""
    dataset = tmp_path / "dataset"
    _session(dataset, "s1", manifest=_manifest(), stdout=_trace(True))
    report = _load().audit(dataset)
    assert report["determinable"] == 1, (
        "the flag lives at randomization.adaptive -- reading the top level "
        "makes every session look non-adaptive"
    )
    assert report["blind"] == 1
    assert report["per_scenario"]["insider_hmac_forgery"]["blind"] == 1


def test_a_missing_flag_is_unknown_not_not_adaptive(tmp_path):
    """"The record moved" and "this runner has no trace" are different facts.

    Collapsing them makes "how many sessions can we not tell about"
    unanswerable, which is how the original bug stayed invisible: 2,053
    sessions reported as a clean `not_adaptive` rather than as unreadable.
    """
    dataset = tmp_path / "dataset"
    manifest = _manifest()
    del manifest["randomization"]
    _session(dataset, "s1", manifest=manifest, stdout=_trace(True))
    report = _load().audit(dataset)
    assert report["determinable"] == 0
    assert report["undeterminable"] == 1
    assert report["undeterminable_reasons"] == {
        "adaptive_flag_absent_from_manifest": 1}
    assert "not_adaptive" not in report["undeterminable_reasons"]


@pytest.mark.parametrize("randomization", [None, {}, {"other": 1}, "yes", []])
def test_a_malformed_randomization_block_is_also_unknown(
    tmp_path, randomization
):
    dataset = tmp_path / "dataset"
    _session(dataset, "s1", manifest=_manifest(randomization=randomization),
             stdout=_trace(True))
    report = _load().audit(dataset)
    assert report["determinable"] == 0
    assert report["undeterminable_reasons"] == {
        "adaptive_flag_absent_from_manifest": 1}


def test_a_sighted_session_is_counted_separately_from_an_unknown_one(tmp_path):
    dataset = tmp_path / "dataset"
    _session(dataset, "s1", manifest=_manifest(scenario_id="cmd_vel_injection"),
             stdout=_trace(False, False))
    _session(dataset, "s2", manifest=_manifest(), stdout=_trace(True))
    _session(dataset, "s3", manifest=_manifest(), stdout="no trace here\n")
    report = _load().audit(dataset)
    assert report["determinable"] == 2
    assert report["blind"] == 1
    assert report["undeterminable"] == 1
    assert report["undeterminable_reasons"] == {"no_decision_trace": 1}
    assert report["blind_rate_of_determinable"] == 0.5


def test_incomplete_sessions_are_skipped_not_counted(tmp_path):
    dataset = tmp_path / "dataset"
    _session(dataset, "s1", manifest=_manifest(status="running"),
             stdout=_trace(True))
    report = _load().audit(dataset)
    assert report["sessions_complete"] == 0
    assert report["blind"] == 0


def test_the_audit_does_not_write_into_session_directories(tmp_path):
    """Originals must stay byte-identical -- the project never back-fills."""
    dataset = tmp_path / "dataset"
    directory = _session(dataset, "s1", manifest=_manifest(),
                         stdout=_trace(True))
    before = {
        p.name: (p.stat().st_size, p.read_bytes())
        for p in sorted(directory.iterdir())
    }
    report = _load().audit(dataset)
    after = {
        p.name: (p.stat().st_size, p.read_bytes())
        for p in sorted(directory.iterdir())
    }
    assert before == after
    assert sorted(p.name for p in directory.iterdir()) == [
        "attack.stdout.log", "manifest.json"]
    assert report["wrote_to_session_directories"] is False


def test_the_audit_declares_that_it_does_not_touch_the_gate():
    """The flag is an observation; making it a gate condition is a decision
    about pass criteria, and the artifact has to say which one it is."""
    report_keys = _load().audit.__doc__
    assert report_keys is not None
    source = _TOOL.read_text(encoding="utf-8")
    assert '"affects_training_gate": False,' in source


def test_it_refuses_to_overwrite_an_existing_audit(tmp_path, capsys):
    dataset = tmp_path / "dataset"
    _session(dataset, "s1", manifest=_manifest(), stdout=_trace(True))
    out = tmp_path / "report.json"
    out.write_text("{}", encoding="utf-8")
    module = _load()
    with pytest.raises(SystemExit):
        module.main(["--dataset", str(dataset), "--output", str(out)])
    assert out.read_text(encoding="utf-8") == "{}"


def test_it_imports_the_orchestrator_helper_rather_than_reimplementing_it():
    """Two implementations of one parser drift apart (C2C-060).

    The audit and the manifest must agree by construction, so the tool has to
    import the helper -- a second copy here would start disagreeing the first
    time either side changed.
    """
    source = _TOOL.read_text(encoding="utf-8")
    assert "from firewall_lab.orchestrator import _read_adaptive_blindness" in source
    assert "DECISION_TRACE" not in source.split('"""', 2)[-1], (
        "the tool parses the trace by importing the helper, so the marker "
        "should not appear in its code"
    )
