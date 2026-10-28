"""Each session records which stack instance (batch) it ran on, read from the
stack's own pid file rather than a supervisor-supplied label.

Why (2026-10-28): "batch (stack instance)" was a time-window proxy through
C2C-116/124/125/127, and P0 itself recorded that the supervisor log is only a
weak corroborator (23% coverage, 31% false positives). This turns it into a
real per-session variable so leave-batch-out CV can group on it.

The id is (boot_id, pid, starttime) hashed: a recycled pid changes starttime, a
reboot changes boot_id, so the triple uniquely names one stack_up. Observed at
start and at end; the id is only given when both agree, so a mid-session
restart is recorded as same=False with no id -- it belongs to no batch.
"""
from __future__ import annotations

import os

from firewall_lab.orchestrator import (
    _observe_stack_instance,
    _summarize_stack_instance,
)


def _write_pid(runtime, mode, pid):
    (runtime / f"{mode}.pid").write_text(str(pid), encoding="utf-8")


def test_a_live_pid_yields_a_stable_observed_id(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_LIVE_RUNTIME", str(tmp_path))
    _write_pid(tmp_path, "enforce", os.getpid())
    a = _observe_stack_instance("enforce")
    b = _observe_stack_instance("enforce")
    assert a["status"] == "observed"
    assert a["id"] == b["id"], "same process must hash to the same id"
    assert a["id"].startswith("enforce-")
    assert a["pid"] == os.getpid()


def test_a_missing_pid_file_is_unknown_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_LIVE_RUNTIME", str(tmp_path))
    out = _observe_stack_instance("enforce")
    assert out == {"status": "unknown", "reason": "missing_pid_file",
                   "id": None}


def test_a_noninteger_pid_file_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_LIVE_RUNTIME", str(tmp_path))
    (tmp_path / "enforce.pid").write_text("not-a-pid\n", encoding="utf-8")
    out = _observe_stack_instance("enforce")
    assert out["status"] == "unknown"
    assert out["reason"] == "pid_file_not_integer"
    assert out["id"] is None


def test_a_dead_pid_is_unknown_never_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("FIREWALL_LIVE_RUNTIME", str(tmp_path))
    # A pid that cannot exist: /proc/<pid>/stat is absent.
    _write_pid(tmp_path, "enforce", 2_000_000_000)
    out = _observe_stack_instance("enforce")
    assert out["status"] == "unknown"
    assert out["reason"].startswith("unreadable")
    assert out["id"] is None


def test_same_instance_at_both_ends_gives_the_id():
    inst = {"status": "observed", "id": "enforce-abc"}
    out = _summarize_stack_instance(inst, dict(inst))
    assert out["status"] == "observed"
    assert out["id"] == "enforce-abc"
    assert out["same"] is True


def test_a_mid_session_restart_belongs_to_no_batch():
    start = {"status": "observed", "id": "enforce-aaa"}
    end = {"status": "observed", "id": "enforce-bbb"}
    out = _summarize_stack_instance(start, end)
    assert out["same"] is False
    assert out["id"] is None, (
        "a session that spanned two stack instances is not in any one batch"
    )


def test_an_unobserved_end_gives_no_id():
    start = {"status": "observed", "id": "enforce-aaa"}
    end = {"status": "unknown", "reason": "missing_pid_file", "id": None}
    out = _summarize_stack_instance(start, end)
    assert out["status"] == "unknown"
    assert out["id"] is None


def test_smoke_mode_is_not_applicable():
    out = _summarize_stack_instance(None, None)
    assert out["status"] == "not_applicable"
    assert out["id"] is None
