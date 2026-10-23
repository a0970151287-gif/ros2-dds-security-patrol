"""The campaign lock has to tell its own corpse from a live holder.

The original lock wrote `pid=` into the file and nobody ever read it, so any
crash -- power loss, SIGKILL, OOM -- left a lock that permanently blocked every
later campaign and every `repair`. The only recovery was `rm -f`.

Measured 2026-09-25: after a reboot `mega_plan.json.lock` named pid 168734,
long dead, and the plan could not be touched.

That forced `rm -f` is what caused the C2C-069 incident. Because the lock could
not distinguish stale from live, deleting it became routine -- and one of those
deletions removed a *live* lock, leaving two campaigns writing the same plan
file from their own in-memory copies. Moving the judgement inside the lock is
what stops the dangerous path from being routine.

The asymmetry below is deliberate and is the whole safety argument:

    dead holder      -> take over   (a stuck plan is certain, and recoverable)
    live holder      -> refuse      (concurrent writers corrupt the plan)
    recycled pid     -> take over   (pids wrap; an impostor must not hold it)
    unreadable lock  -> refuse      (cannot prove death; guess costs the plan)
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from firewall_lab.campaign import (  # noqa: E402
    _CampaignLock,
    _campaign_process_alive,
    _lock_holder_pid,
)

linux_only = pytest.mark.skipif(
    not pathlib.Path("/proc").is_dir(), reason="needs /proc for cmdline checks"
)


@pytest.fixture()
def plan(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text("{}", encoding="utf-8")
    return path


def _lock_path(plan: pathlib.Path) -> pathlib.Path:
    return plan.with_suffix(plan.suffix + ".lock")


def _dead_pid() -> int:
    """A pid that is certainly not running: run a trivial child and reap it.

    ⚠️ Deliberately not `os.fork()`. Forking a multi-threaded process is exactly
    the hazard the code under test documents, and pytest is multi-threaded, so
    Python 3.12 warns on every call. The fork was safe here -- the child did
    nothing but `_exit` -- but three unexplained warnings in the project's count
    is worse than spending 40ms on a subprocess.
    """
    child = subprocess.Popen([sys.executable, "-c", ""])
    assert child.wait(timeout=60) == 0
    return child.pid


# ─────────────────────── reading the holder ───────────────────────


def test_the_holder_pid_is_read_back(plan):
    _lock_path(plan).write_text("pid=4242\n", encoding="ascii")
    assert _lock_holder_pid(_lock_path(plan)) == 4242


@pytest.mark.parametrize("body", ["", "\n", "garbage", "pid=\n", "pid=abc\n",
                                  "pid=0\n", "pid=-3\n", "owner=7\n"])
def test_an_unusable_lock_body_reads_as_no_pid(plan, body):
    """`None` means "cannot tell", which is not the same as "nobody holds it"."""
    _lock_path(plan).write_text(body, encoding="ascii")
    assert _lock_holder_pid(_lock_path(plan)) is None


def test_a_missing_lock_reads_as_no_pid(plan):
    assert _lock_holder_pid(_lock_path(plan)) is None


# ─────────────────── deciding whether the holder lives ───────────────────


def test_a_reaped_pid_is_not_alive():
    assert _campaign_process_alive(_dead_pid()) is False


@linux_only
def test_this_test_process_is_not_mistaken_for_a_campaign():
    """pytest is alive but is not a campaign, so it must not hold the lock.

    This is the pid-reuse case: the number exists, the process is not ours.
    Treating "alive" alone as "still held" is what makes a lock unbreakable.
    """
    assert _campaign_process_alive(os.getpid()) is False


@linux_only
def test_a_process_whose_cmdline_names_the_campaign_counts_as_alive(monkeypatch):
    """The live-holder path, exercised without spawning a real campaign."""
    real = pathlib.Path.read_bytes

    def fake(self, *a, **kw):
        if str(self).startswith("/proc/"):
            return b"python3\x00-m\x00firewall_lab.campaign\x00run\x00"
        return real(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "read_bytes", fake)
    assert _campaign_process_alive(os.getpid()) is True


def test_an_unreadable_cmdline_is_treated_as_alive(monkeypatch):
    """Cannot tell -> assume someone is running. Fail closed, not clever."""
    def boom(self, *a, **kw):
        raise OSError("no /proc here")

    monkeypatch.setattr(pathlib.Path, "read_bytes", boom)
    assert _campaign_process_alive(os.getpid()) is True


# ─────────────────────── the lock's behaviour ───────────────────────


def test_an_uncontended_lock_is_taken_and_released(plan):
    with _CampaignLock(plan) as lock:
        assert _lock_path(plan).is_file()
        assert lock.stole_from is None
        assert _lock_holder_pid(_lock_path(plan)) == os.getpid()
    assert not _lock_path(plan).exists()


def test_a_dead_holder_is_taken_over(plan, capsys):
    """The defect this fix exists for: a reboot must not strand the plan."""
    dead = _dead_pid()
    _lock_path(plan).write_text(f"pid={dead}\n", encoding="ascii")
    with _CampaignLock(plan) as lock:
        assert lock.stole_from == dead
        assert _lock_holder_pid(_lock_path(plan)) == os.getpid()
    assert "接手已死的 campaign 鎖" in capsys.readouterr().out


def test_taking_over_is_announced_not_silent(plan, capsys):
    """A silent takeover would hide that the machine crashed."""
    dead = _dead_pid()
    _lock_path(plan).write_text(f"pid={dead}\n", encoding="ascii")
    with _CampaignLock(plan):
        pass
    out = capsys.readouterr().out
    assert str(dead) in out


@linux_only
def test_a_live_holder_is_still_refused(plan, monkeypatch):
    """The 09-20 failure mode: two campaigns writing one plan.

    Nothing in this change may make a live lock breakable.
    """
    real = pathlib.Path.read_bytes

    def fake(self, *a, **kw):
        if str(self).startswith("/proc/"):
            return b"python3\x00-m\x00firewall_lab.campaign\x00"
        return real(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "read_bytes", fake)
    _lock_path(plan).write_text(f"pid={os.getpid()}\n", encoding="ascii")
    with pytest.raises(RuntimeError, match="already locked by live pid"):
        with _CampaignLock(plan):
            pass


def test_a_recycled_pid_does_not_keep_the_lock(plan):
    """Alive, but not a campaign -- the original holder died and pid wrapped."""
    _lock_path(plan).write_text(f"pid={os.getpid()}\n", encoding="ascii")
    with _CampaignLock(plan) as lock:
        assert lock.stole_from == os.getpid()


@pytest.mark.parametrize("body", ["", "garbage", "pid=abc\n"])
def test_an_unreadable_lock_is_refused_not_taken_over(plan, body):
    """Cannot prove the holder died, and guessing wrong corrupts the plan.

    This keeps `rm -f` available for the genuinely rare case while refusing to
    make it routine -- the message says what to confirm first.
    """
    _lock_path(plan).write_text(body, encoding="ascii")
    with pytest.raises(RuntimeError, match="names no readable pid"):
        with _CampaignLock(plan):
            pass
    assert _lock_path(plan).read_text(encoding="ascii") == body


def test_the_refusal_says_how_to_check_before_removing_by_hand(plan):
    _lock_path(plan).write_text("garbage", encoding="ascii")
    with pytest.raises(RuntimeError) as excinfo:
        with _CampaignLock(plan):
            pass
    message = str(excinfo.value)
    assert "pgrep" in message
    assert "firewall_lab.campaign" in message


def test_the_lock_is_released_even_when_the_body_raises(plan):
    with pytest.raises(ValueError):
        with _CampaignLock(plan):
            raise ValueError("boom")
    assert not _lock_path(plan).exists()


def test_a_second_lock_in_the_same_process_is_refused(plan, monkeypatch):
    """Re-entrancy is not supported and must not silently appear to work."""
    real = pathlib.Path.read_bytes

    def fake(self, *a, **kw):
        if str(self).startswith("/proc/"):
            return b"python3\x00-m\x00firewall_lab.campaign\x00"
        return real(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "read_bytes", fake)
    with _CampaignLock(plan):
        with pytest.raises(RuntimeError, match="already locked"):
            with _CampaignLock(plan):
                pass
