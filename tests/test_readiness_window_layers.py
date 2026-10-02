"""Three nested waits guard stack readiness, and the inner one must not expire
first -- otherwise the outer window is unreachable and its failure message lies.

Measured on 2026-09-28, from the Enforce stack log of a failing round:

    08:41:23  gazebo.launch.py starts; its launch.log gets the banner and
              nothing else -- no "process started" for the next 118 seconds
    08:41:27  all seven stack nodes come up, HMAC fingerprints matching
    08:43:21  the readiness probe gives up at its 120s ceiling
              -> the stack tears itself down fail-closed
    (never)   the supervisor's 200s poll window had 80s left

The supervisor then logged `⛔ enforce stack 起不來`, which is false twice over:
the stack came up, and it was stopped deliberately. `tail -4` of the shared log
showed only the teardown cascade (`rcl_shutdown already called`, six times, one
per process), so the surface pointed at DDS while the cause was Gazebo being
slow to launch.

`gazebo.launch.py` documents the slowness itself: its includes "scan every
installed ROS package to build Gazebo paths, which is especially slow on a
WSL-mounted workspace". C2C-062 measured 39s for that, on an idle machine.

What this file pins is the ORDERING, not the specific seconds. Raising one
number alone is how the inversion happened, so each layer is checked against
its neighbour rather than against a constant.
"""

from __future__ import annotations

import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SUPERVISOR = _ROOT / "工具腳本" / "run_mega_campaign.sh"
_STACKS = {
    "permissive": _ROOT / "展示指令" / "01_啟動系統.sh",
    "enforce": _ROOT / "展示指令" / "01c_啟動系統_enforce.sh",
}


def _probe_seconds(path: pathlib.Path) -> float:
    """The readiness probe's own ceiling (`-p timeout_sec:=N`)."""
    hit = re.search(r"timeout_sec:=([0-9.]+)", path.read_text(encoding="utf-8"))
    assert hit, f"no timeout_sec in {path.name}"
    return float(hit.group(1))


def _wrapper_seconds(path: pathlib.Path) -> float:
    """The `timeout --signal=TERM N` that bounds the probe process."""
    hit = re.search(r"timeout --signal=TERM\s+([0-9.]+)",
                    path.read_text(encoding="utf-8"))
    assert hit, f"no timeout wrapper in {path.name}"
    return float(hit.group(1))


def _supervisor_seconds() -> float:
    """The supervisor's readiness poll: `seq 1 N` iterations of `sleep M`."""
    text = _SUPERVISOR.read_text(encoding="utf-8")
    block = text[text.index("stack_up()"):]
    iterations = re.search(r"for i in \$\(seq 1 (\d+)\); do", block)
    sleep = re.search(r"sleep (\d+)", block)
    assert iterations and sleep, "the stack_up poll loop changed shape"
    return float(iterations.group(1)) * float(sleep.group(1))


# ─────────────────── the ordering, layer against layer ───────────────────


@pytest.mark.parametrize("mode", sorted(_STACKS))
def test_the_probe_ceiling_is_below_its_own_wrapper(mode):
    """The wrapper exists to kill a probe that ignores its own ceiling.

    If the wrapper fires first, the probe never gets to report *why* it failed
    and the stack log loses the only line that names the missing stream.
    """
    probe = _probe_seconds(_STACKS[mode])
    wrapper = _wrapper_seconds(_STACKS[mode])
    assert probe < wrapper, (
        f"{mode}: probe ceiling {probe}s must be under the wrapper {wrapper}s")


@pytest.mark.parametrize("mode", sorted(_STACKS))
def test_the_wrapper_is_below_the_supervisor_poll_window(mode):
    """The inversion that cost the 2026-09-28 run.

    With wrapper 130s against a 200s poll, the stack always tore itself down
    with 70s of the supervisor's patience unspent -- so the supervisor could
    only ever observe "not ready", never "ready but slow".
    """
    wrapper = _wrapper_seconds(_STACKS[mode])
    outer = _supervisor_seconds()
    assert wrapper < outer, (
        f"{mode}: wrapper {wrapper}s must be under the supervisor's {outer}s, "
        "or the outer window is unreachable")


@pytest.mark.parametrize("mode", sorted(_STACKS))
def test_the_probe_allows_more_than_the_measured_gazebo_silence(mode):
    """118s of silence was measured, and it was not a timeout -- it was a floor.

    We never saw when Gazebo *would* have come up, so the ceiling has to clear
    the observed silence by a real margin rather than hug it.
    """
    probe = _probe_seconds(_STACKS[mode])
    assert probe > 118.0 * 1.5, (
        f"{mode}: {probe}s leaves no margin over the 118s silence actually "
        "measured; the launch was still working, not stuck")


def test_both_modes_use_the_same_windows():
    """A per-mode difference would turn a timing bug into a mode-specific one.

    The 2026-09-28 run looked Enforce-specific for three rounds and then took
    Permissive down too; identical windows keep that from being mistaken for a
    property of SROS2.
    """
    probes = {m: _probe_seconds(p) for m, p in _STACKS.items()}
    wrappers = {m: _wrapper_seconds(p) for m, p in _STACKS.items()}
    assert len(set(probes.values())) == 1, probes
    assert len(set(wrappers.values())) == 1, wrappers


# ─────────────────── the check has to bite ───────────────────


def test_the_pre_fix_numbers_would_be_rejected():
    """130s wrapper against a 200s poll -- exactly what shipped until today.

    Without this, the ordering tests could all pass on numbers that happen to
    be fine while the comparison itself is wrong.
    """
    pre_fix_wrapper, pre_fix_outer = 130.0, 200.0
    assert pre_fix_wrapper < pre_fix_outer, (
        "sanity: the pre-fix numbers were ordered, which is why the bug was "
        "subtle -- the ordering held but the margin was below what Gazebo needs")
    pre_fix_probe = 120.0
    assert not pre_fix_probe > 118.0 * 1.5, (
        "the margin check must reject the pre-fix 120s ceiling, which sat 2s "
        "above the silence we actually measured")


def test_the_supervisor_poll_is_still_a_bounded_loop():
    """An unbounded wait would hide a genuinely dead stack instead of failing.

    C2C-049's rule for unattended batches: they must fail loudly. Raising the
    window must not turn into removing it.
    """
    text = _SUPERVISOR.read_text(encoding="utf-8")
    block = text[text.index("stack_up()"):]
    assert re.search(r"for i in \$\(seq 1 \d+\); do", block)
    assert "while true" not in block.split("clear_stale_lock")[0]
    assert _supervisor_seconds() <= 600, (
        "a readiness window over ten minutes is paid on every batch and would "
        "mask a dead stack for most of an hour across MAX_BARREN_BATCHES")


# ─────────────── the value must be acceptable to its consumer ───────────────
#
# ⚠️ This whole section is the test that was missing on 2026-10-02.
#
# The nine checks above verify the ORDERING of the three windows, and they all
# passed -- while the restart they were meant to enable failed immediately with
#
#     readiness probe failed closed: timeout_sec must be a finite value in 1..120
#
# The probe validates its own parameter, and 240 was outside the range it
# accepts. Relating the layers to each other says nothing about whether the
# number is admissible to the node that reads it, so the suite stayed green and
# the live run was lost. Ordering is necessary; acceptance is separate.

_PROBE_NODE = (_ROOT / "src" / "dds_security_monitor" / "dds_security_monitor"
               / "readiness_probe_node.py")


def _probe_accepted_range() -> tuple[float, float]:
    """The bounds the probe itself enforces on `timeout_sec`."""
    text = _PROBE_NODE.read_text(encoding="utf-8")
    hit = re.search(r"not\s+([0-9.]+)\s*<=\s*float\(timeout\)\s*<=\s*([0-9.]+)",
                    text)
    assert hit, "the probe's range check changed shape"
    return float(hit.group(1)), float(hit.group(2))


@pytest.mark.parametrize("mode", sorted(_STACKS))
def test_the_configured_timeout_is_inside_the_probe_accepted_range(mode):
    low, high = _probe_accepted_range()
    configured = _probe_seconds(_STACKS[mode])
    assert low <= configured <= high, (
        f"{mode}: the stack script passes timeout_sec={configured}, which the "
        f"probe rejects (it accepts {low}..{high}). This is the exact failure "
        "of 2026-10-02: the ordering was right and the value was inadmissible.")


def test_the_probe_error_message_states_the_range_it_enforces():
    """A message naming a stale range sends the next reader to the wrong file."""
    text = _PROBE_NODE.read_text(encoding="utf-8")
    low, high = _probe_accepted_range()
    # Anchor on the raise statement. The file's comments now quote the OLD
    # range while explaining the 2026-10-02 mistake, and a bare phrase search
    # would happily match that -- the same weakness that broke two startup
    # visibility tests earlier the same day.
    hit = re.search(
        r'raise ValueError\(\s*"[^"]*finite value in\s*([0-9.]+)\.\.([0-9.]+)',
        text)
    assert hit, "the probe no longer raises with its range stated"
    assert float(hit.group(1)) == low
    assert float(hit.group(2)) == high


def test_the_probe_keeps_an_upper_bound_at_all():
    """Removing the ceiling would turn fail-closed into fail-never.

    Raising it is a judgement call; deleting it changes the safety posture.
    """
    _, high = _probe_accepted_range()
    assert high <= 600.0, (
        f"a {high}s ceiling lets a dead stack hold a batch for most of an hour "
        "across MAX_BARREN_BATCHES")


def test_the_pre_fix_pairing_would_now_be_caught():
    """240 against a 1..120 probe -- the combination that lost the restart."""
    low, high = 1.0, 120.0
    configured = 240.0
    assert not low <= configured <= high, (
        "the acceptance check must reject the pairing that actually shipped")


def test_the_running_copy_matches_the_source_copy():
    """`ros2 run` reaches the source through build/, so the two must agree.

    `install/.../site-packages/dds-security-monitor.egg-link` points at
    `build/dds_security_monitor`, and that package DIRECTORY is a symlink into
    `src` (colcon --symlink-install): the two paths share one inode, so a src
    edit is live immediately and no rebuild is needed.

    ⚠️ Measured, because the layout invites the opposite conclusion: the build
    entry looks like a plain file (`is_symlink()` is False on it, link count 1,
    mtime from July), which reads as a stale copy. It is the parent directory
    that is linked. Keeping this test means a future non-symlink install -- where
    a src edit really would not reach the runtime -- fails loudly here instead
    of silently shipping different behaviour than git records.
    """
    build_copy = (_ROOT / "build" / "dds_security_monitor"
                  / "dds_security_monitor" / "readiness_probe_node.py")
    if not build_copy.is_file():
        pytest.skip("no build/ copy on this machine")
    assert build_copy.read_bytes() == _PROBE_NODE.read_bytes(), (
        "build/ and src/ copies of the readiness probe differ; the running "
        "code is not the code in git -- rebuild the package")
