"""Teardown is reaped out of process, and the child bounds itself.

Measured 2026-09-25 across 29 instrumented sessions: 12 never reached the last
line of teardown, and every one had `observer.ok == True` -- a real rclpy node
to close. Their `wall - declared` was +3.14s, exactly the factory's grace, so
they were inside `observer.close()` when the deadline passed.

The first attempt raised the reserve to 12s and wrapped the close in a
kernel-enforced hard stop. It made things worse: SIGKILL fell from 25.3% to
15.9% but the hard stop contributed 29.5% of its own, and the training-eligible
rate went **74.4% -> 54.5%**. A bounded overrun is still an overrun; `-14`
fails the gate exactly as `-9` does.

The lesson that change bought: once the close starts, control never comes back.
The GIL is held inside a C extension, so threads, signals and timers are all
locked out. Anything that *waits* for it in-process loses some fraction of
sessions, and enlarging the reserve only moves which fraction.

So the parent stops waiting. It emits the trace, forks, and exits zero. The
child does the cleanup it can and is bounded by the one deadline the kernel
enforces without the interpreter: SIGALRM at SIG_DFL.
"""

from __future__ import annotations

import ast
import builtins
import importlib.util
import pathlib
import signal
import subprocess
import sys
import textwrap

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_POC = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"

posix_only = pytest.mark.skipif(
    not hasattr(signal, "setitimer"), reason="POSIX interval timers only"
)


def _driver():
    spec = importlib.util.spec_from_file_location("_n37_hardstop", _POC)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_n37_hardstop"] = module
    spec.loader.exec_module(module)
    return module


n37 = _driver()


def _source() -> str:
    return _POC.read_text(encoding="utf-8")


# ─────────── every name the module calls must actually exist ───────────


def test_no_call_in_the_module_names_something_undefined():
    """The check that would have caught deleting a live helper.

    While removing the now-dead `_close_within` on 2026-09-25 the cleanup script
    also took `_reap_observer_out_of_process` with it, because that function sat
    between the two anchors. `py_compile` still passed -- the only reference is
    inside a function body, so the name is resolved at call time, not at compile
    time. The teardown would have raised NameError on the very first session.
    """
    tree = ast.parse(_source())
    defined = {n.name for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defined.add(target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                defined.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.arg):
            defined.add(node.arg)
        elif isinstance(node, (ast.For, ast.comprehension)):
            target = getattr(node, "target", None)
            if isinstance(target, ast.Name):
                defined.add(target.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            defined.add(node.name)
        elif isinstance(node, ast.withitem):
            var = node.optional_vars
            if isinstance(var, ast.Name):
                defined.add(var.id)

    known = defined | set(dir(builtins))
    missing = sorted(
        {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id not in known
        }
    )
    assert not missing, f"called but never defined: {missing}"


# ─────────────────────── arming the kernel stop ───────────────────────


@posix_only
def test_arming_reports_success():
    assert n37._arm_kernel_hard_stop(30.0) is True
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, signal.SIG_IGN)


@posix_only
@pytest.mark.parametrize("bad", [0.0, -1.0, -0.001])
def test_a_deadline_already_past_is_refused(bad):
    """Arming with a non-positive delay would fire immediately."""
    assert n37._arm_kernel_hard_stop(bad) is False


@posix_only
def test_arming_sets_the_default_disposition_not_a_python_handler():
    """A Python handler is exactly what cannot run while the GIL is held."""
    previous = signal.getsignal(signal.SIGALRM)
    try:
        n37._arm_kernel_hard_stop(30.0)
        assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous if callable(previous) else signal.SIG_IGN)


@posix_only
def test_the_kernel_stop_kills_a_process_blocked_outside_python():
    """The decisive property, exercised end to end in a child process.

    `time.sleep` releases the GIL, so it is not a faithful stand-in for a
    blocked C extension. `os.read` on an empty pipe blocks in a syscall with no
    timeout and no Python frames to return to: nothing in the interpreter can
    end this wait, which is the situation rclpy's shutdown creates.
    """
    program = textwrap.dedent(
        """
        import importlib.util, os, sys
        spec = importlib.util.spec_from_file_location("n37", sys.argv[1])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["n37"] = mod
        spec.loader.exec_module(mod)

        assert mod._arm_kernel_hard_stop(1.0) is True
        read_fd, _write_fd = os.pipe()
        os.read(read_fd, 1)          # blocks forever; nothing will write
        print("SHOULD NEVER PRINT", flush=True)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(_POC)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == -signal.SIGALRM, (
        f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr[-400:]!r}"
    )
    assert "SHOULD NEVER PRINT" not in result.stdout


# ─────────────────── the parent never waits for the close ───────────────────


@posix_only
def test_the_parent_returns_immediately_even_when_the_close_never_returns():
    """The property the whole change exists for.

    A close that blocks forever must not delay the parent at all. Measured
    against a wait, not a sleep: `os.read` on an empty pipe cannot be
    interrupted by anything the interpreter does.
    """
    program = textwrap.dedent(
        """
        import importlib.util, os, sys, time
        spec = importlib.util.spec_from_file_location("n37", sys.argv[1])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["n37"] = mod
        spec.loader.exec_module(mod)

        read_fd, _w = os.pipe()
        started = time.monotonic()
        mod._reap_observer_out_of_process(lambda: os.read(read_fd, 1))
        print(f"PARENT_RETURNED {time.monotonic() - started:.3f}", flush=True)
        os._exit(0)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(_POC)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr[-400:]
    line = [l for l in result.stdout.splitlines() if l.startswith("PARENT_RETURNED")]
    assert line, result.stdout
    elapsed = float(line[0].split()[1])
    assert elapsed < 1.0, f"the parent waited {elapsed:.3f}s for a close that never returns"


@posix_only
def test_the_child_really_runs_the_close():
    """Exiting fast is worthless if the cleanup silently stops happening."""
    program = textwrap.dedent(
        """
        import importlib.util, os, sys, time
        spec = importlib.util.spec_from_file_location("n37", sys.argv[1])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["n37"] = mod
        spec.loader.exec_module(mod)

        marker = sys.argv[2]
        def _close():
            open(marker, "w").write("closed")
        mod._reap_observer_out_of_process(_close)
        time.sleep(2.0)        # parent lingers only so the test can observe
        os._exit(0)
        """
    )
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        marker = pathlib.Path(tmp) / "closed.txt"
        subprocess.run(
            [sys.executable, "-c", program, str(_POC), str(marker)],
            capture_output=True, text=True, timeout=60,
        )
        assert marker.is_file(), "the forked child never ran the close"


@posix_only
def test_a_close_that_raises_does_not_take_the_child_down_noisily():
    program = textwrap.dedent(
        """
        import importlib.util, os, sys, time
        spec = importlib.util.spec_from_file_location("n37", sys.argv[1])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["n37"] = mod
        spec.loader.exec_module(mod)

        def _boom():
            raise RuntimeError("dds went away")
        mod._reap_observer_out_of_process(_boom)
        time.sleep(1.0)
        print("PARENT_OK", flush=True)
        os._exit(0)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(_POC)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0
    assert "PARENT_OK" in result.stdout
    assert "Traceback" not in result.stderr


def test_the_reaper_reports_failure_where_fork_is_unavailable(monkeypatch):
    """Windows has no fork; the driver must degrade, not crash."""
    monkeypatch.delattr(n37.os, "fork", raising=False)
    assert n37._reap_observer_out_of_process(lambda: None) is False


# ─────────────────────── wiring into the teardown ───────────────────────


def test_the_trace_is_emitted_before_the_fork():
    """Evidence first. A child that inherits an unflushed buffer duplicates it."""
    body = _source()
    trace = body.index("_emit_trace(step,")
    reap = body.index("_reap_observer_out_of_process(observer.close)")
    assert trace < reap


def test_stdout_is_flushed_before_the_fork():
    body = _source()
    reap = body.index("_reap_observer_out_of_process(observer.close)")
    window = body[max(0, reap - 400):reap]
    assert "sys.stdout.flush()" in window


def test_the_parent_exits_zero_immediately_after_the_fork():
    body = _source()
    reap = body.index("_reap_observer_out_of_process(observer.close)")
    tail = body[reap:reap + 200]
    assert "os._exit(0)" in tail


def test_the_child_arms_the_kernel_stop_before_closing():
    """An unbounded child becomes the orphan that holds the SHM lock.

    `ManagedProcess.stop()` only signals the group while the *parent* is still
    alive, and by then it is not, so nothing else will collect the child.
    """
    body = _source()
    start = body.index("def _reap_observer_out_of_process")
    end = body.index("def _arm_watchdog", start)
    region = body[start:end]
    armed = region.index("_arm_kernel_hard_stop(CLOSE_BUDGET_SEC)")
    closed = region.index("close()", armed)
    assert armed < closed


def test_the_in_process_wait_is_gone():
    """`_close_within` is the thing measurement showed cannot work.

    Leaving it in place would leave a second path that looks supported.
    """
    body = _source()
    assert "_close_within" not in body


# ─────────────────── the reserve this no longer has to cover ───────────────────


def test_the_reserve_is_back_to_covering_only_the_burst_reap():
    """12s was needed while the close ran here; it no longer does.

    Holding it at 12 would have cost 8s of attack window on every session for a
    cost the parent no longer pays.
    """
    assert n37.TEARDOWN_RESERVE_SEC == 4.0
    assert n37.TEARDOWN_RESERVE_SEC > n37.BURST_EXIT_RESERVE_SEC


def test_the_child_budget_is_smaller_than_the_parent_reserve():
    """The child should be gone before the factory's window closes on the group."""
    assert n37.CLOSE_BUDGET_SEC < n37.TEARDOWN_RESERVE_SEC
