"""Static checks on the local-outcome driver.

Commit 2644092 deleted the wait_for() definition and left all sixteen call
sites. bash returns 127 for an undefined function without stopping, so every
wait silently became an instant failure, and the one call inside `if !` became
an unconditional failure branch: velocity_guard_recovered reported "heartbeat
suppression not consumed" on every run for nine days, regardless of whether the
seam had worked. Nothing caught it because the only symptom was a
"command not found" line on stderr and a failure message that read perfectly
plausibly.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DRIVER = Path(__file__).resolve().parents[1] / "工具腳本" / "run_local_outcomes.sh"

DEFINITION = re.compile(r"^([a-z_][a-z0-9_]*)\(\)\s*\{", re.M)
# Names the preflight guards. Kept here as well so deleting it from the script
# is itself a test failure.
GUARDED = (
    "log",
    "enabled",
    "mark",
    "marker_landed",
    "marker_line",
    "telemetry_lines",
    "wait_for",
    "cleanup",
)


@pytest.fixture(scope="module")
def source() -> str:
    return DRIVER.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def defined(source: str) -> set[str]:
    return set(DEFINITION.findall(source))


@pytest.mark.parametrize("name", GUARDED)
def test_every_guarded_helper_is_defined(name: str, defined: set[str]):
    assert name in defined, (
        f"{name}() is called by the driver but not defined; bash would return "
        f"127 and the run would continue with that step silently skipped"
    )


def test_wait_for_actually_invokes_the_waiter(source: str):
    """A stub that returns success would be worse than a missing function."""
    body = re.search(r"^wait_for\(\) \{.*?^\}", source, re.S | re.M)
    assert body is not None
    assert "wait_for_telemetry.py" in body.group(0)
    assert "--timeout-sec" in body.group(0)


def test_the_preflight_guard_is_present_and_fails_closed(source: str):
    """The runtime check must exit non-zero, not warn and carry on."""
    assert "declare -F" in source
    for name in GUARDED:
        assert name in source
    guard = re.search(r"for _helper in ([^\n;]+); do", source)
    assert guard is not None
    listed = guard.group(1).split()
    assert set(listed) == set(GUARDED), listed
    tail = source[guard.end(): guard.end() + 400]
    assert "exit 2" in tail


def test_the_consumption_check_is_the_only_conditional_wait(source: str):
    """`if ! wait_for` turns a broken waiter into a confident false verdict.

    Only the seam consumption check uses that form today. If another appears,
    it inherits the same failure mode and should be reviewed deliberately.
    """
    code = [
        line for line in source.splitlines()
        if not line.lstrip().startswith("#")
    ]
    conditional = [line.strip() for line in code if line.strip().startswith("if ! wait_for")]
    # Pinned by the event waited on, not just the count. Only the seam
    # consumption check uses this form; it logs and continues, so a broken
    # waiter yields a spurious warning rather than a false pass. A second
    # would need the same review before being added here.
    # if ! wait_for <since> <event_type> ...  -> event type is field 4
    waited_on = sorted(line.split()[4] for line in conditional)
    assert waited_on == ["controlled_fault_injection"], conditional
