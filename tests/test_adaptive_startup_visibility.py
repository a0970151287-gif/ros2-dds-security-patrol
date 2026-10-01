"""A session that writes nothing must not be possible to confuse with one that did nothing.

On 2026-09-25 the mega campaign had 47 SIGKILLed sessions with zero bytes on
both stdout and stderr. Their `wall - declared` was +3.07s, identical to every
other kill, which means they lived their full window. A process that runs for
eighty seconds and writes nothing is stuck before its first flush, and the only
thing standing between process start and the first flushed print was
`Observer()` -- rclpy init, node creation, DDS discovery.

Neither guard could help: the SIGALRM watchdog is not delivered while a C
extension holds the GIL, and the factory's SIGTERM handler cannot run for the
same reason. So the process was killed having said nothing about why.

Moving the banner above the constructor does not fix the hang. It makes the
hang legible: banner and no next line means stuck in the observer; neither line
means something earlier. This project has recorded the same failure shape too
many times -- silence reads as "no evidence" when it means "never ran".
"""

from __future__ import annotations

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_POC = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"


def _source() -> str:
    return _POC.read_text(encoding="utf-8")


def _index(needle: str, body: str) -> int:
    at = body.find(needle)
    assert at != -1, f"anchor vanished from N37: {needle!r}"
    return at


# ⚠️ Anchor on the print STATEMENT, not on the phrase.
#
# These tests used to search for the bare phrase 觀測者就緒. On 2026-10-02 the
# constructor gained a comment that explains this very line, so the first
# occurrence of the phrase moved into prose that sits *above* the construction
# -- and two tests failed while the property they guard was still true. A
# text-anchored check on a phrase that also appears in commentary is the same
# weakness that let a SyntaxError through a whole suite of regex tests
# (C2C-068).
_READY_STATEMENT = 'print(f"   觀測者就緒 {'


def test_the_banner_is_printed_before_the_observer_is_built():
    """The whole point. If this flips back, 47 sessions go silent again."""
    body = _source()
    banner = _index("☠️ N37 自適應攻擊者", body)
    construct = _index("observer = Observer()", body)
    assert banner < construct, (
        "the startup banner must precede Observer(); otherwise a hang inside "
        "rclpy discovery produces a zero-byte log"
    )


def test_the_banner_is_flushed():
    """Unflushed output dies with the process; SIGKILL runs no atexit."""
    body = _source()
    banner = _index("☠️ N37 自適應攻擊者", body)
    tail = body[banner:banner + 400]
    assert "flush=True" in tail, tail[:200]


def test_the_observer_reports_how_long_it_took():
    """Banner then silence localises the hang; without this it only narrows it."""
    body = _source()
    assert _READY_STATEMENT in body


def test_the_observer_timing_line_is_flushed():
    body = _source()
    at = _index(_READY_STATEMENT, body)
    tail = body[at:at + 300]
    assert "flush=True" in tail, tail[:200]


def test_the_observer_timing_line_comes_after_construction():
    """It reports elapsed time, so printing it first would report zero."""
    body = _source()
    construct = _index("observer = Observer()", body)
    reported = _index(_READY_STATEMENT, body)
    assert construct < reported


def test_nothing_unflushed_prints_before_the_banner():
    """A buffered line before the banner would be lost and mislead the next reader.

    Anything printed earlier must either flush or not exist, or a zero-byte log
    stops meaning "stuck before the banner".
    """
    body = _source()
    start = _index("def main()", body)
    banner = _index("☠️ N37 自適應攻擊者", body)
    # Anchor on the statement, not the string: the banner text begins a few
    # characters into its own `print(`, so slicing at the text cuts that
    # statement in half and it reads as an unflushed print of its own. The
    # first version of this test failed for exactly that reason.
    banner_stmt = body.rfind("print(", start, banner)
    assert banner_stmt != -1, "the banner is no longer printed"
    between = body[start:banner_stmt]
    for match in re.finditer(r"\bprint\(", between):
        segment = between[match.start():match.start() + 300]
        assert "flush=True" in segment, (
            f"unflushed print before the banner:\n{segment[:200]}"
        )


def test_the_startup_cost_is_measured_from_process_start():
    """Boot happens before main() runs, so a later origin cannot see it."""
    body = _source()
    assert "_PROCESS_START = time.monotonic()" in body
    assert "startup_cost = time.monotonic() - _PROCESS_START" in body


def test_process_start_is_captured_before_the_heavy_imports():
    """If it moved below `import rclpy`, the boot cost would read as zero."""
    body = _source()
    origin = _index("_PROCESS_START = time.monotonic()", body)
    # the driver defers rclpy to a local import; the catalog import is the
    # first heavy module-scope work that could precede it
    for heavy in ("import rclpy", "from firewall_lab"):
        at = body.find(heavy)
        if at != -1:
            assert origin < at, f"{heavy} runs before _PROCESS_START is taken"
