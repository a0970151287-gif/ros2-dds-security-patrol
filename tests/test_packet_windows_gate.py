"""The training gate has to check that per-packet extraction succeeded.

Measured 2026-09-25 over 836 `dataset_mega` sessions: **94 carried
`packet_windows: failed` and still had `training_eligible: true`.** The gate
checked five things -- pcap, zeek, capture_process, attack_process,
runtime_telemetry -- and `zeek`'s check sat right beside the gap, testing
status *and* return_code *and* conn_log. The identical check for the per-packet
extraction was simply never written.

Why it matters, precisely: this is not silent corruption. `features.py:1479` is
fail-closed -- a session with a pcap but no `packets.tsv.gz` raises SchemaError.
So the damage is deferred instead of hidden: feature extraction aborts on the
first such session, thousands of sessions and days after the defect happened,
with an error that points at the extractor rather than at the gate.

C2C-073 recorded this on 2026-09-24 (40 of 502) and nothing was done; by today
it was 94 of 836. The number grows with the campaign, which is the argument for
closing it at the gate rather than repairing batches after the fact.
"""

from __future__ import annotations

import inspect
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_ORCH = _ROOT / "firewall_lab" / "orchestrator.py"
_FEATURES = _ROOT / "firewall_lab" / "features.py"


def _gate_block() -> str:
    """The new condition together with the comment above it and the gate list.

    The comment is inside the slice on purpose: one of the tests below asserts
    that the measurement which motivated this condition is recorded next to it.
    """
    body = _ORCH.read_text(encoding="utf-8")
    start = body.index("        # ⚠️ 2026-09-25 補上的第六項。")
    end = body.index("        manifest.training_eligible = not gate_failures")
    return body[start:end]


def _evaluate(pcap_ok: bool, packet_result: dict) -> bool:
    """Run the gate's own expression, so the test cannot drift from the source.

    Copying the condition into the test would let the two diverge silently --
    which is the whole failure mode being fixed here.
    """
    block = _gate_block()
    head = "packet_windows_ok = "
    expr = block[block.index(head) + len(head):block.index("gate_failures = [")]
    scope = {"pcap_ok": pcap_ok, "packet_result": packet_result}
    return bool(eval(expr.strip(), {"__builtins__": {}}, scope))  # noqa: S307


# ─────────────────────── the gate now includes it ───────────────────────


def test_packet_windows_is_one_of_the_gate_conditions():
    block = _gate_block()
    assert '("packet_windows", packet_windows_ok),' in block


def test_the_gate_still_checks_every_condition_it_checked_before():
    """Adding a condition must not quietly drop one."""
    block = _gate_block()
    for name in ("pcap", "zeek", "capture_process",
                 "attack_process", "runtime_telemetry"):
        assert f'("{name}", ' in block, name


# ─────────────────────── what the condition decides ───────────────────────


def test_a_completed_extraction_passes():
    assert _evaluate(True, {"status": "complete", "return_code": 0}) is True


def test_the_measured_failure_shape_is_rejected():
    """`status=failed, return_code=None` -- all 94 sessions looked like this.

    A None return code is what a killed or timed-out child leaves behind, so
    this is the exact shape the gate has to catch.
    """
    assert _evaluate(True, {"status": "failed", "return_code": None}) is False


@pytest.mark.parametrize("result", [
    {"status": "complete", "return_code": 1},
    {"status": "failed", "return_code": 0},
    {"status": "skipped", "reason": "tshark_not_found"},
    {},
])
def test_anything_short_of_a_clean_completion_is_rejected(result):
    """Both halves are required, the same way `zeek_ok` requires all three.

    `tshark_not_found` is included deliberately: if the binary goes missing the
    honest outcome is a loudly aborting campaign, not thousands of sessions that
    `features.py` will later refuse.
    """
    assert _evaluate(True, result) is False


def test_a_session_without_a_usable_pcap_is_not_failed_twice():
    """`pcap` already fails that session; this condition must not pile on.

    The criterion mirrors features.py, which only demands the per-packet record
    when a pcap actually exists.
    """
    assert _evaluate(False, {"status": "skipped",
                             "reason": "missing_or_empty_pcap"}) is True
    assert _evaluate(False, {"status": "failed", "return_code": None}) is True


# ─────────────── the criterion matches the consumer's criterion ───────────────


def test_the_gate_and_features_py_agree_on_when_it_is_required():
    """features.py raises exactly when a pcap exists without the TSV.

    If the two drifted, the gate would pass sessions the extractor then refuses
    -- which is the situation this change exists to end.
    """
    features = _FEATURES.read_text(encoding="utf-8")
    assert '缺少 packet_windows/packets.tsv.gz' in features
    guard = features.index("if not session_network and (session_dir")
    assert 'traffic.pcapng").is_file()' in features[guard:guard + 200]


def test_the_comment_records_the_measurement_that_motivated_it():
    """A gate condition with no recorded reason invites a later removal."""
    block = _gate_block()
    assert "94" in block
    assert "features.py" in block


# ─────────────────────── the blast radius is understood ───────────────────────


def test_a_failing_extraction_marks_the_session_ineligible_not_the_batch():
    """C2C-071: a gate failure records `ineligible` and continues.

    Raising instead would let one timed-out tshark destroy the other 39 sessions
    in the batch, which is the defect that collapsed throughput on 2026-09-24.
    """
    from firewall_lab import campaign

    source = inspect.getsource(campaign.execute_campaign)
    assert 'status"] = "ineligible"' in source or "'ineligible'" in source
    assert "MAX_INELIGIBLE_RATE" in inspect.getsource(campaign)

def test_the_module_does_not_claim_packet_windows_is_outside_the_gate():
    """A comment must not state the opposite of the code beside it.

    Until 2026-10-02 the manifest-assembly block carried a comment saying
    packet_windows was "刻意不列入 training gate" -- deliberately left out
    of the gate -- while the gate had included it since 2026-09-25 and
    test_packet_windows_is_one_of_the_gate_conditions pinned that. A comment
    that contradicts its own code is worse than no comment: the next reader
    concludes a failed extraction cannot affect eligibility and goes looking
    somewhere else. Pin the two statements together.
    """
    source = _ORCH.read_text(encoding="utf-8")
    claims_excluded = "刻意不列入 training gate" in source
    in_gate = '("packet_windows", packet_windows_ok),' in source
    assert not (claims_excluded and in_gate), (
        "the module says packet_windows is deliberately kept out of the "
        "training gate while the gate lists it -- one of the two is a lie"
    )

