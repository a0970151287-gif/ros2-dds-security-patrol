"""Regenerating the 2026-08-30 attribution reports at schema v2.

The 79/80 cross-host batch was produced before the fourth blockability
condition (link-layer binding) existed, so its reports are v1 and the chain
harness refuses all of them at check 1. C2C-051 already rechecked that batch
with the standalone link-layer tool and retracted nothing, and every session
still has its `link_layer_binding.json` on disk -- the evidence was there, it
just never reached the machine-readable path.

Two properties matter more than the mechanics, and both are tested here: the
original reports are never touched, and the regenerated verdict is compared
against the original rather than assumed to match. A regeneration that quietly
changed a verdict would be the worst outcome, because the whole point is that
the same raw evidence reaches the same conclusion through a second path.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL = _ROOT / "工具腳本" / "regenerate_crosscheck_v2.py"


def _load():
    spec = importlib.util.spec_from_file_location("_regen_tool", _TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_regen_tool"] = module
    spec.loader.exec_module(module)
    return module


regen = _load()

ATTACKER = "192.168.0.30"
DEFENDER = "192.168.0.129"
# The two halves name the same participant differently, and the fixture keeps
# that difference rather than smoothing it: the packet decoder emits a compact
# hex prefix, the observer emits a dotted GUID with an entity suffix. A fixture
# that used one form on both sides would pass while the real pairing was broken.
GUID_DOTTED = "a2.5a.10.4e.14.09.85.90.91.80.b1.aa|0.0.1.c1"
GUID_COMPACT = "a25a104e140985909180b1aa"
DEFENDER_GUID_COMPACT = "a03a141483daf08d4ae712a3"


def _session(tmp_path, *, name="20260830T000000000000Z_crosshost_deadbeef",
             with_link_layer=True, old_blockable=(ATTACKER,)) -> pathlib.Path:
    """A session directory shaped like the real cross-host batch."""
    session = tmp_path / name
    session.mkdir()
    (session / "rtps_identity_packets.jsonl").write_text(
        "\n".join(
            json.dumps(row)
            for row in (
                {"guid_prefix": GUID_COMPACT, "source_ip": ATTACKER},
                {"guid_prefix": DEFENDER_GUID_COMPACT, "source_ip": DEFENDER},
            )
        ) + "\n",
        encoding="utf-8",
    )
    (session / "observer_events.jsonl").write_text(
        json.dumps(
            {
                "event": "participant_authentication",
                "status": "UNAUTHORIZED",
                "guid": GUID_DOTTED,
            }
        ) + "\n",
        encoding="utf-8",
    )
    if with_link_layer:
        (session / "link_layer_binding.json").write_text(
            json.dumps(
                {
                    "per_ip": {
                        ATTACKER: {"verdict": "consistent", "reasons_inconsistent": []},
                        DEFENDER: {"verdict": "consistent", "reasons_inconsistent": []},
                    }
                }
            ),
            encoding="utf-8",
        )
    (session / "crosscheck.json").write_text(
        json.dumps(
            {
                "schema_version": regen.V1,
                "blockable_ips": sorted(old_blockable),
                "source_ip_attribution_verified": bool(old_blockable),
            }
        ),
        encoding="utf-8",
    )
    return session


# ───────────────────── the original is never touched ─────────────────────


def test_the_original_report_is_left_byte_for_byte(tmp_path):
    """C2C-051 said it did not touch these. Neither does this.

    The v1 reports are the only record of what the decision looked like before
    the fourth condition existed.
    """
    session = _session(tmp_path)
    before = (session / "crosscheck.json").read_bytes()

    regen.regenerate(session, apply=True)

    assert (session / "crosscheck.json").read_bytes() == before


def test_the_output_goes_to_a_separate_filename(tmp_path):
    session = _session(tmp_path)
    regen.regenerate(session, apply=True)
    assert (session / regen.OUTPUT_NAME).is_file()
    assert regen.OUTPUT_NAME != "crosscheck.json"


def test_a_dry_run_writes_nothing(tmp_path):
    session = _session(tmp_path)
    row = regen.regenerate(session, apply=False)
    assert row["status"] == "would_regenerate"
    assert not (session / regen.OUTPUT_NAME).exists()


def test_an_existing_output_is_not_overwritten(tmp_path):
    session = _session(tmp_path)
    regen.regenerate(session, apply=True)
    marker = (session / regen.OUTPUT_NAME).read_bytes()

    row = regen.regenerate(session, apply=True)

    assert row["status"] == "already_present"
    assert (session / regen.OUTPUT_NAME).read_bytes() == marker


# ─────────────────── the regenerated report is really v2 ───────────────────


def test_the_regenerated_report_is_schema_v2(tmp_path):
    session = _session(tmp_path)
    row = regen.regenerate(session, apply=True)
    assert row["status"] == "regenerated"
    assert row["new_schema"] == regen.V2


def test_the_attacker_is_still_blockable(tmp_path):
    session = _session(tmp_path)
    row = regen.regenerate(session, apply=True)
    assert row["new_blockable"] == [ATTACKER]
    assert row["verified"] is True


def test_the_defender_is_not_blockable(tmp_path):
    """No rejection record, so condition 3 refuses it -- as it did in the batch."""
    session = _session(tmp_path)
    regen.regenerate(session, apply=True)
    report = json.loads((session / regen.OUTPUT_NAME).read_text(encoding="utf-8"))
    assert DEFENDER not in report["blockable_ips"]
    assert report["per_ip"][DEFENDER]["blockable"] is False


# ─────────────── agreement is measured, not assumed ───────────────


def test_agreement_with_v1_is_reported(tmp_path):
    session = _session(tmp_path)
    row = regen.regenerate(session, apply=True)
    assert row["agrees_with_v1"] is True
    assert row["old_blockable"] == [ATTACKER]


def test_a_disagreement_is_surfaced_not_swallowed(tmp_path):
    """If the second path reaches a different verdict, that is the result.

    Here the link-layer evidence says the sender was not the address holder,
    so v2 must refuse an address that v1 was willing to block.
    """
    session = _session(tmp_path)
    (session / "link_layer_binding.json").write_text(
        json.dumps(
            {"per_ip": {ATTACKER: {"verdict": "spoofing_evidence",
                                   "reasons_inconsistent": ["mac mismatch"]}}}
        ),
        encoding="utf-8",
    )

    row = regen.regenerate(session, apply=True)

    assert row["new_blockable"] == []
    assert row["agrees_with_v1"] is False


def test_unverifiable_link_layer_also_refuses(tmp_path):
    """Cannot verify is not the same as verified, and must not act like it."""
    session = _session(tmp_path)
    (session / "link_layer_binding.json").write_text(
        json.dumps(
            {"per_ip": {ATTACKER: {"verdict": "unverifiable",
                                   "reasons_inconsistent": ["one-way traffic"]}}}
        ),
        encoding="utf-8",
    )
    row = regen.regenerate(session, apply=True)
    assert row["new_blockable"] == []


# ─────────────────────── missing inputs fail loudly ───────────────────────


def test_a_session_without_link_layer_evidence_is_skipped(tmp_path):
    """Not regenerated as v2-with-nothing-blockable -- skipped and named.

    Producing a v2 report from a session that has no link-layer evidence would
    manufacture a schema promotion the evidence does not support.
    """
    session = _session(tmp_path, with_link_layer=False)
    row = regen.regenerate(session, apply=True)
    assert row["status"] == "missing_inputs"
    assert "link_layer_binding.json" in row["missing"]
    assert not (session / regen.OUTPUT_NAME).exists()


@pytest.mark.parametrize("dropped", regen.REQUIRED)
def test_every_required_input_is_actually_required(tmp_path, dropped):
    session = _session(tmp_path)
    (session / dropped).unlink()
    row = regen.regenerate(session, apply=True)
    assert row["status"] == "missing_inputs"
    assert dropped in row["missing"]


def test_the_batch_run_returns_nonzero_when_a_session_is_incomplete(tmp_path):
    _session(tmp_path, name="20260830T000000000000Z_crosshost_aaaaaaaa")
    _session(tmp_path, name="20260830T000000000000Z_crosshost_bbbbbbbb",
             with_link_layer=False)

    code = regen.main(["--batch", str(tmp_path), "--apply"])

    assert code == 1


def test_the_batch_run_returns_zero_when_every_session_regenerates(tmp_path):
    _session(tmp_path, name="20260830T000000000000Z_crosshost_aaaaaaaa")
    _session(tmp_path, name="20260830T000000000000Z_crosshost_bbbbbbbb")

    assert regen.main(["--batch", str(tmp_path), "--apply"]) == 0


def test_an_empty_batch_directory_is_refused(tmp_path):
    assert regen.main(["--batch", str(tmp_path)]) == 2
