"""One ineligible session must not destroy the batch around it.

Measured on 2026-09-24: 14.3% of adaptive sessions were being SIGKILLed past
their time budget, and `execute_campaign` raised on the first one. With
40-session batches that gave a batch a 0.857^40 chance of finishing -- about
0.2% -- so essentially every batch died after a handful of sessions. Throughput
went from 69 sessions a round to 2, and the supervisor's production-based
circuit breaker never fired because sessions *were* still being produced.

The gate itself is unchanged here: an ineligible session is still recorded with
`training_eligible: false` and still cannot reach a training set. What changed
is that the batch now fails closed on the *rate* rather than on the first
occurrence -- which is both cheaper and more informative, because a run where
most sessions are ineligible is a broken stack rather than bad luck.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from firewall_lab import campaign as campaign_module  # noqa: E402
from firewall_lab.campaign import (  # noqa: E402
    ENTRY_STATUSES,
    MAX_INELIGIBLE_BEFORE_ABORT,
    MAX_INELIGIBLE_RATE,
    repair_campaign_plan,
)


# ── the status vocabulary ────────────────────────────────────────────────────


def test_ineligible_is_a_recognised_entry_status():
    """A plan carrying it must still validate, or the next load would refuse."""
    assert "ineligible" in ENTRY_STATUSES


def test_the_abort_rule_needs_both_a_count_and_a_share():
    """Either alone misfires.

    A count alone aborts a long healthy run that accumulates a few misses over
    thousands of sessions; a share alone aborts a three-session smoke run on
    its first one.
    """
    assert MAX_INELIGIBLE_BEFORE_ABORT >= 2
    assert 0.0 < MAX_INELIGIBLE_RATE < 1.0


def test_the_threshold_is_far_above_the_measured_healthy_rate():
    """7 in 406 (1.7%) was the residual rate once the N37 defect was excluded."""
    healthy_rate = 7 / 406
    assert MAX_INELIGIBLE_RATE > healthy_rate * 10


def test_the_old_behaviour_would_have_killed_every_batch():
    """Stated as arithmetic so the reason for the change stays legible."""
    observed_failure_rate = 58 / 406
    batch = 40
    survival = (1 - observed_failure_rate) ** batch
    assert survival < 0.01, f"batch survival was {survival:.2%}"


# ── the abort rule itself ────────────────────────────────────────────────────


def _aborts(ineligible: int, completed: int) -> bool:
    """Mirror of the condition in execute_campaign."""
    total = ineligible + completed
    return ineligible >= MAX_INELIGIBLE_BEFORE_ABORT and (
        ineligible > MAX_INELIGIBLE_RATE * total
    )


@pytest.mark.parametrize(
    "ineligible,completed,expected,reason",
    [
        (1, 0, False, "the very first session missing must not abort a run"),
        (4, 0, False, "below the count floor"),
        (5, 0, True, "a run producing nothing usable"),
        (5, 39, False, "5 of 44 is 11%, ordinary attrition"),
        (5, 10, True, "5 of 15 is 33%, a broken stack"),
        (2, 2, False, "50% but only two: too few to judge"),
        (40, 1000, False, "4% over a long run"),
        (400, 1000, True, "29% over a long run"),
    ],
)
def test_the_abort_rule_boundaries(ineligible, completed, expected, reason):
    assert _aborts(ineligible, completed) is expected, reason


def test_the_realistic_post_fix_batch_survives():
    """A 40-session batch at the residual 1.7% rate must run to the end."""
    ineligible = round(40 * 7 / 406)
    assert not _aborts(ineligible, 40 - ineligible)


# ── requeueing is deliberate, never automatic ────────────────────────────────


def _plan_with_statuses(tmp_path: pathlib.Path, statuses: list[str]) -> pathlib.Path:
    """A real plan from the production factory, with the first N entries set.

    Hand-building the dict drifts from PLAN_KEYS the moment the schema gains a
    field, and `validate_campaign_plan` rightly refuses it -- which says nothing
    about the behaviour under test.
    """
    plan = campaign_module.create_campaign_plan(
        normal_sessions=4, attack_sessions_per_scenario=4, seed=99,
    )
    assert len(plan["entries"]) >= len(statuses)
    for entry, status in zip(plan["entries"], statuses):
        entry["status"] = status
        if status == "ineligible":
            entry["error"] = "live session failed training gate: ..."
        elif status == "complete":
            entry["session_id"] = "20260924T000000000000Z_normal_patrol_deadbeef"
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def test_repair_leaves_ineligible_alone_by_default(tmp_path):
    """The supervisor calls repair every round.

    Requeueing automatically would put a systematically broken scenario into an
    endless retry loop -- which is precisely the shape of failure the rest of
    this supervisor exists to stop.
    """
    path = _plan_with_statuses(tmp_path, ["ineligible", "pending"])
    report = repair_campaign_plan(path)
    assert report["requeued_ineligible"] == 0
    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["entries"][0]["status"] == "ineligible"


def test_reset_ineligible_requeues_and_clears_the_reason(tmp_path):
    path = _plan_with_statuses(tmp_path, ["ineligible", "complete", "ineligible"])
    report = repair_campaign_plan(path, reset_ineligible=True)
    assert report["requeued_ineligible"] == 2
    after = json.loads(path.read_text(encoding="utf-8"))
    assert [e["status"] for e in after["entries"][:3]] == [
        "pending", "complete", "pending",
    ]
    assert after["entries"][0]["error"] is None


def test_reset_ineligible_writes_even_when_nothing_else_needed_repair(tmp_path):
    """The write used to be gated on `repaired`, which would discard this pass."""
    path = _plan_with_statuses(tmp_path, ["ineligible", "pending"])
    repair_campaign_plan(path, reset_ineligible=True)
    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["entries"][0]["status"] == "pending", "the requeue was not persisted"


def test_reset_ineligible_covers_entries_no_mode_flip_would_touch(tmp_path):
    """The requeue must be its own pass over every entry.

    Placed inside the insider mode-flip loop -- as the first version of this
    change was -- it would have requeued only entries that also needed
    repairing, and reported a number that looked right.
    """
    path = _plan_with_statuses(tmp_path, ["ineligible"] * 5)
    report = repair_campaign_plan(path, reset_ineligible=True)
    assert report["requeued_ineligible"] == 5


def test_dry_run_reports_without_writing(tmp_path):
    path = _plan_with_statuses(tmp_path, ["ineligible", "ineligible"])
    before = path.read_text(encoding="utf-8")
    report = repair_campaign_plan(path, dry_run=True, reset_ineligible=True)
    assert report["requeued_ineligible"] == 2
    assert path.read_text(encoding="utf-8") == before


def test_requeueing_leaves_a_valid_plan(tmp_path):
    """The plan must still load afterwards, not merely have one field changed.

    `requested_counts` is computed separately from the entries and
    `validate_campaign_plan` compares them, so a partial edit passes here and
    fails on the next load.
    """
    path = _plan_with_statuses(tmp_path, ["ineligible", "ineligible", "complete"])
    repair_campaign_plan(path, reset_ineligible=True)
    reloaded = campaign_module.load_campaign_plan(path)
    assert [e["status"] for e in reloaded["entries"][:3]] == [
        "pending", "pending", "complete",
    ]
