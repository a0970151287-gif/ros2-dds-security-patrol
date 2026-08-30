"""Tests for the identity→IP blockability verdict.

This is the most safety-critical decision in the response chain -- it decides
whether an address may be blocked -- and until 2026-08-30 it had no tests at all.

The 80-round cross-host batch exercised two of the three conditions. It never
exercised the second one, because that batch contained no successfully
authenticated remote identity: what kept the defender's own address off the
blockable list was the missing rejection record (condition 3), not the presence
of a legitimate one (condition 2). So the branch guarding against blocking a
legitimate node -- the worst failure direction for automatic blocking -- had
never run in a live session or in a test.

Jesse chose to keep the threat-model boundary rather than put a legitimate
enclave on the attack machine, so condition 2 is covered here instead of by a
cross-host positive control. That is a deliberate trade: this pins the logic, not
the plumbing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "工具腳本" / "crosscheck_identity_attribution.py"
    spec = importlib.util.spec_from_file_location("crosscheck_identity", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cross = _load()

ATTACKER = "a2.5a.10.4e"
LEGIT = "b7.11.02.9c"


def test_the_only_blockable_case_is_unique_rejected_and_unauthenticated():
    verdicts = cross.decide_blockable(
        {"192.168.0.30": {ATTACKER}}, authorized=set(), rejected={ATTACKER}
    )
    assert verdicts["192.168.0.30"]["blockable"] is True
    assert verdicts["192.168.0.30"]["reasons_not_blockable"] == []


def test_an_authenticated_identity_is_never_blockable():
    """Condition 2, the branch no live session has ever reached.

    A legitimate remote node that authenticated successfully must not be
    blockable even though its address carries exactly one GUID.
    """
    verdicts = cross.decide_blockable(
        {"192.168.0.50": {LEGIT}}, authorized={LEGIT}, rejected=set()
    )
    verdict = verdicts["192.168.0.50"]
    assert verdict["blockable"] is False
    assert verdict["has_authorized_identity"] is True
    assert any("合法身分" in reason for reason in verdict["reasons_not_blockable"])


def test_authentication_success_disqualifies_blocking_even_with_a_rejection():
    """A GUID seen both authenticated and rejected must fail safe.

    A participant can be refused once and admitted later, or be observed by two
    listeners disagreeing. Blocking on the strength of the rejection alone would
    take down an identity that demonstrably holds valid credentials.
    """
    verdicts = cross.decide_blockable(
        {"192.168.0.50": {LEGIT}}, authorized={LEGIT}, rejected={LEGIT}
    )
    assert verdicts["192.168.0.50"]["blockable"] is False
    assert verdicts["192.168.0.50"]["has_rejection_record"] is True


def test_a_shared_address_is_never_blockable():
    """Condition 1: blocking an address with several identities hits bystanders.

    This is why same-host attribution is not usable -- every real defender host
    runs several participants behind one address.
    """
    verdicts = cross.decide_blockable(
        {"127.0.0.1": {ATTACKER, LEGIT}}, authorized={LEGIT}, rejected={ATTACKER}
    )
    verdict = verdicts["127.0.0.1"]
    assert verdict["blockable"] is False
    assert verdict["unique_guid"] is False
    assert any("波及" in reason for reason in verdict["reasons_not_blockable"])


def test_absence_of_a_rejection_record_is_not_grounds_to_block():
    """Condition 3: a silently failing observer must not make everyone blockable."""
    verdicts = cross.decide_blockable(
        {"192.168.0.129": {LEGIT}}, authorized=set(), rejected=set()
    )
    verdict = verdicts["192.168.0.129"]
    assert verdict["blockable"] is False
    assert any("查無記錄" in reason for reason in verdict["reasons_not_blockable"])


def test_a_legitimate_node_and_an_attacker_on_separate_addresses():
    """The cross-host positive control, as logic rather than as live evidence.

    Only the attacker is blockable; the legitimate remote node is spared by
    condition 2 rather than by any accident of the other two.
    """
    verdicts = cross.decide_blockable(
        {"192.168.0.30": {ATTACKER}, "192.168.0.50": {LEGIT}},
        authorized={LEGIT},
        rejected={ATTACKER},
    )
    assert verdicts["192.168.0.30"]["blockable"] is True
    assert verdicts["192.168.0.50"]["blockable"] is False
    assert [a for a, v in verdicts.items() if v["blockable"]] == ["192.168.0.30"]


def test_only_an_explicit_authorized_status_counts_as_authenticated():
    events = [
        {"event": "participant_authentication", "status": "AUTHORIZED",
         "guid": "b7.11.02.9c|0.0.1.c1"},
        {"event": "participant_authentication", "status": "UNAUTHORIZED",
         "guid": "a2.5a.10.4e|0.0.1.c1"},
        # Anything that is not an explicit pass is a rejection, including
        # statuses this code has never seen.
        {"event": "participant_authentication", "status": "REQUEST_NOT_COMPLETE",
         "guid": "c9.aa.bb.cc|0.0.1.c1"},
        # Unrelated events and blank GUIDs contribute nothing.
        {"event": "participant_discovery", "status": "AUTHORIZED",
         "guid": "dd.ee.ff.00|0.0.1.c1"},
        {"event": "participant_authentication", "status": "AUTHORIZED", "guid": ""},
    ]
    authorized, rejected = cross.split_authentication(events)
    # Dotted GUIDs are compacted, because the packet half stores them that way
    # (`guid_prefix` looks like 'a03a141483da28145d7d701f'). If the two halves
    # ever normalise differently the intersection is empty for every session and
    # nothing is ever attributable -- silently, and looking exactly like an
    # attacker that never showed up.
    assert authorized == {"b711029c"}
    assert rejected == {"a25a104e", "c9aabbcc"}


def test_both_halves_normalise_guids_the_same_way():
    """The intersection only exists if the two halves agree on the key form."""
    dotted = "A2.5A.10.4E"
    packet_side_form = "a25a104e"   # as written by decode_rtps_identity
    authorized, rejected = cross.split_authentication(
        [{"event": "participant_authentication", "status": "UNAUTHORIZED",
          "guid": f"{dotted}|0.0.1.c1"}]
    )
    assert rejected == {packet_side_form}
    # And that key really does drive a verdict when paired with the packet half.
    verdicts = cross.decide_blockable(
        {"192.168.0.30": {packet_side_form}}, authorized, rejected
    )
    assert verdicts["192.168.0.30"]["blockable"] is True


def test_an_empty_observer_half_blocks_nothing():
    """No observer events at all must yield no blockable address.

    A capture alone can bind GUIDs to addresses; that is not attribution, and it
    is exactly the state a silently dead observer produces.
    """
    verdicts = cross.decide_blockable(
        {"192.168.0.30": {ATTACKER}}, authorized=set(), rejected=set()
    )
    assert verdicts["192.168.0.30"]["blockable"] is False
