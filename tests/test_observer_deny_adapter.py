"""Tests for the observer→sros2_deny bridge.

sros_auth_fail_rate has been dead since day one: the deny adapter read 249,670
lines across the 1,100-session campaign and classified none of them, because
rmw_fastrtps never exposes dds.sec.log.plugin. The sidecar observer is the only
path in this project that has ever produced a DDS authentication verdict, so
this bridge is what finally gives that feature a source.

Which makes its failure modes worth pinning: a bridge that silently drops
denials leaves the feature at zero and looks exactly like the four years of
"no source" that came before it, and a bridge that counts too eagerly invents
evidence for the class it is meant to measure.
"""

from __future__ import annotations

import json

from firewall_lab.observer_deny_adapter import (
    ObserverDenyAdapter,
    classify_observer_event,
)

REJECT = {
    "event": "participant_authentication",
    "status": "UNAUTHORIZED",
    "guid": "a2.5a.10.4e|0.0.1.c1",
}
ACCEPT = {
    "event": "participant_authentication",
    "status": "AUTHORIZED",
    "guid": "b7.11.02.9c|0.0.1.c1",
}


def _adapter(results=None):
    sent = []

    def emit(kind):
        sent.append(kind)
        return True if results is None else results.pop(0)

    return ObserverDenyAdapter(emit), sent


def test_a_rejection_becomes_an_authentication_deny():
    adapter, sent = _adapter()
    adapter.consume_line(json.dumps(REJECT))
    assert sent == ["authentication"]
    assert adapter.summary()["denies_emitted"] == 1


def test_a_successful_authentication_is_not_a_deny():
    """The feature counts refusals. Counting admissions would invert it."""
    adapter, sent = _adapter()
    adapter.consume_line(json.dumps(ACCEPT))
    assert sent == []
    summary = adapter.summary()
    assert summary["denies_emitted"] == 0
    assert summary["authorized_seen"] == 1


def test_only_an_explicit_authorized_counts_as_a_pass():
    """Same rule as the crosscheck: anything that is not an explicit pass is a
    refusal. The two must not diverge, or one component will call a participant
    admitted while the other calls it refused."""
    adapter, sent = _adapter()
    adapter.consume_line(json.dumps({**REJECT, "status": "REQUEST_NOT_COMPLETE"}))
    assert sent == ["authentication"]


def test_events_that_are_not_authentication_verdicts_are_ignored():
    adapter, sent = _adapter()
    adapter.consume_line(json.dumps({
        "event": "participant_discovery", "status": "AUTHORIZED",
        "guid": "cc.dd.ee.ff|0.0.1.c1",
    }))
    assert sent == []
    assert adapter.summary()["denies_emitted"] == 0


def test_a_verdict_without_a_guid_is_not_counted():
    """A refusal that cannot be attributed to a participant is not evidence."""
    adapter, sent = _adapter()
    adapter.consume_line(json.dumps({**REJECT, "guid": ""}))
    assert sent == []


def test_repeated_refusals_of_one_guid_are_counted_separately():
    """Each callback is a distinct handshake attempt being refused.

    distinct_guids is reported alongside so the ratio is visible and nobody has
    to take this decision on trust.
    """
    adapter, sent = _adapter()
    for _ in range(3):
        adapter.consume_line(json.dumps(REJECT))
    summary = adapter.summary()
    assert summary["denies_emitted"] == 3
    assert summary["distinct_guids"] == 1


def test_a_dropped_datagram_is_recorded_not_swallowed():
    """Telemetry is a Unix datagram socket and drops under load.

    A silently lost denial leaves the feature short by one with nobody knowing,
    which is the same defect that cost the d4 incident transition.
    """
    adapter, _sent = _adapter(results=[False, True])
    adapter.consume_line(json.dumps(REJECT))
    adapter.consume_line(json.dumps(REJECT))
    summary = adapter.summary()
    assert summary["denies_emitted"] == 1
    assert summary["send_failures"] == 1


def test_malformed_lines_do_not_stop_the_stream():
    adapter, sent = _adapter()
    adapter.consume_line("{not json")
    adapter.consume_line(json.dumps(REJECT))
    summary = adapter.summary()
    assert summary["malformed"] == 1
    assert sent == ["authentication"]


def test_an_empty_stream_says_it_observed_nothing():
    """Distinguishes 'saw nothing' from 'saw admissions only'.

    Zero denials with zero admissions means the observer produced no verdicts at
    all, which is a broken source rather than a quiet network.
    """
    adapter, _sent = _adapter()
    assert adapter.summary()["observability"] == "no_authentication_events_observed"
    adapter.consume_line(json.dumps(ACCEPT))
    assert adapter.summary()["observability"] == "authentication_events_observed"


def test_permission_denials_are_not_invented():
    """sros_permission_deny_rate still has no source and must stay at zero.

    The participant listener reports authentication, not per-topic access. If
    this bridge ever emitted a permission kind it would populate a feature from
    a source that cannot see that layer.
    """
    for status in ("UNAUTHORIZED", "REQUEST_NOT_COMPLETE", "HANDSHAKE_FAILED"):
        assert classify_observer_event({**REJECT, "status": status}) == "authentication"
