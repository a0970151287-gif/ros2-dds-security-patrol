"""Operator-initiated revocation on the nftables path.

Until 2026-09-24 `revoke()` existed only for the DDS guard. The network path
had two removal guarantees -- the kernel timeout, proven on real hardware, and
reconcile-on-restart -- and no way for an operator to say "stop blocking this
address now". Both are bounded by the TTL, so the gap was never unbounded, but
"wait up to the TTL" is not a revocation, and the response chain's own
definition of done names one.

These tests pin the three decisions in `ResponseBackend.revoke_source` that
could each be argued the other way, and the one failure mode that would make
the audit log actively misleading: reporting a removal the adapter did not
perform.
"""

from __future__ import annotations

import pytest

from firewall_lab.response_backend import (
    BackendApplyError,
    BackendCapacityError,
    Ed25519TicketIssuer,
    InMemoryTimeoutSetAdapter,
    ResponseBackend,
    SQLiteResponseState,
    TicketVerificationError,
)


NOW_NS = 2_000_000_000_000_000_000
BACKEND_ID = "pytest-ed25519-timeout-set"


def _ticket(issuer: Ed25519TicketIssuer, **overrides) -> str:
    values = {
        "evidence_id": "1" * 64,
        "source": "10.10.10.1",
        "source_kind": "network_ip",
        "action": "temporary_block",
        "adapter": "network_helper",
        "backend_id": BACKEND_ID,
        "interface": "eth-test",
        "identity": "dds-guid-test",
        "response_ttl_sec": 30,
        "issued_at_ns": NOW_NS,
        "nonce": "2" * 32,
    }
    values.update(overrides)
    return issuer.issue(**values)


def _backend(tmp_path, issuer, *, adapter=None, max_audit_events=None):
    state_kwargs = {}
    if max_audit_events is not None:
        state_kwargs["max_audit_events"] = max_audit_events
    return ResponseBackend(
        verifier=issuer.verifier(),
        state=SQLiteResponseState(tmp_path / "revocation.sqlite3", **state_kwargs),
        timeout_set=adapter or InMemoryTimeoutSetAdapter(BACKEND_ID),
        backend_id=BACKEND_ID,
        authorized_sources=("10.10.10.0/24",),
    )


def _audit_events(backend):
    return [event["event"] for event in backend.state.audit_events()]


# ─────────────────────── the behaviour itself ───────────────────────


def test_revoking_an_applied_block_removes_it_from_the_adapter(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    backend = _backend(tmp_path, issuer, adapter=adapter)
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)
    assert "10.10.10.1" in adapter.snapshot(now_ns=NOW_NS)

    result = backend.revoke_source("10.10.10.1", now_ns=NOW_NS + 1)

    assert result["existed"] is True
    assert result["removed_from_adapter"] is True
    assert result["active_count"] == 0
    assert "10.10.10.1" not in adapter.snapshot(now_ns=NOW_NS + 1)


def test_revocation_does_not_wait_for_the_ttl(tmp_path):
    """The whole point: the block is gone well inside its own lifetime."""
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    backend = _backend(tmp_path, issuer, adapter=adapter)
    applied = backend.apply_ticket(_ticket(issuer, response_ttl_sec=30), now_ns=NOW_NS)

    one_second_in = NOW_NS + 1_000_000_000
    assert one_second_in < applied.expires_at_ns, "fixture no longer revokes early"
    backend.revoke_source("10.10.10.1", now_ns=one_second_in)

    assert adapter.snapshot(now_ns=one_second_in) == {}


def test_other_blocks_survive_a_revocation(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    backend = _backend(tmp_path, issuer, adapter=adapter)
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)
    backend.apply_ticket(
        _ticket(issuer, source="10.10.10.9", evidence_id="3" * 64, nonce="4" * 32),
        now_ns=NOW_NS,
    )

    backend.revoke_source("10.10.10.1", now_ns=NOW_NS + 1)

    remaining = adapter.snapshot(now_ns=NOW_NS + 1)
    assert set(remaining) == {"10.10.10.9"}


# ─────────────────────── the three arguable decisions ───────────────────────


def test_revocation_requires_no_ticket(tmp_path):
    """Authorisation gates the block, not the unblock.

    If a signed ticket were required to lift one, a rotated or lost key would
    leave a host blocked until its TTL, and the safe direction would depend on
    the same secret as the dangerous one.
    """
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer)
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)

    # No ticket, no signature, no key material -- just the source.
    result = backend.revoke_source("10.10.10.1", now_ns=NOW_NS + 1)
    assert result["existed"] is True


def test_revoking_an_unknown_source_is_not_an_error(tmp_path):
    """Idempotent on purpose.

    A revoke that crashed after committing and is then retried must not raise,
    or the retry loop becomes the reason a block outlives the decision to lift
    it.
    """
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer)

    result = backend.revoke_source("10.10.10.77", now_ns=NOW_NS)

    assert result["existed"] is False
    assert result["removed_from_adapter"] is True


def test_revoking_twice_is_idempotent(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    backend = _backend(tmp_path, issuer, adapter=adapter)
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)

    first = backend.revoke_source("10.10.10.1", now_ns=NOW_NS + 1)
    second = backend.revoke_source("10.10.10.1", now_ns=NOW_NS + 2)

    assert (first["existed"], second["existed"]) == (True, False)
    assert adapter.snapshot(now_ns=NOW_NS + 2) == {}


def test_durable_state_is_cleared_before_the_adapter(tmp_path):
    """Order matters, and the other order is worse.

    Clearing durable state first means a crash in between leaves a block the
    kernel still holds and the record no longer claims; the next reconcile
    removes it, and the TTL bounds the window either way. The other order would
    leave durable state asserting a block the kernel no longer has, and the
    next reconcile would put it back -- a revoked block returning on its own.
    """
    issuer = Ed25519TicketIssuer.generate()
    observed: list[str] = []

    class _OrderRecordingAdapter(InMemoryTimeoutSetAdapter):
        def reconcile(self, desired, *, now_ns):
            observed.append("adapter_reconcile")
            return super().reconcile(desired, now_ns=now_ns)

    backend = _backend(tmp_path, issuer, adapter=_OrderRecordingAdapter(BACKEND_ID))
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)
    observed.clear()

    original = backend.state.revoke_desired

    def _recording_revoke(source, *, now_ns):
        observed.append("durable_delete")
        return original(source, now_ns=now_ns)

    backend.state.revoke_desired = _recording_revoke
    backend.revoke_source("10.10.10.1", now_ns=NOW_NS + 1)

    assert observed == ["durable_delete", "adapter_reconcile"]


def test_a_source_still_present_after_reconcile_fails_closed(tmp_path):
    """Reporting a removal the adapter did not perform is the worst outcome.

    It is the one failure that makes the audit log actively misleading: it
    would say the block was lifted while packets keep being dropped.
    """
    issuer = Ed25519TicketIssuer.generate()

    class _StickyAdapter(InMemoryTimeoutSetAdapter):
        def reconcile(self, desired, *, now_ns):
            super().reconcile(desired, now_ns=now_ns)
            return None

        def snapshot(self, *, now_ns):
            return {"10.10.10.1": now_ns + 1_000_000_000}

    backend = _backend(tmp_path, issuer, adapter=_StickyAdapter(BACKEND_ID))
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)

    with pytest.raises(BackendApplyError, match="still blocked after revocation"):
        backend.revoke_source("10.10.10.1", now_ns=NOW_NS + 1)

    assert "failed_closed" in [
        event["outcome"] for event in backend.state.audit_events()
    ]


# ─────────────────────── the audit trail ───────────────────────


def test_every_revocation_is_audited_including_the_no_op(tmp_path):
    """An attempted revoke is a fact about what an operator did.

    Dropping the record because nothing changed would make the log agree with
    the state while disagreeing with history.
    """
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer)

    backend.revoke_source("10.10.10.55", now_ns=NOW_NS)

    events = _audit_events(backend)
    assert "operator_revoke" in events
    assert "response_revoked" in events
    outcomes = {
        event["event"]: event["outcome"] for event in backend.state.audit_events()
    }
    assert outcomes["operator_revoke"] == "not_present"
    assert outcomes["response_revoked"] == "not_present"


def test_the_reason_reaches_the_audit_row(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer)
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)

    backend.revoke_source("10.10.10.1", now_ns=NOW_NS + 1, reason="false positive")

    rows = [e for e in backend.state.audit_events() if e["event"] == "operator_revoke"]
    assert len(rows) == 1
    assert rows[0]["source"] == "10.10.10.1"


def test_an_exhausted_audit_log_refuses_to_revoke_silently(tmp_path):
    """Fail-closed even in the safe direction.

    An unlogged unblock is how a block silently disappears, so capacity
    exhaustion must raise rather than remove the element unrecorded.
    """
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer, max_audit_events=3)
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)

    with pytest.raises(BackendCapacityError):
        for step in range(12):
            backend.revoke_source(f"10.10.10.{step + 20}", now_ns=NOW_NS + step + 1)


# ─────────────────────── argument validation ───────────────────────


@pytest.mark.parametrize("bad", ["", None, 5, True, []])
def test_a_non_string_source_is_refused(tmp_path, bad):
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer)
    with pytest.raises(BackendApplyError, match="non-empty source"):
        backend.revoke_source(bad, now_ns=NOW_NS)


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "now"])
def test_an_invalid_clock_is_refused(tmp_path, bad):
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer)
    with pytest.raises(TicketVerificationError, match="positive integer"):
        backend.revoke_source("10.10.10.1", now_ns=bad)


def test_expired_entries_are_swept_by_a_revocation(tmp_path):
    """A revoke reads durable state, so it must apply the same expiry rule."""
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    backend = _backend(tmp_path, issuer, adapter=adapter)
    backend.apply_ticket(_ticket(issuer, response_ttl_sec=30), now_ns=NOW_NS)

    long_after = NOW_NS + 3_600_000_000_000
    backend.revoke_source("10.10.10.99", now_ns=long_after)

    assert adapter.snapshot(now_ns=long_after) == {}
    assert "response_expired" in _audit_events(backend)
