"""Reconciliation compares expiries at the adapter's granularity, not exactly.

`ResponseBackend.reconcile` used `!=` on nanosecond integers. The kernel nft set
reports whole seconds of remaining lifetime, so that comparison could never hold
against a real kernel: every reconciliation would have failed closed. The nft
adapter already enforced a one-rounding-second bound internally, and the outer
check silently overrode it with a stricter one.

Nothing offline saw this because every reconcile test drove
``InMemoryTimeoutSetAdapter``, which stores the exact nanosecond value it is
handed and therefore satisfies an exact comparison by construction. That is the
same shape as the two other defects the first live run exposed: the fake and the
production code shared an assumption, so they only ever agreed with each other.

These tests fix the boundary in both directions -- the tolerance must be wide
enough for a real kernel and narrow enough to still catch drift.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from firewall_lab.nft_backend_service import (  # noqa: E402
    PRODUCTION_BACKEND_ID,
    NftablesTimeoutSetAdapter,
)
from firewall_lab.response_backend import (  # noqa: E402
    NETWORK_ACTION,
    NETWORK_ADAPTER,
    BackendApplyError,
    Ed25519TicketIssuer,
    Ed25519TicketVerifier,
    InMemoryTimeoutSetAdapter,
    ResponseBackend,
    SQLiteResponseState,
)
from tests.test_nft_backend_service import MockNftRunner  # noqa: E402

SECOND_NS = 1_000_000_000
SOURCE = "192.168.137.50"
TTL_SEC = 12


# ── the granularity each adapter declares ────────────────────────────────────


def test_the_in_memory_adapter_is_still_exact():
    """The default must not be loosened: it stores what it is given."""
    adapter = InMemoryTimeoutSetAdapter(PRODUCTION_BACKEND_ID)
    assert adapter.expiry_matches(1_000, 1_000)
    assert not adapter.expiry_matches(1_001, 1_000)
    assert not adapter.expiry_matches(999, 1_000)


@pytest.mark.parametrize(
    "offset_ns,accepted,reason",
    [
        (0, True, "exact"),
        (-2 * SECOND_NS, True, "two seconds early is the floor"),
        (-2 * SECOND_NS - 1, False, "just past the floor"),
        (SECOND_NS, True, "one rounding second late is the ceiling"),
        (SECOND_NS + 1, False, "just past the ceiling"),
        (-SECOND_NS, True, "a whole second of kernel rounding"),
        (60 * SECOND_NS, False, "a minute late is drift, not rounding"),
    ],
)
def test_the_kernel_adapter_allows_exactly_one_rounding_second(offset_ns, accepted, reason):
    """Late is bounded harder than early: an expiry must not outlive the ticket.

    The window is asymmetric on purpose -- listing and applying consume time, so
    the observed deadline legitimately drifts earlier, while drifting later
    would mean the block outlives what was signed.
    """
    adapter = NftablesTimeoutSetAdapter(MockNftRunner())
    expected = 5_000_000_000_000
    assert adapter.expiry_matches(expected + offset_ns, expected) is accepted, reason


def test_the_ceiling_is_tighter_than_the_floor():
    """Stated as a property, so widening the late side needs a deliberate edit."""
    adapter = NftablesTimeoutSetAdapter(MockNftRunner())
    expected = 5_000_000_000_000
    late = sum(
        1 for n in range(1, 4) if adapter.expiry_matches(expected + n * SECOND_NS, expected)
    )
    early = sum(
        1 for n in range(1, 4) if adapter.expiry_matches(expected - n * SECOND_NS, expected)
    )
    assert late < early, "an expiry may not outlive the signed deadline"


# ── reconcile() end to end against a second-granularity adapter ──────────────


def _rig(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    runner = MockNftRunner()
    backend = ResponseBackend(
        verifier=Ed25519TicketVerifier(issuer.public_key_bytes()),
        state=SQLiteResponseState(tmp_path / "state.sqlite3"),
        timeout_set=NftablesTimeoutSetAdapter(runner),
        backend_id=PRODUCTION_BACKEND_ID,
        authorized_sources=["192.168.137.0/24"],
        protected_sources=["192.168.137.1/32"],
    )
    ticket = issuer.issue(
        evidence_id="a" * 64,
        source=SOURCE,
        source_kind="network_ip",
        action=NETWORK_ACTION,
        adapter=NETWORK_ADAPTER,
        backend_id=PRODUCTION_BACKEND_ID,
        interface="eth0",
        identity="granularity-test",
        response_ttl_sec=TTL_SEC,
    )
    return backend, runner, ticket


def test_reconcile_succeeds_when_the_adapter_only_knows_whole_seconds(tmp_path):
    """The case that made the live run's reconciliation check unreachable."""
    backend, runner, ticket = _rig(tmp_path)
    backend.apply_ticket(ticket)
    assert runner.entries == {SOURCE: TTL_SEC}

    runner.entries.clear()  # out-of-band drift, as the live check injects
    snapshot = backend.reconcile()
    assert SOURCE in snapshot
    assert runner.entries == {SOURCE: TTL_SEC}


def test_reconcile_still_fails_closed_on_an_extra_source(tmp_path):
    """The source set is compared exactly; only the instant is tolerant."""
    backend, runner, ticket = _rig(tmp_path)
    backend.apply_ticket(ticket)

    original = NftablesTimeoutSetAdapter.snapshot

    def with_a_stray_source(self, *, now_ns):
        result = original(self, now_ns=now_ns)
        result["10.0.0.7"] = now_ns + TTL_SEC * SECOND_NS
        return result

    NftablesTimeoutSetAdapter.snapshot = with_a_stray_source
    try:
        with pytest.raises(BackendApplyError, match="differs from durable"):
            backend.reconcile()
    finally:
        NftablesTimeoutSetAdapter.snapshot = original


def test_reconcile_still_fails_closed_on_an_expiry_far_from_the_ticket(tmp_path):
    """Tolerance is one rounding second, not an open door."""
    backend, runner, ticket = _rig(tmp_path)
    backend.apply_ticket(ticket)

    original = NftablesTimeoutSetAdapter.snapshot

    def with_a_stretched_expiry(self, *, now_ns):
        result = original(self, now_ns=now_ns)
        result[SOURCE] = now_ns + 3600 * SECOND_NS
        return result

    NftablesTimeoutSetAdapter.snapshot = with_a_stretched_expiry
    try:
        with pytest.raises(BackendApplyError, match="differs from durable"):
            backend.reconcile()
    finally:
        NftablesTimeoutSetAdapter.snapshot = original


def test_reconcile_still_fails_closed_when_a_source_is_missing(tmp_path):
    backend, runner, ticket = _rig(tmp_path)
    backend.apply_ticket(ticket)

    original = NftablesTimeoutSetAdapter.snapshot

    def with_nothing(self, *, now_ns):
        return {}

    NftablesTimeoutSetAdapter.snapshot = with_nothing
    try:
        with pytest.raises(BackendApplyError, match="differs from durable"):
            backend.reconcile()
    finally:
        NftablesTimeoutSetAdapter.snapshot = original
