"""An offline rehearsal of everything the live acceptance run does with tickets.

The live run costs a human typing an approval phrase at a console, so each round
trip is expensive and each one should not be spent discovering a defect that was
reachable offline. The first run on 2026-09-21 was spent exactly that way: it
reached ``check_temporary_block_semantics`` and crashed because ``evidence_id``
was a readable label rather than the 64 hex characters the ticket schema
demands. Nothing offline touched that code path.

This file drives the executor's own functions against a mock nft runner, so the
ticket construction, the semantics check and the reconciliation path all fail
here first if they are going to fail at all. What it deliberately cannot cover
is anything only a kernel can answer -- packet drops, timeout expiry, the
rendering of the installed ruleset -- which is why the live run still exists.
"""

from __future__ import annotations

import importlib.util
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
    Ed25519TicketIssuer,
    Ed25519TicketVerifier,
    ResponseBackend,
    SQLiteResponseState,
    TicketVerificationError,
)
from tests.test_nft_backend_service import MockNftRunner  # noqa: E402

_EXECUTOR_PATH = _ROOT / "工具腳本" / "run_nft_live_acceptance.py"

TEST_SOURCE = "192.168.137.50"
AUTHORIZED = ["192.168.137.0/24"]
PROTECTED = ["192.168.137.1/32"]


@pytest.fixture(scope="module")
def executor():
    spec = importlib.util.spec_from_file_location("_nft_rehearsal", _EXECUTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def rig(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    runner = MockNftRunner()
    backend = ResponseBackend(
        verifier=Ed25519TicketVerifier(issuer.public_key_bytes()),
        state=SQLiteResponseState(tmp_path / "state.sqlite3"),
        timeout_set=NftablesTimeoutSetAdapter(runner),
        backend_id=PRODUCTION_BACKEND_ID,
        authorized_sources=AUTHORIZED,
        protected_sources=PROTECTED,
    )
    return issuer, backend, runner


# ── the ticket the run applies ───────────────────────────────────────────────


def test_the_acceptance_ticket_is_accepted(executor, rig):
    """The exact ticket `run()` issues, through the real validator."""
    issuer, backend, runner = rig
    ticket = executor.issue_block_ticket(
        issuer, TEST_SOURCE, interface="eth0", ttl_sec=executor.APPLIED_TTL_SEC
    )
    applied = backend.apply_ticket(ticket)
    assert applied.source == TEST_SOURCE
    assert runner.entries == {TEST_SOURCE: executor.APPLIED_TTL_SEC}


def test_the_evidence_id_meets_the_ticket_schema(executor):
    """The defect that ended the first live run, stated directly."""
    value = executor._evidence_id("nft-live-acceptance")
    assert len(value) == 64
    assert value == value.lower()
    assert all(character in "0123456789abcdef" for character in value)


def test_evidence_ids_identify_which_check_issued_the_ticket(executor):
    labels = ("acceptance-wrong-action", "acceptance-out-of-scope", "nft-live-acceptance")
    digests = {label: executor._evidence_id(label) for label in labels}
    assert len(set(digests.values())) == len(labels), "ids must not collide"
    for label, digest in digests.items():
        assert executor._evidence_id(label) == digest, "ids must be stable"


def test_a_readable_label_would_still_be_rejected(executor, rig):
    """Proof the guard is in the schema, not in this test's politeness."""
    issuer, _, _ = rig
    with pytest.raises(TicketVerificationError, match="evidence_id"):
        issuer.issue(
            evidence_id="nft-live-acceptance",
            source=TEST_SOURCE,
            source_kind="network_ip",
            action="temporary_block",
            adapter="nftables_timeout_set",
            backend_id=PRODUCTION_BACKEND_ID,
            interface="eth0",
            identity="nft-live-acceptance",
            response_ttl_sec=executor.APPLIED_TTL_SEC,
        )


def test_the_applied_ttl_stays_within_the_declared_bound(executor):
    assert 0 < executor.APPLIED_TTL_SEC <= executor.MAX_TEST_TTL_SEC


# ── the semantics check, which is where the live run died ────────────────────


def test_the_semantics_check_passes_offline(executor, rig):
    issuer, backend, runner = rig
    ok, evidence = executor.check_temporary_block_semantics(backend, issuer, TEST_SOURCE)
    assert ok, evidence
    assert "rate_limit rejected" in evidence
    assert "out-of-scope rejected" in evidence
    assert runner.entries == {}, "a refused ticket must not reach the kernel"


def test_the_semantics_check_would_fail_if_a_wrong_action_were_accepted(executor, rig):
    """The check has to be capable of returning False, not just of running."""
    issuer, backend, _ = rig
    backend.apply_ticket = lambda ticket: None  # accept everything
    ok, evidence = executor.check_temporary_block_semantics(backend, issuer, TEST_SOURCE)
    assert not ok
    assert "rate_limit" in evidence


# ── reconciliation, minus the parts only a kernel can answer ─────────────────


def test_reconcile_restores_an_element_deleted_out_of_band(executor, rig, tmp_path):
    """Mirrors check_restart_reconciliation without the nft subprocess.

    The live check drifts the kernel with `nft delete element`; here the mock's
    own table is drifted instead, so the part being rehearsed is a fresh backend
    rebuilding state from its database.
    """
    issuer, backend, runner = rig
    ticket = executor.issue_block_ticket(
        issuer, TEST_SOURCE, interface="eth0", ttl_sec=executor.APPLIED_TTL_SEC
    )
    backend.apply_ticket(ticket)
    assert TEST_SOURCE in runner.entries

    runner.entries.pop(TEST_SOURCE)
    assert runner.entries == {}

    restarted = ResponseBackend(
        verifier=Ed25519TicketVerifier(issuer.public_key_bytes()),
        state=SQLiteResponseState(tmp_path / "state.sqlite3"),
        timeout_set=NftablesTimeoutSetAdapter(runner),
        backend_id=PRODUCTION_BACKEND_ID,
        authorized_sources=AUTHORIZED,
        protected_sources=PROTECTED,
    )
    restarted.reconcile()
    assert TEST_SOURCE in runner.entries


# ── the protected source is refused before any of this ───────────────────────


def test_the_protected_source_can_never_be_blocked(executor, rig):
    """192.168.137.1 is the operator's path in; the backend must refuse it."""
    issuer, backend, runner = rig
    ticket = executor.issue_block_ticket(
        issuer, "192.168.137.1", interface="eth0", ttl_sec=executor.APPLIED_TTL_SEC
    )
    with pytest.raises(TicketVerificationError):
        backend.apply_ticket(ticket)
    assert runner.entries == {}
