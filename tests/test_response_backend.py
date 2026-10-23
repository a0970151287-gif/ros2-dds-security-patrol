from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

import firewall_lab.response_backend as backend_module
from firewall_lab.decision import DecisionPolicy
from firewall_lab.evidence import EvidenceAuthority, feature_sha256
from firewall_lab.response_backend import (
    BackendApplyError,
    BackendCapacityError,
    BackendUnavailableError,
    DisabledProductionTimeoutSetAdapter,
    Ed25519TicketIssuer,
    Ed25519TicketVerifier,
    InMemoryTimeoutSetAdapter,
    ResponseBackend,
    SQLiteResponseState,
    TicketReplayError,
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


def _backend(
    tmp_path,
    issuer: Ed25519TicketIssuer,
    *,
    adapter=None,
    db_name="response-state.sqlite3",
    max_active_sources=64,
    protected_sources=("10.10.10.2/32",),
):
    timeout_set = adapter or InMemoryTimeoutSetAdapter(BACKEND_ID)
    return ResponseBackend(
        verifier=issuer.verifier(),
        state=SQLiteResponseState(
            tmp_path / db_name,
            max_active_sources=max_active_sources,
        ),
        timeout_set=timeout_set,
        backend_id=BACKEND_ID,
        authorized_sources=("10.10.10.0/24",),
        protected_sources=protected_sources,
    )


def _replace_signed_payload(ticket: str, **updates) -> str:
    encoded, signature = ticket.split(".", 1)
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    payload = json.loads(raw.decode("utf-8"))
    payload.update(updates)
    replacement = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        base64.urlsafe_b64encode(replacement).decode("ascii").rstrip("=")
        + "."
        + signature
    )


def test_public_verifier_has_no_signing_or_private_key_capability():
    issuer = Ed25519TicketIssuer.generate()
    verifier = issuer.verifier()
    assert type(verifier) is Ed25519TicketVerifier
    assert not hasattr(verifier, "issue")
    assert not hasattr(verifier, "private_key_bytes")
    assert verifier.public_key_bytes() == issuer.public_key_bytes()
    assert verifier.key_id == issuer.key_id


def test_missing_ed25519_dependency_disables_ticket_backend(monkeypatch):
    monkeypatch.setattr(
        backend_module,
        "_CRYPTO_IMPORT_ERROR",
        ImportError("cryptography intentionally unavailable"),
    )
    assert backend_module.crypto_ready() is False
    with pytest.raises(BackendUnavailableError, match="live response remains disabled"):
        Ed25519TicketIssuer.generate()


def test_backend_rejects_missing_tampered_wrong_key_and_expired_tickets(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer)

    with pytest.raises(TicketVerificationError, match="missing"):
        backend.apply_ticket("", now_ns=NOW_NS)

    valid = _ticket(issuer)
    replacement = "A" if valid[-1] != "A" else "B"
    with pytest.raises(TicketVerificationError, match="signature"):
        backend.apply_ticket(valid[:-1] + replacement, now_ns=NOW_NS)

    other = Ed25519TicketIssuer.generate()
    with pytest.raises(TicketVerificationError, match="signature"):
        backend.apply_ticket(_ticket(other), now_ns=NOW_NS)

    with pytest.raises(TicketVerificationError, match="expired"):
        backend.apply_ticket(valid, now_ns=NOW_NS + 6_000_000_000)

    assert len(backend.state.audit_events()) == 4
    assert all(
        event["outcome"] == "rejected"
        for event in backend.state.audit_events()
    )


def test_source_substitution_is_rejected_and_backend_uses_signed_source(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    backend = _backend(tmp_path, issuer, adapter=adapter)
    ticket = _ticket(issuer, source="10.10.10.8")

    substituted = _replace_signed_payload(ticket, source="10.10.10.9")
    with pytest.raises(TicketVerificationError, match="signature"):
        backend.apply_ticket(substituted, now_ns=NOW_NS)

    result = backend.apply_ticket(ticket, now_ns=NOW_NS)
    assert result.source == "10.10.10.8"
    assert set(adapter.snapshot(now_ns=NOW_NS)) == {"10.10.10.8"}


def test_backend_rejects_protected_unowned_wrong_backend_or_wrong_adapter(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    cases = [
        (_ticket(issuer, source="10.10.10.2", nonce="3" * 32), "protected"),
        (_ticket(issuer, source="10.20.20.1", nonce="4" * 32), "owned scope"),
        (_ticket(issuer, backend_id="another-backend", nonce="5" * 32), "another backend"),
        (
            _ticket(
                issuer,
                action="lock_velocity",
                adapter="velocity_guard",
                nonce="6" * 32,
            ),
            "fixed signed contract",
        ),
    ]
    for index, (ticket, reason) in enumerate(cases):
        backend = _backend(tmp_path, issuer, db_name=f"scope-{index}.sqlite3")
        with pytest.raises(TicketVerificationError, match=reason):
            backend.apply_ticket(ticket, now_ns=NOW_NS)


def test_ticket_replay_is_rejected_by_durable_unique_nonce(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    first = _backend(tmp_path, issuer, adapter=adapter)
    ticket = _ticket(issuer)
    first.apply_ticket(ticket, now_ns=NOW_NS)

    restarted = _backend(tmp_path, issuer, adapter=adapter)
    with pytest.raises(TicketReplayError, match="already consumed"):
        restarted.apply_ticket(ticket, now_ns=NOW_NS + 1)
    assert adapter.apply_count == 1


def test_nonce_consumption_is_atomic_across_concurrent_connections(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    backends = [
        _backend(tmp_path, issuer, adapter=adapter)
        for _ in range(12)
    ]
    ticket = _ticket(issuer)

    def attempt(backend):
        try:
            backend.apply_ticket(ticket, now_ns=NOW_NS)
            return "applied"
        except TicketReplayError:
            return "replayed"

    with ThreadPoolExecutor(max_workers=12) as pool:
        outcomes = list(pool.map(attempt, backends))
    assert outcomes.count("applied") == 1
    assert outcomes.count("replayed") == 11
    assert adapter.apply_count == 1


def test_global_capacity_is_checked_inside_same_atomic_transaction(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    backend = _backend(tmp_path, issuer, max_active_sources=1)
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)
    second = _ticket(
        issuer,
        source="10.10.10.8",
        evidence_id="7" * 64,
        nonce="8" * 32,
    )
    with pytest.raises(BackendCapacityError, match="capacity"):
        backend.apply_ticket(second, now_ns=NOW_NS)


def test_durable_nonce_and_audit_tables_have_hard_fail_closed_limits(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    state = SQLiteResponseState(
        tmp_path / "bounded.sqlite3",
        max_active_sources=4,
        max_consumed_tickets=1,
        max_audit_events=2,
    )
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    backend = ResponseBackend(
        verifier=issuer.verifier(),
        state=state,
        timeout_set=adapter,
        backend_id=BACKEND_ID,
        authorized_sources=("10.10.10.0/24",),
    )
    backend.apply_ticket(_ticket(issuer), now_ns=NOW_NS)
    second = _ticket(
        issuer,
        source="10.10.10.8",
        evidence_id="8" * 64,
        nonce="9" * 32,
    )
    with pytest.raises(BackendCapacityError, match="consumed-ticket capacity"):
        backend.apply_ticket(second, now_ns=NOW_NS)
    with pytest.raises(BackendCapacityError, match="audit capacity"):
        backend.apply_ticket("", now_ns=NOW_NS)
    status = state.capacity_status()
    assert status["consumed_tickets"] == 1
    assert status["audit_events"] == 2
    assert status["consumed_remaining"] == 0
    assert status["audit_remaining"] == 0
    assert status["retention_policy"].startswith("fail_closed_")
    assert adapter.apply_count == 1


def test_database_capacity_configuration_is_persisted_and_cannot_drift(tmp_path):
    path = tmp_path / "metadata.sqlite3"
    SQLiteResponseState(
        path,
        max_active_sources=4,
        max_consumed_tickets=10,
        max_audit_events=20,
    )
    with pytest.raises(BackendUnavailableError, match="does not match"):
        SQLiteResponseState(
            path,
            max_active_sources=4,
            max_consumed_tickets=11,
            max_audit_events=20,
        )


def test_restart_reconciliation_restores_missing_and_removes_stale_state(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    adapter = InMemoryTimeoutSetAdapter(BACKEND_ID)
    first = _backend(tmp_path, issuer, adapter=adapter)
    first.apply_ticket(_ticket(issuer), now_ns=NOW_NS)
    expected_expiry = NOW_NS + 30_000_000_000

    # Simulate loss of kernel state plus drift in the dedicated timeout set.
    adapter.clear_for_test()
    adapter.seed_for_test("10.10.10.99", NOW_NS + 60_000_000_000)
    restarted = _backend(tmp_path, issuer, adapter=adapter)
    assert restarted.reconcile(now_ns=NOW_NS + 1_000_000_000) == {
        "10.10.10.1": expected_expiry
    }

    # The fake timeout set and durable desired state both expire automatically.
    assert restarted.reconcile(now_ns=NOW_NS + 31_000_000_000) == {}
    second_restart = _backend(tmp_path, issuer, adapter=adapter)
    assert second_restart.reconcile(now_ns=NOW_NS + 32_000_000_000) == {}
    events = second_restart.state.audit_events()
    assert any(event["event"] == "response_expired" for event in events)
    assert sum(event["event"] == "restart_reconcile" for event in events) == 3


def test_failed_adapter_is_staged_for_restart_recovery_without_retrying_ticket(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    disabled = DisabledProductionTimeoutSetAdapter(BACKEND_ID)
    backend = _backend(tmp_path, issuer, adapter=disabled)
    ticket = _ticket(issuer)
    with pytest.raises(BackendApplyError, match="staged durably"):
        backend.apply_ticket(ticket, now_ns=NOW_NS)

    fake = InMemoryTimeoutSetAdapter(BACKEND_ID)
    restarted = _backend(tmp_path, issuer, adapter=fake)
    assert set(restarted.reconcile(now_ns=NOW_NS + 1)) == {"10.10.10.1"}
    with pytest.raises(TicketReplayError):
        restarted.apply_ticket(ticket, now_ns=NOW_NS + 2)
    assert any(
        event["outcome"] == "pending_recovery"
        for event in restarted.state.audit_events()
    )


def test_existing_evidence_authority_issues_backend_verifiable_v2_ticket(tmp_path):
    ticket_issuer = Ed25519TicketIssuer.generate()
    authority = EvidenceAuthority(
        b"pytest-evidence-secret" * 2,
        collector_id="pytest-backend-integration",
        ticket_issuer=ticket_issuer,
    )
    decision = DecisionPolicy.authorising(
        ["service_dos", "command_injection", "identity_abuse",
         "message_dos", "replay", "replay_dos", "sensor_spoof",
         "parameter_tamper"]
    ).decide(
        predicted_class="service_dos",
        confidence=0.99,
        anomaly=True,
    )
    envelope = authority.issue(
        source="10.10.10.8",
        source_kind="network_ip",
        interface="eth-test",
        identity="dds-guid-test",
        feature_digest=feature_sha256({"packets": 99.0, "rate": 2.0}),
        session_id="session-test",
        window_id="window-test",
        model_sha256="a" * 64,
        policy_sha256="b" * 64,
        backend_id=BACKEND_ID,
        attribution_confidence=0.99,
        signals={"network": 0.99, "telemetry": 0.90},
        source_shared=False,
        confirmation_windows=2,
        decision=decision,
        observed_at_ns=NOW_NS,
    )
    ticket = authority.claim(
        envelope,
        action=decision.action,
        adapter=decision.adapter,
        ttl_sec=30,
    )
    backend = ResponseBackend(
        verifier=authority.ticket_verifier(),
        state=SQLiteResponseState(tmp_path / "integrated.sqlite3"),
        timeout_set=InMemoryTimeoutSetAdapter(BACKEND_ID),
        backend_id=BACKEND_ID,
        authorized_sources=("10.10.10.0/24",),
    )
    result = backend.apply_ticket(ticket)
    assert result.source == envelope.source
    assert result.evidence_id == envelope.evidence_id


def test_production_adapter_is_fail_closed_and_contains_no_activation_switch():
    adapter = DisabledProductionTimeoutSetAdapter(BACKEND_ID)
    assert not hasattr(adapter, "enable")
    assert not hasattr(adapter, "command")
    with pytest.raises(BackendUnavailableError, match="disabled"):
        adapter.snapshot(now_ns=NOW_NS)
