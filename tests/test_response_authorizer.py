import math
import time
from dataclasses import replace

import pytest

import firewall_lab.evidence as evidence_module
from firewall_lab.catalog import load_catalog
from firewall_lab.decision import DecisionPolicy, FirewallDecision
from firewall_lab.evidence import EvidenceAuthority, feature_sha256
from firewall_lab.response_authorizer import ResponseAuthorizer, ResponseContext
from firewall_lab.schema import SchemaError
from firewall_lab.synthetic_dataset import ATTACK_PROFILES, load_synthetic_scenarios


MODEL_HASH = "1" * 64
POLICY_HASH = "2" * 64
BACKEND_ID = "pytest-nft-timeout-set"


def _authority():
    return EvidenceAuthority(b"test-evidence-secret" * 2, collector_id="pytest")


def _decision(attack_class="service_dos"):
    return DecisionPolicy.load().decide(
        predicted_class=attack_class,
        confidence=0.99,
        anomaly=True,
    )


def _envelope(authority, decision, **overrides):
    values = {
        "source": "10.10.10.1",
        "source_kind": "network_ip",
        "interface": "eth-test",
        "identity": "dds-guid-test",
        "feature_digest": feature_sha256({"packets": 99.0, "rate": 2.0}),
        "session_id": "session-test",
        "window_id": "window-test",
        "model_sha256": MODEL_HASH,
        "policy_sha256": POLICY_HASH,
        "backend_id": BACKEND_ID,
        "attribution_confidence": 0.99,
        "signals": {"network": 0.98, "telemetry": 0.90},
        "source_shared": False,
        "confirmation_windows": 2,
        "decision": decision,
    }
    values.update(overrides)
    return authority.issue(**values)


def _bound(authority, decision, **overrides):
    envelope = _envelope(authority, decision, **overrides)
    return replace(decision, evidence_id=envelope.evidence_id), envelope


def _context(envelope=None, **overrides):
    values = {
        "requested_mode": "live",
        "source": envelope.source if envelope is not None else "10.10.10.1",
        "source_kind": envelope.source_kind if envelope is not None else "network_ip",
        "evidence": envelope,
        "requested_ttl_sec": 300,
    }
    values.update(overrides)
    return ResponseContext(**values)


def _network_authorizer(authority, **overrides):
    values = {
        "authorized_sources": {"10.10.10.0/24"},
        "protected_sources": {"10.10.10.2/32"},
        "evidence_verifier": authority.verifier(),
        "model_deployment_eligible": True,
        "model_artifact_sha256": MODEL_HASH,
        "policy_verified": True,
        "policy_sha256": POLICY_HASH,
        "network_backend_kind": "nftables_timeout_set",
        "network_backend_id": BACKEND_ID,
        "network_backend_capacity_ready": True,
        "network_backend_recovery_verified": True,
    }
    values.update(overrides)
    return ResponseAuthorizer(**values)


def test_action_policy_explicitly_covers_every_model_class():
    policy = DecisionPolicy.load()
    assert set(policy.rules) == {"normal", *ATTACK_PROFILES}


def test_training_catalog_actions_match_runtime_policy_semantics():
    policy = DecisionPolicy.load()
    expected = {
        scenario.attack_class: scenario.expected_action
        for scenario in load_catalog().values()
    }
    expected.update(
        {
            scenario["attack_class"]: scenario["expected_action"]
            for scenario in load_synthetic_scenarios().values()
        }
    )
    assert set(expected) == set(policy.rules)
    assert {
        attack_class: rule["action"]
        for attack_class, rule in policy.rules.items()
    } == expected


def test_network_live_response_requires_signed_attributed_two_signal_evidence():
    authority = _authority()
    decision, envelope = _bound(authority, _decision())
    accepted = _network_authorizer(authority).authorize(
        decision, _context(envelope)
    )
    assert accepted.live_eligible is True
    assert accepted.execute is True
    assert accepted.effective_mode == "live"
    assert accepted.source == "10.10.10.1"
    assert accepted.evidence_id == envelope.evidence_id
    assert "." in accepted.authorization_ticket
    authority.verifier().verify_ticket(
        accepted.authorization_ticket,
        source=accepted.source,
        action=accepted.action,
        adapter=accepted.adapter,
        evidence_id=accepted.evidence_id,
        backend_id=envelope.backend_id,
        interface=envelope.interface,
        identity=envelope.identity,
        ttl_sec=accepted.ttl_sec,
    )
    assert accepted.ttl_sec == 300
    assert accepted.rollback_required is True

    one_signal_decision = _decision()
    one_signal_decision, one_signal = _bound(
        authority, one_signal_decision, signals={"network": 0.99}
    )
    denied = _network_authorizer(authority).authorize(
        one_signal_decision, _context(one_signal)
    )
    assert denied.execute is False
    assert "independent corroborating" in " ".join(denied.blockers)


def test_source_a_evidence_cannot_be_reused_to_block_source_b():
    authority = _authority()
    decision, envelope = _bound(authority, _decision())
    response = _network_authorizer(authority).authorize(
        decision,
        _context(envelope, source="10.10.10.99"),
    )
    assert response.execute is False
    assert "does not match signed evidence" in " ".join(response.blockers)


def test_arbitrary_or_tampered_evidence_is_not_trusted():
    authority = _authority()
    decision, envelope = _bound(authority, _decision())
    mismatched = _network_authorizer(authority).authorize(
        replace(decision, evidence_id="b" * 64), _context(envelope)
    )
    assert mismatched.execute is False
    assert "does not reference" in " ".join(mismatched.blockers)

    forged = replace(envelope, source="10.10.10.99")
    forged_response = _network_authorizer(authority).authorize(
        decision, _context(forged)
    )
    assert forged_response.execute is False
    assert "verification failed" in " ".join(forged_response.blockers)


def test_signed_non_executable_decision_cannot_be_flipped_executable():
    authority = _authority()
    unsigned = FirewallDecision(
        predicted_class="service_dos",
        confidence=0.99,
        anomaly=True,
        action="temporary_block",
        adapter="network_helper",
        executable=False,
        reason="signed as non executable",
    )
    envelope = _envelope(authority, unsigned)
    flipped = replace(unsigned, executable=True, evidence_id=envelope.evidence_id)
    response = _network_authorizer(authority).authorize(
        flipped, _context(envelope)
    )
    assert response.execute is False
    assert "decision fields" in " ".join(response.blockers)


def test_ticket_claim_rejects_action_adapter_or_ttl_escalation():
    authority = _authority()
    decision, envelope = _bound(authority, _decision())
    with pytest.raises(SchemaError, match="does not match signed evidence"):
        authority.claim(
            envelope,
            action="deny_participant",
            adapter="sros2_identity",
            ttl_sec=300,
        )
    with pytest.raises(SchemaError, match="ttl_sec"):
        authority.claim(
            envelope,
            action=decision.action,
            adapter=decision.adapter,
            ttl_sec=999999,
        )


def test_ticket_rejects_tamper_source_substitution_expiry_and_replay(monkeypatch):
    authority = _authority()
    decision, envelope = _bound(authority, _decision())
    accepted = _network_authorizer(authority).authorize(decision, _context(envelope))
    verifier = authority.verifier()
    values = {
        "source": accepted.source,
        "action": accepted.action,
        "adapter": accepted.adapter,
        "evidence_id": accepted.evidence_id,
        "backend_id": envelope.backend_id,
        "interface": envelope.interface,
        "identity": envelope.identity,
        "ttl_sec": accepted.ttl_sec,
    }
    replacement = "0" if accepted.authorization_ticket[-1] != "0" else "1"
    with pytest.raises(SchemaError, match="signature"):
        verifier.verify_ticket(
            accepted.authorization_ticket[:-1] + replacement, **values
        )
    with pytest.raises(SchemaError, match="does not match"):
        verifier.verify_ticket(
            accepted.authorization_ticket,
            **{**values, "source": "10.10.10.99"},
        )
    verifier.verify_ticket(accepted.authorization_ticket, consume=True, **values)
    with pytest.raises(SchemaError, match="already consumed"):
        verifier.verify_ticket(accepted.authorization_ticket, consume=True, **values)

    original_now = time.time_ns()
    monkeypatch.setattr(evidence_module.time, "time_ns", lambda: original_now + 6_000_000_000)
    with pytest.raises(SchemaError, match="expired"):
        verifier.verify_ticket(accepted.authorization_ticket, **values)


def test_authorizer_receives_verifier_capability_without_issue_method():
    authority = _authority()
    verifier = authority.verifier()
    assert not hasattr(verifier, "issue")
    ResponseAuthorizer(evidence_verifier=verifier)
    with pytest.raises(SchemaError, match="evidence_verifier"):
        ResponseAuthorizer(evidence_verifier=authority)


def test_network_response_refuses_protected_allowlisted_special_and_unowned_sources():
    authority = _authority()

    def response_for(source, authorizer):
        base = _decision("spdp_flood")
        bound, evidence = _bound(authority, base, source=source)
        return authorizer.authorize(bound, _context(evidence))

    authorizer = _network_authorizer(
        authority, allowlisted_sources={"10.10.10.10/32"}
    )
    protected = response_for("10.10.10.2", authorizer)
    allowlisted = response_for("10.10.10.10", authorizer)
    loopback = response_for("127.0.0.1", authorizer)
    unowned = response_for("10.20.20.1", authorizer)
    assert not protected.execute and "protected" in " ".join(protected.blockers)
    assert not allowlisted.execute and "allowlist" in " ".join(allowlisted.blockers)
    assert not loopback.execute and "special" in " ".join(loopback.blockers)
    assert not unowned.execute and "authorizer-owned scope" in " ".join(unowned.blockers)


def test_shared_stale_single_window_or_unready_runtime_fails_closed():
    authority = _authority()
    base = _decision()
    cases = [
        (_bound(authority, base, source_shared=True), _network_authorizer(authority)),
        (
            _bound(
                authority,
                base,
                observed_at_ns=time.time_ns() - 11_000_000_000,
            ),
            _network_authorizer(authority),
        ),
        (
            _bound(authority, base, confirmation_windows=1),
            _network_authorizer(authority),
        ),
        (_bound(authority, base), _network_authorizer(authority, model_deployment_eligible=False)),
        (_bound(authority, base), _network_authorizer(authority, model_artifact_sha256="5" * 64)),
        (_bound(authority, base), _network_authorizer(authority, policy_verified=False)),
        (_bound(authority, base), _network_authorizer(authority, policy_sha256="6" * 64)),
        (_bound(authority, base), _network_authorizer(authority, network_backend_kind="iptables_sleep")),
        (_bound(authority, base), _network_authorizer(authority, network_backend_id="different-backend")),
        (_bound(authority, base), _network_authorizer(authority, network_backend_capacity_ready=False)),
        (_bound(authority, base), _network_authorizer(authority, network_backend_recovery_verified=False)),
    ]
    for (decision, envelope), authorizer in cases:
        assert authorizer.authorize(decision, _context(envelope)).execute is False


def test_dry_run_never_executes_when_live_evidence_is_missing():
    decision = _decision("verify_flood")
    response = ResponseAuthorizer().authorize(
        decision,
        _context(None, requested_mode="dry_run"),
    )
    assert response.effective_mode == "dry_run"
    assert response.execute is False
    assert response.live_eligible is False
    assert response.blockers


def test_velocity_guard_requires_signed_behavior_evidence_and_recovery():
    authority = _authority()
    base = _decision("cmd_vel_race")
    decision, envelope = _bound(
        authority,
        base,
        source="dds-guid",
        source_kind="dds_identity",
        signals={"ros_behavior": 0.95},
    )
    authorizer = ResponseAuthorizer(
        evidence_verifier=authority.verifier(),
        policy_verified=True,
        policy_sha256=POLICY_HASH,
        velocity_guard_recovery_verified=True,
    )
    accepted = authorizer.authorize(
        decision,
        _context(
            envelope,
            source="dds-guid",
            source_kind="dds_identity",
            requested_ttl_sec=120,
        ),
    )
    assert accepted.execute is True
    assert accepted.ttl_sec == 30
    assert "." in accepted.authorization_ticket

    missing = authorizer.authorize(
        replace(decision, evidence_id=""),
        _context(None, source="dds-guid", source_kind="dds_identity"),
    )
    assert missing.execute is False
    assert "evidence" in " ".join(missing.blockers)


def test_sros2_and_hmac_controls_are_upstream_prevention_without_dynamic_ticket():
    policy = DecisionPolicy.load()
    for attack_class in ("identity_abuse", "hmac_forgery"):
        decision = policy.decide(
            predicted_class=attack_class,
            confidence=0.99,
            anomaly=True,
        )
        response = ResponseAuthorizer().authorize(decision, _context())
        assert response.effective_mode == "prevention_only"
        assert response.execute is False
        assert response.live_eligible is True
        assert response.authorization_ticket == ""


def test_authorizer_fails_closed_on_invalid_decision_or_runtime_attestation():
    decision = replace(_decision(), confidence=math.nan)
    with pytest.raises(SchemaError, match="decision.confidence"):
        ResponseAuthorizer().authorize(decision, _context())
    with pytest.raises(SchemaError, match="model_deployment_eligible"):
        ResponseAuthorizer(model_deployment_eligible="true")
    with pytest.raises(SchemaError, match="network_backend_kind"):
        ResponseAuthorizer(network_backend_kind=[])
