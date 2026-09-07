"""未知攻擊路徑可以觸發什麼、不可以觸發什麼。

`unknown_anomaly_action` 原本被硬性限制為完全不可執行。2026-08-27 依 Jesse
明確指示放寬，讓它可以走**可撤銷**的第二層守衛——理由是處女 holdout 上的
open-set recall 只有 0.0273，異常判定經常是錯的，而經常錯的判定配得上的
只有收得回來的動作。

這些測試守的是**放寬到哪裡為止**：不可撤銷或會波及第三方的動作必須仍然
被擋在門外，而且執行需要操作者另外明確開啟。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall_lab.decision import (
    REVOCABLE_ANOMALY_ACTION,
    DecisionPolicy,
)
from firewall_lab.schema import SchemaError

_SHIPPED = Path(__file__).resolve().parents[1] / "firewall_lab" / "action_policy.json"


def _policy(**overrides) -> DecisionPolicy:
    value = json.loads(_SHIPPED.read_text(encoding="utf-8"))
    value.update(overrides)
    return DecisionPolicy(value)


def _anomaly_decision(policy: DecisionPolicy, *, predicted_class="normal"):
    return policy.decide(predicted_class=predicted_class, confidence=0.99,
                         anomaly=True)


# ── 出貨姿態沒有被這次放寬改動 ──────────────────────────────────────────────

def test_shipped_policy_still_never_executes_on_an_anomaly():
    policy = DecisionPolicy.load()
    for predicted_class in ("normal", "a_class_with_no_rule"):
        decision = _anomaly_decision(policy, predicted_class=predicted_class)
        assert decision.executable is False
        assert decision.adapter == "none"


def test_shipped_policy_does_not_opt_into_anomaly_response():
    assert DecisionPolicy.load().anomaly_response_authorized is False


# ── 放寬的範圍 ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("action", [
    "temporary_block",    # 網路層、要 root、影響整個 IP
    "deny_participant",   # SROS2 靜態 ACL，不可撤銷
    "drop_message",
    "lock_velocity",
])
def test_irreversible_or_broad_actions_are_still_refused(action):
    # 不確定的判定不該觸發收不回來或波及第三方的動作。
    with pytest.raises(SchemaError, match="unknown_anomaly_action"):
        _policy(unknown_anomaly_action=action)


def test_the_revocable_action_is_accepted():
    policy = _policy(unknown_anomaly_action=REVOCABLE_ANOMALY_ACTION)
    assert policy.unknown_anomaly_action == REVOCABLE_ANOMALY_ACTION


def test_default_action_may_not_use_the_revocable_response():
    # default_action 走的是「未知類別但異常偵測器沒說話」。連異常訊號都沒有，
    # 就沒有任何動作的正當性。
    with pytest.raises(SchemaError, match="default_action"):
        _policy(default_action=REVOCABLE_ANOMALY_ACTION)


# ── 兩道閘，缺一不可 ────────────────────────────────────────────────────────

def test_revocable_action_without_the_operator_switch_stays_observe():
    policy = _policy(unknown_anomaly_action=REVOCABLE_ANOMALY_ACTION)
    decision = _anomaly_decision(policy)
    assert decision.executable is False
    assert decision.adapter == "none"


def test_operator_switch_without_the_revocable_action_stays_observe():
    policy = _policy(unknown_anomaly_action="quarantine",
                     anomaly_response_authorized=True)
    decision = _anomaly_decision(policy)
    assert decision.executable is False
    assert decision.adapter == "none"


def test_both_gates_together_reach_the_revocable_guard():
    policy = _policy(unknown_anomaly_action=REVOCABLE_ANOMALY_ACTION,
                     anomaly_response_authorized=True)
    decision = _anomaly_decision(policy)
    assert decision.executable is True
    assert decision.adapter == "dds_guard"
    assert decision.action == REVOCABLE_ANOMALY_ACTION


def test_both_anomaly_paths_behave_identically():
    # 「已知類別說 normal 但異常頭不同意」與「類別根本沒有規則」是兩條
    # 不同的程式路徑，走出來的授權必須一樣，否則會有一條漏網。
    policy = _policy(unknown_anomaly_action=REVOCABLE_ANOMALY_ACTION,
                     anomaly_response_authorized=True)
    through_normal = _anomaly_decision(policy, predicted_class="normal")
    through_unknown = _anomaly_decision(policy,
                                        predicted_class="never_trained_class")
    assert through_normal.adapter == through_unknown.adapter == "dds_guard"
    assert through_normal.executable is through_unknown.executable is True


# ── 兩份授權清單互不相通 ────────────────────────────────────────────────────

def test_executable_classes_do_not_grant_anomaly_response():
    # 逐類授權與未知攻擊授權是不同的判斷：未知攻擊按定義不屬於任何一類。
    policy = _policy(executable_classes=["service_dos"],
                     unknown_anomaly_action=REVOCABLE_ANOMALY_ACTION)
    assert _anomaly_decision(policy).executable is False


def test_anomaly_response_does_not_grant_class_execution():
    policy = _policy(unknown_anomaly_action=REVOCABLE_ANOMALY_ACTION,
                     anomaly_response_authorized=True)
    for name in policy.rules:
        decision = policy.decide(predicted_class=name, confidence=0.99,
                                 anomaly=False)
        assert decision.executable is False, name


def test_an_unknown_class_without_anomaly_agreement_never_executes():
    # 異常頭沒有同意時，未知類別仍然只能觀察——開關開著也一樣。
    policy = _policy(unknown_anomaly_action=REVOCABLE_ANOMALY_ACTION,
                     anomaly_response_authorized=True)
    decision = policy.decide(predicted_class="never_trained_class",
                             confidence=0.99, anomaly=False)
    assert decision.executable is False
    assert decision.adapter == "none"


# ── 型別與 helper ───────────────────────────────────────────────────────────

def test_the_switch_must_be_a_boolean():
    for bad in ("true", 1, None, []):
        with pytest.raises(SchemaError, match="anomaly_response_authorized"):
            _policy(anomaly_response_authorized=bad)


def test_an_anomaly_decision_survives_the_authorizer_to_the_guard():
    """端到端：未知攻擊判定 → 授權器 → 可執行的守衛封鎖。

    分開測兩端不夠。政策端讓 adapter 通過、授權器卻因為某個欄位對不上而
    永遠拒絕的話，這條路等於沒接通，而且兩邊的測試都會是綠的。
    """
    from dataclasses import replace

    from firewall_lab.evidence import EvidenceAuthority, feature_sha256
    from firewall_lab.response_authorizer import (
        ResponseAuthorizer, ResponseContext,
    )

    model_hash, policy_hash = "7" * 64, "8" * 64
    guard_id = "pytest-anomaly-guard"
    guid = "a25a104e1409062029a7d1b3"

    policy = _policy(unknown_anomaly_action=REVOCABLE_ANOMALY_ACTION,
                     anomaly_response_authorized=True)
    decision = _anomaly_decision(policy, predicted_class="never_trained_class")
    assert decision.executable is True

    authority = EvidenceAuthority(b"anomaly-evidence-secret" * 2,
                                  collector_id="pytest")
    envelope = authority.issue(
        source=guid, source_kind="dds_identity", interface="lo",
        identity="unknown-intruder",
        feature_digest=feature_sha256({"packets": 7.0}),
        session_id="session-anomaly", window_id="window-anomaly",
        model_sha256=model_hash, policy_sha256=policy_hash,
        backend_id=guard_id, attribution_confidence=0.99,
        signals={"sros2": 0.95, "telemetry": 0.88},
        source_shared=False, confirmation_windows=2, decision=decision,
    )
    authorizer = ResponseAuthorizer(
        evidence_verifier=authority.verifier(),
        model_deployment_eligible=True, model_artifact_sha256=model_hash,
        policy_verified=True, policy_sha256=policy_hash,
        dds_guard_id=guard_id, dds_guard_present=True,
        dds_guard_revocation_verified=True,
    )
    response = authorizer.authorize(
        replace(decision, evidence_id=envelope.evidence_id),
        ResponseContext(requested_mode="live", source=guid,
                        source_kind="dds_identity", evidence=envelope,
                        requested_ttl_sec=30),
    )
    assert response.blockers == ()
    assert response.execute is True
    assert response.rollback_required is True
    assert response.authorization_ticket


def test_authorising_helper_requires_the_anomaly_action_explicitly():
    without = DecisionPolicy.authorising(["service_dos"])
    assert _anomaly_decision(without).executable is False

    with_anomaly = DecisionPolicy.authorising(
        ["service_dos"], anomaly_action=REVOCABLE_ANOMALY_ACTION)
    assert _anomaly_decision(with_anomaly).executable is True
