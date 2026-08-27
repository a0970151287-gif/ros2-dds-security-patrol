"""第二層守衛的授權→執行→撤銷鏈。

守衛的黑名單本來是一行一個 GUID 的純文字檔，任何能寫那個檔的東西都能封鎖
任何 participant。這些測試守的是補上去的那道閘：**沒有有效授權就不准寫**，
而且每一筆封鎖都必須帶著票的雜湊與到期時間。
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from firewall_lab.dds_guard_backend import (
    BLOCKLIST_SCHEMA,
    DdsGuardBackend,
    normalize_guid_prefix,
)
from firewall_lab.decision import DecisionPolicy, FirewallDecision
from firewall_lab.evidence import EvidenceAuthority, feature_sha256
from firewall_lab.response_authorizer import (
    MAX_GUARD_TTL_SEC,
    ResponseAuthorizer,
    ResponseContext,
)
from firewall_lab.schema import SchemaError

MODEL_HASH = "3" * 64
POLICY_HASH = "4" * 64
GUARD_ID = "pytest-dds-guard"
GUID = "a25a104e1409062029a7d1b3"


def _authority():
    return EvidenceAuthority(b"guard-evidence-secret" * 2, collector_id="pytest")


def _decision(**overrides):
    values = {
        "predicted_class": "identity_abuse",
        "confidence": 0.99,
        "anomaly": False,
        "action": "revocable_participant_block",
        "adapter": "dds_guard",
        "executable": True,
        "reason": "test",
        "evidence_id": "",
    }
    values.update(overrides)
    return FirewallDecision(**values)


def _envelope(authority, decision, **overrides):
    values = {
        "source": GUID,
        "source_kind": "dds_identity",
        "interface": "eth-test",
        "identity": "wrong-ca-intruder",
        "feature_digest": feature_sha256({"packets": 12.0}),
        "session_id": "session-guard",
        "window_id": "window-guard",
        "model_sha256": MODEL_HASH,
        "policy_sha256": POLICY_HASH,
        "backend_id": GUARD_ID,
        "attribution_confidence": 0.99,
        "signals": {"sros2": 0.95, "telemetry": 0.88},
        "source_shared": False,
        "confirmation_windows": 2,
        "decision": decision,
    }
    values.update(overrides)
    return authority.issue(**values)


def _guard_authorizer(authority, **overrides):
    values = {
        "evidence_verifier": authority.verifier(),
        "model_deployment_eligible": True,
        "model_artifact_sha256": MODEL_HASH,
        "policy_verified": True,
        "policy_sha256": POLICY_HASH,
        "dds_guard_id": GUARD_ID,
        "dds_guard_present": True,
        "dds_guard_revocation_verified": True,
    }
    values.update(overrides)
    return ResponseAuthorizer(**values)


def _authorize(authority=None, *, decision_overrides=None,
               envelope_overrides=None, authorizer_overrides=None,
               ttl_sec=30, requested_mode="live"):
    authority = authority or _authority()
    decision = _decision(**(decision_overrides or {}))
    envelope = _envelope(authority, decision, **(envelope_overrides or {}))
    bound = replace(decision, evidence_id=envelope.evidence_id)
    context = ResponseContext(
        requested_mode=requested_mode,
        source=envelope.source,
        source_kind=envelope.source_kind,
        evidence=envelope,
        requested_ttl_sec=ttl_sec,
    )
    authorizer = _guard_authorizer(authority, **(authorizer_overrides or {}))
    return authorizer.authorize(bound, context)


def _backend(tmp_path):
    return DdsGuardBackend(
        tmp_path / "blocklist.txt",
        tmp_path / "journal.jsonl",
        guard_id=GUARD_ID,
    )


# ── GUID 正規化 ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value", [
    GUID,
    "a2.5a.10.4e.14.09.06.20.29.a7.d1.b3",
    "A2:5A:10:4E:14:09:06:20:29:A7:D1:B3",
    "A25A104E1409062029A7D1B3",
])
def test_every_guid_spelling_normalizes_to_one_form(value):
    # 觀測者發點分格式、封包解碼器發連續十六進位。兩種寫法各封鎖一次，
    # 而撤銷只解除其中一種——這是必須在入口就消除的分歧。
    assert normalize_guid_prefix(value) == GUID


@pytest.mark.parametrize("value", ["", "zz" * 12, GUID[:-1], GUID + "ab", 123])
def test_malformed_guid_prefixes_are_rejected(value):
    with pytest.raises(SchemaError):
        normalize_guid_prefix(value)


# ── 授權器 ─────────────────────────────────────────────────────────────────

def test_fully_attested_identity_evidence_authorises_a_revocable_block():
    response = _authorize()
    assert response.execute is True
    assert response.effective_mode == "live"
    assert response.rollback_required is True
    assert response.authorization_ticket
    assert response.blockers == ()


def test_rollback_is_required_even_when_the_response_is_denied():
    # 可撤銷是這一層存在的理由。任何情況下都不可以是 False，否則執行端
    # 會拿到一份「不必撤銷」的封鎖。
    response = _authorize(authorizer_overrides={"dds_guard_present": False})
    assert response.execute is False
    assert response.rollback_required is True


@pytest.mark.parametrize("overrides,expected", [
    ({"dds_guard_present": False}, "dds guard is not attested as running"),
    ({"dds_guard_revocation_verified": False},
     "dds guard revocation path is not verified"),
    ({"model_deployment_eligible": False},
     "model is not approved for live deployment"),
    ({"policy_verified": False},
     "action policy integrity is not verified"),
    ({"dds_guard_id": "someone-elses-guard"},
     "signed evidence is not bound to the active dds guard"),
])
def test_each_missing_attestation_blocks_execution(overrides, expected):
    response = _authorize(authorizer_overrides=overrides)
    assert response.execute is False
    assert expected in response.blockers


def test_network_attribution_cannot_drive_a_participant_block():
    # 身份範圍的動作要求身份層的歸因。用 IP 歸因去封鎖一個 participant
    # 是兩種不同的東西被混用。
    response = _authorize(
        envelope_overrides={"source": "10.10.10.5", "source_kind": "network_ip"})
    assert response.execute is False
    assert "dds guard requires dds_identity attribution" in response.blockers


def test_traffic_shape_alone_cannot_justify_a_participant_block():
    response = _authorize(
        envelope_overrides={"signals": {"network": 0.99, "telemetry": 0.99}})
    assert response.execute is False
    assert "dds identity signal below 0.80" in response.blockers


def test_identity_signal_without_an_independent_corroborator_is_refused():
    response = _authorize(envelope_overrides={"signals": {"sros2": 0.99}})
    assert response.execute is False
    assert "no independent corroborating signal at 0.75" in response.blockers


def test_ttl_beyond_the_guard_bound_is_refused():
    response = _authorize(ttl_sec=MAX_GUARD_TTL_SEC + 1)
    assert response.execute is False
    assert any("ttl must not exceed" in blocker for blocker in response.blockers)


def test_single_window_or_shared_identity_fails_closed():
    for override, expected in (
        ({"confirmation_windows": 1}, "dds guard needs two signed consecutive windows"),
        ({"source_shared": True},
         "publisher identity is shared or attribution is ambiguous"),
    ):
        response = _authorize(envelope_overrides=override)
        assert response.execute is False
        assert expected in response.blockers


# ── 執行端 ─────────────────────────────────────────────────────────────────

def test_authorised_block_is_written_with_ticket_hash_and_expiry(tmp_path):
    backend = _backend(tmp_path)
    response = _authorize()
    record = backend.apply(response, guid_prefix=GUID)

    assert record["applied"] is True
    body = (tmp_path / "blocklist.txt").read_text(encoding="utf-8")
    assert BLOCKLIST_SCHEMA in body
    entries = [line.split() for line in body.splitlines()
               if line and not line.startswith("#")]
    assert len(entries) == 1
    prefix, ticket_sha, expires = entries[0]
    assert prefix == GUID
    assert len(ticket_sha) == 64
    assert float(expires) > 0


def test_the_ticket_itself_never_reaches_disk(tmp_path):
    backend = _backend(tmp_path)
    response = _authorize()
    backend.apply(response, guid_prefix=GUID)

    ticket = response.authorization_ticket
    assert ticket
    for name in ("blocklist.txt", "journal.jsonl"):
        assert ticket not in (tmp_path / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("mutation,expected", [
    ({"execute": False}, "authorization did not grant execution"),
    ({"adapter": "network_helper"}, "authorization is not for the dds guard"),
    ({"action": "temporary_block"},
     "authorization is not a revocable participant block"),
    ({"authorization_ticket": ""}, "authorization carries no ticket"),
    ({"rollback_required": False},
     "authorization does not require rollback"),
    ({"ttl_sec": MAX_GUARD_TTL_SEC + 1}, "ttl must be"),
])
def test_an_invalid_authorisation_writes_nothing(tmp_path, mutation, expected):
    backend = _backend(tmp_path)
    response = replace(_authorize(), **mutation)
    record = backend.apply(response, guid_prefix=GUID)

    assert record["applied"] is False
    assert any(expected in refusal for refusal in record["refusals"])
    # 最重要的斷言：拒絕時**沒有產生黑名單檔**。留下一個空檔案也不行，
    # 那會讓守衛以為黑名單存在而只是空的。
    assert not (tmp_path / "blocklist.txt").exists()


def test_a_denied_authorisation_from_the_real_authorizer_writes_nothing(tmp_path):
    # 不是人工竄改的 dataclass，而是授權器自己拒絕的那一種。
    backend = _backend(tmp_path)
    response = _authorize(authorizer_overrides={"dds_guard_present": False})
    record = backend.apply(response, guid_prefix=GUID)
    assert record["applied"] is False
    assert not (tmp_path / "blocklist.txt").exists()


def test_revoke_removes_the_entry_and_records_whether_it_existed(tmp_path):
    backend = _backend(tmp_path)
    backend.apply(_authorize(), guid_prefix=GUID)
    assert GUID in backend.active()

    record = backend.revoke(GUID, reason="test")
    assert record["was_active"] is True
    assert backend.active() == {}
    body = (tmp_path / "blocklist.txt").read_text(encoding="utf-8")
    assert GUID not in body

    # 撤銷一個沒被套用過的封鎖不是錯誤，但必須看得出來差別——
    # 否則「撤銷成功」會掩蓋「這個封鎖根本沒生效過」。
    again = backend.revoke(GUID)
    assert again["was_active"] is False


def test_expiry_lifts_the_block_without_an_explicit_revocation(tmp_path):
    clock = {"now": 1000.0}
    backend = DdsGuardBackend(
        tmp_path / "blocklist.txt", tmp_path / "journal.jsonl",
        guard_id=GUARD_ID, clock=lambda: clock["now"],
    )
    backend.apply(_authorize(ttl_sec=30), guid_prefix=GUID)
    assert backend.expire_due() == []

    clock["now"] = 1029.9
    assert backend.expire_due() == []
    clock["now"] = 1030.1
    assert backend.expire_due() == [GUID]
    assert backend.active() == {}


def test_writes_are_atomic_and_leave_no_partial_file(tmp_path):
    # 守衛靠 mtime 觸發重讀。直接覆寫會讓它有機會讀到半個黑名單，
    # 而半個黑名單看起來就像封鎖被解除了。
    backend = _backend(tmp_path)
    backend.apply(_authorize(), guid_prefix=GUID)
    leftovers = [p.name for p in tmp_path.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []


# ── 出貨姿態沒有被這一輪改動 ────────────────────────────────────────────────

def test_shipping_policy_still_authorises_nothing_to_execute():
    policy = DecisionPolicy.load()
    assert not policy.executable_classes
    for name in policy.rules:
        decision = policy.decide(predicted_class=name, confidence=0.99,
                                 anomaly=False)
        assert decision.executable is False


def test_no_shipped_rule_routes_to_the_dds_guard():
    # adapter 支援已經加進去了，但出貨 policy 沒有任何一條規則用它。
    # 這是刻意的：接線與啟用是兩件事。
    policy = DecisionPolicy.load()
    assert all(rule["adapter"] != "dds_guard" for rule in policy.rules.values())
