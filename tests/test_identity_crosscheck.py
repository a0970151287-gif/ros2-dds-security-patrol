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

ATTACKER_MAC = "e8:65:38:20:23:2f"
VICTIM_MAC = "aa:bb:cc:dd:ee:ff"


def _consistent(*addresses: str) -> dict[str, dict]:
    """鏈路層綁定自洽：來源 MAC 等於防守方 ARP 解析出的 MAC。"""
    return {
        address: {
            "source_macs": [ATTACKER_MAC],
            "resolved_macs": [ATTACKER_MAC],
            "verdict": "consistent",
            "reasons_inconsistent": [],
        }
        for address in addresses
    }


def _spoofed(address: str) -> dict[str, dict]:
    """偽造來源：封包帶著攻擊者的 MAC，但該位址的持有者是別人。

    防守方的回應會依 ARP 送到 VICTIM_MAC，攻擊者收不到——所以兩者不相交。
    """
    return {
        address: {
            "source_macs": [ATTACKER_MAC],
            "resolved_macs": [VICTIM_MAC],
            "verdict": "spoofing_evidence",
            "reasons_inconsistent": ["來源 MAC 與解析出的 MAC 完全不相交"],
        }
    }


def test_the_only_blockable_case_is_unique_rejected_and_unauthenticated():
    verdicts = cross.decide_blockable(
        {"192.168.0.30": {ATTACKER}},
        authorized=set(),
        rejected={ATTACKER},
        link_layer=_consistent("192.168.0.30"),
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
        link_layer=_consistent("192.168.0.30", "192.168.0.50"),
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
        {"192.168.0.30": {packet_side_form}}, authorized, rejected,
        link_layer=_consistent("192.168.0.30"),
    )
    assert verdicts["192.168.0.30"]["blockable"] is True


def test_the_parser_reads_a_real_authorized_record():
    """Condition 2's plumbing, against live evidence rather than a fixture.

    The dual-observer run of 2026-08-26 (C2C-040) is the only place in this
    project where the observer has ever emitted AUTHORIZED: two legitimate
    observers each recorded the other as authenticated while both refused the
    wrong-CA participant. This pins that the parser still classifies those real
    records correctly, so a future change cannot quietly stop recognising a
    legitimate identity -- which would turn every legitimate node blockable.
    """
    import json

    base = ROOT / "文件" / "階段0_DDS認證證據_2026-08-26" / "雙觀測者"
    for name in ("obsA_events.jsonl", "obsB_events.jsonl"):
        path = base / name
        assert path.exists(), f"live evidence missing: {path}"
        events = [json.loads(line) for line in
                  path.read_text(encoding="utf-8").splitlines() if line.strip()]
        authorized, rejected = cross.split_authentication(events)
        assert len(authorized) == 1, (name, authorized)
        assert rejected, (name, "the wrong-CA participant should be refused")
        assert not (authorized & rejected), (name, "a GUID cannot be both")


def test_an_empty_observer_half_blocks_nothing():
    """No observer events at all must yield no blockable address.

    A capture alone can bind GUIDs to addresses; that is not attribution, and it
    is exactly the state a silently dead observer produces.
    """
    verdicts = cross.decide_blockable(
        {"192.168.0.30": {ATTACKER}}, authorized=set(), rejected=set()
    )
    assert verdicts["192.168.0.30"]["blockable"] is False


# --------------------------------------------------------------------------
# 第四條：鏈路層綁定（2026-08-31 新增）
# --------------------------------------------------------------------------


def test_a_spoofed_source_address_is_never_blockable():
    """前三條擋不住的那一種攻擊。

    同一個 L2 網段上的攻擊者以**受害者的 IP** 為來源送 RTPS：握手必然失敗
    （防守方的回應依 ARP 送到受害者那裡），觀測者記下 UNAUTHORIZED，封包層
    把 GUID 綁到受害者的 IP。前三條全部成立——系統會宣告一個**無辜主機**
    可封鎖，而那是自動封鎖最糟的失效方向。

    2026-08-30 那批 79／80 的陰性對照測不到它：對照組是防守方自己，
    不是被偽造的第三方。
    """
    verdicts = cross.decide_blockable(
        {"192.168.0.77": {ATTACKER}},
        authorized=set(),
        rejected={ATTACKER},
        link_layer=_spoofed("192.168.0.77"),
    )

    verdict = verdicts["192.168.0.77"]
    # 前三條全部成立⋯⋯
    assert verdict["unique_guid"] is True
    assert verdict["has_rejection_record"] is True
    assert verdict["has_authorized_identity"] is False
    # ⋯⋯但第四條擋下來了。
    assert verdict["blockable"] is False
    assert verdict["link_layer_verdict"] == "spoofing_evidence"
    assert any("偽造" in r for r in verdict["reasons_not_blockable"])


def test_missing_link_layer_evidence_is_not_treated_as_verified():
    """沒有證據是「無法驗證」，不是「驗證通過」。

    這是整個專案反覆踩到的同一種錯：查無記錄被當成量測到零。
    """
    verdicts = cross.decide_blockable(
        {"192.168.0.30": {ATTACKER}}, authorized=set(), rejected={ATTACKER}
    )

    verdict = verdicts["192.168.0.30"]
    assert verdict["blockable"] is False
    assert verdict["link_layer_verdict"] == "no_evidence"
    assert any("偽造" in r for r in verdict["reasons_not_blockable"])


def test_an_ambiguous_link_layer_binding_is_not_enough():
    """同一個位址出現多個來源 MAC 時，分不出是多介面還是偽造。

    實測防守方自己的位址就會這樣：WSL mirrored 讓實體與虛擬 MAC 同時出現。
    分不出來就不可封鎖——但理由要如實說是「分不出來」，不是斷定偽造。
    """
    verdicts = cross.decide_blockable(
        {"192.168.0.30": {ATTACKER}},
        authorized=set(),
        rejected={ATTACKER},
        link_layer={
            "192.168.0.30": {
                "source_macs": [ATTACKER_MAC, VICTIM_MAC],
                "resolved_macs": [ATTACKER_MAC],
                "verdict": "unverifiable",
                "reasons_inconsistent": ["此位址有 2 個來源 MAC、1 個解析 MAC"],
            }
        },
    )

    verdict = verdicts["192.168.0.30"]
    assert verdict["blockable"] is False
    assert verdict["link_layer_verdict"] == "unverifiable"
    assert any("2 個來源 MAC" in r for r in verdict["reasons_not_blockable"])


def test_the_link_layer_check_alone_cannot_authorise_a_block():
    """第四條是必要條件不是充分條件——其他三條仍然要成立。"""
    verdicts = cross.decide_blockable(
        {"192.168.0.50": {LEGIT}},
        authorized={LEGIT},
        rejected=set(),
        link_layer=_consistent("192.168.0.50"),
    )

    assert verdicts["192.168.0.50"]["link_layer_verdict"] == "consistent"
    assert verdicts["192.168.0.50"]["blockable"] is False


# --------------------------------------------------------------------------
# 鏈路層檢查器本身
# --------------------------------------------------------------------------


def _load_link_layer():
    path = ROOT / "工具腳本" / "check_link_layer_binding.py"
    spec = importlib.util.spec_from_file_location("check_link_layer", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


llb = _load_link_layer()


def test_binding_is_consistent_when_the_sender_owns_the_address():
    """正常情況：從 X 收到的來源 MAC 就是送往 X 時解析出的 MAC。"""
    rows = [
        (ATTACKER_MAC, "28:92:00:62:4e:bd", "192.168.0.30", "192.168.0.129"),
        ("28:92:00:62:4e:bd", ATTACKER_MAC, "192.168.0.129", "192.168.0.30"),
    ]

    bindings = llb.build_bindings(rows)

    assert bindings["192.168.0.30"]["verdict"] == "consistent"
    assert bindings["192.168.0.30"]["bidirectional"] is True


def test_binding_detects_a_spoofed_source_address():
    """攻擊者用自己的 MAC 送出、卻宣稱是受害者的 IP。

    防守方的回應會依 ARP 送到受害者真正的 MAC，所以兩者不相交——
    這是偽造的確證，不只是可疑。
    """
    rows = [
        # 收到：宣稱來自受害者，但框上是攻擊者的 MAC。
        (ATTACKER_MAC, "28:92:00:62:4e:bd", "192.168.0.77", "192.168.0.129"),
        # 送出：防守方解析 .77 得到受害者真正的 MAC。
        ("28:92:00:62:4e:bd", VICTIM_MAC, "192.168.0.129", "192.168.0.77"),
    ]

    bindings = llb.build_bindings(rows)

    assert bindings["192.168.0.77"]["verdict"] == "spoofing_evidence"
    assert any("不相交" in r
               for r in bindings["192.168.0.77"]["reasons_inconsistent"])


def test_one_way_traffic_cannot_be_verified():
    """沒有送往該位址的單播流量就取不到 ARP 解析結果。

    這是「無法驗證」，不是「驗證通過」——一個不存在的受害者位址正好長這樣。
    """
    rows = [
        (ATTACKER_MAC, "28:92:00:62:4e:bd", "192.168.0.99", "192.168.0.129"),
    ]

    bindings = llb.build_bindings(rows)

    assert bindings["192.168.0.99"]["verdict"] == "unverifiable"
    assert bindings["192.168.0.99"]["bidirectional"] is False


def test_multicast_destination_macs_are_not_treated_as_arp_results():
    """多播的目的 MAC 是從 IP 算出來的、不經 ARP，拿它當解析結果會出錯。"""
    rows = [
        (ATTACKER_MAC, "01:00:5e:7f:00:01", "192.168.0.30", "239.255.0.1"),
        (ATTACKER_MAC, "ff:ff:ff:ff:ff:ff", "192.168.0.30", "192.168.0.255"),
    ]

    bindings = llb.build_bindings(rows)

    # 廣播位址的目的 MAC 沒有被收進 resolved_macs。
    assert bindings.get("192.168.0.255", {}).get("resolved_macs", []) == []


def test_two_source_macs_on_one_address_is_ambiguous_not_spoofing():
    """WSL mirrored 會讓同一個 IP 同時出現實體與虛擬 MAC。

    判定（不可封鎖）一樣，但理由要說是分不出來，不能斷定偽造——
    2026-08-31 實測防守方自己的位址就是這樣。
    """
    rows = [
        ("00:15:5d:25:b1:21", VICTIM_MAC, "192.168.0.129", "192.168.0.30"),
        ("28:92:00:62:4e:bd", VICTIM_MAC, "192.168.0.129", "192.168.0.30"),
        (VICTIM_MAC, "28:92:00:62:4e:bd", "192.168.0.30", "192.168.0.129"),
    ]

    bindings = llb.build_bindings(rows)

    verdict = bindings["192.168.0.129"]
    assert verdict["verdict"] == "unverifiable"
    assert not any("不相交" in r for r in verdict["reasons_inconsistent"])
