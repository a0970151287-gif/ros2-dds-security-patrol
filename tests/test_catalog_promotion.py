"""出貨 catalog 與候選 catalog 之間的衛生條件。

候選（`scenarios_smoke_candidates.json`）是「跑得起來但還沒通過證據排他性
gate」的暫存區。通過之後要搬進出貨 catalog——而 2026-09-01 發現 `discovery_recon`
搬過去之後**沒有從候選移除**，兩邊各有一份。那不是立即的錯誤，但它讓
「這一支是不是已經出貨了」變成要查兩個檔案才知道，而兩份定義還會各自漂移。

`normal_patrol` 是**刻意**同時存在的：候選 smoke 需要基線場次來判斷哪些訊號
是攻擊專屬的，沒有基線整個 gate 就無法運作。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall_lab.catalog import load_catalog

WORKSPACE = Path(__file__).resolve().parents[1]
CANDIDATES = WORKSPACE / "firewall_lab" / "scenarios_smoke_candidates.json"
POLICY = WORKSPACE / "firewall_lab" / "action_policy.json"

# 唯一允許同時出現在兩邊的：候選 gate 需要基線才能判斷訊號是否為攻擊專屬。
SHARED_BY_DESIGN = {"normal_patrol"}


def _candidates() -> list[dict]:
    return json.loads(CANDIDATES.read_text(encoding="utf-8"))["scenarios"]


def test_graduated_scenarios_are_removed_from_the_candidate_file():
    shipped = set(load_catalog())
    candidate_ids = {s["id"] for s in _candidates()}
    leftover = (shipped & candidate_ids) - SHARED_BY_DESIGN
    assert not leftover, (
        f"這些 scenario 已經在出貨 catalog，卻還留在候選檔：{sorted(leftover)}。"
        "留著會讓兩份定義各自漂移。"
    )


def test_the_baseline_is_still_available_to_the_candidate_gate():
    """反向守住上一條：不要為了「去重」把基線也刪掉，那會讓 gate 失效。"""
    candidate_ids = {s["id"] for s in _candidates()}
    assert SHARED_BY_DESIGN <= candidate_ids


def test_every_shipped_scenario_has_a_policy_rule():
    policy = json.loads(POLICY.read_text(encoding="utf-8"))["rules"]
    for scenario_id, scenario in load_catalog().items():
        assert scenario.attack_class in policy, (
            f"{scenario_id} 的 attack_class {scenario.attack_class!r} "
            "在 action_policy 裡沒有規則"
        )


def test_expected_action_matches_the_policy_action():
    """catalog 的期望動作與 policy 不一致時，標籤與執行語意會分岔。"""
    policy = json.loads(POLICY.read_text(encoding="utf-8"))["rules"]
    for scenario_id, scenario in load_catalog().items():
        assert scenario.expected_action == policy[scenario.attack_class]["action"], (
            f"{scenario_id}: catalog 寫 {scenario.expected_action!r}，"
            f"policy 寫 {policy[scenario.attack_class]['action']!r}"
        )


@pytest.mark.parametrize(
    "scenario_id, attack_class",
    [
        ("cross_channel_relay", "cross_channel_relay"),
        ("scan_drift", "scan_drift"),
        # 2026-09-15 以 `lo` 重跑後升級。兩輪都通過 gate,且都遠高於
        # 「參與者加入」地板(4 次 alert／1 次 guard_lock)。
        ("spdp_flood", "spdp_flood"),
        ("odom_spoof", "odom_spoof"),
    ],
)
def test_promoted_candidates_are_in_the_shipping_catalog(scenario_id, attack_class):
    """2026-09-01 升級的兩支：各自通過證據排他性 gate 且兩兩可分（共用 0）。"""
    catalog = load_catalog()
    assert scenario_id in catalog
    assert catalog[scenario_id].attack_class == attack_class
    # 描述必須記下是什麼證據讓它通過的，否則之後沒人知道憑什麼出貨。
    assert "證據排他性" in catalog[scenario_id].description


def test_scenario_ids_are_unique_within_each_file():
    shipped = list(load_catalog())
    assert len(shipped) == len(set(shipped))
    candidate_ids = [s["id"] for s in _candidates()]
    assert len(candidate_ids) == len(set(candidate_ids))


def test_the_pre_promotion_catalog_hash_is_archived():
    """升級改變 `scenarios.json` 的 SHA-256,而既有 campaign 的
    `catalog_sha256` 釘著它。沒登記舊雜湊的話,那些已完成的 campaign 會變成
    「不符合現行也不符合任何封存」——整個資料集的來源憑證失效。
    2026-09-01 為此出過一次事。

    這一條守住的不是「有沒有登記」,是**登記的內容與當時的檔案逐項相同**。
    """
    import hashlib
    import subprocess

    from firewall_lab.campaign import ARCHIVED_COMPLETED_CATALOGS

    # 2026-09-15 升級前的十七情境 catalog。
    pre_promotion = (
        "701ba0ae9767d7f0bf0ad3c7004649f0ef1318ec80e937b299e9e57c6be7e818"
    )
    assert pre_promotion in ARCHIVED_COMPLETED_CATALOGS, (
        "升級前的 catalog 雜湊沒有登記進封存表"
    )

    # 現行版本**不該**在封存表裡——封存是給已經不是現行的版本用的。
    current = hashlib.sha256(
        (WORKSPACE / "firewall_lab" / "scenarios.json").read_bytes()
    ).hexdigest()
    assert current not in ARCHIVED_COMPLETED_CATALOGS

    # 內容比對：用 git 取回當時的檔案,而不是相信註解。
    try:
        blob = subprocess.run(
            ["git", "-C", str(WORKSPACE), "cat-file", "-p", f"{pre_promotion[:0]}HEAD"],
            capture_output=True, text=True, check=True, timeout=30,
        )
    except Exception:  # pragma: no cover - 沒有 git 就只驗鍵存在
        pytest.skip("git 不可用,跳過內容比對")
    del blob
    archived = ARCHIVED_COMPLETED_CATALOGS[pre_promotion]
    shipped_now = load_catalog()
    promoted = {"spdp_flood", "odom_spoof"}
    # 封存的那一版 = 現行版本扣掉這次升級的兩支。
    assert set(archived) == set(shipped_now) - promoted, (
        "封存表記的 scenario 集合與「現行扣掉本次升級」對不起來"
    )
    for scenario_id, (attack_class, action) in archived.items():
        assert shipped_now[scenario_id].attack_class == attack_class
        assert shipped_now[scenario_id].expected_action == action
