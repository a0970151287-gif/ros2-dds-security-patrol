#!/usr/bin/env python3
"""把兩半證據接起來，判定哪些來源位址真的可以封鎖。

這是整條身份歸因路徑的終點。單獨一半都不夠：

| 來源 | 知道 | 不知道 |
|---|---|---|
| security observer | 這個 GUID 合不合法 | **它在哪**——認證失敗者連 discovery 事件都沒有 |
| 封包擷取 | 這個 GUID 從哪個 IP 來 | **它合不合法** |

合起來才能回答「該封鎖哪個位址」。

**判定規則**（2026-08-26 更正，見 `文件/階段0_DDS認證證據_2026-08-26.md` §四之三）：

一個位址可封鎖，當且僅當

1. 該 IP 只對應**一個** GUID——否則封鎖會波及合法 participant；
2. 該 GUID **沒有** `authenticated_identity` 記錄——它不是合法身分；
3. 該 GUID 有被觀測者**明確判定為 UNAUTHORIZED**——不是只靠「查無記錄」推論。

第 3 條是刻意加的。初版規則只要求「沒有合法記錄」，那是 absence of evidence：
觀測者漏記、啟動太晚、或根本沒跑，都會讓一個正常的 participant 看起來可封鎖。
要求一筆**正面的拒絕記錄**，才不會把「沒看到」當成「不合法」。

⚠️ 契約目前沒有承載「認證遭拒」的證據類型（已回報 Codex，C2C-040），
所以第 3 條的資料來自觀測者的事件檔而不是契約觀測。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _compact(dotted: str) -> str:
    return dotted.replace(".", "").replace(":", "").strip().lower()


def split_authentication(events: list[dict]) -> tuple[set[str], set[str]]:
    """觀測者事件 → (通過認證的 GUID, 被拒絕的 GUID)。

    非 AUTHORIZED 一律歸入 rejected：認證結果只有「明確通過」才算通過，
    任何其他狀態都不是。
    """
    authorized: set[str] = set()
    rejected: set[str] = set()
    for row in events:
        if row.get("event") != "participant_authentication":
            continue
        prefix = _compact(str(row.get("guid", "")).split("|")[0])
        if not prefix:
            continue
        if row.get("status") == "AUTHORIZED":
            authorized.add(prefix)
        else:
            rejected.add(prefix)
    return authorized, rejected


def decide_blockable(
    ip_to_guids: dict[str, set[str]],
    authorized: set[str],
    rejected: set[str],
) -> dict[str, dict]:
    """逐 IP 判定可否封鎖。三條**全部**成立才算，任一不成立就不封。

    1. 該 IP 只掛一個 GUID——否則封鎖會波及同一位址上的其他人。
    2. 該 GUID **沒有**通過認證的記錄。
    3. 該 GUID **有**觀測者明確的拒絕記錄——不可用「查無記錄」推論，因為
       觀測者靜默失效是真實會發生的事，那種情況下每個正常 participant 都會
       看起來可封鎖（C2C-041）。

    第 2 條在 2026-08-30 那批 80 輪跨主機資料裡**一次都沒有被走過**：那批
    沒有任何成功認證的遠端身分，所以擋下防守方自己位址的是第 3 條而不是第 2 條。
    這個函式被抽出來，就是為了讓第 2 條可以被測試覆蓋——它守的是自動封鎖最
    危險的失效方向：誤封一個合法節點。
    """
    verdicts: dict[str, dict] = {}
    for address, guids in sorted(ip_to_guids.items()):
        unique = len(guids) == 1
        only = next(iter(guids)) if unique else None
        is_authorized = bool(guids & authorized)
        is_rejected = bool(guids & rejected)
        blockable = bool(unique and only in rejected and only not in authorized)

        reasons: list[str] = []
        if not unique:
            reasons.append(f"{len(guids)} 個 GUID 共用此位址，封鎖會波及他人")
        if is_authorized:
            reasons.append("此位址上有通過認證的合法身分")
        if unique and not is_rejected:
            reasons.append("觀測者沒有對此 GUID 的拒絕記錄（不可用查無記錄推論）")

        verdicts[address] = {
            "guid_count": len(guids),
            "unique_guid": unique,
            "has_authorized_identity": is_authorized,
            "has_rejection_record": is_rejected,
            "blockable": blockable,
            "reasons_not_blockable": reasons,
        }
    return verdicts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-observations", type=Path, required=True,
                        help="decode_rtps_identity.py 的輸出（GUID ↔ 實際 IP）")
    parser.add_argument("--observer-events", type=Path, required=True,
                        help="security_observer 的事件檔（認證判定）")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-attacker-ip", default=None,
                        help="攻擊機回報的實際 IPv4。給了之後，若擷取檔裡"
                             "完全沒有這個位址，報告會明確標成「路徑不通」"
                             "而不是安靜地少一列。")
    args = parser.parse_args()

    if args.output.exists():
        print(f"⛔ {args.output} 已存在，拒絕覆寫", file=sys.stderr)
        return 1

    packets = _load_jsonl(args.packet_observations)
    events = _load_jsonl(args.observer_events)

    # 封包那一半：GUID ↔ 實際來源 IP
    guid_to_ips: dict[str, set[str]] = {}
    ip_to_guids: dict[str, set[str]] = {}
    for row in packets:
        prefix = row["guid_prefix"]
        address = row["source_ip"]
        guid_to_ips.setdefault(prefix, set()).add(address)
        ip_to_guids.setdefault(address, set()).add(prefix)

    authorized, rejected = split_authentication(events)

    # 兩半共同看到的 GUID——這個交集本身就是歸因是否成立的指標。
    observed_both = set(guid_to_ips) & (authorized | rejected)

    verdicts = decide_blockable(ip_to_guids, authorized, rejected)

    blockable = [a for a, v in verdicts.items() if v["blockable"]]
    multi_ip_guids = {g: sorted(ips) for g, ips in guid_to_ips.items()
                      if len(ips) > 1}

    # 擷取檔裡沒有來自攻擊機的 RTPS——這一輪沒有證據，**不可**解讀成防禦成功。
    #
    # 但這裡只陳述觀測，不斷定原因。至少三條路會走到同一個現象：
    #   1. 攻擊根本沒有執行（沒有人按下去）
    #   2. participant 起不來（攻擊端環境問題）
    #   3. 網路路徑不通（防火牆、跨網段、多播沒穿過去）
    # 前一版直接寫「封包根本沒到這台機器——網路路徑不通」，那是把第 3 條當成
    # 唯一解釋。2026-08-29 的真因是第 1 條，而那句話會害人去查防火牆——正是
    # 這個專案一再掉進去的坑：一句聽起來完全合理的失敗訊息。
    #
    # 注意這個欄位判斷的是 **RTPS 觀測**，不是原始封包：攻擊機可能有 mDNS 之類
    # 的背景流量在擷取檔裡，卻沒有任何 RTPS。命名要如實反映這件事。
    reachability = None
    if args.expect_attacker_ip:
        seen = args.expect_attacker_ip in ip_to_guids
        reachability = {
            "expected_attacker_ip": args.expect_attacker_ip,
            "attacker_rtps_present": seen,
            "verdict": "ok" if seen else "no_attacker_rtps_evidence_void",
            "possible_causes": None if seen else [
                "attack_never_executed",
                "attacker_participant_failed_to_start",
                "network_path_blocked",
            ],
            "next_step": None if seen else
                    "先向攻擊端索取 rc 與 Publishing 行數：rc 不是 124/0 就是"
                    "participant 沒起來；有 Publishing 行卻仍無 RTPS 才需要查路徑。",
            "note": None if seen else
                    "擷取檔中沒有來自攻擊機的 RTPS 封包。這一輪的證據無效，"
                    "**不可**解讀成防禦成功；原因未定，見 possible_causes。",
        }

    report = {
        "schema_version": "sros2-firewall-identity-crosscheck/v1",
        "inputs": {
            "packet_observations": str(args.packet_observations),
            "observer_events": str(args.observer_events),
        },
        "counts": {
            "packet_guids": len(guid_to_ips),
            "source_ips": len(ip_to_guids),
            "authorized_guids": len(authorized),
            "rejected_guids": len(rejected),
            "guids_seen_by_both_halves": len(observed_both),
        },
        "contract_bindings": {
            "unique_guid_to_ip_binding":
                len(guid_to_ips) - len(multi_ip_guids) == len(guid_to_ips),
            "guids_appearing_at_multiple_ips": multi_ip_guids,
        },
        "per_ip": verdicts,
        "attacker_reachability": reachability,
        "blockable_ips": sorted(blockable),
        # 這份報告本身**不授權**任何封鎖動作。它只說「證據是否支持」。
        # 實際執行仍須經過授權器，而 executable_classes 目前為空清單。
        "authorizes_action": False,
        "source_ip_attribution_verified": bool(blockable),
    }
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    print("=== 身份歸因交叉比對 ===")
    print(f"  封包看到的 GUID   : {len(guid_to_ips)}")
    print(f"  來源位址          : {len(ip_to_guids)}")
    print(f"  觀測者判定 AUTHORIZED / UNAUTHORIZED : "
          f"{len(authorized)} / {len(rejected)}")
    print(f"  **兩半都看到的 GUID** : {len(observed_both)}")
    if not observed_both:
        print("     ⚠️ 交集為零——兩半沒有對上，歸因無從談起。")
        print("        常見原因：擷取介面錯、觀測者與攻擊時間沒重疊、domain 不同、")
        print("        或 FastCDR 與 FastRTPS 不同源導致 discovery 靜默失效。")
    if reachability and not reachability["attacker_rtps_present"]:
        print()
        print(f"  ⛔ **本輪證據無效**：擷取檔中沒有來自 "
              f"{reachability['expected_attacker_ip']} 的 RTPS 封包。")
        print("     這**不可**解讀成防禦成功，但原因也還沒確定。三種可能：")
        print("       1. 攻擊根本沒有執行")
        print("       2. 攻擊端 participant 起不來")
        print("       3. 網路路徑不通")
        print("     先向攻擊端索取 rc 與 Publishing 行數再判斷：")
        print("     rc 不是 124/0 → 第 2 種；有 Publishing 行卻仍無 RTPS → 第 3 種。")
    print()
    print("  逐 IP 判定：")
    for address, verdict in verdicts.items():
        mark = "**可封鎖**" if verdict["blockable"] else "不可封鎖"
        print(f"     {address:16s} GUID {verdict['guid_count']:3d}  → {mark}")
        for reason in verdict["reasons_not_blockable"]:
            print(f"        · {reason}")
    print()
    if blockable:
        print(f"  ✅ 可封鎖位址：{', '.join(blockable)}")
        print("     （本報告不授權執行，仍須經過授權器）")
    else:
        print("  ❌ 沒有任何位址通過三條判定。")
    print(f"\n→ {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
