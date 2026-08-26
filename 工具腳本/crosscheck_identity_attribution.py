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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-observations", type=Path, required=True,
                        help="decode_rtps_identity.py 的輸出（GUID ↔ 實際 IP）")
    parser.add_argument("--observer-events", type=Path, required=True,
                        help="security_observer 的事件檔（認證判定）")
    parser.add_argument("--output", type=Path, required=True)
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

    # 觀測者那一半：GUID → 認證判定
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

    # 兩半共同看到的 GUID——這個交集本身就是歸因是否成立的指標。
    observed_both = set(guid_to_ips) & (authorized | rejected)

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

    blockable = [a for a, v in verdicts.items() if v["blockable"]]
    multi_ip_guids = {g: sorted(ips) for g, ips in guid_to_ips.items()
                      if len(ips) > 1}

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
        print("        常見原因：擷取介面錯、觀測者與攻擊時間沒重疊、domain 不同。")
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
