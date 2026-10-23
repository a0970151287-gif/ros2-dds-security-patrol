#!/usr/bin/env python3
"""用合成觀測驗證身份歸因管線，並示範同機為什麼過不了驗收。

⚠️ **這支產生的是合成資料，不是證據。** 依專案規則 4，合成資料不得寫成
live pass；輸出的 artifact 一律帶 `synthetic: true` 與 `evidence: false`。

**為什麼需要它。** P2（Codex）已經把契約、驗證器與稽核工具寫完了，但收集器
與解碼器還沒寫，第二台機器也還沒有。在投入硬體之前，先用合成觀測回答兩件事：

1. **我打算讓收集器產出的格式，P2 的驗證器會不會接受？** 如果不會，
   規格就寫錯了，現在發現比收完資料才發現便宜得多。
2. **同機資料到底卡在哪一條驗收條件？** 與其用文字宣稱「同機不可能」，
   不如讓 Codex 自己的特徵計算把它算出來。

跑法：

    python3 工具腳本/dryrun_identity_pipeline.py

不需要參數、不碰 dataset、不需要 live runtime。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.identity_attribution import (  # noqa: E402
    IDENTITY_FEATURES,
    build_identity_window_features,
    validate_identity_observation,
)

WINDOW_SEC = 8.0
NS = 1_000_000_000


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _guid(seed: str) -> str:
    """12 bytes → 24 個小寫十六進位字元，與 `_GUID_PREFIX_RE` 相符。"""

    return _digest(seed)[:24]


def _entity(seed: str) -> str:
    return _digest(seed)[:8]


def _observation(index: int, *, session: str, mode: str, source_ip: str,
                 guid_prefix: str, kind: str, entity_id=None, topic=None,
                 subject=None, permission_state="unknown") -> dict:
    """組一筆觀測。欄位必須剛好 19 個，多一個少一個都會被拒。"""

    return {
        "schema_version": "sros2-firewall-rtps-identity-observation/v1",
        "session_id": session,
        "sequence": index,
        "ts_unix_ns": 1_787_000_000 * NS + index * NS,
        "window": index // 4,
        "collector_id": "dryrun-collector",
        "capture_sha256": _digest(f"capture:{session}"),
        "decoder_sha256": _digest("decoder:dryrun"),
        "policy_sha256": _digest("policy:dryrun"),
        "security_mode": mode,
        "source_ip": source_ip,
        "interface": "eth0",
        "guid_prefix": guid_prefix,
        "entity_id": entity_id,
        "topic": topic,
        "evidence_kind": kind,
        "identity_subject_sha256": subject,
        "permission_state": permission_state,
    }


def _scenario(name: str, participants) -> list[dict]:
    """造一場：`participants` 是 (參與者名稱, 來源位址) 的清單。

    刻意讓多個 participant 共用同一個位址——那才是真實情形。防守方那台
    本來就會同時跑 monitor、IDS、Gazebo，所以**即使跨主機，防守方的 IP
    仍然是「多身份共用」**。

    這帶出契約真正的意思：`ip_not_shared_by_multiple_identities` 必須是
    **逐 IP** 判定，不是全域。一個只掛著單一 GUID 且有認證綁定的 IP 可以封鎖；
    被多個身份共用的 IP 不可以。同機的問題是**每一個 IP 都屬於後者**。
    """

    rows: list[dict] = []
    index = 0
    for participant, address, authenticated in participants:
        guid = _guid(f"{name}:{participant}")
        rows.append(_observation(
            index, session=name, mode="enforce", source_ip=address,
            guid_prefix=guid, kind="spdp_locator"))
        index += 1
        rows.append(_observation(
            index, session=name, mode="enforce", source_ip=address,
            guid_prefix=guid, kind="sedp_endpoint",
            entity_id=_entity(f"{participant}:writer"), topic="rt/cmd_vel",
            permission_state="allow"))
        index += 1
        if authenticated:
            # 只有 DDS 安全層能產生這一種——封包抓不到。
            rows.append(_observation(
                index, session=name, mode="enforce", source_ip=address,
                guid_prefix=guid, kind="authenticated_identity",
                subject=_digest(f"CN={participant}"),
                permission_state="allow"))
            index += 1
    return rows


def _blockable(rows: list[dict]) -> dict:
    """逐 IP 判斷哪些位址可以封鎖。

    ⚠️ **2026-08-26 更正。** 本函式初版要求「該 GUID 有 authenticated_identity
    記錄」才可封鎖。那是錯的：實測（`文件/階段0_DDS認證證據_2026-08-26.md`）
    顯示**攻擊者永遠不會有那筆記錄**——它的認證失敗了，所以沒有任何經過驗證
    的 subject。要求它有，規則就永遠封鎖不了任何人。

    正確的規則是反過來的：

    1. 該 IP 只對應一個 GUID（否則封鎖會波及合法 participant），且
    2. 該 GUID **沒有** authenticated_identity 記錄（不是合法身分），且
    3. 該 GUID 有被觀測到（不是憑空推論它存在）。

    第 3 條目前只能用 `spdp_locator` 承載，而契約自己說那是可偽造的。
    真正需要的是一種「認證遭拒」的證據類型，契約目前沒有——已回報 Codex。
    """

    by_ip: dict[str, set[str]] = {}
    authenticated: set[str] = set()
    for row in rows:
        by_ip.setdefault(row["source_ip"], set()).add(row["guid_prefix"])
        if row["evidence_kind"] == "authenticated_identity":
            authenticated.add(row["guid_prefix"])
    result = {}
    for address, guids in sorted(by_ip.items()):
        unique = len(guids) == 1
        legitimate = bool(guids & authenticated)
        result[address] = {
            "guids": len(guids),
            "unique_guid": unique,
            "has_authenticated_identity": legitimate,
            # 唯一且非合法才可封鎖；合法的不封（不該封自己人）。
            "blockable": unique and not legitimate,
        }
    return result


def _summarise(rows: list[dict]) -> dict:
    for row in rows:
        validate_identity_observation(row)
    windows = build_identity_window_features(rows, window_sec=WINDOW_SEC)
    # 特徵是攤平在視窗列上的，不是巢狀在 "features" 底下。
    merged = {feature: max(window[feature] for window in windows)
              for feature in IDENTITY_FEATURES}
    addresses = {row["source_ip"] for row in rows}
    guids = {row["guid_prefix"] for row in rows}
    return {
        "observations": len(rows),
        "windows": len(windows),
        "distinct_source_ips": len(addresses),
        "distinct_guids": len(guids),
        "features": merged,
        "per_ip": _blockable(rows),
        "blockable_ips": sorted(
            a for a, v in _blockable(rows).items() if v["blockable"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    # 防守方那台同時跑 monitor／IDS／Gazebo——三個 participant。
    # 防守方那台同時跑 monitor／IDS／Gazebo——三個 participant，全部通過認證。
    defender = [("monitor", True), ("ids", True), ("gazebo", True)]
    cases = {
        # 現有 1,101 場的狀態：全部擠在 127.0.0.1，且無安全層記錄。
        "same_host_no_security_log": _scenario(
            "dryrun-same-host",
            [(n, "127.0.0.1", False) for n, _ in defender]
            + [("attacker", "127.0.0.1", False)]),
        # 同機但安全層記錄可得（2026-08-26 已證實可行）。
        "same_host_with_security_log": _scenario(
            "dryrun-same-host-auth",
            [(n, "127.0.0.1", a) for n, a in defender]
            + [("attacker", "127.0.0.1", False)]),
        # 目標狀態：防守方三個 participant 在一台，攻擊者單獨一台且認證失敗。
        "cross_host_with_security_log": _scenario(
            "dryrun-cross-host",
            [(n, "10.42.0.11", a) for n, a in defender]
            + [("attacker", "10.42.0.12", False)]),
    }

    report = {}
    for name, rows in cases.items():
        report[name] = _summarise(rows)

    print("=== 合成觀測通過 P2 驗證器（格式正確性驗證）===")
    for name, summary in report.items():
        print(f"  {name:32s} 觀測 {summary['observations']:2d}　"
              f"IP {summary['distinct_source_ips']}　"
              f"GUID {summary['distinct_guids']}")

    print()
    print("=== 三條與驗收直接相關的特徵 ===")
    header = "%-32s %14s %14s %16s" % (
        "情境", "ip_multi_guid", "guid_multi_ip", "authenticated")
    print(header)
    for name, summary in report.items():
        features = summary["features"]
        print("%-32s %14.4f %14.4f %16.4f" % (
            name,
            features["rtps_ip_multi_guid_ratio"],
            features["rtps_guid_multi_ip_ratio"],
            features["rtps_authenticated_binding_ratio"]))

    print()
    print("=== 逐 IP：哪些位址可以封鎖 ===")
    for name, summary in report.items():
        print(f"  {name}")
        for address, info in summary["per_ip"].items():
            mark = "可封鎖" if info["blockable"] else "不可封鎖"
            print(f"     {address:14s} GUID {info['guids']}　"
                  f"唯一={info['unique_guid']}　"
                  f"合法身分={info['has_authenticated_identity']}　→ {mark}")

    print()
    print("讀法：")
    print("  ip_multi_guid > 0 代表一個 IP 被多個 GUID 共用 →")
    print("  契約的 `ip_not_shared_by_multiple_identities` 不成立，該 IP 不可封鎖。")
    print("  authenticated = 0 代表完全沒有加密綁定 →")
    print("  `authenticated_identity_subject_binding` 不成立。")

    if args.output:
        args.output.write_text(
            json.dumps(
                {
                    "schema_version": "sros2-firewall-identity-dryrun/v1",
                    # 這兩個旗標是刻意放的：任何人拿到這份檔案都要立刻知道
                    # 它不是證據。
                    "synthetic": True,
                    "evidence": False,
                    "purpose": "pipeline shape validation before hardware exists",
                    "window_sec": WINDOW_SEC,
                    "cases": report,
                },
                ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(f"\n→ {args.output}（synthetic=true，不是證據）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
