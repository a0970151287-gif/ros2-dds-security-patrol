#!/usr/bin/env python3
"""防禦策略表 — ML 辨識出攻擊類別後「做出相應防禦」的規則層。

設計原則（回應使用者構想「知道面對甚麼攻擊→做出相應防禦」）：
  ★ ML 負責「看懂是哪種攻擊」（偵測/分類）；本表負責「出手」（class→action）。
  ★ 防禦動作刻意用**規則表**而非學出來的策略：可審計、可解釋、安全
    （學出來的策略可能在沒見過的情況亂下急停/亂封）。
  ★ 預防(SROS2 Enforce) > 反應：外部未授權攻擊在認證層就被擋，根本到不了本表。
    本表是 Permissive 下、或「持合法憑證的內鬼」情境的反應層。

每個動作都對應到 repo 既有的實作，不是空話。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Defense:
    action: str          # 防禦動作
    impl: str            # 對應實作（repo 既有）
    auto: bool           # 是否自動執行（False=只告警，避免打斷攻防遊戲/誤封）


# class → 相應防禦
POLICY: dict[str, Defense] = {
    "normal": Defense(
        "放行", "—", auto=True),
    "recon": Defense(
        "告警 + 持續追蹤（不封鎖，避免打斷攻防回合）",
        "Zeek dds_monitor.zeek 偵察規則 + LINE", auto=False),
    "dos": Defense(
        "告警／限流建議 → 雙訊號授權；backend 准入前不封鎖",
        "Zeek sensor + firewall_lab response authorizer（live backend blocked）", auto=False),
    "stealth_dos": Defense(
        "信任來源速率異常告警 → SROS2 身分驗證根治",
        "Zeek check_trusted_dos() + SROS2 Enforce", auto=False),
    "inject": Defense(
        "驗章拒收（未簽章/重放/cross-channel 直接丟） + 告警",
        "monitor_node sign_alert/verify_alert（app 層，已生效）", auto=True),
    "param": Defense(
        "read_only 鎖 + F1-b runtime veto 拒絕竄改 + 告警",
        "lock_sensitive_params()（6 節點，已驗證）", auto=True),
    "spoof": Defense(
        "IP↔MAC 綁定查核 → 全偽造則靠 SROS2 已驗證身分/GUID",
        "Zeek raw_packet F7 + SROS2 Enforce", auto=True),
    "behavioral": Defense(
        "行為層投票(≥2) → 緊急停車",
        "intelligent_defense_node D1–D6", auto=True),
}

# 縱深第一道：預防（不在本反應表內，但最重要）
PREVENTION = ("SROS2 Enforce：外部未授權 participant 無 CA 憑證 → 配不上加密握手 → "
              "偽造封包根本進不了網路（DATA=0）。攻擊在到達機器人前就死，機器人無感。")


def respond(attack_class: str) -> Defense:
    """ML 預測類別 → 回傳相應防禦動作。"""
    return POLICY.get(attack_class, POLICY["recon"])  # 未知 → 保守告警追蹤


def _print_table():
    print("ML-IDS 防禦策略表（class → 相應防禦）")
    print("=" * 78)
    print(f"{'攻擊類別':<14}{'自動':<6}{'防禦動作'}")
    print("-" * 78)
    for cls, d in POLICY.items():
        auto = "✅自動" if d.auto else "🔔告警"
        print(f"{cls:<16}{auto:<7}{d.action}")
        print(f"{'':<23}↳ {d.impl}")
    print("=" * 78)
    print(f"★ 縱深第一道（預防）：{PREVENTION}")


if __name__ == "__main__":
    _print_table()
