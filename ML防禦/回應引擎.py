#!/usr/bin/env python3
"""回應引擎 — 偵測後「配合對應的防禦」自動出手。

把 ML/規則的偵測結果，經安全閘後，**真正執行**策略表對應的防禦動作。
這是「腦（偵測）→ 手（出手）」的橋；牆（預防）仍是 SROS2 Enforce。

★ 安全閘（不灌水、不亂封）：
  1) confidence 門檻：信心不足 → 只觀察，不出手（避免 FP 誤封；PoC precision 0.77）。
  2) 紅隊白名單：攻防遊戲中不硬封 PEER(10.10.10.1)，除非明確開 demo 模式。
  3) per-(source,action) 速率限制：同一招短時間不重複出手。
  4) **預設 dry-run**：只印「會下什麼指令」，不真的執行；要 live 才真出手。

★ 動作分三種真實性：
  [已生效] inject/param —— app 層 HMAC 驗章 / lock_sensitive_params 早就在擋，引擎只記錄。
  [可執行] dos —— 呼叫既有 dos_firewall.sh/block_source.sh（opt-in、自動解封）。
  [可執行] behavioral —— 對 /cmd_vel 發 0 速度急停（live 需在 ROS 環境跑 ros2）。
  [建議]   spoof/stealth_dos —— 告警 + 指向 SROS2 Enforce 根治（網路層擋不死身分偽造）。
"""
from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass, field

from 防禦策略 import POLICY, respond

REPO = "/home/jesse/ros2_ws"


def hms() -> str:
    return time.strftime("%H:%M:%S")


@dataclass
class Detection:
    attack_class: str           # ML/規則判定的攻擊類別
    source: str = "?"           # 來源（IP / 節點）
    confidence: float = 1.0     # 偵測信心 0~1
    evidence: str = ""          # 佐證（特徵/封包摘要）
    ts: float = field(default_factory=time.time)


@dataclass
class ResponseRecord:
    detection: Detection
    action: str                 # 實際採取的動作
    executed: bool              # 是否真的執行（dry-run=False）
    command: str                # 對應的具體指令（可審計）
    note: str = ""


class ResponseEngine:
    def __init__(self, mode: str = "dry_run", confidence_min: float = 0.70,
                 game_allowlist=frozenset({"10.10.10.1"}),
                 enable_firewall: bool = False, action_cooldown: float = 30.0):
        assert mode in ("dry_run", "live")
        self.mode = mode
        self.confidence_min = confidence_min
        self.game_allowlist = set(game_allowlist)
        self.enable_firewall = enable_firewall      # demo 時才 True，才會真封來源
        self.action_cooldown = action_cooldown
        self._last_action: dict[tuple, float] = {}
        self.log: list[ResponseRecord] = []

    # ── 對外主入口 ────────────────────────────────────────────────
    def respond(self, det: Detection) -> ResponseRecord:
        d = POLICY.get(det.attack_class, POLICY["recon"])

        # 閘 1：normal 直接放行
        if det.attack_class == "normal":
            return self._record(det, "放行", False, "—", "正常流量")

        # 閘 2：信心不足 → 只觀察
        if det.confidence < self.confidence_min:
            return self._record(det, "觀察（信心不足）", False, "—",
                                 f"confidence {det.confidence:.2f} < {self.confidence_min}")

        # 閘 3：速率限制
        key = (det.source, det.attack_class)
        now = time.monotonic()
        if now - self._last_action.get(key, -1e9) < self.action_cooldown:
            return self._record(det, "略過（cooldown）", False, "—",
                                 "同來源同攻擊 cooldown 中")
        self._last_action[key] = now

        # 派工到對應 executor
        executor = {
            "recon": self._recon, "dos": self._dos, "stealth_dos": self._stealth_dos,
            "inject": self._inject, "param": self._param, "spoof": self._spoof,
            "behavioral": self._behavioral,
        }.get(det.attack_class, self._recon)
        return executor(det)

    # ── 各類別 executor（回傳 ResponseRecord）────────────────────
    def _recon(self, det):
        # 遊戲安全：偵察只告警追蹤，不封（免打斷攻防回合）
        return self._record(det, "告警 + 持續追蹤（不封鎖）", self._do_alert(det),
                            "log+LINE", "recon 不自動封，避免打斷攻防")

    def _dos(self, det):
        # 想真封但要過「紅隊白名單 + demo 開關」兩道閘
        cmd = f"sudo bash {REPO}/Zeek監控/block_source.sh {det.source} 300"
        if det.source in self.game_allowlist and not self.enable_firewall:
            self._do_alert(det)
            return self._record(det, "限流告警（遊戲安全：不硬封紅隊）", False, cmd,
                                "PEER 在白名單且未開 demo → 不執行封鎖")
        if not self.enable_firewall:
            self._do_alert(det)
            return self._record(det, "DoS 告警（封鎖預設關）", False, cmd,
                                "enable_firewall=False → 只告警")
        return self._record(det, "封鎖洪水來源 300s（自動解封）", self._run(cmd), cmd,
                            "demo 模式：真封")

    def _stealth_dos(self, det):
        self._do_alert(det)
        return self._record(det, "信任來源速率異常告警 → 指向 SROS2", False,
                            "—", "網路層擋不死身分偽造，根治＝Enforce")

    def _inject(self, det):
        # app 層 HMAC 驗章「早就在擋」——引擎記錄 + 告警，不需另外動作
        return self._record(det, "已由 app 層驗章拒收（sign/verify_alert）",
                            self._do_alert(det), "—", "未簽章/重放/cross-channel 自動丟")

    def _param(self, det):
        return self._record(det, "已由 read_only + F1-b veto 拒絕竄改",
                            self._do_alert(det), "—", "lock_sensitive_params 早就在擋")

    def _spoof(self, det):
        self._do_alert(det)
        return self._record(det, "IP↔MAC 查核告警 → 全偽造指向 SROS2 身分", False,
                            "—", "raw_packet 抓半偽造；全偽造根治＝Enforce")

    def _behavioral(self, det):
        # 真正的「擋」：對 /cmd_vel 發 0 速度急停（live 需 ROS 環境）
        cmd = ("ros2 topic pub --once /cmd_vel geometry_msgs/msg/TwistStamped "
               "'{twist: {linear: {x: 0.0}, angular: {z: 0.0}}}'")
        executed = self._run(cmd) if self.mode == "live" else False
        return self._record(det, "緊急停車（/cmd_vel 歸零）", executed, cmd,
                            "行為層劫持 → 立即停車；部署時走 IDS 簽章 alert 鏈")

    # ── 底層 ──────────────────────────────────────────────────────
    def _do_alert(self, det) -> bool:
        # 告警一律執行（不危險）
        print(f"  [{hms()}] 🔔 ALERT {det.attack_class} 來源={det.source} "
              f"信心={det.confidence:.2f} {det.evidence}")
        return True

    def _run(self, cmd: str) -> bool:
        if self.mode != "live":
            return False
        try:
            subprocess.run(shlex.split(cmd), timeout=10, check=False)
            return True
        except Exception as e:  # noqa
            print(f"  ⚠️ 執行失敗：{e}")
            return False

    def _record(self, det, action, executed, command, note) -> ResponseRecord:
        tag = "✅執行" if executed else ("🟡dry-run" if self.mode == "dry_run" else "⏭️未動作")
        print(f"[{hms()}] {tag} | {det.attack_class:<11}→ {action}")
        if command not in ("—", ""):
            print(f"            指令: {command}")
        if note:
            print(f"            註: {note}")
        rec = ResponseRecord(det, action, executed, command, note)
        self.log.append(rec)
        return rec


def _demo():
    print("=" * 70)
    print("回應引擎 demo（dry-run）：每類偵測 → 對應防禦出手")
    print("=" * 70)
    eng = ResponseEngine(mode="dry_run", confidence_min=0.70)
    samples = [
        Detection("normal", "10.10.10.2", 0.99),
        Detection("recon", "10.10.10.1", 0.95, "uniq_ports=12"),
        Detection("dos", "10.10.10.1", 0.97, "spdp 53/s"),
        Detection("inject", "10.10.10.1", 0.93, "writer_seq 異常+payload"),
        Detection("param", "10.10.10.1", 0.88, "set_parameters use_sim_time"),
        Detection("spoof", "10.10.10.250", 0.91, "IP↔MAC 不符"),
        Detection("behavioral", "patrol_node?", 0.96, "cmd_lin=0.5 超物理"),
        Detection("inject", "10.10.10.1", 0.55, "低信心樣本"),   # 測信心閘
    ]
    for d in samples:
        eng.respond(d)
    print("\n安全閘示範：dos 對紅隊 10.10.10.1（白名單）→ 遊戲安全不硬封")
    print(f"\n共處理 {len(eng.log)} 筆，實際執行 {sum(r.executed for r in eng.log)} 個動作"
          f"（dry-run 下只有告警會執行）")


if __name__ == "__main__":
    _demo()
