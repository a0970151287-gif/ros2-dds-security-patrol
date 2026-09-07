#!/usr/bin/env python3
"""回應引擎 — 偵測後「配合對應的防禦」自動出手。

把 ML/規則的偵測結果，經安全閘後，**真正執行**策略表對應的防禦動作。
這是「腦（偵測）→ 手（出手）」的橋；牆（預防）仍是 SROS2 Enforce。

★ 安全閘（不灌水、不亂封）：
  1) confidence 門檻：信心不足 → 只觀察，不出手（避免 FP 誤封）。
  2) 紅隊白名單：攻防遊戲中不硬封 PEER(10.10.10.1)，除非明確開 demo 模式。
  3) per-(source,action) 速率限制：同一招短時間不重複出手。
  4) **預設 dry-run**：只印「會下什麼指令」，不真的執行；要 live 才真出手。

★ 動作分三種真實性：
  [已生效] inject/param —— app 層 HMAC 驗章 / lock_sensitive_params 早就在擋，引擎只記錄。
  [可執行] dos —— 只呼叫 root-owned 固定 helper（opt-in、自動解封）。
  [已生效] behavioral —— 由 IDS 簽章 alert → velocity_guard 單一仲裁急停。
  [建議]   spoof/stealth_dos —— 告警 + 指向 SROS2 Enforce 根治（網路層擋不死身分偽造）。
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import shlex
import stat
import subprocess
import time
from collections import OrderedDict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from firewall_lab.decision import FirewallDecision
from firewall_lab.evidence import EvidenceEnvelope
from firewall_lab.response_authorizer import ResponseAuthorizer, ResponseContext
from firewall_lab.schema import SchemaError

BLOCK_SOURCE = Path(
    os.environ.get(
        "DDS_BLOCK_HELPER",
        "/usr/local/libexec/dds-monitor/block-source",
    )
).resolve()


def hms() -> str:
    return time.strftime("%H:%M:%S")


@dataclass
class Detection:
    attack_class: str           # ML/規則判定的攻擊類別
    source: str = "?"           # 來源（IP / 節點）
    confidence: float = 1.0     # 偵測信心 0~1
    evidence: str = ""          # 佐證（特徵/封包摘要）
    ts: float = field(default_factory=time.time)
    # 只有受信任 collector 簽發的 envelope 能授權動態處置；上游不得再
    # 透過一串自我宣告的 bool / confidence 欄位取得封鎖權限。
    evidence_envelope: EvidenceEnvelope | None = None


@dataclass
class ResponseRecord:
    detection: Detection
    action: str                 # 實際採取的動作
    executed: bool              # 是否真的執行（dry-run=False）
    command: str                # 對應的具體指令（可審計）
    note: str = ""
    evidence_id: str = ""
    authorization_ticket_sha256: str = ""


class ResponseEngine:
    def __init__(self, mode: str = "dry_run", confidence_min: float = 0.70,
                 game_allowlist=frozenset({"10.10.10.1"}),
                 protected_sources=frozenset({"10.10.10.2", "127.0.0.1"}),
                 enable_firewall: bool = False, action_cooldown: float = 30.0,
                 max_cooldown_entries: int = 4096,
                 max_log_entries: int = 4096,
                 firewall_actions_per_minute: int = 10,
                 max_active_blocks: int = 64,
                 response_authorizer: ResponseAuthorizer | None = None):
        if mode not in ("dry_run", "live"):
            raise ValueError("mode 必須是 'dry_run' 或 'live'")
        if (
            isinstance(confidence_min, bool)
            or not isinstance(confidence_min, (int, float))
            or not math.isfinite(confidence_min)
            or not 0.0 <= confidence_min <= 1.0
        ):
            raise ValueError("confidence_min 必須是 0..1 的有限數值")
        if (
            isinstance(action_cooldown, bool)
            or not isinstance(action_cooldown, (int, float))
            or not math.isfinite(action_cooldown)
            or action_cooldown < 0.0
        ):
            raise ValueError("action_cooldown 必須是非負有限數值")
        if not isinstance(enable_firewall, bool):
            raise ValueError("enable_firewall 必須是 bool；字串 'false' 不可當成關閉")
        for name, value in (
            ("max_cooldown_entries", max_cooldown_entries),
            ("max_log_entries", max_log_entries),
            ("firewall_actions_per_minute", firewall_actions_per_minute),
            ("max_active_blocks", max_active_blocks),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} 必須是正整數")
        self.mode = mode
        self.confidence_min = float(confidence_min)
        self.game_allowlist = set(game_allowlist)
        self.protected_sources = set(protected_sources)
        self.enable_firewall = enable_firewall      # demo 時才 True，才會真封來源
        self.action_cooldown = float(action_cooldown)
        self.max_cooldown_entries = max_cooldown_entries
        self.max_log_entries = max_log_entries
        self.firewall_actions_per_minute = firewall_actions_per_minute
        self.max_active_blocks = max_active_blocks
        self._last_action: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._firewall_actions: deque[float] = deque()
        self._blocked_until: OrderedDict[str, float] = OrderedDict()
        self.log: list[ResponseRecord] = []
        if response_authorizer is not None and not isinstance(
            response_authorizer, ResponseAuthorizer
        ):
            raise ValueError("response_authorizer 類型無效")
        # 預設 authorizer 沒有 evidence authority、owned scope、合格模型或
        # timeout backend，因此即使 enable_firewall=True 也必定 fail closed。
        self._authorizer = response_authorizer or ResponseAuthorizer(
            protected_sources=self.protected_sources,
        )

    # ── 對外主入口 ────────────────────────────────────────────────
    def respond(self, det: Detection) -> ResponseRecord:
        if (
            not isinstance(det.attack_class, str)
            or not det.attack_class
            or len(det.attack_class) > 64
        ):
            return self._record(det, "觀察（無效攻擊類別）", False, "—",
                                "attack_class 必須是 1..64 字元字串")

        # 閘 1：信心必須是可信的有限機率。NaN 比較永遠為 False，
        # 若只寫 `confidence < threshold`，NaN 反而會繞過安全閘。
        if (
            not isinstance(det.confidence, (int, float))
            or isinstance(det.confidence, bool)
            or not math.isfinite(det.confidence)
            or not 0.0 <= det.confidence <= 1.0
        ):
            return self._record(det, "觀察（無效信心值）", False, "—",
                                "confidence 必須是 0..1 的有限數值")

        # 閘 2：normal 僅在 detection 結構有效時放行。
        if det.attack_class == "normal":
            return self._record(det, "放行", False, "—", "正常流量")

        # 閘 3：信心不足 → 只觀察
        if det.confidence < self.confidence_min:
            return self._record(det, "觀察（信心不足）", False, "—",
                                 f"confidence {det.confidence:.2f} < {self.confidence_min}")

        # 閘 4：速率限制。來源轉成字串，避免不可信輸入以 list 等
        # unhashable 值讓整個回應程序崩潰。
        key = (self._safe_text(det.source, 128), det.attack_class)
        now = time.monotonic()
        self._purge_cooldowns(now)
        previous = self._last_action.get(key)
        if previous is not None and now - previous < self.action_cooldown:
            return self._record(det, "略過（cooldown）", False, "—",
                                 "同來源同攻擊 cooldown 中")
        self._last_action[key] = now
        self._last_action.move_to_end(key)
        while len(self._last_action) > self.max_cooldown_entries:
            self._last_action.popitem(last=False)

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
        # 想真封但要過「合法 IPv4 + 自身保護 + 紅隊白名單 + demo 開關」安全閘。
        # subprocess 一律吃 argv，不把偵測來源拼進 shell command。
        try:
            source_ip = ipaddress.ip_address(det.source)
        except (TypeError, ValueError):
            self._do_alert(det)
            return self._record(det, "DoS 告警（來源格式無效，不封鎖）", False, "—",
                                "source 必須是單一 IPv4 位址")
        if (
            source_ip.version != 4
            or source_ip.is_loopback
            or source_ip.is_link_local
            or source_ip.is_multicast
            or source_ip.is_unspecified
            or source_ip.is_reserved
        ):
            self._do_alert(det)
            return self._record(det, "DoS 告警（不可封鎖位址）", False, "—",
                                f"拒絕對特殊/非 IPv4 位址執行防火牆：{source_ip}")

        source = str(source_ip)
        if source in self.protected_sources:
            self._do_alert(det)
            return self._record(det, "DoS 告警（保護本機／目標，不自封）", False, "—",
                                "來源在 protected_sources，拒絕防火牆動作")
        if source in self.game_allowlist and not self.enable_firewall:
            self._do_alert(det)
            return self._record(det, "限流告警（遊戲安全：不硬封紅隊）", False, "—",
                                "PEER 在白名單且未開 demo → 不執行封鎖")
        if not self.enable_firewall:
            self._do_alert(det)
            return self._record(det, "DoS 告警（封鎖預設關）", False, "—",
                                "enable_firewall=False → 只告警")
        envelope = det.evidence_envelope
        decision = FirewallDecision(
            predicted_class="service_dos",
            confidence=float(det.confidence),
            anomaly=True,
            action="temporary_block",
            adapter="network_helper",
            executable=True,
            reason="legacy response engine routed through fail-closed authorizer",
            evidence_id=(
                envelope.evidence_id
                if isinstance(envelope, EvidenceEnvelope)
                else ""
            ),
        )
        try:
            authorization = self._authorizer.authorize(
                decision,
                ResponseContext(
                    requested_mode=self.mode,
                    source=source,
                    source_kind="network_ip",
                    requested_ttl_sec=300,
                    evidence=envelope,
                ),
            )
        except SchemaError as exc:
            self._do_alert(det)
            return self._record(
                det,
                "DoS 告警（授權證據格式無效）",
                False,
                "—",
                self._safe_text(exc, 256),
            )
        if not authorization.execute:
            self._do_alert(det)
            return self._record(
                det,
                "DoS 告警（未通過雙證據封鎖授權）",
                False,
                "—",
                "; ".join(authorization.blockers),
            )
        # The helper target comes only from the verified authorization result,
        # never from the original Detection object.
        source = authorization.source
        argv = [
            "sudo", "-n", str(BLOCK_SOURCE), "apply",
            "--ticket-stdin",
        ]
        cmd = shlex.join(argv)
        if self.mode == "live" and not self._trusted_firewall_helper():
            self._do_alert(det)
            return self._record(
                det,
                "DoS 告警（防火牆 helper 不可信，拒絕提權）",
                False,
                cmd,
                f"{BLOCK_SOURCE} 必須是 root-owned、不可被 group/other 寫入的 executable",
                authorization.evidence_id,
                authorization.authorization_ticket,
            )
        now = time.monotonic()
        if self.mode == "live" and not self._reserve_firewall_capacity(
            source, now
        ):
            self._do_alert(det)
            return self._record(
                det,
                "DoS 告警（全域防火牆容量已滿）",
                False,
                cmd,
                "拒絕建立更多 rule/process，避免來源高基數造成資源耗盡",
                authorization.evidence_id,
                authorization.authorization_ticket,
            )
        executed = self._run(
            argv, stdin_secret=authorization.authorization_ticket
        )
        if self.mode == "live" and not executed:
            self._release_firewall_reservation(source, now)
            self._last_action.pop(
                (self._safe_text(det.source, 128), det.attack_class),
                None,
            )
        return self._record(
            det,
            (
                "封鎖洪水來源 300s（自動解封）"
                if executed
                else "封鎖執行失敗（保留告警並允許受限重試）"
            ),
            executed,
            cmd,
            "live 模式：root-owned helper",
            authorization.evidence_id,
            authorization.authorization_ticket,
        )

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
        # ML helper 不再繞過唯一 writer 直接搶 final /cmd_vel。
        self._do_alert(det)
        return self._record(
            det,
            "交由 IDS 簽章 alert → velocity guard 鎖零速",
            False,
            "—",
            "final /cmd_vel 僅允許 velocity_guard_node 發布",
        )

    # ── 底層 ──────────────────────────────────────────────────────
    @staticmethod
    def _safe_text(value, max_chars: int) -> str:
        """限制不可信標籤長度，避免灌爆 log 與 cooldown key。"""
        try:
            text = str(value)
        except Exception:
            text = f"<{type(value).__name__}>"
        text = "".join(ch if ch.isprintable() else "�" for ch in text)
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 1] + "…"

    def _purge_cooldowns(self, now: float) -> None:
        """清掉過期 key，並配合 LRU 上限抵抗高基數來源耗盡記憶體。"""
        cutoff = now - self.action_cooldown
        while self._last_action:
            _key, timestamp = next(iter(self._last_action.items()))
            if timestamp > cutoff:
                break
            self._last_action.popitem(last=False)

    def _trusted_firewall_helper(self) -> bool:
        """Accept only a fixed root-owned executable outside the writable repo."""
        try:
            info = BLOCK_SOURCE.lstat()
        except OSError:
            return False
        return (
            stat.S_ISREG(info.st_mode)
            and not BLOCK_SOURCE.is_symlink()
            and info.st_uid == 0
            and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and bool(info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        )

    def _reserve_firewall_capacity(self, source: str, now: float) -> bool:
        while self._firewall_actions and now - self._firewall_actions[0] >= 60.0:
            self._firewall_actions.popleft()
        for blocked_source, expiry in list(self._blocked_until.items()):
            if expiry <= now:
                del self._blocked_until[blocked_source]
        if source in self._blocked_until:
            return False
        if (
            len(self._firewall_actions) >= self.firewall_actions_per_minute
            or len(self._blocked_until) >= self.max_active_blocks
        ):
            return False
        self._firewall_actions.append(now)
        self._blocked_until[source] = now + 300.0
        return True

    def _release_firewall_reservation(self, source: str, now: float) -> None:
        self._blocked_until.pop(source, None)
        try:
            self._firewall_actions.remove(now)
        except ValueError:
            pass

    def _do_alert(self, det) -> bool:
        # 告警一律執行（不危險）
        attack = self._safe_text(det.attack_class, 64)
        source = self._safe_text(det.source, 128)
        evidence = self._safe_text(det.evidence, 512)
        confidence = (
            f"{float(det.confidence):.2f}"
            if (
                isinstance(det.confidence, (int, float))
                and not isinstance(det.confidence, bool)
                and math.isfinite(det.confidence)
            )
            else "invalid"
        )
        print(f"  [{hms()}] 🔔 ALERT {attack} 來源={source} "
              f"信心={confidence} {evidence}")
        return True

    def _run(self, argv: Sequence[str], *, stdin_secret: str = "") -> bool:
        if self.mode != "live":
            return False
        try:
            result = subprocess.run(
                list(argv),
                timeout=10,
                check=False,
                capture_output=True,
                text=True,
                input=stdin_secret,
            )
            if result.returncode == 0:
                return True
            detail = (result.stderr or result.stdout or "").strip()
            print(f"  ⚠️ 執行失敗 (rc={result.returncode})：{detail}")
            return False
        except (OSError, subprocess.TimeoutExpired) as e:
            print(f"  ⚠️ 執行失敗：{e}")
            return False

    def _record(
        self,
        det,
        action,
        executed,
        command,
        note,
        evidence_id="",
        authorization_ticket="",
    ) -> ResponseRecord:
        tag = "✅執行" if executed else ("🟡dry-run" if self.mode == "dry_run" else "⏭️未動作")
        attack = self._safe_text(det.attack_class, 64)
        print(f"[{hms()}] {tag} | {attack:<11}→ {action}")
        if command not in ("—", ""):
            print(f"            指令: {command}")
        if note:
            print(f"            註: {note}")
        confidence = (
            float(det.confidence)
            if (
                isinstance(det.confidence, (int, float))
                and not isinstance(det.confidence, bool)
                and math.isfinite(det.confidence)
            )
            else 0.0
        )
        timestamp = (
            float(det.ts)
            if (
                isinstance(det.ts, (int, float))
                and not isinstance(det.ts, bool)
                and math.isfinite(det.ts)
            )
            else time.time()
        )
        bounded_detection = Detection(
            attack_class=self._safe_text(det.attack_class, 64),
            source=self._safe_text(det.source, 128),
            confidence=confidence,
            evidence=self._safe_text(det.evidence, 512),
            ts=timestamp,
        )
        rec = ResponseRecord(
            bounded_detection,
            self._safe_text(action, 256),
            bool(executed),
            self._safe_text(command, 2048),
            self._safe_text(note, 512),
            self._safe_text(evidence_id, 64),
            (
                hashlib.sha256(authorization_ticket.encode("utf-8")).hexdigest()
                if authorization_ticket
                else ""
            ),
        )
        self.log.append(rec)
        if len(self.log) > self.max_log_entries:
            del self.log[: len(self.log) - self.max_log_entries]
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
