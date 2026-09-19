#!/usr/bin/env python3
"""N37 — 自適應攻擊者：會看防禦反應並改變行為的驅動器。

## 為什麼需要它

2026-09-20 查出來的事實：**27 支 PoC 沒有任何一支有內部隨機性**。同一類的
兩場之間只差三樣——一個 `intensity` 純量、起止時間、以及場次順序。而每個
runner 把所有參數都綁在那一個純量上（`points = 5000 + intensity*45000`、
`rate = 1 + intensity*2`），所以**同一類的所有場次落在特徵空間的一條一維
曲線上**。

這件事與 2026-09-19 量到的東西直接衝突：Enforce 的 26 個活特徵有 **19 個是
網路層**（突發度、到達間隔變異、封包大小、埠熵），而那些現在每一類都固定。
資料集因此給了每一類一個人工的乾淨網路指紋——**識別率被高估**，真實攻擊者
不會這樣。

## 這一支怎麼「有智慧」

它不是隨機參數，是**回饋迴路**：

    偵察 → 試探 → 觀察防禦反應 → 升級 或 退避 → 再觀察 → …

### 攻擊者看得到什麼（而且只看得到這些）

一個未認證的攻擊者在網路上真的觀察得到的東西，沒有別的：

| 通道 | 看得到什麼 | 為什麼合法 |
|---|---|---|
| `/cmd_vel` | 機器人在不在動 | 公開 topic；速度歸零＝守衛鎖了 |
| `/security/alerts` | **訊息數**（不是內容） | 公開 topic；沒有金鑰驗不了簽章，但數得出來 |
| ROS graph | 有哪些節點／topic | discovery 本來就是公開的 |

⚠️ **它沒有 HMAC 金鑰，也沒有遙測 socket。** 那兩條是方法學界線不是權限：
攻擊者若能寫遙測，它就能自己偽造「防禦有反應」的證據，整批資料作廢
（C2C-053）。

⚠️ **Enforce 下它會是盲的**——未認證 participant 進不了握手，訂閱收不到
任何東西。這不是缺陷，是這個威脅模型的真實樣子，而且值得單獨記錄：
`blind=true` 會寫進決策軌跡。

### 決策規則（事前寫下，跑完不改）

每一個 burst 之後計算兩個觀察量：

    noticed   = alerts 增量速率 > 基線 × NOTICE_ALERT_FACTOR
    contained = /cmd_vel 的零速比例 > CONTAINED_ZERO_FRACTION

| 觀察 | 行為 | 像什麼樣的攻擊者 |
|---|---|---|
| 都沒有 | **升級**：intensity ×1.6，縮短間隔 | 沒被抓到就加大力道 |
| 只有 noticed | **潛行**：intensity ×0.45，拉長間隔 | 被發現就低速慢慢來 |
| contained | **暫停**再小幅試探 | 被擋住就等守衛釋放 |

### 它不換攻擊類別

一場只打一個類別。換類別會讓場次變成多標籤，而
`session_labels()` 對多標籤直接拋例外——整條管線假設一場一種攻擊。
**那個假設本身是個盲點**，但要動它是另一件事，不在這一支裡混做。

## 不重寫任何攻擊

驅動器 import `firewall_lab.runners.build_attack_argv`，用**調整後的
intensity** 去呼叫既有的 PoC。不另外維護一份參數對應表——重寫就會有兩個
版本各自漂移（C2C-054 的程式碼稽核記過這件事）。

## 決策軌跡

每一步都印到 stdout，會被收進 `attack.stdout.log` 成為場次證據。
那份軌跡本身就是「攻擊者當時看到什麼、因此決定做什麼」的紀錄。

## 用法

    python3 N37_adaptive_attacker.py <duration_sec> \\
        --scenario <id> --catalog <path> [--seed N]
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import subprocess
import sys
import time
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[2]
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

MAX_DURATION_SEC = 300.0
RECON_SEC = 4.0
BURST_MIN_SEC = 5.0
BURST_MAX_SEC = 10.0
# 判定「被注意到」與「被擋住」的門檻。事前宣告。
NOTICE_ALERT_FACTOR = 2.5      # 告警速率超過基線這麼多倍
CONTAINED_ZERO_FRACTION = 0.80  # /cmd_vel 的零速比例
ESCALATE = 1.6
BACK_OFF = 0.45
TEARDOWN_RESERVE_SEC = 4.0

_STOP = False


def _on_terminate(_signum, _frame) -> None:
    global _STOP
    _STOP = True


class Observer:
    """攻擊者的眼睛。只訂閱公開 topic，不碰遙測也不碰金鑰。"""

    def __init__(self) -> None:
        self.ok = False
        self.blind_reason = ""
        self._node = None
        self._alerts = 0
        self._cmd_total = 0
        self._cmd_zero = 0
        try:
            import rclpy
            from geometry_msgs.msg import TwistStamped
            from rclpy.node import Node
            from rclpy.qos import QoSProfile, ReliabilityPolicy
            from std_msgs.msg import String

            rclpy.init()
            self._rclpy = rclpy
            self._node = Node("n37_probe")
            best_effort = QoSProfile(
                depth=20, reliability=ReliabilityPolicy.BEST_EFFORT)
            self._node.create_subscription(
                String, "/security/alerts", self._on_alert, 20)
            self._node.create_subscription(
                TwistStamped, "/cmd_vel", self._on_cmd, best_effort)
            self.ok = True
        except Exception as exc:                     # pragma: no cover
            self.blind_reason = f"{type(exc).__name__}: {exc}"

    def _on_alert(self, _msg) -> None:
        # 只數,不解析。沒有金鑰,簽章驗不了——數量本身才是訊號。
        self._alerts += 1

    def _on_cmd(self, msg) -> None:
        self._cmd_total += 1
        twist = getattr(msg, "twist", msg)
        if abs(getattr(twist.linear, "x", 0.0)) < 1e-6 and \
                abs(getattr(twist.angular, "z", 0.0)) < 1e-6:
            self._cmd_zero += 1

    def pump(self, seconds: float) -> None:
        if not self.ok:
            time.sleep(seconds)
            return
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not _STOP:
            try:
                self._rclpy.spin_once(self._node, timeout_sec=0.05)
            except Exception:
                break

    def snapshot(self) -> dict:
        total = self._cmd_total
        return {"alerts": self._alerts, "cmd_total": total,
                "zero_fraction": (self._cmd_zero / total) if total else 0.0}

    def reset_counters(self) -> None:
        self._alerts = 0
        self._cmd_total = 0
        self._cmd_zero = 0

    def close(self) -> None:
        if not self.ok:
            return
        try:
            self._node.destroy_node()
        except Exception:
            pass
        try:
            self._rclpy.shutdown()
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("duration_sec", nargs="?", type=float, default=45.0)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--seed", type=int, default=0)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    duration = max(5.0, min(float(args.duration_sec), MAX_DURATION_SEC))
    rng = random.Random(args.seed)

    from firewall_lab.catalog import load_catalog
    from firewall_lab.runners import build_attack_argv

    scenario = load_catalog(args.catalog)[args.scenario]

    signal.signal(signal.SIGTERM, _on_terminate)
    signal.signal(signal.SIGINT, _on_terminate)

    t0 = time.monotonic()
    stop_by = t0 + duration - TEARDOWN_RESERVE_SEC
    trace: list[dict] = []

    observer = Observer()
    print(f"☠️ N37 自適應攻擊者 | vector={scenario.scenario_id} "
          f"| {duration:.0f}s | seed={args.seed}", flush=True)
    if not observer.ok:
        print(f"   ⚠️ 觀察不到任何東西（{observer.blind_reason or '訂閱收不到'}）"
              "——盲打模式。Enforce 下這是預期的。", flush=True)

    # ── 偵察：先量基線，之後的判定都相對於它 ──
    observer.pump(RECON_SEC)
    base = observer.snapshot()
    base_alert_rate = base["alerts"] / RECON_SEC
    print(f"[偵察] {RECON_SEC:.0f}s：alerts={base['alerts']} "
          f"({base_alert_rate:.2f}/s)  cmd_vel={base['cmd_total']} "
          f"零速比例={base['zero_fraction']:.2f}  盲打={not observer.ok}",
          flush=True)

    intensity = rng.uniform(scenario.intensity_min,
                            min(0.45, scenario.intensity_max))
    pause = rng.uniform(1.0, 3.0)
    step = 0
    try:
        while not _STOP and time.monotonic() < stop_by:
            step += 1
            remaining = stop_by - time.monotonic()
            burst = min(rng.uniform(BURST_MIN_SEC, BURST_MAX_SEC), remaining)
            if burst < 2.0:
                break
            intensity = max(scenario.intensity_min,
                            min(intensity, scenario.intensity_max))
            argv = build_attack_argv(
                scenario, workspace_root=WORKSPACE,
                duration_sec=burst, intensity=intensity)
            print(f"[burst {step}] intensity={intensity:.2f} "
                  f"{burst:.1f}s", flush=True)
            observer.reset_counters()
            started = time.monotonic()
            rc = None
            if argv is not None:
                try:
                    proc = subprocess.Popen(
                        argv, cwd=str(WORKSPACE),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    observer.pump(burst)
                    proc.terminate()
                    try:
                        rc = proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        rc = proc.wait(timeout=5)
                except Exception as exc:
                    print(f"   ⚠️ burst 起不來：{exc}", flush=True)
                    observer.pump(burst)
            else:
                observer.pump(burst)

            seen = observer.snapshot()
            elapsed = max(time.monotonic() - started, 0.1)
            rate = seen["alerts"] / elapsed
            noticed = rate > max(base_alert_rate * NOTICE_ALERT_FACTOR, 0.2)
            contained = seen["zero_fraction"] > CONTAINED_ZERO_FRACTION

            if not observer.ok:
                decision = "盲打：固定節奏"
                intensity *= rng.uniform(0.9, 1.3)
                pause = rng.uniform(1.0, 4.0)
            elif contained:
                decision = "被擋住 ⇒ 暫停後小幅試探"
                intensity *= BACK_OFF
                pause = rng.uniform(3.0, 6.0)
            elif noticed:
                decision = "被注意到 ⇒ 潛行"
                intensity *= BACK_OFF
                pause = rng.uniform(2.0, 4.5)
            else:
                decision = "沒被注意 ⇒ 升級"
                intensity *= ESCALATE
                pause = rng.uniform(0.5, 2.0)

            print(f"   [觀察] alerts={seen['alerts']} ({rate:.2f}/s, "
                  f"基線 {base_alert_rate:.2f}/s)  "
                  f"零速比例={seen['zero_fraction']:.2f}  rc={rc}", flush=True)
            print(f"   [決策] {decision}  下一次 intensity≈"
                  f"{min(max(intensity, scenario.intensity_min), scenario.intensity_max):.2f}"
                  f"  間隔 {pause:.1f}s", flush=True)
            trace.append({
                "step": step, "burst_sec": round(burst, 2),
                "intensity": round(intensity, 3), "rc": rc,
                "alerts": seen["alerts"], "alert_rate": round(rate, 3),
                "zero_fraction": round(seen["zero_fraction"], 3),
                "noticed": noticed, "contained": contained,
                "decision": decision, "blind": not observer.ok,
            })
            if _STOP or time.monotonic() >= stop_by:
                break
            observer.pump(min(pause, max(stop_by - time.monotonic(), 0.0)))
    finally:
        observer.close()
        print(f"⏹ N37 結束：{step} 個 burst，歷時 "
              f"{time.monotonic() - t0:.1f}s", flush=True)
        print("DECISION_TRACE " + json.dumps(trace, ensure_ascii=False),
              flush=True)
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
