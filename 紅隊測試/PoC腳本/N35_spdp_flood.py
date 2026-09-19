#!/usr/bin/env python3
"""N35 — SPDP 洪泛：用大量 participant 公告淹沒 discovery。

## 這一類要打的是什麼

`spdp_flood` 是 `action_policy.json` 二十三條規則之一，但**從來沒有 runner
產生過資料**。

SPDP（Simple Participant Discovery Protocol）是 DDS 用來互相發現的多播公告。
它在**安全握手之前**就要處理——所以即使 Enforce 全開，防守方仍必須解析每一
筆進來的公告。這是少數在 Enforce 下仍能造成負擔的攻擊面。

## 與 N33（node_churn）的差別，以及為什麼不是同一支

| | N33 node_churn | N35 spdp_flood |
|---|---|---|
| 手法 | 少數 participant 反覆生滅 | **同時**存在大量 participant |
| 成本落在 | 端點的建立與清除（SEDP） | 公告本身的量（SPDP） |
| 預期訊號 | `participant_change` 的**轉換次數** | 網路層 `spdp_ratio`、`meta_ratio` |

⚠️ 如果證據排他性 gate 判這兩支不可分，**那就是答案**——代表在這個觀測層
它們是同一件事。不要靠調頻率硬拉開；2026-09-01 記過 `discovery_recon` 的
14 對 18 就是那種會隨腳本參數漂移的假判別。

## 專屬訊號的假設（事前寫下）

網路特徵 `spdp_ratio` 與 `meta_ratio` 在封包分窗表上都有值（2026-08-31 修正後
才可信）。預期：SPDP 佔比與 `uniq_dst_hosts` 明顯上升，而 `userdata_ratio`
下降——因為這個攻擊**完全不送使用者資料**。

## 用法

    python3 N35_spdp_flood.py <duration_sec> [--participants 40]

沒有憑證、不送使用者資料、不需要 root。

⚠️ participant 數有硬上限。DDS 的 discovery 是 O(n²) 的，數量開太大會讓
**攻擊者自己**先耗盡本機資源——那時防守端看到的是攻擊變慢，而不是被打，
與「防禦擋下了」在遙測上難以分辨。
"""

from __future__ import annotations

import sys
import time

import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from rclpy.parameter import Parameter

MAX_DURATION_SEC = 300.0
MIN_PARTICIPANTS = 2
# 上限的理由見模組 docstring：超過這個量，瓶頸會從防守端移到攻擊端。
MAX_PARTICIPANTS = 60


def _make_node(index: int) -> Node:
    return Node(
        f"spdp_flood_{index:04d}",
        start_parameter_services=False,
        enable_rosout=False,
        parameter_overrides=[
            Parameter("start_type_description_service", Parameter.Type.BOOL, False),
        ],
    )


def main() -> int:
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    count = 40
    if "--participants" in sys.argv:
        count = int(sys.argv[sys.argv.index("--participants") + 1])
    duration = max(1.0, min(duration, MAX_DURATION_SEC))
    count = max(MIN_PARTICIPANTS, min(count, MAX_PARTICIPANTS))

    print(f"☠️ N35: 同時建立 {count} 個 participant，維持 {duration:.1f} 秒",
          flush=True)

    rclpy.init()
    nodes: list[Node] = []
    try:
        for i in range(count):
            if not rclpy.ok():
                break
            nodes.append(_make_node(i))
            if (i + 1) % 10 == 0:
                print(f"   已建立 {i + 1} 個", flush=True)
        print(f"   {len(nodes)} 個 participant 就位，開始維持", flush=True)

        deadline = time.monotonic() + duration
        while time.monotonic() < deadline and rclpy.ok():
            # 只 spin 第一個就夠了：這個攻擊的負擔來自 participant 的**存在**
            # 與它們的週期性 SPDP 公告，不是來自我們處理進來的訊息。
            rclpy.spin_once(nodes[0], timeout_sec=0.1)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        alive = len(nodes)
        for node in nodes:
            try:
                node.destroy_node()
            except Exception:      # noqa: BLE001 — 收尾不得讓退出碼變 1
                pass
        # SIGTERM 時 rclpy 已 shutdown 過 context；重複呼叫會讓退出碼變 1，
        # 而那在 gate 眼裡是「攻擊沒有執行」。
        if rclpy.ok():
            rclpy.shutdown()
        print(f"✅ N35 結束：{alive} 個 participant 已清除", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
