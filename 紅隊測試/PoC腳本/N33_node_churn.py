#!/usr/bin/env python3
"""N33 — participant churn：快速反覆加入與離開 DDS domain。

## 這一類要打的是什麼

`node_churn` 是 `action_policy.json` 二十三條規則之一，但**從來沒有 runner
產生過資料**。它不是打某個應用層漏洞——攻擊者不送任何有內容的訊息，只是讓
自己的 participant 一直生一直死。

代價落在 discovery：每一次加入都觸發 SPDP／SEDP 交換，每一次離開都要讓對方
清掉端點。頻率夠高時，合法節點會把時間花在處理拓撲變動而不是工作。

## 專屬訊號的假設（事前寫下）

`participant_churn_rate` 這個 telemetry 特徵已經存在且在 1,100 場裡有 17.04%
的視窗非零，所以**訊號通道是活的**，不是恆零特徵。預期看到：

    participant_change  ← 每次加入／離開
    unknown_node        ← Permissive 下攻擊者本來就是未知節點

⚠️ 與 `unauthorized_participant`（N28／identity_abuse）的差別在**頻率**而不是
種類。那一類是**一個**未授權 participant 停留整場；這一類是**幾十個**短命
participant。如果證據排他性 gate 判它們兩兩不可分，那就是這個設計的答案，
不該靠調參數硬拉開——2026-09-01 記過 `discovery_recon` 的 14 對 18 就是那種
不穩健的判別。

## 用法

    python3 N33_node_churn.py <duration_sec> [--cycle-sec 0.5]

沒有憑證、不送使用者資料、不需要 root。
"""

from __future__ import annotations

import sys
import time

import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from rclpy.parameter import Parameter
from std_msgs.msg import String

# 一輪最短的生存時間。低於這個值 DDS 來不及完成 SPDP 交換，攻擊就變成
# 「快速建立又銷毀本地物件」而不是「讓對方處理拓撲變動」——那樣防守端
# 什麼都不會看到，而在 gate 眼裡與「攻擊沒有執行」無法分辨。
MIN_CYCLE_SEC = 0.25
MAX_CYCLE_SEC = 5.0
MAX_DURATION_SEC = 300.0


def _make_node(index: int) -> Node:
    # 節點名每輪不同：同名 participant 反覆出現會被 DDS 當成同一個實體重連，
    # 那量到的是重連不是 churn。
    return Node(
        f"churn_probe_{index:04d}",
        start_parameter_services=False,
        enable_rosout=False,
        parameter_overrides=[
            Parameter("start_type_description_service", Parameter.Type.BOOL, False),
        ],
    )


def main() -> int:
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    cycle = 0.5
    if "--cycle-sec" in sys.argv:
        cycle = float(sys.argv[sys.argv.index("--cycle-sec") + 1])
    duration = max(1.0, min(duration, MAX_DURATION_SEC))
    cycle = max(MIN_CYCLE_SEC, min(cycle, MAX_CYCLE_SEC))

    print(f"☠️ N33: 每 {cycle:.2f} 秒生滅一個 participant，共 {duration:.1f} 秒",
          flush=True)

    rclpy.init()
    deadline = time.monotonic() + duration
    cycles = 0
    try:
        while time.monotonic() < deadline and rclpy.ok():
            node = _make_node(cycles)
            # 建一個 publisher 才會產生 SEDP endpoint 公告；只有 participant
            # 的話對方只看到 SPDP，拓撲變動的成本小一個量級。
            node.create_publisher(String, "/churn_probe", 1)
            end = min(time.monotonic() + cycle, deadline)
            while time.monotonic() < end and rclpy.ok():
                rclpy.spin_once(node, timeout_sec=0.05)
            node.destroy_node()
            cycles += 1
            if cycles % 10 == 0:
                print(f"   已生滅 {cycles} 個", flush=True)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        # 收到 SIGTERM 時 rclpy 的 signal handler 已經 shutdown 過 context，
        # 再呼叫一次會拋「rcl_shutdown already called」而讓退出碼變 1——
        # 那在 gate 眼裡是「攻擊沒有執行」，判定正確但結論完全相反。
        if rclpy.ok():
            rclpy.shutdown()

    print(f"✅ N33 結束：{cycles} 個 participant 生滅", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
