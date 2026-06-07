#!/usr/bin/env python3
"""感測器集線器節點。

訂閱 /scan 和 /imu，彙整感測器狀態後發布到 /sensor/status。
這展示了 DDS 在機器人內部模組間的訊息傳遞。
"""
import math

import rclpy
from rclpy.node import Node
from rclpy.qos import HistoryPolicy, QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import Imu, LaserScan
from std_msgs.msg import String

# N6 修補：sensor/status 簽章後才發 — receiver 端不認簽章的訊息就拒絕，
# 攻擊者偽裝 sensor_hub_node 直接 publish raw 字串無法通過驗證。
from dds_security_monitor.monitor_node import (
    CH_SENSOR,
    _load_alert_secret,
    secret_fingerprint,
    sign_alert,
)


class SensorHubNode(Node):
    """感測資料融合節點 — 將 /scan + /imu 聚合成 /sensor/status 給下游用。

    所有對外訊息以 sign_alert(channel=CH_SENSOR) 簽章發送；
    下游模組（mission_manager / system_status）用 verify_alert(
    expected_channel=CH_SENSOR) 驗章，擋 ROSEC-2026-013 N6 模組冒名攻擊
    （未授權程式以 __node:=sensor_hub_node 偽冒 + 高頻發未簽章狀態）。
    """

    def __init__(self) -> None:
        super().__init__('sensor_hub_node')

        sensor_qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.BEST_EFFORT,
            history=HistoryPolicy.KEEP_LAST,
        )

        self.create_subscription(LaserScan, '/scan', self._on_scan, sensor_qos)
        self.create_subscription(Imu, '/imu', self._on_imu, sensor_qos)
        self._status_pub = self.create_publisher(String, '/sensor/status', 10)

        self._min_range: float | None = None
        self._linear_acc: float = 0.0
        self._imu_ready: bool = False
        self._secret = _load_alert_secret()

        self.create_timer(1.0, self._publish_status)
        self.get_logger().info(
            f'📡 感測器集線器啟動 — 訂閱 /scan + /imu  '
            f'secret fingerprint={secret_fingerprint(self._secret)}'
        )

    def _on_scan(self, msg: LaserScan) -> None:
        valid = [r for r in msg.ranges
                 if not math.isinf(r) and not math.isnan(r) and r > 0.01]
        self._min_range = min(valid) if valid else None

    def _on_imu(self, msg: Imu) -> None:
        ax = msg.linear_acceleration.x
        ay = msg.linear_acceleration.y
        self._linear_acc = math.sqrt(ax**2 + ay**2)
        self._imu_ready = True

    def _publish_status(self) -> None:
        if self._min_range is None:
            status = '[感測器狀態] 等待 LiDAR 資料...'
        else:
            obstacle = self._min_range < 0.35
            status = (
                f'[感測器狀態] '
                f'最近障礙物: {self._min_range:.2f}m | '
                f'{"⚠️ 危險" if obstacle else "✅ 安全"} | '
                f'水平加速度: {self._linear_acc:.2f}m/s²'
            )
        msg = String()
        # N6 修補：簽章 + channel=sensor/status，攻擊者 spoof 字串無 secret 不能簽
        msg.data = sign_alert(status, self._secret, channel=CH_SENSOR)
        self._status_pub.publish(msg)
        if self._min_range is not None:
            self.get_logger().info(status)


def main(args=None) -> None:
    rclpy.init(args=args)
    node = SensorHubNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
