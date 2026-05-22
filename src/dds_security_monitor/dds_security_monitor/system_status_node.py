#!/usr/bin/env python3
"""系統狀態聚合節點。

訂閱所有模組的狀態 Topic，彙整後發布到 /system/health。
讓操作者從單一 Topic 掌握整個系統狀態。
"""
import time

import rclpy
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

ALERT_TIMEOUT = 30.0  # 秒後自動清除警報狀態


class SystemStatusNode(Node):

    def __init__(self) -> None:
        super().__init__('system_status_node')

        qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )

        self.create_subscription(String, '/sensor/status',    self._on_sensor,  10)
        self.create_subscription(String, '/mission/cmd',      self._on_mission, 10)
        self.create_subscription(String, '/security/alerts',  self._on_alert,   qos)

        self._health_pub = self.create_publisher(String, '/system/health', 10)

        self._sensor_status:  str = '等待感測器...'
        self._mission_status: str = '等待任務...'
        self._security_status: str = '✅ 安全'
        self._alert_time: float = 0.0

        self.create_timer(2.0, self._publish_health)
        self.get_logger().info('📊 系統狀態節點啟動 — 聚合所有模組狀態')

    def _on_sensor(self, msg: String) -> None:
        self._sensor_status = msg.data

    def _on_mission(self, msg: String) -> None:
        self._mission_status = msg.data

    def _on_alert(self, msg: String) -> None:
        clean = msg.data.replace('\n', ' ').replace('\r', '')
        self._security_status = f'🚨 警報: {clean[:100]}'
        self._alert_time = time.time()

    def _publish_health(self) -> None:
        if self._alert_time > 0 and time.time() - self._alert_time > ALERT_TIMEOUT:
            self._security_status = '✅ 安全'
            self._alert_time = 0.0
        report = (
            f'\n========== 系統健康報告 ==========\n'
            f'感測器: {self._sensor_status}\n'
            f'任務:   {self._mission_status}\n'
            f'資安:   {self._security_status}\n'
            f'=================================='
        )
        msg = String()
        msg.data = report
        self._health_pub.publish(msg)
        self.get_logger().info(report)


def main(args=None) -> None:
    rclpy.init(args=args)
    node = SystemStatusNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
