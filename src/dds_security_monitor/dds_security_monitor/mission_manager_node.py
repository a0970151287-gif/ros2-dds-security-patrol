#!/usr/bin/env python3
"""任務管理節點。

訂閱 /sensor/status 和 /security/alerts，
根據感測器狀態發布任務指令到 /mission/cmd。
展示多模組透過 DDS Topic 協調運作。
"""
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

EMERGENCY_RECOVERY_SEC = 30.0


class MissionManagerNode(Node):

    def __init__(self) -> None:
        super().__init__('mission_manager_node')

        qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )

        self.create_subscription(String, '/sensor/status', self._on_sensor, 10)
        self.create_subscription(String, '/security/alerts', self._on_alert, qos)
        self._cmd_pub = self.create_publisher(String, '/mission/cmd', 10)

        self._mission: str = 'PATROL'
        self._alert_time: float = 0.0
        self.create_timer(1.0, self._check_recovery)
        self.get_logger().info('🎯 任務管理節點啟動 — 訂閱 /sensor/status + /security/alerts')

    def _on_sensor(self, msg: String) -> None:
        if self._mission == 'EMERGENCY_STOP':
            return
        if '⚠️ 危險' in msg.data:
            self._set_mission('AVOID_OBSTACLE')
        else:
            self._set_mission('PATROL')

    def _on_alert(self, msg: String) -> None:
        self._alert_time = time.time()
        if self._mission != 'EMERGENCY_STOP':
            self.get_logger().error('🚨 安全警報！任務強制切換為緊急停止')
            self._set_mission('EMERGENCY_STOP')

    def _check_recovery(self) -> None:
        if self._mission == 'EMERGENCY_STOP' and self._alert_time > 0:
            elapsed = time.time() - self._alert_time
            if elapsed >= EMERGENCY_RECOVERY_SEC:
                self.get_logger().info(f'✅ 警報解除 {EMERGENCY_RECOVERY_SEC:.0f} 秒，恢復巡邏')
                self._alert_time = 0.0
                self._set_mission('PATROL')

    def _set_mission(self, new_mission: str) -> None:
        if new_mission != self._mission:
            self._mission = new_mission
            self.get_logger().info(f'📋 任務切換 → {self._mission}')

        cmd = String()
        cmd.data = self._mission
        self._cmd_pub.publish(cmd)


def main(args=None) -> None:
    rclpy.init(args=args)
    node = MissionManagerNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
