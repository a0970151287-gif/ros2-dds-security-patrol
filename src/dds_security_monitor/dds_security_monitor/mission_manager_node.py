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
from dds_security_monitor.monitor_node import (
    CH_ALERTS,
    CH_MISSION,
    CH_SENSOR,
    ReplayCache,
    _load_alert_secret,
    secret_fingerprint,
    sign_alert,
    verify_alert,
)

EMERGENCY_RECOVERY_SEC = 30.0


class MissionManagerNode(Node):
    """任務狀態機 — 依 /sensor/status 與 /security/alerts 切換任務模式。

    輸入：/sensor/status (CH_SENSOR 驗章) + /security/alerts (CH_ALERTS 驗章)
    輸出：/mission/cmd (CH_MISSION 簽章) 供 system_status_node 聚合健康狀態

    Channel binding 防 ROSEC-2026-014 N7：未授權程式偽冒
    mission_manager_node 名字發未簽章 /mission/cmd → 下游因驗章失敗拒絕。
    """

    def __init__(self) -> None:
        super().__init__('mission_manager_node')

        # B2 修補：alert subscription 改 VOLATILE，啟動時不吃歷史 alert
        qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.VOLATILE,
        )

        self.create_subscription(String, '/sensor/status', self._on_sensor, 10)
        self.create_subscription(String, '/security/alerts', self._on_alert, qos)
        self._cmd_pub = self.create_publisher(String, '/mission/cmd', 10)

        self._mission: str = 'PATROL'
        self._alert_time: float = 0.0
        # N21/N23 修補：cascade-DoS 偵測 — 60s 內超 3 次 EMERGENCY_STOP = attacker 借力
        self._pause_history: list[float] = []
        self._alert_secret = _load_alert_secret()
        # N3 修補：alert nonce LRU 防 replay
        self._alert_replay_cache = ReplayCache()
        # N6 修補：sensor/status nonce LRU
        self._sensor_replay_cache = ReplayCache()
        self.create_timer(1.0, self._check_recovery)
        self.get_logger().info(
            f'🎯 任務管理節點啟動 — alert secret fingerprint={secret_fingerprint(self._alert_secret)}'
        )

    def _on_sensor(self, msg: String) -> None:
        if self._mission == 'EMERGENCY_STOP':
            return
        # N6 修補：必須通過 HMAC + channel=sensor/status 驗章才信任。
        # 攻擊者用白名單名字 (sensor_hub_node) 偽造 status 無法簽章 → 拒絕。
        # 用較長 max_age（sensor 1Hz 發送，網路延遲也要留 buffer）
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_SENSOR,
            cache=self._sensor_replay_cache,
            max_age=5.0,
        )
        if payload is None:
            self.get_logger().warn(
                f'⚠️ /sensor/status 未簽章/重放/過期/cross-channel — 拒絕',
                throttle_duration_sec=5.0)
            return
        if '⚠️ 危險' in payload:
            self._set_mission('AVOID_OBSTACLE')
        else:
            self._set_mission('PATROL')

    def _on_alert(self, msg: String) -> None:
        # B + N3 + N4 修補：HMAC + channel binding + freshness + nonce LRU
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_ALERTS,
            cache=self._alert_replay_cache,
        )
        if payload is None:
            # N15 修補：throttle 防 log storm
            self.get_logger().warn(
                '⚠️ /security/alerts 未簽章/重放/過期/cross-channel — 拒絕',
                throttle_duration_sec=5.0)
            return
        now = time.monotonic()
        # N21/N23 修補：跟 patrol 一樣，alert 不再無限延長 recovery 倒數。
        # 首次 alert 才設定 _alert_time，後續只計數。同時偵測 cascade DoS。
        if self._mission != 'EMERGENCY_STOP':
            self._alert_time = now    # 首次 pause 設 recovery 起點
            self.get_logger().error('🚨 安全警報（已驗章）！任務強制切換為緊急停止')
            self._set_mission('EMERGENCY_STOP')
            self._pause_history.append(now)
            self._pause_history = [t for t in self._pause_history if now - t < 60.0]
            if len(self._pause_history) >= 3:
                self.get_logger().error(
                    f'🚨🚨🚨 [N21/N23 cascade-DoS] 60s 內 {len(self._pause_history)} 次 '
                    f'EMERGENCY_STOP — 疑似 attacker 借力，等人工介入')
        else:
            self.get_logger().warn(
                '⚠️ EMERGENCY_STOP 期間收到 alert — recovery 倒數不延長（防 N21/N23）',
                throttle_duration_sec=5.0)

    def _check_recovery(self) -> None:
        if self._mission == 'EMERGENCY_STOP' and self._alert_time > 0:
            elapsed = time.monotonic() - self._alert_time
            if elapsed >= EMERGENCY_RECOVERY_SEC:
                self.get_logger().info(f'✅ 警報解除 {EMERGENCY_RECOVERY_SEC:.0f} 秒，恢復巡邏')
                self._alert_time = 0.0
                self._set_mission('PATROL')

    def _set_mission(self, new_mission: str) -> None:
        if new_mission != self._mission:
            self._mission = new_mission
            self.get_logger().info(f'📋 任務切換 → {self._mission}')

        # N7 修補：/mission/cmd 也簽章 + channel binding，
        # 攻擊者偽裝 mission_manager_node 直接 publish /mission/cmd 沒 secret → 簽不出
        cmd = String()
        cmd.data = sign_alert(self._mission, self._alert_secret, channel=CH_MISSION)
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
