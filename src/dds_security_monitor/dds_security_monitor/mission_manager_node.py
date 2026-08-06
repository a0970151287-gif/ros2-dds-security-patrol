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
from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer
from dds_security_monitor.monitor_node import (
    CH_ALERTS,
    CH_MISSION,
    CH_SENSOR,
    ReplayCache,
    SECURITY_STATE_MONITOR_HEARTBEAT,
    _load_alert_secret,
    decode_security_state,
    decode_sensor_status,
    hms,
    lock_sensitive_params,
    secret_fingerprint,
    sign_alert,
    verify_alert,
)

EMERGENCY_RECOVERY_SEC = 30.0
CASCADE_WINDOW_SEC = 90.0
CASCADE_PAUSE_THRESHOLD = 2
CASCADE_QUIET_SEC = 120.0
SENSOR_STATUS_TIMEOUT_SEC = 3.0


def _record_pause(history: list[float], now: float) -> tuple[list[float], bool]:
    """記錄一次 pause 並判斷 borrowed-authority cascade。

    recovery 本身至少 30 秒，舊版「60 秒內 3 次」實際上幾乎不可達；
    與 patrol 的實測校準統一為 90 秒內 2 次。
    """
    recent = [t for t in history if now - t < CASCADE_WINDOW_SEC]
    recent.append(now)
    return recent, len(recent) >= CASCADE_PAUSE_THRESHOLD


class MissionManagerNode(Node):
    """任務狀態機 — 依 /sensor/status 與 /security/alerts 切換任務模式。

    輸入：/sensor/status (CH_SENSOR 驗章) + /security/alerts (CH_ALERTS 驗章)
    輸出：/mission/cmd (CH_MISSION 簽章) 供 system_status_node 聚合健康狀態

    Channel binding 防 ROSEC-2026-014 N7：未授權程式偽冒
    mission_manager_node 名字發未簽章 /mission/cmd → 下游因驗章失敗拒絕。
    """

    def __init__(self) -> None:
        super().__init__('mission_manager_node')
        self._telemetry = RuntimeTelemetryProducer.from_environment(
            "mission_manager_node"
        )

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
        self._monitor_down: bool = False
        self._startup_wall: float = time.monotonic()
        self._last_sensor_status_wall: float = 0.0
        self._last_sensor_state: str = 'unknown'
        # N21/N23 修補：cascade-DoS 偵測 — 90s 內 2 次 EMERGENCY_STOP
        self._pause_history: list[float] = []
        self._cascade_quiet_until: float = 0.0
        self._alert_secret = _load_alert_secret()
        # N3 修補：alert nonce LRU 防 replay
        self._alert_replay_cache = ReplayCache()
        # N6 修補：sensor/status nonce LRU
        self._sensor_replay_cache = ReplayCache()
        # F1-b 修補：鎖 use_sim_time 等敏感參數，runtime 拒絕未授權竄改
        lock_sensitive_params(self)
        self.create_timer(1.0, self._check_recovery)
        self.get_logger().info(
            f'🎯 任務管理節點啟動 — alert secret fingerprint={secret_fingerprint(self._alert_secret)}'
        )

    def _on_sensor(self, msg: String) -> None:
        # N6 修補：必須通過 HMAC + channel=sensor/status 驗章才信任。
        # 攻擊者用白名單名字 (sensor_hub_node) 偽造 status 無法簽章 → 拒絕。
        # 用較長 max_age（sensor 1Hz 發送，網路延遲也要留 buffer）
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_SENSOR,
            cache=self._sensor_replay_cache,
            max_age=5.0,
            telemetry=getattr(self, "_telemetry", None),
        )
        if payload is None:
            self.get_logger().warn(
                f'⚠️ /sensor/status 未簽章/重放/過期/cross-channel — 拒絕',
                throttle_duration_sec=5.0)
            return
        decoded = decode_sensor_status(payload)
        if decoded is None:
            self._last_sensor_state = 'invalid'
            self.get_logger().error(
                '⛔ /sensor/status 雖通過 HMAC 但 schema/欄位無效；fail-closed',
                throttle_duration_sec=5.0)
            if self._mission != 'EMERGENCY_STOP':
                self._set_mission('SENSOR_FAULT')
            return
        state, _detail = decoded
        self._last_sensor_status_wall = time.monotonic()
        self._last_sensor_state = state
        if self._mission == 'EMERGENCY_STOP':
            return
        if state == 'danger':
            self._set_mission('AVOID_OBSTACLE')
        else:
            self._set_mission('PATROL')

    def _on_alert(self, msg: String) -> None:
        # B + N3 + N4 修補：HMAC + channel binding + freshness + nonce LRU
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_ALERTS,
            cache=self._alert_replay_cache,
            telemetry=getattr(self, "_telemetry", None),
        )
        if payload is None:
            # N15 修補：throttle 防 log storm
            self.get_logger().warn(
                '⚠️ /security/alerts 未簽章/重放/過期/cross-channel — 拒絕',
                throttle_duration_sec=5.0)
            return
        state_event = decode_security_state(payload)
        if state_event is not None:
            kind, state, detail = state_event
            if kind == SECURITY_STATE_MONITOR_HEARTBEAT:
                if state == "clear":
                    self._monitor_down = False
                    self.get_logger().info(
                        f'💓 monitor 心跳恢復（authenticated clear）：{detail}')
                    return
                self._monitor_down = True
                payload = f'D5 monitor heartbeat fault: {detail}'
        now = time.monotonic()
        if now < self._cascade_quiet_until:
            if self._mission != 'EMERGENCY_STOP':
                self._set_mission('EMERGENCY_STOP')
            if self._alert_time <= 0:
                self._alert_time = now
            self.get_logger().warn(
                f'⛔ [cascade-DoS quiet] 維持 EMERGENCY_STOP，不延長期限 '
                f'（剩 {self._cascade_quiet_until - now:.0f}s，需外部介入確認）',
                throttle_duration_sec=5.0)
            return
        # N21/N23 修補：跟 patrol 一樣，alert 不再無限延長 recovery 倒數。
        # 首次 alert 才設定 _alert_time，後續只計數。同時偵測 cascade DoS。
        if self._mission != 'EMERGENCY_STOP':
            self._alert_time = now    # 首次 pause 設 recovery 起點
            self.get_logger().error(f'[{hms()}] 🚨 攻擊觸發！安全警報（已驗章）→ 任務強制切換為緊急停止')
            self._set_mission('EMERGENCY_STOP')
            self._pause_history, cascade = _record_pause(
                self._pause_history, now)
            if cascade:
                self._cascade_quiet_until = now + CASCADE_QUIET_SEC
                self.get_logger().error(
                    f'🚨🚨🚨 [N21/N23 cascade-DoS] '
                    f'{CASCADE_WINDOW_SEC:.0f}s 內 {len(self._pause_history)} 次 '
                    f'EMERGENCY_STOP — 疑似 attacker 借力；立即維持 '
                    f'{CASCADE_QUIET_SEC:.0f}s quiet window，等外部介入')
        else:
            self.get_logger().warn(
                '⚠️ EMERGENCY_STOP 期間收到 alert — recovery 倒數不延長（防 N21/N23）',
                throttle_duration_sec=5.0)

    def _check_recovery(self) -> None:
        now = time.monotonic()
        sensor_fresh = self._sensor_is_fresh(now)
        if self._mission != 'EMERGENCY_STOP' and not sensor_fresh:
            self._set_mission('SENSOR_FAULT')
        if self._mission == 'EMERGENCY_STOP' and self._alert_time > 0:
            if self._monitor_down:
                self.get_logger().error(
                    '⛔ monitor 心跳仍失效；只接受 IDS 的 authenticated clear，'
                    '維持 EMERGENCY_STOP',
                    throttle_duration_sec=5.0)
                return
            if now < self._cascade_quiet_until:
                self.get_logger().warn(
                    f'⛔ cascade-DoS quiet 尚餘 '
                    f'{self._cascade_quiet_until - now:.0f}s，維持 EMERGENCY_STOP',
                    throttle_duration_sec=5.0)
                return
            if self._cascade_quiet_until > 0:
                self._cascade_quiet_until = 0.0
                self._pause_history.clear()
                self.get_logger().info(
                    'cascade-DoS quiet window 結束，允許任務恢復')
            elapsed = now - self._alert_time
            if elapsed >= EMERGENCY_RECOVERY_SEC:
                self._alert_time = 0.0
                if not sensor_fresh:
                    self.get_logger().warn(
                        f'[{hms()}] 資安警報期限結束，但感測狀態失聯／過期 → SENSOR_FAULT')
                    self._set_mission('SENSOR_FAULT')
                elif self._last_sensor_state == 'danger':
                    self._set_mission('AVOID_OBSTACLE')
                else:
                    self.get_logger().info(
                        f'[{hms()}] ✅ 攻擊解除且感測狀態新鮮 → 恢復巡邏')
                    self._set_mission('PATROL')

    def _sensor_is_fresh(self, now: float | None = None) -> bool:
        check_time = time.monotonic() if now is None else now
        if self._last_sensor_status_wall <= 0:
            return check_time - self._startup_wall <= SENSOR_STATUS_TIMEOUT_SEC
        return (
            self._last_sensor_state in {'safe', 'danger'}
            and check_time - self._last_sensor_status_wall
            <= SENSOR_STATUS_TIMEOUT_SEC
        )

    def _set_mission(self, new_mission: str) -> None:
        if new_mission != self._mission:
            self._mission = new_mission
            self.get_logger().info(f'[{hms()}] 📋 任務切換 → {self._mission}')

        # N7 修補：/mission/cmd 也簽章 + channel binding，
        # 攻擊者偽裝 mission_manager_node 直接 publish /mission/cmd 沒 secret → 簽不出
        cmd = String()
        cmd.data = sign_alert(self._mission, self._alert_secret, channel=CH_MISSION)
        self._cmd_pub.publish(cmd)

    def destroy_node(self):
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is not None:
            telemetry.close()
        return super().destroy_node()


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
