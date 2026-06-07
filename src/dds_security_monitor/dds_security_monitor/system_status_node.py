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
from dds_security_monitor.monitor_node import (
    CH_ALERTS,
    CH_HEALTH,
    CH_MISSION,
    CH_SENSOR,
    ReplayCache,
    _load_alert_secret,
    secret_fingerprint,
    sign_alert,
    verify_alert,
)

ALERT_TIMEOUT = 30.0  # 秒後自動清除警報狀態

# N13 修補 rate-limit 常數（不再用 latch — latch 一次性致盲）
_UNSIGNED_LOG_COOLDOWN_SEC: float = 10.0    # 未簽章雜訊 log 頻率上限
_REAL_IMPOSTOR_COOLDOWN_SEC: float = 60.0   # 真 impostor (持 secret 第二者) log 頻率上限


class SystemStatusNode(Node):

    def __init__(self) -> None:
        super().__init__('system_status_node')

        # B2 修補：alert subscription 改 VOLATILE，啟動時不吃歷史 alert
        qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.VOLATILE,
        )

        self.create_subscription(String, '/sensor/status',    self._on_sensor,  10)
        self.create_subscription(String, '/mission/cmd',      self._on_mission, 10)
        self.create_subscription(String, '/security/alerts',  self._on_alert,   qos)

        self._health_pub = self.create_publisher(String, '/system/health', 10)
        # N8 修補：訂自己發的 /system/health → 看到不認識的 nonce 就 log（N13: 不再反射成 alert）
        self.create_subscription(String, '/system/health', self._on_health_watch, 10)
        self._my_health_nonces: set[str] = set()      # 自己發出去的 nonce 集合
        # N13 修補：移除 _health_impostor_alerted latch，改用 rate-limit cooldown
        self._last_unsigned_log_t: float = 0.0
        self._last_real_impostor_log_t: float = 0.0
        self._unsigned_count_since_last_log: int = 0

        self._sensor_status:  str = '等待感測器...'
        self._mission_status: str = '等待任務...'
        self._security_status: str = '✅ 安全'
        self._alert_time: float = 0.0
        self._alert_secret = _load_alert_secret()
        # N3 修補：alert nonce LRU 防 replay
        self._alert_replay_cache = ReplayCache()
        # N7 修補：mission/cmd nonce LRU
        self._mission_replay_cache = ReplayCache()
        # N6 修補：sensor/status nonce LRU
        self._sensor_replay_cache = ReplayCache()
        # N8 修補：health 自我監控也用 cache（impostor 重放也擋）
        self._health_replay_cache = ReplayCache()

        self.create_timer(2.0, self._publish_health)
        self.get_logger().info(
            f'📊 系統狀態節點啟動 — alert secret fingerprint={secret_fingerprint(self._alert_secret)}'
        )

    def _on_sensor(self, msg: String) -> None:
        # N6 修補：驗 sensor 簽章後才顯示 — 攻擊者 spoof 不簽章 → operator 面板
        # 不會顯示假感測資訊（顯示「等待感測器...」直到下一筆合法 reading）
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_SENSOR,
            cache=self._sensor_replay_cache,
            max_age=5.0,
        )
        if payload is None:
            self.get_logger().warn(
                '⚠️ /sensor/status 未簽章/重放/過期/cross-channel — 拒絕',
                throttle_duration_sec=5.0)
            return
        self._sensor_status = payload

    def _on_mission(self, msg: String) -> None:
        # N7 修補：mission/cmd 必須通過 HMAC + channel=mission/cmd 驗章。
        # 攻擊者偽裝 mission_manager_node 直接 publish → 簽不出 → 拒絕。
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_MISSION,
            cache=self._mission_replay_cache,
            max_age=5.0,
        )
        if payload is None:
            self.get_logger().warn(
                '⚠️ /mission/cmd 未簽章/重放/過期/cross-channel — 拒絕',
                throttle_duration_sec=5.0)
            return
        self._mission_status = payload

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
        clean = payload.replace('\n', ' ').replace('\r', '')
        self._security_status = f'🚨 警報: {clean[:100]}'
        self._alert_time = time.monotonic()

    def _on_health_watch(self, msg: String) -> None:
        """N8 self-watch — N13 修補後：不再 reflection、不再 latch。

        紅隊 N13 證明原版 self-watch 是 confused-deputy + 一次性 latch：
          - 未簽章垃圾 → system_status 用 secret 簽出 CH_ALERTS alert → patrol 停車
            （attacker 無 secret 卻能觸發 emergency stop = 破壞核心不變式）
          - latch 設一次永不 reset → 一個未授權 packet 永久關閉 N8 偵測

        N13 修補要求（紅方建議全收）：
          (a) 未簽章垃圾 → **只 log，throttled**，不發任何 ROS alert 不進 sign_alert
              理由：未簽章封包在 DDS Permissive 模式下任何 L1 attacker 都能產生 = 雜訊
              系統不該為雜訊觸發 emergency stop
          (b) 簽章合法但 nonce 非自己發 → log + LINE notification 給人類研判，
              **不發到 CH_ALERTS（不會觸發 emergency stop）**
              理由：這才是真正的「第二個持 secret publisher」威脅，但仍應由人類研判，
              不該自動 cascade 到全系統停車
          (c) 移除 latch，改用 rate-limit cooldown — 持續偵測，但限制 log 洗版頻率
        """
        # 驗 sig
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_HEALTH,
            cache=self._health_replay_cache,
            max_age=10.0,
        )
        now = time.monotonic()
        # (a) 未簽章/重放/cross-channel → 只 log throttled，絕對不反射到 CH_ALERTS
        if payload is None:
            if now - self._last_unsigned_log_t > _UNSIGNED_LOG_COOLDOWN_SEC:
                self._last_unsigned_log_t = now
                self._unsigned_count_since_last_log += 1
                self.get_logger().warn(
                    f'⚠️ [N8/N13] /system/health 收到 {self._unsigned_count_since_last_log} '
                    f'筆未簽章/重放/cross-channel 訊息 — 已忽略（不反射成 alert）'
                )
                self._unsigned_count_since_last_log = 0
            else:
                self._unsigned_count_since_last_log += 1
            return
        # (b) 簽章合法但 nonce 非己發 → 真正的 impostor (持 secret 的第二者)
        try:
            import json as _json
            nonce = _json.loads(_json.loads(msg.data)["body"])["nonce"]
        except Exception:
            return
        if nonce not in self._my_health_nonces:
            if now - self._last_real_impostor_log_t > _REAL_IMPOSTOR_COOLDOWN_SEC:
                self._last_real_impostor_log_t = now
                self.get_logger().error(
                    f'🔴 [N8] /system/health 簽章合法但非自己發出 (nonce={nonce[:8]}) — '
                    f'第二個 secret 持有者出現，疑似 supply chain 攻擊。'
                    f'log-only：不自動觸發 emergency stop，請人類研判'
                )

    def _publish_health(self) -> None:
        if self._alert_time > 0 and time.monotonic() - self._alert_time > ALERT_TIMEOUT:
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
        # N8 修補：簽章 + channel=system/health。
        # 拿出 nonce 記到 _my_health_nonces，self-watch 才能分辨「自己 vs impostor」
        msg.data = sign_alert(report, self._alert_secret, channel=CH_HEALTH)
        try:
            import json as _json
            nonce = _json.loads(_json.loads(msg.data)["body"])["nonce"]
            self._my_health_nonces.add(nonce)
            # 限制集合大小 — health 每 2s 一筆，1024 entries 撐 ~30min 夠用
            if len(self._my_health_nonces) > 1024:
                self._my_health_nonces = set(list(self._my_health_nonces)[-512:])
        except Exception:
            pass
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
