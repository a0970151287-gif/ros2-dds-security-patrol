#!/usr/bin/env python3
"""One-shot Gazebo readiness probe used by the SROS2 Enforce supervisor."""

from __future__ import annotations

import math
import time

import rclpy
from nav_msgs.msg import Odometry
from rcl_interfaces.msg import ParameterDescriptor
from rclpy.node import Node
from rclpy.qos import qos_profile_sensor_data
from rosgraph_msgs.msg import Clock
from sensor_msgs.msg import Imu, LaserScan
from tf2_msgs.msg import TFMessage


REQUIRED_TOPICS = {
    "/scan": LaserScan,
    "/odom": Odometry,
    "/imu": Imu,
    "/clock": Clock,
    "/tf": TFMessage,
}


class ReadinessProbe(Node):
    """Exit successfully only after every required simulation stream is live."""

    def __init__(self) -> None:
        super().__init__("security_readiness_probe")
        descriptor = ParameterDescriptor(
            description="Fail-closed wall-clock readiness timeout in seconds",
            read_only=True,
        )
        # ⚠️ 上限 2026-10-02 從 120 提到 300,因為 120 已經小於 Gazebo 實際需要的時間。
        #
        # 實測（09-28 的失敗批次）：`gazebo.launch.py` 起來之後 **118 秒內一個
        # `process started` 都沒有**（它的 launch.log 只有 204 bytes、兩行），
        # 而這個 probe 在 120 秒上限放棄,stack 於是 fail-closed 停掉整組。
        # 症狀是監督器寫 `⛔ stack 起不來`,而 stack 其實起得來:
        # 七個節點全部正常、HMAC 指紋一致。
        #
        # 慢的原因 `gazebo.launch.py` 的 docstring 自己寫了:那些
        # `IncludeLaunchDescription`「會掃過每一個已安裝的 ROS 套件來組 Gazebo
        # 路徑,在 WSL 掛載的工作區上特別慢」——而那個成本付在**建 launch
        # description 的時候**,也就是任何行程啟動**之前**,正好對應我們看到的
        # 「橫幅印了、urdf 印了、然後什麼都沒有」。
        #
        # ⚠️ 這是治症狀不是治本。真正的修法是讓那個掃描不要發生（明確給
        # `GZ_SIM_RESOURCE_PATH`、不走 include),但那會改動 launch 的結構。
        # 放寬上限先讓「Gazebo 慢一點」不再等於整批報廢。
        #
        # ⚠️ 上限仍然必須存在:它是 fail-closed 的界線。300 秒 × 4 個空轉批次
        # ≈ 20 分鐘,監督器的 MAX_BARREN_BATCHES 仍然會大聲停下來（C2C-049）。
        #
        # ⚠️ 2026-10-02 的教訓:我先前把呼叫端的 `timeout_sec` 改成 240 卻**沒有
        # 查這裡的範圍**,於是 probe 立刻 `failed closed: timeout_sec must be a
        # finite value in 1..120`,整次重啟報廢。
        # `tests/test_readiness_window_layers.py` 現在會比對這兩端。
        self.declare_parameter("timeout_sec", 45.0, descriptor)
        timeout = self.get_parameter("timeout_sec").value
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 1.0 <= float(timeout) <= 300.0
        ):
            raise ValueError("timeout_sec must be a finite value in 1..300")
        self.timeout_sec = float(timeout)
        self.seen: set[str] = set()
        # Do not shadow Node._subscriptions: rclpy owns that internal list.
        # Duplicating its entries causes destroy_node() to remove each
        # subscription twice and fail during probe cleanup.
        self._probe_subscriptions = []
        for topic, message_type in REQUIRED_TOPICS.items():
            self._probe_subscriptions.append(
                self.create_subscription(
                    message_type,
                    topic,
                    lambda _msg, name=topic: self.seen.add(name),
                    qos_profile_sensor_data,
                )
            )


def run_probe(node: ReadinessProbe) -> bool:
    deadline = time.monotonic() + node.timeout_sec
    while rclpy.ok() and time.monotonic() < deadline:
        rclpy.spin_once(node, timeout_sec=0.2)
        if node.seen == set(REQUIRED_TOPICS):
            node.get_logger().info(
                "Gazebo readiness passed: scan, odom, imu, clock and tf are live"
            )
            return True
    missing = sorted(set(REQUIRED_TOPICS) - node.seen)
    node.get_logger().error(
        f"Gazebo readiness failed; missing streams: {', '.join(missing)}"
    )
    return False


def main(args=None) -> int:
    rclpy.init(args=args)
    node = None
    try:
        node = ReadinessProbe()
        return 0 if run_probe(node) else 1
    except Exception as exc:
        if node is not None:
            node.get_logger().error(f"readiness probe failed closed: {exc}")
        else:
            print(f"readiness probe failed closed: {exc}")
        return 1
    finally:
        if node is not None:
            node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
