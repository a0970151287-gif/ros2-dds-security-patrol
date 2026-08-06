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
        self.declare_parameter("timeout_sec", 45.0, descriptor)
        timeout = self.get_parameter("timeout_sec").value
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 1.0 <= float(timeout) <= 120.0
        ):
            raise ValueError("timeout_sec must be a finite value in 1..120")
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
