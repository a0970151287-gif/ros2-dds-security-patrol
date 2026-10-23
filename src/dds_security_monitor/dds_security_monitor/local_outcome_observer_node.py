#!/usr/bin/env python3
"""Bounded, read-only ROS observer for semantic local outcome evidence.

The node subscribes and performs one read-only ``get_parameters`` request.  It
never publishes a ROS topic, changes a parameter, starts another node, invokes
an attack, or touches a host firewall.  Startup fails unless SROS2 Enforce,
``ROS_LOCALHOST_ONLY=1`` and the explicit live acknowledgement are present.
All evidence leaves through the existing mode-0600 local telemetry socket.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time

import rclpy
from geometry_msgs.msg import TwistStamped
from nav_msgs.msg import Odometry
from rcl_interfaces.msg import ParameterDescriptor
from rcl_interfaces.srv import GetParameters
from rclpy.node import Node
from rclpy.parameter import parameter_value_to_python
from rclpy.qos import qos_profile_sensor_data
from sensor_msgs.msg import Imu, LaserScan
from std_msgs.msg import String

from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer


LIVE_ACK = "I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE"
LIVE_ACK_ENV = "SROS2_FIREWALL_LIVE_ACK"
CORE_NODES = frozenset(
    {
        "dds_security_monitor",
        "intelligent_defense_node",
        "patrol_node",
        "sensor_hub_node",
        "velocity_guard_node",
    }
)
TOPICS = ("scan", "odom", "imu", "cmd_vel")
MAX_COUNTER = 10_000_000
SCAN_MAX_POINTS = 4096


def _require_local_enforce_environment() -> None:
    expected = {
        "ROS_LOCALHOST_ONLY": "1",
        "ROS_SECURITY_ENABLE": "true",
        "ROS_SECURITY_STRATEGY": "Enforce",
        LIVE_ACK_ENV: LIVE_ACK,
    }
    for name, wanted in expected.items():
        if os.environ.get(name) != wanted:
            raise RuntimeError(f"local outcome observer requires {name}={wanted}")
    socket_path = os.environ.get("SROS2_FIREWALL_TELEMETRY_SOCKET", "")
    if not socket_path or not socket_path.startswith("/") or len(socket_path) > 100:
        raise RuntimeError("local outcome observer requires a local telemetry socket")


def _increment(value: int, amount: int = 1) -> int:
    return min(MAX_COUNTER, value + amount)


class LocalOutcomeObserver(Node):
    """Observe only the minimum streams needed to re-derive local outcomes."""

    def __init__(self) -> None:
        _require_local_enforce_environment()
        super().__init__("local_outcome_probe")
        self._telemetry = RuntimeTelemetryProducer.from_environment(
            "local_outcome_probe"
        )
        if not self._telemetry.enabled:
            raise RuntimeError("local telemetry producer is unavailable")

        descriptor = ParameterDescriptor(
            read_only=True,
            description="Bounded passive observation duration in seconds",
        )
        self.declare_parameter("duration_sec", 30.0, descriptor)
        duration = self.get_parameter("duration_sec").value
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(float(duration))
            or not 2.0 <= float(duration) <= 300.0
        ):
            raise ValueError("duration_sec must be finite and in 2..300")
        self._deadline = time.monotonic() + float(duration)

        self._counts = {topic: 0 for topic in TOPICS}
        self._valid_scan_count = 0
        self._chatter_count = 0
        self._parameter_pending = None
        # One client, not AsyncParameterClient.  That helper builds a client
        # for all six parameter services at once, and the /local_outcome_probe
        # enclave grants exactly one: publish rq/dds_security_monitor/
        # get_parametersRequest and subscribe rr/.../get_parametersReply.  Under
        # Enforce the extra clients fail closed on the reply reader --
        # "rr/dds_security_monitor/list_parametersReply topic not found in allow
        # rule" -- and take the whole observer down with them.  Asking for only
        # the privilege the policy grants is the point of this node.
        self._parameter_client = self.create_client(
            GetParameters, "/dds_security_monitor/get_parameters"
        )

        self.create_subscription(
            LaserScan, "/scan", self._on_scan, qos_profile_sensor_data
        )
        self.create_subscription(
            Odometry, "/odom", lambda _msg: self._seen("odom"), qos_profile_sensor_data
        )
        self.create_subscription(
            Imu, "/imu", lambda _msg: self._seen("imu"), qos_profile_sensor_data
        )
        self.create_subscription(TwistStamped, "/cmd_vel", lambda _msg: self._seen("cmd_vel"), 10)
        self.create_subscription(String, "/chatter", self._on_chatter, 10)
        self.create_timer(1.0, self._sample)

    def _seen(self, topic: str) -> None:
        self._counts[topic] = _increment(self._counts[topic])

    def _on_scan(self, msg: LaserScan) -> None:
        self._seen("scan")
        try:
            count = len(msg.ranges)
        except TypeError:
            count = 0
        if 1 <= count <= SCAN_MAX_POINTS:
            self._valid_scan_count = _increment(self._valid_scan_count)

    def _on_chatter(self, _msg: String) -> None:
        self._chatter_count = _increment(self._chatter_count)

    @staticmethod
    def _node_name(info) -> str:
        return str(getattr(info, "node_name", "")).lstrip("/")

    def _publisher_counts(self, topic: str) -> tuple[int, int, list[str]]:
        infos = self.get_publishers_info_by_topic(f"/{topic}")
        names = sorted(
            name for name in (self._node_name(info) for info in infos) if name
        )
        if topic == "cmd_vel":
            authorized = sum(name == "velocity_guard_node" for name in names)
        else:
            # Only final /cmd_vel ownership is an admission assertion.  Sensor
            # publishers vary between ros_gz_bridge versions and are used only
            # for liveness counts here.
            authorized = len(names)
        return len(names), authorized, names

    def _emit_parameter_digest(self, future) -> None:
        self._parameter_pending = None
        try:
            response = future.result()
            values = getattr(response, "values", None)
            if not isinstance(values, (list, tuple)) or len(values) != 1:
                return
            value = parameter_value_to_python(values[0])
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            self._telemetry.emit_parameter_digest(
                "dds_security_monitor",
                "whitelist",
                hashlib.sha256(encoded).hexdigest(),
            )
        except Exception:
            return

    def _request_parameter_digest(self) -> None:
        if self._parameter_pending is not None:
            return
        if not self._parameter_client.service_is_ready():
            return
        try:
            request = GetParameters.Request()
            request.names = ["whitelist"]
            future = self._parameter_client.call_async(request)
            future.add_done_callback(self._emit_parameter_digest)
            self._parameter_pending = future
        except Exception:
            self._parameter_pending = None

    def _sample(self) -> None:
        try:
            nodes = sorted(name.lstrip("/") for name in self.get_node_names())
            graph_state: dict[str, object] = {
                "core_nodes": [name for name in nodes if name in CORE_NODES],
                "publishers": {},
            }
            for topic in TOPICS:
                publisher_count, authorized_count, names = self._publisher_counts(topic)
                graph_state["publishers"][topic] = names
                self._telemetry.emit_topic_probe(
                    topic,
                    message_count=self._counts[topic],
                    publisher_count=publisher_count,
                    authorized_publisher_count=authorized_count,
                )
            for node in CORE_NODES:
                self._telemetry.emit_process_health(
                    node, "healthy" if node in nodes else "unhealthy"
                )
            self._telemetry.emit_delivery_probe(
                "unauthorized_participant",
                observed_count=self._chatter_count,
            )
            self._telemetry.emit_delivery_probe(
                "valid_input", observed_count=self._valid_scan_count
            )
            encoded = json.dumps(
                graph_state,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self._telemetry.emit_state_digest(
                "runtime_state", hashlib.sha256(encoded).hexdigest()
            )
            self._request_parameter_digest()
        except Exception:
            # A graph query failure must be observed by the main graph monitor;
            # this auxiliary observer never fabricates a healthy snapshot.
            pass
        finally:
            self._counts = {topic: 0 for topic in TOPICS}
            self._valid_scan_count = 0
            self._chatter_count = 0
        if time.monotonic() >= self._deadline and rclpy.ok():
            rclpy.shutdown()

    def destroy_node(self):
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is not None:
            telemetry.close()
        return super().destroy_node()


def main(args=None) -> int:
    rclpy.init(args=args)
    node = None
    try:
        node = LocalOutcomeObserver()
        rclpy.spin(node)
        return 0
    except Exception as exc:
        if node is not None:
            node.get_logger().error(f"local outcome observer failed closed: {exc}")
        else:
            print(f"local outcome observer failed closed: {exc}")
        return 1
    finally:
        if node is not None:
            node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
