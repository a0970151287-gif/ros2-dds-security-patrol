#!/usr/bin/env python3
"""Single-writer safety gate for the robot's final ``/cmd_vel``.

Controllers publish only to private input topics.  This node validates one
explicitly selected source, applies a freshness watchdog, consumes signed
security alerts, and is the only application node allowed to publish the final
drive command under the SROS2 policy.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass

import rclpy
from geometry_msgs.msg import TwistStamped
from rcl_interfaces.msg import ParameterDescriptor
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer

from dds_security_monitor.monitor_node import (
    CH_ALERTS,
    CH_HEARTBEAT,
    ReplayCache,
    SECURITY_STATE_MONITOR_HEARTBEAT,
    _load_alert_secret,
    decode_security_state,
    lock_sensitive_params,
    secret_fingerprint,
    verify_alert,
)


SOURCE_TOPICS = {
    "patrol": "/cmd_vel/patrol",
    "nav2": "/cmd_vel/nav2",
    "tqc": "/cmd_vel/tqc",
}
VALID_SOURCES = frozenset({*SOURCE_TOPICS, "none"})
DEFAULT_INPUT_TIMEOUT_SEC = 0.5
DEFAULT_ALERT_STOP_SEC = 30.0
DEFAULT_MAX_LINEAR = 0.23
DEFAULT_MAX_ANGULAR = 2.85
HEARTBEAT_LEASE_TIMEOUT_SEC = 5.0
GUARD_TELEMETRY_PERIOD_SEC = 0.1
GUARD_REASON_PRIORITY = (
    "monitor_fault",
    "generic_alert",
    "monitor_lease_missing",
    "source_none",
    "stale_command",
)


@dataclass(frozen=True)
class SafeVelocity:
    linear_x: float
    angular_z: float


def validate_velocity(
    linear_x,
    angular_z,
    *,
    max_linear: float = DEFAULT_MAX_LINEAR,
    max_angular: float = DEFAULT_MAX_ANGULAR,
) -> SafeVelocity:
    """Reject non-finite, bool, or out-of-envelope controller commands."""
    values = (linear_x, angular_z, max_linear, max_angular)
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        for value in values
    ):
        raise ValueError("velocity fields and limits must be finite numbers")
    if max_linear <= 0 or max_angular <= 0:
        raise ValueError("velocity limits must be positive")
    if abs(float(linear_x)) > max_linear or abs(float(angular_z)) > max_angular:
        raise ValueError(
            f"command exceeds safety envelope: v={linear_x}, w={angular_z}"
        )
    return SafeVelocity(float(linear_x), float(angular_z))


class VelocityGuardNode(Node):
    """Fail-closed controller arbiter and sole final velocity publisher."""

    def __init__(self) -> None:
        super().__init__("velocity_guard_node")
        self._telemetry = RuntimeTelemetryProducer.from_environment(
            "velocity_guard_node"
        )

        read_only = ParameterDescriptor(read_only=True)
        self.declare_parameter("active_source", "patrol", read_only)
        self.declare_parameter(
            "input_timeout_sec", DEFAULT_INPUT_TIMEOUT_SEC, read_only
        )
        self.declare_parameter(
            "alert_stop_sec", DEFAULT_ALERT_STOP_SEC, read_only
        )
        self.declare_parameter("max_linear", DEFAULT_MAX_LINEAR, read_only)
        self.declare_parameter("max_angular", DEFAULT_MAX_ANGULAR, read_only)

        self._active_source = str(
            self.get_parameter("active_source").value
        ).strip().lower()
        if self._active_source not in VALID_SOURCES:
            raise ValueError(
                f"active_source must be one of {sorted(VALID_SOURCES)}"
            )
        self._input_timeout = float(
            self.get_parameter("input_timeout_sec").value
        )
        self._alert_stop_sec = float(
            self.get_parameter("alert_stop_sec").value
        )
        self._max_linear = float(self.get_parameter("max_linear").value)
        self._max_angular = float(self.get_parameter("max_angular").value)
        if (
            not math.isfinite(self._input_timeout)
            or self._input_timeout <= 0
            or not math.isfinite(self._alert_stop_sec)
            or self._alert_stop_sec <= 0
        ):
            raise ValueError("watchdog durations must be finite and positive")
        validate_velocity(
            0.0,
            0.0,
            max_linear=self._max_linear,
            max_angular=self._max_angular,
        )

        self._final_pub = self.create_publisher(
            TwistStamped, "/cmd_vel", 10
        )
        for source, topic in SOURCE_TOPICS.items():
            self.create_subscription(
                TwistStamped,
                topic,
                lambda msg, selected=source: self._on_command(selected, msg),
                10,
            )

        alert_qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self.create_subscription(
            String, "/security/alerts", self._on_alert, alert_qos
        )
        heartbeat_qos = QoSProfile(
            depth=1,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self.create_subscription(
            String,
            "/security/heartbeat",
            self._on_heartbeat,
            heartbeat_qos,
        )

        self._secret = _load_alert_secret()
        self._alert_cache = ReplayCache()
        self._heartbeat_cache = ReplayCache()
        self._latest: SafeVelocity | None = None
        self._latest_wall = 0.0
        self._generic_stop_until = 0.0
        self._monitor_down = False
        # A controller command is never released until a fresh authenticated
        # monitor lease has been observed after this guard starts.
        self._last_monitor_hb_wall = 0.0
        self._heartbeat_timeout = HEARTBEAT_LEASE_TIMEOUT_SEC
        self._telemetry_guard_state: tuple[str, str] | None = None
        self._telemetry_last_output_wall = -math.inf
        self._telemetry_last_output: tuple[float, float, bool] | None = None

        lock_sensitive_params(
            self,
            {
                "active_source",
                "input_timeout_sec",
                "alert_stop_sec",
                "max_linear",
                "max_angular",
            },
        )
        self.create_timer(0.05, self._publish_selected)
        self.get_logger().info(
            f"🛡️ velocity guard 啟動：active_source={self._active_source}, "
            f"timeout={self._input_timeout:.2f}s, "
            f"secret={secret_fingerprint(self._secret)}"
        )

    def _on_command(self, source: str, msg: TwistStamped) -> None:
        if source != self._active_source:
            self.get_logger().warn(
                f"⛔ 忽略非 active controller input：{source}",
                throttle_duration_sec=5.0,
            )
            return
        try:
            command = validate_velocity(
                msg.twist.linear.x,
                msg.twist.angular.z,
                max_linear=self._max_linear,
                max_angular=self._max_angular,
            )
        except ValueError as exc:
            self._latest = None
            self._latest_wall = 0.0
            self.get_logger().error(
                f"⛔ controller command 無效，fail-closed 歸零：{exc}",
                throttle_duration_sec=2.0,
            )
            return
        self._latest = command
        self._latest_wall = time.monotonic()
        VelocityGuardNode._emit_runtime(
            self,
            "emit_guard_input",
            command.linear_x,
            command.angular_z,
            accepted_count=1,
        )

    def _on_alert(self, msg: String) -> None:
        payload = verify_alert(
            msg.data,
            self._secret,
            expected_channel=CH_ALERTS,
            cache=self._alert_cache,
            telemetry=getattr(self, "_telemetry", None),
        )
        if payload is None:
            self.get_logger().warn(
                "⛔ velocity guard 拒絕未簽章／重放／過期 alert",
                throttle_duration_sec=5.0,
            )
            return

        state_event = decode_security_state(payload)
        if state_event is not None:
            kind, state, detail = state_event
            if kind == SECURITY_STATE_MONITOR_HEARTBEAT:
                self._monitor_down = state == "fault"
                if self._monitor_down:
                    VelocityGuardNode._emit_runtime(
                        self, "emit_authenticated_action", "guard_lock"
                    )
                    self.get_logger().error(
                        f"⛔ D5 monitor fault latch：{detail}"
                    )
                else:
                    VelocityGuardNode._emit_runtime(
                        self, "emit_authenticated_action", "guard_clear"
                    )
                    self.get_logger().info(
                        f"💓 D5 authenticated clear：{detail}"
                    )
                return

        now = time.monotonic()
        if now >= self._generic_stop_until:
            self._generic_stop_until = now + self._alert_stop_sec
        VelocityGuardNode._emit_runtime(
            self, "emit_authenticated_action", "guard_lock"
        )
        self.get_logger().error(
            "⛔ signed security alert：velocity guard 鎖零速；"
            "重複 alert 不延長本次期限"
        )

    def _on_heartbeat(self, msg: String) -> None:
        payload = verify_alert(
            msg.data,
            self._secret,
            expected_channel=CH_HEARTBEAT,
            cache=self._heartbeat_cache,
            max_age=3.0,
            telemetry=getattr(self, "_telemetry", None),
        )
        if payload is None:
            self.get_logger().warn(
                "velocity guard rejected invalid/replayed monitor heartbeat",
                throttle_duration_sec=5.0,
            )
            return
        self._last_monitor_hb_wall = time.monotonic()
        VelocityGuardNode._emit_runtime(
            self, "emit_authenticated_action", "heartbeat"
        )

    def _blocking_reasons(self, now: float) -> frozenset[str]:
        reasons: set[str] = set()
        last_heartbeat = getattr(self, "_last_monitor_hb_wall", 0.0)
        heartbeat_timeout = getattr(
            self, "_heartbeat_timeout", HEARTBEAT_LEASE_TIMEOUT_SEC
        )
        if (
            last_heartbeat <= 0.0
            or now - last_heartbeat > heartbeat_timeout
        ):
            reasons.add("monitor_lease_missing")
        if self._monitor_down:
            reasons.add("monitor_fault")
        if now < self._generic_stop_until:
            reasons.add("generic_alert")
        if self._active_source == "none":
            reasons.add("source_none")
        if self._latest is None or now - self._latest_wall > self._input_timeout:
            reasons.add("stale_command")
        return frozenset(reasons)

    def _publish_selected(self) -> None:
        now = time.monotonic()
        command = SafeVelocity(0.0, 0.0)
        reasons = self._blocking_reasons(now)
        if not reasons:
            command = self._latest
        self._publish(command)
        VelocityGuardNode._record_guard_telemetry(
            self, now, command, reasons
        )

    def _emit_runtime(self, method: str, *args, **kwargs) -> bool:
        """Evidence loss must never interfere with the safety decision."""
        telemetry = getattr(self, "_telemetry", None)
        callback = getattr(telemetry, method, None)
        if not callable(callback):
            return False
        try:
            return bool(callback(*args, **kwargs))
        except Exception:
            return False

    @staticmethod
    def _primary_blocking_reason(reasons: frozenset[str]) -> str:
        for reason in GUARD_REASON_PRIORITY:
            if reason in reasons:
                return reason
        return "stale_command"

    def _record_guard_telemetry(
        self,
        now: float,
        command: SafeVelocity,
        reasons: frozenset[str],
    ) -> None:
        state = "locked" if reasons else "released"
        reason = (
            VelocityGuardNode._primary_blocking_reason(reasons)
            if reasons
            else "none"
        )
        transition = (state, reason)
        if transition != getattr(self, "_telemetry_guard_state", None):
            VelocityGuardNode._emit_runtime(
                self, "emit_guard_state", state, reason
            )
            self._telemetry_guard_state = transition

        sample = (command.linear_x, command.angular_z, bool(reasons))
        previous = getattr(self, "_telemetry_last_output", None)
        last_wall = getattr(self, "_telemetry_last_output_wall", -math.inf)
        if sample != previous or now - last_wall >= GUARD_TELEMETRY_PERIOD_SEC:
            VelocityGuardNode._emit_runtime(
                self,
                "emit_guard_output",
                command.linear_x,
                command.angular_z,
                blocked=bool(reasons),
            )
            self._telemetry_last_output = sample
            self._telemetry_last_output_wall = now

    def _publish(self, command: SafeVelocity) -> None:
        msg = TwistStamped()
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.twist.linear.x = command.linear_x
        msg.twist.angular.z = command.angular_z
        self._final_pub.publish(msg)

    def destroy_node(self):
        try:
            self._publish(SafeVelocity(0.0, 0.0))
        except Exception:
            pass
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is not None:
            telemetry.close()
        return super().destroy_node()


def main(args=None) -> None:
    rclpy.init(args=args)
    node = VelocityGuardNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
