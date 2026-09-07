#!/usr/bin/env python3
"""感測器集線器節點。

訂閱 /scan 和 /imu，彙整感測器狀態後發布到 /sensor/status。
這展示了 DDS 在機器人內部模組間的訊息傳遞。
"""
import math
import time

import rclpy
from rclpy.event_handler import SubscriptionEventCallbacks
from rclpy.node import Node
from rclpy.qos import HistoryPolicy, QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import Imu, LaserScan
from std_msgs.msg import String

from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer

# N6 修補：sensor/status 簽章後才發 — receiver 端不認簽章的訊息就拒絕，
# 攻擊者偽裝 sensor_hub_node 直接 publish raw 字串無法通過驗證。
from dds_security_monitor.monitor_node import (
    CH_SENSOR,
    _load_alert_secret,
    encode_sensor_status,
    lock_sensitive_params,
    secret_fingerprint,
    sign_alert,
)

SCAN_STALE_SEC = 2.0
IMU_STALE_SEC = 2.0
SCAN_MAX_POINTS = 4096


def _minimum_scan_range(
    ranges,
    range_min: float,
    range_max: float,
) -> float | None:
    """取可用最短距離；+inf 依 LaserScan 慣例視為「無回波到上限」。

    NaN、-inf、負值與低於 sensor range_min 的值不可信；整幀皆不可信時
    回傳 None，讓上層明確標成 LiDAR fault，而不是誤報安全。
    """
    if (
        not math.isfinite(range_min)
        or not math.isfinite(range_max)
        or range_min < 0.0
        or range_max <= range_min
    ):
        return None
    lower = range_min
    upper = range_max
    try:
        point_count = len(ranges)
    except TypeError:
        return None
    if point_count < 1 or point_count > SCAN_MAX_POINTS:
        return None
    minimum: float | None = None
    for value in ranges:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
        ):
            continue
        if math.isnan(value) or value == float("-inf"):
            continue
        if value == float("inf"):
            candidate = upper
        elif not math.isfinite(value) or value < lower or value > upper:
            continue
        else:
            candidate = float(value)
        if minimum is None or candidate < minimum:
            minimum = candidate
    return minimum


def _horizontal_acceleration(ax: float, ay: float, az: float) -> float:
    """Validate all three IMU axes and return finite horizontal magnitude."""
    axes = (ax, ay, az)
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        for value in axes
    ):
        raise ValueError("IMU acceleration 含 NaN/Infinity/非數值")
    horizontal = math.hypot(ax, ay)
    if not math.isfinite(horizontal):
        raise ValueError("IMU acceleration magnitude 溢位")
    return horizontal


def _format_sensor_status(
    *,
    now: float,
    min_range: float | None,
    linear_acc: float,
    scan_last_valid: float,
    imu_last_valid: float,
    scan_invalid: bool,
    imu_invalid: bool,
) -> str:
    """Build fail-closed status; missing/stale/invalid sensors are all dangerous."""
    faults: list[str] = []
    if scan_invalid:
        faults.append("LiDAR 最新幀無效")
    elif scan_last_valid <= 0:
        faults.append("LiDAR 尚未收到有效資料")
    elif now - scan_last_valid > SCAN_STALE_SEC:
        faults.append(f"LiDAR 已過期 {now - scan_last_valid:.1f}s")
    elif min_range is None or not math.isfinite(min_range):
        faults.append("LiDAR 距離狀態無效")

    if imu_invalid:
        faults.append("IMU 最新幀無效")
    elif imu_last_valid <= 0:
        faults.append("IMU 尚未收到有效資料")
    elif now - imu_last_valid > IMU_STALE_SEC:
        faults.append(f"IMU 已過期 {now - imu_last_valid:.1f}s")
    elif not math.isfinite(linear_acc):
        faults.append("IMU 加速度狀態無效")

    if faults:
        return f'[感測器狀態] ⚠️ 危險：{"；".join(faults)}'

    obstacle = min_range < 0.35
    return (
        f'[感測器狀態] '
        f'最近障礙物: {min_range:.2f}m | '
        f'{"⚠️ 危險" if obstacle else "✅ 安全"} | '
        f'水平加速度: {linear_acc:.2f}m/s²'
    )


def _sensor_state(
    *,
    now: float,
    min_range: float | None,
    linear_acc: float,
    scan_last_valid: float,
    imu_last_valid: float,
    scan_invalid: bool,
    imu_invalid: bool,
) -> str:
    """Return a machine state independently of the human display wording."""
    invalid_or_stale = (
        scan_invalid
        or imu_invalid
        or scan_last_valid <= 0
        or imu_last_valid <= 0
        or now - scan_last_valid > SCAN_STALE_SEC
        or now - imu_last_valid > IMU_STALE_SEC
        or min_range is None
        or not math.isfinite(min_range)
        or not math.isfinite(linear_acc)
    )
    if invalid_or_stale or min_range < 0.35:
        return "danger"
    return "safe"


class SensorHubNode(Node):
    """感測資料融合節點 — 將 /scan + /imu 聚合成 /sensor/status 給下游用。

    所有對外訊息以 sign_alert(channel=CH_SENSOR) 簽章發送；
    下游模組（mission_manager / system_status）用 verify_alert(
    expected_channel=CH_SENSOR) 驗章，擋 ROSEC-2026-013 N6 模組冒名攻擊
    （未授權程式以 __node:=sensor_hub_node 偽冒 + 高頻發未簽章狀態）。
    """

    def __init__(self) -> None:
        super().__init__('sensor_hub_node')
        self._telemetry = RuntimeTelemetryProducer.from_environment(
            "sensor_hub_node"
        )

        sensor_qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.BEST_EFFORT,
            history=HistoryPolicy.KEEP_LAST,
        )

        # BEST_EFFORT sensor streams are exactly where DDS drops show up, so
        # this is where qos_drop_ratio gets its live source.  Counters are
        # reset every time they are reported, giving per-window rates rather
        # than a session-cumulative total.
        self._qos_delivered = 0
        self._qos_lost = 0
        qos_events = SubscriptionEventCallbacks(
            message_lost=self._on_message_lost
        )
        self.create_subscription(
            LaserScan, '/scan', self._on_scan, sensor_qos,
            event_callbacks=qos_events,
        )
        self.create_subscription(
            Imu, '/imu', self._on_imu, sensor_qos,
            event_callbacks=qos_events,
        )
        self._status_pub = self.create_publisher(String, '/sensor/status', 10)

        self._min_range: float | None = None
        self._scan_last_valid_wall: float = 0.0
        self._scan_invalid: bool = False
        self._linear_acc: float = 0.0
        self._imu_last_valid_wall: float = 0.0
        self._imu_invalid: bool = False
        self._secret = _load_alert_secret()

        # F1-b 修補：鎖 use_sim_time 等敏感參數，runtime 拒絕未授權竄改
        lock_sensitive_params(self)

        self.create_timer(1.0, self._publish_status)
        self.get_logger().info(
            f'📡 感測器集線器啟動 — 訂閱 /scan + /imu  '
            f'secret fingerprint={secret_fingerprint(self._secret)}'
        )

    @staticmethod
    def _count_delivery(node) -> None:
        """Best-effort delivery tally.

        Written defensively like the rest of this node's telemetry: the sensor
        callbacks are also driven directly by unit tests with lightweight stand
        -in objects, and evidence collection must never break the handler.
        """
        try:
            node._qos_delivered = getattr(node, "_qos_delivered", 0) + 1
        except Exception:
            pass

    def _on_message_lost(self, info) -> None:
        """DDS reported dropped samples on a sensor stream.

        Only the delta is taken: total_count is cumulative for the lifetime of
        the subscription, and a cumulative value would make every later window
        inherit earlier loss.
        """
        try:
            self._qos_lost += max(0, int(info.total_count_change))
        except (AttributeError, TypeError, ValueError):
            pass

    def _report_qos_delivery(self) -> None:
        """Emit and reset the per-interval delivery counters."""
        delivered = getattr(self, "_qos_delivered", 0)
        lost = getattr(self, "_qos_lost", 0)
        self._qos_delivered = 0
        self._qos_lost = 0
        if delivered <= 0 and lost <= 0:
            return
        telemetry = getattr(self, "_telemetry", None)
        emit = getattr(telemetry, "emit_qos_delivery", None)
        if not callable(emit):
            return
        try:
            emit(expected_count=delivered + lost, delivered_count=delivered)
        except Exception:
            # Evidence is best-effort and must never disturb sensor handling.
            pass

    def _on_scan(self, msg: LaserScan) -> None:
        SensorHubNode._count_delivery(self)
        try:
            point_count = len(msg.ranges)
        except TypeError:
            point_count = 0
        telemetry = getattr(self, "_telemetry", None)
        emit_validation = getattr(
            telemetry, "emit_message_validation", None
        )
        if callable(emit_validation):
            try:
                emit_validation(
                    count=1,
                    oversized_count=int(point_count > SCAN_MAX_POINTS),
                )
            except Exception:
                pass
        min_range = _minimum_scan_range(
            msg.ranges, msg.range_min, msg.range_max)
        if min_range is None:
            self._scan_invalid = True
            self.get_logger().warn(
                '⚠️ LiDAR 幀無效；不刷新 freshness timestamp',
                throttle_duration_sec=2.0)
            return
        self._min_range = min_range
        self._scan_invalid = False
        self._scan_last_valid_wall = time.monotonic()

    def _on_imu(self, msg: Imu) -> None:
        SensorHubNode._count_delivery(self)
        ax = msg.linear_acceleration.x
        ay = msg.linear_acceleration.y
        az = msg.linear_acceleration.z
        try:
            linear_acc = _horizontal_acceleration(ax, ay, az)
        except ValueError as exc:
            self._imu_invalid = True
            self.get_logger().warn(
                f'⚠️ IMU 幀無效；不刷新 freshness timestamp: {exc}',
                throttle_duration_sec=2.0)
            return
        self._linear_acc = linear_acc
        self._imu_invalid = False
        self._imu_last_valid_wall = time.monotonic()

    def _publish_status(self) -> None:
        SensorHubNode._report_qos_delivery(self)
        now = time.monotonic()
        status = _format_sensor_status(
            now=now,
            min_range=self._min_range,
            linear_acc=self._linear_acc,
            scan_last_valid=self._scan_last_valid_wall,
            imu_last_valid=self._imu_last_valid_wall,
            scan_invalid=self._scan_invalid,
            imu_invalid=self._imu_invalid,
        )
        state = _sensor_state(
            now=now,
            min_range=self._min_range,
            linear_acc=self._linear_acc,
            scan_last_valid=self._scan_last_valid_wall,
            imu_last_valid=self._imu_last_valid_wall,
            scan_invalid=self._scan_invalid,
            imu_invalid=self._imu_invalid,
        )
        msg = String()
        # N6 修補：簽章 + channel=sensor/status，攻擊者 spoof 字串無 secret 不能簽
        msg.data = sign_alert(
            encode_sensor_status(state, status),
            self._secret,
            channel=CH_SENSOR,
        )
        self._status_pub.publish(msg)
        self.get_logger().info(status)

    def destroy_node(self):
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is not None:
            telemetry.close()
        return super().destroy_node()


def main(args=None) -> None:
    rclpy.init(args=args)
    node = SensorHubNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
