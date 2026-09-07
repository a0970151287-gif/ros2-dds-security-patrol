#!/usr/bin/env python3
"""智慧巡航節點 — 動態巡邏點版。
巡邏點從 waypoints.yaml 載入，執行中可透過以下方式即時更新：
  - ros2 topic pub --once /patrol/goto std_msgs/String '{"name":"生產線A","x":-2.0,"y":1.5}'
  - ros2 service call /patrol/reload std_srvs/srv/Trigger
"""
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import rclpy
from geometry_msgs.msg import TwistStamped
from nav_msgs.msg import Odometry
from rcl_interfaces.msg import ParameterDescriptor
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan
from std_msgs.msg import String
from std_srvs.srv import Trigger

from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer

try:
    import yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

# HMAC 驗章 — 紅隊測試發現任何人都能偽造 /security/alerts 讓 patrol 停車
# G3 修補：/patrol/goto 也用同樣 secret 簽章，攻擊者無法調度 robot
from dds_security_monitor.monitor_node import (
    CH_ALERTS,
    CH_GOTO,
    ReplayCache,
    SECURITY_STATE_MONITOR_HEARTBEAT,
    _load_alert_secret,
    decode_security_state,
    hms,
    lock_sensitive_params,
    secret_fingerprint,
    verify_alert,
)

# ── 速度參數（保守低速，防止翻倒）────────────────────────────────────────────
MAX_LIN  = 0.12
MAX_ANG  = 0.8
KP_ANG   = 1.2
ALIGN    = 25.0     # 超過此角度先轉再走 (°)

# ── 障礙物參數 ────────────────────────────────────────────────────────────────
OBS_STOP = 0.19
OBS_SLOW = 0.35
SCAN_N   = 90
SCAN_MIN_POINTS = 32
SCAN_MAX_POINTS = 4096
LIDAR_MAX_RANGE = 3.5
REQUIRED_FRONT_HALF_ANGLE_DEG = 60.0
# Gazebo's TurtleBot3 model declares a 360-sample scan as 0..6.28 rather than
# 0..2π.  Treat at most half a beam (capped at 1°) at each endpoint as the
# angular cell represented by that beam.  The cap prevents a low-resolution or
# attacker-crafted scan from hiding a materially large blind wedge.
MAX_SCAN_ENDPOINT_TOLERANCE_DEG = 1.0
ODOM_STALE_SEC = 1.0
FRONT_D  = 30       # 前方偵測半角 (°)
WORLD_BOUND = 2.5
WAYPOINT_NAME_MAX_CHARS = 40
WAYPOINTS_MAX_COUNT = 256

# ── 卡住偵測 ──────────────────────────────────────────────────────────────────
STUCK_TIME   = 3.0
STUCK_DIST   = 0.03
BACKUP_SEC   = 2.0
WAYPOINT_R   = 0.30
CONTROL_HZ   = 5

# ── 預設巡邏點（yaml 讀不到時用）────────────────────────────────────────────
DEFAULT_WAYPOINTS = [
    {"name": "電源控制室", "x": -1.5, "y": -1.5},
    {"name": "冷卻水塔",   "x":  1.5, "y": -1.5},
    {"name": "生產線A",   "x": -1.5, "y":  1.5},
    {"name": "生產線B",   "x":  1.5, "y":  1.5},
    {"name": "出入口",     "x":  0.0, "y": -1.8},
]

@dataclass
class Waypoint:
    """巡邏路徑點（YAML 讀入後的 in-memory 形式）。"""
    name: str
    x:    float
    y:    float


def _validate_waypoint(raw, *, allow_default_name: bool = False) -> Waypoint:
    """Validate one YAML/goto waypoint without coercing attacker-controlled types."""
    if not isinstance(raw, dict):
        raise ValueError("waypoint 必須是 object/map")

    if "name" not in raw and allow_default_name:
        raw_name = "臨時目標"
    else:
        raw_name = raw.get("name")
    if not isinstance(raw_name, str):
        raise ValueError("waypoint name 必須是字串")
    name = raw_name.strip()
    if not name or len(name) > WAYPOINT_NAME_MAX_CHARS:
        raise ValueError(
            f"waypoint name 長度必須為 1..{WAYPOINT_NAME_MAX_CHARS}")
    if any(not char.isprintable() or char == "\x1b" for char in name):
        raise ValueError("waypoint name 含控制字元")

    coords: list[float] = []
    for key in ("x", "y"):
        value = raw.get(key)
        if (isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)):
            raise ValueError(f"waypoint {key} 必須是有限數值")
        numeric = float(value)
        if not -WORLD_BOUND <= numeric <= WORLD_BOUND:
            raise ValueError(
                f"waypoint {key}={numeric} 超出 ±{WORLD_BOUND}m")
        coords.append(numeric)
    return Waypoint(name=name, x=coords[0], y=coords[1])


def _load_yaml(path: Path) -> list[Waypoint]:
    if not _YAML_OK or not path.exists():
        return [Waypoint(**w) for w in DEFAULT_WAYPOINTS]
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or set(data) != {"waypoints"}:
        raise ValueError("waypoints.yaml root 必須只包含 waypoints list")
    pts = data["waypoints"]
    if not isinstance(pts, list) or not pts:
        raise ValueError("waypoints 必須是非空 list")
    if len(pts) > WAYPOINTS_MAX_COUNT:
        raise ValueError(f"waypoints 超過上限 {WAYPOINTS_MAX_COUNT}")
    return [_validate_waypoint(point) for point in pts]


def _covers_angle_segment(
    angle_min: float,
    angle_max: float,
    segment_min: float,
    segment_max: float,
) -> bool:
    """Return whether an unwrapped scan interval covers a circular segment."""
    full_turn = 2 * math.pi
    for turn in range(-2, 3):
        offset = turn * full_turn
        if (angle_min - 1e-6 <= segment_min + offset
                and segment_max + offset <= angle_max + 1e-6):
            return True
    return False


def _has_required_front_coverage(
    angle_min: float,
    angle_max: float,
    endpoint_tolerance: float = 0.0,
) -> bool:
    tolerance = max(
        0.0,
        min(
            float(endpoint_tolerance),
            math.radians(MAX_SCAN_ENDPOINT_TOLERANCE_DEG),
        ),
    )
    if angle_max - angle_min + 2 * tolerance >= 2 * math.pi - 1e-6:
        return True

    half = math.radians(REQUIRED_FRONT_HALF_ANGLE_DEG)
    return (
        _covers_angle_segment(
            angle_min - tolerance, angle_max + tolerance, 0.0, half)
        and _covers_angle_segment(
            angle_min - tolerance, angle_max + tolerance, -half, 0.0)
    )


def _prepare_scan(
    ranges,
    angle_min: float,
    angle_max: float,
) -> tuple[np.ndarray, float, float]:
    """驗證並等距降採樣一幀 LaserScan。

    畸形幀不能刷新 patrol 的 scan watchdog。NaN/-inf 採 fail-safe 映射為
    0m 障礙物；+inf（正常的「無回波」）映射為 LiDAR 最大距離。
    """
    try:
        n = len(ranges)
    except TypeError as exc:
        raise ValueError("ranges 不是可計數序列") from exc
    if not SCAN_MIN_POINTS <= n <= SCAN_MAX_POINTS:
        raise ValueError(
            f"scan 點數 {n} 不在 {SCAN_MIN_POINTS}..{SCAN_MAX_POINTS}")
    if not math.isfinite(angle_min) or not math.isfinite(angle_max):
        raise ValueError("scan 角度不是有限值")
    angle_span = angle_max - angle_min
    if angle_span <= 1e-6 or angle_span > 2 * math.pi + 1e-3:
        raise ValueError(f"scan angle span {angle_span!r} 不合法")
    source_increment = angle_span / (n - 1)
    endpoint_tolerance = min(
        source_increment / 2,
        math.radians(MAX_SCAN_ENDPOINT_TOLERANCE_DEG),
    )
    if not _has_required_front_coverage(
            angle_min, angle_max, endpoint_tolerance):
        raise ValueError(
            f"scan 未實際覆蓋前方 ±{REQUIRED_FRONT_HALF_ANGLE_DEG:.0f}°")

    try:
        values = np.asarray(ranges, dtype=np.float32)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("scan ranges 無法轉成浮點陣列") from exc
    if values.ndim != 1 or values.size != n:
        raise ValueError("scan ranges 必須是一維陣列")
    values = np.nan_to_num(
        values,
        nan=0.0,
        posinf=LIDAR_MAX_RANGE,
        neginf=0.0,
    )
    values = np.clip(values, 0.0, LIDAR_MAX_RANGE)

    sample_count = min(SCAN_N, n)
    indices = np.rint(np.linspace(0, n - 1, sample_count)).astype(np.intp)
    sampled = values[indices]
    angle_increment = angle_span / (sample_count - 1)
    return sampled, float(angle_min), float(angle_increment)


def _prepare_odom_pose(
    x: float,
    y: float,
    qx: float,
    qy: float,
    qz: float,
    qw: float,
) -> tuple[float, float, float]:
    """Validate an odometry pose and return finite x/y/yaw.

    A malformed quaternion must never propagate NaN into `/cmd_vel`.  Normal
    ROS odometry quaternions have unit length; small numeric drift is normalized.
    """
    values = (x, y, qx, qy, qz, qw)
    if any(not math.isfinite(value) for value in values):
        raise ValueError("odom pose 含 NaN/Infinity")
    norm = math.hypot(qx, qy, qz, qw)
    if norm < 1e-6 or abs(norm - 1.0) > 0.1:
        raise ValueError(f"odom quaternion norm={norm:.3f} 不合法")
    qx, qy, qz, qw = (value / norm for value in (qx, qy, qz, qw))
    heading = math.atan2(
        2 * (qw * qz + qx * qy),
        1 - 2 * (qy ** 2 + qz ** 2),
    )
    if not math.isfinite(heading):
        raise ValueError("odom heading 不是有限值")
    return float(x), float(y), heading


class SmartPatrolNode(Node):
    """幾何控制器版的巡邏節點（部署模式 — 與 burger_env_top 訓練模式擇一）。

    控制流程：
      讀 /scan + /odom → 算與當前 waypoint 的方位差 → 發 /cmd_vel/patrol
      最終 /cmd_vel 僅由 velocity_guard_node 仲裁發布。
      到達 waypoint → 切下一個（FIFO queue 循環）
      卡住偵測（3 秒未移動）→ 倒退 + 交替轉向

    安全行為：
      • 訂閱 /security/alerts，驗章通過 → emergency stop（_cmd_pub 送 0）
      • resume timer 首次 30s 固定，不 reset on alert（防 ROSEC-2026-011 cascade DoS）
      • 90s 內 ≥2 次 pause → 進入 120s quiet window 等外部介入
      • /patrol/goto 帶 HMAC envelope + 座標 ±2.5m 範圍檢查（ROSEC-2026-010 修補）
      • /patrol/reload service 預設停用 + 5s rate-limit（ROSEC-2026-015 修補）
    """

    def __init__(self) -> None:
        super().__init__('patrol_node')
        self._telemetry = RuntimeTelemetryProducer.from_environment(
            "patrol_node"
        )

        # ── yaml 路徑（ROS2 參數可覆寫）─────────────────────────────────────
        # N14-gap 修補：read_only。雖然 runtime 改 yaml path 對已 cache 的點是 inert，
        # 但保持「所有安全敏感參數一律 read_only」的一致性（紅方第六輪建議）
        ro = ParameterDescriptor(read_only=True)
        self.declare_parameter('waypoints_file',
            str(Path(__file__).resolve().parents[2] / 'config' / 'waypoints.yaml'), ro)
        self._yaml_path = Path(
            self.get_parameter('waypoints_file').get_parameter_value().string_value)

        sq = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        # B2 修補：alert subscription 改 VOLATILE，啟動時不收歷史 alert
        # （TRANSIENT_LOCAL 會在重啟瞬間收到舊 alert → 立刻 emergency stop）
        aq = QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE,
                        durability=DurabilityPolicy.VOLATILE)

        self._cmd  = self.create_publisher(
            TwistStamped, '/cmd_vel/patrol', 10)
        self.create_subscription(LaserScan, '/scan',            self._cb_scan,  sq)
        self.create_subscription(Odometry,  '/odom',            self._cb_odom,  sq)
        self.create_subscription(String,    '/security/alerts', self._cb_alert, aq)

        # ── 動態巡邏點介面 ────────────────────────────────────────────────────
        self.create_subscription(String, '/patrol/goto', self._cb_goto, 10)
        # G4 修補：/patrol/reload 預設關閉，避免任何人都能觸發 reload
        # 需要時啟動參數 `enable_reload_service:=true`
        # N14-gap 修補：read_only 一致性
        self.declare_parameter('enable_reload_service', False, ro)
        self._reload_enabled = self.get_parameter('enable_reload_service').value
        if self._reload_enabled:
            self.create_service(Trigger, '/patrol/reload', self._srv_reload)
            self.get_logger().warn(
                '⚠️ /patrol/reload service 已啟用 — 確保只在受信任的網路使用')
        else:
            self.get_logger().info(
                '🔒 /patrol/reload service 預設關閉 (G4)，'
                '需啟動參數 enable_reload_service:=true 才啟用')

        # scan
        self._scan:  np.ndarray | None = None
        self._scan_angle_min:  float = 0.0
        self._scan_angle_increment:  float = 0.1
        self._scan_num_points:  int   = SCAN_N
        self._scan_ready:  bool  = False
        # 使用本地 generation，不信任可能為 0、重複或遭偽造的 message header stamp。
        self._scan_generation: int = 0
        self._scan_processed_generation: int = -1
        self._scan_recv_wall_time: float = 0.0   # wall time when scan was received (watchdog)

        # odom
        self._pos_x = self._pos_y = self._heading = 0.0
        self._odom_ready = False
        self._odom_recv_wall_time: float = 0.0

        # 卡住偵測
        self._last_pos_x   = 0.0
        self._last_pos_y   = 0.0
        self._stuck_since   = time.monotonic()
        self._backing     = False
        self._backup_end_time    = 0.0
        self._backup_turn_rate   = 0.0
        self._stuck_count = 0

        # 巡邏
        self._reload_waypoints()

        # 資安
        self._paused  = False
        self._monitor_down = False
        self._resume_timer  = None
        # pause 期間高頻送零到私有 input；最終速度由 guard 單一仲裁。
        self._race_timer = None
        # N21/N23 修補：cascade-DoS 偵測 — 90s 內 2 次 pause = attacker 借力
        self._pause_history: list[float] = []
        self._alerts_during_pause: int = 0
        self._cascade_dos_escalated: bool = False
        self._cascade_dos_quiet_until: float = 0.0
        self._alert_secret = _load_alert_secret()  # 驗 monitor 發的 alert HMAC
        # N3 修補：alert 跟 goto 各自獨立的 nonce LRU，攻擊者重放會在 cache hit
        self._alert_replay_cache = ReplayCache()
        self._goto_replay_cache  = ReplayCache()
        self.get_logger().info(
            f'🔐 patrol_node alert secret fingerprint={secret_fingerprint(self._alert_secret)}'
        )
        # 修補紅隊攻擊 L：/patrol/reload service flood DoS
        # 每 5 秒最多 1 次 reload，超出就拒絕，避免 single-threaded executor 被洗
        self._reload_min_interval = 5.0
        self._last_reload_time    = 0.0

        # F1-b 修補：鎖 use_sim_time 等敏感參數，runtime 拒絕未授權竄改
        lock_sensitive_params(self)

        self.create_timer(1.0 / CONTROL_HZ, self._step)
        self.get_logger().info(
            f'智慧巡航（動態巡邏點）| waypoints: {self._yaml_path} | '
            f'第一目標: {self._current_waypoint.name} ({self._current_waypoint.x},{self._current_waypoint.y})')

    # ── 巡邏點管理 ────────────────────────────────────────────────────────────

    def _reload_waypoints(self) -> None:
        try:
            wps = _load_yaml(self._yaml_path)
        except Exception as e:
            self.get_logger().error(f'waypoints.yaml 解析失敗 ({e})，使用預設值')
            wps = []
        if not wps:
            self.get_logger().error('waypoints.yaml 沒有任何點，使用預設值')
            wps = [Waypoint(**w) for w in DEFAULT_WAYPOINTS]
        self._waypoint_queue = list(wps)
        self._current_waypoint  = self._waypoint_queue.pop(0)

    def _cb_goto(self, msg: String) -> None:
        """即時送機器人去指定座標 — 須 HMAC 簽章。

        Payload 格式（已簽章）：
            {"payload": "{\"name\":\"X\",\"x\":1.0,\"y\":2.0}", "sig": "<hmac-hex>"}

        紅隊修補歷史：
          - D: 座標超範圍 → 已加 ±2.5m 夾擠
          - G3: 任何人都能調度 → 加 HMAC 驗章，無 secret 者無法發指令
                同時剝離 control char 防 ANSI escape injection
        """
        # G3 + N3 + N4: HMAC + channel binding + freshness + nonce LRU。
        # channel=goto 確保 attacker forward alert/heartbeat bytes 到 /patrol/goto 會被拒。
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_GOTO,
            cache=self._goto_replay_cache,
            telemetry=getattr(self, "_telemetry", None),
        )
        if payload is None:
            # N15 修補：throttle 防 log storm
            self.get_logger().warn(
                f'⚠️ /patrol/goto 收到未簽章/重放/過期的訊息，已忽略 '
                f'(data 前 60 字: {msg.data[:60]!r})',
                throttle_duration_sec=5.0
            )
            return
        try:
            d = json.loads(payload)
            waypoint = _validate_waypoint(d, allow_default_name=True)
        except Exception as e:
            self.get_logger().error(
                f'/patrol/goto validation error: {e}')
            return
        self._current_waypoint = waypoint
        self._waypoint_queue = []   # 清空隊列，抵達後再重載 yaml
        self._stuck_count = 0
        self.get_logger().warn(
            f'[goto] (已驗章) 立刻前往 {waypoint.name} '
            f'({waypoint.x},{waypoint.y})')

    def _srv_reload(self, _req, resp: Trigger.Response) -> Trigger.Response:
        """重載 waypoints.yaml，從第一個點重新開始。

        加 rate limit（紅隊攻擊 L 修補）：每 5s 最多 1 次，防止 service flood DoS
        """
        now = time.monotonic()
        elapsed = now - self._last_reload_time
        if elapsed < self._reload_min_interval:
            remaining = self._reload_min_interval - elapsed
            resp.success = False
            resp.message = f"rate limited, 請等 {remaining:.1f}s（防 DoS）"
            self.get_logger().warn(f"⚠️ /patrol/reload 過於頻繁，已拒絕（紅隊 L 防護）")
            return resp
        self._last_reload_time = now

        self._reload_waypoints()
        msg = f'重載完成，共 {len(self._waypoint_queue)+1} 個點，目前目標: {self._current_waypoint.name}'
        self.get_logger().info(msg)
        resp.success = True
        resp.message = msg
        return resp

    # ── 回呼 ──────────────────────────────────────────────────────────────────

    def _cb_scan(self, msg: LaserScan) -> None:
        try:
            raw, angle_min, angle_increment = _prepare_scan(
                msg.ranges, msg.angle_min, msg.angle_max)
        except ValueError as exc:
            # 不更新 scan、generation 或 watchdog 時間；控制迴圈會因 stale scan 停車。
            self.get_logger().warn(
                f'⚠️ 畸形 /scan，忽略此幀: {exc}',
                throttle_duration_sec=2.0)
            return

        was_ready = self._scan_ready
        self._scan = raw
        self._scan_num_points = len(raw)
        self._scan_angle_min = angle_min
        self._scan_angle_increment = angle_increment
        self._scan_ready = True
        self._scan_generation += 1
        self._scan_recv_wall_time = time.monotonic()
        if not was_ready:
            fi = self._fwd()
            self.get_logger().info(
                f'LiDAR: amin={math.degrees(self._scan_angle_min):.0f}° '
                f'ainc={math.degrees(self._scan_angle_increment):.1f}°/pt fwd={fi}')

    def _cb_odom(self, msg: Odometry) -> None:
        position = msg.pose.pose.position
        q = msg.pose.pose.orientation
        try:
            pos_x, pos_y, heading = _prepare_odom_pose(
                position.x, position.y, q.x, q.y, q.z, q.w)
        except ValueError as exc:
            # 不刷新 watchdog；控制迴圈會對持續畸形 odom fail-safe 停車。
            self.get_logger().warn(
                f'⚠️ 畸形 /odom，忽略此幀: {exc}',
                throttle_duration_sec=2.0)
            return
        self._pos_x = pos_x
        self._pos_y = pos_y
        self._heading = heading
        self._odom_recv_wall_time = time.monotonic()
        if not self._odom_ready:
            self._odom_ready = True
            self._last_pos_x, self._last_pos_y = self._pos_x, self._pos_y
            self.get_logger().info(
                f'Odom 就緒 ({self._pos_x:.2f},{self._pos_y:.2f})')

    def _cb_alert(self, msg: String) -> None:
        # B + N3 + N4 修補：HMAC + channel binding + freshness + nonce LRU。
        # channel=alerts 攔截 N4 cross-channel forwarding（attacker 把 heartbeat bytes 丟過來）
        payload = verify_alert(
            msg.data, self._alert_secret,
            expected_channel=CH_ALERTS,
            cache=self._alert_replay_cache,
            telemetry=getattr(self, "_telemetry", None),
        )
        if payload is None:
            # N15 修補：throttle 防 log storm (attacker 100Hz flood unsigned → 4 receivers each 100Hz log → DoS)
            self.get_logger().warn(
                f'⚠️ 收到未簽章/重放/過期的 /security/alerts 訊息，已忽略 '
                f'(data 前 60 字: {msg.data[:60]!r})',
                throttle_duration_sec=5.0
            )
            return
        state_event = decode_security_state(payload)
        if state_event is not None:
            kind, state, detail = state_event
            if kind == SECURITY_STATE_MONITOR_HEARTBEAT:
                if state == "clear":
                    was_down = self._monitor_down
                    self._monitor_down = False
                    self.get_logger().info(
                        f'💓 monitor 心跳恢復（authenticated clear）：{detail}'
                    )
                    if was_down and self._paused:
                        self._resume()
                    return
                self._monitor_down = True
                payload = f'D5 monitor heartbeat fault: {detail}'
        now = time.monotonic()
        # N21/N23 cascade-DoS 升級窗：忽略後續 alert 的倒數延長效果，
        # 但整個 quiet window 必須維持停車，等人工介入。
        if self._cascade_dos_escalated and now < self._cascade_dos_quiet_until:
            remaining = self._cascade_dos_quiet_until - now
            self._paused = True
            self._pub(0, 0)
            if self._race_timer is None:
                self._race_timer = self.create_timer(
                    0.01, self._race_pub_zero)
            if self._resume_timer is None:
                self._resume_timer = self.create_timer(
                    max(0.1, remaining), self._resume)
            self.get_logger().warn(
                f'⚠️ [cascade-DoS quiet] 維持停車，不延長 quiet window '
                f'(剩 {remaining:.0f}s)，payload={payload[:40]}',
                throttle_duration_sec=10.0)
            return
        # 離開 quiet window 後 reset escalation flag，允許 cascade-DoS 偵測重新運作
        if self._cascade_dos_escalated and now >= self._cascade_dos_quiet_until:
            self._cascade_dos_escalated = False
            self._pause_history.clear()
            self.get_logger().info('cascade-DoS quiet window 結束，恢復正常 pause 行為')

        if not self._paused:
            self._paused = True
            self._alerts_during_pause = 0
            self._pub(0, 0)
            self.get_logger().error(f'[{hms()}] 🚨 攻擊觸發！安全警報（已驗章）→ 巡航停止: {payload[:60]}')
            # pause 期間在私有 controller input 維持零速。
            if self._race_timer is None:
                self._race_timer = self.create_timer(0.01, self._race_pub_zero)
            # N21/N23 修補：首次 pause 設定 30s timer，**後續 alerts 不再 reset**
            # 紅方第七輪證明：attacker 用「未授權 publisher」每 8s 戳 IDS（IDS 自己拿 secret
            # 簽 alert），cooldown 10s < resume 30s → patrol 永久停車（borrowed-authority cascade）。
            # 解法：timer 只在「首次 pause」設定，期間後續 alerts 累計但不延長 timer。
            # 真實攻擊：30s 後 resume，若攻擊還在，IDS 會再 fire → 再 pause 30s（循環，但不卡死）。
            # 攻擊者借力 DoS：90s 內 2 次 pause → 維持停車 quiet window，升級人工介入
            self._resume_timer = self.create_timer(30.0, self._resume)
            self._pause_history.append(now)
            self._check_cascade_dos()
        else:
            # 已 pause — alert 只計數，不延長 timer
            self._alerts_during_pause += 1
            self.get_logger().warn(
                f'⚠️ pause 期間收到第 {self._alerts_during_pause} 筆 alert — '
                f'timer 不延長（防 N21/N23 借力 DoS）',
                throttle_duration_sec=5.0)

    def _check_cascade_dos(self) -> None:
        """N21/N23: 90s 內 >=2 次 pause = attacker 借 IDS 之手 DoS。

        Threshold 校準（紅方第七輪實測）：attacker 8s 戳一次 → IDS 10s cooldown
        → patrol 30s pause cycle → 平均 60-90s 出現 2 次 pause。設 2/90s 才抓得到。
        誤判風險：合法情境若 90s 內真的有 2 次獨立攻擊也會升級，但這時人工介入本就合理。

        升級後 quiet window 期間維持 pause；後續 alert 只記錄、不延長期限。
        """
        now = time.monotonic()
        # 清掉 90s 前的舊紀錄
        self._pause_history = [t for t in self._pause_history if now - t < 90.0]
        if len(self._pause_history) >= 2 and not self._cascade_dos_escalated:
            self._cascade_dos_escalated = True
            self._cascade_dos_quiet_until = now + 120.0  # 2 分鐘人工介入窗
            self.get_logger().error(
                f'🚨🚨🚨 [N21/N23 cascade-DoS] 90s 內 {len(self._pause_history)} 次 pause — '
                f'疑似 attacker 借監控之手按停車按鈕。維持停車 2 分鐘，等人工介入')

    def _race_pub_zero(self) -> None:
        """Pause 期間在 /cmd_vel/patrol 維持零速；guard 是唯一 final writer。"""
        if self._paused:
            self._pub(0, 0)

    def _resume(self) -> None:
        now = time.monotonic()
        if self._monitor_down:
            self._paused = True
            self._pub(0, 0)
            self.get_logger().error(
                '⛔ monitor 心跳仍失效；只接受 IDS 的 authenticated clear，維持停車',
                throttle_duration_sec=5.0)
            return
        if (self._cascade_dos_escalated
                and now < self._cascade_dos_quiet_until):
            remaining = self._cascade_dos_quiet_until - now
            if self._resume_timer is not None:
                self._resume_timer.cancel()
            self._resume_timer = self.create_timer(
                max(0.1, remaining), self._resume)
            self._paused = True
            self._pub(0, 0)
            self.get_logger().warn(
                f'⛔ cascade-DoS quiet 尚餘 {remaining:.0f}s，維持巡航停止',
                throttle_duration_sec=5.0)
            return
        if self._resume_timer is not None:
            self._resume_timer.cancel()
            self._resume_timer = None
        if self._race_timer is not None:
            self._race_timer.cancel()
            self._race_timer = None
        if self._cascade_dos_escalated:
            self._cascade_dos_escalated = False
            self._cascade_dos_quiet_until = 0.0
            self._pause_history.clear()
            self.get_logger().info(
                'cascade-DoS quiet window 結束，允許人工確認後恢復巡航')
        if self._paused:
            self._paused = False
            self.get_logger().warn(f'[{hms()}] ✅ 攻擊解除，安全暫停結束 → 恢復巡航')
            self._stuck_since = time.monotonic()
            self._last_pos_x, self._last_pos_y = self._pos_x, self._pos_y

    # ── scan 工具 ─────────────────────────────────────────────────────────────

    def _fwd(self) -> int:
        if not self._scan_ready:
            return 0
        full_turn = 2 * math.pi
        first_turn = math.ceil((self._scan_angle_min - 1e-6) / full_turn)
        last_turn = math.floor(
            (self._scan_angle_min
             + self._scan_angle_increment * (self._scan_num_points - 1)
             + 1e-6) / full_turn)
        front_angles = [
            turn * full_turn for turn in range(first_turn, last_turn + 1)
        ]
        if not front_angles:
            return 0
        scan_mid = (
            self._scan_angle_min
            + self._scan_angle_increment * (self._scan_num_points - 1) / 2
        )
        front_angle = min(front_angles, key=lambda angle: abs(angle - scan_mid))
        return max(0, min(self._scan_num_points - 1,
                          int(round(
                              (front_angle - self._scan_angle_min)
                              / self._scan_angle_increment))))

    def _sector(self, fwd: int, ccw: float, cw: float) -> float:
        if self._scan is None:
            return 9.9
        n = self._scan_num_points
        sl = int(round(math.radians(ccw) / self._scan_angle_increment))
        sr = int(round(math.radians(cw)  / self._scan_angle_increment))
        start = fwd - sr
        stop = fwd + sl
        scan_span = self._scan_angle_increment * (n - 1)
        full_circle = scan_span >= 2 * math.pi - 2 * self._scan_angle_increment
        if not full_circle and (start < 0 or stop >= n):
            # 不把 partial scan 的尾端 modulo 成另一側；未知區域採 fail-safe 障礙。
            return 0.0
        idx = [
            (fwd + offset) % n
            for offset in range(-sr, sl + 1)
        ]
        return float(min(self._scan[i] for i in idx)) if idx else 9.9

    # ── 主迴圈 ────────────────────────────────────────────────────────────────

    def _step(self) -> None:
        if self._paused:
            self._pub(0, 0)
            return
        if not (self._odom_ready and self._scan_ready and self._scan is not None):
            return
        odom_stale = time.monotonic() - self._odom_recv_wall_time
        if self._odom_recv_wall_time <= 0 or odom_stale > ODOM_STALE_SEC:
            self._pub(0, 0)
            self.get_logger().warn(
                f'/odom 已 {odom_stale:.1f}s 未更新，急停',
                throttle_duration_sec=2.0)
            return
        # Safety watchdog：scan 太久沒更新就停車（防止 robot 以舊 cmd 失控）
        if self._scan_recv_wall_time > 0:
            stale = time.monotonic() - self._scan_recv_wall_time
            if stale > 1.0:
                self._pub(0, 0)
                self.get_logger().warn(
                    f'/scan 已 {stale:.1f}s 未更新，急停',
                    throttle_duration_sec=2.0)
                return
        if self._scan_generation == self._scan_processed_generation:
            return
        self._scan_processed_generation = self._scan_generation

        now = time.monotonic()

        if self._backing:
            if now < self._backup_end_time:
                self._pub(-0.08, self._backup_turn_rate)
                return
            else:
                self._backing = False
                self._stuck_since = now
                self._last_pos_x, self._last_pos_y = self._pos_x, self._pos_y

        moved = math.hypot(self._pos_x - self._last_pos_x,
                           self._pos_y - self._last_pos_y)
        if moved > STUCK_DIST:
            self._last_pos_x, self._last_pos_y = self._pos_x, self._pos_y
            self._stuck_since = now
        elif now - self._stuck_since > STUCK_TIME:
            self._stuck_count += 1
            turn_mag = min(MAX_ANG, 0.3 * self._stuck_count)
            self._backup_turn_rate = turn_mag if self._stuck_count % 2 == 1 else -turn_mag
            self.get_logger().warn(
                f'卡住第 {self._stuck_count} 次，倒退轉向 {self._backup_turn_rate:.1f} rad/s')
            self._backing  = True
            self._backup_end_time = now + BACKUP_SEC
            self._pub(-0.08, self._backup_turn_rate)
            return

        dx = self._current_waypoint.x - self._pos_x
        dy = self._current_waypoint.y - self._pos_y
        dist  = math.hypot(dx, dy)
        angle = math.atan2(dy, dx) - self._heading
        while angle >  math.pi: angle -= 2 * math.pi
        while angle < -math.pi: angle += 2 * math.pi

        if dist < WAYPOINT_R:
            self._pub(0, 0)
            self.get_logger().info(
                f'[{hms()}] ✅ 抵達 {self._current_waypoint.name} | ({self._pos_x:.2f},{self._pos_y:.2f}) 誤差 {dist:.2f}m')
            if self._waypoint_queue:
                self._current_waypoint = self._waypoint_queue.pop(0)
            else:
                # 從 yaml 重載，開始下一輪
                self._reload_waypoints()
                self.get_logger().info(f'[{hms()}] 🔄 完成一輪，重新開始')
            self.get_logger().info(
                f'[{hms()}] ➡️  切換任務 → {self._current_waypoint.name} '
                f'({self._current_waypoint.x},{self._current_waypoint.y})')
            self._stuck_since = now
            self._last_pos_x, self._last_pos_y = self._pos_x, self._pos_y
            self._stuck_count = 0
            return

        fwd   = self._fwd()
        front = self._sector(fwd, FRONT_D, FRONT_D)
        fl    = self._sector(fwd, 60, 0)
        fr    = self._sector(fwd, 0,  60)

        ang_g = float(np.clip(KP_ANG * angle, -MAX_ANG, MAX_ANG))

        if abs(angle) > math.radians(ALIGN):
            v, w = 0.0, ang_g
        elif front <= OBS_STOP:
            v = 0.0
            w = MAX_ANG if fl > fr else -MAX_ANG
        elif front < OBS_SLOW:
            ratio = (front - OBS_STOP) / (OBS_SLOW - OBS_STOP)
            v = MAX_LIN * ratio
            nudge = (MAX_ANG * 0.4) if fl > fr else -(MAX_ANG * 0.4)
            w = float(np.clip(ang_g + nudge * (1 - ratio), -MAX_ANG, MAX_ANG))
        else:
            v, w = MAX_LIN, ang_g

        self._pub(v, w)
        self.get_logger().info(
            f'[{self._current_waypoint.name}] ({self._pos_x:.2f},{self._pos_y:.2f}) '
            f'dist={dist:.2f}m angle={math.degrees(angle):.0f}° '
            f'F={front:.2f} v={v:.2f} w={w:.2f}',
            throttle_duration_sec=2.0)

    def _pub(self, v: float, w: float) -> None:
        if not math.isfinite(v) or not math.isfinite(w):
            self.get_logger().error(
                f'⛔ 拒絕發布非有限 /cmd_vel：v={v!r}, w={w!r}；改發 0')
            v, w = 0.0, 0.0
        m = TwistStamped()
        m.header.stamp    = self.get_clock().now().to_msg()
        m.header.frame_id = 'base_link'
        m.twist.linear.x  = float(v)
        m.twist.angular.z = float(w)
        self._cmd.publish(m)

    def destroy_node(self):
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is not None:
            telemetry.close()
        return super().destroy_node()


def main(args=None) -> None:
    rclpy.init(args=args)
    node = SmartPatrolNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node._pub(0.0, 0.0)
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
