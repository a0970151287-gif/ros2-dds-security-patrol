#!/usr/bin/env python3
"""智慧巡航節點 — 動態巡邏點版。
巡邏點從 waypoints.yaml 載入，執行中可透過以下方式即時更新：
  - ros2 topic pub --once /patrol/goto std_msgs/String '{"name":"生產線A","x":-2.0,"y":1.5}'
  - ros2 service call /patrol/reload std_srvs/srv/Trigger
"""
import json
import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import rclpy
from geometry_msgs.msg import TwistStamped
from nav_msgs.msg import Odometry
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan
from std_msgs.msg import String
from std_srvs.srv import Trigger

try:
    import yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

# ── 速度參數（保守低速，防止翻倒）────────────────────────────────────────────
MAX_LIN  = 0.12
MAX_ANG  = 0.8
KP_ANG   = 1.2
ALIGN    = 25.0     # 超過此角度先轉再走 (°)

# ── 障礙物參數 ────────────────────────────────────────────────────────────────
OBS_STOP = 0.19
OBS_SLOW = 0.35
SCAN_N   = 90
FRONT_D  = 30       # 前方偵測半角 (°)

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

_VENV = Path.home() / 'dqn_env' / 'lib' / 'python3.12' / 'site-packages'
if _VENV.exists() and str(_VENV) not in sys.path:
    sys.path.insert(0, str(_VENV))
    for _m in [k for k in sys.modules if k == 'numpy' or k.startswith('numpy.')]:
        del sys.modules[_m]


@dataclass
class Waypoint:
    name: str
    x:    float
    y:    float


def _load_yaml(path: Path) -> list[Waypoint]:
    if not _YAML_OK or not path.exists():
        return [Waypoint(**w) for w in DEFAULT_WAYPOINTS]
    with open(path) as f:
        data = yaml.safe_load(f)
    pts = data.get("waypoints", [])
    return [Waypoint(name=p["name"], x=float(p["x"]), y=float(p["y"])) for p in pts]


class SmartPatrolNode(Node):

    def __init__(self) -> None:
        super().__init__('patrol_node')

        # ── yaml 路徑（ROS2 參數可覆寫）─────────────────────────────────────
        self.declare_parameter('waypoints_file',
            str(Path(__file__).resolve().parents[2] / 'config' / 'waypoints.yaml'))
        self._yaml_path = Path(
            self.get_parameter('waypoints_file').get_parameter_value().string_value)

        sq = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        aq = QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE,
                        durability=DurabilityPolicy.TRANSIENT_LOCAL)

        self._cmd  = self.create_publisher(TwistStamped, '/cmd_vel', 10)
        self.create_subscription(LaserScan, '/scan',            self._cb_scan,  sq)
        self.create_subscription(Odometry,  '/odom',            self._cb_odom,  sq)
        self.create_subscription(String,    '/security/alerts', self._cb_alert, aq)

        # ── 動態巡邏點介面 ────────────────────────────────────────────────────
        self.create_subscription(String, '/patrol/goto', self._cb_goto, 10)
        self.create_service(Trigger, '/patrol/reload', self._srv_reload)

        # scan
        self._scan:  np.ndarray | None = None
        self._amin:  float = 0.0
        self._ainc:  float = 0.1
        self._npts:  int   = SCAN_N
        self._scok:  bool  = False
        self._ls:    float = -1.0
        self._ps:    float = -1.0

        # odom
        self._x = self._y = self._yaw = 0.0
        self._ook = False

        # 卡住偵測
        self._last_px   = 0.0
        self._last_py   = 0.0
        self._stuck_t   = time.monotonic()
        self._backing     = False
        self._back_end    = 0.0
        self._back_turn   = 0.0
        self._stuck_count = 0

        # 巡邏
        self._reload_waypoints()

        # 資安
        self._paused  = False
        self._rtimer  = None

        self.create_timer(1.0 / CONTROL_HZ, self._step)
        self.get_logger().info(
            f'智慧巡航（動態巡邏點）| waypoints: {self._yaml_path} | '
            f'第一目標: {self._wp.name} ({self._wp.x},{self._wp.y})')

    # ── 巡邏點管理 ────────────────────────────────────────────────────────────

    def _reload_waypoints(self) -> None:
        wps = _load_yaml(self._yaml_path)
        if not wps:
            self.get_logger().error('waypoints.yaml 沒有任何點，使用預設值')
            wps = [Waypoint(**w) for w in DEFAULT_WAYPOINTS]
        self._wps = list(wps)
        self._wp  = self._wps.pop(0)

    def _cb_goto(self, msg: String) -> None:
        """即時送機器人去指定座標：{"name":"X","x":1.0,"y":2.0}"""
        try:
            d = json.loads(msg.data)
            name = d.get("name", "臨時目標")
            x    = float(d["x"])
            y    = float(d["y"])
        except Exception as e:
            self.get_logger().error(f'/patrol/goto parse error: {e}')
            return
        self._wp  = Waypoint(name=name, x=x, y=y)
        self._wps = []   # 清空隊列，抵達後再重載 yaml
        self._stuck_count = 0
        self.get_logger().warn(
            f'[goto] 立刻前往 {name} ({x},{y})')

    def _srv_reload(self, _req, resp: Trigger.Response) -> Trigger.Response:
        """重載 waypoints.yaml，從第一個點重新開始。"""
        self._reload_waypoints()
        msg = f'重載完成，共 {len(self._wps)+1} 個點，目前目標: {self._wp.name}'
        self.get_logger().info(msg)
        resp.success = True
        resp.message = msg
        return resp

    # ── 回呼 ──────────────────────────────────────────────────────────────────

    def _cb_scan(self, msg: LaserScan) -> None:
        r = np.array(msg.ranges, dtype=np.float32)
        r = np.where(np.isfinite(r), r, 3.5)
        r = np.clip(r, 0.0, 3.5)
        n    = len(r)
        step = max(1, n // SCAN_N)
        raw  = r[::step][:SCAN_N]
        if len(raw) < SCAN_N:
            raw = np.pad(raw, (0, SCAN_N - len(raw)), constant_values=3.5)
        self._scan = raw
        self._npts = len(raw)
        if not self._scok and n > 1:
            self._amin = msg.angle_min
            self._ainc = (msg.angle_max - msg.angle_min) / (n - 1) * step
            self._scok = True
            fi = self._fwd()
            self.get_logger().info(
                f'LiDAR: amin={math.degrees(self._amin):.0f}° '
                f'ainc={math.degrees(self._ainc):.1f}°/pt fwd={fi}')
        self._ls = msg.header.stamp.sec + msg.header.stamp.nanosec * 1e-9

    def _cb_odom(self, msg: Odometry) -> None:
        self._x = msg.pose.pose.position.x
        self._y = msg.pose.pose.position.y
        q = msg.pose.pose.orientation
        self._yaw = math.atan2(
            2*(q.w*q.z + q.x*q.y), 1 - 2*(q.y**2 + q.z**2))
        if not self._ook:
            self._ook = True
            self._last_px, self._last_py = self._x, self._y
            self.get_logger().info(
                f'Odom 就緒 ({self._x:.2f},{self._y:.2f})')

    def _cb_alert(self, msg: String) -> None:
        if not self._paused:
            self._paused = True
            self._pub(0, 0)
            self.get_logger().error('🚨 安全警報！巡航停止')
        if self._rtimer:
            self._rtimer.cancel()
        self._rtimer = self.create_timer(30.0, self._resume)

    def _resume(self) -> None:
        if self._rtimer:
            self._rtimer.cancel()
            self._rtimer = None
        if self._paused:
            self._paused = False
            self.get_logger().warn('安全暫停解除，恢復巡航')

    # ── scan 工具 ─────────────────────────────────────────────────────────────

    def _fwd(self) -> int:
        if not self._scok:
            return 0
        return max(0, min(self._npts - 1,
                          int(round(-self._amin / self._ainc))))

    def _sector(self, fwd: int, ccw: float, cw: float) -> float:
        if self._scan is None:
            return 9.9
        n = self._npts
        sl = int(round(math.radians(ccw) / self._ainc))
        sr = int(round(math.radians(cw)  / self._ainc))
        idx = [(fwd + k) % n for k in range(-sr, sl + 1)]
        return float(min(self._scan[i] for i in idx)) if idx else 9.9

    # ── 主迴圈 ────────────────────────────────────────────────────────────────

    def _step(self) -> None:
        if self._paused:
            self._pub(0, 0)
            return
        if not (self._ook and self._scok and self._scan is not None):
            return
        if self._ls == self._ps:
            return
        self._ps = self._ls

        now = time.monotonic()

        if self._backing:
            if now < self._back_end:
                self._pub(-0.08, self._back_turn)
                return
            else:
                self._backing = False
                self._stuck_t = now
                self._last_px, self._last_py = self._x, self._y

        moved = math.hypot(self._x - self._last_px,
                           self._y - self._last_py)
        if moved > STUCK_DIST:
            self._last_px, self._last_py = self._x, self._y
            self._stuck_t = now
        elif now - self._stuck_t > STUCK_TIME:
            self._stuck_count += 1
            turn_mag = min(MAX_ANG, 0.3 * self._stuck_count)
            self._back_turn = turn_mag if self._stuck_count % 2 == 1 else -turn_mag
            self.get_logger().warn(
                f'卡住第 {self._stuck_count} 次，倒退轉向 {self._back_turn:.1f} rad/s')
            self._backing  = True
            self._back_end = now + BACKUP_SEC
            self._pub(-0.08, self._back_turn)
            return

        dx = self._wp.x - self._x
        dy = self._wp.y - self._y
        dist  = math.hypot(dx, dy)
        angle = math.atan2(dy, dx) - self._yaw
        while angle >  math.pi: angle -= 2 * math.pi
        while angle < -math.pi: angle += 2 * math.pi

        if dist < WAYPOINT_R:
            self._pub(0, 0)
            self.get_logger().info(
                f'✅ {self._wp.name} | ({self._x:.2f},{self._y:.2f}) 誤差 {dist:.2f}m')
            if self._wps:
                self._wp = self._wps.pop(0)
            else:
                # 從 yaml 重載，開始下一輪
                self._reload_waypoints()
                self.get_logger().info('🔄 完成一輪，重新開始')
            self.get_logger().info(f'➡️  {self._wp.name} ({self._wp.x},{self._wp.y})')
            self._stuck_t = now
            self._last_px, self._last_py = self._x, self._y
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
            f'[{self._wp.name}] ({self._x:.2f},{self._y:.2f}) '
            f'dist={dist:.2f}m angle={math.degrees(angle):.0f}° '
            f'F={front:.2f} v={v:.2f} w={w:.2f}',
            throttle_duration_sec=2.0)

    def _pub(self, v: float, w: float) -> None:
        m = TwistStamped()
        m.header.stamp    = self.get_clock().now().to_msg()
        m.header.frame_id = 'base_link'
        m.twist.linear.x  = float(v)
        m.twist.angular.z = float(w)
        self._cmd.publish(m)


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
