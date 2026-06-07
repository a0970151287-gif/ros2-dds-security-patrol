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
from rcl_interfaces.msg import ParameterDescriptor
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

# HMAC 驗章 — 紅隊測試發現任何人都能偽造 /security/alerts 讓 patrol 停車
# G3 修補：/patrol/goto 也用同樣 secret 簽章，攻擊者無法調度 robot
from dds_security_monitor.monitor_node import (
    CH_ALERTS,
    CH_GOTO,
    ReplayCache,
    _load_alert_secret,
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

        self._cmd  = self.create_publisher(TwistStamped, '/cmd_vel', 10)
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
        self._scan_stamp:    float = -1.0    # scan header time (sim time)
        self._scan_processed_stamp:    float = -1.0
        self._scan_recv_wall_time: float = 0.0   # wall time when scan was received (watchdog)

        # odom
        self._pos_x = self._pos_y = self._heading = 0.0
        self._odom_ready = False

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
        self._resume_timer  = None
        # N9 修補：pause 期間用 50Hz 跟 attacker 競爭 cmd_vel
        self._race_timer = None
        # N21/N23 修補：cascade-DoS 偵測 — 60s 內超 3 次 pause = attacker 借力
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
            raw_name = str(d.get("name", "臨時目標"))[:40]
            # G3: 剝離 control char (含 ANSI escape \x1b) 防 log injection
            name = "".join(c for c in raw_name if c.isprintable() and c != '\x1b') or "臨時目標"
            x    = float(d["x"])
            y    = float(d["y"])
        except Exception as e:
            self.get_logger().error(f'/patrol/goto parse error: {e}')
            return
        # 工廠地圖範圍硬上限（Gazebo turtlebot3_world 約 ±2.5m）
        MAX_RANGE = 2.5
        if not (-MAX_RANGE <= x <= MAX_RANGE) or not (-MAX_RANGE <= y <= MAX_RANGE):
            self.get_logger().error(
                f'⚠️ /patrol/goto 座標 ({x},{y}) 超出工廠範圍 ±{MAX_RANGE}m，拒絕'
            )
            return
        self._current_waypoint  = Waypoint(name=name, x=x, y=y)
        self._waypoint_queue = []   # 清空隊列，抵達後再重載 yaml
        self._stuck_count = 0
        self.get_logger().warn(
            f'[goto] (已驗章) 立刻前往 {name} ({x},{y})')

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
        r = np.array(msg.ranges, dtype=np.float32)
        r = np.where(np.isfinite(r), r, 3.5)
        r = np.clip(r, 0.0, 3.5)
        n    = len(r)
        step = max(1, n // SCAN_N)
        raw  = r[::step][:SCAN_N]
        if len(raw) < SCAN_N:
            raw = np.pad(raw, (0, SCAN_N - len(raw)), constant_values=3.5)
        self._scan = raw
        self._scan_num_points = len(raw)
        if not self._scan_ready and n > 1:
            self._scan_angle_min = msg.angle_min
            self._scan_angle_increment = (msg.angle_max - msg.angle_min) / (n - 1) * step
            self._scan_ready = True
            fi = self._fwd()
            self.get_logger().info(
                f'LiDAR: amin={math.degrees(self._scan_angle_min):.0f}° '
                f'ainc={math.degrees(self._scan_angle_increment):.1f}°/pt fwd={fi}')
        self._scan_stamp = msg.header.stamp.sec + msg.header.stamp.nanosec * 1e-9
        self._scan_recv_wall_time = time.monotonic()

    def _cb_odom(self, msg: Odometry) -> None:
        self._pos_x = msg.pose.pose.position.x
        self._pos_y = msg.pose.pose.position.y
        q = msg.pose.pose.orientation
        self._heading = math.atan2(
            2*(q.w*q.z + q.x*q.y), 1 - 2*(q.y**2 + q.z**2))
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
        )
        if payload is None:
            # N15 修補：throttle 防 log storm (attacker 100Hz flood unsigned → 4 receivers each 100Hz log → DoS)
            self.get_logger().warn(
                f'⚠️ 收到未簽章/重放/過期的 /security/alerts 訊息，已忽略 '
                f'(data 前 60 字: {msg.data[:60]!r})',
                throttle_duration_sec=5.0
            )
            return
        now = time.monotonic()
        # N21/N23 cascade-DoS 升級窗：escalation 後不再自動 pause（等人工介入）
        if self._cascade_dos_escalated and now < self._cascade_dos_quiet_until:
            self.get_logger().warn(
                f'⚠️ [cascade-DoS quiet] alert 收到但不自動 pause '
                f'(剩 {self._cascade_dos_quiet_until - now:.0f}s)，payload={payload[:40]}',
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
            self.get_logger().error(f'🚨 安全警報（已驗章）！巡航停止: {payload[:60]}')
            # N9 修補：pause 期間用 100Hz 高頻送 0 cmd_vel 跟可能的 attacker 競爭
            if self._race_timer is None:
                self._race_timer = self.create_timer(0.01, self._race_pub_zero)
            # N21/N23 修補：首次 pause 設定 30s timer，**後續 alerts 不再 reset**
            # 紅方第七輪證明：attacker 用「未授權 publisher」每 8s 戳 IDS（IDS 自己拿 secret
            # 簽 alert），cooldown 10s < resume 30s → patrol 永久停車（borrowed-authority cascade）。
            # 解法：timer 只在「首次 pause」設定，期間後續 alerts 累計但不延長 timer。
            # 真實攻擊：30s 後 resume，若攻擊還在，IDS 會再 fire → 再 pause 30s（循環，但不卡死）。
            # 攻擊者借力 DoS：60s 內 PAUSE_BURST_THRESHOLD 次 pause → escalate human + 不再自動 pause
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

        升級後 ESCALATION_QUIET_SEC 期間 alert 收到不 pause（log only），等人工。
        """
        now = time.monotonic()
        # 清掉 90s 前的舊紀錄
        self._pause_history = [t for t in self._pause_history if now - t < 90.0]
        if len(self._pause_history) >= 2 and not self._cascade_dos_escalated:
            self._cascade_dos_escalated = True
            self._cascade_dos_quiet_until = now + 120.0  # 2 分鐘人工介入窗
            self.get_logger().error(
                f'🚨🚨🚨 [N21/N23 cascade-DoS] 90s 內 {len(self._pause_history)} 次 pause — '
                f'疑似 attacker 借監控之手按停車按鈕。後續 2 分鐘不再自動 pause，等人工介入')

    def _race_pub_zero(self) -> None:
        """N9: pause 期間高頻送 0 cmd_vel 跟 attacker 競爭 latest-message-wins"""
        if self._paused:
            self._pub(0, 0)

    def _race_pub_zero(self) -> None:
        """N9: pause 期間高頻送 0 cmd_vel 跟 attacker 競爭 latest-message-wins"""
        if self._paused:
            self._pub(0, 0)

    def _resume(self) -> None:
        if self._resume_timer is not None:
            self._resume_timer.cancel()
            self._resume_timer = None
        if self._race_timer is not None:
            self._race_timer.cancel()
            self._race_timer = None
        if self._paused:
            self._paused = False
            self.get_logger().warn('安全暫停解除，恢復巡航')
            self._stuck_since = time.monotonic()
            self._last_pos_x, self._last_pos_y = self._pos_x, self._pos_y

    # ── scan 工具 ─────────────────────────────────────────────────────────────

    def _fwd(self) -> int:
        if not self._scan_ready:
            return 0
        return max(0, min(self._scan_num_points - 1,
                          int(round(-self._scan_angle_min / self._scan_angle_increment))))

    def _sector(self, fwd: int, ccw: float, cw: float) -> float:
        if self._scan is None:
            return 9.9
        n = self._scan_num_points
        sl = int(round(math.radians(ccw) / self._scan_angle_increment))
        sr = int(round(math.radians(cw)  / self._scan_angle_increment))
        idx = [(fwd + k) % n for k in range(-sr, sl + 1)]
        return float(min(self._scan[i] for i in idx)) if idx else 9.9

    # ── 主迴圈 ────────────────────────────────────────────────────────────────

    def _step(self) -> None:
        if self._paused:
            self._pub(0, 0)
            return
        if not (self._odom_ready and self._scan_ready and self._scan is not None):
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
        if self._scan_stamp == self._scan_processed_stamp:
            return
        self._scan_processed_stamp = self._scan_stamp

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
                f'✅ {self._current_waypoint.name} | ({self._pos_x:.2f},{self._pos_y:.2f}) 誤差 {dist:.2f}m')
            if self._waypoint_queue:
                self._current_waypoint = self._waypoint_queue.pop(0)
            else:
                # 從 yaml 重載，開始下一輪
                self._reload_waypoints()
                self.get_logger().info('🔄 完成一輪，重新開始')
            self.get_logger().info(f'➡️  {self._current_waypoint.name} ({self._current_waypoint.x},{self._current_waypoint.y})')
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
