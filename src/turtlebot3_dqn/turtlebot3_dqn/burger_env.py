"""
BurgerEnv — TurtleBot3 Burger Gymnasium Environment for SAC
基底：reiniscimurs/DRL-Robot-Navigation-ROS2
本實作對論文做了以下修改（reviewer 點名要寫清楚的部分）：

觀測空間（state_dim = 25）：
  [20 LiDAR bins (min per bin, 正規化 /3.5)] + [dist/4] + [cos(angle)] + [sin(angle)]
  + [prev_lin_vel/MAX_LIN_VEL] + [prev_ang_vel/MAX_ANG_VEL]

不使用 frame stacking（論文原始設計）。每 bin 取最小值（最保守）。

Reward（與論文差異列出，方便評審質詢）：
  +100   到達 waypoint（含中繼跟最後一個）
  -100   碰撞 (LaserScan min < COLLISION_DIST)
  -100   security_stop / scan_timeout — TODO: reviewer A3 指出該改 truncated 不入 buffer
  else:  lin_vel - abs(ang_vel)/2 - obstacle_penalty + PROGRESS_K * Δdist
         |        論文原版         | <- 本實作新增 progress shaping
  其中 obstacle_penalty = max(0, 1.35 - min_range) / 2.0   (論文式)
       Δdist            = prev_dist - curr_dist
       PROGRESS_K       = 10.0  (本實作選擇，無 ablation, 見 known limitations)

Known limitations（reviewer 質疑而我同意的）：
  - PROGRESS_K=10 沒做 ablation，progress term 量級可能蓋過論文原 reward
  - security_stop/scan_timeout 給 -100 會污染 replay buffer（環境失敗 != agent 失敗）
  - 沒有 deterministic eval set，無法回答「是否 overfit 到特定起點順序」
"""
import math
import os
import random
import subprocess
import time
from dataclasses import dataclass

import numpy as np
import gymnasium as gym
from gymnasium import spaces
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped
from nav_msgs.msg import Odometry
from sensor_msgs.msg import LaserScan
from std_msgs.msg import String
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy

# HMAC alert 驗章 — 紅隊測試發現未驗章時任何人能偽造 alert 中斷訓練
# fail-safe：若 dds_security_monitor 沒裝（例如獨立部署訓練），預設拒絕所有 alert
# N3 修補：anti-replay 加 nonce LRU，每個 instance 自己 own 一個 cache
try:
    from dds_security_monitor.monitor_node import (
        CH_ALERTS,
        ReplayCache,
        _load_alert_secret,
        verify_alert,
    )
    _ALERT_SECRET = _load_alert_secret()
    _ALERT_VERIFY_OK = True
except Exception:
    _ALERT_SECRET = b""
    _ALERT_VERIFY_OK = False
    CH_ALERTS = "alerts"
    class ReplayCache:  # type: ignore[no-redef]
        def check_and_add(self, _n): return True
    def verify_alert(_payload, _secret, **_kwargs):  # type: ignore[no-redef]
        return None  # 找不到 verify_alert 就一律拒絕（最安全）

# ── 環境參數（已對齊 Burger 規格）────────────────────────────────────────────
N_SCAN_BINS    = 20      # 20 個 LiDAR bins，每 bin 取最小值（論文做法）
STATE_DIM      = 25      # 20 + dist + cos + sin + lin_vel + ang_vel
MAX_LIN_VEL    = 0.22    # Burger 官方上限 0.22 m/s（之前寫 0.25 超規格）
MAX_ANG_VEL    = 1.5     # Burger 官方上限 ~2.84 rad/s，論文用 1.5 保守
COLLISION_DIST = 0.18    # Burger 機器人碰撞距離
WAYPOINT_REACH = 0.30    # 到達門檻（Burger 較小，用 0.30m）
MAX_STEPS      = 500
LIDAR_MAX      = 3.5     # Burger LDS-01 實際上限 3.5m（之前寫 7.0 浪費 dynamic range）
DIST_MAX       = 4.0     # 目標距離正規化上限（超過視為 1.0）
SCAN_TIMEOUT   = 2.0     # scan 等待超時（秒）

# ── 障礙物位置（Gazebo 世界中的柱子）────────────────────────────────────────
CYLINDERS = [
    (-1.1, -1.1), (-1.1, 0.0), (-1.1, 1.1),
    ( 0.0, -1.1), ( 0.0, 0.0), ( 0.0, 1.1),
    ( 1.1, -1.1), ( 1.1, 0.0), ( 1.1, 1.1),
]


# ── 巡邏點定義 ────────────────────────────────────────────────────────────────
@dataclass
class Waypoint:
    name: str
    x:    float
    y:    float

WAYPOINTS = [
    Waypoint("電源控制室", -1.5, -1.5),
    Waypoint("冷卻水塔",    1.5, -1.5),
    Waypoint("生產線A",   -1.5,  1.5),
    Waypoint("生產線B",    1.5,  1.5),
    Waypoint("出入口",     0.0, -1.8),
]


def _is_safe(x: float, y: float, clearance: float = 0.50) -> bool:
    if abs(x) > 1.8 or abs(y) > 1.8:
        return False
    for cx, cy in CYLINDERS:
        if math.hypot(x - cx, y - cy) < clearance:
            return False
    return True


def _random_safe_pos(rng) -> tuple[float, float]:
    """用傳入的 rng（np.random.Generator）保證 seed 可重現。"""
    for _ in range(2000):
        x = float(rng.uniform(-1.8, 1.8))
        y = float(rng.uniform(-1.8, 1.8))
        if _is_safe(x, y):
            return x, y
    return 0.5, 0.5


# ── 環境 ──────────────────────────────────────────────────────────────────────

class BurgerEnv(gym.Env, Node):
    metadata = {"render_modes": []}

    def __init__(self):
        Node.__init__(self, "burger_sac_env")
        gym.Env.__init__(self)

        qos     = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        # Alert subscription 用 VOLATILE durability，避免收到「訂閱前的歷史 alert」
        # 如果用 TRANSIENT_LOCAL（跟 monitor publisher 同），broker 裡的舊 alert 訊息
        # 會在訓練一啟動就立刻打進來 → _security_stop=True → 第一個 step 就 -100，
        # 訓練從第一個 episode 就被廢掉。
        qos_sec = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.VOLATILE,
        )

        self._scan_sub  = self.create_subscription(LaserScan, "/scan",            self._scan_cb,  qos)
        self._odom_sub  = self.create_subscription(Odometry,  "/odom",            self._odom_cb,  qos)
        self._alert_sub = self.create_subscription(String,    "/security/alerts", self._alert_cb, qos_sec)
        self._cmd_pub   = self.create_publisher(TwistStamped, "/cmd_vel", 10)

        # observation_space = 25 維，無 frame stack
        # 各維度正規化後的實際範圍：
        #   [0..19] LiDAR bins  → [0, 1]  (除以 LIDAR_MAX)
        #   [20] dist           → [0, 1]  (除以 DIST_MAX，clip)
        #   [21] cos(angle)     → [-1, 1]
        #   [22] sin(angle)     → [-1, 1]
        #   [23] prev_lin_vel   → [0, 1]  (除以 MAX_LIN_VEL)
        #   [24] prev_ang_vel   → [-1, 1] (除以 MAX_ANG_VEL)
        _obs_low  = np.array([0.0]*N_SCAN_BINS + [0.0, -1.0, -1.0,  0.0, -1.0], dtype=np.float32)
        _obs_high = np.array([1.0]*N_SCAN_BINS + [1.0,  1.0,  1.0,  1.0,  1.0], dtype=np.float32)
        self.observation_space = spaces.Box(low=_obs_low, high=_obs_high, dtype=np.float32)
        self.action_space = spaces.Box(
            low=-1.0, high=1.0, shape=(2,), dtype=np.float32
        )

        # 感測器狀態
        self._raw_scan:    list | None = None
        self._robot_x      = 0.0
        self._robot_y      = 0.0
        self._robot_yaw    = 0.0
        self._odom_received = False
        self._prev_lin_vel = 0.0
        self._prev_ang_vel = 0.0
        self._steps        = 0
        self._scan_failed  = False     # scan timeout 旗標，下一次 step 視為 episode failure

        # 巡邏狀態
        self._waypoint_queue: list[Waypoint] = []
        self._current_wp:     Waypoint | None = None
        self._waypoints_done  = 0          # 該 episode 已到達的 waypoint 數
        self._ep_min_clearance = float("inf")  # 該 episode 最接近障礙物的距離
        self._prev_dist        = 0.0       # 上一步到 waypoint 的距離（給 progress reward 用）

        # 資安警報
        self._security_stop = False
        # N3 修補：alert nonce LRU 防 replay（攻擊者錄一筆 alert 重放讓訓練永久卡死）
        self._alert_replay_cache = ReplayCache()
        # N21/N23 修補：cascade-DoS 偵測（attacker 故意觸發 IDS → patrol/burger 永久 stop）
        self._alert_history: list[float] = []
        self._cascade_dos_quiet_until: float = 0.0

        # 啟動時先等 Gazebo /scan + /odom 真的活著再開始訓練（避免每個 ep 都 timeout）
        self._wait_for_simulator_ready(timeout=60.0)

        # 修補紅隊攻擊 J + K：啟動時檢查 /cmd_vel 跟 /scan publisher 來源
        self._check_cmd_vel_publishers()
        self._check_scan_publishers()

    # ── ROS2 Callbacks ────────────────────────────────────────────────────────

    def _scan_cb(self, msg: LaserScan):
        # 修補紅隊攻擊 K：scan poisoning 三重偵測
        new_scan = list(msg.ranges)
        if len(new_scan) > 50:
            try:
                arr = np.asarray(new_scan, dtype=np.float32)
                arr = np.where(np.isinf(arr) | np.isnan(arr), LIDAR_MAX, arr)
                std = float(np.std(arr))
                # (1) std 過低：粗糙偽造（全 3.5m 或全 1.0m 之類）
                if std < 0.01:
                    self.get_logger().warn(
                        f"⚠️ /scan std={std:.4f} 異常低（攻擊 K-1：粗糙偽造），跳過此幀"
                    )
                    return
                # (2) 與上一幀完全相同：攻擊者重複送同一個假 scan
                # 真實 lidar 即使靜止也有測量雜訊，每幀必有微差
                if self._raw_scan is not None and new_scan == self._raw_scan:
                    self.get_logger().warn(
                        "⚠️ /scan 與上一幀完全相同（攻擊 K-2：固定 pattern），跳過此幀"
                    )
                    return
                # (3) 95% 以上 bin 都接近 LIDAR_MAX：偽造「完全空曠」（真實場景幾乎不可能）
                near_max = float(np.sum(arr > 0.9 * LIDAR_MAX)) / len(arr)
                if near_max > 0.95:
                    self.get_logger().warn(
                        f"⚠️ /scan {near_max*100:.0f}% bin 接近 max（攻擊 K-3：偽造空曠），跳過此幀"
                    )
                    return
            except Exception:
                pass
        self._raw_scan = new_scan

    def _check_scan_publishers(self) -> None:
        """掃描 /scan publisher，提醒同 topic 上多個 publisher 是異常。

        正常只有 ros_gz_bridge（模擬）或 hokuyo/rplidar/ldlidar（實機）。
        多個 publisher 同時存在 = 攻擊 K 偽造 lidar 的徵兆。
        """
        try:
            infos = self.get_publishers_info_by_topic("/scan")
        except Exception as e:
            self.get_logger().warn(f"無法掃描 /scan publisher: {e}")
            return
        ALLOWED = {
            "ros_gz_bridge", "parameter_bridge",
            "hokuyo_driver", "rplidar_node", "ldlidar_node", "urg_node",
        }
        suspicious = [i for i in infos if i.node_name not in ALLOWED]
        if suspicious or len(infos) > 1:
            names = ", ".join(f"{i.node_namespace}/{i.node_name}" for i in infos)
            self.get_logger().error(
                f"🚨 /scan publisher 異常：{len(infos)} 個 publisher [{names}]  "
                "（可能是攻擊 K：偽造 lidar）"
            )
        else:
            self.get_logger().info(f"✓ /scan publisher 檢查通過（{len(infos)} 個）")

    def _odom_cb(self, msg: Odometry):
        self._robot_x = msg.pose.pose.position.x
        self._robot_y = msg.pose.pose.position.y
        q = msg.pose.pose.orientation
        self._robot_yaw = math.atan2(
            2.0 * (q.w * q.z + q.x * q.y),
            1.0 - 2.0 * (q.y ** 2 + q.z ** 2),
        )
        self._odom_received = True

    def _alert_cb(self, msg: String):
        # B + N3 + N4 修補：HMAC + channel binding + freshness + nonce LRU
        payload = verify_alert(
            msg.data, _ALERT_SECRET,
            expected_channel=CH_ALERTS,
            cache=self._alert_replay_cache,
        )
        if payload is None:
            # N15 修補：throttle 防 log storm
            self.get_logger().warn(
                f'⚠️ 收到未簽章/重放/過期的 /security/alerts，已忽略 (data 前 60 字: {msg.data[:60]!r})',
                throttle_duration_sec=5.0
            )
            return
        # N21/N23 修補：cascade-DoS 偵測（適配 RL：threshold 較高，因 episode 短）
        # 60s 內 10+ 次 alert → escalate + 後續 60s 不再 stop（讓訓練繼續，等人工）
        now = time.monotonic()
        if self._cascade_dos_quiet_until > now:
            self.get_logger().warn(
                f'⚠️ [cascade-DoS quiet] alert 收到但不 stop episode '
                f'(剩 {self._cascade_dos_quiet_until - now:.0f}s)',
                throttle_duration_sec=10.0)
            return
        self._alert_history.append(now)
        self._alert_history = [t for t in self._alert_history if now - t < 60.0]
        if len(self._alert_history) >= 10:
            self._cascade_dos_quiet_until = now + 60.0
            self.get_logger().error(
                f'🚨🚨🚨 [N21/N23 cascade-DoS] 60s 內 {len(self._alert_history)} 次 alert — '
                f'疑似 attacker 借力 DoS，後續 60s 不再 stop episode，等人工介入')
            return
        if not self._security_stop:
            self._security_stop = True
            self._publish_cmd(0.0, 0.0)
            self.get_logger().warn(f"🚨 收到資安警報（已驗章），停止訓練 episode: {payload[:60]}")

    # ── Gymnasium API ─────────────────────────────────────────────────────────

    def reset(self, *, seed=None, options=None) -> tuple[np.ndarray, dict]:
        super().reset(seed=seed)
        self._steps         = 0
        self._security_stop = False
        self._scan_failed   = False
        self._prev_lin_vel  = 0.0
        self._prev_ang_vel  = 0.0
        self._waypoints_done = 0
        self._ep_min_clearance = float("inf")
        self._publish_cmd(0.0, 0.0)

        # 用 gymnasium 提供的 self.np_random，seed=X 才會 deterministic
        rng = self.np_random

        # 隨機起點 + 隨機初始 yaw（避免機器人學到方向偏置）
        sx, sy = _random_safe_pos(rng)
        syaw = float(rng.uniform(-math.pi, math.pi))
        self._odom_received = False
        self._teleport(sx, sy, yaw=syaw)
        time.sleep(0.3)
        self._raw_scan = None
        self._wait_scan(timeout=SCAN_TIMEOUT)
        self._wait_odom(timeout=2.0)         # 確保 odom 已更新到 teleport 後位置
        self._spin_for(0.1)

        # 初始化巡邏佇列（隨機順序，增加訓練多樣性）
        wps = list(WAYPOINTS)
        rng.shuffle(wps)
        self._waypoint_queue = wps
        self._current_wp = self._waypoint_queue.pop(0)
        # 初始化 prev_dist（給 progress reward 用），避免第一步算出超大的 progress
        self._prev_dist, _ = self._wp_info()

        return self._get_state(), {}

    def step(self, action: np.ndarray) -> tuple[np.ndarray, float, bool, bool, dict]:
        self._steps += 1

        if self._security_stop:
            self._publish_cmd(0.0, 0.0)
            return self._get_state(), -100.0, True, False, self._build_info(event="security_stop")

        # 防呆：NaN/Inf 的 action 強制歸零（防止 critic 爆炸時送壞命令進機器人）
        action = np.asarray(action, dtype=np.float32)
        if not np.all(np.isfinite(action)):
            self.get_logger().error(f"⚠️ 收到 non-finite action: {action}，視為碰撞結束 episode")
            self._publish_cmd(0.0, 0.0)
            return self._get_state(), -100.0, True, False, self._build_info(event="collision")
        # action 必須在 [-1, 1]（SAC 偶爾會超出邊界）
        action = np.clip(action, -1.0, 1.0)

        lin_cmd = float((action[0] + 1.0) / 2.0 * MAX_LIN_VEL)
        ang_cmd = float(action[1] * MAX_ANG_VEL)
        self._publish_cmd(lin_cmd, ang_cmd)

        self._raw_scan = None
        scan_ok = self._wait_scan(timeout=SCAN_TIMEOUT)
        self._spin_for(0.05)

        # scan 卡住 → 視為環境失效，提早結束 episode，避免 SAC 學到「看不到障礙的世界」
        if not scan_ok:
            self.get_logger().error(f"⚠️ /scan {SCAN_TIMEOUT}s 沒更新，終止 episode")
            self._publish_cmd(0.0, 0.0)
            self._scan_failed = True
            return self._get_state(), -100.0, True, False, self._build_info(event="scan_timeout")

        self._prev_lin_vel = lin_cmd
        self._prev_ang_vel = ang_cmd

        reward, terminated, event = self._compute_reward(lin_cmd, ang_cmd)
        truncated = self._steps >= MAX_STEPS and not terminated
        if truncated and event == "running":
            event = "timeout"

        return self._get_state(), reward, terminated, truncated, self._build_info(event=event)

    def _build_info(self, event: str) -> dict:
        """組合 episode 統計資訊給 callback 使用。"""
        return {
            "event":             event,                  # collision / waypoint / all_done / timeout / running / security_stop
            "waypoints_done":    self._waypoints_done,   # 該 ep 累計到達的 waypoint 數
            "total_waypoints":   len(WAYPOINTS),
            "min_clearance":     self._ep_min_clearance, # 該 ep 最近的障礙物距離
            "is_collision":      event == "collision",
            "is_full_success":   event == "all_done",
            "is_timeout":        event == "timeout",
        }

    def close(self):
        self._publish_cmd(0.0, 0.0)

    # ── 核心：論文的觀測值建構 ─────────────────────────────────────────────────

    def _get_state(self) -> np.ndarray:
        """論文格式 25 維觀測，所有維度正規化至 observation_space 邊界。"""
        raw = self._raw_scan if self._raw_scan else [LIDAR_MAX] * 360
        scan = np.array(raw, dtype=np.float32)
        scan = np.where(np.isinf(scan) | np.isnan(scan), LIDAR_MAX, scan)
        scan = np.clip(scan, 0.0, LIDAR_MAX)

        # 分成 N_SCAN_BINS 個 bin，每個 bin 取最小值
        bin_size = max(1, int(np.ceil(len(scan) / N_SCAN_BINS)))
        bins: list[float] = []
        for i in range(0, len(scan), bin_size):
            bins.append(float(scan[i : i + bin_size].min()))
            if len(bins) == N_SCAN_BINS:
                break
        while len(bins) < N_SCAN_BINS:
            bins.append(LIDAR_MAX)

        # 正規化 LiDAR → [0, 1]
        bins_norm = [b / LIDAR_MAX for b in bins]

        dist, angle = self._wp_info()

        state = (
            bins_norm
            + [
                min(dist / DIST_MAX, 1.0),          # [0, 1]
                math.cos(angle),                     # [-1, 1]
                math.sin(angle),                     # [-1, 1]
                self._prev_lin_vel / MAX_LIN_VEL,   # [0, 1]
                self._prev_ang_vel / MAX_ANG_VEL,   # [-1, 1]
            ]
        )
        return np.array(state, dtype=np.float32)

    # ── 論文 Reward ───────────────────────────────────────────────────────────

    def _compute_reward(self, lin_vel: float, ang_vel: float) -> tuple[float, bool, str]:
        raw = self._raw_scan if self._raw_scan else [LIDAR_MAX] * 360
        scan = np.array(raw, dtype=np.float32)
        scan = np.where(np.isinf(scan) | np.isnan(scan), LIDAR_MAX, scan)
        min_range = float(scan.min())
        if min_range < self._ep_min_clearance:
            self._ep_min_clearance = min_range

        # 碰撞 → -100，終止
        if min_range <= COLLISION_DIST:
            self._publish_cmd(0.0, 0.0)
            return -100.0, True, "collision"

        # 到達巡邏點 → +100
        dist, _ = self._wp_info()
        if dist < WAYPOINT_REACH and self._current_wp is not None:
            name = self._current_wp.name
            self._waypoints_done += 1
            if self._waypoint_queue:
                self._current_wp = self._waypoint_queue.pop(0)
                # 切換目標後重設 prev_dist，避免「換目標瞬間」算出超大 progress
                self._prev_dist, _ = self._wp_info()
                self.get_logger().info(f"✅ 到達 {name} → 下一目標: {self._current_wp.name}")
                return 100.0, False, "waypoint"
            else:
                self.get_logger().info("✅ 完成所有巡邏點！")
                return 100.0, True, "all_done"

        # Progress reward — 距離 waypoint 變近就獎勵，遠離就扣分
        # 每步 robot 最多走 0.22*0.15 ≈ 0.033 m，× 10 = ±0.33 /step
        # 目標：讓「走錯方向」比「躺平」還慘（負分），「走對方向」明顯比「躺平」好（正分）
        # 配合 waypoint bonus +100 / 碰撞 -100，agent 應該學到「靠近目標 + 避障」
        progress = self._prev_dist - dist
        self._prev_dist = dist
        progress_reward = 10.0 * progress

        # 論文 reward：鼓勵前進，懲罰轉圈，靠牆懲罰
        obstacle_penalty = max(0.0, 1.35 - min_range) / 2.0
        reward = lin_vel - abs(ang_vel) / 2.0 - obstacle_penalty + progress_reward
        return float(reward), False, "running"

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _wp_info(self) -> tuple[float, float]:
        if self._current_wp is None:
            return 999.0, 0.0
        dx = self._current_wp.x - self._robot_x
        dy = self._current_wp.y - self._robot_y
        dist = math.hypot(dx, dy)
        angle = math.atan2(dy, dx) - self._robot_yaw
        while angle >  math.pi: angle -= 2 * math.pi
        while angle < -math.pi: angle += 2 * math.pi
        return dist, angle

    def _teleport(self, x: float, y: float, yaw: float = 0.0):
        """把機器人傳送到 (x, y) 並設定朝向 yaw（弧度）。"""
        # yaw → quaternion (Z 軸旋轉)
        qz = math.sin(yaw / 2.0)
        qw = math.cos(yaw / 2.0)
        env = os.environ.copy()
        env["GZ_IP"] = "127.0.0.1"
        result = subprocess.run([
            "gz", "service", "-s", "/world/default/set_pose",
            "--reqtype", "gz.msgs.Pose",
            "--reptype", "gz.msgs.Boolean",
            "--timeout", "3000",
            "--req",
            f'name: "burger", '
            f'position: {{x: {x}, y: {y}, z: 0.05}}, '
            f'orientation: {{x: 0.0, y: 0.0, z: {qz}, w: {qw}}}',
        ], capture_output=True, env=env)
        if result.returncode != 0:
            self.get_logger().warn(
                f'Teleport 失敗 (rc={result.returncode}): {result.stderr.decode()[:120]}'
            )

    def _check_cmd_vel_publishers(self) -> None:
        """掃描 domain 內 /cmd_vel 的 publisher，發現未預期 publisher 就 warn。

        合法 publisher：
          - burger_sac_env       (自己，SAC 訓練)
          - teleop_keyboard      (部署時 teleop)
          - patrol_node          (部署時自動巡邏)
          - dds_security_monitor (emergency stop = 合法用途)
        若看到陌生 node，可能是攻擊 J（namesake hijack）的徵兆。
        """
        try:
            infos = self.get_publishers_info_by_topic("/cmd_vel")
        except Exception as e:
            self.get_logger().warn(f"無法掃描 /cmd_vel publisher: {e}")
            return
        ALLOWED = {
            "burger_sac_env",
            "teleop_keyboard",
            "patrol_node",
            "dds_security_monitor",
        }
        suspicious = [i for i in infos if i.node_name not in ALLOWED]
        if suspicious:
            names = ", ".join(f"{i.node_namespace}/{i.node_name}" for i in suspicious)
            self.get_logger().error(
                f"🚨 偵測到 /cmd_vel 上有非預期 publisher: {names}  "
                "（可能是攻擊 J：同名節點搶控制）"
            )
        else:
            self.get_logger().info(f"✓ /cmd_vel publisher 檢查通過（{len(infos)} 個合法）")

    def _wait_for_simulator_ready(self, timeout: float = 60.0) -> None:
        """啟動時阻塞等 Gazebo bridge 把 /scan + /odom 接通才回。

        如果不等：reset() 第一次呼叫時 _wait_scan timeout (2s) → fake scan → 第一個 step
        又 timeout → -100 → 每個失敗 ep 浪費 4s。Gazebo 啟動慢時可能跑 100+ 個失敗 ep
        才終於 ready，那段時間 buffer 全是廢資料。
        """
        self.get_logger().info(f"等待 Gazebo /scan + /odom 就緒（最多 {timeout:.0f}s）…")
        t0 = time.time()
        while time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.2)
            if self._raw_scan is not None and self._odom_received:
                elapsed = time.time() - t0
                self.get_logger().info(f"✅ Gazebo 就緒（耗時 {elapsed:.1f}s）— 開始訓練")
                # 清掉 init 階段的舊資料，讓 reset 自己重抓
                self._raw_scan = None
                self._odom_received = False
                return
        self.get_logger().error(
            f"❌ 等待 {timeout:.0f}s 仍未收到 /scan 或 /odom，"
            "Gazebo 可能沒啟動或 ros_gz_bridge 沒設好"
        )

    def _wait_scan(self, timeout: float = 2.0) -> bool:
        """等到收到新 scan 或 timeout。回傳 True 表示成功收到。"""
        t0 = time.time()
        while self._raw_scan is None and time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.1)
        return self._raw_scan is not None

    def _wait_odom(self, timeout: float = 2.0) -> bool:
        """等到 odom callback 被觸發（teleport 後 robot 位置已更新）。"""
        t0 = time.time()
        while not self._odom_received and time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.1)
        if not self._odom_received:
            self.get_logger().warn(f'_wait_odom timeout {timeout}s，robot 位置可能不準確')
        return self._odom_received

    def _spin_for(self, sec: float):
        t0 = time.time()
        while time.time() - t0 < sec:
            rclpy.spin_once(self, timeout_sec=0.05)

    def _publish_cmd(self, linear: float, angular: float):
        msg = TwistStamped()
        msg.header.stamp    = self.get_clock().now().to_msg()
        msg.header.frame_id = "base_link"
        msg.twist.linear.x  = float(linear)
        msg.twist.angular.z = float(angular)
        self._cmd_pub.publish(msg)
