"""
BurgerEnv — TurtleBot3 Burger Gymnasium Environment for SAC
完全照論文實作：reiniscimurs/DRL-Robot-Navigation-ROS2

觀測空間（state_dim = 25）：
  [20 LiDAR bins (min per bin)] + [dist] + [cos(angle)] + [sin(angle)]
  + [prev_lin_vel] + [prev_ang_vel]

不使用 frame stacking（論文原始設計）
每個 bin 取最小值（最保守，看到每個方向最近的障礙物）

Reward：
  +100 到達目標
  -100 碰撞
  else: lin_vel - abs(ang_vel)/2 - obstacle_penalty/2
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

# ── 論文參數（不要隨便改）────────────────────────────────────────────────────
N_SCAN_BINS    = 20      # 20 個 LiDAR bins，每 bin 取最小值（論文做法）
STATE_DIM      = 25      # 20 + dist + cos + sin + lin_vel + ang_vel
MAX_LIN_VEL    = 0.25
MAX_ANG_VEL    = 1.5
COLLISION_DIST = 0.18    # Burger 機器人碰撞距離
WAYPOINT_REACH = 0.30    # 到達門檻（Burger 較小，用 0.30m）
MAX_STEPS      = 500

# ── 障礙物位置（Gazebo 世界中的柱子）────────────────────────────────────────
CYLINDERS = [
    (-1.1, -1.1), (-1.1, 0.0), (-1.1, 1.1),
    ( 0.0, -1.1), ( 0.0, 0.0), ( 0.0, 1.1),
    ( 1.1, -1.1), ( 1.1, 0.0), ( 1.1, 1.1),
]


# ── 巡邏點定義 ────────────────────────────────────────────────────────────────
@dataclass
class Waypoint:
    name:          str
    x:             float
    y:             float
    arrival_bonus: float

WAYPOINTS = [
    Waypoint("電源控制室", -1.5, -1.5, 100.0),
    Waypoint("冷卻水塔",    1.5, -1.5, 100.0),
    Waypoint("生產線A",   -1.5,  1.5, 100.0),
    Waypoint("生產線B",    1.5,  1.5, 100.0),
    Waypoint("出入口",     0.0, -1.8, 100.0),
]


def _is_safe(x: float, y: float, clearance: float = 0.50) -> bool:
    if abs(x) > 1.8 or abs(y) > 1.8:
        return False
    for cx, cy in CYLINDERS:
        if math.hypot(x - cx, y - cy) < clearance:
            return False
    return True


def _random_safe_pos() -> tuple[float, float]:
    for _ in range(2000):
        x = random.uniform(-1.8, 1.8)
        y = random.uniform(-1.8, 1.8)
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
        qos_sec = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )

        self._scan_sub  = self.create_subscription(LaserScan, "/scan",            self._scan_cb,  qos)
        self._odom_sub  = self.create_subscription(Odometry,  "/odom",            self._odom_cb,  qos)
        self._alert_sub = self.create_subscription(String,    "/security/alerts", self._alert_cb, qos_sec)
        self._cmd_pub   = self.create_publisher(TwistStamped, "/cmd_vel", 10)

        # observation_space = 25 維，無 frame stack
        self.observation_space = spaces.Box(
            low=-1.0, high=1.0, shape=(STATE_DIM,), dtype=np.float32
        )
        self.action_space = spaces.Box(
            low=-1.0, high=1.0, shape=(2,), dtype=np.float32
        )

        # 感測器狀態
        self._raw_scan:    list | None = None
        self._robot_x      = 0.0
        self._robot_y      = 0.0
        self._robot_yaw    = 0.0
        self._prev_lin_vel = 0.0
        self._prev_ang_vel = 0.0
        self._steps        = 0

        # 巡邏狀態
        self._waypoint_queue: list[Waypoint] = []
        self._current_wp:     Waypoint | None = None

        # 資安警報
        self._security_stop = False

    # ── ROS2 Callbacks ────────────────────────────────────────────────────────

    def _scan_cb(self, msg: LaserScan):
        # 儲存完整原始 scan，讓 prepare_state 做 binning
        self._raw_scan = list(msg.ranges)

    def _odom_cb(self, msg: Odometry):
        self._robot_x = msg.pose.pose.position.x
        self._robot_y = msg.pose.pose.position.y
        q = msg.pose.pose.orientation
        self._robot_yaw = math.atan2(
            2.0 * (q.w * q.z + q.x * q.y),
            1.0 - 2.0 * (q.y ** 2 + q.z ** 2),
        )

    def _alert_cb(self, msg: String):
        if not self._security_stop:
            self._security_stop = True
            self._publish_cmd(0.0, 0.0)
            self.get_logger().warn("🚨 收到資安警報，停止訓練 episode")

    # ── Gymnasium API ─────────────────────────────────────────────────────────

    def reset(self, *, seed=None, options=None) -> tuple[np.ndarray, dict]:
        super().reset(seed=seed)
        self._steps        = 0
        self._security_stop = False
        self._prev_lin_vel  = 0.0
        self._prev_ang_vel  = 0.0
        self._publish_cmd(0.0, 0.0)

        # 隨機起點
        sx, sy = _random_safe_pos()
        self._teleport(sx, sy)
        time.sleep(0.3)
        self._raw_scan = None
        self._wait_scan(timeout=5.0)
        self._spin_for(0.1)

        # 初始化巡邏佇列（隨機順序，增加訓練多樣性）
        self._waypoint_queue = random.sample(WAYPOINTS, len(WAYPOINTS))
        self._current_wp = self._waypoint_queue.pop(0)

        return self._get_state(), {}

    def step(self, action: np.ndarray) -> tuple[np.ndarray, float, bool, bool, dict]:
        self._steps += 1

        if self._security_stop:
            self._publish_cmd(0.0, 0.0)
            return self._get_state(), -100.0, True, False, {}

        lin_cmd = float((action[0] + 1.0) / 2.0 * MAX_LIN_VEL)
        ang_cmd = float(action[1] * MAX_ANG_VEL)
        self._publish_cmd(lin_cmd, ang_cmd)

        self._raw_scan = None
        self._wait_scan()
        self._spin_for(0.05)

        self._prev_lin_vel = lin_cmd
        self._prev_ang_vel = ang_cmd

        reward, terminated = self._compute_reward(lin_cmd, ang_cmd)
        truncated = self._steps >= MAX_STEPS

        return self._get_state(), reward, terminated, truncated, {}

    def close(self):
        self._publish_cmd(0.0, 0.0)

    # ── 核心：論文的觀測值建構 ─────────────────────────────────────────────────

    def _get_state(self) -> np.ndarray:
        """
        完全照論文：
        1. 把全部 LiDAR 點分成 N_SCAN_BINS=20 個 bin
        2. 每個 bin 取最小值（最近障礙物）
        3. inf → 7.0（論文做法）
        4. 加上 dist, cos(angle), sin(angle), prev_lin, prev_ang
        """
        raw = self._raw_scan if self._raw_scan else [7.0] * 360
        scan = np.array(raw, dtype=np.float32)
        scan = np.where(np.isinf(scan), 7.0, scan)
        scan = np.clip(scan, 0.0, 7.0)

        # 分成 N_SCAN_BINS 個 bin，每個 bin 取最小值
        bin_size = max(1, int(np.ceil(len(scan) / N_SCAN_BINS)))
        bins = []
        for i in range(0, len(scan), bin_size):
            b = scan[i : i + bin_size]
            bins.append(float(b.min()))
            if len(bins) == N_SCAN_BINS:
                break

        # 如果 bin 數不夠，補 7.0
        while len(bins) < N_SCAN_BINS:
            bins.append(7.0)

        # 目標方向
        dist, angle = self._wp_info()

        # 組合成 25 維 state（論文格式）
        state = (
            bins
            + [dist, math.cos(angle), math.sin(angle)]
            + [self._prev_lin_vel, self._prev_ang_vel]
        )
        return np.array(state, dtype=np.float32)

    # ── 論文 Reward ───────────────────────────────────────────────────────────

    def _compute_reward(self, lin_vel: float, ang_vel: float) -> tuple[float, bool]:
        raw = self._raw_scan if self._raw_scan else [7.0] * 360
        scan = np.array(raw, dtype=np.float32)
        scan = np.where(np.isinf(scan), 7.0, scan)
        min_range = float(scan.min())

        # 碰撞 → -100，終止
        if min_range <= COLLISION_DIST:
            self._publish_cmd(0.0, 0.0)
            return -100.0, True

        # 到達巡邏點 → +100
        dist, _ = self._wp_info()
        if dist < WAYPOINT_REACH and self._current_wp is not None:
            name = self._current_wp.name
            if self._waypoint_queue:
                self._current_wp = self._waypoint_queue.pop(0)
                self.get_logger().info(f"✅ 到達 {name} → 下一目標: {self._current_wp.name}")
                return 100.0, False
            else:
                self.get_logger().info(f"✅ 完成所有巡邏點！")
                return 100.0, True

        # 論文 reward：鼓勵前進，懲罰轉圈，靠牆懲罰
        obstacle_penalty = max(0.0, 1.35 - min_range) / 2.0
        reward = lin_vel - abs(ang_vel) / 2.0 - obstacle_penalty
        return float(reward), False

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

    def _teleport(self, x: float, y: float):
        env = os.environ.copy()
        env["GZ_IP"] = "127.0.0.1"
        subprocess.run([
            "gz", "service", "-s", "/world/default/set_pose",
            "--reqtype", "gz.msgs.Pose",
            "--reptype", "gz.msgs.Boolean",
            "--timeout", "3000",
            "--req",
            f'name: "burger", '
            f'position: {{x: {x}, y: {y}, z: 0.05}}, '
            f'orientation: {{x: 0.0, y: 0.0, z: 0.0, w: 1.0}}',
        ], capture_output=True, env=env)

    def _wait_scan(self, timeout: float = 5.0):
        t0 = time.time()
        while self._raw_scan is None and time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.1)

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
