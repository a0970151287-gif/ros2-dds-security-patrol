"""ROS2 Gymnasium 環境 — 純避障版本（規則固定不動）

State:  24 個 LiDAR 扇區（正規化 0~1）
Action: 5 個動作，線速度固定 0.2 m/s
Reward: 直行加分 / 靠牆扣分 / 撞牆 -50
"""
import math
import os
import random
import subprocess
import time

import numpy as np
import gymnasium as gym
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped
from nav_msgs.msg import Odometry
from sensor_msgs.msg import LaserScan
from std_msgs.msg import String
from rclpy.qos import QoSProfile, ReliabilityPolicy

# 探索格子設定（arena 約 -2.5~2.5m）
GRID_SIZE  = 12        # 12×12 格子
GRID_MIN   = -2.5
GRID_MAX   =  2.5
EXPLORE_BONUS = 3.0    # 踏入新格子的獎勵

STATE_SIZE     = 24
ACTION_SIZE    = 5
LINEAR_VEL     = 0.2
COLLISION_DIST = 0.18   # 碰撞距離
DANGER_DIST    = 0.30   # 危險區邊界
NAV_DIST       = 0.80   # 導航區上限（最佳導航距離帶）
OPTIMAL_DIST   = 0.50   # 最佳距離（獎勵最高點）
MAX_STEPS      = 300

# 5 個動作：角速度從急左到急右
ANGULAR_VELS = [1.5, 0.75, 0.0, -0.75, -1.5]
ACTIONS = [[LINEAR_VEL, av] for av in ANGULAR_VELS]

# 安全起點（避開柱子：柱子在 ±1.1 的格點）
START_POSITIONS = [
    (-2.0, -0.5),
    (-0.5, -0.5),
    ( 0.5, -0.5),
    (-0.5,  0.5),
    ( 0.5,  0.5),
    (-2.0,  0.5),
]


class TurtleBot3Env(gym.Env, Node):
    metadata = {'render_modes': []}

    def __init__(self):
        Node.__init__(self, 'dqn_environment')
        gym.Env.__init__(self)

        qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        self._scan_sub  = self.create_subscription(LaserScan, '/scan',            self._scan_cb,  qos)
        self._odom_sub  = self.create_subscription(Odometry,  '/odom',            self._odom_cb,  qos)
        self._alert_sub = self.create_subscription(String,    '/security/alerts', self._alert_cb, qos)
        self._cmd_pub   = self.create_publisher(TwistStamped, '/cmd_vel', 10)

        self.observation_space = gym.spaces.Box(
            low=0.0, high=1.0, shape=(STATE_SIZE,), dtype=np.float32
        )
        self.action_space = gym.spaces.Discrete(ACTION_SIZE)

        self._scan:          np.ndarray | None = None
        self._robot_x        = 0.0
        self._robot_y        = 0.0
        self._odom_received  = False
        self._steps          = 0
        self._security_stop  = False
        self._scan_failed    = False
        self._pos_history:   list = []
        self._stuck_steps    = 0
        self._visit_count: dict = {}   # 格子 (i,j) → 累計訪問次數（跨集不清）

    def _scan_cb(self, msg: LaserScan):
        r = np.array(msg.ranges, dtype=np.float32)
        r[np.isnan(r) | np.isinf(r)] = 3.5
        r = np.clip(r, 0.0, 3.5)
        n   = len(r)
        sec = n // STATE_SIZE
        self._scan = np.array(
            [r[i * sec:(i + 1) * sec].min() for i in range(STATE_SIZE)],
            dtype=np.float32,
        )

    def _odom_cb(self, msg: Odometry):
        self._robot_x = msg.pose.pose.position.x
        self._robot_y = msg.pose.pose.position.y
        self._odom_received = True

    def _alert_cb(self, msg: String):
        if not self._security_stop:
            self._security_stop = True
            self._publish_cmd(0.0, 0.0)

    def _wait_scan(self, timeout=5.0) -> bool:
        """等到收到新 scan 或 timeout。回傳 True 表示成功收到。"""
        t0 = time.time()
        while self._scan is None and time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.1)
        return self._scan is not None

    def _wait_odom(self, timeout=2.0) -> bool:
        """等到收到新 odom（teleport 後的位置）。"""
        t0 = time.time()
        while not self._odom_received and time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.1)
        return self._odom_received

    def reset(self, *, seed=None, options=None, episode=0):
        super().reset(seed=seed)
        self._steps         = 0
        self._security_stop = False
        self._scan_failed   = False
        self._scan          = None
        self._odom_received = False
        self._pos_history   = []
        self._stuck_steps   = 0
        # _visit_count 跨集保留，不清除
        self._publish_cmd(0.0, 0.0)

        env_copy = os.environ.copy()
        env_copy['GZ_IP'] = '127.0.0.1'

        def _teleport(px, py):
            subprocess.run([
                'gz', 'service', '-s', '/world/default/set_pose',
                '--reqtype', 'gz.msgs.Pose',
                '--reptype', 'gz.msgs.Boolean',
                '--timeout', '3000',
                '--req',
                f'name: "burger", '
                f'position: {{x: {px}, y: {py}, z: 0.05}}, '
                f'orientation: {{x: 0.0, y: 0.0, z: 0.0, w: 1.0}}',
            ], capture_output=True, env=env_copy)

        def _scan_safe() -> bool:
            for _ in range(10):
                self._scan = None
                self._wait_scan(timeout=2.0)
                if self._scan is not None and self._scan.min() > 0.45:
                    return True
                time.sleep(0.2)
            return False

        # 用 gymnasium 提供的 self.np_random，seed=X 才會 deterministic
        positions = START_POSITIONS.copy()
        self.np_random.shuffle(positions)
        for sx, sy in positions:
            _teleport(sx, sy)
            time.sleep(0.5)
            self._publish_cmd(0.0, 0.0)
            time.sleep(0.3)
            if _scan_safe():
                break
        else:
            _teleport(0.0, -0.5)
            time.sleep(0.6)
            self._publish_cmd(0.0, 0.0)
            _scan_safe()

        # 確保 odom 已更新（避免用上個 episode 的位置算 reward）
        self._wait_odom(timeout=2.0)
        self._publish_cmd(0.0, 0.0)
        time.sleep(0.4)
        return self._get_obs(), {}

    def step(self, action):
        self._steps += 1

        if self._security_stop:
            self._publish_cmd(0.0, 0.0)
            return self._get_obs(), -50.0, True, False, {}

        lin, ang = ACTIONS[action]
        self._publish_cmd(lin, ang)

        self._scan = None
        scan_ok = self._wait_scan(timeout=2.0)

        # scan 卡住 → 提早結束 episode，避免 DQN 學到「看不到障礙的世界」
        if not scan_ok:
            self.get_logger().error("⚠️ /scan 2s 沒更新，終止 episode")
            self._publish_cmd(0.0, 0.0)
            self._scan_failed = True
            return self._get_obs(), -50.0, True, False, {}

        obs    = self._get_obs()
        reward, terminated = self._compute_reward(action)
        return obs, reward, terminated, self._steps >= MAX_STEPS, {}

    def close(self):
        self._publish_cmd(0.0, 0.0)

    def _get_obs(self) -> np.ndarray:
        s = self._scan if self._scan is not None else np.full(STATE_SIZE, 3.5, dtype=np.float32)
        return (s / 3.5).astype(np.float32)  # 正規化到 [0, 1]

    def _compute_reward(self, action) -> tuple[float, bool]:
        scan = self._scan if self._scan is not None else np.full(STATE_SIZE, 3.5, dtype=np.float32)
        min_range = float(scan.min())

        # ── 1. 撞牆終止 ────────────────────────────────────────────────────────
        if min_range <= COLLISION_DIST:
            self._publish_cmd(0.0, 0.0)
            return -50.0, True

        # ── 2. 前進效率獎勵（直行 +1.0，急轉 +0.5）────────────────────────────
        ang_ratio  = abs(ANGULAR_VELS[action]) / 1.5
        move_reward = 1.0 - 0.5 * ang_ratio

        # ── 3. 最佳距離區間獎勵（核心）────────────────────────────────────────
        # 危險區（< 0.30m）：線性懲罰，最深 -3.0
        # 導航區（0.30~0.80m）：拋物線，最高 +2.0（峰值在 0.50m）
        # 空曠區（> 0.80m）：不加不扣
        if min_range < DANGER_DIST:
            t    = (min_range - COLLISION_DIST) / (DANGER_DIST - COLLISION_DIST)
            zone = -3.0 * (1.0 - t)                 # 0.18m=-3, 0.30m=0
        elif min_range < NAV_DIST:
            t    = (min_range - DANGER_DIST) / (NAV_DIST - DANGER_DIST)    # 0~1
            opt  = (OPTIMAL_DIST - DANGER_DIST) / (NAV_DIST - DANGER_DIST) # ~0.4
            zone = 2.0 * max(0.0, 1.0 - ((t - opt) / max(1.0 - opt, opt)) ** 2)
        else:
            zone = 0.0                               # 空曠區，不加不扣

        # ── 4. 探索獎勵（去越少去的地方加越多，跨集累計）──────────────────────
        gx = int((self._robot_x - GRID_MIN) / (GRID_MAX - GRID_MIN) * GRID_SIZE)
        gy = int((self._robot_y - GRID_MIN) / (GRID_MAX - GRID_MIN) * GRID_SIZE)
        gx = max(0, min(GRID_SIZE - 1, gx))
        gy = max(0, min(GRID_SIZE - 1, gy))
        cell = (gx, gy)
        n    = self._visit_count.get(cell, 0)
        self._visit_count[cell] = n + 1
        explore = 2.0 / (1.0 + 0.3 * n)            # 首次 +2.0，漸漸降低

        return move_reward + zone + explore, False

    def _publish_cmd(self, linear, angular):
        msg = TwistStamped()
        msg.header.stamp    = self.get_clock().now().to_msg()
        msg.header.frame_id = 'base_link'
        msg.twist.linear.x  = float(linear)
        msg.twist.angular.z = float(angular)
        self._cmd_pub.publish(msg)
