"""
BurgerEnvTop — Tier-1 TQC training environment for TurtleBot3 Burger.

Upgrades over burger_env.py (v1):
    1. Raw 180-beam lidar instead of 20 min-pooled bins
       — spatial structure preserved for 1D-Conv encoder
    2. Frame stack K=4 — temporal velocity/accel inferable from obs alone
    3. Potential-based reward shaping (Ng-Harada-Russell 1999)
       — preserves optimal policy under shaping (theoretically grounded)
    4. Domain randomization (lidar noise / dropout / max-vel jitter)
       — sim2real ready
    5. Curriculum-aware waypoint queue (1..stage samples per episode)
    6. Adversarial training mode (subtle lidar bias / noise burst /
       action-feedback jam) — robust under DDS-layer attacks
    7. Event-driven reset (no wall-clock sleep) — deterministic timing
    8. SPL (Anderson 2018) metric in info dict — Habitat-grade eval

Obs (per frame, then K-stacked, then flattened):
    lidar (180)    : ranges normalized to [0,1] via /LIDAR_MAX_M
    state (6)      : [dist_norm, cos(angle), sin(angle),
                      prev_lin_norm, prev_ang_norm, time_norm]
    per-frame = 186; K=4 → 744-dim flat Box

Action: Box[-1,1]^2 → (lin ∈ [0, max_lin_eff], ang ∈ [-max_ang_eff, +max_ang_eff])

Reward (per step):
    r_collide = -100               (terminal)
    r_reach   = +100               (per waypoint)
    r_shape   = γ·Φ(s') - Φ(s)     Φ = -dist_to_goal  (optimality-preserving)
    r_smooth  = -0.05·‖a_t - a_{t-1}‖²
    r_time    = -0.005
"""
from __future__ import annotations

import math
import os
import subprocess
import time
from collections import deque
from dataclasses import dataclass

import numpy as np
import gymnasium as gym
from gymnasium import spaces
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped
from nav_msgs.msg import Odometry
from sensor_msgs.msg import LaserScan
from rclpy.qos import QoSProfile, ReliabilityPolicy

# ── Spec constants ────────────────────────────────────────────────────────
LIDAR_BEAMS    = 180
STATE_DIM      = 6
FRAME_STACK    = 4
PER_FRAME      = LIDAR_BEAMS + STATE_DIM
OBS_DIM        = FRAME_STACK * PER_FRAME

LIDAR_MAX_M    = 3.5
DIST_MAX_M     = 4.5

MAX_LIN_NOMINAL = 0.22
MAX_ANG_NOMINAL = 1.5
COLLISION_DIST  = 0.18
WAYPOINT_REACH  = 0.30

MAX_STEPS       = 500
SCAN_TIMEOUT_S  = 2.0
GAMMA_SHAPING   = 0.99

W_COLLIDE       = -100.0
W_REACH         =  100.0
W_SMOOTH        =  0.05
W_TIME          =  0.005

DR_LIDAR_NOISE_STD = (0.0, 0.02)
DR_LIDAR_DROPOUT_P = (0.0, 0.05)
DR_MAX_LIN_RANGE   = (0.18, 0.22)
DR_MAX_ANG_RANGE   = (1.2, 1.8)

ADV_LIDAR_BIAS_P   = 0.05
ADV_NOISE_BURST_P  = 0.05
ADV_ACTION_JAM_P   = 0.05

CYLINDERS = [
    (-1.1, -1.1), (-1.1, 0.0), (-1.1, 1.1),
    ( 0.0, -1.1), ( 0.0, 0.0), ( 0.0, 1.1),
    ( 1.1, -1.1), ( 1.1, 0.0), ( 1.1, 1.1),
]


@dataclass
class Waypoint:
    name: str
    x: float
    y: float


WAYPOINTS_ALL = [
    Waypoint("電源控制室", -1.5, -1.5),
    Waypoint("冷卻水塔",    1.5, -1.5),
    Waypoint("生產線A",   -1.5,  1.5),
    Waypoint("生產線B",    1.5,  1.5),
    Waypoint("出入口",     0.0, -1.8),
]
N_WP_TOTAL = len(WAYPOINTS_ALL)


def _is_safe(x: float, y: float, clearance: float = 0.50) -> bool:
    if abs(x) > 1.8 or abs(y) > 1.8:
        return False
    for cx, cy in CYLINDERS:
        if math.hypot(x - cx, y - cy) < clearance:
            return False
    return True


def _random_safe_pos(rng) -> tuple[float, float]:
    for _ in range(2000):
        x = float(rng.uniform(-1.8, 1.8))
        y = float(rng.uniform(-1.8, 1.8))
        if _is_safe(x, y):
            return x, y
    return 0.5, 0.5


class BurgerEnvTop(gym.Env, Node):
    """Tier-1 SAC/TQC navigation env. Single Gazebo Burger instance."""

    metadata = {"render_modes": []}

    def __init__(
        self,
        eval_mode: bool = False,
        curriculum_max_wp: int = N_WP_TOTAL,
        node_name: str = "burger_env_top",
    ) -> None:
        Node.__init__(self, node_name)
        gym.Env.__init__(self)
        self.eval_mode = eval_mode
        self.curriculum_max_wp = max(1, min(N_WP_TOTAL, curriculum_max_wp))

        # Flat Box obs; structure interpreted by LiDARConvExtractor
        self.observation_space = spaces.Box(
            low=-2.0, high=2.0, shape=(OBS_DIM,), dtype=np.float32
        )
        self.action_space = spaces.Box(
            low=-1.0, high=1.0, shape=(2,), dtype=np.float32
        )

        qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        self._scan_sub = self.create_subscription(LaserScan, "/scan", self._scan_cb, qos)
        self._odom_sub = self.create_subscription(Odometry,  "/odom", self._odom_cb, qos)
        self._cmd_pub  = self.create_publisher(TwistStamped, "/cmd_vel", 10)

        self._raw_scan: np.ndarray | None = None
        self._x = self._y = self._yaw = 0.0
        self._odom_ok = False

        self._frame_buffer: deque[np.ndarray] = deque(maxlen=FRAME_STACK)
        self._prev_action = np.zeros(2, dtype=np.float32)

        self._steps = 0
        self._waypoint_queue: list[Waypoint] = []
        self._current_wp: Waypoint | None = None
        self._prev_dist = 0.0
        self._path_length = 0.0
        self._optimal_length = 0.0
        self._prev_pos = (0.0, 0.0)
        self._waypoints_done = 0
        self._n_wp_total_ep = 0
        self._ep_min_clearance = float("inf")

        # DR / adversarial sampled per-episode
        self._dr_noise = 0.0
        self._dr_dropout = 0.0
        self._dr_max_lin = MAX_LIN_NOMINAL
        self._dr_max_ang = MAX_ANG_NOMINAL
        self._adv_lidar_bias = 0.0
        self._adv_noise_burst = False
        self._adv_action_jam = False

        self._wait_sim_ready(60.0)

    # ── External hooks (curriculum / eval-flip) ──────────────────────────
    def set_curriculum_max_wp(self, n: int) -> None:
        self.curriculum_max_wp = max(1, min(N_WP_TOTAL, int(n)))

    def set_eval_mode(self, flag: bool) -> None:
        self.eval_mode = bool(flag)

    # ── ROS callbacks ────────────────────────────────────────────────────
    def _scan_cb(self, msg: LaserScan) -> None:
        self._raw_scan = np.asarray(msg.ranges, dtype=np.float32)

    def _odom_cb(self, msg: Odometry) -> None:
        self._x = msg.pose.pose.position.x
        self._y = msg.pose.pose.position.y
        q = msg.pose.pose.orientation
        self._yaw = math.atan2(
            2.0 * (q.w * q.z + q.x * q.y),
            1.0 - 2.0 * (q.y ** 2 + q.z ** 2),
        )
        self._odom_ok = True

    # ── gym API ──────────────────────────────────────────────────────────
    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        rng = self.np_random

        if self.eval_mode:
            self._dr_noise = 0.0
            self._dr_dropout = 0.0
            self._dr_max_lin = MAX_LIN_NOMINAL
            self._dr_max_ang = MAX_ANG_NOMINAL
            self._adv_lidar_bias = 0.0
            self._adv_noise_burst = False
            self._adv_action_jam = False
        else:
            self._dr_noise   = float(rng.uniform(*DR_LIDAR_NOISE_STD))
            self._dr_dropout = float(rng.uniform(*DR_LIDAR_DROPOUT_P))
            self._dr_max_lin = float(rng.uniform(*DR_MAX_LIN_RANGE))
            self._dr_max_ang = float(rng.uniform(*DR_MAX_ANG_RANGE))
            self._adv_lidar_bias = (
                float(rng.uniform(0.03, 0.08))
                if rng.random() < ADV_LIDAR_BIAS_P else 0.0
            )
            self._adv_noise_burst = bool(rng.random() < ADV_NOISE_BURST_P)
            self._adv_action_jam  = bool(rng.random() < ADV_ACTION_JAM_P)

        self._steps = 0
        self._prev_action = np.zeros(2, dtype=np.float32)
        self._waypoints_done = 0
        self._ep_min_clearance = float("inf")
        self._publish_cmd(0.0, 0.0)
        self._frame_buffer.clear()

        sx, sy = _random_safe_pos(rng)
        syaw   = float(rng.uniform(-math.pi, math.pi))
        self._odom_ok = False
        self._teleport(sx, sy, syaw)
        self._wait_odom(2.0)
        self._raw_scan = None
        self._wait_scan(SCAN_TIMEOUT_S)

        wps = list(WAYPOINTS_ALL)
        rng.shuffle(wps)
        n_target = int(rng.integers(1, self.curriculum_max_wp + 1))
        self._waypoint_queue = wps[:n_target]
        self._current_wp = self._waypoint_queue.pop(0)
        self._n_wp_total_ep = 1 + len(self._waypoint_queue)
        self._prev_dist, _ = self._wp_info()
        self._prev_pos = (self._x, self._y)
        self._path_length = 0.0

        # optimal length = sum of consecutive Euclidean (start→wp1→wp2→...)
        opt = math.hypot(self._x - self._current_wp.x,
                         self._y - self._current_wp.y)
        prev = self._current_wp
        for nxt in self._waypoint_queue:
            opt += math.hypot(prev.x - nxt.x, prev.y - nxt.y)
            prev = nxt
        self._optimal_length = opt

        first = self._build_single_frame()
        for _ in range(FRAME_STACK):
            self._frame_buffer.append(first)

        return self._stacked_obs(), {
            "dr_noise": self._dr_noise,
            "dr_max_lin": self._dr_max_lin,
            "n_wp_total": self._n_wp_total_ep,
        }

    def step(self, action):
        self._steps += 1
        action = np.asarray(action, dtype=np.float32)
        if not np.all(np.isfinite(action)):
            return self._stacked_obs(), W_COLLIDE, True, False, self._build_info("collision")
        action = np.clip(action, -1.0, 1.0)

        lin_cmd = float((action[0] + 1.0) / 2.0 * self._dr_max_lin)
        ang_cmd = float(action[1] * self._dr_max_ang)
        self._publish_cmd(lin_cmd, ang_cmd)

        self._raw_scan = None
        scan_ok = self._wait_scan(SCAN_TIMEOUT_S)
        self._spin_for(0.05)

        if not scan_ok:
            # environment failure: truncate without polluting reward signal
            return self._stacked_obs(), 0.0, False, True, self._build_info("scan_timeout")

        dx_walk = self._x - self._prev_pos[0]
        dy_walk = self._y - self._prev_pos[1]
        self._path_length += math.hypot(dx_walk, dy_walk)
        self._prev_pos = (self._x, self._y)

        reward, terminated, event = self._compute_reward(action)
        truncated = (self._steps >= MAX_STEPS) and not terminated
        if truncated and event == "running":
            event = "timeout"
        if terminated:
            self._publish_cmd(0.0, 0.0)

        self._prev_action = action.copy()
        self._frame_buffer.append(self._build_single_frame())
        return self._stacked_obs(), reward, terminated, truncated, self._build_info(event)

    def close(self):
        try:
            self._publish_cmd(0.0, 0.0)
        except Exception:
            pass

    # ── reward ──────────────────────────────────────────────────────────
    def _compute_reward(self, action: np.ndarray):
        # Use TRUE scan for collision check (ground-truth physics);
        # the agent's perceived scan may be DR-perturbed but collision is real.
        scan = self._safe_scan_array()
        min_range = float(scan.min())
        if min_range < self._ep_min_clearance:
            self._ep_min_clearance = min_range

        if min_range <= COLLISION_DIST:
            return W_COLLIDE, True, "collision"

        dist, _ = self._wp_info()
        if dist < WAYPOINT_REACH and self._current_wp is not None:
            self._waypoints_done += 1
            if self._waypoint_queue:
                self._current_wp = self._waypoint_queue.pop(0)
                self._prev_dist, _ = self._wp_info()
                return W_REACH, False, "waypoint"
            return W_REACH, True, "all_done"

        phi_now  = -dist
        phi_prev = -self._prev_dist
        r_shape  = GAMMA_SHAPING * phi_now - phi_prev
        self._prev_dist = dist

        a_diff = action - self._prev_action
        r_smooth = -W_SMOOTH * float(np.dot(a_diff, a_diff))

        r_time = -W_TIME

        return float(r_shape + r_smooth + r_time), False, "running"

    # ── obs builders ────────────────────────────────────────────────────
    def _safe_scan_array(self) -> np.ndarray:
        raw = self._raw_scan if self._raw_scan is not None else \
              np.full(360, LIDAR_MAX_M, dtype=np.float32)
        scan = np.where(np.isfinite(raw), raw, LIDAR_MAX_M).astype(np.float32)
        return np.clip(scan, 0.0, LIDAR_MAX_M)

    def _build_single_frame(self) -> np.ndarray:
        scan = self._safe_scan_array()
        if len(scan) >= LIDAR_BEAMS:
            stride = max(1, len(scan) // LIDAR_BEAMS)
            lidar = scan[::stride][:LIDAR_BEAMS]
            if len(lidar) < LIDAR_BEAMS:
                lidar = np.pad(lidar, (0, LIDAR_BEAMS - len(lidar)),
                               constant_values=LIDAR_MAX_M)
        else:
            lidar = np.pad(scan, (0, LIDAR_BEAMS - len(scan)),
                           constant_values=LIDAR_MAX_M)

        lidar = (lidar / LIDAR_MAX_M).astype(np.float32)

        if not self.eval_mode:
            if self._dr_noise > 0:
                lidar = lidar + self.np_random.normal(
                    0.0, self._dr_noise, size=lidar.shape
                ).astype(np.float32)
            if self._dr_dropout > 0:
                mask = self.np_random.random(lidar.shape) < self._dr_dropout
                lidar = np.where(mask, 1.0, lidar).astype(np.float32)
            if self._adv_lidar_bias > 0:
                lidar = lidar + self._adv_lidar_bias
            if self._adv_noise_burst and (self._steps % 10 == 0):
                lidar = lidar + self.np_random.uniform(
                    -0.1, 0.1, size=lidar.shape
                ).astype(np.float32)
            lidar = np.clip(lidar, 0.0, 1.0)

        dist, angle = self._wp_info()
        dist_norm = min(dist / DIST_MAX_M, 1.0)
        cos_a, sin_a = math.cos(angle), math.sin(angle)
        if self._adv_action_jam:
            prev_lin_n = 0.0
            prev_ang_n = 0.0
        else:
            prev_lin_n = float(self._prev_action[0])
            prev_ang_n = float(self._prev_action[1])
        time_norm = self._steps / MAX_STEPS

        state = np.array(
            [dist_norm, cos_a, sin_a, prev_lin_n, prev_ang_n, time_norm],
            dtype=np.float32,
        )
        return np.concatenate([lidar, state]).astype(np.float32)

    def _stacked_obs(self) -> np.ndarray:
        return np.concatenate(list(self._frame_buffer)).astype(np.float32)

    def _build_info(self, event: str) -> dict:
        spl_denom = max(self._optimal_length, self._path_length, 1e-6)
        spl = self._optimal_length / spl_denom if event == "all_done" else 0.0
        return {
            "event": event,
            "waypoints_done": self._waypoints_done,
            "n_wp_total": self._n_wp_total_ep,
            "min_clearance": self._ep_min_clearance,
            "is_collision":    event == "collision",
            "is_full_success": event == "all_done",
            "is_timeout":      event == "timeout",
            "path_length":     self._path_length,
            "optimal_length":  self._optimal_length,
            "spl":             float(spl),
            "dr_noise":        self._dr_noise,
            "dr_max_lin":      self._dr_max_lin,
        }

    # ── geometry ────────────────────────────────────────────────────────
    def _wp_info(self) -> tuple[float, float]:
        if self._current_wp is None:
            return 999.0, 0.0
        dx = self._current_wp.x - self._x
        dy = self._current_wp.y - self._y
        dist = math.hypot(dx, dy)
        a = math.atan2(dy, dx) - self._yaw
        while a >  math.pi: a -= 2 * math.pi
        while a < -math.pi: a += 2 * math.pi
        return dist, a

    # ── sim plumbing ────────────────────────────────────────────────────
    def _teleport(self, x: float, y: float, yaw: float = 0.0) -> None:
        qz = math.sin(yaw / 2.0)
        qw = math.cos(yaw / 2.0)
        env = os.environ.copy()
        env["GZ_IP"] = "127.0.0.1"
        subprocess.run(
            [
                "gz", "service", "-s", "/world/default/set_pose",
                "--reqtype", "gz.msgs.Pose",
                "--reptype", "gz.msgs.Boolean",
                "--timeout", "1500",
                "--req",
                f'name: "burger", position: {{x: {x}, y: {y}, z: 0.05}}, '
                f'orientation: {{x: 0, y: 0, z: {qz}, w: {qw}}}',
            ],
            capture_output=True,
            env=env,
        )

    def _wait_sim_ready(self, timeout: float) -> None:
        self.get_logger().info(f"等待 Gazebo /scan + /odom 就緒 (max {timeout:.0f}s)…")
        t0 = time.time()
        while time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.1)
            if self._raw_scan is not None and self._odom_ok:
                elapsed = time.time() - t0
                self.get_logger().info(f"✓ Gazebo 就緒（{elapsed:.1f}s）")
                self._raw_scan = None
                self._odom_ok = False
                return
        self.get_logger().error(f"Gazebo not ready after {timeout:.0f}s")

    def _wait_scan(self, timeout: float) -> bool:
        t0 = time.time()
        while self._raw_scan is None and time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.05)
        return self._raw_scan is not None

    def _wait_odom(self, timeout: float) -> bool:
        t0 = time.time()
        while not self._odom_ok and time.time() - t0 < timeout:
            rclpy.spin_once(self, timeout_sec=0.05)
        return self._odom_ok

    def _spin_for(self, sec: float) -> None:
        t0 = time.time()
        while time.time() - t0 < sec:
            rclpy.spin_once(self, timeout_sec=0.02)

    def _publish_cmd(self, lin: float, ang: float) -> None:
        m = TwistStamped()
        m.header.stamp = self.get_clock().now().to_msg()
        m.header.frame_id = "base_link"
        m.twist.linear.x  = float(lin)
        m.twist.angular.z = float(ang)
        self._cmd_pub.publish(m)
