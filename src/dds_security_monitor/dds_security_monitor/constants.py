"""共用常數 — 訓練、部署、IDS、Monitor 都從這裡 import。

設計目標：消除散布在多個檔案的重複定義（reviewer 指出的 day-1 紅旗）。
任何「環境邊界」、「物理規格」、「白名單」改動都只在這裡改一次。

模組順序：
    A. 機器人物理規格
    B. 環境 / 場地
    C. SAC 訓練超參
    D. 巡邏路徑點
    E. ROS2 安全白名單
    F. HMAC / Alert 相關
"""
from __future__ import annotations

import os
from dataclasses import dataclass


# ── A. 機器人物理規格 (TurtleBot3 Burger) ───────────────────────────────────
# 來源：robotis e-Manual + Gazebo turtlebot3_burger model.sdf
BURGER_MAX_LIN_VEL  = 0.22       # m/s (官方規格)
BURGER_MAX_ANG_VEL  = 2.84       # rad/s (官方規格)
BURGER_RADIUS       = 0.105      # m (footprint half-width)
BURGER_LIDAR_RANGE  = 3.5        # m (LDS-01 LiDAR 上限)
COLLISION_DIST      = 0.18       # m (碰撞判定門檻)


# ── B. 場地 / 環境參數 ──────────────────────────────────────────────────────
# Gazebo turtlebot3_world：5m × 5m 工廠模擬場，9 根柱子陣列
WORLD_BOUND         = 2.5        # m (場地半邊，±2.5m 為有效範圍)
WAYPOINT_REACH      = 0.30       # m (到達門檻)

# 9 根柱子位置 (Gazebo 世界座標)
CYLINDERS = [
    (-1.1, -1.1), (-1.1, 0.0), (-1.1, 1.1),
    ( 0.0, -1.1), ( 0.0, 0.0), ( 0.0, 1.1),
    ( 1.1, -1.1), ( 1.1, 0.0), ( 1.1, 1.1),
]


# ── C. SAC 訓練 ─────────────────────────────────────────────────────────────
TRAIN_MAX_LIN_VEL   = BURGER_MAX_LIN_VEL          # 訓練用足物理上限
TRAIN_MAX_ANG_VEL   = 1.5                          # rad/s（論文設定，比物理 2.84 保守）
DEPLOY_MAX_LIN_VEL  = 0.55 * BURGER_MAX_LIN_VEL   # 部署 patrol 保守 55%（防翻倒）≈ 0.12 m/s
DEPLOY_MAX_ANG_VEL  = 0.8                          # rad/s
MAX_EPISODE_STEPS   = 500


# ── D. 巡邏路徑點 ───────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Waypoint:
    name: str
    x:    float
    y:    float

# 唯一真實來源 (single source of truth)
# burger_env.py / patrol_node.py 都從這裡 import
# config/waypoints.yaml 在部署時可動態 override 此預設
DEFAULT_WAYPOINTS: tuple[Waypoint, ...] = (
    Waypoint("電源控制室", -1.5, -1.5),
    Waypoint("冷卻水塔",    1.5, -1.5),
    Waypoint("生產線A",   -1.5,  1.5),
    Waypoint("生產線B",    1.5,  1.5),
    Waypoint("出入口",     0.0, -1.8),
)


# ── E. ROS2 節點安全白名單 ──────────────────────────────────────────────────
# 系統合法 publisher / subscriber 的 node 名清單
# Reviewer 指出原本散布在 4 處，現在集中在這裡

# 合法 /cmd_vel publisher（不含 ROS internal 跟 SAC 訓練專用）
CMD_VEL_ALLOWED_PUBS = frozenset({
    "burger_sac_env",          # SAC 訓練環境
    "teleop_keyboard",         # 手動 teleop
    "patrol_node",             # 自動巡邏（部署）
    "dds_security_monitor",    # emergency stop
    "intelligent_defense_node",  # IDS 也可發 stop cmd
})

# 合法 /scan publisher
SCAN_ALLOWED_PUBS = frozenset({
    "ros_gz_bridge",
    "parameter_bridge",
    "hokuyo_driver",
    "rplidar_node",
    "ldlidar_node",
    "urg_node",
})

# 合法的 ROS2 圖中節點（給 monitor_node 白名單用）
# 註：實際 monitor 從 config.yaml 載入，這裡只是「程式內預設」
ROS_GRAPH_ALLOWED_NODES = frozenset({
    # Nav2 / TurtleBot3
    "bt_navigator", "planner_server", "controller_server", "map_server",
    "amcl", "behavior_server", "waypoint_follower", "velocity_smoother",
    "lifecycle_manager_navigation", "lifecycle_manager_localization",
    "robot_state_publisher", "joint_state_publisher",
    "rviz2", "rviz",
    "cartographer_node", "cartographer_occupancy_grid_node",
    "turtlebot3_node", "turtlebot3_fake_node",
    "diff_drive_controller", "teleop_keyboard",
    "turtlebot3_patrol_server", "my_nav_client",
    # 本系統節點
    "dds_security_monitor", "patrol_node",
    "sensor_hub_node", "mission_manager_node", "system_status_node",
    "intelligent_defense_node",
    # Gazebo / Bridge
    "ros_gz_bridge", "ros_gz_image", "ros_gz_point_cloud", "ros_gz_sim",
    "gazebo", "gzserver", "gzclient",
    # 訓練
    "burger_sac_env", "dqn_environment",
})

# 已知 ROS2 內部 node 前綴（非攻擊，不警告）
INTERNAL_NODE_PREFIXES = frozenset({
    "_ros2cli_",                    # ros2 CLI daemon
    "transform_listener_impl",      # TF2 dynamic impl
    "launch_ros",                   # launch system
})


# ── F. HMAC / Alert 設定 ────────────────────────────────────────────────────
ALERT_SECRET_FILE     = os.path.expanduser("~/.config/dds-monitor/alert_secret")
ALERT_SECRET_ENV      = "DDS_ALERT_SECRET"
LINE_TOKEN_FILE       = os.path.expanduser("~/.config/dds-monitor/line_token")
LINE_USER_ID_FILE     = os.path.expanduser("~/.config/dds-monitor/line_user_id")

LINE_RATE_LIMIT_SEC   = 15.0          # LINE 推送頻率限制


# ── G. IDS detector thresholds（智能防禦）──────────────────────────────────
IDS_PHYSICS_LIN_MAX    = 0.50          # m/s, 超出即攻擊 C
IDS_PHYSICS_ANG_MAX    = 4.50          # rad/s
IDS_OSCILLATION_RATIO  = 0.15          # 方向衝突比例（D2）
IDS_SCAN_REPEAT_DIFF   = 0.005         # 連續幀差異門檻（D3）
IDS_VOTE_THRESHOLD     = 2             # 至少幾個 detector 觸發才發 alert
IDS_ALERT_COOLDOWN_SEC = 10.0          # alert 之間最少間隔
