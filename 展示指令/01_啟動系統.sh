#!/bin/bash
# ============================================================
# 01 啟動系統（DDS Security 監控 + 幾何智慧巡航）
# 每個區塊開一個新終端執行，順序很重要
# ============================================================

# ── 終端 1：Gazebo 模擬器（先開，等機器人出現再開其他）────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
export TURTLEBOT3_MODEL=burger
ros2 launch dds_security_monitor gazebo.launch.py

# ── 終端 2：sensor_hub_node ──────────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
ros2 run dds_security_monitor sensor_hub_node

# ── 終端 3：patrol_node（幾何智慧巡航，部署模式）────────────
# 機器人依序導航：電源控制室 → 冷卻水塔 → 生產線A → 生產線B → 出入口 → 循環
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
export PYTHONPATH="$HOME/dqn_env/lib/python3.12/site-packages:$PYTHONPATH"
ros2 run dds_security_monitor patrol_node

# ── 終端 4：mission_manager ──────────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
ros2 run dds_security_monitor mission_manager

# ── 終端 5：system_status_node ───────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
ros2 run dds_security_monitor system_status_node

# ── 終端 6：monitor_node（最後開）───────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
ros2 run dds_security_monitor monitor_node --params-file ~/ros2_ws/src/dds_security_monitor/config/config.yaml

# ── 全部啟動後確認 ───────────────────────────────────────────
# ros2 node list
# 應出現：/dds_security_monitor /patrol_node /sensor_hub_node
#         /mission_manager_node /system_status_node
#         /robot_state_publisher /ros_gz_bridge
#
# ros2 topic echo /cmd_vel   ← 確認 patrol_node 正在輸出 /cmd_vel 指令
