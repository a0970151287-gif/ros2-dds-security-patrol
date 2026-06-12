#!/bin/bash
# ============================================================
# 00 重置模擬器（機器人位置/狀態還原）
# ============================================================

# ── 方法 0：清除模擬器紀錄（機器人不見、黑屏、異常時用）──
pkill -9 -f "gz sim" 2>/dev/null
pkill -9 -f "parameter_bridge" 2>/dev/null
pkill -9 -f "robot_state_publisher" 2>/dev/null
pkill -9 -f "ros_gz" 2>/dev/null
sleep 2
rm -rf ~/.gz/sim/8/log/*
rm -rf ~/.ros/log/*
echo "模擬器紀錄已清除，重開 Gazebo："
echo "  source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash"
echo "  export TURTLEBOT3_MODEL=burger"
echo "  ros2 launch dds_security_monitor gazebo.launch.py"

# ── 方法 1：傳送機器人回安全起點（Gazebo 繼續跑，最快）────
# 一般巡邏用：回 (0, 0)
GZ_IP=127.0.0.1 gz service -s /world/default/set_pose \
  --reqtype gz.msgs.Pose \
  --reptype gz.msgs.Boolean \
  --timeout 3000 \
  --req 'name: "burger", position: {x: 0.0, y: 0.0, z: 0.01}, orientation: {x: 0.0, y: 0.0, z: 0.0, w: 1.0}'

# TQC 訓練用：回 (-2, -0.5)（空曠安全位置）
GZ_IP=127.0.0.1 gz service -s /world/default/set_pose \
  --reqtype gz.msgs.Pose \
  --reptype gz.msgs.Boolean \
  --timeout 3000 \
  --req 'name: "burger", position: {x: -2.0, y: -0.5, z: 0.05}, orientation: {x: 0.0, y: 0.0, z: 0.0, w: 1.0}'

# ── 方法 2：完整重開（關掉所有節點 + Gazebo）────────────────
pkill -f "ros2 run dds_security_monitor"
pkill -f "train_top.py"
pkill -9 -f "gz sim"
pkill -f "parameter_bridge"
pkill -f "robot_state_publisher"
sleep 3

# 確認清空
source ~/ros2_ws/install/setup.bash
ros2 node list

# 重開 Gazebo
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
export TURTLEBOT3_MODEL=burger
ros2 launch dds_security_monitor gazebo.launch.py
