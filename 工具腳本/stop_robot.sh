#!/bin/bash
# Gazebo 開啟後立刻停止機器人（清除初始速度）
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
echo "等待 Gazebo 和 bridge 就緒..."
sleep 5
ros2 topic pub --times 10 /cmd_vel geometry_msgs/msg/TwistStamped \
  "{header: {frame_id: 'base_link'}, twist: {linear: {x: 0.0}, angular: {z: 0.0}}}" \
  --rate 10
echo "機器人已停止"
