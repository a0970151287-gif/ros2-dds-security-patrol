#!/usr/bin/env bash
# ============================================================================
# 01b 跨主機 Permissive 完整系統 supervisor
#
# domain 30 + 直連 Fast DDS profile，讓 10.10.10.1 紅隊能在受控網段看到
# 10.10.10.2 目標。這版故意不開 SROS2，供 before/after 對照；Enforce 用 01c。
# 任一必要程序退出就停止整組，Ctrl+C 也會清理。
# ============================================================================
set -euo pipefail

WS="${ROS2_WS:-$HOME/ros2_ws}"
DIRECT_PROFILE="$WS/跨主機紅隊/dds_directlink_target.xml"
PIDS=()

[[ -f "$DIRECT_PROFILE" ]] || {
  echo "找不到直連 DDS profile：$DIRECT_PROFILE" >&2
  exit 1
}

CROSS_HOST_ENV() {
  source "$WS/工具腳本/load_ros_environment.sh" || exit 1
  unset ROS_SECURITY_KEYSTORE ROS_SECURITY_ENABLE ROS_SECURITY_STRATEGY
  unset ROS_SECURITY_ENCLAVE_OVERRIDE
  export ROS_DOMAIN_ID=30
  export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
  export FASTRTPS_DEFAULT_PROFILES_FILE="$DIRECT_PROFILE"
  export TURTLEBOT3_MODEL=burger
}

cleanup() {
  trap - EXIT INT TERM
  if ((${#PIDS[@]})); then
    kill -TERM "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

start_gazebo() {
  (
    CROSS_HOST_ENV
    exec ros2 launch dds_security_monitor gazebo.launch.py
  ) &
  PIDS+=("$!")
}

start_node() {
  local executable="$1"
  shift
  (
    CROSS_HOST_ENV
    exec ros2 run dds_security_monitor "$executable" --ros-args "$@"
  ) &
  PIDS+=("$!")
}

start_gazebo
start_node sensor_hub_node
start_node velocity_guard_node -p active_source:=patrol
start_node patrol_node \
  --params-file "$WS/src/dds_security_monitor/config/config.yaml"
start_node mission_manager
start_node system_status_node
start_node monitor_node \
  --params-file "$WS/src/dds_security_monitor/config/config.yaml"
start_node intelligent_defense_node

echo "✅ 跨主機 Permissive 程序已派發（${#PIDS[@]} 個 supervised process）"
echo "   domain=30；patrol → velocity_guard → final /cmd_vel"
echo "   此模式允許受控紅隊流量進入，不能當成 Enforce 阻擋證據。"
echo "   Ctrl+C 會停止整組程序。"

wait -n "${PIDS[@]}"
echo "⛔ 必要程序已退出，正在停止整組跨主機系統" >&2
exit 1
