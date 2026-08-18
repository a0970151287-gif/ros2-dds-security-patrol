#!/usr/bin/env bash
# ============================================================================
# 01 本機 Permissive 完整系統 supervisor
#
# 用於本機功能展示與「攻擊可進、應用層偵測/急停」對照。這不是 SROS2
# 來源預防模式；要證明未授權 participant 被拒，請改用 01c。
# 任一必要程序退出就停止整組，Ctrl+C 也會清理。
# ============================================================================
set -euo pipefail

WS="${ROS2_WS:-$HOME/ros2_ws}"
PIDS=()

PERMISSIVE_ENV() {
  source "$WS/工具腳本/load_ros_environment.sh" || exit 1
  unset ROS_SECURITY_KEYSTORE ROS_SECURITY_ENABLE ROS_SECURITY_STRATEGY
  unset ROS_SECURITY_ENCLAVE_OVERRIDE
  # 不掛 security-log profile：rmw_fastrtps 在啟用 SROS2 時會自行組出
  # participant 的 dds.sec.* property，XML 的 propertiesPolicy 不會保留。
  # 詳見 文件/DDS_Security_audit_log_不可用_2026-08-18.md
  unset FASTRTPS_DEFAULT_PROFILES_FILE
  # NOTE (2026-08-06): same-host Permissive runs on shared memory, so every
  # loopback session captures a header-only PCAP and is rejected as
  # non-trainable -- see 文件/M1_loopback_pilot發現_2026-08-06.md.  A UDPv4
  # profile with an interfaceWhiteList of 127.0.0.1 was tried here and reverted:
  # it did keep DDS off the shared segment, but only because it broke discovery
  # outright (talker->listener delivered 0 messages vs 23 without it).  Do not
  # reintroduce a transport profile without checking messages actually flow.
  export ROS_DOMAIN_ID="${ROS_DOMAIN_ID:-30}"
  export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
  export TURTLEBOT3_MODEL=burger
}

cleanup() {
  trap - EXIT INT TERM
  # ros2 run/launch can leave their executable children behind when only the
  # CLI parent is signalled. live_stack.sh starts this supervisor as a session
  # leader, so terminate every other member of this verified process group.
  local pgid
  pgid="$(ps -o pgid= -p "$$" | tr -d ' ')"
  if [[ "$pgid" == "$$" ]]; then
    mapfile -t group_pids < <(
      ps -eo pid=,pgid= |
        awk -v target="$pgid" -v self="$$" \
          '$2 == target && $1 != self { print $1 }'
    )
    if ((${#group_pids[@]})); then
      kill -TERM "${group_pids[@]}" 2>/dev/null || true
    fi
  fi
  if ((${#PIDS[@]})); then
    kill -TERM "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

start_gazebo() {
  (
    PERMISSIVE_ENV
    exec ros2 launch dds_security_monitor gazebo.launch.py
  ) &
  PIDS+=("$!")
}

start_node() {
  local executable="$1"
  shift
  (
    PERMISSIVE_ENV
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

echo "→ 等待 Gazebo/bridge/RSP 五條必要資料流..."
(
  PERMISSIVE_ENV
  timeout --signal=TERM 130 ros2 run dds_security_monitor \
    security_readiness_probe --ros-args -p timeout_sec:=120.0
) || {
  echo "⛔ Permissive readiness 失敗；不宣告系統可用，正在停止整組" >&2
  exit 1
}
for pid in "${PIDS[@]}"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "⛔ 必要程序在 readiness 期間退出；不宣告系統可用" >&2
    exit 1
  fi
done

echo "✅ 本機 Permissive readiness 通過（${#PIDS[@]} 個 supervised process）"
echo "   patrol → /cmd_vel/patrol → velocity_guard → final /cmd_vel"
echo "   這是反應式攻防對照；來源預防證據請用 01c。"
echo "   Ctrl+C 會停止整組程序。"

wait -n "${PIDS[@]}"
echo "⛔ 必要程序已退出，正在停止整組本機系統" >&2
exit 1
