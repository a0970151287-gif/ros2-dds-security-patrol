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
# ⚠️ 三層等待窗必須 probe < wrapper < 監督器,否則外層那一層永遠用不到。
#
# 2026-09-28 實測:Gazebo 的 launch 在 **118 秒內一個 `process started` 都沒有**,
# probe 在 120 秒上限放棄,stack 於是 fail-closed 停掉整組——而監督器的輪詢窗是
# 200 秒,它從來沒有機會等到。症狀是 `⛔ stack 起不來`,而 stack 其實起得來:
# 七個節點全部正常、HMAC 指紋一致。
#
# `gazebo.launch.py` 的 docstring 自己寫了為什麼慢:那些 IncludeLaunchDescription
# 「會掃過每一個已安裝的 ROS 套件來組 Gazebo 路徑,在 WSL 掛載的工作區上特別慢」。
# C2C-062 量過它要 39 秒,而那是機器輕鬆的時候。
#
# ⚠️ 「為什麼會逐輪變慢」仍然未解(drvfs 快取、357 個 ~/.ros/log 目錄、SHM 洩漏
# 都是候選),但**不必先回答它就能修**:窗放大之後 Gazebo 慢一點不再等於整批報廢,
# 而真正起不來的時候失敗會落在監督器看得見的那一層。
#
# 數字的關係由 tests/test_readiness_window_layers.py 釘住,不要單獨改一個。
  timeout --signal=TERM 250 ros2 run dds_security_monitor \
    security_readiness_probe --ros-args -p timeout_sec:=240.0
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
