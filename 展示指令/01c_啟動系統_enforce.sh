#!/bin/bash
# ============================================================
# 01c 啟動系統（SROS2 Enforce 版）— 真的「擋下」未授權節點
#
# 與 01/01b 差別：每個節點掛 SROS2 Enforce + 自己的 enclave。
# 攻擊機沒有本 CA 簽的憑證 → 連 participant 都建不起來 →
# recon/注入/F1/F7 在「認證層」就被擋（不是偵測，是阻擋）。
#
# 傳輸：用「預設」(安全模式自動走 UDP，含 eth0)，不掛直連 SHM profile
#   —— 實測 Enforce 與 SHM profile 不相容(合法節點互相發現失敗)。
#   預設 UDP 同機可通(安全模式)、eth0 也對外可見 → 攻擊機打得到但被拒。
#
# 前提：先跑 10_SROS2啟用.sh 建好 enclave + governance domain 30。
# 本腳本是單一 supervisor：任一必要程序退出就清理整組，Ctrl+C 也會收乾淨。
# ============================================================
set -euo pipefail

KEYSTORE="$HOME/ros2_ws/sros2_keystore"
PIDS=()

ENFORCE() {
  source ~/ros2_ws/工具腳本/load_ros_environment.sh || exit 1
  export ROS_SECURITY_KEYSTORE="$KEYSTORE"
  export ROS_SECURITY_ENABLE=true
  export ROS_SECURITY_STRATEGY=Enforce
  export ROS_DOMAIN_ID=30
  export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
  # Security audit sink only. The profile sets nothing but the four
  # dds.sec.log.* properties, so the default transports the previous
  # comment protected are untouched -- the profile that broke DDS set
  # useBuiltinTransports=false with an interfaceWhiteList, and
  # tests/test_security.py now refuses any profile that does that.
  # Without this, sros_auth_fail_rate and sros_permission_deny_rate have
  # no source at all: the adapter read 249,670 lines of generic stack
  # stdout across the campaign and classified none of them.
  export FASTRTPS_DEFAULT_PROFILES_FILE="$HOME/ros2_ws/firewall_lab/fastdds_security_log.xml"
  unset  ROS_SECURITY_ENCLAVE_OVERRIDE
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
    ENFORCE
    export ROS_SECURITY_ENCLAVE_OVERRIDE=/gazebo
    exec ros2 launch dds_security_monitor gazebo.launch.py
  ) &
  PIDS+=("$!")
}

start_node() {
  local enclave="$1"
  local executable="$2"
  shift 2
  (
    ENFORCE
    exec ros2 run dds_security_monitor "$executable" \
      --ros-args --enclave "$enclave" "$@"
  ) &
  PIDS+=("$!")
}

start_gazebo
start_node /sensor_hub_node sensor_hub_node
start_node /velocity_guard_node velocity_guard_node -p active_source:=patrol
start_node /patrol_node patrol_node \
  --params-file "$HOME/ros2_ws/src/dds_security_monitor/config/config.yaml"
start_node /mission_manager mission_manager
start_node /system_status_node system_status_node
start_node /dds_security_monitor monitor_node \
  --params-file "$HOME/ros2_ws/src/dds_security_monitor/config/config.yaml"
start_node /intelligent_defense_node intelligent_defense_node

echo "→ 等待 Gazebo/bridge/RSP 五條必要資料流..."
(
  ENFORCE
  timeout --signal=TERM 130 ros2 run dds_security_monitor \
    security_readiness_probe --ros-args \
    --enclave /security_readiness_probe -p timeout_sec:=120.0
) || {
  echo "⛔ Enforce readiness 失敗；不宣告系統可用，正在停止整組" >&2
  exit 1
}
for pid in "${PIDS[@]}"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "⛔ 必要程序在 readiness 期間退出；不宣告系統可用" >&2
    exit 1
  fi
done

echo "✅ SROS2 Enforce readiness 通過（${#PIDS[@]} 個 supervised process）"
echo "   final /cmd_vel 唯一 publisher：/velocity_guard_node"
echo "   Ctrl+C 會停止整組程序"

# 任一必要程序退出即視為整組失效；EXIT trap 會終止其餘程序。
wait -n "${PIDS[@]}"
echo "⛔ 必要程序已退出，正在停止整組 Enforce 系統" >&2
exit 1

# ── 驗證「擋下」───────────────────────────────────────────────
# 本機： ros2 node list --ros-args --enclave /dds_security_monitor  應看到系統節點
# 攻擊機(無憑證)： 任何 recon/inject/param 注入 → 應「couldn't find security files」配不上、收不到
# 對照：先用 01b(Permissive) 攻擊得手，再用 01c(Enforce) 同一招被擋 = 報告核心證據
