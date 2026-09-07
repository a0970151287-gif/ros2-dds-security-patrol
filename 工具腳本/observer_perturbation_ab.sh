#!/usr/bin/env bash
# 觀測者擾動對照：加上 sidecar 觀測者，會不會改變被防禦 stack 自己的遙測？
#
# 用法： observer_perturbation_ab.sh [每臂秒數] [重複幾對]
#
# ## 為什麼一定要先做這個
#
# 觀測者不是被動的。它是同一個 domain 上的 DDS participant，2026-08-29 就看到
# outcome observer 加入 graph 會被 monitor 判為未知節點而觸發警報，進而讓
# patrol 進入 cascade-DoS quiet。如果 sidecar 觀測者也這樣，把它接進 campaign
# 會**改變被觀測的系統**，整批資料就被污染了——而且是事後很難發現的那種。
#
# 這一支不產生任何攻擊流量：兩臂都是正常 stack，唯一的差別是有沒有觀測者。
# 因此不需要 `--confirm-isolated-lab`，也不會有流量上到區網。
#
# 判準：兩臂的 telemetry 事件組成如果有系統性差異（特別是 unknown_node、
# participant_change、log_reject、guard_lock），就代表觀測者會擾動，不可以
# 直接接進 campaign。

set -uo pipefail

SECONDS_PER_ARM="${1:-90}"
PAIRS="${2:-3}"
WS="$HOME/ros2_ws"
RUNTIME="/home/jesse/.local/share/sros2-firewall/live_runtime"
SOCK="$RUNTIME/runtime_telemetry.sock"
ACK="I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE"
OBSERVER_BIN="${OBSERVER_BIN:-$HOME/observer_build/security_observer}"
OUT="$HOME/observer_ab/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

[ -x "$OBSERVER_BIN" ] || { echo "⛔ 找不到觀測者：$OBSERVER_BIN" >&2; exit 2; }

setup_env() {
  # shellcheck disable=SC1091
  source "$WS/工具腳本/load_ros_environment.sh" >/dev/null || return 1
  export ROS_SECURITY_KEYSTORE="$WS/sros2_keystore"
  export ROS_SECURITY_ENABLE=true
  export ROS_SECURITY_STRATEGY=Enforce
  export ROS_DOMAIN_ID=30
  # 流量限制在 loopback。這一支不需要區網，而 mirrored 之下不設這個就會把
  # ROS 流量送上家裡的網路。
  export ROS_LOCALHOST_ONLY=1
  export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
  export SROS2_FIREWALL_LIVE_ACK="$ACK"
  export SROS2_FIREWALL_TELEMETRY_SOCKET="$SOCK"
  export FIREWALL_LIVE_RUNTIME="$RUNTIME"
  unset FASTRTPS_DEFAULT_PROFILES_FILE
  unset ROS_SECURITY_ENCLAVE_OVERRIDE
}
setup_env || { echo "⛔ ROS 環境載入失敗" >&2; exit 1; }

cleanup() {
  trap - EXIT INT TERM
  [ -n "${OBS_PID:-}" ] && kill -TERM "$OBS_PID" 2>/dev/null
  [ -n "${COLLECTOR_PID:-}" ] && kill -INT "$COLLECTOR_PID" 2>/dev/null
  bash "$WS/firewall_lab/live_stack.sh" stop enforce >/dev/null 2>&1
  pkill -f 'security_observer 30' 2>/dev/null
}
trap cleanup EXIT INT TERM

run_arm() {  # arm_name with_observer pair_index
  local arm="$1" with_obs="$2" idx="$3"
  local dir="$OUT/${arm}_${idx}"
  mkdir -p "$dir"
  echo "  ── $arm (pair $idx) ── $(date -u +%H:%M:%SZ)"

  rm -f "$SOCK"
  ( cd "$WS" && exec python3 -m firewall_lab.live_telemetry_collector \
      --session-id "$(date -u +%Y%m%dT%H%M%S%6NZ)_normal_patrol_$(openssl rand -hex 4)" \
      --source telemetry_collector --output "$dir/telemetry_events.jsonl" \
      --socket "$SOCK" --tick-sec 1.0 ) >"$dir/collector.log" 2>&1 &
  COLLECTOR_PID=$!
  for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.5; done
  [ -S "$SOCK" ] || { echo "    ⛔ collector socket 未建立"; return 1; }

  bash "$WS/firewall_lab/live_stack.sh" start enforce >"$dir/stack.log" 2>&1
  local ready=0
  for _ in $(seq 1 40); do
    grep -q "SROS2 Enforce readiness 通過" "$RUNTIME/enforce.log" 2>/dev/null && { ready=1; break; }
    sleep 3
  done
  if [ "$ready" -ne 1 ]; then
    echo "    ⛔ readiness 失敗"; bash "$WS/firewall_lab/live_stack.sh" stop enforce >/dev/null 2>&1
    kill -INT "$COLLECTOR_PID" 2>/dev/null; return 1
  fi

  OBS_PID=""
  if [ "$with_obs" = "yes" ]; then
    # 觀測者需要六個憑證路徑；少一個就立刻退出。2026-08-30 第一輪就是這樣，
    # 「有觀測者」那一臂其實是第二個對照組，整輪作廢。所以下面不只啟動，
    # 還要**證明它活著**，不然這一對不算數。
    local enclave="$WS/sros2_keystore/enclaves/security_readiness_probe"
    OBSERVER_IDENTITY_CA="$enclave/identity_ca.cert.pem" \
    OBSERVER_CERTIFICATE="$enclave/cert.pem" \
    OBSERVER_PRIVATE_KEY="$enclave/key.pem" \
    OBSERVER_GOVERNANCE="$enclave/governance.p7s" \
    OBSERVER_PERMISSIONS="$enclave/permissions.p7s" \
    OBSERVER_PERMISSIONS_CA="$enclave/permissions_ca.cert.pem" \
    OBSERVER_AUDIT_LOG="$dir/dds_security_audit.log" \
    OBSERVER_EVENTS_LOG="$dir/observer_events.jsonl" \
    OBSERVER_INTERFACE_ADDRESS="127.0.0.1" \
    "$OBSERVER_BIN" 30 "$SECONDS_PER_ARM" >"$dir/observer.log" 2>&1 &
    OBS_PID=$!
    sleep 3
    if ! kill -0 "$OBS_PID" 2>/dev/null; then
      echo "    ⛔ 觀測者啟動失敗，這一對作廢：$(head -1 "$dir/observer.log")"
      touch "$dir/VOID"
      bash "$WS/firewall_lab/live_stack.sh" stop enforce >/dev/null 2>&1
      kill -INT "$COLLECTOR_PID" 2>/dev/null; COLLECTOR_PID=""
      return 1
    fi
    echo "    觀測者執行中 (pid $OBS_PID)"
  fi

  sleep "$SECONDS_PER_ARM"

  [ -n "$OBS_PID" ] && { kill -TERM "$OBS_PID" 2>/dev/null; wait "$OBS_PID" 2>/dev/null; OBS_PID=""; }
  bash "$WS/firewall_lab/live_stack.sh" stop enforce >>"$dir/stack.log" 2>&1
  kill -INT "$COLLECTOR_PID" 2>/dev/null; wait "$COLLECTOR_PID" 2>/dev/null; COLLECTOR_PID=""
  # stack 收乾淨才跑下一臂，否則兩組節點會同時在 domain 30 上——這個坑咬過一次。
  pkill -f 'dds_security_monitor|gazebo.launch|gzserver' 2>/dev/null
  sleep 4
  echo "    events: $(wc -l < "$dir/telemetry_events.jsonl" 2>/dev/null || echo 0)"
}

echo "=================================================="
echo " 觀測者擾動對照"
echo "=================================================="
echo "  每臂 ${SECONDS_PER_ARM}s × ${PAIRS} 對，Enforce，loopback only"
echo "  輸出 $OUT"
echo

for pair in $(seq 1 "$PAIRS"); do
  run_arm control  no  "$pair"
  run_arm observer yes "$pair"
done

echo
echo "=================================================="
python3 "$WS/工具腳本/compare_observer_arms.py" --root "$OUT"
echo "  產物在 $OUT"
