#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${ROS2_WS:-$HOME/ros2_ws}"
RUNTIME_DIR="${FIREWALL_LIVE_RUNTIME:-$WORKSPACE/firewall_lab/live_runtime}"
PLAN="${FIREWALL_PILOT_PLAN:-$WORKSPACE/firewall_lab/campaign_pilot_20.json}"
DATASET="${FIREWALL_PILOT_DATASET:-$WORKSPACE/firewall_lab/dataset_pilot}"
INTERFACE="${FIREWALL_CAPTURE_INTERFACE:-any}"
MINIMUM_FREE_GIB="${FIREWALL_MINIMUM_FREE_GIB:-8}"
mkdir -p "$RUNTIME_DIR" "$DATASET"

usage() {
  printf '%s\n' \
    "usage: $0 start <permissive|enforce> [limit]" \
    "       $0 status <permissive|enforce>" \
    "       $0 run <permissive|enforce> <limit>"
}

[[ $# -ge 2 ]] || {
  usage >&2
  exit 2
}
ACTION="$1"
MODE="$2"
[[ "$MODE" == "permissive" || "$MODE" == "enforce" ]] || {
  usage >&2
  exit 2
}
PID_FILE="$RUNTIME_DIR/campaign_${MODE}.pid"
LOG_FILE="$RUNTIME_DIR/campaign_${MODE}.log"

read_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local value
  value="$(<"$PID_FILE")"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "$value"
}

is_our_process() {
  local pid="$1"
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  local command_line
  command_line="$(tr '\0' ' ' < "/proc/$pid/cmdline")"
  [[ "$command_line" == *"$0 run $MODE"* ]] || {
    # The run branch intentionally execs Python, preserving the PID while
    # replacing the wrapper command line.
    [[ "$command_line" == *"python3 -m firewall_lab.campaign run"* ]] \
      && [[ "$command_line" == *"--plan $PLAN"* ]] \
      && [[ "$command_line" == *"--security-mode $MODE"* ]]
  }
}

case "$ACTION" in
  run)
    [[ $# -eq 3 && "$3" =~ ^[1-9][0-9]*$ ]] || {
      usage >&2
      exit 2
    }
    LIMIT="$3"
    cd "$WORKSPACE"
    source "$WORKSPACE/工具腳本/load_ros_environment.sh"
    unset ROS_SECURITY_KEYSTORE ROS_SECURITY_ENABLE ROS_SECURITY_STRATEGY
    unset ROS_SECURITY_ENCLAVE_OVERRIDE FASTRTPS_DEFAULT_PROFILES_FILE
    export ROS_DOMAIN_ID=30
    export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
    exec python3 -m firewall_lab.campaign run \
      --plan "$PLAN" \
      --dataset "$DATASET" \
      --security-mode "$MODE" \
      --capture-interface "$INTERFACE" \
      --limit "$LIMIT" \
      --minimum-free-gib "$MINIMUM_FREE_GIB" \
      --confirm-isolated-lab
    ;;
  start)
    LIMIT="${3:-10}"
    [[ "$LIMIT" =~ ^[1-9][0-9]*$ ]] || {
      printf 'limit must be a positive integer\n' >&2
      exit 2
    }
    [[ -f "$PLAN" ]] || {
      printf 'missing pilot plan: %s\n' "$PLAN" >&2
      exit 1
    }
    if pid="$(read_pid 2>/dev/null)"; then
      if kill -0 "$pid" 2>/dev/null && is_our_process "$pid"; then
        printf 'already_running mode=%s pid=%s\n' "$MODE" "$pid"
        exit 0
      fi
      rm -f -- "$PID_FILE"
    fi
    : > "$LOG_FILE"
    setsid bash "$0" run "$MODE" "$LIMIT" \
      >"$LOG_FILE" 2>&1 </dev/null &
    pid="$!"
    printf '%s\n' "$pid" > "$PID_FILE"
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null || ! is_our_process "$pid"; then
      tail -n 100 "$LOG_FILE" >&2 || true
      rm -f -- "$PID_FILE"
      printf 'campaign failed during startup\n' >&2
      exit 1
    fi
    printf 'started mode=%s pid=%s limit=%s log=%s\n' \
      "$MODE" "$pid" "$LIMIT" "$LOG_FILE"
    ;;
  status)
    if pid="$(read_pid 2>/dev/null)" \
        && kill -0 "$pid" 2>/dev/null \
        && is_our_process "$pid"; then
      state="running"
    else
      state="stopped"
    fi
    printf 'campaign mode=%s state=%s\n' "$MODE" "$state"
    tail -n 80 "$LOG_FILE" 2>/dev/null || true
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
