#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${ROS2_WS:-$HOME/ros2_ws}"
RUNTIME_DIR="${FIREWALL_LIVE_RUNTIME:-$WORKSPACE/firewall_lab/live_runtime}"
TELEMETRY_SOCKET="$RUNTIME_DIR/runtime_telemetry.sock"
mkdir -p "$RUNTIME_DIR"

usage() {
  printf '%s\n' \
    "usage: $0 start <permissive|enforce>" \
    "       $0 status <permissive|enforce>" \
    "       $0 stop <permissive|enforce>"
}

[[ $# -eq 2 ]] || {
  usage >&2
  exit 2
}
ACTION="$1"
MODE="$2"
case "$MODE" in
  permissive)
    STACK_SCRIPT="$WORKSPACE/展示指令/01_啟動系統.sh"
    READY_TEXT="本機 Permissive readiness 通過"
    ;;
  enforce)
    STACK_SCRIPT="$WORKSPACE/展示指令/01c_啟動系統_enforce.sh"
    READY_TEXT="SROS2 Enforce readiness 通過"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

PID_FILE="$RUNTIME_DIR/${MODE}.pid"
LOG_FILE="$RUNTIME_DIR/${MODE}.log"

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
  [[ "$command_line" == *"$STACK_SCRIPT"* ]]
}

case "$ACTION" in
  start)
    if pid="$(read_pid 2>/dev/null)"; then
      if kill -0 "$pid" 2>/dev/null && is_our_process "$pid"; then
        printf 'already_running mode=%s pid=%s\n' "$MODE" "$pid"
        exit 0
      fi
      rm -f -- "$PID_FILE"
    fi
    [[ -f "$STACK_SCRIPT" ]] || {
      printf 'missing stack script: %s\n' "$STACK_SCRIPT" >&2
      exit 1
    }
    : > "$LOG_FILE"
    SROS2_FIREWALL_TELEMETRY_SOCKET="$TELEMETRY_SOCKET" \
      setsid bash "$STACK_SCRIPT" >"$LOG_FILE" 2>&1 </dev/null &
    pid="$!"
    printf '%s\n' "$pid" > "$PID_FILE"
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null || ! is_our_process "$pid"; then
      tail -n 80 "$LOG_FILE" >&2 || true
      rm -f -- "$PID_FILE"
      printf 'stack failed during startup\n' >&2
      exit 1
    fi
    printf 'started mode=%s pid=%s log=%s telemetry_socket=%s\n' \
      "$MODE" "$pid" "$LOG_FILE" "$TELEMETRY_SOCKET"
    ;;
  status)
    pid="$(read_pid)" || {
      printf 'stopped mode=%s\n' "$MODE"
      exit 1
    }
    if ! kill -0 "$pid" 2>/dev/null || ! is_our_process "$pid"; then
      printf 'stale mode=%s pid=%s\n' "$MODE" "$pid"
      exit 1
    fi
    if grep -Fq "$READY_TEXT" "$LOG_FILE"; then
      readiness="ready"
    else
      readiness="starting"
    fi
    printf 'running mode=%s pid=%s readiness=%s\n' \
      "$MODE" "$pid" "$readiness"
    tail -n 30 "$LOG_FILE" || true
    ;;
  stop)
    pid="$(read_pid)" || {
      printf 'already_stopped mode=%s\n' "$MODE"
      exit 0
    }
    if kill -0 "$pid" 2>/dev/null && is_our_process "$pid"; then
      # The launch script starts ROS/Gazebo children in the same session.
      # Terminate the verified process group so those children cannot survive
      # after the wrapper shell exits and contaminate the next capture.
      kill -TERM -- "-$pid"
      for _ in {1..30}; do
        if ! kill -0 -- "-$pid" 2>/dev/null; then
          break
        fi
        sleep 0.5
      done
      if kill -0 -- "-$pid" 2>/dev/null; then
        kill -KILL -- "-$pid"
        sleep 0.5
      fi
      if kill -0 -- "-$pid" 2>/dev/null; then
        printf 'stack process group did not stop: pgid=%s\n' "$pid" >&2
        exit 1
      fi
    fi
    rm -f -- "$PID_FILE"
    printf 'stopped mode=%s\n' "$MODE"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
