#!/usr/bin/env bash
# Bounded, non-root packet evidence capture for an authorized external red team.
# This script never sends packets and never enables Zeek's blocking helper.
set -euo pipefail

WORKSPACE="${ROS2_WS:-$HOME/ros2_ws}"
RUNTIME_DIR="${BLUE_TEAM_CAPTURE_RUNTIME:-$WORKSPACE/firewall_lab/live_runtime/external_redteam}"
DURATION_SEC="${BLUE_TEAM_CAPTURE_DURATION_SEC:-900}"
PID_FILE="$RUNTIME_DIR/capture.pid"
CURRENT_FILE="$RUNTIME_DIR/current_run.txt"
ZEEK_SCRIPT="$WORKSPACE/Zeek監控/dds_monitor.zeek"
# Keep in sync with firewall_lab/orchestrator.py ZEEK_UDP_INACTIVITY_TIMEOUT_SEC.
ZEEK_UDP_TIMEOUT_SEC=5
PROFILE=""
IFACE=""
CAPTURE_FILTER=""

usage() {
  printf '%s\n' \
    "usage: $0 start <loopback_tcp|dds_domain30>" \
    "       $0 status" \
    "       $0 stop" \
    "       $0 analyze"
}

configure_profile() {
  PROFILE="$1"
  case "$PROFILE" in
    loopback_tcp)
      IFACE="lo"
      CAPTURE_FILTER="tcp and host 127.0.0.1"
      ;;
    dds_domain30)
      IFACE="eth0"
      # ROS_DOMAIN_ID=30 uses RTPS port base 14900. Keep the bounded range
      # needed for discovery and unicast endpoints; exclude unrelated LAN TCP.
      CAPTURE_FILTER="udp portrange 14900-15150"
      ;;
    *)
      printf 'invalid capture profile: %s\n' "$PROFILE" >&2
      exit 2
      ;;
  esac
}

validate_settings() {
  ip link show dev "$IFACE" >/dev/null 2>&1 || {
    printf 'capture interface does not exist: %s\n' "$IFACE" >&2
    exit 2
  }
  [[ "$DURATION_SEC" =~ ^[0-9]+$ ]] &&
    ((DURATION_SEC >= 60 && DURATION_SEC <= 1800)) || {
      printf 'duration must be 60..1800 seconds\n' >&2
      exit 2
    }
}

read_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local value
  value="$(<"$PID_FILE")"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "$value"
}

read_run_dir() {
  [[ -f "$CURRENT_FILE" ]] || return 1
  local value runtime_real run_real
  value="$(<"$CURRENT_FILE")"
  [[ -n "$value" ]] || return 1
  runtime_real="$(readlink -f "$RUNTIME_DIR")"
  run_real="$(readlink -f "$value")"
  [[ "$run_real" == "$runtime_real"/capture-* ]] || {
    printf 'refusing run directory outside capture runtime\n' >&2
    return 1
  }
  [[ -d "$run_real" && ! -L "$run_real" ]] || return 1
  printf '%s\n' "$run_real"
}

metadata_value() {
  local run_dir="$1" key="$2" metadata value
  metadata="$run_dir/capture.meta"
  [[ -f "$metadata" && ! -L "$metadata" ]] || return 1
  value="$(grep -m1 -E "^${key}=" "$metadata" | cut -d= -f2-)"
  [[ -n "$value" ]] || return 1
  printf '%s\n' "$value"
}

is_our_process() {
  local pid="$1" run_dir="$2" iface="$3" command_line run_name
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  command_line="$(tr '\0' ' ' <"/proc/$pid/cmdline")"
  run_name="$(basename "$run_dir")"
  [[ "$command_line" == *"dumpcap"* &&
     "$command_line" == *"$run_name"* &&
     "$command_line" == *"-i $iface"* ]]
}

finalize_hashes() {
  local run_dir="$1"
  (
    cd "$run_dir"
    find . -type f ! -name evidence.sha256 -print0 |
      sort -z |
      xargs -0r sha256sum >evidence.sha256
  )
}

ACTION="${1:-}"
case "$ACTION" in
  start)
    [[ $# -eq 2 ]] || {
      usage >&2
      exit 2
    }
    configure_profile "$2"
    ;;
  status|stop|analyze)
    [[ $# -eq 1 ]] || {
      usage >&2
      exit 2
    }
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

mkdir -p "$RUNTIME_DIR"
case "$ACTION" in
  start)
    validate_settings
    command -v dumpcap >/dev/null 2>&1 || {
      printf 'dumpcap is required\n' >&2
      exit 1
    }
    if pid="$(read_pid 2>/dev/null)" &&
       run_dir="$(read_run_dir 2>/dev/null)" &&
       active_iface="$(metadata_value "$run_dir" iface 2>/dev/null)" &&
       kill -0 "$pid" 2>/dev/null &&
       is_our_process "$pid" "$run_dir" "$active_iface"; then
      active_profile="$(metadata_value "$run_dir" profile)"
      printf 'already_running pid=%s profile=%s run_dir=%s\n' \
        "$pid" "$active_profile" "$run_dir"
      exit 0
    fi

    run_id="capture-${PROFILE}-$(date -u '+%Y%m%dT%H%M%SZ')"
    run_dir="$RUNTIME_DIR/$run_id"
    umask 077
    mkdir -p "$run_dir"
    printf '%s\n' "$run_dir" >"$CURRENT_FILE"
    {
      printf 'profile=%s\n' "$PROFILE"
      printf 'iface=%s\n' "$IFACE"
      printf 'filter=%s\n' "$CAPTURE_FILTER"
      printf 'duration_sec=%s\n' "$DURATION_SEC"
    } >"$run_dir/capture.meta"
    : >"$run_dir/dumpcap.stdout"
    : >"$run_dir/dumpcap.stderr"
    setsid timeout --signal=TERM "$DURATION_SEC" \
      dumpcap -q -i "$IFACE" \
      -f "$CAPTURE_FILTER" \
      -b filesize:20480 -b files:10 \
      -w "$run_dir/traffic.pcapng" \
      >"$run_dir/dumpcap.stdout" 2>"$run_dir/dumpcap.stderr" &
    pid="$!"
    printf '%s\n' "$pid" >"$PID_FILE"
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null ||
       ! is_our_process "$pid" "$run_dir" "$IFACE"; then
      sed -n '1,80p' "$run_dir/dumpcap.stderr" >&2 || true
      printf 'capture failed during startup\n' >&2
      exit 1
    fi
    printf 'started pid=%s profile=%s iface=%s filter=%s max_bytes=%s duration_sec=%s run_dir=%s\n' \
      "$pid" "$PROFILE" "$IFACE" "$CAPTURE_FILTER" \
      "$((20480 * 1024 * 10))" "$DURATION_SEC" "$run_dir"
    ;;
  status)
    run_dir="$(read_run_dir)" || {
      printf 'no_capture_run\n'
      exit 1
    }
    active_profile="$(metadata_value "$run_dir" profile 2>/dev/null || printf 'legacy')"
    active_iface="$(metadata_value "$run_dir" iface 2>/dev/null || printf 'unknown')"
    pid="$(read_pid 2>/dev/null || true)"
    if [[ -n "$pid" ]] &&
       kill -0 "$pid" 2>/dev/null &&
       [[ "$active_iface" != "unknown" ]] &&
       is_our_process "$pid" "$run_dir" "$active_iface"; then
      state="running"
    else
      state="stopped"
    fi
    bytes="$(
      find "$run_dir" -maxdepth 1 -type f -name '*.pcapng' \
        -printf '%s\n' 2>/dev/null |
        awk '{ total += $1 } END { print total + 0 }'
    )"
    printf 'state=%s pid=%s profile=%s iface=%s bytes=%s run_dir=%s\n' \
      "$state" "${pid:-none}" "$active_profile" "$active_iface" \
      "$bytes" "$run_dir"
    ;;
  stop)
    run_dir="$(read_run_dir)" || {
      printf 'already_stopped\n'
      exit 0
    }
    active_iface="$(metadata_value "$run_dir" iface 2>/dev/null || printf 'unknown')"
    pid="$(read_pid 2>/dev/null || true)"
    if [[ -n "$pid" ]] &&
       kill -0 "$pid" 2>/dev/null &&
       [[ "$active_iface" != "unknown" ]] &&
       is_our_process "$pid" "$run_dir" "$active_iface"; then
      kill -TERM -- "-$pid"
      for _ in {1..20}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
      done
    fi
    rm -f -- "$PID_FILE"
    finalize_hashes "$run_dir"
    printf 'stopped run_dir=%s\n' "$run_dir"
    ;;
  analyze)
    run_dir="$(read_run_dir)" || {
      printf 'no capture run to analyze\n' >&2
      exit 1
    }
    active_iface="$(metadata_value "$run_dir" iface 2>/dev/null || printf 'unknown')"
    if pid="$(read_pid 2>/dev/null)" &&
       kill -0 "$pid" 2>/dev/null &&
       [[ "$active_iface" != "unknown" ]] &&
       is_our_process "$pid" "$run_dir" "$active_iface"; then
      printf 'stop capture before offline analysis\n' >&2
      exit 1
    fi
    command -v zeek >/dev/null 2>&1 || {
      printf 'zeek is required\n' >&2
      exit 1
    }
    [[ -f "$ZEEK_SCRIPT" ]] || {
      printf 'missing Zeek script: %s\n' "$ZEEK_SCRIPT" >&2
      exit 1
    }
    mkdir -p "$run_dir/zeek"
    count=0
    while IFS= read -r -d '' pcap; do
      name="$(basename "$pcap" .pcapng)"
      output="$run_dir/zeek/$name"
      mkdir -p "$output"
      (
        cd "$output"
        # Match firewall_lab/orchestrator.py: ZEEK_UDP_INACTIVITY_TIMEOUT_SEC.
        # Long-lived DDS flows are otherwise logged once at t0 and every later
        # 8s feature window comes out empty.
        zeek -r "$pcap" "$ZEEK_SCRIPT" DOS_BLOCK_ENABLED=F \
          -e "redef udp_inactivity_timeout = ${ZEEK_UDP_TIMEOUT_SEC}sec;" \
          >stdout.log 2>stderr.log
      )
      count=$((count + 1))
    done < <(
      find "$run_dir" -maxdepth 1 -type f -name '*.pcapng' -print0 |
        sort -z
    )
    ((count > 0)) || {
      printf 'no pcapng files found\n' >&2
      exit 1
    }
    finalize_hashes "$run_dir"
    printf 'analyzed pcaps=%s run_dir=%s\n' "$count" "$run_dir"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
