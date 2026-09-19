#!/usr/bin/env bash
# Authorised paired run, 2026-08-18: 9 scenarios x 2 modes x 3 seeds = 54.
# Same-host loopback, domain 30, no sudo, no second host, no cross-host.
#
# Two defects from the smoke test are guarded against here:
#   - the telemetry socket must not land on the 9p mount (Errno 95), so the
#     runtime dir is pinned to the Linux filesystem;
#   - PYTHONPATH must be prepended, not replaced, or the attacker subprocess
#     loses rclpy and dies on import while the session still reports complete.
# Every session is checked for that second failure rather than trusted.
set -o pipefail
cd /home/jesse/ros2_ws

export FIREWALL_LIVE_RUNTIME=/home/jesse/.local/share/sros2-firewall/live_runtime
mkdir -p "$FIREWALL_LIVE_RUNTIME"
OUT=firewall_lab/dataset_paired54_20260818
mkdir -p "$OUT"

SCENARIOS="normal_patrol unauthorized_participant cmd_vel_injection sensor_status_spoof parameter_tamper oversized_scan parameter_flood heartbeat_replay alert_replay"

stop_all() {
  for m in permissive enforce; do
    bash firewall_lab/live_stack.sh stop "$m" >/dev/null 2>&1
  done
}
trap stop_all EXIT

# Use the project's own loader: it sources the workspace overlay as well as
# the distro. Sourcing only /opt/ros/jazzy leaves dds_security_monitor off the
# path, and the SROS2 deny adapter then dies on import in every session while
# the session still reports complete.
source 工具腳本/load_ros_environment.sh || { echo "PREFLIGHT FAIL: ROS env"; exit 1; }
export PYTHONPATH=/home/jesse/ros2_ws${PYTHONPATH:+:$PYTHONPATH}
for m in rclpy dds_security_monitor firewall_lab; do
  python3 -c "import $m" 2>/dev/null || { echo "PREFLIGHT FAIL: $m not importable"; exit 1; }
done
echo "preflight ok: rclpy, dds_security_monitor, firewall_lab all importable"

n=0; ok=0; bad=0
for mode in permissive enforce; do
  echo "############ starting $mode stack ############"
  stop_all
  bash firewall_lab/live_stack.sh start "$mode" 2>&1 | tail -2
  ready=0
  for i in $(seq 1 120); do
    s=$(bash firewall_lab/live_stack.sh status "$mode" 2>&1)
    case "$s" in
      *readiness=ready*) ready=1; echo "$mode ready after $((i*2))s"; break ;;
      *stopped*) echo "$mode STACK DIED"; tail -15 "$FIREWALL_LIVE_RUNTIME/$mode.log"; break ;;
    esac
    sleep 2
  done
  [ "$ready" = "1" ] || { echo "SKIPPING $mode: never ready"; continue; }

  for scenario in $SCENARIOS; do
    for i in 1 2 3; do
      n=$((n+1))
      seed=$((910000 + n))
      printf '[%2d/54] %-24s %-10s seed=%d ... ' "$n" "$scenario" "$mode" "$seed"
      before=$(ls -1 "$OUT" 2>/dev/null | wc -l)
      python3 -m firewall_lab.orchestrator \
        --mode live --scenario "$scenario" --sessions 1 \
        --security-mode "$mode" --domain-id 30 \
        --seed "$seed" --capture-interface lo \
        --output "$OUT" --confirm-isolated-lab >/dev/null 2>&1
      after=$(ls -1 "$OUT" 2>/dev/null | wc -l)
      if [ "$after" -le "$before" ]; then
        echo "NO SESSION WRITTEN"; bad=$((bad+1)); continue
      fi
      d="$OUT/$(ls -t "$OUT" | head -1)"
      # The smoke test produced six 'complete' sessions in which the attacker
      # had died on import. Never trust status alone.
      # Check every subprocess, not just the attacker. The first paired run
      # had 54 clean-looking sessions in which the deny adapter had died on
      # import, because only attack.stderr.log was inspected.
      crashed=""
      for log in attack capture sros2_adapter telemetry_collector; do
        f="$d/$log.stderr.log"
        [ -f "$f" ] || continue
        if grep -q "ModuleNotFoundError\|Traceback (most recent call last)" "$f"; then
          crashed="$crashed $log"
        fi
      done
      if [ -n "$crashed" ]; then
        echo "SUBPROCESS CRASHED:$crashed"; bad=$((bad+1))
      else
        echo "ok"; ok=$((ok+1))
      fi
    done
  done
done
echo "############ done: $ok ok, $bad problem, $(ls -1 "$OUT" | wc -l) session dirs ############"
