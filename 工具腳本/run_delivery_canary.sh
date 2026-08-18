#!/usr/bin/env bash
# Authorised canary verification, 2026-08-18.
#   protected sink : the existing /listener enclave, which may subscribe rt/chatter
#   attacker       : an uncredentialed publisher on the same topic
# Enforce should deliver nothing; Permissive is the control and must deliver,
# otherwise a zero under Enforce only shows the canary itself is broken.
set -o pipefail
cd /home/jesse/ros2_ws
export FIREWALL_LIVE_RUNTIME=/home/jesse/.local/share/sros2-firewall/live_runtime
OUT=/home/jesse/canary_evidence
rm -rf "$OUT"; mkdir -p "$OUT"
KEYSTORE=$HOME/ros2_ws/sros2_keystore
POLICY_SHA=$(sha256sum firewall_lab/action_policy.json | cut -d" " -f1)

trap 'for m in permissive enforce; do bash firewall_lab/live_stack.sh stop $m >/dev/null 2>&1; done' EXIT
source 工具腳本/load_ros_environment.sh || { echo "PREFLIGHT FAIL"; exit 1; }
python3 -c 'import rclpy' || exit 1
echo "preflight ok; policy=$POLICY_SHA"

trial=0
for mode in permissive enforce; do
  echo "########## $mode ##########"
  for m in permissive enforce; do bash firewall_lab/live_stack.sh stop $m >/dev/null 2>&1; done
  bash firewall_lab/live_stack.sh start "$mode" 2>&1 | tail -1
  ready=0
  for i in $(seq 1 120); do
    case "$(bash firewall_lab/live_stack.sh status "$mode" 2>&1)" in
      *readiness=ready*) ready=1; echo "$mode ready after $((i*2))s"; break ;;
      *stopped*) echo "$mode STACK DIED"; exit 1 ;;
    esac
    sleep 5   # let the sink finish discovery before the source starts
  done
  [ "$ready" = 1 ] || { echo "$mode NOT READY"; exit 1; }

  for seed in 1 2 3; do
    trial=$((trial+1))
    TID="canary_trial_$(printf '%04d' $trial)"
    SID="$(date -u +%Y%m%dT%H%M%S%6NZ)_delivery_canary_$(openssl rand -hex 4)"
    D="$OUT/$TID"; mkdir -p "$D"
    printf '  [%2d/6] %-11s %s ... ' "$trial" "$mode" "$TID"

    common=(--session-id "$SID" --trial-id "$TID" --security-mode "$mode"
            --policy-sha256 "$POLICY_SHA"
            --source-id uncredentialed_source --source-enclave /uncredentialed_source
            --protected-sink-id canary_listener --protected-enclave /listener
            --canary-topic /chatter --first-sequence 0 --attempt-count 10
            --interval-sec 0.4 --heartbeat-sec 1.0 --duration-sec 14)

    # Protected sink: real SROS2 identity under Enforce, plain under Permissive.
    ( if [ "$mode" = enforce ]; then
        export ROS_SECURITY_KEYSTORE="$KEYSTORE" ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce
        exec python3 -m dds_security_monitor.delivery_canary \
          --role protected_received --output "$D/protected_received.jsonl" \
          --collector-id sink_collector --node-name listener "${common[@]}" --ros-args --enclave /listener >"$D/sink.log" 2>&1
      else
        exec python3 -m dds_security_monitor.delivery_canary \
          --role protected_received --output "$D/protected_received.jsonl" \
          --collector-id sink_collector "${common[@]}" >"$D/sink.log" 2>&1
      fi ) &
    sink_pid=$!
    sleep 5   # let the sink finish discovery before the source starts
    # Attacker: never credentialed, in either mode. Under Enforce it should not
    # be able to join at all; under Permissive it should be delivered.
    ( env -u ROS_SECURITY_KEYSTORE -u ROS_SECURITY_ENABLE -u ROS_SECURITY_STRATEGY \
        python3 -m dds_security_monitor.delivery_canary \
        --role attempted --output "$D/attempted.jsonl" \
        --collector-id source_collector "${common[@]}" >"$D/source.log" 2>&1 ) &
    src_pid=$!
    wait $src_pid 2>/dev/null
    wait $sink_pid 2>/dev/null

    if [ -s "$D/attempted.jsonl" ] && [ -s "$D/protected_received.jsonl" ]; then
      a=$(grep -c attempted_canary "$D/attempted.jsonl")
      r=$(grep -c protected_received_canary "$D/protected_received.jsonl")
      echo "attempted=$a delivered=$r"
    else
      echo "ARCHIVE MISSING"; tail -3 "$D/sink.log" "$D/source.log" 2>/dev/null
    fi
  done
done
echo "########## archives in $OUT ##########"
