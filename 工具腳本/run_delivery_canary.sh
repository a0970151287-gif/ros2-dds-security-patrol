#!/usr/bin/env bash
# Authorised canary verification, 2026-08-18.
#   protected sink : the existing /listener enclave, which may subscribe rt/chatter
#   attacker       : an uncredentialed publisher on the same topic
# Enforce should deliver nothing; Permissive is the control and must deliver,
# otherwise a zero under Enforce only shows the canary itself is broken.
set -o pipefail
cd /home/jesse/ros2_ws
export FIREWALL_LIVE_RUNTIME=/home/jesse/.local/share/sros2-firewall/live_runtime
EVIDENCE_ROOT=${CANARY_EVIDENCE_ROOT:-/home/jesse/canary_evidence}
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)_direct_delivery"
OUT="$EVIDENCE_ROOT/$RUN_ID"
if [ -e "$OUT" ]; then
  echo "refusing to overwrite existing evidence directory: $OUT" >&2
  exit 1
fi
mkdir -p "$OUT"
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

  for source_kind in uncredentialed credentialed; do
   for seed in 1 2 3; do
    trial=$((trial+1))
    TID="canary_${source_kind}_seed_$(printf '%02d' "$seed")"
    SID="$(date -u +%Y%m%dT%H%M%S%6NZ)_delivery_canary_$(openssl rand -hex 4)"
    D="$OUT/${TID}_${mode}"; mkdir -p "$D"
    printf '  [%2d/12] %-11s %-14s %s ... ' "$trial" "$mode" "$source_kind" "$TID"

    if [ "$source_kind" = credentialed ]; then
      SOURCE_ID=credentialed_source
      SOURCE_ENCLAVE=/talker
    else
      SOURCE_ID=uncredentialed_source
      SOURCE_ENCLAVE=/uncredentialed_source
    fi
    common=(--session-id "$SID" --trial-id "$TID" --security-mode "$mode"
            --policy-sha256 "$POLICY_SHA"
            --source-id "$SOURCE_ID" --source-enclave "$SOURCE_ENCLAVE"
            --protected-sink-id canary_listener --protected-enclave /listener
            --canary-topic /chatter --first-sequence 0 --attempt-count 10
            --interval-sec 0.4 --heartbeat-sec 1.0)
    # The sink must outlive the source. Both ran for 14s while the sink started
    # 5s earlier, so it shut down 5s before the source finished -- and because
    # the source waits up to 5s for a subscriber match before publishing, its
    # traffic landed exactly as the sink was leaving. A zero produced that way
    # is a timing artefact, not prevention, which is the confusion this canary
    # is supposed to remove.
    SINK_SECONDS=30
    SOURCE_SECONDS=16

    # Protected sink: real SROS2 identity under Enforce, plain under Permissive.
    ( if [ "$mode" = enforce ]; then
        export ROS_SECURITY_KEYSTORE="$KEYSTORE" ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce
        exec python3 -m dds_security_monitor.delivery_canary \
          --role protected_received --output "$D/protected_received.jsonl" \
          --collector-id sink_collector --node-name listener "${common[@]}" --duration-sec "$SINK_SECONDS" --ros-args --enclave /listener >"$D/sink.log" 2>&1
      else
        exec python3 -m dds_security_monitor.delivery_canary \
          --role protected_received --output "$D/protected_received.jsonl" \
          --collector-id sink_collector "${common[@]}" --duration-sec "$SINK_SECONDS" >"$D/sink.log" 2>&1
      fi ) &
    sink_pid=$!
    sleep 5   # let the sink finish discovery before the source starts
    # Two sources. The uncredentialed one is the attacker. The credentialed
    # one is the control that matters most: without it, an Enforce zero could
    # equally mean Enforce broke delivery for everyone, and the result would
    # say nothing about prevention.
    if [ "$source_kind" = credentialed ] && [ "$mode" = enforce ]; then
      ( export ROS_SECURITY_KEYSTORE="$KEYSTORE" ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce; python3 -m dds_security_monitor.delivery_canary --role attempted --output "$D/attempted.jsonl" --collector-id source_collector --node-name talker "${common[@]}" --duration-sec "$SOURCE_SECONDS" --ros-args --enclave /talker >"$D/source.log" 2>&1 ) &
    else
      ( env -u ROS_SECURITY_KEYSTORE -u ROS_SECURITY_ENABLE -u ROS_SECURITY_STRATEGY python3 -m dds_security_monitor.delivery_canary --role attempted --output "$D/attempted.jsonl" --collector-id source_collector "${common[@]}" --duration-sec "$SOURCE_SECONDS" >"$D/source.log" 2>&1 ) &
    fi
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
done
echo "########## archives in $OUT ##########"
