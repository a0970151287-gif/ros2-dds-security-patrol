#!/usr/bin/env bash
# ============================================================
# 九項本機防禦結果：一次 campaign 的驅動器
#
# 依 firewall_lab/LOCAL_OUTCOME_LIVE_RUNBOOK.md：整個 campaign 共用同一個
# collector session_id 與同一份停止後的 telemetry JSONL；每個 stage 前後只
# 放 fact-free marker，真正的判定一律由 local_outcome_campaign 事後重算。
#
# 用法：
#   run_local_outcomes.sh rehearse       # 全部 stage 都標記，寫進排練目錄
#   run_local_outcomes.sh record "a b c" # 只標記列出的 check_id
#
# 排練的用意：guard_state 只在狀態轉換時發、D5 需要 10 秒才 fire，某個
# window 缺證據會讓 derive_marked_campaign 整批中止（它是 list comprehension，
# 一個 SchemaError 就全滅）。所以先用相同流程跑一次、用真實推導路徑確認哪些
# window 站得住，正式跑再只標記那些。
#
# 安全邊界：同一台主機、loopback、SROS2 Enforce；不使用 sudo、不改防火牆、
# 不連第二台主機。攻擊面只有一個「無憑證 participant 發 /chatter」，以及對
# 本專案自己的 monitor 行程送 SIGSTOP／SIGCONT（可逆，不是 kill）。
# ============================================================
set -uo pipefail

MODE="${1:-rehearse}"
ENABLED="${2:-}"

WS="$HOME/ros2_ws"
RUNTIME="/home/jesse/.local/share/sros2-firewall/live_runtime"
SOCK="$RUNTIME/runtime_telemetry.sock"
ACK="I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE"
FAULT_ACK="I_CONFIRM_ONE_SHOT_CONTROLLED_GRAPH_FAULT"
HB_ACK="I_CONFIRM_ONE_SHOT_CONTROLLED_HEARTBEAT_SUPPRESS"
FAULT_DIR="/home/jesse/.local/share/sros2-firewall/controlled_graph_fault"

# collector 的 session_id 有固定格式：8 位日期 T 12 位時間（含微秒）Z_名稱_8 位 hex。
STAMP="$(date -u +%Y%m%dT%H%M%S%6NZ)"
SID="${STAMP}_${MODE}_$(openssl rand -hex 4)"
ROOT="/home/jesse/.local/share/sros2-firewall/local_outcomes/$SID"
mkdir -p "$ROOT" "$RUNTIME"

setup_env() {
  # shellcheck disable=SC1091
  source "$WS/工具腳本/load_ros_environment.sh" >/dev/null || return 1
  export ROS_SECURITY_KEYSTORE="$WS/sros2_keystore"
  export ROS_SECURITY_ENABLE=true
  export ROS_SECURITY_STRATEGY=Enforce
  export ROS_DOMAIN_ID=30
  export ROS_LOCALHOST_ONLY=1
  export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
  export SROS2_FIREWALL_LIVE_ACK="$ACK"
  export SROS2_FIREWALL_TELEMETRY_SOCKET="$SOCK"
  export SROS2_FIREWALL_GRAPH_FAULT_ACK="$FAULT_ACK"
  export SROS2_FIREWALL_HEARTBEAT_SUPPRESS_ACK="$HB_ACK"
  export SROS2_FIREWALL_GRAPH_FAULT_DIR="$FAULT_DIR"
  export FIREWALL_LIVE_RUNTIME="$RUNTIME"
  unset FASTRTPS_DEFAULT_PROFILES_FILE
  unset ROS_SECURITY_ENCLAVE_OVERRIDE
}
setup_env || { echo "⛔ ROS 環境載入失敗"; exit 1; }

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$ROOT/driver.log"; }

# 只在 record 模式、且該 check 在啟用清單裡時才送 marker。
enabled() {
  [[ "$MODE" == "rehearse" ]] && return 0
  [[ " $ENABLED " == *" $1 "* ]]
}

marker_landed() {
  python3 - "$ROOT/telemetry_events.jsonl" "$1" "$2" "$3" <<'PY'
import json, sys
path, check_id, stage, boundary = sys.argv[1:5]
try:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event_type") != "outcome_marker":
                continue
            details = event.get("details", {})
            if (
                details.get("check_id") == check_id
                and details.get("stage") == stage
                and details.get("boundary") == boundary
            ):
                raise SystemExit(0)
except FileNotFoundError:
    pass
raise SystemExit(1)
PY
}

# marker 走的是 Unix datagram socket。第一次排練有兩個 marker 送出成功卻沒進
# telemetry——那兩段的事件量都在 2,000 以上，collector 的接收緩衝在尖峰被灌滿，
# datagram 就這樣掉了。marker 本身沒有 facts，重送不會造出任何證據，所以確認
# 落地後才繼續；真的補不上就明講，不讓一個缺角的窗被當成有效觀測。
mark() {
  enabled "$1" || return 0
  local attempt
  for attempt in 1 2 3 4; do
    ( cd "$WS" && python3 -m firewall_lab.local_outcome_marker \
        --socket "$SOCK" --check-id "$1" --stage "$2" --boundary "$3" \
        --live-loopback-ack "$ACK" ) >>"$ROOT/markers.log" 2>&1
    sleep 0.7
    if marker_landed "$1" "$2" "$3"; then
      return 0
    fi
    log "marker 未落地，重送 $1/$2/$3（第 $attempt 次）"
  done
  log "⛔ marker 最終未落地 $1/$2/$3"
}

telemetry_lines() {
  wc -l < "$ROOT/telemetry_events.jsonl" 2>/dev/null || echo 0
}

# 窗的起點就是那個 start marker 自己那一行——不是呼叫 mark 之前或之後的行數。
# mark 要等 0.7 秒確認落地，取「之前」會讓等待器找到窗外的舊事件，取「之後」
# 會漏掉這 0.7 秒內發生的轉換。兩種都踩過：前者讓 velocity_guard_recovered/
# trigger 空了兩輪，後者讓 guard_clear 落進 trigger 窗而 recovery 空掉。
marker_line() {  # check stage boundary
  python3 - "$ROOT/telemetry_events.jsonl" "$1" "$2" "$3" <<'PYEOF'
import json, sys
path, check_id, stage, boundary = sys.argv[1:5]
found = 0
try:
    with open(path, encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event_type") != "outcome_marker":
                continue
            details = event.get("details", {})
            if (
                details.get("check_id") == check_id
                and details.get("stage") == stage
                and details.get("boundary") == boundary
            ):
                found = index
except FileNotFoundError:
    pass
print(found)
PYEOF
}

# 等某個狀態轉換真的出現才關窗。guard_state / graph_state / detector_state 都
# 只在轉換時發一次，用固定 sleep 猜時機前兩輪空了四個窗。
wait_for() {  # since_line event_type source timeout [detail ...]
  local since="$1" etype="$2" source="$3" timeout="$4"; shift 4
  local args=()
  for detail in "$@"; do args+=(--detail "$detail"); done
  python3 "$WS/工具腳本/wait_for_telemetry.py" \
    --telemetry "$ROOT/telemetry_events.jsonl" --event-type "$etype" \
    ${source:+--source "$source"} --since-line "$since" \
    --timeout-sec "$timeout" "${args[@]}" >>"$ROOT/driver.log" 2>&1
}

CLEAN_PIDS=()
cleanup() {
  trap - EXIT INT TERM
  log "收尾中"
  # monitor 若還停著必須先放回來，否則 stack 停不乾淨。
  [[ -n "${MON_PID:-}" ]] && kill -CONT "$MON_PID" 2>/dev/null
  for pid in "${CLEAN_PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null
  done
  bash "$WS/firewall_lab/live_stack.sh" stop enforce >>"$ROOT/driver.log" 2>&1
  # collector 用 SIGINT，讓它寫完 clean shutdown 再退出。
  [[ -n "${COLLECTOR_PID:-}" ]] && kill -INT "$COLLECTOR_PID" 2>/dev/null
  [[ -n "${COLLECTOR_PID:-}" ]] && wait "$COLLECTOR_PID" 2>/dev/null
  log "收尾完成，證據在 $ROOT"
}
trap cleanup EXIT INT TERM

# ── 1. collector ────────────────────────────────────────────
log "啟動 collector（session=$SID）"
rm -f "$SOCK"
( cd "$WS" && exec python3 -m firewall_lab.live_telemetry_collector \
    --session-id "$SID" --source telemetry_collector \
    --output "$ROOT/telemetry_events.jsonl" \
    --socket "$SOCK" --tick-sec 1.0 ) \
  >"$ROOT/collector.stdout.log" 2>"$ROOT/collector.stderr.log" &
COLLECTOR_PID=$!

for _ in $(seq 1 40); do
  [[ -S "$SOCK" ]] && break
  sleep 0.5
done
[[ -S "$SOCK" ]] || { log "⛔ collector socket 未建立"; cat "$ROOT/collector.stderr.log"; exit 1; }
log "collector socket 就緒"

# ── 2. 受控 graph fault seam 的目錄 ─────────────────────────
# 必須在 stack 之前。ControlledGraphFaultSeam.from_environment 在節點「建構時」
# 就要求這個目錄已存在且為 0700，否則該行程一律以 enabled=false 啟動，之後再
# arm 也不會有人消費——第一次排練 arm 成功卻 0 個 controlled_fault_injection，
# 就是這個順序錯了。
log "建立受控 graph fault seam 目錄"
# prepare 會拒絕含殘留 arm 檔的目錄（"stale control files"）。arm 檔是一次性的，
# 上一輪沒被消費就會留下來，所以先清掉自己上次的殘留再建。
rm -f "$FAULT_DIR"/monitor.arm "$FAULT_DIR"/ids.arm 2>/dev/null
( cd "$WS" && python3 -m firewall_lab.local_graph_fault_control prepare \
    --runtime-dir "$FAULT_DIR" --live-loopback-ack "$ACK" \
    --graph-fault-ack "$FAULT_ACK" ) >>"$ROOT/driver.log" 2>&1 \
  || log "⛔ seam prepare 失敗（graph 項會取不到證據）"

# ── 3. Enforce stack ────────────────────────────────────────
log "啟動 SROS2 Enforce stack（readiness 最長 130 秒）"
bash "$WS/firewall_lab/live_stack.sh" start enforce >>"$ROOT/driver.log" 2>&1 || {
  log "⛔ stack 啟動失敗"; tail -n 40 "$RUNTIME/enforce.log"; exit 1; }

READY=0
for _ in $(seq 1 150); do
  if grep -q "SROS2 Enforce readiness 通過" "$RUNTIME/enforce.log" 2>/dev/null; then
    READY=1; break
  fi
  if grep -q "readiness 失敗\|不宣告系統可用" "$RUNTIME/enforce.log" 2>/dev/null; then
    break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || { log "⛔ Enforce readiness 未通過"; tail -n 40 "$RUNTIME/enforce.log"; exit 1; }
log "✅ Enforce readiness 通過"

# ── 3. bounded observer（/local_outcome_probe enclave）───────
log "啟動 observer（duration 300s）"
( exec ros2 run dds_security_monitor local_outcome_observer --ros-args \
    --enclave /local_outcome_probe -p duration_sec:=300.0 ) \
  >"$ROOT/observer.stdout.log" 2>"$ROOT/observer.stderr.log" &
OBSERVER_PID=$!
CLEAN_PIDS+=("$OBSERVER_PID")
sleep 6
kill -0 "$OBSERVER_PID" 2>/dev/null || {
  log "⛔ observer 已退出"; cat "$ROOT/observer.stderr.log"; exit 1; }
log "observer 執行中"

# ── 4. 各 stage ─────────────────────────────────────────────

# 4b. 正常流量保留
log "stage: normal_traffic_preserved/baseline"
mark normal_traffic_preserved baseline start
sleep 14
mark normal_traffic_preserved baseline end

# 4c. 未授權 participant：無憑證節點對 /chatter 發話，observer 應收到 0
log "stage: unauthorized_participant_denied"
mark unauthorized_participant_denied trigger start
(
  export ROS_SECURITY_ENABLE=false
  unset ROS_SECURITY_STRATEGY ROS_SECURITY_KEYSTORE
  exec ros2 topic pub -r 5 /chatter std_msgs/msg/String \
    "{data: 'unauthorized-participant-probe'}"
) >"$ROOT/unauthorized_chatter.stdout.log" 2>"$ROOT/unauthorized_chatter.stderr.log" &
UA_PID=$!
CLEAN_PIDS+=("$UA_PID")
sleep 14
kill -TERM "$UA_PID" 2>/dev/null; wait "$UA_PID" 2>/dev/null
mark unauthorized_participant_denied trigger end

sleep 2
mark unauthorized_participant_denied protected start
sleep 6
mark unauthorized_participant_denied protected end

mark unauthorized_participant_denied recovery start
sleep 5
mark unauthorized_participant_denied recovery end

# graph 整段只在它被列入本次紀錄時才跑。marker 停用時 arm 與等待仍會執行，
# 白白吃掉 observer 的 300 秒預算，還會消耗掉一次性的 seam。
if enabled graph_failure_fail_safe; then
  # 4d. 受控 graph fault seam（一次性、不殺行程、只寫兩個 0600 arm 檔）
  # 必須排在 guard 凍結之前：recovery 要 monitor 自己發出 graph_state=recovery，
  # monitor 一旦沒能從凍結中恢復，這一項就永遠取不到。
  log "stage: graph_failure_fail_safe（受控 seam）"
  arm_seam() {  # hold_sec
    rm -f "$FAULT_DIR"/monitor.arm "$FAULT_DIR"/ids.arm 2>/dev/null
    ( cd "$WS" && python3 -m firewall_lab.local_graph_fault_control prepare \
        --runtime-dir "$FAULT_DIR" --live-loopback-ack "$ACK" \
        --graph-fault-ack "$FAULT_ACK" ) >>"$ROOT/driver.log" 2>&1
    ( cd "$WS" && python3 -m firewall_lab.local_graph_fault_control arm \
        --runtime-dir "$FAULT_DIR" --ttl-sec 20 --hold-sec "$1" \
        --live-loopback-ack "$ACK" --graph-fault-ack "$FAULT_ACK" ) \
      >>"$ROOT/driver.log" 2>&1 || log "⛔ seam arm 失敗"
  }

  # 這一項需要兩次故障，不是一次。實測時間軸：d4 incident 93.97 秒、guard lock
  # 94.00 秒、graph fault 95.06 秒——鎖定與 d4 只差 0.03 秒。trigger 窗必須同時
  # 涵蓋 d4 與 graph fault，所以 guard lock 無可避免落在 trigger 裡，protected 就
  # 沒有新的狀態轉換可看（guard_state 只在轉換時發）。
  #
  # 第一次故障取 trigger；等 guard 自己釋放之後再故障一次，「故障後才鎖定」才會
  # 是一個真正的新轉換，recovery 也才有自己的窗。
  mark graph_failure_fail_safe trigger start
  GLINE0="$(marker_line graph_failure_fail_safe trigger start)"
  arm_seam 6
  wait_for "$GLINE0" graph_state dds_security_monitor 30 state=fault
  mark graph_failure_fail_safe trigger end

  # 警報鎖是有期限的，實測約 30 秒後自行釋放。沒等到釋放就再故障一次的話，
  # protected 一樣看不到轉換。
  log "等待 guard 從第一次故障釋放"
  GREL="$(telemetry_lines)"
  wait_for "$GREL" guard_state velocity_guard_node 60 state=released \
    || log "⚠️ guard 未釋放，graph/protected 可能取不到"

  mark graph_failure_fail_safe protected start
  GLINE1="$(marker_line graph_failure_fail_safe protected start)"
  arm_seam 16
  wait_for "$GLINE1" guard_state velocity_guard_node 30 state=locked
  sleep 3
  mark graph_failure_fail_safe protected end

  mark graph_failure_fail_safe recovery start
  GLINE2="$(marker_line graph_failure_fail_safe recovery start)"
  wait_for "$GLINE2" graph_state dds_security_monitor 34 state=recovery
  sleep 4
  mark graph_failure_fail_safe recovery end
else
  log "跳過 graph_failure_fail_safe（未列入本次紀錄）"
fi

# 4e. guard 恢復：用受控心跳抑制，不再凍結整個行程
# SIGSTOP 讓兩個 stage 互相排斥——凍久一點 trigger 才穩，但超過約 40 秒 DDS
# liveliness lease 會判死 monitor，心跳再也不回來，recovery 就永遠拿不到。
# 五次嘗試 trigger 成功 2 次、recovery 成功 2 次、同場同時成功 0 次。
# 心跳抑制只跳過 publish 那一行，行程、participant 與其他職責照常運作。
log "stage: velocity_guard_recovered（受控心跳抑制 24 秒）"
rm -f "$FAULT_DIR"/monitor.heartbeat.arm 2>/dev/null
( cd "$WS" && python3 -m firewall_lab.local_graph_fault_control prepare     --runtime-dir "$FAULT_DIR" --kind heartbeat_suppression     --live-loopback-ack "$ACK" --graph-fault-ack "$HB_ACK" )   >>"$ROOT/driver.log" 2>&1
( cd "$WS" && python3 -m firewall_lab.local_graph_fault_control arm     --runtime-dir "$FAULT_DIR" --kind heartbeat_suppression     --ttl-sec 20 --hold-sec 24     --live-loopback-ack "$ACK" --graph-fault-ack "$HB_ACK" )   >>"$ROOT/driver.log" 2>&1 || log "⛔ 心跳抑制 arm 失敗"

if ! wait_for 0 controlled_fault_injection dds_security_monitor 12 kind=heartbeat_suppression state=trigger; then
  log "⚠️ 心跳抑制未被消費，velocity_guard_recovered 這一輪取不到"
fi

mark velocity_guard_recovered baseline start
HLINE0="$(marker_line velocity_guard_recovered baseline start)"
wait_for "$HLINE0" guard_state velocity_guard_node 14 state=locked
sleep 1
mark velocity_guard_recovered baseline end

mark velocity_guard_recovered trigger start
HLINE1="$(marker_line velocity_guard_recovered trigger start)"
wait_for "$HLINE1" guard_state velocity_guard_node 20 state=locked reason=monitor_fault
sleep 1
mark velocity_guard_recovered trigger end

# hold 期滿後心跳自己回來，IDS 收到新鮮心跳就發 authenticated clear。
mark velocity_guard_recovered recovery start
HLINE2="$(marker_line velocity_guard_recovered recovery start)"
wait_for "$HLINE2" authenticated_action velocity_guard_node 26 action=guard_clear
sleep 6
mark velocity_guard_recovered recovery end

# 4f. guard 歸零：沿用 SIGSTOP，它已穩定拿到六次量測，且放在最後不需要恢復。
MON_PID2="$(pgrep -f 'dds_security_monitor/monitor_node' | head -1)"
if [[ -n "$MON_PID2" ]]; then
  log "stage: velocity_guard_zeroed（SIGSTOP，最後一段）"
  kill -STOP "$MON_PID2"
  mark velocity_guard_zeroed trigger start
  LINE3="$(marker_line velocity_guard_zeroed trigger start)"
  wait_for "$LINE3" authenticated_action velocity_guard_node 25 action=guard_lock
  sleep 3
  mark velocity_guard_zeroed trigger end

  mark velocity_guard_zeroed protected start
  sleep 6
  mark velocity_guard_zeroed protected end
  kill -CONT "$MON_PID2" 2>/dev/null
else
  log "⚠️ 找不到 monitor，跳過 velocity_guard_zeroed"
fi

log "所有 stage 結束"
exit 0
