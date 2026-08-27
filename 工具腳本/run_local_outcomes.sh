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

# 安全模式。預設 Enforce——既有五項 outcome 都是在 Enforce 下取得的。
#
# parameter_unchanged 必須用 Permissive，而且那不是為了讓它比較容易通過：
# Enforce 下 ACL 直接擋掉每一個 set_parameters 呼叫，請求根本到不了節點，
# 「參數沒有被改」因此是**空洞地成立**——它證明的是 ACL，不是應用層。
# Permissive 下請求真的抵達，被 rcl 的 read_only 拒絕，那才是第二道防線
# 實際出手的證據。
STRATEGY="${SROS2_OUTCOME_STRATEGY:-Enforce}"
case "$STRATEGY" in
  Enforce|Permissive) ;;
  *) echo "⛔ SROS2_OUTCOME_STRATEGY 只能是 Enforce 或 Permissive"; exit 2 ;;
esac
STACK_MODE="$(printf '%s' "$STRATEGY" | tr '[:upper:]' '[:lower:]')"

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
  export ROS_SECURITY_STRATEGY="$STRATEGY"
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

# marker 的兩個輔助函式只掃檔案尾端。整份掃描是 O(檔案大小)，而 telemetry 會長到
# 數十萬行；mark 最多重試 4 次、每次掃一遍，光是「確認 marker 落地」就能吃掉數十
# 秒，窗因此被撐過 60 秒安全上限而作廢——量測工具自己把證據弄丟。
MARKER_TAIL_LINES=4000

marker_landed() {
  python3 - "$ROOT/telemetry_events.jsonl" "$1" "$2" "$3" "$MARKER_TAIL_LINES" <<'PYEOF'
import collections, json, sys
path, check_id, stage, boundary, tail = sys.argv[1:6]
try:
    with open(path, encoding="utf-8") as handle:
        # 只 JSON-parse 檔尾。讀行本身很快，貴的是每行都 json.loads。
        lines = collections.deque(handle, maxlen=int(tail))
except FileNotFoundError:
    raise SystemExit(1)
for line in lines:
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
raise SystemExit(1)
PYEOF
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
    sleep 2.0
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
marker_line() {  # check stage boundary -> 該 marker 在檔案中的行號
  python3 - "$ROOT/telemetry_events.jsonl" "$1" "$2" "$3" "$MARKER_TAIL_LINES" <<'PYEOF'
import collections, json, sys
path, check_id, stage, boundary, tail = sys.argv[1:6]
tail = int(tail)
found = 0
try:
    # 單次讀取：先前先數行數再 seek(0) 重讀，等於掃兩遍，而檔案已達數十萬行。
    # 每個 mark 的開銷約 5 秒，三個窗就吃掉受控故障的整個持續時間。
    with open(path, encoding="utf-8") as handle:
        window = collections.deque(enumerate(handle), maxlen=tail)
    start = window[0][0] if window else 0
    window = [line for _index, line in window]
except FileNotFoundError:
    print(0)
    raise SystemExit(0)
found = start
for offset, line in enumerate(window):
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
        found = start + offset
print(found)
PYEOF
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

# ── 3. stack ────────────────────────────────────────────────
if [[ "$STRATEGY" == "Enforce" ]]; then
  READY_TEXT="SROS2 Enforce readiness 通過"
else
  READY_TEXT="本機 Permissive readiness 通過"
fi
STACK_LOG="$RUNTIME/$STACK_MODE.log"
log "啟動 SROS2 $STRATEGY stack（readiness 最長 130 秒）"
bash "$WS/firewall_lab/live_stack.sh" start "$STACK_MODE" >>"$ROOT/driver.log" 2>&1 || {
  log "⛔ stack 啟動失敗"; tail -n 40 "$STACK_LOG"; exit 1; }

READY=0
for _ in $(seq 1 150); do
  if grep -q "$READY_TEXT" "$STACK_LOG" 2>/dev/null; then
    READY=1; break
  fi
  if grep -q "readiness 失敗\|不宣告系統可用" "$STACK_LOG" 2>/dev/null; then
    break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || { log "⛔ $STRATEGY readiness 未通過"; tail -n 40 "$STACK_LOG"; exit 1; }
log "✅ $STRATEGY readiness 通過"

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
  # 4c2. 內部威脅：持合法憑證、無 HMAC 金鑰
# Enforce 下無憑證攻擊者連 handshake 都建不起來，訊息到不了 HMAC 驗證器、
# SensorHub 的 oversized 分支或 parameter veto——那幾道防線在外部威脅模型下
# 無法被觀測。竊取的身分決定能打哪裡，這本身就是最小權限 ACL 的實測結果。
N29="$WS/紅隊測試/PoC腳本/N29_insider_credentialed.py"
CAPTURE="$RUNTIME/captured_alert.json"

insider() {  # enclave mode [extra...]
  local enclave="$1" mode="$2"; shift 2
  ( exec python3 "$N29" --mode "$mode" "$@"       --ros-args --enclave "$enclave" )     >>"$ROOT/insider_${mode}.log" 2>&1
}

# 側錄一則真品 alert 供之後重放。攻擊者簽不出有效訊息，重放必須用真的；而沒有
# 任何 enclave 同時有 alerts 的發布與訂閱權，所以重放需要兩個被攻陷的身分。
if enabled hmac_forgery_dropped; then
  log "stage: hmac_forgery_dropped（IDS 憑證被竊）"
  mark hmac_forgery_dropped trigger start
  FLINE="$(marker_line hmac_forgery_dropped trigger start)"
  insider /intelligent_defense_node hmac_forgery --count 12 --duration-sec 12 &
  ATTACK_PID=$!
  wait_for "$FLINE" hmac_result "" 25 reason=invalid_signature
  sleep 2
  mark hmac_forgery_dropped trigger end
  wait "$ATTACK_PID" 2>/dev/null
  sleep 10

  mark hmac_forgery_dropped protected start
  sleep 7
  mark hmac_forgery_dropped protected end

  mark hmac_forgery_dropped recovery start
  RLINE="$(marker_line hmac_forgery_dropped recovery start)"
  wait_for "$RLINE" hmac_result "" 25 reason=accepted
  sleep 2
  mark hmac_forgery_dropped recovery end
fi

if enabled oversized_input_dropped; then
  log "stage: oversized_input_dropped（gazebo 憑證被竊）"
  mark oversized_input_dropped trigger start
  OLINE="$(marker_line oversized_input_dropped trigger start)"
  insider /gazebo oversized_scan --count 12 --duration-sec 12 &
  ATTACK_PID=$!
  wait_for "$OLINE" message_validation sensor_hub_node 22 oversized_count=1
  sleep 2
  mark oversized_input_dropped trigger end
  wait "$ATTACK_PID" 2>/dev/null
  sleep 10

  mark oversized_input_dropped protected start
  sleep 7
  mark oversized_input_dropped protected end

  mark oversized_input_dropped recovery start
  sleep 8
  mark oversized_input_dropped recovery end
fi

if enabled parameter_unchanged; then
  # 這一項**只在 Permissive 下有意義**。
  #
  # Enforce 下 ACL 擋掉每一個 set_parameters 呼叫，請求根本到不了節點，
  # 「參數沒有被改」因此是空洞地成立——它證明的是 ACL，不是應用層。
  # Permissive 下請求真的抵達，被 rcl 的 read_only 拒絕，那才是第二道防線
  # 實際出手的證據。
  if [[ "$STRATEGY" != "Permissive" ]]; then
    log "⏭  parameter_unchanged 需要 Permissive（目前 $STRATEGY），跳過"
  else
  log "stage: parameter_unchanged（Permissive 下 set_parameters 抵達節點）"

  mark parameter_unchanged baseline start
  PBLINE="$(marker_line parameter_unchanged baseline start)"
  wait_for "$PBLINE" parameter_digest local_outcome_probe 25 parameter=whitelist
  sleep 2
  mark parameter_unchanged baseline end

  mark parameter_unchanged trigger start
  PTLINE="$(marker_line parameter_unchanged trigger start)"
  (
    export ROS_SECURITY_ENABLE=false
    unset ROS_SECURITY_STRATEGY ROS_SECURITY_KEYSTORE
    exec python3 "$WS/紅隊測試/PoC腳本/N14_param_whitelist_hijack.py" 14
  ) >"$ROOT/n14.stdout.log" 2>"$ROOT/n14.stderr.log" &
  ATTACK_PID=$!
  CLEAN_PIDS+=("$ATTACK_PID")
  # 等的是 rcl 那一層的拒絕。等 application 層的 veto 會永遠等不到：
  # whitelist 是 read_only，on_set_parameters 從來沒被呼叫過（C2C-022）。
  wait_for "$PTLINE" parameter_veto dds_security_monitor 25 layer=rcl_read_only
  sleep 2
  mark parameter_unchanged trigger end
  wait "$ATTACK_PID" 2>/dev/null
  sleep 6

  mark parameter_unchanged protected start
  PPLINE="$(marker_line parameter_unchanged protected start)"
  wait_for "$PPLINE" parameter_digest local_outcome_probe 25 parameter=whitelist
  sleep 2
  mark parameter_unchanged protected end

  mark parameter_unchanged recovery start
  PRLINE="$(marker_line parameter_unchanged recovery start)"
  wait_for "$PRLINE" process_health local_outcome_probe 25 node=dds_security_monitor
  sleep 2
  mark parameter_unchanged recovery end
  fi
fi

if enabled replay_dropped; then
  log "stage: replay_dropped（側錄真品 alert 後立刻重放）"
  # 攻擊者簽不出有效訊息，重放必須用真品；而信封的 freshness window 只有
  # REPLAY_MAX_AGE_SEC = 10 秒，所以側錄與重放必須貼在一起。先前把側錄放在整場
  # 開頭、90 秒後才重放，訊息一律先被時間戳檢查攔下，拒絕理由是
  # timestamp_violation 而不是 nonce 重用——擋是擋住了，但擋它的是另一道防線。
  # 側錄心跳而不是 alert：monitor 每秒都在發，側錄幾乎瞬間完成。alert 只有偵測器
  # 投票時才出現，上一輪側錄 70 秒一則都沒等到。IDS 訂閱心跳、monitor 發布心跳，
  # 所以側錄與重放各用一個被攻陷的身分。
  # 改回 alerts 頻道：它的 freshness window 是 REPLAY_MAX_AGE_SEC = 10 秒，
  # 心跳只有 3 秒（velocity_guard 對心跳更嚴），三種排法都輸掉那場競速。
  #
  # 順序：publisher 先起、先完成 discovery → 側錄與誘發同時跑 → **等側錄完成才
  # 開窗** → 放行 go 檔。把 marker 的 0.7 秒挪到窗外，窗因此只涵蓋真正的重放，
  # 而側錄到發送的間隔壓在 1 秒出頭，遠在 10 秒內。
  GO="$RUNTIME/replay_go"
  rm -f "$CAPTURE" "$GO"
  insider /intelligent_defense_node replay_publish --count 12 --duration-sec 60     --settle-sec 6 --topic /security/alerts     --capture-file "$CAPTURE" --go-file "$GO" &
  ATTACK_PID=$!

  ( insider /velocity_guard_node replay_capture --duration-sec 45       --topic /security/alerts --capture-file "$CAPTURE" ) &
  CAPTURE_PID=$!

  # 真品 alert 要有人產生：無憑證 participant 會讓 IDS 投票發警報（前幾輪
  # 觀察到 generic_alert 鎖定就是這樣來的）。
  (
    export ROS_SECURITY_ENABLE=false
    unset ROS_SECURITY_STRATEGY ROS_SECURITY_KEYSTORE
    exec ros2 topic pub -r 5 /chatter std_msgs/msg/String       "{data: 'replay-alert-provoke'}"
  ) >>"$ROOT/replay_provoke.log" 2>&1 &
  PROVOKE_PID=$!
  CLEAN_PIDS+=("$PROVOKE_PID")

  wait "$CAPTURE_PID" 2>/dev/null
  kill -TERM "$PROVOKE_PID" 2>/dev/null

  if [[ -s "$CAPTURE" ]]; then
    mark replay_dropped trigger start
    PLINE="$(marker_line replay_dropped trigger start)"
    : > "$GO"
    wait_for "$PLINE" hmac_result "" 22 reason=nonce_reuse_or_capacity
    sleep 2
    mark replay_dropped trigger end
    wait "$ATTACK_PID" 2>/dev/null
    sleep 10

    mark replay_dropped protected start
    sleep 7
    mark replay_dropped protected end

    mark replay_dropped recovery start
    QLINE="$(marker_line replay_dropped recovery start)"
    wait_for "$QLINE" hmac_result "" 20 reason=accepted
    sleep 2
    mark replay_dropped recovery end
  else
    log "⚠️ 沒有側錄到 alert，replay_dropped 這一輪取不到"
  fi
fi

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

  # 單次 arm，hold 取消費端上限 25 秒。
  #
  # 先前試過「兩次故障」（第一次取 trigger、等 guard 釋放後再故障一次），
  # **不可行**：seam 是每個行程最多消費一張 arm，第二張寫進去了但沒有任何行程
  # 消費它，實際只有第一張的 6 秒 hold 生效，故障總長 10 秒（hold 6 ＋ 一次
  # graph 輪詢），三個窗根本塞不下。那個一次性保證是刻意的，不該為了讓檢查過
  # 而拿掉。
  #
  # protected 不再需要「鎖定轉換」——判準已改為「窗內每一筆輸出都鎖定且為零」，
  # 那個轉換落在 trigger 窗裡也無妨（artifact 會如實記 lock_transition_observed）。
  mark graph_failure_fail_safe trigger start
  GLINE0="$(marker_line graph_failure_fail_safe trigger start)"
  arm_seam 25
  wait_for "$GLINE0" graph_state dds_security_monitor 25 state=fault
  mark graph_failure_fail_safe trigger end

  # protected 必須整段落在故障期間內：窗一旦拖過 hold 期滿、guard 釋放，就會出現
  # 未鎖定輸出而正確地被拒。
  mark graph_failure_fail_safe protected start
  sleep 4
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
if ! enabled velocity_guard_recovered; then
  log "跳過 velocity_guard_recovered（未列入本次紀錄）"
else
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

fi

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
