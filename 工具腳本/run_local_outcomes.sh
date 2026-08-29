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
# parameter_unchanged 也在 Enforce 下取得，做法見該段的註解：不是放寬安全模式，
# 而是替它建一個**被授權**呼叫 set_parameters 的 enclave，讓請求真的抵達節點，
# 再由 rcl 的 read_only 描述子拒絕它。
#
# （2026-08-28 更正：這裡原本寫「必須用 Permissive」。那條路走不通——outcome
#   observer 拒絕在 Enforce 以外執行，而那道拒絕是對的：沒有強制執行時收的
#   證據支撐不了部署宣稱。）
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
  local attempt start
  for attempt in 1 2 3 4; do
    ( cd "$WS" && python3 -m firewall_lab.local_outcome_marker \
        --socket "$SOCK" --check-id "$1" --stage "$2" --boundary "$3" \
        --live-loopback-ack "$ACK" ) >>"$ROOT/markers.log" 2>&1
    # 固定 sleep 2.0 讓 velocity_guard_recovered 漏掉 monitor_fault：那個轉換
    # 落在窗開啟前 1.1 秒，而開窗的兩個 mark 就吃掉約 4 秒。marker 實際約
    # 0.2 秒就落地，所以改成**落地即返回**。
    #
    # 上限用經過時間而不是次數：marker_landed 自己要起一個 python，單次成本
    # 約 0.3 秒，用「跑 20 次」當上限反而會比原本的 sleep 2.0 更慢——把量測
    # 工具的延遲加進窗的位置，正是這裡要修掉的東西。
    start=$SECONDS
    while (( SECONDS - start < 3 )); do
      if marker_landed "$1" "$2" "$3"; then
        return 0
      fi
      sleep 0.1
    done
    log "marker 未落地，重送 $1/$2/$3（第 $attempt 次）"
  done
  log "⛔ marker 最終未落地 $1/$2/$3"
}

telemetry_lines() {
  wc -l < "$ROOT/telemetry_events.jsonl" 2>/dev/null || echo 0
}

# 等某個事件真的出現才關窗。固定 sleep 對這批證據不管用：guard_state 與
# detector_state 只在狀態「轉換」時發一次。
#
# ⚠️ 2026-08-19 的 commit 2644092 把這個函式**刪掉了**，而 16 個呼叫點全部留著。
# bash 對未定義的函式回 127，所以從那天起每一次 wait_for 都是「立刻失敗」：
# 不在條件式裡的呼叫變成完全不等（靠後面的 sleep 湊合，所以多數 stage 仍然
# 過得去），而 `if ! wait_for ...` 那一個變成**無條件走失敗分支**——
# velocity_guard_recovered 因此每一輪都被判「心跳抑制未被消費」，
# 與接縫實際有沒有運作完全無關。九天內沒有人發現，因為
# 「command not found」只出現在 stderr，而失敗訊息本身讀起來完全合理。
wait_for() {  # since_line event_type source timeout [detail | any-nonzero:k1,k2 ...]
  local since="$1" etype="$2" source="$3" timeout="$4"; shift 4
  local args=() detail key
  for detail in "$@"; do
    # `any-nonzero:linear_x,angular_z` → 至少一個非零（OR）。等值比對表達不了
    # 「機器人動了」——它可以只轉不進，所以兩個欄位是 OR 不是 AND。
    if [[ "$detail" == any-nonzero:* ]]; then
      local keys="${detail#any-nonzero:}"
      for key in ${keys//,/ }; do
        args+=(--detail-any-nonzero "$key")
      done
      continue
    fi
    args+=(--detail "$detail")
  done
  python3 "$WS/工具腳本/wait_for_telemetry.py" \
    --telemetry "$ROOT/telemetry_events.jsonl" --event-type "$etype" \
    ${source:+--source "$source"} --since-line "$since" \
    --timeout-sec "$timeout" "${args[@]}" >>"$ROOT/driver.log" 2>&1
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
  # 停的必須是**這一輪啟動的那個模式**。寫死 enforce 會讓 Permissive 的 stack
  # 留著不死，下一輪兩組節點同時在同一個 domain 上，readiness 就會以
  # 「missing streams: /scan」失敗——症狀完全不像「上一輪沒收乾淨」。
  bash "$WS/firewall_lab/live_stack.sh" stop "$STACK_MODE" >>"$ROOT/driver.log" 2>&1
  # collector 用 SIGINT，讓它寫完 clean shutdown 再退出。
  [[ -n "${COLLECTOR_PID:-}" ]] && kill -INT "$COLLECTOR_PID" 2>/dev/null
  [[ -n "${COLLECTOR_PID:-}" ]] && wait "$COLLECTOR_PID" 2>/dev/null
  log "收尾完成，證據在 $ROOT"
}
trap cleanup EXIT INT TERM

# ── 0. helper 完整性 ────────────────────────────────────────
# bash 對未定義的函式只回 127，不會停下來。一個被刪掉的 helper 因此會安靜地
# 把每一次等待變成立刻失敗，而失敗訊息讀起來仍然合理（見 wait_for 的註解）。
# 這道檢查讓那種情況在**取得任何證據之前**就爆掉。
for _helper in log enabled mark marker_landed marker_line telemetry_lines wait_for cleanup; do
  declare -F "$_helper" >/dev/null || {
    echo "⛔ driver helper 未定義：$_helper（呼叫它只會回 127，等待會變成立刻失敗）" >&2
    exit 2
  }
done
unset _helper

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

# 沒有被列入本次紀錄的 stage 不要跑。marker 本來就會被 enabled 擋掉，但**動作
# 還是會發生**，而動作有副作用。
#
# 2026-08-29 實測：`unauthorized_participant_denied` 會觸發一次已驗章安全警報，
# 而 patrol_node 的 N21/N23 cascade-DoS 修補把「90 秒內兩次 pause」判定為攻擊者
# 借力，進入 quiet window 並**維持停車、忽略恢復**。接著跑
# `velocity_guard_recovered` 就是第二次 pause，於是 guard 解除封鎖之後
# patrol 仍然不動（log：`⛔ cascade-DoS quiet 尚餘 102s，維持巡航停止`），
# recovery 因此永遠等不到非零輸出。
#
# 這不是防禦壞掉，也不是判定太嚴——是驅動器自己製造的 stage 交互作用。
# 這兩段各自的證據早就在別的 session 收齊了（6／9），沒有理由在這裡重跑。
if enabled normal_traffic_preserved; then
# 4b. 正常流量保留
log "stage: normal_traffic_preserved/baseline"
mark normal_traffic_preserved baseline start
sleep 14
mark normal_traffic_preserved baseline end
fi

if enabled unauthorized_participant_denied; then
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
fi

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
  # 這一項在 **Enforce** 下取得，而且必須如此。
  #
  # 要證明的是「請求真的抵達節點之後，安全敏感參數仍然改不了」。原本沒有
  # 任何身分能呼叫 set_parameters，所以 Enforce 下請求到不了節點——那一項
  # 空洞地成立，證明的是 ACL 不是應用層。改用 Permissive 讓請求抵達也不行：
  # observer 拒絕在 Enforce 以外執行，而那道拒絕是對的。
  #
  # 所以改成讓請求**合法**：/parameter_write_probe enclave 只被授權一條
  # dds_security_monitor/set_parameters，連 get_parameters 都沒有。
  # 拒絕因此來自 rcl 的 read_only 描述子，不是來自 ACL。
  if [[ "$STRATEGY" != "Enforce" ]]; then
    log "⏭  parameter_unchanged 需要 Enforce（目前 $STRATEGY），跳過"
  else
  log "stage: parameter_unchanged（已授權的寫入 → rcl read_only 拒絕）"

  mark parameter_unchanged baseline start
  PBLINE="$(marker_line parameter_unchanged baseline start)"
  wait_for "$PBLINE" parameter_digest local_outcome_probe 25 parameter=whitelist
  sleep 2
  mark parameter_unchanged baseline end

  mark parameter_unchanged trigger start
  PTLINE="$(marker_line parameter_unchanged trigger start)"
  (
    export N30_DURATION_SEC=14
    exec python3 "$WS/紅隊測試/PoC腳本/N30_authorized_parameter_write.py"       --ros-args --enclave /parameter_write_probe
  ) >"$ROOT/n30.stdout.log" 2>"$ROOT/n30.stderr.log" &
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
# 殘留的 arm 必須先講再刪。它代表**上一張 arm 從來沒有被消費**，而那正是
# C2C-018 查不出根因的那個現象；先前這裡是無聲 rm -f，等於把唯一的證據
# 抹掉，然後用「prepare 沒失敗」去排除 stale arm 這個假設——那個排除因此
# 是不成立的（見 C2C-044）。
if [[ -e "$FAULT_DIR/monitor.heartbeat.arm" ]]; then
  log "⚠️ 發現殘留的心跳 arm：上一張從未被消費（seam 可能已是一次性用盡）"
fi
rm -f "$FAULT_DIR"/monitor.heartbeat.arm 2>/dev/null

# 先讓 patrol 的 cascade-DoS 偵測窗清空，再注入故障。
#
# patrol_node 的 N21/N23 修補：**90 秒內 2 次 pause** 判定為攻擊者借監控之手
# 按停車按鈕，於是維持停車 **120 秒**等人工介入，期間收到 authenticated clear
# 也不恢復（log：`⛔ cascade-DoS quiet 尚餘 102s，維持巡航停止`）。
#
# observer 自己加入 graph 會被 monitor 判為未知節點而觸發第一次 pause，我們的
# 受控故障就是第二次——recovery 因此永遠等不到「恢復非零輸出」，而 120 秒的
# quiet 遠超過窗的 60 秒安全上限。
#
# 等 95 秒讓 pause_history 清空，我們的故障就成為窗內唯一一次 pause，patrol
# 會照正常的 30 秒 resume timer 恢復巡航。**這不是放寬判定**，是不要用自己的
# 觀測行為去觸發一個與受測性質無關的防禦機制。
log "等待 patrol 的 cascade-DoS 偵測窗清空（95 秒）"
sleep 95

# prepare 只是把目錄準備好，不會造成任何故障；arm 才會，而 arm 已經移到
# trigger 窗開啟之後（見下方）。
( cd "$WS" && python3 -m firewall_lab.local_graph_fault_control prepare     --runtime-dir "$FAULT_DIR" --kind heartbeat_suppression     --live-loopback-ack "$ACK" --graph-fault-ack "$HB_ACK" )   >>"$ROOT/driver.log" 2>&1

# 故障在 baseline 開窗之前注入，這是這一項本來的設計：抑制開始 → 守衛因為
# 心跳過期而鎖定（baseline 要看到的「已經鎖著」）→ 十秒後 D5 升級成
# monitor_fault（trigger 要的）→ hold 期滿心跳回來 → guard_clear（recovery 要的）。
# 三個窗各拿一個轉換。
#
# 這個順序先前失敗，是因為注入時守衛**已經鎖著**（observer 的警報），
# lease_missing 那個轉換於是不存在，baseline 的等待就往後吃掉 monitor_fault。
# 上面等掉 cascade 窗之後 patrol 已恢復巡航、守衛回到 released，這個前提才成立。
( cd "$WS" && python3 -m firewall_lab.local_graph_fault_control arm     --runtime-dir "$FAULT_DIR" --kind heartbeat_suppression     --ttl-sec 20 --hold-sec 24     --live-loopback-ack "$ACK" --graph-fault-ack "$HB_ACK" )   >>"$ROOT/driver.log" 2>&1 || log "⛔ 心跳抑制 arm 失敗"

if ! wait_for 0 controlled_fault_injection dds_security_monitor 12 kind=heartbeat_suppression state=trigger; then
  log "⚠️ 心跳抑制未被消費，velocity_guard_recovered 這一輪取不到"
fi

mark velocity_guard_recovered baseline start
HLINE0="$(marker_line velocity_guard_recovered baseline start)"
# 任何 locked 轉換都算。守衛在注入前是 released，所以這裡拿到的會是
# monitor_lease_missing，而 monitor_fault 要再等十秒——兩個窗不會搶同一個事件。
wait_for "$HLINE0" guard_state velocity_guard_node 20 state=locked
sleep 1
mark velocity_guard_recovered baseline end

mark velocity_guard_recovered trigger start
HLINE1="$(marker_line velocity_guard_recovered trigger start)"
wait_for "$HLINE1" guard_state velocity_guard_node 25 state=locked reason=monitor_fault
sleep 1
mark velocity_guard_recovered trigger end

# hold 期滿後心跳自己回來，IDS 收到新鮮心跳就發 authenticated clear。
mark velocity_guard_recovered recovery start
HLINE2="$(marker_line velocity_guard_recovered recovery start)"
wait_for "$HLINE2" authenticated_action velocity_guard_node 26 action=guard_clear
# 解除封鎖之後還要等到**真的有一筆非零且未封鎖的輸出**才關窗。
#
# 2026-08-29 實測：guard 在 guard_clear 後 0.01 秒就 blocked=False，之後 49 筆
# 連續未封鎖、橫跨 7.26 秒——防禦完全恢復了。但巡邏機器人當時停著（它是間歇
# 移動的，實測約 10–20 秒動、30 秒停），49 筆輸出全是 0.0/0.0，probe 因此以
# 「沒有恢復非零輸出」拒絕。那量到的是模擬器當下有沒有在走，不是防禦。
#
# 判定門檻**沒有改**：probe 仍然要求未封鎖且非零。改的是窗要等到證據出現才關。
wait_for "$HLINE2" guard_output velocity_guard_node 35 blocked=False any-nonzero:linear_x,angular_z
sleep 2
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
