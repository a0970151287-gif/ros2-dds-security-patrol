#!/usr/bin/env bash
# 讓重跑 campaign 撐得過偶發的單場失敗。
#
# 為什麼需要：campaign 是 fail-closed 的，單場失敗就中止整批。實測約 1–2% 的
# 場次會因為攻擊行程超出時間預算而失敗（enforce 126 場中：heartbeat_replay
# rc=-15 兩場、rc=-9 一場，parameter_flood rc=-15 一場）。每一次都讓整批停在
# 那裡等人來看——實跑時因此空轉了三小時。
#
# fail-closed 本身是對的，不該拿掉：它防止半有效的資料集被當成完整的。要修的
# 是「沒有人重啟它」。
#
# 兩個階段的順序很重要：
#   階段 A  不帶 --retry-failed，把 pending 抽乾（失敗的場次會被跳過）
#   階段 B  帶 --retry-failed，回頭補救失敗的
# 反過來的話，--retry-failed 會把失敗的那場排在最前面，它一失敗就中止整批，
# pending 永遠輪不到——這正是實跑時卡住的原因。
#
# 連續三輪沒有任何進展才放棄，避免無限重試一個真正壞掉的場次。
set -uo pipefail
MODE="${1:-enforce}"
WS="${ROS2_WS:-$HOME/ros2_ws}"
PLAN="${RERUN_PLAN_ABS:-$WS/firewall_lab/campaign_rerun_300.json}"
RUNNER="$WS/工具腳本/run_rerun_campaign.sh"
LOG="${RERUN_LOG:-$HOME/rerun300_${MODE}.log}"
MAX_ROUNDS="${RERUN_MAX_ROUNDS:-40}"

count() {  # status
  python3 - "$PLAN" "$MODE" "$1" <<'PYEOF'
import json, sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
print(sum(1 for entry in plan["entries"]
          if entry["security_mode"] == sys.argv[2]
          and entry["status"] == sys.argv[3]))
PYEOF
}

phase() {  # label retry_flag watch_status
  local label="$1" retry="$2" watch="$3"
  local stale=0 before after
  for attempt in $(seq 1 "$MAX_ROUNDS"); do
    before="$(count "$watch")"
    if [ "$before" -eq 0 ]; then
      echo "== $label：已無待處理 =="
      return 0
    fi
    echo "== $(date -u +%H:%M:%S) $label 第 $attempt 輪，剩 $before =="
    RETRY="$retry" bash "$RUNNER" "$MODE" >>"$LOG" 2>&1
    after="$(count "$watch")"
    if [ "$after" -ge "$before" ]; then
      stale=$((stale + 1))
      echo "   無進展（$before → $after），連續 $stale 次"
      if [ "$stale" -ge 3 ]; then
        echo "⛔ $label 連續三輪無進展，停止"
        return 1
      fi
    else
      echo "   進展 $before → $after"
      stale=0
    fi
    sleep 15
  done
  echo "⛔ $label 超過 $MAX_ROUNDS 輪，停止"
  return 1
}

echo "=== $(date -u +%H:%M:%S) 監督開始 mode=$MODE ==="
phase "階段A 抽乾 pending" no pending
phase "階段B 補救 failed" yes failed
echo "=== $(date -u +%H:%M:%S) 監督結束：complete=$(count complete) failed=$(count failed) pending=$(count pending) ==="
