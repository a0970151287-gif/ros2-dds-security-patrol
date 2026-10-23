#!/usr/bin/env bash
# 大型 campaign 的「自停之後重新啟動」監看器。
#
# 為什麼需要它：2026-10-09 量到 campaign 會在約 3.5 小時後因為攻擊端孤兒累積
# 而被步調熔斷器停下（場次內部中位 126s → 337s）。孤兒本身已在
# `run_mega_campaign.sh` 的 STACK_PATTERNS 補上，但 C2C-105 記過一句要緊的話：
#
#     「任何一次重啟都會看起來有效，然後數小時後再次失效。」
#
# 所以這一支**不假設修正有效**：它每一輪都記下停止原因、耗時與場次增量，
# 讓「重啟節奏 vs 產能」事後可以被量，而不是靠印象。
#
# ⚠️ 它會讓 live 攻擊流量持續產生，需要 Jesse 涵蓋多次重啟的授權。
#
# 用法（背景執行，脫離目前的 shell）：
#     setsid nohup bash 工具腳本/relaunch_mega_campaign.sh \
#         > ~/mega_relaunch.log 2>&1 & disown
#
# 停下來（先停這一支，否則它會把 campaign 再拉起來）：
#     pkill -f "[r]elaunch_mega_campaign.sh"
#     pkill -f "[r]un_mega_campaign.sh"
#
# 只在熔斷器自停時重啟（exit 3＝零產出、exit 4＝步調過慢）。其他退出碼代表
# 未預期的失敗，繼續拉起來只會重複同一個錯誤，所以停下並留下紀錄。
set -u
REPO="${REPO:-/home/jesse/ros2_ws}"
cd "$REPO" || exit 1
SUPERVISOR="工具腳本/run_mega_campaign.sh"
DATASET="${DATASET:-$HOME/dataset_mega}"
LOG="${RELAUNCH_LOG:-$HOME/mega_relaunch.log}"
MAX_RELAUNCH="${MAX_RELAUNCH:-24}"
SETTLE_SEC="${SETTLE_SEC:-20}"

# 熔斷器自停的退出碼。只有這些才重啟。
EXPECTED_STOPS="3 4"

session_count() { ls -d "$DATASET"/*/ 2>/dev/null | wc -l; }

sweep_orphans() {
  # 攻擊端的長跑行程。monitor 的 STACK_PATTERNS 也涵蓋它了，這裡是雙重保險
  # ——而雙重保險是刻意的：2026-10-09 之前**兩邊都沒有**。
  local n
  n=$(ps -eo comm --no-headers 2>/dev/null | grep -cx talker)
  if [ "${n:-0}" -gt 0 ]; then
    echo "    ♻️ 清掉 $n 個 talker 孤兒"
    pkill -TERM -x talker 2>/dev/null || true
    sleep 3
    pkill -KILL -x talker 2>/dev/null || true
    sleep 1
  fi
  bash firewall_lab/live_stack.sh stop enforce    >/dev/null 2>&1 || true
  bash firewall_lab/live_stack.sh stop permissive  >/dev/null 2>&1 || true
  local shm
  shm=$(ls /dev/shm 2>/dev/null | grep -cE '^(sem\.)?fastrtps')
  if [ "${shm:-0}" -gt 0 ]; then
    rm -f /dev/shm/fastrtps_* /dev/shm/sem.fastrtps_* 2>/dev/null
    echo "    ♻️ 清掉 $shm 個 Fast DDS 段與鎖"
  fi
}

echo "=== relaunch 監看器啟動 $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    上限 $MAX_RELAUNCH 次，只在 exit {$EXPECTED_STOPS} 時重啟"

for attempt in $(seq 1 "$MAX_RELAUNCH"); do
  if pgrep -f "[r]un_mega_campaign.sh" >/dev/null 2>&1; then
    echo "⛔ 已經有 campaign 監督器在跑——不重複啟動"
    exit 2
  fi
  sweep_orphans
  before=$(session_count)
  t0=$(date +%s)
  echo "===== relaunch $attempt/$MAX_RELAUNCH  $(date -u +%Y-%m-%dT%H:%M:%SZ)  場次 $before ====="
  bash "$SUPERVISOR" >> "$HOME/mega_supervisor.log" 2>&1
  rc=$?
  after=$(session_count)
  mins=$(( ($(date +%s) - t0) / 60 ))
  echo "  監督器結束 rc=$rc  跑了 ${mins} 分鐘  場次 $before → $after (+$((after-before)))"
  if [ "$mins" -gt 0 ]; then
    echo "  這一輪速率 約 $(( (after-before) * 60 / mins )) 場/小時"
  fi
  echo "  停止原因（監督器日誌尾端）："
  tail -4 "$HOME/mega_supervisor.log" | sed 's/^/    /'

  if [ "$after" -le "$before" ] && [ "$attempt" -gt 1 ]; then
    echo "⛔ 這一輪一場都沒產出 —— 重啟不是解法，停下來。"
    sweep_orphans
    exit 5
  fi
  case " $EXPECTED_STOPS " in
    *" $rc "*) : ;;
    *)
      echo "⛔ rc=$rc 不是熔斷器自停（預期 $EXPECTED_STOPS）——未預期的失敗，停下來。"
      sweep_orphans
      exit "$rc"
      ;;
  esac
  sleep "$SETTLE_SEC"
done
echo "=== 達到 $MAX_RELAUNCH 次上限，停止 ==="
sweep_orphans
