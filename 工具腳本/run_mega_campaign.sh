#!/usr/bin/env bash
# 大型資料集 campaign 的監督器（自適應攻擊者 ＋ 場次抖動）。⚠️ 會產生 live 攻擊流量，需要 Jesse 的授權。
#
# 用法（背景執行，脫離目前的 shell）：
#     nohup bash 工具腳本/run_mega_campaign.sh > ~/mega_supervisor.log 2>&1 &
#
# 看進度：
#     ls -d ~/dataset_mega/*/ | wc -l          # 已完成幾場
#     tail -5 ~/mega_supervisor.log
#
# 停下來：
#     pkill -f "[r]un_mega_campaign.sh"; cd ~/ros2_ws
#     bash firewall_lab/live_stack.sh stop permissive
#     bash firewall_lab/live_stack.sh stop enforce
#
# ⚠️ 筆電休眠會讓它停住（2026-09-17 發生過）。醒來之後照上面的用法重跑即可，
#    campaign 會接著跑 plan 裡還沒完成的場次，已完成的不會重做。

ROS_SETUP="${ROS_SETUP:-/opt/ros/jazzy/setup.bash}"
. "$ROS_SETUP"
set -u
cd /home/jesse/ros2_ws || exit 1
export PYTHONUTF8=1
export FIREWALL_LIVE_RUNTIME="$HOME/.sros2_live_runtime"
mkdir -p "$FIREWALL_LIVE_RUNTIME"

PLAN="${PLAN:-$HOME/mega_plan.json}"
DATASET="${DATASET:-$HOME/dataset_mega}"
CHUNK="${CHUNK:-40}"
LOG="${LOG:-$HOME/mega_campaign.log}"
mkdir -p "$DATASET"

stack_up() {   # $1 = mode
  bash firewall_lab/live_stack.sh start "$1" >/dev/null 2>&1 || return 1
  for i in $(seq 1 40); do
    s=$(bash firewall_lab/live_stack.sh status "$1" 2>&1 | head -1)
    case "$s" in *readiness=ready*) return 0;; esac
    sleep 5
  done
  return 1
}
clear_stale_lock() {
  # campaign 用 `<plan>.lock` 防止兩個執行者同時寫壞資料集,而鎖是在
  # `__exit__` 釋放的——行程被 kill（或筆電休眠後被收掉）就會留下陳舊的鎖,
  # 之後每一次執行都直接 RuntimeError。多天執行一定會遇到,而且是**安靜地
  # 卡住**:監督器照跑,但每一批都失敗。
  #
  # ⚠️ 不可以無條件刪。鎖檔裡寫了 `pid=`,只有那個行程**確實不在**才清掉;
  # 還活著就讓它留著並跳過這一批。
  local lock="${PLAN}.lock"
  [ -e "$lock" ] || return 0
  local pid
  pid=$(sed -n 's/^pid=\([0-9]\+\).*/\1/p' "$lock" 2>/dev/null | head -1)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    echo "  ⛔ 鎖被 pid=$pid 持有且它還活著,跳過" | tee -a "$LOG"
    return 1
  fi
  echo "  ♻️ 清掉陳舊的鎖（pid=${pid:-未知} 已不存在）" | tee -a "$LOG"
  rm -f "$lock"
  return 0
}

stack_down() {   # $1 = mode
  bash firewall_lab/live_stack.sh stop "$1" >/dev/null 2>&1 || true
  # 等到行程真的消失，不要用固定秒數。
  # 2026-09-20 實測：收尾後 3 秒仍有 1 個行程活著（再幾秒才退）。殘留會污染
  # 下一批——C2C-044 記過，沒收乾淨的 stack 讓三輪 live 全部作廢，而症狀是
  # 「Gazebo readiness failed」，看起來像模擬器壞了。
  local left=0
  for _ in $(seq 1 30); do
    left=0
    for p in "gz sim" gzserver monitor_node intelligent_defense \
             velocity_guard patrol_node dumpcap sensor_hub mission_manager; do
      n=$(pgrep -cf "$p" 2>/dev/null); n=${n:-0}
      if [ "$n" -gt 0 ] 2>/dev/null; then left=$((left + n)); fi
    done
    if [ "$left" -eq 0 ]; then return 0; fi
    sleep 2
  done
  echo "  ⚠️ 收尾逾時，仍有 $left 個行程——下一批可能受污染" | tee -a "$LOG"
  return 1
}

round=0
while :; do
  round=$((round + 1))
  for mode in permissive enforce; do
    echo "===== round $round / $mode / $(date -u +%H:%M:%SZ) =====" | tee -a "$LOG"
    if ! stack_up "$mode"; then
      echo "  ⛔ $mode stack 起不來,跳過這一批" | tee -a "$LOG"
      stack_down "$mode"; continue
    fi
    if ! clear_stale_lock; then stack_down "$mode"; continue; fi
    for phase in "" "--retry-failed"; do
      # shellcheck disable=SC2086
      python3 -m firewall_lab.campaign run \
        --plan "$PLAN" --dataset "$DATASET" \
        --security-mode "$mode" --capture-interface lo \
        --limit "$CHUNK" --jitter --adaptive --confirm-isolated-lab $phase \
        >> "$LOG" 2>&1
      echo "  $mode $phase rc=$?" | tee -a "$LOG"
    done
    stack_down "$mode"
    n=$(ls -d "$DATASET"/*/ 2>/dev/null | wc -l)
    echo "  累計場次 = $n" | tee -a "$LOG"
  done
done
