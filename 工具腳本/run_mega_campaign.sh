#!/usr/bin/env bash
# 大型資料集 campaign 的監督器。⚠️ 會產生 live 攻擊流量，需要 Jesse 的授權。
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
stack_down() { bash firewall_lab/live_stack.sh stop "$1" >/dev/null 2>&1 || true; sleep 3; }

round=0
while :; do
  round=$((round + 1))
  for mode in permissive enforce; do
    echo "===== round $round / $mode / $(date -u +%H:%M:%SZ) =====" | tee -a "$LOG"
    if ! stack_up "$mode"; then
      echo "  ⛔ $mode stack 起不來,跳過這一批" | tee -a "$LOG"
      stack_down "$mode"; continue
    fi
    for phase in "" "--retry-failed"; do
      # shellcheck disable=SC2086
      python3 -m firewall_lab.campaign run \
        --plan "$PLAN" --dataset "$DATASET" \
        --security-mode "$mode" --capture-interface lo \
        --limit "$CHUNK" --jitter --confirm-isolated-lab $phase \
        >> "$LOG" 2>&1
      echo "  $mode $phase rc=$?" | tee -a "$LOG"
    done
    stack_down "$mode"
    n=$(ls -d "$DATASET"/*/ 2>/dev/null | wc -l)
    echo "  累計場次 = $n" | tee -a "$LOG"
  done
done
