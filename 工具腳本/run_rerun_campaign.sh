#!/usr/bin/env bash
# 跑一個 security mode 的重跑 campaign。
#
# 三個前置條件，缺一每場都會失敗（2026-08-21 實跑逐一踩到）：
#   1. FIREWALL_LIVE_RUNTIME 必須在 Linux fs——Unix datagram socket 不能建在
#      Windows 9p 掛載上（Errno 95）。
#   2. ROS stack 必須先起來。orchestrator **不會**啟動 stack，它只跟隨 stack
#      log、起 collector 與攻擊行程；stack 沒起來時 collector 正常建 socket、
#      攻擊正常執行、rc=0，但遙測是空的（not_eligible:runtime_telemetry）。
#   3. 攻擊腳本收尾要有硬上限，否則會與 orchestrator 的時間預算競速。
#
# RETRY=yes 時才帶 --retry-failed。監督器用這個開關分兩階段跑：先抽乾 pending，
# 再回頭補 failed。反過來的話，失敗的那場會排在最前面、一失敗就中止整批，
# pending 永遠輪不到。
set -uo pipefail
MODE="${1:?usage: run_rerun_campaign.sh <permissive|enforce>}"
WS="${ROS2_WS:-$HOME/ros2_ws}"
DATASET="${RERUN_DATASET:-$HOME/dataset_rerun300}"
PLAN="${RERUN_PLAN:-firewall_lab/campaign_rerun_300.json}"
IFACE="${RERUN_CAPTURE_IFACE:-lo}"

cd "$WS" || exit 1
# shellcheck disable=SC1091
source 工具腳本/load_ros_environment.sh >/dev/null || exit 1
export FIREWALL_LIVE_RUNTIME="${FIREWALL_LIVE_RUNTIME:-$HOME/.local/share/sros2-firewall/live_runtime}"
mkdir -p "$FIREWALL_LIVE_RUNTIME" "$DATASET"

case "$MODE" in
  permissive) READY="本機 Permissive readiness 通過" ;;
  enforce)    READY="SROS2 Enforce readiness 通過" ;;
  *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac

cleanup() { bash firewall_lab/live_stack.sh stop "$MODE" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

echo "== 啟動 $MODE stack =="
bash firewall_lab/live_stack.sh start "$MODE" || exit 1
STACK_LOG="$FIREWALL_LIVE_RUNTIME/${MODE}.log"
for _ in $(seq 1 180); do
  grep -q "$READY" "$STACK_LOG" 2>/dev/null && break
  sleep 1
done
grep -q "$READY" "$STACK_LOG" 2>/dev/null || {
  echo "⛔ readiness 未通過"; tail -n 30 "$STACK_LOG"; exit 1; }
echo "== readiness 通過，開始 campaign =="

RETRY_ARG=""
if [ "${RETRY:-no}" = "yes" ]; then
  RETRY_ARG="--retry-failed"
fi

python3 -m firewall_lab.campaign run \
  --plan "$PLAN" \
  --dataset "$DATASET" \
  --security-mode "$MODE" \
  --capture-interface "$IFACE" \
  $RETRY_ARG \
  --confirm-isolated-lab
