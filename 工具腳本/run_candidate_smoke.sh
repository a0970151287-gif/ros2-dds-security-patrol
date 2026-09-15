#!/usr/bin/env bash
# 9 支候選各跑一場 smoke，加 3 場基線，然後逐一過證據排他性 gate。
#
# ⚠️ 這會執行 live 攻擊，需要 Jesse 對該次操作的明確授權。
#
# 為什麼要這一步：policy 有 14 個空類別，其中 9 類的腳本已經寫好——但六支
# 打的是**已經修好的**缺陷。漏洞修好之後再跑很可能完全沒有應用層訊號，那樣
# 新增的類別會是模型認不出來的，重演 C2C-013 記錄的失效（parameter_tamper
# 與 replay 觸發同一組五個通用特徵，所以分不開）。
#
# 一場 smoke 約 52 秒，12 場約 11 分鐘——遠低於一輪 campaign 的 15 小時。
#
# 候選用**獨立的** catalog，不動出貨的 scenarios.json：沒通過 gate 之前不該
# 進預設 campaign，而且改 catalog 的 SHA-256 會讓既有 campaign 的來源憑證
# 失效（2026-09-01 發生過一次）。
#
# 用法（ROS stack 必須已經在跑，campaign 假設 external stack）：
#     bash 工具腳本/run_candidate_smoke.sh          # 介面預設 lo
#
# ⚠️ 2026-09-15：這一行原本寫 `eth1`，而 2026-09-02 那一批就照著跑了。
# 同機的 ROS 2 流量走 loopback，擷取開在區網介面上只看得到漏出去的多播——
# 實測九場**每一場單播封包都是 0**，而其中 96% 還是 Gazebo 的 gz-transport，
# 跟 DDS 無關。攻擊自己回報「送出 1,480 筆偽造 odometry」，對應的封包 0 個。
# 那一批的網路證據因此**無效**（不是陰性），而 gate 的判定寫進了
# 「至少 4 類在目前的觀測層結構上做不到」。
# 正式 campaign 一直都是 `-i lo`（實測 2,308 場，單播佔比 71–100%），
# 所以這是 smoke 這條路徑專屬的缺陷。
# ROS 必須在 `set -u` **之前** source：setup.bash 會讀未設定的
# AMENT_TRACE_SETUP_FILES。沒有 source 的話攻擊行程 import rclpy 就死，
# 而那在 gate 眼裡是「攻擊沒有執行」——判定正確，但整批白跑。
# 2026-09-01 第一次跑就是這樣，九支全部 return_code=1。
ROS_SETUP="${ROS_SETUP:-/opt/ros/jazzy/setup.bash}"
if [ -r "$ROS_SETUP" ]; then
  # shellcheck disable=SC1090
  . "$ROS_SETUP"
else
  printf '⛔ 找不到 ROS setup：%s\n' "$ROS_SETUP" >&2
  exit 2
fi

set -u

python3 -c "import rclpy" 2>/dev/null || {
  printf '⛔ source 過 ROS 但仍然 import 不到 rclpy，攻擊行程一定會失敗\n' >&2
  exit 2
}

# 同機 smoke 的正解就是 lo，與 `formal_preflight.py` 的 same_host_loopback
# 規則一致——那條規則早就存在，只是這支腳本沒有套用它。
IFACE="${1:-lo}"
if [ "$IFACE" != "lo" ] &&    [ "${SMOKE_ALLOW_NON_LOOPBACK:-}" != "i_know_this_cannot_see_same_host_dds" ]; then
  printf '⛔ 介面 %s 看不到同機 ROS 2 的流量，這一批的網路特徵會是無效的。
' "$IFACE" >&2
  printf '   同機 smoke 請用 lo。真的要用其他介面，設
' >&2
  printf '   SMOKE_ALLOW_NON_LOOPBACK=i_know_this_cannot_see_same_host_dds
' >&2
  exit 2
fi
WORKSPACE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
CATALOG="firewall_lab/scenarios_smoke_candidates.json"
OUT="${SMOKE_OUT:-$HOME/candidate_smoke_$(date -u +%Y%m%dT%H%M%SZ)}"

# 候選清單**從 catalog 讀**，不寫死。
#
# 2026-09-02 的教訓：寫死的陣列與檔案分岔之後，4 支已經升級或丟棄的候選
# 仍留在陣列裡，每一支都印 `unknown scenario` 然後被跳過。腳本 rc 仍是 0，
# 摘要仍寫「通過 N / 9」——分母是陣列長度而不是實際跑到的數量。
CANDIDATES=()
while IFS= read -r line; do
  [ -n "$line" ] && CANDIDATES+=("$line")
done < <(python3 - "$CATALOG" <<'PY_LIST'
import json, sys
from pathlib import Path
doc = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for s in doc["scenarios"]:
    if s["id"] != "normal_patrol":
        print(s["id"])
PY_LIST
)
[ "${#CANDIDATES[@]}" -gt 0 ] || { echo "⛔ 候選 catalog 是空的"; exit 2; }

cd "$WORKSPACE" || exit 1
mkdir -p "$OUT" || exit 1

# telemetry 走 Unix domain socket，而工作區在 /mnt/c（9p/drvfs）——那裡建不出
# socket（Errno 95）。orchestrator 與 live_stack 都認 FIREWALL_LIVE_RUNTIME，
# 指到 ext4 上。**stack 必須用同一個值啟動**，否則節點會送到別的地方去。
export FIREWALL_LIVE_RUNTIME="${FIREWALL_LIVE_RUNTIME:-$HOME/.sros2_live_runtime}"
mkdir -p "$FIREWALL_LIVE_RUNTIME" || exit 1
echo "  runtime dir : $FIREWALL_LIVE_RUNTIME"

python3 - "$FIREWALL_LIVE_RUNTIME" <<'PYEOF' || exit 2
import os
import socket
import sys

directory = sys.argv[1]
probe = os.path.join(directory, ".socket_probe")
try:
    handle = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    handle.bind(probe)
    handle.close()
    os.unlink(probe)
except OSError as error:
    print(f"⛔ {directory} 不支援 Unix socket：{error}")
    print("   telemetry 會收不到任何東西，整批是零事件——那與「防禦有效」")
    print("   在資料上長得一樣。換一個 ext4 上的目錄。")
    raise SystemExit(2)
PYEOF

echo "=================================================================="
echo " 候選攻擊 smoke——證據排他性 gate"
echo "=================================================================="
echo "  輸出   : $OUT"
echo "  介面   : $IFACE"
echo "  候選   : ${#CANDIDATES[@]} 支 ＋ 3 場基線"
echo "  預期約 $(( (${#CANDIDATES[@]} + 3) * 52 / 60 )) 分鐘"
echo

run_one() {
  local scenario="$1" seed="$2"
  echo "── $scenario ──"
  python3 -m firewall_lab.orchestrator \
    --catalog "$CATALOG" \
    --scenario "$scenario" \
    --sessions 1 \
    --seed "$seed" \
    --mode live \
    --security-mode permissive \
    --capture-interface "$IFACE" \
    --output "$OUT" \
    --confirm-isolated-lab 2>&1 | tail -3
}

# 基線先跑：gate 需要它，而且先跑能確認整條管線是活的。
for i in 1 2 3; do
  run_one normal_patrol "$((900 + i))"
done

for index in "${!CANDIDATES[@]}"; do
  run_one "${CANDIDATES[$index]}" "$((1000 + index))"
done

echo
echo "=================================================================="
echo " 逐一過 gate"
echo "=================================================================="
mapfile -t BASELINES < <(ls -d "$OUT"/*_normal_patrol_* 2>/dev/null)
if [ "${#BASELINES[@]}" -eq 0 ]; then
  echo "⛔ 沒有基線場次，gate 無從比較。整批作廢。"
  exit 2
fi

PASSED=0
for index in "${!CANDIDATES[@]}"; do
  scenario="${CANDIDATES[$index]}"
  session=$(ls -d "$OUT"/*_"${scenario}"_* 2>/dev/null | head -1)
  if [ -z "$session" ]; then
    echo "── $scenario : ⛔ 沒有產生 session（orchestrator 失敗）"
    continue
  fi
  # 不要寫成 `if cmd | tail; then`——管線的退出碼取自最後一個指令（tail），
  # 而 tail 永遠成功。2026-09-01 第一次跑就因此印出「通過 9 / 9」，
  # 而真實情況是九支全部作廢。回報全部通過的腳本比沒有腳本更危險。
  gate_log="$OUT/gate_${scenario}.log"
  python3 工具腳本/check_evidence_exclusivity.py \
    --candidate "$session" \
    --baseline "${BASELINES[@]}" \
    --output "$OUT/gate_${scenario}.json" > "$gate_log" 2>&1
  gate_rc=$?
  tail -12 "$gate_log"
  if [ "$gate_rc" -eq 0 ]; then
    PASSED=$((PASSED + 1))
  fi
  echo
done

echo "=================================================================="
echo " 通過 $PASSED / ${#CANDIDATES[@]}"
echo " 報告在 $OUT/gate_*.json"
echo "=================================================================="
echo
echo "=================================================================="
echo " 擷取範圍稽核（判定之後才跑，因為它會否決上面整張表）"
echo "=================================================================="
# gate 只看遙測，所以它不會發現擷取是空的。這一步獨立問：這一批的封包
# 擷取裡到底有沒有同機 DDS 的使用者資料？沒有的話上面的 gate 結論對
# **網路層**完全不適用——是無效，不是陰性。
if ! python3 工具腳本/audit_capture_scope.py --batch "$OUT"        --output "$OUT/capture_scope.json"; then
  echo
  echo "⛔ 這一批的封包擷取無效。gate 的遙測判定仍然成立，但任何"
  echo "   以網路特徵做出的判定都不可引用。"
  exit 3
fi

echo
echo "⚠️ 預期（2026-09-01 事前寫下）：打已修補缺陷的六支多半不會通過——"
echo "   N2、N5、N4、N20、N24b、N8。若它們反而通過了，代表那些漏洞沒有"
echo "   真的修好，那是比補資料更重要的發現。"
