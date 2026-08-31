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
#     bash 工具腳本/run_candidate_smoke.sh eth1
set -u

IFACE="${1:?請指定擷取介面，例如 eth1。可用 dumpcap -D 查看}"
WORKSPACE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
CATALOG="firewall_lab/scenarios_smoke_candidates.json"
OUT="${SMOKE_OUT:-$HOME/candidate_smoke_$(date -u +%Y%m%dT%H%M%SZ)}"

CANDIDATES=(
  baseline_poisoning
  confused_deputy
  cross_channel_relay
  health_spoof
  mission_spoof
  node_name_evasion
  scan_drift
  verify_flood
  discovery_recon
)

cd "$WORKSPACE" || exit 1
mkdir -p "$OUT" || exit 1

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
  if python3 工具腳本/check_evidence_exclusivity.py \
      --candidate "$session" \
      --baseline "${BASELINES[@]}" \
      --output "$OUT/gate_${scenario}.json" 2>&1 | tail -12; then
    PASSED=$((PASSED + 1))
  fi
  echo
done

echo "=================================================================="
echo " 通過 $PASSED / ${#CANDIDATES[@]}"
echo " 報告在 $OUT/gate_*.json"
echo "=================================================================="
echo
echo "⚠️ 預期（2026-09-01 事前寫下）：打已修補缺陷的六支多半不會通過——"
echo "   N2、N5、N4、N20、N24b、N8。若它們反而通過了，代表那些漏洞沒有"
echo "   真的修好，那是比補資料更重要的發現。"
