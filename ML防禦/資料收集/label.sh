#!/usr/bin/env bash
# ============================================================================
# label.sh — Phase 2 乾淨標註：攻擊前後打時間戳，取代弱標籤 bootstrap。
#
# 用法：
#   bash label.sh start normal          # 開始一段「正常」基線
#   bash label.sh end   normal
#   bash label.sh start recon           # 紅隊開始跑偵察
#   bash label.sh end   recon
#   bash label.sh start metasploit_scan # Metasploit nmap/掃描
#   bash label.sh end   metasploit_scan
#   bash label.sh note  "說明文字"       # 任意備註（不影響切窗，僅記錄）
#
# 攻擊類別名稱自由（不寫死）：dos / inject / param / spoof / stealth_dos /
# behavioral / metasploit_scan / metasploit_exploit / host_ssh / host_smtp ...
# 每類「隔離跑」（同時間只跑一種），效果最乾淨。
#
# 輸出：ML防禦/資料收集/labels.txt（epoch \t start|end|note \t class \t 備註）
# ============================================================================
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/labels.txt"

action="${1:-}"; cls="${2:-}"
if [[ "$action" != "start" && "$action" != "end" && "$action" != "note" ]]; then
  echo "用法: bash label.sh start|end <class>   或   bash label.sh note \"備註\""
  exit 1
fi

ts=$(date +%s.%N)
human=$(date '+%Y-%m-%d %H:%M:%S')

if [[ "$action" == "note" ]]; then
  msg="${2:-}"
  echo -e "${ts}\tnote\t-\t${msg}" >> "$OUT"
  echo "📝 [$human] 備註: $msg"
else
  echo -e "${ts}\t${action}\t${cls}\t" >> "$OUT"
  if [[ "$action" == "start" ]]; then
    echo "🟢 [$human] START  $cls   (epoch=$ts)"
  else
    echo "🔴 [$human] END    $cls   (epoch=$ts)"
  fi
fi
echo "   → 已記錄到 $OUT"
