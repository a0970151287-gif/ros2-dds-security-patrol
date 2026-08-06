#!/usr/bin/env bash
# ============================================================================
# 主機攻擊面稽核 — 盤點「對外暴露」的服務與介面（免 root，可反覆跑看加固前後）
#
# 加固目標：攻擊面收斂（least exposure）。紅隊測試前後各跑一次，看暴露面有沒有縮。
# 用法： bash 展示指令/主機攻擊面稽核.sh
# ============================================================================
set -uo pipefail
LAB_IF="${LAB_IF:-eth0}"
RISK=0

echo "════════ 主機攻擊面稽核 $(date '+%F %T') ════════"

echo "── 網路介面（非 lab 介面 = 額外暴露路徑）──"
ip -br addr 2>/dev/null | grep -vE "^(lo|docker)" | while read -r ifc st addrs; do
  tag=""
  # 只把 scope global 的 IPv6 視為對外路徑。舊版用任意 2xxx:
  # 片段判斷，會把 fe80::...:2abc:... 的 link-local 位址誤報成公網。
  if ip -6 addr show dev "$ifc" scope global 2>/dev/null |
      grep -qE '^[[:space:]]*inet6 '; then
    tag=" ⚠️全域IPv6"
  fi
  # lab 介面以名稱明確指定；只有其他 UP 且真的有位址的介面才告警。
  if [[ "$ifc" != "$LAB_IF" && "$st" == "UP" && -n "$addrs" ]]; then
    tag="$tag ⚠️非lab介面"
  fi
  echo "  $ifc ($st): $addrs$tag"
done

echo "── 對外暴露的監聽服務（0.0.0.0 / :: → lab 對端與其他網路都搆得到）──"
mapfile -t EXP < <(ss -tulnH 2>/dev/null | awk '$5 ~ /(0\.0\.0\.0|\[::\]|\*):[0-9]+$/ {print $1, $5}' | sort -u)
declare -A RISKY=( [22]="SSH 暴力破解" [23]="Telnet 明文" [25]="SMTP 郵件面" [139]="NetBIOS" [445]="SMB 入侵" [3389]="RDP 登入" [21]="FTP" [3306]="MySQL" [5432]="Postgres" [6379]="Redis" )
for line in "${EXP[@]}"; do
  proto=${line%% *}; hostport=${line##* }; port=${hostport##*:}
  note="${RISKY[$port]:-}"
  if [[ -n "$note" ]]; then echo "  ❗ $proto $hostport  ← $note（考慮關閉或綁 localhost/eth0）"; RISK=$((RISK+1))
  else echo "  •  $proto $hostport"; fi
done
[[ ${#EXP[@]} -eq 0 ]] && echo "  （無任何 0.0.0.0/:: 暴露 — 最佳狀態）"

echo "── SSH 設定（若可讀）──"
cfg=$(grep -rhiE "^\s*(PasswordAuthentication|PermitRootLogin)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null)
if [[ -n "$cfg" ]]; then
  echo "$cfg" | sed 's/^/  /'
  echo "$cfg" | grep -qiE "PasswordAuthentication\s+no" || { echo "  ❗ 未關閉密碼登入 → 建議 key-only"; RISK=$((RISK+1)); }
else echo "  （sshd_config 需 root 才讀得到，用 checklist 手動確認）"; fi

echo "════════════════════════════════"
echo "風險暴露項： $RISK（目標：收斂到 0，只留 lab 必要的 DDS domain 30）"
[[ $RISK -eq 0 ]] && echo "✅ 攻擊面已收斂" || echo "→ 見 文件/主機加固_攻擊面收斂.md 逐項鎖"
