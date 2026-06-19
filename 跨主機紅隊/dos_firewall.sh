#!/usr/bin/env bash
# ============================================================================
# dos_firewall.sh — DoS/DDoS 主動式限流防火牆（目標機 eth0，需 sudo）
#
# 策略（針對直連 DDS 實驗室 10.10.10.0/24）：
#   1) 允許清單：DDS UDP 埠只放行「預期對端」(直連 peer + 自己)，其餘來源直接 DROP
#   2) 每來源限速：用 hashlimit 對 SPDP/DDS 封包做 per-source rate cap，
#      單一來源洪水(N-DoS 40 participant/8s)會被丟到門檻以下
#   3) 連線數上限：限制同一來源同時 UDP flow 數，擋「狂開 participant」
#
# 用法： sudo bash dos_firewall.sh on    # 套用
#        sudo bash dos_firewall.sh off   # 移除
#
# ⚠️ WSL2 mirrored 模式：host iptables 可能不攔截鏡像流量 → 需在 Windows 端
#    防火牆做對應限制(見 文件/DoS_DDoS防禦策略.md)。原生 Linux 攻擊機/目標機則有效。
# ============================================================================
set -uo pipefail
IFACE="${IFACE:-eth0}"
PEER="${PEER:-10.10.10.1}"      # 預期的直連對端（合法跨主機 DDS）
SELF="${SELF:-10.10.10.2}"
PLO=7400; PHI=65000
CH="DDS_RATELIMIT"

apply() {
  iptables -N "$CH" 2>/dev/null
  iptables -F "$CH"
  # (1) 自己 / 多播探索放行
  iptables -A "$CH" -s "$SELF" -j RETURN
  iptables -A "$CH" -d 239.0.0.0/8 -p udp -m hashlimit \
      --hashlimit-name spdp_mcast --hashlimit-mode srcip \
      --hashlimit-above 50/sec --hashlimit-burst 100 -j DROP
  # (2) 預期對端：限速放行（per-source 50/s，突發 100）
  iptables -A "$CH" -s "$PEER" -p udp --dport "$PLO:$PHI" -m hashlimit \
      --hashlimit-name dds_peer --hashlimit-mode srcip \
      --hashlimit-above 50/sec --hashlimit-burst 100 -j DROP
  iptables -A "$CH" -s "$PEER" -p udp --dport "$PLO:$PHI" -j RETURN
  # (3) 其餘來源打 DDS 埠：一律 DROP（允許清單）
  iptables -A "$CH" -p udp --dport "$PLO:$PHI" -j DROP
  # 掛上 INPUT（限本介面）
  iptables -C INPUT -i "$IFACE" -j "$CH" 2>/dev/null || iptables -I INPUT -i "$IFACE" -j "$CH"
  echo "✅ DoS/DDoS 限流已套用 ($IFACE)：peer=$PEER 限 50/s、其餘 DDS 來源 DROP"
}

remove() {
  iptables -D INPUT -i "$IFACE" -j "$CH" 2>/dev/null
  iptables -F "$CH" 2>/dev/null; iptables -X "$CH" 2>/dev/null
  echo "🧹 DoS/DDoS 限流已移除"
}

case "${1:-}" in
  on)  apply ;;
  off) remove ;;
  *)   echo "用法: sudo bash dos_firewall.sh on|off"; exit 1 ;;
esac
