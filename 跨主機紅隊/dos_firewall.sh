#!/usr/bin/env bash
# ============================================================================
# 固定 L1 DDS 限流實驗腳本（不由 Zeek／ML 自動執行，也不由 installer 安裝）
#
# 僅供管理者在自有、無路由的隔離跨主機實驗中明確手動操作；它不是通過
# signed-ticket 准入的正式 response backend，也不得建立 NOPASSWD 規則。
#
# 僅保護本專題固定的 eth0 / 10.10.10.1↔10.10.10.2 / DDS domain 0..30
# 實驗網段；不接受環境變數覆寫，避免受限 sudo 被拿去修改其他介面/主機。
# WSL2 mirrored 模式下 Linux iptables 可能不攔截鏡像流量，需另驗證 Windows
# 防火牆效果。
# ============================================================================
set -euo pipefail

readonly IFACE="eth0"
readonly PEER="10.10.10.1"
readonly SELF="10.10.10.2"
readonly PORT_LOW=7400
readonly PORT_HIGH=15200
readonly CHAIN="DDS_RATELIMIT"

if (( EUID != 0 )); then
  echo "dos-firewall 僅能由隔離實驗管理者以 root 明確執行" >&2
  exit 1
fi
command -v iptables >/dev/null 2>&1 || {
  echo "找不到 iptables" >&2
  exit 1
}
[[ -d "/sys/class/net/$IFACE" ]] || {
  echo "找不到固定介面 $IFACE；拒絕猜測其他介面" >&2
  exit 1
}

apply_rules() {
  iptables -w 5 -nL "$CHAIN" >/dev/null 2>&1 ||
    iptables -w 5 -N "$CHAIN"
  iptables -w 5 -F "$CHAIN"

  # 本機回送與合法對端；只作用在本專題 DDS UDP 範圍。
  iptables -w 5 -A "$CHAIN" -s "$SELF" -p udp \
    --dport "$PORT_LOW:$PORT_HIGH" -j RETURN
  iptables -w 5 -A "$CHAIN" -d 239.0.0.0/8 -p udp \
    --dport "$PORT_LOW:$PORT_HIGH" -m hashlimit \
    --hashlimit-name dds_spdp_mcast --hashlimit-mode srcip \
    --hashlimit-above 50/sec --hashlimit-burst 100 -j DROP
  iptables -w 5 -A "$CHAIN" -s "$PEER" -p udp \
    --dport "$PORT_LOW:$PORT_HIGH" -m hashlimit \
    --hashlimit-name dds_peer --hashlimit-mode srcip \
    --hashlimit-above 50/sec --hashlimit-burst 100 -j DROP
  iptables -w 5 -A "$CHAIN" -s "$PEER" -p udp \
    --dport "$PORT_LOW:$PORT_HIGH" -j RETURN
  iptables -w 5 -A "$CHAIN" -p udp \
    --dport "$PORT_LOW:$PORT_HIGH" -j DROP

  iptables -w 5 -C INPUT -i "$IFACE" -j "$CHAIN" 2>/dev/null ||
    iptables -w 5 -I INPUT -i "$IFACE" -j "$CHAIN"
  echo "✅ DDS 限流已套用：$IFACE，peer=$PEER，UDP $PORT_LOW-$PORT_HIGH"
}

remove_rules() {
  iptables -w 5 -D INPUT -i "$IFACE" -j "$CHAIN" 2>/dev/null || true
  iptables -w 5 -F "$CHAIN" 2>/dev/null || true
  iptables -w 5 -X "$CHAIN" 2>/dev/null || true
  echo "🧹 DDS 限流已移除"
}

case "${1:-}" in
  on) apply_rules ;;
  off) remove_rules ;;
  *)
    echo "用法：dos-firewall on|off" >&2
    exit 2
    ;;
esac
