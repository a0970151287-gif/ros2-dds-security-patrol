#!/usr/bin/env bash
# ============================================================================
# block_source.sh <來源IP> [封鎖秒數] — DoS 主動阻斷（被 Zeek 偵測到風暴時呼叫）
#
# Zeek 以 root 跑(sudo zeek -i eth0)，故可直接下 iptables。
# 對偵測到的洪水來源 IP 加一條 INPUT DROP（限 DDS UDP 埠），N 秒後自動移除。
# 冪等：同 IP 已封鎖則不重複加。
#
# ⚠️ WSL2 mirrored 模式下，host 端 iptables 可能不攔截鏡像流量；
#    若無效，改用 Windows 端防火牆封鎖該來源（見 DoS_DDoS防禦策略.md）。
# ============================================================================
set -uo pipefail
IP="${1:?用法: block_source.sh <IP> [秒數]}"
SECS="${2:-300}"
PORTLO=7400; PORTHI=65000
CHAIN="DDS_DOS_BLOCK"

command -v iptables >/dev/null 2>&1 || { echo "no iptables"; exit 0; }

# 自有 chain（與系統規則隔離，方便清理）
iptables -nL "$CHAIN" >/dev/null 2>&1 || {
  iptables -N "$CHAIN" 2>/dev/null
  iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT -j "$CHAIN"
}

# 冪等：已封鎖就跳過
if iptables -C "$CHAIN" -s "$IP" -p udp --dport "$PORTLO:$PORTHI" -j DROP 2>/dev/null; then
  echo "[block] $IP 已在封鎖中"; exit 0
fi

iptables -I "$CHAIN" -s "$IP" -p udp --dport "$PORTLO:$PORTHI" -j DROP
echo "[block] 已封鎖 $IP（DDS UDP $PORTLO-$PORTHI）$SECS 秒"

# 排程自動解封（背景，不卡 Zeek）
( sleep "$SECS"
  iptables -D "$CHAIN" -s "$IP" -p udp --dport "$PORTLO:$PORTHI" -j DROP 2>/dev/null
  echo "[block] $IP 已自動解封" ) >/dev/null 2>&1 &
