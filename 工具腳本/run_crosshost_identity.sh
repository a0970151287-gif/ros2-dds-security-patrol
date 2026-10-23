#!/usr/bin/env bash
# 跨主機身份證據收集——**防守端**。
#
# 攻擊端在另一台機器，見 文件/跨主機攻擊機交接_2026-08-26.md。
#
# 這支把兩半證據同時收起來再交叉比對：
#
#   security_observer  →  GUID ＋ 認證判定（但拿不到攻擊者的位址）
#   dumpcap → tshark   →  GUID ↔ 實際來源 IP（但不知道合不合法）
#   crosscheck         →  逐 IP 判定哪個位址真的可以封鎖
#
# 不需要 sudo：dumpcap 有 cap_net_raw。
#
# 用法：
#   bash 工具腳本/run_crosshost_identity.sh <介面> [秒數]
#
# 例：bash 工具腳本/run_crosshost_identity.sh eth0 90
#
# 執行後會印出**攻擊視窗的起訖時間**，請在那段時間內於攻擊機執行 N28。

# ⚠️ 必須在 `set -u` **之前** source——ROS 的 setup.bash 會讀未設定的
# AMENT_TRACE_SETUP_FILES，在 `set -u` 下會直接中止。
#
# 而 source 本身是必要的，不是習慣問題：觀測者連結的 libfastrtps 是對
# ROS 那份 FastCDR 編譯的，沒有 ROS 的 LD_LIBRARY_PATH 時會載入
# /usr/local/lib/libfastcdr.so.2。實測（2026-08-26）那會讓 discovery
# 完全失效——觀測者跑滿整個視窗卻**一個 participant 都沒看到**，
# 而封包擷取證明攻擊者確實同時在線。這正是階段 0c 那次無法解釋的空檔。
ROS_SETUP="${ROS_SETUP:-/opt/ros/jazzy/setup.bash}"
# shellcheck disable=SC1090
[ -r "$ROS_SETUP" ] && . "$ROS_SETUP"

set -u

IFACE="${1:?請指定擷取介面，例如 eth0。可用 dumpcap -D 查看}"
DURATION="${2:-90}"
DOMAIN="${ROS_DOMAIN_ID:-30}"
WORKSPACE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
KEYSTORE="${SROS2_REAL_KEYSTORE:-$HOME/ros2_ws/sros2_keystore}"
ENCLAVE="${OBSERVER_ENCLAVE:-$KEYSTORE/enclaves/security_readiness_probe}"
OBSERVER_BIN="${OBSERVER_BIN:-$HOME/observer_build/security_observer}"
VENV_PYTHON="${SROS2_ML_VENV:-$HOME/.venvs/sros2-firewall}/bin/python"

SESSION="$(date -u +%Y%m%dT%H%M%S%6NZ)_crosshost_$(openssl rand -hex 4)"
OUT="${CROSSHOST_OUT:-$HOME/crosshost}/$SESSION"
mkdir -p "$OUT" || exit 1

# ── preflight：這個專案被「看起來成功但其實沒執行」咬過三次，一律先擋 ────
fail() { printf '❌ %s\n' "$1" >&2; exit 2; }

[ -x "$OBSERVER_BIN" ] || fail "找不到觀測者：$OBSERVER_BIN（先 cmake --build）"
[ -r "$ENCLAVE/key.pem" ] || fail "找不到觀測者 enclave：$ENCLAVE"
[ -x "$VENV_PYTHON" ] || fail "找不到 Python 環境：$VENV_PYTHON"
command -v dumpcap >/dev/null 2>&1 || fail "找不到 dumpcap"
command -v tshark  >/dev/null 2>&1 || fail "找不到 tshark"
dumpcap -D 2>/dev/null | grep -qw "$IFACE" || \
  fail "介面 $IFACE 不在 dumpcap -D 的清單裡"

# 觀測者必須與 libfastrtps 載入**同一套** FastCDR，否則 discovery 靜默失效：
# 程式跑滿整個視窗、log 乾乾淨淨、事件檔是空的。這種失敗看起來像「沒有攻擊」，
# 是這個專案最危險的那類錯誤，所以在這裡 fail-closed 而不是事後才發現。
CDR_PATH="$(ldd "$OBSERVER_BIN" 2>/dev/null \
  | awk '/libfastcdr/ {print $3}' | head -n1)"
RTPS_PATH="$(ldd "$OBSERVER_BIN" 2>/dev/null \
  | awk '/libfastrtps/ {print $3}' | head -n1)"
[ -n "$CDR_PATH" ] && [ -n "$RTPS_PATH" ] || \
  fail "無法判斷觀測者載入哪一套 Fast DDS（ldd 沒有輸出）"
[ "$(dirname "$CDR_PATH")" = "$(dirname "$RTPS_PATH")" ] || \
  fail "FastCDR 與 FastRTPS 來自不同目錄，discovery 會靜默失效：
       libfastrtps : $RTPS_PATH
       libfastcdr  : $CDR_PATH
     請先 source $ROS_SETUP，或設定 LD_LIBRARY_PATH 指向同一個前綴。"

# 介面位址檢查。跨主機要成立，攻擊機必須連得到這個位址；預設 NAT 模式的 WSL2
# 躲在 172.16–172.31 後面，區網上的另一台機器打不進來，DDS 多播也穿不過去。
# 這裡不中止——同機診斷是合法用途——但要講清楚，否則會白跑一輪。
IFACE_IPV4="$(ip -4 -o addr show dev "$IFACE" 2>/dev/null \
  | awk '{print $4}' | cut -d/ -f1 | head -n1)"
case "${IFACE_IPV4:-}" in
  172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
    echo "⚠️  $IFACE 的位址是 $IFACE_IPV4 —— 看起來是 WSL2 NAT。"
    echo "    攻擊機在區網上連不到這個位址，跨主機收集會拿不到對方的封包。"
    echo "    需要 networkingMode=mirrored（Jesse 自己改 .wslconfig 後 wsl --shutdown）。"
    echo "    若這一輪只是同機診斷，可以忽略這則警告。"
    echo
    ;;
esac

# SPDP 預設走多播。有線沒問題，**Wi-Fi 對 Wi-Fi 常常被 AP 吃掉**，而失敗形態
# 又是「觀測者什麼都沒記到」——與防禦成功外觀相同。既然攻擊機的位址本來就要
# 給（ATTACKER_IP），就直接拿它當 unicast initial peer，discovery 不再賭多播。
PEERS="${OBSERVER_PEERS:-${ATTACKER_IP:-}}"

# WSL 的 mirrored 模式會在 `lo` 上放一個 scope global 的 10.255.255.254/32。
# Fast DDS 把它當成可宣告的單播 locator → **discovery 完全靜默失敗**：
# 節點正常啟動、log 乾淨、事件檔是空的。2026-08-27 實測，見
# 工具腳本/make_fastdds_profile.py 的對照表。
#
# 兩邊都要釘：ROS 節點吃 profile，觀測者自帶 QoS 所以要用環境變數。
PIN_ADDRESS="${OBSERVER_INTERFACE_ADDRESS:-$IFACE_IPV4}"
if [ -n "$PIN_ADDRESS" ]; then
  FASTDDS_PROFILE="$OUT/fastdds_pinned.xml"
  "$VENV_PYTHON" "$WORKSPACE/工具腳本/make_fastdds_profile.py" \
    --interface "$IFACE" --output "$FASTDDS_PROFILE" >/dev/null \
    || fail "無法產生 Fast DDS profile"
  export FASTRTPS_DEFAULT_PROFILES_FILE="$FASTDDS_PROFILE"
fi

POLICY_SHA="$(sha256sum "$WORKSPACE/firewall_lab/action_policy.json" | cut -c1-64)"

echo "=================================================================="
echo " 跨主機身份收集（防守端）"
echo "=================================================================="
echo "  session   : $SESSION"
echo "  介面      : $IFACE"
echo "  domain    : $DOMAIN"
echo "  觀測者    : $ENCLAVE"
echo "  輸出      : $OUT"
if [ -n "$PEERS" ]; then
  echo "  unicast peer : $PEERS（discovery 不依賴多播）"
else
  echo "  unicast peer : 未設定——只靠多播。Wi-Fi 連線建議設 ATTACKER_IP。"
fi
echo

# ── 1. 封包擷取 ───────────────────────────────────────────────────────────
# 只收 UDP：RTPS 走 UDP，收 TCP 只會讓檔案變大。
dumpcap -i "$IFACE" -f "udp" -w "$OUT/traffic.pcapng" -q \
  > "$OUT/dumpcap.log" 2>&1 &
CAP=$!
sleep 2
kill -0 $CAP 2>/dev/null || { cat "$OUT/dumpcap.log"; fail "擷取沒有啟動"; }
echo "[1/4] 封包擷取已啟動"

# ── 2. 觀測者 ─────────────────────────────────────────────────────────────
# 觀測者要**先於**攻擊者啟動，這樣最穩。
# （先前記為「相反順序會漏記、成因未查明」的現象，2026-08-26 已查明是上面那個
#  FastCDR 不一致，與啟動順序無關；preflight 已擋住。）
OBSERVER_IDENTITY_CA="$ENCLAVE/identity_ca.cert.pem" \
OBSERVER_CERTIFICATE="$ENCLAVE/cert.pem" \
OBSERVER_PRIVATE_KEY="$ENCLAVE/key.pem" \
OBSERVER_GOVERNANCE="$ENCLAVE/governance.p7s" \
OBSERVER_PERMISSIONS="$ENCLAVE/permissions.p7s" \
OBSERVER_PERMISSIONS_CA="$ENCLAVE/permissions_ca.cert.pem" \
OBSERVER_AUDIT_LOG="$OUT/dds_security_audit.log" \
OBSERVER_EVENTS_LOG="$OUT/observer_events.jsonl" \
OBSERVER_LOG_LEVEL=DEBUG_LEVEL \
OBSERVER_PEERS="$PEERS" \
OBSERVER_INTERFACE_ADDRESS="$PIN_ADDRESS" \
"$OBSERVER_BIN" "$DOMAIN" "$DURATION" > "$OUT/observer.log" 2>&1 &
OBS=$!
sleep 3
kill -0 $OBS 2>/dev/null || { cat "$OUT/observer.log"; fail "觀測者沒有啟動"; }
echo "[2/4] 觀測者已啟動"
echo
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │  現在到攻擊機執行 N28（約 $((DURATION - 10)) 秒內）        │"
echo "  │    export ROS_DOMAIN_ID=$DOMAIN                            │"
echo "  │    bash N28_wrong_ca_participant.sh 40                    │"
echo "  └──────────────────────────────────────────────────────────┘"
echo
date -u +"  攻擊視窗開始 %Y-%m-%dT%H:%M:%SZ"

wait $OBS
date -u +"  攻擊視窗結束 %Y-%m-%dT%H:%M:%SZ"
sleep 2
kill $CAP 2>/dev/null
sleep 2
echo "[3/4] 收集結束"

# ── 3. 解碼與轉換 ─────────────────────────────────────────────────────────
cd "$WORKSPACE" || exit 1
"$VENV_PYTHON" 工具腳本/decode_rtps_identity.py \
  --capture "$OUT/traffic.pcapng" \
  --output "$OUT/rtps_identity_packets.jsonl" \
  --session-id "$SESSION" --security-mode enforce \
  --collector-id pcap-decoder --interface "$IFACE" \
  --policy-sha256 "$POLICY_SHA" || fail "封包解碼失敗"

# 觀測者那一半可能沒有可用的宣告位址（攻擊者就是這種情形），
# 所以轉換失敗不中止——交叉比對本來就只需要事件檔。
"$VENV_PYTHON" 工具腳本/observer_events_to_observations.py \
  --events "$OUT/observer_events.jsonl" \
  --output "$OUT/rtps_identity_observer.jsonl" \
  --session-id "$SESSION" --security-mode enforce \
  --collector-id security-observer --interface "$IFACE" \
  --policy-sha256 "$POLICY_SHA" || \
  echo "ℹ️  觀測者那一半沒有產出契約觀測（攻擊者無宣告位址時屬正常）"

# 鏈路層綁定：擋「來源位址偽造」。攻擊者可以用受害者的 IP 送 RTPS，前三條
# 判定全部會成立，於是系統宣告一個無辜主機可封鎖。防守方送出時的 eth.dst 是
# 它自己的 ARP 解析結果，收到時的 eth.src 是實際發送者——偽造時兩者必然不同。
"$VENV_PYTHON" 工具腳本/check_link_layer_binding.py \
  --capture "$OUT/traffic.pcapng" \
  --output "$OUT/link_layer_binding.json" || \
  fail "鏈路層綁定檢查失敗"

echo "[4/4] 交叉比對"
echo
# ATTACKER_IP 由攻擊機回報。給了之後，若它的封包一個都沒到，報告會明確標成
# 「路徑不通、本輪證據無效」，而不是安靜地少一列——那會被誤讀成防禦成功。
CROSSCHECK_ARGS=""
[ -n "${ATTACKER_IP:-}" ] && CROSSCHECK_ARGS="--expect-attacker-ip $ATTACKER_IP"

# shellcheck disable=SC2086
"$VENV_PYTHON" 工具腳本/crosscheck_identity_attribution.py \
  --packet-observations "$OUT/rtps_identity_packets.jsonl" \
  --observer-events "$OUT/observer_events.jsonl" \
  --link-layer "$OUT/link_layer_binding.json" \
  --output "$OUT/crosscheck.json" $CROSSCHECK_ARGS

echo
echo "=================================================================="
echo " 全部產物在 $OUT"
echo "=================================================================="
