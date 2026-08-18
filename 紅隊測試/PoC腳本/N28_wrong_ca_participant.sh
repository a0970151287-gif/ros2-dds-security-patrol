#!/usr/bin/env bash
# 攻擊 N28 — wrong-CA secure participant：進入 SROS2 握手然後認證失敗
#
# 為什麼需要這個攻擊：
#   既有的 unauthorized_participant 用的是「完全沒有安全設定」的 participant
#   （ros2 run demo_nodes_cpp talker）。它不會進入 SROS2 的安全握手，因此
#   防守方沒有任何「認證失敗」可以記錄——1,100 場正式資料中
#   sros_auth_fail_rate 與 sros_permission_deny_rate 恆為零，這是主因之一。
#   它不是被拒絕，是從一開始就不在那個協定裡。
#
#   N28 相反：攻擊者**有**一張看起來完整的身分憑證，只是由**別的 CA** 簽的。
#   它會發起握手，防守方用自己的 identity_ca 驗證憑證鏈 → 驗不過 → 拒絕，
#   並在 DDS Security audit log 產生一筆 authentication 記錄。
#
# 與 N26 的差別（互補，不重複）：
#   N26 假設 CA 私鑰外洩，用**偷來的真 CA** 簽 → 認證會**通過** → 繞過 Enforce。
#   N28 不需要任何秘密，攻擊者自己生一個 CA → 認證**必定失敗** → 產生拒絕證據。
#   N28 是更基本的威脅：任何人都做得到，不需要先攻破信任根。
#
# 安全邊界：
#   - 只「讀」真 keystore 的 public 憑證（判斷 CN 命名慣例），不讀私鑰、不寫入。
#   - 所有偽造產物寫在 /tmp/sros2_wrongca，結束時保留供稽核。
#   - 不使用 sudo、不修改防火牆、不跨主機。
#   - 需要與防守方同一個 domain 才會產生握手，預設 30（與既有情境一致）。
set -u

DURATION="${1:-40}"
DOMAIN="${ROS_DOMAIN_ID:-30}"
REAL_KEYSTORE="${SROS2_REAL_KEYSTORE:-$HOME/ros2_ws/sros2_keystore}"
W=/tmp/sros2_wrongca
NODE_CN="/wrong_ca_intruder"

echo "=================================================================="
echo " N28  wrong-CA secure participant → authentication denial"
echo "=================================================================="
echo "  domain    : $DOMAIN"
echo "  duration  : ${DURATION}s"
echo "  workspace : $W"

if [ ! -d "$REAL_KEYSTORE/public" ]; then
  echo "❌ 找不到防守方 keystore: $REAL_KEYSTORE" >&2
  exit 2
fi

# 三道 preflight。本專案已出現過三次「攻擊回報成功但其實沒執行」，
# 每次都是環境問題被靜默吞掉，所以一律先擋、大聲失敗。
command -v ros2 >/dev/null 2>&1 || {
  echo "❌ 找不到 ros2。請先 source 工具腳本/load_ros_environment.sh" >&2
  exit 3
}
command -v openssl >/dev/null 2>&1 || { echo "❌ 找不到 openssl" >&2; exit 3; }

rm -rf "$W"; mkdir -p "$W/enclaves/$NODE_CN" "$W/public" "$W/private"
cd "$W" || exit 1

# ── 1. 生一個完全獨立的 CA。這是重點：不碰真 CA，也不需要它的私鑰 ──────────
echo
echo "[1/4] 生成攻擊者自己的 CA（與防守方無任何關係）"
printf '[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=v3\n[dn]\nCN=wrongCA\n[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.cnf
openssl ecparam -name prime256v1 -genkey -noout -out private/ca.key.pem 2>/dev/null
openssl req -new -x509 -key private/ca.key.pem -out public/ca.cert.pem \
  -days 30 -config ca.cnf 2>/dev/null
cp public/ca.cert.pem public/identity_ca.cert.pem
cp public/ca.cert.pem public/permissions_ca.cert.pem
echo "      CA subject: $(openssl x509 -in public/ca.cert.pem -noout -subject 2>/dev/null)"
echo "      防守方 CA : $(openssl x509 -in "$REAL_KEYSTORE/public/identity_ca.cert.pem" -noout -subject 2>/dev/null)"
echo "      → 兩者不同，憑證鏈驗證必定失敗，這正是本攻擊要觸發的路徑"

# ── 2. 用這個 CA 簽一張身分憑證，CN 沿用 SROS2 的 /node_name 慣例 ──────────
echo
echo "[2/4] 用攻擊者 CA 簽出身分憑證 CN=$NODE_CN"
E="enclaves/$NODE_CN"
printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=%s\n' "$NODE_CN" > node.cnf
openssl ecparam -name prime256v1 -genkey -noout -out "$E/key.pem" 2>/dev/null
openssl req -new -key "$E/key.pem" -out node.csr -config node.cnf 2>/dev/null
openssl x509 -req -in node.csr -CA public/ca.cert.pem -CAkey private/ca.key.pem \
  -CAcreateserial -out "$E/cert.pem" -days 30 2>/dev/null
cp public/identity_ca.cert.pem    "$E/identity_ca.cert.pem"
cp public/permissions_ca.cert.pem "$E/permissions_ca.cert.pem"

# ── 3. governance 與 permissions，同樣用攻擊者 CA 簽 ───────────────────────
echo
echo "[3/4] 產生並簽署 governance / permissions"
cat > governance.xml <<XML
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <domain_access_rules>
    <domain_rule>
      <domains><id>$DOMAIN</id></domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <liveliness_protection_kind>ENCRYPT</liveliness_protection_kind>
      <rtps_protection_kind>SIGN</rtps_protection_kind>
      <topic_access_rules>
        <topic_rule>
          <topic_expression>*</topic_expression>
          <enable_discovery_protection>true</enable_discovery_protection>
          <enable_liveliness_protection>true</enable_liveliness_protection>
          <enable_read_access_control>true</enable_read_access_control>
          <enable_write_access_control>true</enable_write_access_control>
          <metadata_protection_kind>ENCRYPT</metadata_protection_kind>
          <data_protection_kind>ENCRYPT</data_protection_kind>
        </topic_rule>
      </topic_access_rules>
    </domain_rule>
  </domain_access_rules>
</dds>
XML
cat > permissions.xml <<XML
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <permissions>
    <grant name="intruder">
      <subject_name>CN=$NODE_CN</subject_name>
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2027-12-31T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>$DOMAIN</id></domains>
        <publish><topics><topic>*</topic></topics></publish>
        <subscribe><topics><topic>*</topic></topics></subscribe>
      </allow_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
XML
for f in governance permissions; do
  openssl smime -sign -in "$f.xml" -text -outform PEM \
    -signer public/ca.cert.pem -inkey private/ca.key.pem \
    -out "$E/$f.p7s" 2>/dev/null
done
cp permissions.xml "$E/permissions.xml"
echo "      enclave: $(ls "$E" | tr '\n' ' ')"

# ── 4. 以這個 keystore 啟動 secure participant，觸發握手 ──────────────────
echo
echo "[4/4] 以 wrong-CA 身分加入 domain $DOMAIN（Enforce），持續 ${DURATION}s"
echo "      預期：防守方驗不過憑證鏈 → 拒絕 → audit log 出現 authentication 記錄"
export ROS_SECURITY_KEYSTORE="$W"
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_ENCLAVE_OVERRIDE="$NODE_CN"
export ROS_DOMAIN_ID="$DOMAIN"
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export PYTHONUNBUFFERED=1

# 不要用管線接 tail：$? 會變成 tail 的狀態，讓失敗看起來像成功。
ATTACK_LOG="$W/attack_output.log"
timeout --signal=TERM "$DURATION" ros2 run demo_nodes_cpp talker --ros-args --enclave "$NODE_CN" >"$ATTACK_LOG" 2>&1
rc=$?
tail -20 "$ATTACK_LOG"

# timeout 正常結束回 124；其餘非零代表 participant 根本沒起來。
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
  echo "❌ participant 未能啟動（rc=$rc）——沒有握手，不可視為攻擊已執行。" >&2
fi
if grep -qE "Traceback|command not found|No such file" "$ATTACK_LOG" 2>/dev/null; then
  echo "❌ 攻擊行程崩潰，見 $ATTACK_LOG" >&2
  rc=1
fi

echo
echo "=================================================================="
echo " 結束（rc=$rc）。攻擊者產物保留在 $W 供稽核。"
echo " 檢查防守方是否記錄了拒絕："
echo "   \$FIREWALL_LIVE_RUNTIME/dds_security_audit.log"
echo "=================================================================="
