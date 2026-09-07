#!/usr/bin/env bash
# N26b setup — 用「偷來的」CA 私鑰，在隔離 domain 99 建一套 Enforce keystore + 三個 enclave。
#   victim       : 合法 secured listener（訂 rt/chatter）— 防守方授權的受害節點
#   legit_talker : 合法 talker（發 rt/chatter）— baseline，證明安全通道本身會通
#   evil         : 偽造 talker（發 rt/chatter）— 防守方「從未授權」此身分，但用偷來的 CA 簽出
# 對照組（control）在跑節點時做：用「無安全」talker，Enforce 應擋下。
#
# 安全：全程 domain 99；只「讀」真 keystore 的 CA（private/ca.key.pem 644 可讀）+ public cert；
#       所有產物寫 /tmp/sros2_live；不修改真 keystore；不碰 domain 30。
set -u
SRC=/home/jesse/ros2_security_keystore
LIVE=/tmp/sros2_live
rm -rf "$LIVE"; mkdir -p "$LIVE/enclaves"
cp -r "$SRC/public"  "$LIVE/public"
cp -r "$SRC/private" "$LIVE/private"      # ← 含世界可讀的 ca.key.pem（攻擊者偷走的那把）
CAKEY="$LIVE/private/ca.key.pem"
IDCA="$LIVE/public/identity_ca.cert.pem"
PMCA="$LIVE/public/permissions_ca.cert.pem"; [ -f "$PMCA" ] || PMCA="$IDCA"

# ── 1. domain-99 嚴格 governance（allow_unauthenticated=false → 對照組會被擋）──
cat > "$LIVE/enclaves/governance.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-SECURITY/20170901/omg_shared_ca_governance.xsd">
  <domain_access_rules>
    <domain_rule>
      <domains><id>99</id></domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>NONE</discovery_protection_kind>
      <liveliness_protection_kind>NONE</liveliness_protection_kind>
      <rtps_protection_kind>NONE</rtps_protection_kind>
      <topic_access_rules>
        <topic_rule>
          <topic_expression>*</topic_expression>
          <enable_discovery_protection>false</enable_discovery_protection>
          <enable_liveliness_protection>false</enable_liveliness_protection>
          <enable_read_access_control>true</enable_read_access_control>
          <enable_write_access_control>true</enable_write_access_control>
          <metadata_protection_kind>NONE</metadata_protection_kind>
          <data_protection_kind>ENCRYPT</data_protection_kind>
        </topic_rule>
      </topic_access_rules>
    </domain_rule>
  </domain_access_rules>
</dds>
XML
# 用偷來的 CA 簽 governance（證明連 governance 都能被攻擊者重簽）
openssl smime -sign -in "$LIVE/enclaves/governance.xml" -text \
  -signer "$PMCA" -inkey "$CAKEY" -outform SMIME -nodetach \
  -out "$LIVE/enclaves/governance.p7s" 2>/dev/null

# ── 2. enclave 產生器：用偷來的 CA 簽身分 + 權限 ──
# 參數：enclave名  CN  chatter方向(pub|sub)
make_enclave() {
  local name="$1" cn="$2" dir_chatter="$3"
  local d="$LIVE/enclaves/$name"; mkdir -p "$d"
  # 身分金鑰 + 用偷來的 CA 簽發憑證
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/key.pem" 2>/dev/null
  printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=%s\n' "$cn" > "$d/req.cnf"
  openssl req -new -key "$d/key.pem" -out "$d/req.csr" -config "$d/req.cnf" 2>/dev/null
  openssl x509 -req -in "$d/req.csr" -CA "$IDCA" -CAkey "$CAKEY" -CAcreateserial \
    -days 3650 -out "$d/cert.pem" 2>/dev/null
  cp "$IDCA" "$d/identity_ca.cert.pem"
  cp "$PMCA" "$d/permissions_ca.cert.pem"
  cp "$LIVE/enclaves/governance.p7s" "$d/governance.p7s"
  # 權限：chatter 指定方向 + 標準 ROS topic（讓節點能正常 bring-up）
  local pub_chatter="" sub_chatter=""
  [ "$dir_chatter" = "pub" ] && pub_chatter="<topic>rt/chatter</topic>"
  [ "$dir_chatter" = "sub" ] && sub_chatter="<topic>rt/chatter</topic>"
  cat > "$d/permissions.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-SECURITY/20170901/omg_shared_ca_permissions.xsd">
  <permissions>
    <grant name="$name">
      <subject_name>CN=$cn</subject_name>
      <validity><not_before>2026-01-01T00:00:00</not_before><not_after>2037-01-01T00:00:00</not_after></validity>
      <allow_rule>
        <domains><id>99</id></domains>
        <publish><topics>
          $pub_chatter
          <topic>rt/rosout</topic><topic>rt/parameter_events</topic>
          <topic>ros_discovery_info</topic><topic>rt/clock</topic>
          <topic>rq/*Request</topic><topic>rr/*Reply</topic>
        </topics></publish>
        <subscribe><topics>
          $sub_chatter
          <topic>rt/rosout</topic><topic>rt/parameter_events</topic>
          <topic>ros_discovery_info</topic><topic>rt/clock</topic>
          <topic>rq/*Request</topic><topic>rr/*Reply</topic>
        </topics></subscribe>
      </allow_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
XML
  openssl smime -sign -in "$d/permissions.xml" -text \
    -signer "$d/permissions_ca.cert.pem" -inkey "$CAKEY" -outform SMIME -nodetach \
    -out "$d/permissions.p7s" 2>/dev/null
  echo "  [+] enclave $name (CN=$cn, chatter=$dir_chatter)  cert verify: $(openssl verify -CAfile "$IDCA" "$d/cert.pem" 2>&1 | sed 's/.*: //')"
}

echo "[*] 建立 enclave（全用偷來的 CA 簽）:"
make_enclave victim       /victim       sub
make_enclave legit_talker /legit_talker pub
make_enclave evil         /evil_injector pub   # ← 防守方從未授權這個身分

echo "[*] keystore 就緒: $LIVE  (domain 99, Enforce, allow_unauthenticated=false)"
ls "$LIVE/enclaves"
