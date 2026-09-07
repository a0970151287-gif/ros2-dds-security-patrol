#!/usr/bin/env bash
# N27 setup — 在隔離 domain 99 重建「與真實系統相同」的 SROS2 governance 的 secured victim，
# 用來測「純網路、無鑰匙攻擊者」能打到什麼。
#
# 真實 governance 關鍵設定（/home/jesse/ros2_security_keystore/enclaves/governance.xml）：
#   allow_unauthenticated_participants = true   ← 真系統就是 true（比 N26b 的 false 弱）
#   discovery_protection_kind = NONE            ← discovery 明文
#   rtps_protection_kind      = NONE            ← RTPS 不保護
#   topic *: write/read access control = true, data_protection = ENCRYPT
#
# 攻擊者全程「零鑰匙」（ROS_SECURITY_ENABLE=false / 不用任何 enclave）。
# 這裡用 CA 只是「防守方佈建自己的 victim」——攻擊者不碰 CA。全程 domain 99，不碰 domain 30。
set -u
SRC=/home/jesse/ros2_security_keystore
LIVE=/tmp/sros2_real
rm -rf "$LIVE"; mkdir -p "$LIVE/enclaves"
cp -r "$SRC/public"  "$LIVE/public"
cp -r "$SRC/private" "$LIVE/private"
CAKEY="$LIVE/private/ca.key.pem"
IDCA="$LIVE/public/identity_ca.cert.pem"
PMCA="$LIVE/public/permissions_ca.cert.pem"; [ -f "$PMCA" ] || PMCA="$IDCA"

# governance：完全照真實系統（allow_unauthenticated=true），但綁 domain 99
cat > "$LIVE/enclaves/governance.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-SECURITY/20170901/omg_shared_ca_governance.xsd">
  <domain_access_rules>
    <domain_rule>
      <domains><id>99</id></domains>
      <allow_unauthenticated_participants>true</allow_unauthenticated_participants>
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
openssl smime -sign -in "$LIVE/enclaves/governance.xml" -text \
  -signer "$PMCA" -inkey "$CAKEY" -outform SMIME -nodetach \
  -out "$LIVE/enclaves/governance.p7s" 2>/dev/null

make_enclave() {
  local name="$1" cn="$2" dir_chatter="$3"
  local d="$LIVE/enclaves/$name"; mkdir -p "$d"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/key.pem" 2>/dev/null
  printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=%s\n' "$cn" > "$d/req.cnf"
  openssl req -new -key "$d/key.pem" -out "$d/req.csr" -config "$d/req.cnf" 2>/dev/null
  openssl x509 -req -in "$d/req.csr" -CA "$IDCA" -CAkey "$CAKEY" -CAcreateserial \
    -days 3650 -out "$d/cert.pem" 2>/dev/null
  cp "$IDCA" "$d/identity_ca.cert.pem"; cp "$PMCA" "$d/permissions_ca.cert.pem"
  cp "$LIVE/enclaves/governance.p7s" "$d/governance.p7s"
  local pub="" sub=""
  [ "$dir_chatter" = "pub" ] && pub="<topic>rt/chatter</topic>"
  [ "$dir_chatter" = "sub" ] && sub="<topic>rt/chatter</topic>"
  cat > "$d/permissions.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-SECURITY/20170901/omg_shared_ca_permissions.xsd">
  <permissions><grant name="$name">
    <subject_name>CN=$cn</subject_name>
    <validity><not_before>2026-01-01T00:00:00</not_before><not_after>2037-01-01T00:00:00</not_after></validity>
    <allow_rule><domains><id>99</id></domains>
      <publish><topics>$pub<topic>rt/rosout</topic><topic>rt/parameter_events</topic><topic>ros_discovery_info</topic><topic>rt/clock</topic><topic>rq/*Request</topic><topic>rr/*Reply</topic></topics></publish>
      <subscribe><topics>$sub<topic>rt/rosout</topic><topic>rt/parameter_events</topic><topic>ros_discovery_info</topic><topic>rt/clock</topic><topic>rq/*Request</topic><topic>rr/*Reply</topic></topics></subscribe>
    </allow_rule><default>DENY</default>
  </grant></permissions>
</dds>
XML
  openssl smime -sign -in "$d/permissions.xml" -text -signer "$d/permissions_ca.cert.pem" \
    -inkey "$CAKEY" -outform SMIME -nodetach -out "$d/permissions.p7s" 2>/dev/null
  echo "  [+] $name (CN=$cn, chatter=$dir_chatter) verify: $(openssl verify -CAfile "$IDCA" "$d/cert.pem" 2>&1 | sed 's/.*: //')"
}
echo "[*] 建立 victim + 合法 talker（真實 governance: allow_unauthenticated=true, domain 99）"
make_enclave victim       /victim       sub
make_enclave legit_talker /legit_talker pub
echo "[*] keystore: $LIVE"
