#!/bin/bash
# ============================================================
# 03 DDS 加密證明
# 對比有無 SROS2 時的封包內容
# ============================================================

#  A：有 SROS2（加密）— 封包內容為亂碼
# 抓 10 個 DDS UDP 封包，顯示 hex data
sudo tshark -i lo -f "udp portrange 7400-7500" -c 10 \
  -T fields -e data 2>/dev/null | head -5

#  B：確認 governance 設定（data_protection_kind=ENCRYPT）
cat ~/ros2_security_keystore/enclaves/governance.xml

#  C：驗證 governance.p7s 簽名有效
openssl smime -verify \
  -in ~/ros2_security_keystore/enclaves/governance.p7s \
  -CAfile ~/ros2_security_keystore/public/permissions_ca.cert.pem \
  -noverify 2>&1 | head -3
