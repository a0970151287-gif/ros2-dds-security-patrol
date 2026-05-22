#!/bin/bash
# ============================================================
# 06 SROS2 三層防護設定查看（截圖用）
# 對應報告：身份驗證 / 加密傳輸 / 存取控制
# ============================================================

source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash

echo "======================================================"
echo " 第一層：身份驗證（X.509 憑證）"
echo "======================================================"
echo "--- 節點憑證列表 ---"
ls ~/ros2_security_keystore/enclaves/

echo ""
echo "--- patrol_node 憑證資訊 ---"
openssl x509 -in ~/ros2_security_keystore/enclaves/patrol_node/cert.pem \
  -noout -subject -issuer -dates

echo ""
echo "======================================================"
echo " 第二層：加密傳輸（AES-256）"
echo "======================================================"
echo "--- governance.xml 加密設定 ---"
cat ~/ros2_security_keystore/enclaves/governance.xml

echo ""
echo "--- governance.p7s 簽名驗證 ---"
openssl smime -verify \
  -in ~/ros2_security_keystore/enclaves/governance.p7s \
  -CAfile ~/ros2_security_keystore/public/permissions_ca.cert.pem \
  -noverify 2>&1 | tail -1

echo ""
echo "======================================================"
echo " 第三層：存取控制（XML 政策檔）"
echo "======================================================"
echo "--- patrol_node 只能存取這些 Topic ---"
grep "rt/" ~/ros2_security_keystore/enclaves/patrol_node/permissions.xml | \
  grep -v "action\|rosout\|parameter\|clock\|discovery" | sed 's/.*<topic>//;s/<\/topic>//'

echo ""
echo "--- dds_security_monitor 只能存取這些 Topic ---"
grep "rt/" ~/ros2_security_keystore/enclaves/dds_security_monitor/permissions.xml | \
  grep -v "action\|rosout\|parameter\|clock\|discovery" | sed 's/.*<topic>//;s/<\/topic>//'

echo ""
echo "======================================================"
echo " 環境確認"
echo "======================================================"
echo "ROS_SECURITY_ENABLE=$ROS_SECURITY_ENABLE"
echo "ROS_SECURITY_STRATEGY=$ROS_SECURITY_STRATEGY"
echo "ROS_SECURITY_KEYSTORE=$ROS_SECURITY_KEYSTORE"
