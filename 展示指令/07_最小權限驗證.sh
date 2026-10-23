#!/bin/bash
# ============================================================
# 07 最小權限原則驗證
# 展示每個節點只能存取自己需要的 Topic
#
# 路徑修正（2026-07）：舊版寫死 ~/ros2_security_keystore（不存在，早就抓空），
# 實際 keystore 一直是 ~/ros2_ws/sros2_keystore。
# 政策已從全 wildcard 換成逐節點最小權限（見 sros2_policy_least_privilege.xml），
# 完整自動化稽核(雙CA/私鑰權限/憑證鏈/governance)請用 展示指令/sros2_稽核.sh。
# ============================================================

# 查看各節點權限（對比不同節點的允許範圍）
echo "=== patrol_node 可發布/訂閱的 Topic ==="
grep -A2 "<topic>" ~/ros2_ws/sros2_keystore/enclaves/patrol_node/permissions.xml

echo "=== sensor_hub_node 可發布/訂閱的 Topic ==="
grep -A2 "<topic>" ~/ros2_ws/sros2_keystore/enclaves/sensor_hub_node/permissions.xml

echo "=== dds_security_monitor 可發布/訂閱的 Topic ==="
grep -A2 "<topic>" ~/ros2_ws/sros2_keystore/enclaves/dds_security_monitor/permissions.xml
