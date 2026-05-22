#!/bin/bash
# ============================================================
# 07 最小權限原則驗證
# 展示每個節點只能存取自己需要的 Topic
# ============================================================

# 查看各節點權限（對比不同節點的允許範圍）
echo "=== patrol_node 可發布/訂閱的 Topic ==="
grep -A2 "<topic>" ~/ros2_security_keystore/enclaves/patrol_node/permissions.xml

echo "=== sensor_hub_node 可發布/訂閱的 Topic ==="
grep -A2 "<topic>" ~/ros2_security_keystore/enclaves/sensor_hub_node/permissions.xml

echo "=== dds_security_monitor 可發布/訂閱的 Topic ==="
grep -A2 "<topic>" ~/ros2_security_keystore/enclaves/dds_security_monitor/permissions.xml
