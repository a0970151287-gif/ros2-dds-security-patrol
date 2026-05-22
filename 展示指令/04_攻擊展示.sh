#!/bin/bash
# ============================================================
# 04 攻擊展示（對應三層防護）
# 執行前確認系統已依照 01_啟動系統.sh 全部開好
# ============================================================

# ── 攻擊 1：身份驗證測試（沒有憑證能加入嗎？）─────────────
# 不 source credentials，直接加入 domain 30
# 防護開啟時：什麼也看不到（被拒絕）
source ~/ros2_ws/install/setup.bash
ROS_DOMAIN_ID=30 ros2 topic list

# ── 攻擊 2：加入未知節點（觸發 monitor_node 偵測）──────────
# 不帶憑證，模擬入侵者
# 觸發：緊急停止 + LINE 警報
source ~/ros2_ws/install/setup.bash
ros2 run demo_nodes_py listener --ros-args --remap __node:=intruder_node

# ── 攻擊 3：越權資料注入（存取控制測試）──────────────────
# 有憑證的 patrol_node 試圖 pub /sensor/status（無此權限）
# 防護開啟時：DDS 直接擋住，publisher 建不起來
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
export ROS_SECURITY_ENCLAVE_OVERRIDE=/patrol_node
ros2 topic pub /sensor/status std_msgs/msg/String "data: '危險'" --rate 5
