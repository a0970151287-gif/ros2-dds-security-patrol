#!/bin/bash
# ============================================================
# 05 防禦回應截圖
# 攻擊後觀察各節點的防禦反應
# ============================================================

source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash

# 截圖 A：monitor_node 終端輸出
# 觀察：「偵測到未知節點: /intruder_node」→ 緊急停止 → LINE 通知

# 截圖 B：patrol_node 終端輸出
# 觀察：「收到安全警報！巡邏緊急停止！」→ 30 秒後自動恢復

# 截圖 C：mission_manager 終端輸出
# 觀察：任務切換 PATROL → EMERGENCY_STOP → (30秒後) PATROL

# 截圖 D：security/alerts Topic
ros2 topic echo /security/alerts --once

# 截圖 E：系統健康報告（攻擊中）
ros2 topic echo /system/health --once

# 截圖 F：LINE 手機警報通知（手動截手機畫面）

# 截圖 G：越權注入被擋（存取控制）
# 執行後應看到 rt/sensor/status topic not found in allow rule
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
export ROS_SECURITY_ENCLAVE_OVERRIDE=/patrol_node
ros2 topic pub /sensor/status std_msgs/msg/String "data: '危險'" --rate 5

# ── 攻擊結束後恢復 ──────────────────────────────────────────
# Ctrl+C 停掉攻擊指令
# 30 秒後 patrol_node 與 mission_manager 自動恢復 PATROL
