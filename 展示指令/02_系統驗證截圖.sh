#!/bin/bash
# ============================================================
# 02 系統驗證截圖（正常運作畫面）
# 執行前確認系統已依照 01_啟動系統.sh 全部開好
# ============================================================

source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash

# 截圖 1：確認所有節點正在運行（應出現 7 個節點）
ros2 node list

# 截圖 2：所有 Topic 清單
ros2 topic list

# 截圖 3：感測器資料（含 SROS2 安全目錄確認）
ros2 topic echo /sensor/status --once

# 截圖 4：系統健康報告
ros2 topic echo /system/health --once

# 截圖 5：rqt_graph Topic 架構圖（開 GUI）
rqt_graph

# 截圖 6：Topic 訂閱關係（重要 topic）
ros2 topic info /cmd_vel
ros2 topic info /scan
ros2 topic info /security/alerts

# 截圖 7：靜態 Topic 架構圖
eog ~/ros2_ws/工具腳本/topic_architecture.png
