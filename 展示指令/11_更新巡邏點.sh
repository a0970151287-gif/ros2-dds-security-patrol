#!/bin/bash
# ============================================================
# 04 動態更新巡邏點
# ============================================================

source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash

# ── 用法 ─────────────────────────────────────────────────────

# 【方法 A】即時送機器人去單一座標（不用重啟）
# 改好下面的 name / x / y 後直接執行
TARGET_NAME="生產線A"
TARGET_X=-2.0
TARGET_Y=1.5

ros2 topic pub --once /patrol/goto std_msgs/msg/String \
  "{\"data\": \"{\\\"name\\\":\\\"${TARGET_NAME}\\\",\\\"x\\\":${TARGET_X},\\\"y\\\":${TARGET_Y}}\"}"

echo "已送出目標：${TARGET_NAME} (${TARGET_X}, ${TARGET_Y})"

# ── 方法 B：修改 yaml 後整批重載 ──────────────────────────
# 1. 先編輯：nano ~/ros2_ws/src/dds_security_monitor/config/waypoints.yaml
# 2. 再執行：
# ros2 service call /patrol/reload std_srvs/srv/Trigger

# ── 方法 C：直接查看目前機器人位置 ───────────────────────
# ros2 topic echo /odom --once | grep -A3 "position"
