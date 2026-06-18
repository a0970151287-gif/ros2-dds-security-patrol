#!/bin/bash
# ============================================================
# 01b 啟動系統（跨主機版）— domain 30 + 直連線 profile
#
# 與 01 差別：每個終端多設三個環境變數，讓系統的 DDS 走「直連介面
# 10.10.10.2」並在 domain 30 上線 → 攻擊機(10.10.10.1)打得到、Zeek
# 在 eth0 看得到。用於 live 跨主機攻防 / 五類偵測驗收 / SROS2 對照。
#
# 前提：
#   - 直連線已通（10.10.10.2 ↔ 10.10.10.1，見 跨主機紅隊/環境建置指南.md）
#   - 直連 profile：跨主機紅隊/dds_directlink_target.xml
#
# 每個區塊開一個新終端執行，順序很重要。
# （本版維持 Permissive；要測 SROS2 控制鏈對照另見 12_cmd_vel_enforce對照.sh）
# ============================================================

# ── 跨主機共用環境（每個終端都要，已嵌入各區塊）──────────────
#   export ROS_DOMAIN_ID=30
#   export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
#   export FASTRTPS_DEFAULT_PROFILES_FILE=~/ros2_ws/跨主機紅隊/dds_directlink_target.xml

# ── 終端 1：Gazebo 模擬器（先開，等機器人出現再開其他）────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
export ROS_DOMAIN_ID=30 RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE=~/ros2_ws/跨主機紅隊/dds_directlink_target.xml
export TURTLEBOT3_MODEL=burger
ros2 launch dds_security_monitor gazebo.launch.py

# ── 終端 2：sensor_hub_node ──────────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
export ROS_DOMAIN_ID=30 RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE=~/ros2_ws/跨主機紅隊/dds_directlink_target.xml
ros2 run dds_security_monitor sensor_hub_node

# ── 終端 3：patrol_node（幾何智慧巡航，部署模式）────────────
# 機器人依序導航：電源控制室 → 冷卻水塔 → 生產線A → 生產線B → 出入口 → 循環
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
export ROS_DOMAIN_ID=30 RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE=~/ros2_ws/跨主機紅隊/dds_directlink_target.xml
export PYTHONPATH="$HOME/dqn_env/lib/python3.12/site-packages:$PYTHONPATH"
ros2 run dds_security_monitor patrol_node

# ── 終端 4：mission_manager ──────────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
export ROS_DOMAIN_ID=30 RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE=~/ros2_ws/跨主機紅隊/dds_directlink_target.xml
ros2 run dds_security_monitor mission_manager

# ── 終端 5：system_status_node ───────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
export ROS_DOMAIN_ID=30 RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE=~/ros2_ws/跨主機紅隊/dds_directlink_target.xml
ros2 run dds_security_monitor system_status_node

# ── 終端 6：monitor_node（最後開）───────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
unset ROS_SECURITY_ENCLAVE_OVERRIDE
export ROS_DOMAIN_ID=30 RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE=~/ros2_ws/跨主機紅隊/dds_directlink_target.xml
ros2 run dds_security_monitor monitor_node --params-file ~/ros2_ws/src/dds_security_monitor/config/config.yaml

# ── 全部啟動後確認 ───────────────────────────────────────────
# 本機： ros2 node list   應出現 6 個系統節點 + /robot_state_publisher /ros_gz_bridge
# 攻擊機(10.10.10.1，同 domain 30 + 攻擊機 profile)： ros2 topic list 應看得到 /cmd_vel /scan ...
# Zeek(目標機 eth0)： sudo /opt/zeek/bin/zeek -i eth0 ~/ros2_ws/Zeek監控/dds_monitor.zeek
#   → 攻擊機一上線/注入，應跳五類告警
