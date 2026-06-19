#!/bin/bash
# ============================================================
# 01c 啟動系統（SROS2 Enforce 版）— 真的「擋下」未授權節點
#
# 與 01/01b 差別：每個節點掛 SROS2 Enforce + 自己的 enclave。
# 攻擊機沒有本 CA 簽的憑證 → 連 participant 都建不起來 →
# recon/注入/F1/F7 在「認證層」就被擋（不是偵測，是阻擋）。
#
# 傳輸：用「預設」(安全模式自動走 UDP，含 eth0)，不掛直連 SHM profile
#   —— 實測 Enforce 與 SHM profile 不相容(合法節點互相發現失敗)。
#   預設 UDP 同機可通(安全模式)、eth0 也對外可見 → 攻擊機打得到但被拒。
#
# 前提：先跑 10_SROS2啟用.sh 建好 10 個 enclave(含系統節點)+ governance domain 30
# 每個區塊開一個新終端執行，順序很重要。
# ============================================================

KEYSTORE="$HOME/ros2_ws/sros2_keystore"
ENFORCE() {            # 每個終端共用的 Enforce 環境
  source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
  export ROS_SECURITY_KEYSTORE="$KEYSTORE"
  export ROS_SECURITY_ENABLE=true
  export ROS_SECURITY_STRATEGY=Enforce
  export ROS_DOMAIN_ID=30
  export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
  unset  FASTRTPS_DEFAULT_PROFILES_FILE   # 預設傳輸，勿掛 SHM 直連 profile
  unset  ROS_SECURITY_ENCLAVE_OVERRIDE
  export TURTLEBOT3_MODEL=burger
}

# ── 終端 1：Gazebo（整包 bridge+robot_state_publisher+gz 共用 /gazebo enclave）──
ENFORCE
export ROS_SECURITY_ENCLAVE_OVERRIDE=/gazebo   # launch 內多節點共用一個 enclave
ros2 launch dds_security_monitor gazebo.launch.py

# ── 終端 2：sensor_hub_node ──────────────────────────────────
ENFORCE
ros2 run dds_security_monitor sensor_hub_node --ros-args --enclave /sensor_hub_node

# ── 終端 3：patrol_node ──────────────────────────────────────
ENFORCE
export PYTHONPATH="$HOME/dqn_env/lib/python3.12/site-packages:$PYTHONPATH"
ros2 run dds_security_monitor patrol_node --ros-args --enclave /patrol_node

# ── 終端 4：mission_manager ──────────────────────────────────
ENFORCE
ros2 run dds_security_monitor mission_manager --ros-args --enclave /mission_manager

# ── 終端 5：system_status_node ───────────────────────────────
ENFORCE
ros2 run dds_security_monitor system_status_node --ros-args --enclave /system_status_node

# ── 終端 6：monitor_node（enclave=/dds_security_monitor）─────
ENFORCE
ros2 run dds_security_monitor monitor_node --ros-args --enclave /dds_security_monitor \
  --params-file ~/ros2_ws/src/dds_security_monitor/config/config.yaml

# ── 終端 7（選配）：intelligent_defense_node（行為 IDS D1-D6）──
ENFORCE
ros2 run dds_security_monitor intelligent_defense_node --ros-args --enclave /intelligent_defense_node

# ── 驗證「擋下」───────────────────────────────────────────────
# 本機： ros2 node list --ros-args --enclave /dds_security_monitor  應看到系統節點
# 攻擊機(無憑證)： 任何 recon/inject/param 注入 → 應「couldn't find security files」配不上、收不到
# 對照：先用 01b(Permissive) 攻擊得手，再用 01c(Enforce) 同一招被擋 = 報告核心證據
