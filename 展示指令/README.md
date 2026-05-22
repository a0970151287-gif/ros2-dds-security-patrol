# ROS2 DDS 安全監控系統 — 指令速查

## 展示流程

| 檔案 | 內容 | 用途 |
|------|------|------|
| `00_重置模擬器.sh` | 清除 log / 傳送機器人 / 完整重開 | 機器人卡住或黑屏 |
| `01_啟動系統.sh` | Gazebo + 6 個安全節點（帶憑證啟動）| 開場 |
| `02_系統驗證截圖.sh` | node list / rqt_graph / topic info | 正常運作截圖 |
| `03_加密證明.sh` | tshark 封包 / governance.xml / 簽名驗證 | DDS 加密展示 |
| `04_攻擊展示.sh` | 身份驗證 / intruder_node / 越權注入 | 三層攻擊手法 |
| `05_防禦回應截圖.sh` | monitor_node / patrol_node 30 秒恢復 / LINE 警報 | 防禦回應截圖 |
| `06_SROS2設定查看.sh` | 三層防護設定查看（憑證/加密/存取控制）| 安全設定展示 |
| `07_最小權限驗證.sh` | permissions.xml 各節點 Topic 權限對比 | 最小權限原則 |
| `08_DQN訓練.sh` | 訓練 / 曲線 / 重置 / GPU 確認 | DQN 強化學習 |
| `09_環境設定.sh` | dqn_env / PyTorch GPU / colcon build | 環境安裝 |

## 快速重開系統

```bash
# 清除模擬器 log（黑屏或機器人不見時用）
pkill -9 -f "gz sim" && rm -rf ~/.gz/sim/8/log/* ~/.ros/log/*

# 殺掉所有安全節點
pkill -f "ros2 run dds_security_monitor"

# 重開 Gazebo（一定要帶 credentials）
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
export TURTLEBOT3_MODEL=burger
ros2 launch dds_security_monitor gazebo.launch.py
```

## 每個終端都要先 source

```bash
# DDS 安全監控節點（所有終端）
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash

# DQN 訓練（額外多加 dqn_env）
source ~/.config/dds-monitor/credentials && source ~/dqn_env/bin/activate && source ~/ros2_ws/install/setup.bash
```

> ⚠️ 虛擬環境是 `~/dqn_env/`，不是 `.venv`
> ⚠️ `unset ROS_SECURITY_ENCLAVE_OVERRIDE` 若節點載入錯誤 enclave 時用此清除

## 重要路徑

| 項目 | 路徑 |
|------|------|
| DDS 安全節點 | `~/ros2_ws/src/dds_security_monitor/` |
| DQN 訓練程式 | `~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/` |
| DQN 訓練曲線 | `~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/logs/training_curve.png` |
| DQN 模型權重 | `~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/models/` |
| SROS2 Keystore | `~/ros2_security_keystore/` |
| Governance 設定 | `~/ros2_security_keystore/enclaves/governance.xml` |
| 系統設定檔 | `~/ros2_ws/src/dds_security_monitor/config/config.yaml` |
| 憑證設定 | `~/.config/dds-monitor/credentials` |
| 靜態架構圖 | `~/ros2_ws/工具腳本/topic_architecture.png` |

## SAC 訓練架構（最新）

**演算法：** Soft Actor-Critic (SAC) — Stable Baselines3 v2.8

**優勢：** 連續動作空間、最大熵探索（自動平衡探索/利用，天生防轉圈）

**Observation（376 維，4 幀疊加）：**
90 點 LiDAR（正規化）+ goal_dist + goal_angle + lin_vel + ang_vel = 94 × 4

**Action（連續）：** [linear_vel, angular_vel] 映射到 [0, 0.25] m/s 和 [-1.5, 1.5] rad/s

**Reward（7 個組件）：**
progress + yaw + safety_penalty + smooth_penalty + spin_penalty + slow_penalty + collision/goal

**Domain Randomization：** 每集隨機起點 + 隨機目標（自動避開 9 個柱子）

**目標：3,000,000 timesteps，每 50,000 steps 自動存 checkpoint**

**TensorBoard：**
```bash
source ~/dqn_env/bin/activate
tensorboard --logdir ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/logs_sac/tensorboard
```

## SROS2 防護三層架構

| 層 | 技術 | 效果 |
|----|------|------|
| 身份驗證 | X.509 憑證（9 個節點各自簽發）| 沒有憑證的節點無法加入 |
| 加密傳輸 | AES-256 (data_protection_kind: ENCRYPT) | 竊聽封包看不到內容 |
| 存取控制 | permissions.xml（最小權限原則）| 有憑證但無權限也無法 pub/sub |
