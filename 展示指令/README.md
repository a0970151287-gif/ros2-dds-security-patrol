# ROS2 DDS 安全監控系統 — 指令速查

## 展示流程

| 檔案 | 內容 | 用途 |
|------|------|------|
| `00_重置模擬器.sh` | 清除 log / 傳送機器人 / 完整重開 | 機器人卡住或黑屏 |
| `01_啟動系統.sh` | Gazebo + 安全節點（monitor + 行為 IDS 等）| 開場 |
| `02_系統驗證截圖.sh` | node list / rqt_graph / topic info | 正常運作截圖 |
| `03_加密證明.sh` | tshark 封包 / governance.xml / HMAC 簽章驗證 | DDS + 應用層簽章展示 |
| `04_攻擊展示.sh` | 紅隊 N1–N24（replay / spoof / channel / hijack）| 攻擊手法 |
| `05_防禦回應截圖.sh` | monitor / IDS / patrol 30 秒恢復 / LINE 警報 | 防禦回應截圖 |
| `06_SROS2設定查看.sh` | 三層防護設定查看（Permissive 模式）| 安全設定展示 |
| `07_最小權限驗證.sh` | permissions.xml 各節點 Topic 權限對比 | 最小權限原則 |
| `08_SAC訓練.sh` | TQC 訓練 / SPL 曲線 / eval / GPU 確認 | **TQC** 強化學習訓練 |
| `09_環境設定.sh` | dqn_env / PyTorch GPU / colcon build | 環境安裝 |
| `10_LLM模糊測試.sh` | （早期 LLM Fuzzer；現主力為紅隊 N1–N24）| 歷史工具，見 `紅隊測試/` |
| `11_更新巡邏點.sh` | /patrol/goto（簽章）更新巡邏目標 | 動態巡邏點 |

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
| RL 訓練程式 | `~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/` |
| TQC 訓練腳本 | `~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/train_top.sh` |
| TQC 評估腳本 | `~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/eval_top.py` |
| TQC 模型 / log | `~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/runs_top/` |
| SROS2 Keystore | `~/ros2_security_keystore/` |
| Governance 設定 | `~/ros2_security_keystore/enclaves/governance.xml` |
| 系統設定檔 | `~/ros2_ws/src/dds_security_monitor/config/config.yaml` |
| 憑證設定 | `~/.config/dds-monitor/credentials` |
| 靜態架構圖 | `~/ros2_ws/工具腳本/topic_architecture.png` |

## TQC 訓練架構（Tier-1 頂尖版）

**演算法：** Truncated Quantile Critics — sb3-contrib v2.8（SAC 後繼者）
- `top_quantiles_to_drop_per_net=2` 抑制 Q over-estimation

**Observation（744 維 = 4 幀 × 186）：**
180-beam raw LiDAR + 6 state（dist_norm / cos / sin / prev_lin / prev_ang / time_norm）

**Policy / Critic 網路：**
LiDARConvExtractor（Conv1D(32,k=5) → Conv1D(64,k=3) → AdaptiveAvgPool(8)
→ LayerNorm → Linear(192)）+ state MLP(64) + fusion(256) + MLP[256, 256]

**Action（連續）：** [-1, 1]² → lin ∈ [0, 0.22] m/s，ang ∈ [-1.5, 1.5] rad/s

**Reward（potential-based shaping，理論最優保證）：**
γ·Φ(s') − Φ(s) − λ‖Δa‖² − 0.005   ＋   {碰撞 -100 / 到達 +100}

**Domain Randomization（每集隨機）：**
lidar 雜訊 σ ∈ [0, 0.02] / dropout ∈ [0, 5%] / max_lin ∈ [0.18, 0.22] / max_ang ∈ [1.2, 1.8]

**對抗訓練（5% episode 機率）：**
subtle lidar bias / noise burst / prev_action jam — 對應 DDS 攻擊 K 的端到端 robust policy

**Curriculum：** 1 → 5 waypoints 自適應升級（stage success ≥ 0.7 才升）

**目標：** 2,000,000 timesteps（預期 1.0–1.5M 收，SPL plateau 即可停）

**Best 模型：** 以 SPL（Habitat 標準）而非 reward 為判準，存檔即 HMAC 簽章

**TensorBoard：**
```bash
source ~/dqn_env/bin/activate
tensorboard --logdir ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/runs_top/logs/tensorboard
```

## 防護三層架構（實際運作）

| 層 | 技術 | 效果 | 狀態 |
|----|------|------|------|
| **L1 DDS（SROS2）** | X.509 憑證 + governance.xml + permissions.xml | 憑證/加密/最小權限 keystore 已建 | ⚠️ **Permissive 模式 — DDS 層目前不強制擋**；Enforce 列入未來工作 |
| **L2 應用層（主防線）** | HMAC envelope v3（channel+ts+nonce）+ ReplayCache + 檔案簽章 | 防偽造 / 重放 / 跨頻道 / pickle RCE | ✅ 主要防禦 |
| **L3 行為 IDS** | intelligent_defense_node D1–D6 + cascade 斷路器 | 攔 cmd_vel/scan/odom 注入 + 看門狗 | ✅ 最後防線 |

> ⚠️ **介紹重點**：因 SROS2 是 Permissive 模式，**真正擋住攻擊的是 L2 應用層簽章 + L3 行為 IDS**，不是 DDS 層。紅隊 N1–N24 驗證 18 漏洞全擋下 / 緩解。不要說「沒有憑證就無法加入」——那是 Enforce 模式才成立。
