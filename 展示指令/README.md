# ROS2 DDS 安全監控系統 — 指令速查

## 🛡️ 全開防護啟動流程（推薦，照這條就對）

> 三個 `01` 會混淆，**要全防護就只走這條**：先建/驗 keystore，再用 `01c` Enforce 啟動。

```bash
# ── 前置（keystore 有改才需重跑）──
bash 展示指令/10_SROS2啟用.sh      # 建/重簽 keystore：雙CA + 最小權限ACL + governance domain30
bash 展示指令/sros2_稽核.sh         # 離線驗加固結構，要全綠（28 ✅ / 0 ❌）

# ── 啟動（每個區塊一個新終端，順序見 01c 內註解）──
bash 展示指令/01c_啟動系統_enforce.sh   # 🧱 全系統 SROS2 Enforce（未授權節點進不來）

# ── 另開 sudo 終端：監控 + 偵測 ──
# ⚠️ 一定要先 cd 網路記錄，Zeek 輸出的 conn.log 等才會落在官方位置，
#    不會亂噴到 repo 根目錄或 Zeek監控/（2026-07 曾因此散落三份要重整）
cd ~/ros2_ws/網路記錄 && sudo /opt/zeek/bin/zeek -i eth0 ../Zeek監控/dds_monitor.zeek

# ── （可選）智慧反應系統：偵測→對應防禦 ──
/home/jesse/ml_ids_env/bin/python ML防禦/回應引擎.py
```

**三個 01 的差別（只有 01c 是全防護）**：

| 腳本 | 模式 | 用途 |
|------|------|------|
| `01_啟動系統.sh` | 本機 Permissive | 純功能 demo，**無防護** |
| `01b_啟動系統_跨主機.sh` | 跨主機 Permissive | 給紅隊打、Zeek 看，但 DDS **不擋** |
| **`01c_啟動系統_enforce.sh`** | 跨主機 **SROS2 Enforce** | ✅ **全開防護用這個** |

---

## 展示流程

| 檔案 | 內容 | 用途 |
|------|------|------|
| `00_重置模擬器.sh` | 清除 log / 傳送機器人 / 完整重開 | 機器人卡住或黑屏 |
| `01c_啟動系統_enforce.sh` | **全開防護啟動**（SROS2 Enforce 全系統）| ✅ 主用，見上方流程 |
| `01_/01b_啟動系統*.sh` | Permissive 版（本機 / 跨主機，無 DDS 防護）| 純功能 / 給紅隊打 |
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

# TQC 訓練（額外多加 dqn_env）
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
| SROS2 Keystore | `~/ros2_ws/sros2_keystore/`（gitignored，勿提交）|
| Governance 設定 | `~/ros2_ws/sros2_keystore/enclaves/governance.xml` |
| 最小權限政策 | `~/ros2_ws/展示指令/sros2_policy_least_privilege.xml` |
| SROS2 稽核腳本 | `~/ros2_ws/展示指令/sros2_稽核.sh` |
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

## 防護架構（實際運作，已加固）

| 層 | 技術 | 效果 | 狀態 |
|----|------|------|------|
| **🧱 L0 牆／預防（SROS2 Enforce）** | 雙CA分離 + 最小權限ACL + governance(rtps SIGN / discovery·data ENCRYPT / allow_unauth=false) | 未授權 participant **進不來**；持證內鬼也只能碰自己 grant 內的 topic（發不了別人的 /cmd_vel、改不了別人的參數）| ✅ **已加固+實測**（稽核 28✅、live talker→listener 通） |
| **L1 應用層簽章** | HMAC envelope v3（channel+ts+nonce）+ ReplayCache + F1-b 參數鎖 | 防偽造 / 重放 / 跨頻道 / 參數竄改 | ✅ |
| **L2 行為 IDS** | intelligent_defense_node D1–D6 + cascade 斷路器 | cmd_vel/scan/odom 注入最後防線 + 看門狗 | ✅ |
| **🧠✋ L3 偵測+反應** | Zeek 五類+隱形DoS + ML-IDS + 回應引擎（4 道安全閘）| 偵測攻擊類型 → 出對應防禦 | ✅ |

> ✅ **介紹重點（已更新）**：SROS2 **Enforce** 是真正擋下攻擊的「牆」——攻擊機沒有本 CA 簽的憑證 → 連 DDS participant 都建不起來 → recon/注入/F1/F7 在**認證層就被擋**（預防，非偵測）。L1/L2 是縱深、L3 是「進得來的內鬼/變種」的偵測+反應腦手。**「沒有憑證就無法加入」在 Enforce(01c) 下成立。**
>
> 加固細節見 [文件/紅隊報告_漏洞補丁總帳_2026-06-19.md](../文件/紅隊報告_漏洞補丁總帳_2026-06-19.md)、[文件/AI評估_ML-IDS何時有用.md](../文件/AI評估_ML-IDS何時有用.md)。
