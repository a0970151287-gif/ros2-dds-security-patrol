# ROS2 DDS 安全監控系統 — 指令速查

> **先分清楚「能啟動」與「已驗證」**：`01c` 是 Enforce 全系統啟動編排；28 項稽核證明政策/憑證結構，N26b/N27 證明隔離 domain 的 live 認證邊界。修補後全 Gazebo 場景尚未長時間跑滿並重打所有紅隊情境，尤其 N9 after 仍待補。下列指令是實際攻防操作，不是紙上步驟；TurtleBot3 本體為 Gazebo 模擬。

## 🛡️ 全開防護啟動流程（推薦，照這條就對）

> 三個 `01` 會混淆，**要全防護就只走這條**：先建/驗 keystore，再用 `01c` Enforce 啟動。

```bash
# ── 前置（keystore 有改才需重跑）──
bash 展示指令/10_SROS2啟用.sh      # 建/重簽 keystore：雙CA + 最小權限ACL + governance domain30
bash 展示指令/sros2_稽核.sh         # 離線驗加固結構，要全綠（28 ✅ / 0 ❌）

# ── 啟動（每個區塊一個新終端，順序見 01c 內註解）──
bash 展示指令/01c_啟動系統_enforce.sh   # 🧱 啟動全系統 SROS2 Enforce（啟動後仍須做下方驗收）

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
| `01_啟動系統.sh` | 本機 Permissive | 功能 demo；有部分應用層簽章，但**無 DDS 身分/權限強制**，且此腳本未啟動行為 IDS |
| `01b_啟動系統_跨主機.sh` | 跨主機 Permissive | 給紅隊打、Zeek 看，但 DDS **不擋** |
| **`01c_啟動系統_enforce.sh`** | 跨主機 **SROS2 Enforce** | 全開防護入口；需另做節點、topic、無憑證對照與攻擊 after 驗收 |

---

## 展示流程

| 檔案 | 內容 | 用途 |
|------|------|------|
| `00_重置模擬器.sh` | 清除 log / 傳送機器人 / 完整重開 | 機器人卡住或黑屏 |
| `01c_啟動系統_enforce.sh` | **全開防護啟動編排**（SROS2 Enforce 全系統）| 主用；不把啟動成功直接當成完整攻防通過 |
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

# 重開 Gazebo（只載入白名單內的非秘密 ROS 設定）
source ~/ros2_ws/工具腳本/load_ros_environment.sh || exit 1
export TURTLEBOT3_MODEL=burger
ros2 launch dds_security_monitor gazebo.launch.py
```

## 每個終端都要先 source

```bash
# DDS 安全監控節點（所有終端）
source ~/ros2_ws/工具腳本/load_ros_environment.sh || exit 1

# TQC 訓練（額外多加 dqn_env）
source ~/dqn_env/bin/activate || exit 1
source ~/ros2_ws/工具腳本/load_ros_environment.sh || exit 1
```

> ⚠️ 虛擬環境是 `~/dqn_env/`，不是 `.venv`
> ⚠️ `unset ROS_SECURITY_ENCLAVE_OVERRIDE` 若節點載入錯誤 enclave 時用此清除
> ⚠️ 選用的 `credentials` 只能放載入器白名單內的非秘密 ROS/DDS 設定（相容
> `LINE_USER_ID`）。共用載入器會拒絕其中出現 `DDS_ALERT_SECRET` 或
> `LINE_CHANNEL_TOKEN`，並清掉呼叫端殘留的同名環境變數。
> `chmod 600` 檔案可避免秘密被子程序環境繼承或被其他帳號讀取，但無法防住
> 已取得同一 Linux UID 的惡意程式；密鑰集中化仍是殘餘風險。

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
| ROS 環境載入器 | `~/ros2_ws/工具腳本/load_ros_environment.sh` |
| 選用的非秘密 ROS 設定 | `~/.config/dds-monitor/credentials`（不存在時使用目前環境／ROS 預設值）|
| Alert HMAC 密鑰 | `~/.config/dds-monitor/alert_secret`（`chmod 600`）|
| LINE token | `~/.config/dds-monitor/line_token`（`chmod 600`）|
| LINE user ID | `~/.config/dds-monitor/line_user_id`（非秘密；也相容 credentials 內的 `LINE_USER_ID`）|
| 靜態架構圖 | `~/ros2_ws/工具腳本/topic_architecture.png` |

## TQC 訓練架構（獨立未來工作軌）

**演算法：** Truncated Quantile Critics — sb3-contrib v2.8（SAC 後繼者）
- `top_quantiles_to_drop_per_net=2` 抑制 Q over-estimation

**Observation（744 維 = 4 幀 × 186）：**
180-beam raw LiDAR + 6 state（dist_norm / cos / sin / prev_lin / prev_ang / time_norm）

**Policy / Critic 網路：**
LiDARConvExtractor（Conv1D(32,k=5) → Conv1D(64,k=3) → AdaptiveAvgPool(8)
→ LayerNorm → Linear(192)）+ state MLP(64) + fusion(256) + MLP[256, 256]

**Action（連續）：** [-1, 1]² → lin ∈ [0, 0.22] m/s，ang ∈ [-1.5, 1.5] rad/s

**Reward（現行 progress-based 實作）：**
Δdist − 0.05‖Δa‖² − 0.05 + 0.04·action[0]   ＋   {碰撞 -100 / 到達 +100}

> 早期的 NHR `γ·Φ(s') − Φ(s)` 版本曾讓原地不動取得正基線，121 集成功率為 0%；現行程式已改成上式。TQC 本身不訂閱 `/security/alerts`，也不取代 DDS 防禦層。

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
| **🧱 L0 牆／預防（SROS2 Enforce）** | 雙CA分離 + 最小權限ACL + governance(rtps SIGN / discovery·data ENCRYPT / allow_unauth=false) | 機制上拒絕無憑證 participant，並限制持證 enclave 的 topic 權限 | 🟡 政策/憑證稽核 28✅；隔離 live 對照通過；修補後全 Gazebo 長時間回歸待補 |
| **L1 應用層簽章** | HMAC envelope v3（channel+ts+nonce）+ ReplayCache + F1-b 參數鎖 | 防偽造 / 重放 / 跨頻道 / 參數竄改 | ✅ |
| **L2 行為 IDS** | intelligent_defense_node D1–D6 + cascade 斷路器 | cmd_vel/scan/odom 注入最後防線 + 看門狗 | ✅ |
| **🧠✋ L3 偵測+反應** | Zeek 五類+隱形DoS + ML-IDS + 回應引擎（4 道安全閘）| 偵測攻擊類型 → 出對應防禦 | ✅ |

> **介紹重點**：SROS2 Enforce 是預防層；無本 CA 憑證的 participant 在正確啟用並載入有效 policy 的前提下無法配對。L1/L2 是縱深，L3 處理內鬼/變種。口試時應同時說明：隔離 live 對照已證明此認證邊界，但修補後 `01c` 全場景的長時間與逐攻擊 after 證據仍待補。
>
> 加固細節見 [文件/紅隊報告_漏洞補丁總帳_2026-06-19.md](../文件/紅隊報告_漏洞補丁總帳_2026-06-19.md)、[文件/AI評估_ML-IDS何時有用.md](../文件/AI評估_ML-IDS何時有用.md)。
