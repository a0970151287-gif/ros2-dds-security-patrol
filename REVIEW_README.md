# Code Review Package — ROS2 DDS Security Monitor + TQC Patrol

> 這份是給 reviewer（工程師）的快速指引。
> 系統概述：ROS2 機器人巡邏系統 + 應用層資安防護 + SROS2 DDS層加固 + ML-IDS；TQC 強化學習為獨立的未來工作軌。
> 學術專題等級；採 IEC 62443 / NIST CSF 對齊。

> 📌 **2026-07 更新**：本文件原版（2026-06-12）只涵蓋應用層防護，以下三塊是後續新增、
> 為本專題目前的核心與 AI 主軸，**優先看這三份**：
> - [文件/專題完整總報告.md](文件/專題完整總報告.md) — 全專題彙整（架構/威脅模型/三層防禦/現況），**建議從這份開始**
> - [文件/AI評估_ML-IDS何時有用.md](文件/AI評估_ML-IDS何時有用.md) — AI/ML-IDS 完整評估 + 口試問答
> - [展示指令/sros2_稽核.sh](展示指令/sros2_稽核.sh) — SROS2 Enforce 加固稽核（28項檢查）

> **證據邊界（review 前先看）**：
> - 這不是紙上攻防：`紅隊測試/PoC腳本/` 會實際送出 ROS2/DDS 訊息或流量，`紅隊測試/攻擊報告/` 保存攻擊端與受害端觀察結果；被保護的機器人本體則是 Gazebo 裡的 TurtleBot3。
> - SROS2 現況分三層：政策/雙 CA/私鑰權限已由離線稽核確認；N26b/N27 在隔離 domain 做過 Enforce live 對照；但修補後的 `01c` 全 Gazebo 場景尚未長時間重跑，N9 的 Enforce after 數據也未補。
> - `tests/test_security.py` 在 2026-07-24 的 WSL ROS2 Jazzy 環境收集並通過 **60/60**；涵蓋 ReplayCache fail-closed、HMAC 邊界/短 key、secret 載入、LiDAR 正規化、D5 啟動心跳、unknown DDS publisher 與 cascade 門檻等安全回歸。單元測試數不等於紅隊情境數；後續仍以當次 collection/run 為準。

---

## 1. 套件內容

```
src/
  dds_security_monitor/                資安監控核心（6 個 ROS2 executables）
    dds_security_monitor/
      monitor_node.py                   HMAC envelope v3 + ROS graph 偵測
      intelligent_defense_node.py       行為 IDS（D1~D6 + 看門狗）
      patrol_node.py                    幾何路徑控制 + alert 訂閱
      sensor_hub_node.py                感測彙整
      mission_manager_node.py           任務切換
      system_status_node.py             健康聚合 + self-watch（log-only，不反射急停警報）
      constants.py                      白名單 / 閾值集中
    config/config.yaml
    setup.py

  turtlebot3_dqn/                       強化學習訓練（獨立未來工作軌，不含模型權重）
    turtlebot3_dqn/
      burger_env_top.py                 TQC 環境（744D 堆疊觀測 + 1D-Conv + DR/對抗擾動）
      train_top.py / train_top.sh       TQC 訓練主程式
      eval_top.py                       Deterministic eval + Bootstrap CI
      feature_extractors.py             1D-Conv LiDAR encoder
      scoreboard_top_callback.py        終端計分板

tests/
  test_security.py                      pytest 安全邊界/回歸測試（持續擴充）
  conftest.py
pytest.ini

紅隊測試/                               （核心文件留根目錄，腳本/報告各自歸資料夾）
  漏洞分析報告.md                       ★ 主報告：18 漏洞 CVSS + BIA + 合規對應（§8含2026-07 Enforce完成更新註）
  系統威脅分析.md                       威脅分析（軟體模組角度，18介面 T-01~T-18）
  ARCHITECTURE.md                      系統架構 + 介面清單
  THREAT_MODEL.md                      30個攻擊完整戰績（defense-in-depth統計）
  N1-N20_完整目錄.md / 攻擊總表_成功與失敗.md
  PoC腳本/                             紅隊 PoC 程式（N1~N27*.py/.sh）
  攻擊報告/                            單次紅隊輪次報告（含N24b/N26/N26b/N27：SROS2 CA淪陷發現鏈）

展示指令/                               操作示範指令筆記
  01c_啟動系統_enforce.sh              SROS2 Enforce 全系統啟動編排（完整場景待長時間回歸）
  sros2_policy_least_privilege.xml     逐節點最小權限ACL（G2）
  sros2_稽核.sh                        SROS2加固離線稽核（28項檢查）
  主機攻擊面稽核.sh                    主機層暴露面盤點（免sudo）

ML防禦/                                 ML-IDS：機器學習異常偵測 + 偵測→防禦回應引擎
  README.md                            架構/工具/執行指令總覽
  特徵抽取.py / 訓練.py                 Zeek conn.log → 流量特徵 → RandomForest/IsolationForest
  評估_規則vs機器學習.py               規則式vs ML同測試集混淆矩陣對照（AI評估報告的核心實驗）
  回應引擎.py                          偵測→查策略→4道安全閘→執行對應防禦
  RTPS資料集_訓練.py                   外部乾淨資料集(HCRL)驗證方法上限
  資料收集/                            Phase 2 精確標註工具（label.sh等）+ 紅隊Phase2邀請.md

文件/                                   報告文件
  專題完整總報告.md                    ★★ 全專題彙整報告（建議從這份開始）
  AI評估_ML-IDS何時有用.md             ★ AI/ML-IDS完整評估 + 口試問答
  主機加固_攻擊面收斂.md               主機層加固計畫與執行狀態
  紅隊報告_漏洞補丁總帳_2026-06-19.md   最新漏洞補丁狀態總帳
```

---

## 2. 套件「不」包含什麼（已主動排除）

| 排除項 | 原因 |
|---|---|
| `~/.config/dds-monitor/alert_secret` | HMAC 密鑰（chmod 600） |
| `~/.config/dds-monitor/line_token` | LINE 推播 token |
| `runs_top/`, `runs_sac/`, `models_sac/`, `logs_sac/` | 訓練輸出（3.5 GB） |
| `*.zip`, `*.pkl`, `*.sha256.hmac` | 模型權重檔 |
| `build/`, `install/`, `log/` | ROS2 build 產物 |
| `.venv/`, `dqn_env/` | Python virtualenvs |
| `__pycache__/`, `*.pyc` | Python cache |
| `.git/` | git history（可選） |

**敏感檔位於 `~/.config/dds-monitor/` 範圍，不在 `src/` 內，預設不會打包。**

---

## 3. 建議閱讀順序（給 reviewer）

| # | 檔案 | 為什麼先看這個 |
|---|---|---|
| 1 | [文件/專題完整總報告.md](文件/專題完整總報告.md) | ★★ 全專題彙整：架構/威脅模型/三層防禦/現況，**最快建立全貌** |
| 2 | [紅隊測試/ARCHITECTURE.md](紅隊測試/ARCHITECTURE.md) | 系統長什麼樣（11 個模組拓樸 + 介面清單） |
| 3 | [紅隊測試/系統威脅分析.md](紅隊測試/系統威脅分析.md) | 攻擊情境（軟體模組對軟體模組角度） |
| 4 | [紅隊測試/漏洞分析報告.md](紅隊測試/漏洞分析報告.md) | 18 漏洞 CVSS + BIA + 合規對應 + 修補時程 |
| 5 | [文件/AI評估_ML-IDS何時有用.md](文件/AI評估_ML-IDS何時有用.md) | ★ AI主軸：規則式vs ML評估、資料瓶頸實證 |
| 6 | `src/dds_security_monitor/dds_security_monitor/monitor_node.py` | HMAC envelope v3 + ReplayCache 核心邏輯 |
| 7 | `src/dds_security_monitor/dds_security_monitor/intelligent_defense_node.py` | IDS D1~D6 偵測層 |
| 8 | `src/dds_security_monitor/dds_security_monitor/patrol_node.py` | 接收端驗章 + cascade quiet window + N25防護 |
| 9 | `tests/test_security.py` | 自動化安全邊界/回歸測試 |

---

## 4. 如果 reviewer 要實際跑

### 4.1 環境需求

| 元件 | 版本 |
|---|---|
| OS | Ubuntu 24.04 LTS |
| ROS2 | Jazzy Jalisco |
| Python | 3.12 |
| Gazebo | Garden（如要訓練 / 部署） |

### 4.2 Python 套件

```bash
pip install stable-baselines3 sb3-contrib torch gymnasium pyyaml requests pytest
```

**ML-IDS 另需隔離環境**（避免與上方 RL 套件的 numpy 版本衝突）：
```bash
python3 -m venv ~/ml_ids_env
~/ml_ids_env/bin/pip install -r ML防禦/requirements.txt
```

### 4.3 一次性 setup

```bash
# 1. 解壓到 workspace
mkdir -p ~/ros2_ws_review
tar xzf ros2_review_*.tar.gz -C ~/ros2_ws_review

# 2. 建立 HMAC 密鑰（reviewer 自己生新的，與我的不同）
mkdir -p ~/.config/dds-monitor
openssl rand -hex 32 > ~/.config/dds-monitor/alert_secret
chmod 600 ~/.config/dds-monitor/alert_secret

# 3. 建置 ROS2 packages（如要實際跑 node；只跑 pytest 可跳過）
cd ~/ros2_ws_review
colcon build --symlink-install
source install/setup.bash

# 4. 跑單元測試（最快驗證入口）
cd ~/ros2_ws_review
pytest tests/test_security.py -v
# → 驗收：以當次 collected 全數 passed 為準
```

### 4.4 跑完整紅隊測試（可選）

**選項A — Permissive模式**（應用層HMAC+行為IDS防線）：
```bash
# 開 3 個終端
# Terminal A: 啟動模擬器
ros2 launch dds_security_monitor gazebo.launch.py

# Terminal B: 啟動防護堆疊
ros2 run dds_security_monitor monitor_node &
ros2 run dds_security_monitor intelligent_defense_node &

# Terminal C: 跑紅隊 PoC
cd 紅隊測試/PoC腳本
python3 N1_heartbeat_replay.py
python3 N3_alert_replay_dos.py
python3 N13_health_reflection.py
# 預期：全部失敗（攻擊被擋）
```

**選項B — SROS2 Enforce全開**（DDS層加固，本專題現行主線）：
```bash
bash 展示指令/10_SROS2啟用.sh       # 建雙CA + 套最小權限政策
bash 展示指令/sros2_稽核.sh          # 稽核，預期 28✅/0❌
bash 展示指令/01c_啟動系統_enforce.sh  # 全系統啟動（7個終端機區塊）
# 安全機制預期：無本 CA 憑證的 participant 無法配對；
# 驗收時仍須記錄全場景節點存活、topic 通訊與紅隊 after 結果，不能只以啟動成功視為通過。
```

---

## 5. 我想要 reviewer 重點看的

按重要度排序：

| # | Review 重點 | 對應檔案 |
|---|---|---|
| 1 | HMAC envelope v3 設計是否真的擋住 channel confusion + replay | `monitor_node.py: sign_alert / verify_alert / ReplayCache` |
| 2 | IDS D1~D6 偵測閾值是否合理（D1 物理 / D3 std / D6 cmd-vs-odom） | `intelligent_defense_node.py` |
| 3 | cascade quiet window 設計是否會卡死合法 emergency stop | `patrol_node.py: _on_alert + resume timer + quiet window` |
| 4 | SROS2 雙CA分離(G1)+最小權限ACL(G2)設計，以及離線稽核、隔離 live test、完整 01c 回歸三種證據是否有清楚區分 | `sros2_稽核.sh`、`文件/紅隊報告_漏洞補丁總帳_2026-06-19.md` |
| 5 | 規則式vs ML同測試集混淆矩陣對照，「資料瓶頸」論點是否站得住 | `文件/AI評估_ML-IDS何時有用.md` |
| 6 | TQC reward shaping：Δdist+forward bonus是否真的解決了NHR shaping陷阱（原版γ·Φ(s')−Φ(s)給原地不動正分基線，121集0%成功）| `burger_env_top.py: _compute_reward`、`展示指令/08_SAC訓練.sh` |
| 7 | pytest 現行測試覆蓋率是否足夠（不要只看總數） | `tests/test_security.py` |
| 8 | 修補時程（30/60/90 天）是否合理，是否誠實標註已提前完成的部分 | `漏洞分析報告.md §8` |
| 9 | 殘餘風險（R-1 ~ R-6）是否誠實 | `漏洞分析報告.md §10` |

---

## 6. 已知未解 / 殘餘風險（先說在前）

詳見 [漏洞分析報告.md §10 殘餘風險](紅隊測試/漏洞分析報告.md#10-殘餘風險residual-risk)。
總結 3 個最大的：

1. **R-1 DDS Permissive 模式**：`/cmd_vel` `/scan` `/odom` 非 String 訊息無法包 HMAC envelope；日常 demo（01/01b）靠行為偵測緩解。SROS2 Enforce（`01c`）的雙 CA、最小權限 ACL 與稽核已完成，但修補後的完整 Gazebo 攻防回歸尚未完成，不能把「政策已就緒」寫成「全場景已證實根治」。
2. **R-2 HMAC 密鑰集中化**：一把 `alert_secret` 守整條簽章鏈。**根治需 key rotation 機制（仍是未來工作，90 天計畫未變動）。**
3. **R-5 N9 race 殘餘 38%**：100 Hz 攻擊下機器人 62% 時間是停的。Enforce 政策提供預防路徑，但尚未針對 N9 實際重測 after 效果（見 `文件/專題完整總報告.md` 第九節）。

> 另**新發現並已修補**：N25（patrol_node畸形`/scan`除以零崩潰）——本次盤點查證程式碼確認曾未修補，已補上防護並用直接呼叫`_cb_scan()`驗證（20幀連續攻擊不崩潰）。

---

## 7. Reviewer 回饋怎麼回給我

請以以下任一方式：
- 直接 diff / patch
- 在報告/程式碼上 inline 註解
- 條列重點 + 對應檔案行號（例：`monitor_node.py:142 — 這裡的 try/except 太寬，建議分開 catch`）

謝謝你願意看 🙏

---

## 8. 文件版本

| 文件 | 最後更新 |
|---|---|
| 專題完整總報告.md | 2026-07-02 — 全專題彙整（新增） |
| AI評估_ML-IDS何時有用.md | 2026-07-04 — AI主軸完整評估（新增） |
| 主機加固_攻擊面收斂.md | 2026-07-04 — 主機層加固計畫與執行狀態（新增） |
| 紅隊報告_漏洞補丁總帳_2026-06-19.md | 2026-06-19 — 紅隊報告漏洞補丁總帳（新增） |
| 漏洞分析報告.md | 2026-07-24 — 更正 Enforce 證據邊界與漏洞狀態計數；2026-06-05 首版 |
| 系統威脅分析.md | 2026-06-05 — 教授指導後重寫（軟體模組角度） |
| ARCHITECTURE.md | 2026-06-05 — 補介面清單表 |
| test_security.py | 2026-07-24 — WSL ROS2 Jazzy 現行安全回歸 60/60；原始 24-test 為歷史快照 |
| patrol_node.py | 2026-07-04 — N25畸形/scan除以零崩潰防護（新增） |
