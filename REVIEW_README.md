# Code Review Package — ROS2 DDS Security Monitor + TQC Patrol

> 這份是給 reviewer（工程師）的快速指引。
> 系統概述：ROS2 機器人巡邏系統 + 應用層資安防護 + TQC 強化學習。
> 學術專題等級；採 IEC 62443 / NIST CSF 對齊。

---

## 1. 套件內容

```
src/
  dds_security_monitor/                資安監控核心（7 個 ROS2 nodes）
    dds_security_monitor/
      monitor_node.py                   HMAC envelope v3 + ROS graph 偵測
      intelligent_defense_node.py       行為 IDS（D1~D6 + 看門狗）
      patrol_node.py                    幾何路徑控制 + alert 訂閱
      sensor_hub_node.py                感測彙整
      mission_manager_node.py           任務切換
      system_status_node.py             健康聚合 + self-watch
      constants.py                      白名單 / 閾值集中
    config/config.yaml
    setup.py

  turtlebot3_dqn/                       強化學習訓練（不含模型權重）
    turtlebot3_dqn/
      burger_env_top.py                 TQC 環境（180 beams + DR + 對抗 5%）
      train_top.py / train_top.sh       TQC 訓練主程式
      eval_top.py                       Deterministic eval + Bootstrap CI
      feature_extractors.py             1D-Conv LiDAR encoder
      scoreboard_top_callback.py        終端計分板

tests/
  test_security.py                      24 個 pytest 單元測試
  conftest.py
pytest.ini

紅隊測試/
  漏洞分析報告.md                       ★ 主報告：18 漏洞 CVSS + BIA + 合規對應
  系統威脅分析.md                       威脅分析（軟體模組角度）
  ARCHITECTURE.md                      系統架構 + 介面清單
  THREAT_MODEL.md                      早期版（已被前兩份取代，僅供 CIA 表參考）
  N1~N24*.py                           紅隊 PoC 程式
  N*_新攻擊報告.md                     單次紅隊輪次報告

展示指令/
  *.sh                                 操作示範指令筆記
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
| 1 | [紅隊測試/ARCHITECTURE.md](紅隊測試/ARCHITECTURE.md) | 系統長什麼樣（11 個模組拓樸 + 介面清單） |
| 2 | [紅隊測試/系統威脅分析.md](紅隊測試/系統威脅分析.md) | 攻擊情境（軟體模組對軟體模組角度） |
| 3 | [紅隊測試/漏洞分析報告.md](紅隊測試/漏洞分析報告.md) | ★ 18 漏洞 CVSS + BIA + 合規對應 + 修補時程 |
| 4 | `src/dds_security_monitor/dds_security_monitor/monitor_node.py` | HMAC envelope v3 + ReplayCache 核心邏輯 |
| 5 | `src/dds_security_monitor/dds_security_monitor/intelligent_defense_node.py` | IDS D1~D6 偵測層 |
| 6 | `src/dds_security_monitor/dds_security_monitor/patrol_node.py` | 接收端驗章 + cascade quiet window |
| 7 | `tests/test_security.py` | 24 個自動化測試 |

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
# → 預期: 24 passed
```

### 4.4 跑完整紅隊測試（可選）

```bash
# 開 3 個終端
# Terminal A: 啟動模擬器
ros2 launch dds_security_monitor gazebo.launch.py

# Terminal B: 啟動防護堆疊
ros2 run dds_security_monitor monitor_node &
ros2 run dds_security_monitor intelligent_defense_node &

# Terminal C: 跑紅隊 PoC
cd 紅隊測試
python3 N1_heartbeat_replay.py
python3 N3_alert_replay_dos.py
python3 N13_health_reflection.py
# 預期：全部失敗（攻擊被擋）
```

---

## 5. 我想要 reviewer 重點看的

按重要度排序：

| # | Review 重點 | 對應檔案 |
|---|---|---|
| 1 | HMAC envelope v3 設計是否真的擋住 channel confusion + replay | `monitor_node.py: sign_alert / verify_alert / ReplayCache` |
| 2 | IDS D1~D6 偵測閾值是否合理（D1 物理 / D3 std / D6 cmd-vs-odom） | `intelligent_defense_node.py` |
| 3 | cascade quiet window 設計是否會卡死合法 emergency stop | `patrol_node.py: _on_alert + resume timer + quiet window` |
| 4 | TQC reward shaping 是否真符合 Ng-Harada-Russell 1999（potential-based） | `burger_env_top.py: _compute_reward` |
| 5 | pytest 24 個測試覆蓋率是否足夠 | `tests/test_security.py` |
| 6 | 修補時程（30/60/90 天）是否合理 | `漏洞分析報告.md §8` |
| 7 | 殘餘風險（R-1 ~ R-6）是否誠實 | `漏洞分析報告.md §10` |

---

## 6. 已知未解 / 殘餘風險（先說在前）

詳見 [漏洞分析報告.md §10 殘餘風險](紅隊測試/漏洞分析報告.md#10-殘餘風險residual-risk)。
總結 3 個最大的：

1. **R-1 DDS Permissive 模式**：`/cmd_vel` `/scan` `/odom` 非 String 訊息無法包 HMAC envelope；目前只靠行為偵測。**根治需 SROS2 Enforce migration（90 天計畫）。**
2. **R-2 HMAC 密鑰集中化**：一把 `alert_secret` 守整條簽章鏈。**根治需 key rotation 機制 + SROS2 enclave（90 天計畫）。**
3. **R-5 N9 race 殘餘 38%**：100 Hz 攻擊下機器人 62% 時間是停的。**根治需 SROS2 Enforce。**

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
| 系統威脅分析.md | 2026-06-05 — 教授指導後重寫（軟體模組角度） |
| 漏洞分析報告.md | 2026-06-05 — 升級到商業 / 合規等級（CVSS + BIA + IEC 62443） |
| ARCHITECTURE.md | 2026-06-05 — 補介面清單表 |
| test_security.py | 2026-05-30 — 24 個測試全綠 |
