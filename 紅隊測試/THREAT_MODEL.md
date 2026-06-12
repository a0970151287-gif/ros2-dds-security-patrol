# Threat Model — ROS2 DDS Security Monitor + SAC 巡邏系統

> ⚠️ **本文件 §2.1 仍包含「蹭工廠 WiFi 的入侵者」「operator dashboard hijack」等帶人視角的描述。**
> **正式威脅分析請見 [系統威脅分析.md](系統威脅分析.md)**：用「介面 → 未授權程式 → 受害軟體模組」的格式重寫，符合教授指導（情境是系統不是人；威脅分析從介面切入；威脅評估高/中/低）。
> 本文件保留作為 CIA 屬性 / 攻擊者能力等級表 / 修補紀錄的歷史參考。

## 1. 系統範圍

本文件描述 [dds_security_monitor](../src/dds_security_monitor/) +
[turtlebot3_dqn](../src/turtlebot3_dqn/) 的威脅模型。

**受保護資產 (assets)**：
| Asset | 描述 | CIA 屬性 |
|---|---|---|
| Robot 控制權 | `/cmd_vel` topic | Integrity, Availability |
| SAC 模型權重 | `models_sac/*.zip` | Integrity, Confidentiality |
| Replay buffer | `models_sac/*.pkl` | Integrity |
| LINE 通知 token | `~/.config/dds-monitor/line_token` | Confidentiality |
| 感測資料完整性 | `/scan`, `/odom` | Integrity |
| 訓練過程 | 訓練 process | Availability |

---

## 2. 攻擊者能力假設 (Adversary Capabilities)

### 2.1 In-scope (本系統聲稱能擋的)

| Level | 能力 | 範例 |
|---|---|---|
| **L1** | 同 LAN 內任意 ROS2 node | 蹭工廠 WiFi 的入侵者 |
| **L2** | 同 user shell 存取 | 透過其他漏洞拿到 jesse user 的 SSH，但不是 root |
| **L3** | 可讀 `~/ros2_ws/` 但不能寫 keystore | 部分檔案存取權 |

### 2.2 Out-of-scope (本系統不擋的)

| | 為什麼 out-of-scope |
|---|---|
| Root / 物理存取 | 機器被物理控制無法防禦 |
| 拿到 `~/.config/dds-monitor/alert_secret` | HMAC key 被偷則整個 chain 失效，這是密碼學前提 |
| Side-channel (timing, power) | 學術專題範圍 |
| 偽裝 ROS2 internal name (`_NODE_NAME_UNKNOWN_`) | DDS discovery 暫態，難以區分 |
| 攻擊者用 deep learning 學習 detector 後製作 adaptive attack | 需要 white-box 知識，threat level 過高 |
| SROS2 切到 Enforce 後的 DDS 層攻擊 | 已知 Permissive 模式有 DDS layer holes，依賴 SROS2 而非本系統 |

### 2.3 攻擊者不知道的（Security Assumption）

- **HMAC secret** (`~/.config/dds-monitor/alert_secret`, chmod 600)
- **LINE token** (`~/.config/dds-monitor/line_token`, chmod 600)
- **正確的 node 名稱白名單**（理論上可從 publicly observable graph 推測）

---

## 3. 攻擊面分類 (Attack Surface)

```
攻擊面                  傳輸機制              受影響資產
────────────────────────────────────────────────────────
/cmd_vel             ROS topic (DDS)     →   Robot 控制
/security/alerts     ROS topic           →   Emergency stop 邏輯
/patrol/goto         ROS topic           →   巡邏目標
/patrol/reload       ROS service         →   Patrol 控制 loop
/scan                ROS topic           →   SAC 觀測
ROS2 graph           DDS discovery       →   監控偵測
*.pkl, *.zip         檔案系統             →   模型/buffer 完整性
/proc/<pid>/environ  Linux /proc         →   敏感變數洩漏
```

---

## 4. 攻擊 ↔ 防禦對照表（30 個攻擊）

> 註：N8-N12 是**藍方主動預判**的攻擊（紅方未提出），藍方搶先實作修補 + 自己寫 PoC 驗證。從被動補丁改為主動 hardening。

| # | 攻擊 | 攻擊面 | 攻擊者能力 | Layer 1 (SROS2) | Layer 2 (App) | Layer 3 (IDS) | 整體狀態 |
|---|---|---|---|---|---|---|---|
| **A** | Prefix bypass | ROS graph | L1 | ⚪ N/A | ✅ [monitor:29](../src/dds_security_monitor/dds_security_monitor/monitor_node.py#L29) `_INTERNAL_PREFIXES` 精確化 | ⚪ N/A | **✅ 擋下** |
| **B** | `/security/alerts` 偽造 | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ HMAC 驗章 [monitor:88](../src/dds_security_monitor/dds_security_monitor/monitor_node.py#L88) | ⚪ N/A | **✅ 擋下** |
| **C** | `/cmd_vel` hijack | ROS topic | L1 | 🟡 Permissive 不擋 | 🟡 burger_env 啟動掃描 | ✅ D1 physics + D4 publisher | **✅ 擋下** |
| **D** | `/patrol/goto` 劫機 | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ 座標 ±2.5m + name 長度檢查 + HMAC 驗章 (G3) | ⚪ N/A | **✅ 擋下** |
| **H** | LINE token leak | Linux /proc | L2 | ⚪ N/A | ✅ token 改檔案讀取，credentials 不再 export | ⚪ N/A | **✅ 新 process 擋下** |
| **I** | Pickle RCE | buffer.pkl | L3 | ⚪ N/A | ✅ HMAC 檔案簽章 + load 前驗章 [train_sac:91](../src/turtlebot3_dqn/turtlebot3_dqn/train_sac.py#L91) | ⚪ N/A | **✅ 擋下** |
| **J** | 同名 node 劫持 | DDS race | L1 | 🟡 Permissive 不擋 | 🟡 burger_env 啟動掃描 | ✅ D2 oscillation + D4 duplicate | **✅ 擋下** |
| **K** | Scan poisoning | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ std<0.01 + frame-repeat + 95% near-max [burger_env:172](../src/turtlebot3_dqn/turtlebot3_dqn/burger_env.py#L172) | ✅ D4 unauthorized | **✅ 擋下** |
| **L** | Service flood DoS | ROS service | L1 | 🟡 Permissive 不擋 | ✅ 5s rate limit + `enable_reload_service` 預設關閉 (G4) | ⚪ N/A | **✅ 擋下** |
| **M** | Model file swap | 檔案系統 | L3 | ⚪ N/A | ✅ HMAC 簽章 + load 前驗章 | ⚪ N/A | **✅ 擋下** |
| **N1** | `/security/heartbeat` replay | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ envelope 加 ts + nonce + receiver 端 ReplayCache + HB 用 RELIABLE+TRANSIENT_LOCAL (擋 BEST_EFFORT 假冒 publisher) + max_age=3s | ✅ D5 watchdog 在 monitor 真死後 10s 內 fire | **✅ 擋下** |
| **N2** | `_INTERNAL_NODE_REGEX` 後門 | ROS graph | L1 | ⚪ N/A | ✅ 完全移除 regex 白名單，改用「baseline 快照 + grace period 只吸收白名單」 | ⚪ N/A | **✅ 擋下** |
| **N3** | `/security/alerts` replay → 永久 patrol DoS | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ envelope 加 ts + nonce + 每個 subscriber 自帶 ReplayCache（patrol / mission / system / burger_env） | ⚪ N/A | **✅ 擋下** |
| **N4** | Cross-channel signature confusion (HB → alerts forward) | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ envelope 加 `channel` 欄位 + receiver 端帶 `expected_channel`；signs/verifies 全面綁定 CH_* 常數 | ⚪ N/A | **✅ 擋下** |
| **N5** | Pre-startup baseline poison | ROS graph | L1 | ⚪ N/A | ✅ 首次 baseline 改為「只信任白名單」— 啟動時看到非白名單節點立刻 alert | ⚪ N/A | **✅ 擋下** |
| **N6** | `/sensor/status` spoof (namesake `sensor_hub_node`) | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ sensor_hub 改用 `sign_alert(..., channel=CH_SENSOR)` 發送；mission_manager + system_status 用 `verify_alert(..., expected_channel=CH_SENSOR)` 驗章 | ⚪ N/A | **✅ 擋下** |
| **N7** | `/mission/cmd` 直擊 (operator panel hijack) | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ mission_manager 用 `sign_alert(..., channel=CH_MISSION)` 發送；system_status 用 `verify_alert(..., expected_channel=CH_MISSION)` 驗章 | ⚪ N/A | **✅ 擋下** |
| **N8** 🔵 | `/system/health` spoof (operator dashboard hijack) | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ system_status 簽 `CH_HEALTH` + self-watch：訂自己發的 health channel，看到非自己發的 nonce → 透過 /security/alerts 廣播 N8 防護警報 | ⚪ N/A | **✅ 擋下（藍方主動修）** |
| **N9** 🔵 | `/cmd_vel` race during emergency stop | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ D1 threshold 收緊 0.25→0.23；patrol pause 期間 5Hz→100Hz 高頻送 0 cmd_vel 跟 attacker 競爭 latest-message-wins | ✅ D4 持續 fire alert | **✅ 緩解（藍方主動修）— 100Hz attacker 下 robot 62% 時間是 0** |
| **N10** 🔵 | `/scan` drift attack (LaserScan poisoning 繞過 D3) | ROS topic | L1 | 🟡 Permissive 不擋；message type 非 String 無法包 envelope | 🟡 D4 publisher 名字+計數檢查 | ✅ 新增 D6 行為一致性偵測（odom 移動但 scan 完全靜止） | **🟡 部分擋（藍方主動修）— 根治需 SROS2** |
| **N11** 🔵 | `/odom` poisoning (位置認知劫持) | ROS topic | L1 | 🟡 Permissive 不擋；message type 非 String 無法包 envelope | ⚪ N/A | ✅ D4 延伸到 /odom（dual publisher 偵測）+ D6 cmd-vs-odom 一致性（cmd 推進但 odom 不動） | **🟡 部分擋（藍方主動修）— 根治需 SROS2** |
| **N12** 🔵 | ReplayCache LRU flood eviction | 應用層 | L1 (學術等級) | ⚪ N/A | ✅ ReplayCache 加 TTL eviction（與 max_age 對齊），LRU flood 也無法擠掉「仍在 freshness window 內」的 nonce | ⚪ N/A | **✅ 擋下（藍方主動修）** |
| **N13** | N8 self-watch reflection + latch（藍方主動修 N8 引入的新洞）| ROS topic | L1 | 🟡 Permissive 不擋 | ✅ self-watch 改為 **log-only + rate-limit cooldown**：未簽章垃圾**絕不**反射成 CH_ALERTS；移除 `_health_impostor_alerted` 一次性 latch | ⚪ N/A | **✅ 擋下（紅方教訓，藍方收下）** |
| **N14** 🔵 | `/dds_security_monitor/set_parameters` 改 whitelist 永久隱身 | ROS2 service | L1 | ⚪ N/A | ✅ 所有安全敏感參數（whitelist / poll_interval / emergency_stop_* / line_*）用 `ParameterDescriptor(read_only=True)` declare，`/set_parameters` 自動拒絕 | ⚪ N/A | **✅ 擋下（藍方主動修）— 驗證 service 直接回 `Trying to set a read-only parameter`** |
| **N15** 🔵 | Unsigned message flood log storm DoS | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ 所有 verify_alert 失敗的 warn log 加 `throttle_duration_sec=5.0`，attacker 538 筆 flood → receiver 各只印 1 條 log | ⚪ N/A | **✅ 擋下（藍方主動修）** |
| **N17** 🔵 | LINE notification flood (attacker 灌 100 個唯一 unknown names → operator 通知爆炸) | ROS graph | L1 | ⚪ N/A | ✅ monitor LINE 通知改 batch — pending alerts 每 30s 聚合成 1 條 burst summary，「30 秒內偵測到 N 個未知節點」+ 名單預覽；副作用修補：leading-edge 第一筆立即送不延遲 + pending list 上限 256 防 memory spike | ⚪ N/A | **✅ 擋下（藍方主動修）** |
| **N18** | `_alerted_nodes` set 無上限增長 → OOM (attacker rotate 100 萬 unique node names) | 應用層 | L1 | ⚪ N/A | ✅ dedup set 改為 OrderedDict + 10min TTL + 2048 LRU 上限。同源 TTL 過期允許再次 alert，防 attacker 用同名 squat | ⚪ N/A | **✅ 擋下（紅方第六輪挑出）** |
| **N19** | ros2 /set_parameters service flood DoS (1626 req/s) | ROS2 service | L1 | ⚪ N/A | 🟢 DDS RELIABLE QoS + depth=10 自動限速 — N14 read_only 設定後 service call 還是被 reject，executor 公平調度保證 timer 拿得到時間片 | ⚪ N/A | **✅ QoS 自然擋下（紅方確認 monitor 心跳 0.5Hz 紋風不動）** |
| **N20** | verify-flood (368k/s heartbeat + 18k/s alerts) | ROS topic | L1 | ⚪ N/A | 🟢 BEST_EFFORT 心跳：DDS 自動丟包是天然 flood shield；RELIABLE alerts: KEEP_LAST depth=10 限制 receiver 每 spin 只處理 ~10 筆，timer 不會被餓死 | ⚪ N/A | **✅ QoS 自然擋下（紅方確認 IDS timer 精確 5s 不動）** |
| **N21** | IDS detector-induced cascade DoS (attacker 用未授權 publisher 戳 D4 → IDS 替他簽 alert) | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ patrol/mission/burger_env resume timer **不再 reset on alert**（首次 pause 30s 之後 timer 固定，不延長）；cascade-DoS 偵測 90s 內 ≥2 次 pause → 120s 不再自動 pause 等人工介入 | ⚪ N/A | **✅ 擋下 — 12 pokes / 2 pause / 2 resume / 1 escalation / 7 quiet-window blocks** |
| **N22** | `/imu` spoof (未簽章 + monitor 未列管 publisher count) | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ D4 publisher count 延伸到 /imu — dual publisher 視為 spoof | ✅ D4 | **✅ 擋下（低危但補上一致性）** |
| **N23** | 用白名單名（teleop_keyboard）+ 異常行為觸發 D1/D2 → IDS cascade DoS | ROS topic | L1 | 🟡 Permissive 不擋 | ✅ 同 N21 receiver-side 修補（不是擋 detector 而是擋「自動 cascade 到 emergency stop」這個結構） | ⚪ N/A | **✅ 擋下 — 2 pause / 2 resume / 1 escalation / 4 quiet-window blocks** |
| **N14-gap** 🔵 | patrol_node waypoints_file + enable_reload_service 未鎖 read_only | ROS2 service | L2 (inert) | ⚪ N/A | ✅ 補齊 ParameterDescriptor(read_only=True) 一致性 | ⚪ N/A | **✅ 擋下（藍方補齊）** |

### 4.1 Defence-in-Depth 統計

- **單層擋下**：D, H, I, L, M, N2, N3, N4, N5, N6, N7, N12, N13, N14, N14-gap, N15, N17, N18, N21, N22, N23 (21/30)
- **兩層協作**：A, B, C, J, K, N1, N8, N10, N11 (9/30)
- **QoS 自然擋下**：N19, N20 (DDS + executor 公平調度自帶 flood shield)
- **強化（非完整擋下，配合多層緩解）**：N9 (62% 競爭勝率)
- **完全沒擋**：0/30
- **依賴 SROS2 Enforce 才能根治**：C, J, N9, N10, N11
- **藍方主動預判修補（紅方未提出 / 藍方先打）**：N8, N9, N10, N11, N12, N14, N15, N17, N18 (部分), N22, N14-gap
- **紅方教訓 → 藍方收下**：N13（self-watch 變新攻擊面）、N18（dedup set 無上限）、N21/N23（cascade-DoS — 偵測器本身可被借力按按鈕）

### 4.2 已知繞過 (Known Bypasses) — 誠實寫出

| 攻擊 | 繞過方法 | 對應修補方向 |
|---|---|---|
| K (進階) | 攻擊者 remap `__node:=ros_gz_bridge` + 動態 noise | SROS2 Enforce |
| C / J | 取得合法 enclave 憑證後從內部攻擊 | 不在 threat model 範圍 |
| H (舊 process) | 已 source 舊 credentials 的 shell 重啟前仍洩漏 | 用戶端 hygiene |
| Pickle (I) | 攻擊者拿到 `alert_secret` 後可重新簽 | 不在 threat model 範圍 |
| N2 (進階) | 攻擊者在 monitor 啟動的 grace period (15s) 內、用白名單上的名字加入 | 操作 hygiene — 不在 grace period 內啟動可疑工作；或縮 `_STARTUP_GRACE_SEC` |
| N1/N3 (極端) | 攻擊者搶在 receiver 訂閱前捕獲訊息，且 receiver 永遠收不到原始 | DDS QoS 升級（已對心跳 RELIABLE+TRANSIENT_LOCAL；alert 已是）|
| N5 (operational) | `ros2 cli daemon` 比 monitor 早啟 → alert 一次（不是攻擊但是 noise） | 部署順序：先啟 monitor 再開 daemon；或把 daemon name pattern 加入白名單 |
| N6/N7 (secret leak) | 攻擊者拿到 `alert_secret` 後可正確簽出 sensor/mission 訊息 | 不在 threat model 範圍（2.2 已聲明 secret leak = out-of-scope）|

---

## 5. 驗證 (Verification)

| 驗證手段 | 涵蓋範圍 | 位置 |
|---|---|---|
| 紅隊攻擊腳本 (原 10) | A/B/C/D/H/I/J/K/L/M | [12_紅隊攻擊測試.sh](PoC腳本/12_紅隊攻擊測試.sh) |
| 紅隊報告 (原 10) | 攻擊原理 + 漏洞 + 修補 | [12_紅隊攻擊報告.md](12_紅隊攻擊報告.md) |
| 紅隊第二輪攻擊 (新 3) | N1 heartbeat replay / N2 regex 後門 / N3 alert replay DoS | [run_N_attacks.sh](PoC腳本/run_N_attacks.sh) |
| 紅隊第二輪報告 | 攻擊原理 + 共同根因 + 修補建議 | [N_新攻擊報告.md](攻擊報告/N_新攻擊報告.md) |
| 紅隊第三輪攻擊 (新 4) | N4 cross-channel confusion / N5 baseline poison / N6 sensor spoof / N7 mission spoof | [run_N4_attack.sh](PoC腳本/run_N4_attack.sh) + N5-N7 PoC |
| 紅隊第三輪報告 | channel binding 缺失 + 內部 topic 全無簽章 | [N4_新攻擊報告.md](攻擊報告/N4_新攻擊報告.md), [N5_新攻擊報告.md](攻擊報告/N5_新攻擊報告.md), [N6_N7_新攻擊報告.md](攻擊報告/N6_N7_新攻擊報告.md) |
| 藍方主動 PoC (N8/N9) | /system/health spoof + cmd_vel race during emergency | [N8_system_health_spoof.py](PoC腳本/N8_system_health_spoof.py), [N9_cmd_vel_race.py](PoC腳本/N9_cmd_vel_race.py) |
| Unit test (pytest) | HMAC 驗章 / 座標檢查 / scan std | `tests/` |
| Regression | 修補後重跑紅隊腳本 | 同上 |

---

## 6. 殘餘風險 (Residual Risk)

即使本系統完整實作，仍有以下風險：

1. **DDS Permissive 模式** — `/cmd_vel`, `/scan`, `/odom` 沒 publisher 身份驗證
2. **secret 集中化** — 一個 `alert_secret` 保護所有 HMAC 簽章，被偷則全 chain 失效
3. **IDS False Positive** — D2/D3 偵測可能誤報合法但少見的 patrol 行為
4. **無 forward secrecy** — 沒有 key rotation 機制
5. **Bootstrap trust** — 第一次安裝時 `alert_secret` 怎麼分發未在範圍內

---

## 7. 更新紀錄

| 日期 | 變更 |
|---|---|
| 2026-05-25 | 初版 — 對齊紅隊報告 10 個攻擊 |
| 2026-05-27 | 加入 defence-in-depth 統計、已知繞過、殘餘風險 |
| 2026-05-28 | 加入 N1 / N2 / N3（紅隊第二輪），共同根因「HMAC envelope 缺 anti-replay 欄位」已修補：sign_alert 加 ts+nonce；接收端 ReplayCache；heartbeat QoS 升級為 RELIABLE+TRANSIENT_LOCAL；`_INTERNAL_NODE_REGEX` 移除改用 baseline 快照。13/13 全擋下 |
| 2026-05-28 (晚) | 加入 N4 / N5 / N6 / N7（紅隊第三輪），共同根因「envelope 不綁 channel + 內部 status/mission topic 完全無簽章 + baseline 無條件吸收」已修補：sign_alert/verify_alert 加 `channel` binding；首次 baseline 改為「只信白名單」；sensor_hub 跟 mission_manager 改用簽章發內部訊息。17/17 全擋下 |
| 2026-05-29 | **藍方主動 hardening** 加入 N8-N12（紅方未提出，藍方預判 + 自寫 PoC 驗證）：N8 /system/health 簽章 + self-watch; N9 D1 收緊+100Hz 競爭; N10/N11 D4 延伸到 /odom + 新增 D6 行為一致性偵測; N12 ReplayCache 加 TTL eviction 防 LRU flood。22/22 全擋下/緩解。轉守為攻：不再被動等紅方教 |
| 2026-05-30 | **紅方 N13 證明 N8 self-watch 自己變成新攻擊面**（confused-deputy reflection + 一次性 latch 致盲）。藍方收下教訓 + 同時主動加 N14（read_only param）/ N15（log throttle）/ N17（LINE batch）。**修補 N8 self-watch 改為 log-only + rate-limit cooldown — 偵測器絕不能反射成 emergency stop alert**。26/26 全擋下。新教訓：每個新偵測器都是新攻擊面，要做威脅建模才能上線 |
| 2026-06-02 | 紅方第六輪 N19/N20 DoS 全陰性（QoS 自然擋）+ 第七輪 N21/N23 結構性攻擊：**偵測到 → 自動 emergency stop** 這個設計本身被借力。「攻擊者故意讓自己被偵測到」變成攻擊武器。藍方主修：**receiver-side resume timer 不再 reset on alert**（首次 pause 30s 後 timer 固定，不被後續 alert 延長）+ cascade-DoS 偵測（90s 內 ≥2 次 pause → 120s quiet window 不再自動 pause 等人工介入）。同時補 N14-gap（patrol params read_only）+ N18 (`_alerted_nodes` TTL+LRU 防 OOM) + N22 (D4 延伸到 /imu) + N17 副作用（leading-edge 不延遲 + pending list 上限）。30/30 全擋下/緩解。新教訓：**任何 cascade 設計都是按鈕，要設「升級到人類」的斷路器** |
