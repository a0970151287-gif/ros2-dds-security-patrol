# 系統架構圖（UML 模組化設計）

> 依據教授建議：定義系統邊界、模組間關係、Level 1 → Level 2 展開
> 方框 = 模組（Class / 功能主體）；虛線框 = 系統邊界（System Boundary）；箭頭 = 依賴 / 資料流
>
> 版本：TQC（Truncated Quantile Critics）+ HMAC envelope v3 + 行為 IDS + 紅隊 N1–N24

---

## Level 1 — 系統全貌（System Boundary）

```
╔═══════════════════════════════════════════════════════════════════════════╗
║  << 外部環境 >> External Systems                                          ║
║                                                                           ║
║  ┌─────────────────┐      ┌──────────────────────────────────────┐       ║
║  │  Gazebo Garden  │      │  紅隊測試 Lab（離線驗證）             │       ║
║  │  LiDAR / IMU    │      │  N1–N24 PoC · pytest · CVSS v3.1     │       ║
║  │  物理引擎        │      │  IEC 62443-3-3 / NIST CSF v2.0       │       ║
║  └────────┬────────┘      └────────────────────┬─────────────────┘       ║
╚═══════════╪════════════════════════════════════╪═════════════════════════╝
            │ /scan /imu /odom                   │ 攻擊（同 DDS domain，無密鑰）
            ▼                                    ▼
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
  << 系統邊界 System Boundary >> （本專題開發範圍）
│                                                                            │
│  ┌───────────────────────────┐     ┌────────────────────────────────────┐ │
│  │  模組 A：TQC 智慧巡航      │     │  模組 B：DDS 資安監控              │ │
│  │  patrol_node /            │◀───▶│  monitor_node                     │ │
│  │  burger_env_top           │     │                                    │ │
│  │  · 巡邏點管理（5 點循環）  │     │  · 未知節點偵測（baseline+grace）    │ │
│  │  · TQC 推論 deterministic │     │  · 白名單 11 節點 + read_only param │ │
│  │  · obs[744] 4 幀疊加      │     │  · HMAC envelope v3 簽章 / 緊急停止  │ │
│  └─────────────┬─────────────┘     └────────────────────────────────────┘ │
│                │ /cmd_vel                       │ /security/alerts         │
│                ▼                               ▼                          │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  模組 C：任務管理與系統狀態                                           │  │
│  │  mission_manager_node   system_status_node   sensor_hub_node        │  │
│  │  （channel binding：CH_MISSION / CH_HEALTH / CH_SENSOR 全簽章驗章）   │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  模組 D：紅隊 PoC + 行為 IDS（最後一道防線）                          │  │
│  │  N1–N24 PoC → HMAC 驗章 → intelligent_defense_node(D1–D6) → 斷路器  │  │
│  │  驗證模組 B 的防禦，並在 topic 層攔截 cmd_vel / scan / odom 攻擊      │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘

模組關係：
  A <──> B  ：Security 偵測到威脅時，透過 /security/alerts（簽章）讓 A 緊急停止
  A ────> C  ：TQC 輸出 /cmd_vel，任務管理依此判斷任務狀態
  B ────> C  ：Security 發出簽章警報，任務管理驗章後切換任務模式
  D ────> B  ：紅隊 PoC 驗證 B 的防禦；IDS 在行為層補 topic 攻擊（cmd_vel/scan/odom）
```

---

## Level 2A — 模組 A 展開：TQC 智慧巡航（推論模式）

```
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
  模組 A：TQC 智慧巡航（Level 2 展開，推論模式）
│                                                                     │
│  ┌──────────────────────┐     ┌──────────────────────────────────┐ │
│  │ A1：巡邏點管理        │────>│ A2：觀測值建構                    │ │
│  │ WaypointManager      │     │ ObservationBuilder               │ │
│  │                      │     │                                  │ │
│  │ 巡邏點（5 個工廠點）： │     │ · LiDAR 180 raw beams 正規化 /3.5 │
│  │  1. 電源控制室        │     │ · 6 state：dist, cos, sin,       │ │
│  │  2. 冷卻水塔          │     │   prev_lin, prev_ang, stage      │ │
│  │  3. 生產線A           │     │ · Frame stack K=4 → obs[744]     │ │
│  │  4. 生產線B           │     │ · 1D-Conv encoder 抓 spatial     │ │
│  │  5. 出入口            │     └──────────────────┬───────────────┘ │
│  │ 到達門檻 0.30m        │                        │ obs (744 維)    │
│  │ curriculum 1→5 自動升級│                       ▼                │
│  └──────────────────────┘     ┌──────────────────────────────────┐ │
│                                │ A3：TQC 策略網路（推論模式）       │ │
│                                │ TQCPolicy.predict()              │ │
│                                │                                  │ │
│                                │ · 載入 tqc_best.zip（驗 HMAC）    │ │
│                                │ · top_quantiles_drop=2（抑制 Q   │ │
│                                │   overestimation）               │ │
│                                │ · Eval：deterministic + 95% CI   │ │
│                                └──────────────────┬───────────────┘ │
│                                                   │ action[v, w]   │
│                                                   ▼                │
│                                ┌──────────────────────────────────┐ │
│                                │ A4：指令輸出                      │ │
│                                │ CommandPublisher                 │ │
│                                │                                  │ │
│                                │ · 線速 = (a[0]+1)/2 x 0.22 m/s   │ │
│                                │   （Burger 物理上限）            │ │
│                                │ · 角速 = a[1] x 1.5 rad/s        │ │
│                                │ · 發布 /cmd_vel (10 Hz)          │ │
│                                │ · 資安警報（驗章）時強制 v=0 w=0  │ │
│                                └──────────────────────────────────┘ │
│                                                                     │
│  推論迴圈（10 Hz）：                                                 │
│  /scan /odom -> A2 -> A3.predict() -> A4 -> /cmd_vel -> 機器人      │
│                                                                     │
│  與訓練模式的差異：無 reward shaping、無 reset/step、無探索雜訊        │
│  訓練額外機制：Domain Randomization + 5% 對抗訓練 + curriculum 1→5    │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘

  外部依賴：
    · Gazebo 提供 /scan（180 beams LiDAR）、/odom（位置/航向/速度）
    · /security/alerts（簽章）驗章通過 -> 覆蓋 A4 輸出（緊急停止）
    · 模型檔：runs_top/models/tqc_best.zip（load 前驗 .sha256.hmac）
    · Reward = γ·Φ(s') − Φ(s)（Ng-Harada-Russell 1999 potential-based）
```

---

## Level 2B — 模組 B 展開：DDS 資安監控

```
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
  模組 B：DDS 資安監控（Level 2 展開）
│                                                                     │
│  ┌─────────────────────┐     ┌─────────────────────────────────┐   │
│  │ B1：白名單 + baseline│────>│ B2：DDS 節點掃描                 │   │
│  │ WhitelistManager    │     │ NodeScanner                     │   │
│  │                     │     │                                 │   │
│  │ · 合法節點清單（11） │     │ · get_node_names() 定期輪詢      │   │
│  │ · 開機 baseline 快照 │     │ · 頻率：每 5 秒                  │   │
│  │ · read_only param    │     │ · 發 /security/heartbeat 給 IDS │   │
│  │   （防 N14 hijack）  │     │ · 非白名單 -> 觸發 B3            │   │
│  └─────────────────────┘     └──────────────────┬──────────────┘   │
│                                                  │ 未知節點全路徑   │
│                                                  ▼                  │
│                               ┌──────────────────────────────────┐  │
│                               │ B3：異常判斷                      │  │
│                               │ AnomalyDetector                  │  │
│                               │                                  │  │
│                               │ 【已修補】                        │  │
│                               │ · baseline 快照 + 15s grace       │  │
│                               │   period 只吸收白名單             │  │
│                               │ · 移除 prefix 後門，非白名單一律   │  │
│                               │   alert（namespace+name 一致）    │  │
│                               └──────────┬────────────────────────┘  │
│                                          │ 判斷結果                   │
│                         ┌────────────────┼──────────────┐            │
│                         ▼                ▼              ▼            │
│              ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│              │ B4：警報發布 │  │ B5：緊急停止 │  │ B6：事件記錄 │       │
│              │ AlertPublish│  │ （下游驗章） │  │ EventLogger│      │
│              │             │  │              │  │            │      │
│              │ · /security │  │ · 各下游驗章 │  │ · throttle │      │
│              │   /alerts   │  │   後 v=0,w=0 │  │   5s 防洪水 │      │
│              │ · CH_ALERTS │  │ · resume 30s │  │ · LINE 30s │      │
│              │ · envelope  │  │   固定不reset│  │   batch    │      │
│              │   v3 簽章   │  │ · 90s 內≥2   │  │ · LRU+TTL  │      │
│              │ · RELIABLE  │  │   pause →    │  │   防 OOM   │      │
│              │   VOLATILE  │  │   120s quiet │  │            │      │
│              │   max_age3s │  │   window     │  │            │      │
│              └─────────────┘  └─────────────┘  └─────────────┘      │
│  資料流：DDS 圖 -> B2 -> B3 -> [B4 + B5 + B6]                       │
│  下游模組（patrol / burger_env / mission）驗章通過才進緊急停止       │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘

  外部依賴：
    · 無（B2 直接呼叫 ROS2 Graph API，不需外部服務）
    · B4 輸出 /security/alerts（CH_ALERTS 簽章）-> 模組 C / A 驗章後處理
    · 共享密鑰 ~/.config/dds-monitor/alert_secret（chmod 600）
    · 紅隊 N1–N24 已驗證：18 漏洞全擋下 / 緩解
```

---

## Level 2D — 模組 D 展開：紅隊 PoC + 行為 IDS

```
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
  模組 D：紅隊 PoC + 行為 IDS（防線最末端，Level 2 展開）
│                                                                     │
│  ┌──────────────────────┐                                          │
│  │ D1：紅隊 PoC          │                                          │
│  │ N1–N24 獨立可執行檔   │                                          │
│  │                       │                                          │
│  │ · N1 heartbeat replay │                                          │
│  │ · N4 cross-channel    │                                          │
│  │ · N13 confused-deputy │──────────┐                               │
│  │ · N14 param hijack    │          ▼                               │
│  │ · N21 cascade DoS     │  ┌───────────────────────┐               │
│  │ · 無密鑰 · 同 domain  │  │ D2：HMAC 驗章          │               │
│  └──────────────────────┘  │ envelope v3 五道檢查   │               │
│                             │ · sig == HMAC(body)    │               │
│                             │ · channel == expected  │               │
│                             │ · ts 在 3s 窗內         │               │
│                             │ · nonce ∉ ReplayCache  │               │
│                             └───────────┬────────────┘               │
│                                         │ 未經簽章 / 過期 / 重放      │
│                                         ▼                            │
│                    ┌────────────────────────────────────────┐        │
│                    │ D3：行為 IDS                            │        │
│                    │ intelligent_defense_node                │        │
│                    │                                         │        │
│                    │ · D1 cmd_vel > 0.23 m/s（物理門檻）      │        │
│                    │ · D3 scan std < 0.01（重複偽造）         │        │
│                    │ · D4 unauthorized publisher             │        │
│                    │ · D5 heartbeat watchdog 10s             │        │
│                    │ · D6 cmd-vs-odom-vs-scan 一致性          │        │
│                    │ · 投票 ≥2 fire（D4/D5 可單獨）           │        │
│                    └────────────────────┬───────────────────┘        │
│                                         │ 偵測到攻擊                  │
│                    ┌────────────────────┼───────────────────┐        │
│                    ▼                    ▼                    │        │
│  ┌──────────────────────┐  ┌──────────────────────┐          │        │
│  │ D4：Cascade 斷路器    │  │ D5：漏洞報告          │          │        │
│  │                       │  │ CVSS v3.1            │          │        │
│  │ · resume timer 不reset│  │                       │         │        │
│  │ · 90s 內≥2 pause →    │  │ · Critical × 4 (9.1) │           │        │
│  │   120s quiet window   │  │ · High × 10 (7.1-8.7)│          │        │
│  │ · 升級到外部介入       │  │ · Medium × 4 (4.3-6.5)│          │        │
│  │ · LINE 30s batch 通知 │  │ · pytest 24 全綠     │          │        │
│  └──────────────────────┘  └──────────────────────┘           │        │
│                                                                │        │
│  發現漏洞統計（截至目前）：                                      │        │
│    18 漏洞 100% 修補 / 緩解                                     │        │
│    對齊 IEC 62443-3-3（17/17 SR）+ NIST CSF v2.0（6/6 Function）│        │
│                                                                │        │
│  資料流：D1 攻擊 -> D2 驗章 -> D3 行為偵測 -> D4 斷路器 + D5 報告│        │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘

  外部依賴：
    · 無外部 API（紅隊 PoC 與 IDS 全在本機 ROS2 domain 內）
    · pytest tests/test_security.py（24 個自動化測試）
    · 驗證對象：模組 B 的防禦 + topic 層 cmd_vel/scan/odom 攻擊
```

---

## 模組間關係一覽

```
WaypointManager ──> ObservationBuilder ──> TQCPolicy.predict()
   (curriculum 1→5)    (obs[744], 1D-Conv)        |
                                            CommandPublisher
                                                   |
                                              /cmd_vel
                                            /          \
                                    機器人移動      緊急停止
                                                   (驗章後 v=0)

WhitelistManager ──> NodeScanner ──> AnomalyDetector
  (11 + read_only)   (5s + heartbeat)  (baseline+grace)
                                      /    |    \
                              B4Alert  B5Stop  B6Log
                          (envelope v3) (30s+quiet) (throttle/LINE)
                                  |
                          /security/alerts（CH_ALERTS 簽章）
                                  |
                        MissionManager / SystemStatus（驗章）

紅隊 PoC ──> HMAC 驗章 ──> 行為 IDS ──> Cascade 斷路器 ──> 漏洞報告
  (N1-N24)   (envelope v3)  (D1-D6)      (quiet window)    (CVSS, 18/18)
```

---

## 系統邊界說明

| 分類 | 元件 | 說明 |
|------|------|------|
| **外部** | Gazebo Garden | /scan /imu /odom，非本專題開發 |
| **外部** | 紅隊測試 Lab | N1–N24 PoC / pytest / CVSS，離線驗證 |
| **外部** | SROS2（Permissive） | DDS 層；Enforce migration 列入 90 天計畫 |
| **內部** | patrol_node / burger_env_top | TQC 推論 + 巡邏點管理 |
| **內部** | monitor_node | 白名單偵測 + HMAC 簽章警報 + 緊急停止 |
| **內部** | MissionManager / SystemStatus / SensorHub | 任務整合層（channel binding 驗章） |
| **內部** | intelligent_defense_node | 行為 IDS（D1–D6）+ cascade 斷路器 |
