# 系統架構圖

> **現行版本註記**：DDS 攻防核心使用幾何 `patrol_node`；TQC 是保留的獨立未來工作軌。日常 `01/01b` 為 Permissive，`01c` 才是 Enforce。Enforce 的政策與憑證已通過離線稽核，隔離 domain 有 live 對照，但修補後全 Gazebo 長時間攻防回歸尚未完成。

## 1. 節點拓樸（11 個 ROS2 nodes）

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ROS2 DOMAIN (ROS_DOMAIN_ID=30)                       │
│                                                                            │
│  ┌──────────────────┐                                                     │
│  │   Gazebo Garden  │  (turtlebot3_world.world + Burger)                   │
│  └─────────┬────────┘                                                     │
│            │ DDS                                                           │
│  ┌─────────▼──────────┐    publishes:                                     │
│  │  ros_gz_bridge     │   ┌──── /scan        (LaserScan, BE)              │
│  │ (parameter_bridge) ├───┼──── /odom        (Odometry, BE)               │
│  │                    │   ├──── /tf, /imu, /clock                          │
│  └────────────────────┘   └──── /cmd_vel ←   subscribes                   │
│                                                                            │
│                          ╔════════════════════════════╗                   │
│                          ║   控制器分支                  ║                   │
│                          ╚════════════════════════════╝                   │
│  ┌────────────────────┐                  ┌────────────────────┐           │
│  │  burger_env_top    │  TQC獨立軌       │  patrol_node       │  攻防主線 │
│  │  (TQC environment) │  /未來工作       │  (幾何控制器)       │           │
│  │                    │                  │                    │           │
│  │  sub: /scan /odom  │                  │  sub: /scan /odom  │           │
│  │       /alerts     ┘│                  │       /alerts      │           │
│  │  pub: /cmd_vel     │                  │       /patrol/goto │           │
│  └────────────────────┘                  │  pub: /cmd_vel     │           │
│                                          │  srv: /patrol/reload│           │
│                                          └────────────────────┘           │
│                                                                            │
│  ╔══════════════════════════════════════════════════════════════════╗     │
│  ║                 資安監控與防禦堆疊（三層防線）                       ║     │
│  ╚══════════════════════════════════════════════════════════════════╝     │
│                                                                            │
│  Layer 1 — DDS                                                             │
│  ┌────────────────────┐                                                   │
│  │  SROS2 keystore    │  ~/ros2_ws/sros2_keystore/                        │
│  │  01/01b Permissive │  01c: 雙CA + 逐節點 permissions + Enforce         │
│  └────────────────────┘  （完整場景長時間回歸待補）                         │
│                                                                            │
│  Layer 2 — Application                                                     │
│  ┌────────────────────┐                                                   │
│  │ dds_security_      │  sub: ROS2 graph (poll 5s)                        │
│  │ monitor (節點偵測)   │  pub: /security/alerts  (HMAC 簽章)               │
│  │                    │       /security/heartbeat                          │
│  │                    │  → LINE notify (token from file)                   │
│  └────────────────────┘                                                   │
│                                                                            │
│  Layer 3 — Behavioral IDS                                                  │
│  ┌────────────────────┐                                                   │
│  │ intelligent_       │  sub: /cmd_vel /scan /odom /heartbeat              │
│  │ defense_node       │  6 個 detector (D1~D6) + voting (≥2)               │
│  │ (行為異常偵測)       │  pub: /security/alerts  (HMAC 簽章)               │
│  └────────────────────┘                                                   │
│                                                                            │
│  ╔══════════════════════════════════════════════════════════════════╗     │
│  ║                  狀態/任務管理（資訊聚合）                          ║     │
│  ╚══════════════════════════════════════════════════════════════════╝     │
│                                                                            │
│  ┌────────────────────┐  sub: /scan /imu                                   │
│  │ sensor_hub_node    │  pub: /sensor/status                               │
│  └────────────────────┘                                                   │
│                                                                            │
│  ┌────────────────────┐  sub: /sensor/status /alerts                       │
│  │ mission_manager    │  pub: /mission/cmd                                 │
│  └────────────────────┘                                                   │
│                                                                            │
│  ┌────────────────────┐  sub: /sensor/status /mission/cmd /alerts          │
│  │ system_status_node │  pub: /system/health                               │
│  └────────────────────┘                                                   │
│                                                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

## 2. Topic / QoS 一覽表

| Topic | Type | Publisher | Subscriber | QoS | 攻擊面 |
|---|---|---|---|---|---|
| `/scan` | LaserScan | ros_gz_bridge | burger_env, patrol, sensor_hub, IDS | BE, depth=10 | K |
| `/odom` | Odometry | ros_gz_bridge | burger_env, patrol, IDS | BE, depth=10 | (state poison) |
| `/cmd_vel` | TwistStamped | monitor / burger_env / patrol | ros_gz_bridge | depth=10 | C, J, N9 |
| `/security/alerts` | String (envelope v3) | monitor / IDS | patrol, mission, status | RELIABLE+VOLATILE | B, N3, N4 |
| `/security/heartbeat` | String (envelope v3) | monitor | IDS | RELIABLE+TRANSIENT_LOCAL | N1, N20 |
| `/patrol/goto` | String (envelope v3) | （外部委派） | patrol | depth=10 | D |
| `/patrol/reload` | Trigger srv | (外部) | patrol | service | L |
| `/sensor/status` | String (envelope v3) | sensor_hub | mission, status | depth=10 | N6 |
| `/mission/cmd` | String (envelope v3) | mission_manager | status | depth=10 | N7 |
| `/system/health` | String (envelope v3) | system_status | system_status self-watch / dashboard | depth=10 | N8, N13 |

**圖例**：BE = BEST_EFFORT；RELIABLE+VOLATILE = 可靠交付但不重送歷史

## 3. HMAC 簽章流向

```
所有 node 共用 ~/.config/dds-monitor/alert_secret (chmod 600)
啟動時印 secret_fingerprint(16 hex chars) → 互相比對

┌─────────────────┐ sign_alert(text, secret, channel=CH_*) ┌──────────────────┐
│ monitor_node    │ ─────────────────────────────▶│ /security/alerts │
│ IDS             │                                 └────────┬──────────┘
│ (publishers)    │                                          │
└─────────────────┘                                          │
                                                              │ HMAC-SHA256
                                                              │ JSON envelope v3:
                                                              │ {"body":"{channel,nonce,
                                                              │ payload,ts}","sig":"..."}
                                                              │
                              ┌───────────────────────────────┘
                              ▼
   ┌─────────────────┐  verify_alert(msg.data, secret)   ┌────────┐
   │ patrol_node     │ ─────────────────────────────────▶│ emergency
   │ mission_manager │  → None     (拒絕)                 │
   │ system_status   │                                    │
   │ (subscribers)   │                                    │
   └─────────────────┘                                    └────────┘

檔案完整性 (攻擊 I/M 修補):
   train_top.py save → atomic_save + sign_file → model.zip + .sha256.hmac
   train/eval/bench load → require_verified_artifact → 缺章/錯章預設拒絕
   replay buffer (pickle) → 無 legacy bypass，驗章前絕不反序列化
```

## 4. 紅隊攻擊面對應

```
攻擊 A (prefix bypass)        ──→ monitor_node._INTERNAL_PREFIXES
攻擊 B (alert forge)          ──→ HMAC sign_alert / verify_alert
攻擊 C (cmd_vel hijack)       ──→ IDS D1 (physics) + D4 (publisher)
攻擊 D (patrol/goto remote)   ──→ patrol_node._cb_goto: HMAC + ±2.5m 範圍
攻擊 H (LINE token leak)      ──→ ~/.config/dds-monitor/line_token (chmod 600)
攻擊 I (Pickle RCE)           ──→ train_top.py: sign_file/verify_file
攻擊 J (namesake)             ──→ IDS D2 (oscillation) + D4 (duplicate)
攻擊 K (scan poison)          ──→ burger_env._scan_cb 三重偵測 + IDS D4
攻擊 L (service flood DoS)    ──→ patrol_node._srv_reload: 5s rate limit + 預設關閉
攻擊 M (model swap)           ──→ HMAC sign_file/verify_file (同 I)
```

## 5. 攻防主線 / TQC 獨立軌啟動流程

### TQC 訓練（獨立未來工作軌）

```
$ source ~/dqn_env/bin/activate
$ source ~/ros2_ws/install/setup.bash
$ source ~/ros2_ws/工具腳本/load_ros_environment.sh   ← 白名單載入非秘密 ROS 設定；拒絕 token
$ export TURTLEBOT3_MODEL=burger

  Terminal A: ros2 launch dds_security_monitor gazebo.launch.py
  Terminal B: bash src/turtlebot3_dqn/turtlebot3_dqn/train_top.sh
  Terminal C: tensorboard --logdir src/turtlebot3_dqn/turtlebot3_dqn/runs_top/logs/tensorboard
```

### DDS 攻防主線（幾何巡邏）

```
  Terminal A: ros2 launch dds_security_monitor gazebo.launch.py
  Terminal B: ros2 run dds_security_monitor monitor_node    ← Layer 2
  Terminal C: ros2 run dds_security_monitor intelligent_defense_node  ← Layer 3
  Terminal D: ros2 run dds_security_monitor patrol_node
```

### TQC 評估（獨立軌，deterministic eval）

```
  Terminal A: ros2 launch dds_security_monitor gazebo.launch.py
  Terminal B: python3 src/turtlebot3_dqn/turtlebot3_dqn/eval_top.py \
                --episodes 20 --seed-base 42
```

---

## 6. 對外介面清單（Interface Inventory）= 攻擊面

> 教授指導：「系統有一些介面，那個介面都是弱點。威脅分析就從系統介面、對外的介面去談。」
> 本節列出全部對外介面，用於對應 [系統威脅分析.md](系統威脅分析.md) 的 T-01 ~ T-18 威脅編號。

### 6.1 介面類別總覽

| 類別 | 介面數 | 攻擊成本（無密鑰時） | 主要威脅編號 |
|---|---|---|---|
| DDS topic | 10 | 低（單一 ROS2 程式即可發布） | T-01 ~ T-09 |
| DDS service | 2 | 低（單一 service client 呼叫） | T-10、T-11 |
| ROS2 discovery | 1 | 低（啟動 node 即註冊） | T-12 |
| Linux 檔案系統 | 5 | 中（需 same-user write 權限） | T-13、T-14、T-15 |
| Linux process | 1 | 低（same-user 讀 `/proc`） | T-16 |
| 外部 HTTPS (LINE) | 1 | 中（需經由 alert 鏈觸發） | T-17 |
| 結構性介面（IDS→alert→pause） | 1 | 低（觸發偵測即可） | T-18 |

### 6.2 介面 → 軟體模組對應表

> 每行 = 一個介面 = 一個攻擊面。「發布模組」是合法擁有者。在 Permissive 模式，未授權程式可從同 DDS domain 冒充發布；Enforce 模式則由憑證與 permissions 限制，但完整 `01c` 回歸證據仍待補。

| 介面 | 訊息/服務型別 | 合法發布模組 | 訂閱/呼叫模組 | 簽章 | 威脅 |
|---|---|---|---|---|---|
| `/cmd_vel` | `TwistStamped` | `monitor_node` / `patrol_node` / `burger_env_top` | `ros_gz_bridge` | ❌ | T-01 |
| `/scan` | `LaserScan` | `ros_gz_bridge` | `patrol_node` / `burger_env_top` / `sensor_hub_node` / `intelligent_defense_node` | ❌ | T-02 |
| `/odom` | `Odometry` | `ros_gz_bridge` | `patrol_node` / `burger_env_top` / `intelligent_defense_node` | ❌ | T-03 |
| `/imu` | `Imu` | `ros_gz_bridge` | `sensor_hub_node` | ❌ | T-02 |
| `/security/alerts` | `String` (envelope v3) | `monitor_node` / `intelligent_defense_node` | 全部下游 | ✅ HMAC+ts+nonce+channel | T-04 |
| `/security/heartbeat` | `String` (envelope v3) | `monitor_node` | `intelligent_defense_node` | ✅ HMAC+ts+nonce+channel | T-05 |
| `/patrol/goto` | `String` (envelope v3) | （外部委派） | `patrol_node` | ✅ HMAC + 座標 ±2.5m | T-06 |
| `/sensor/status` | `String` (envelope v3) | `sensor_hub_node` | `mission_manager_node` / `system_status_node` | ✅ HMAC + channel | T-07 |
| `/mission/cmd` | `String` (envelope v3) | `mission_manager_node` | `system_status_node` | ✅ HMAC + channel | T-08 |
| `/system/health` | `String` (envelope v3) | `system_status_node` | `system_status_node` self-watch（log-only，不反射急停警報） | ✅ HMAC + channel | T-09 |
| `/patrol/reload` | service | （外部委派） | `patrol_node` | 預設停用 + 5s rate-limit | T-10 |
| `/<node>/set_parameters` | service (ROS2 內建) | 任意 client | 全部模組 | 敏感參數 `read_only=True` | T-11 |
| ROS graph | DDS discovery | 任意註冊的 node | `monitor_node` poll | baseline+grace 機制 | T-12 |
| `~/.config/dds-monitor/alert_secret` | 檔案 (HMAC 密鑰) | （安裝時寫入） | 全部簽章模組 read | chmod 600 (out-of-scope) | T-13 |
| `~/.config/dds-monitor/line_token` | 檔案 (LINE token) | （安裝時寫入） | `monitor_node` read | chmod 600 (out-of-scope) | T-13 |
| `runs_top/models/*.zip` | 檔案 (模型權重) | `train_top.py` | `train_top.py` / `eval_top.py` load | ✅ `.sha256.hmac` | T-15 |
| `runs_top/models/*.pkl` | 檔案 (replay buffer) | `train_top.py` | `train_top.py` load | ✅ `.sha256.hmac` | T-14 |
| `/proc/<pid>/environ` | Linux /proc | （行程啟動時） | （任何 same-user read） | 移除 export | T-16 |
| LINE 推播管線 | HTTPS POST | `monitor_node` | LINE Notify endpoint | 30s batch + leading-edge | T-17 |
| IDS → alert → pause 結構 | （非單一介面） | `intelligent_defense_node` | `patrol_node` | resume timer 不 reset + cascade quiet window | T-18 |

### 6.3 攻擊敘事公式

每個介面的攻擊情境統一以下格式描述（詳見 [系統威脅分析.md §4](系統威脅分析.md)）：

```
未授權程式（rogue process）
     │
     ▼  透過 介面 X（DDS topic / service / file）
受害軟體模組（receiver module）
     │
     ▼  進入錯誤狀態（誤判存活 / 接受偽訊息 / load 惡意檔）
下游軟體模組鏈（downstream cascade）
```

**情境不寫人**。攻擊方是程式，受害方是命名的軟體模組，傳遞媒介是上述介面。
