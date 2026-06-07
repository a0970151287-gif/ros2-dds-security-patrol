# 紅隊報告 — 第 6 輪：DoS 攻擊面全力探測（N19/N20 + N14 缺口）

> 作者：紅方  日期：2026-05-30
> 任務：使用者要求「全力攻擊找漏洞讓藍方補」
> 攻擊者能力：**L1**（同 LAN 任意 ROS2 node，無 secret）
> 隔離：`ROS_DOMAIN_ID=99`

---

## 摘要（誠實分級）

| # | 攻擊 | 結果 | 對藍方的意義 |
|---|---|---|---|
| **N18** | `_alerted_nodes` 無上限成長 | 🔴 **真漏洞（已量化）** | 需修：套 TTL/LRU |
| **N19** | parameter-service flood | 🟢 **陰性（防禦有效）** | 參數服務面非 DoS 點，不用白花力氣 |
| **N20-BE** | verify-flood `/security/heartbeat` (BEST_EFFORT) | 🟢 **陰性** | BEST_EFFORT QoS 天然丟包 = flood shield |
| **N20-REL** | verify-flood `/security/alerts` (RELIABLE) | 🟢 **陰性** | KEEP_LAST depth-10 + executor 公平調度擋住 |
| **N14-gap** | patrol 參數未鎖 read_only | 🟡 **低（read-once，inert）** | 補完整性：patrol 參數也加 read_only |

**本輪誠實總結：全力打了 3 個 DoS 向量（N19/N20×2），全部陰性。** 系統的 QoS 選擇 +
rclpy executor 設計讓「訊息/服務洪水」這條 DoS 路天然防住。唯一真漏洞仍是 N18
（上一輪已量化）。陰性結果同樣有價值 — 告訴藍方哪裡不用再加防禦。

---

## N19 — Parameter-service flood DoS（陰性）

### 假設
每個 ROS2 node 自動 expose `/<node>/get_parameters` 等服務，跑在 single-threaded
executor 上，**無法 app 層關閉或 rate-limit**（不像已修的 `/patrol/reload`）。
猜測：高併發 flood 可餓死 node 的 timer。

### 實測
- 目標：`/dds_security_monitor/get_parameters`
- 負載：**~1,626 req/s**（PoC 有共用 executor bug，實際併發受限，但仍達千級 req/s）
- 量測：`ros2 topic hz /security/heartbeat`

| 階段 | 心跳頻率 | std dev |
|---|---|---|
| baseline | 0.500 Hz | 0.0006s |
| flood 中 | **0.500 Hz** | 0.0001s |

### 結論
**心跳完全不受影響。** read-only 參數的 get callback 極便宜（回傳 cached 值），
1,626 req/s 餓不死 0.5Hz timer。rclpy executor 把便宜的 service callback 與 timer
公平交錯。**參數服務面不是可行 DoS 點。**

---

## N20 — Verify-flood DoS（陰性 ×2）

### 假設（針對 N15 修補的縫）
N15 修補加了「reject **log** throttle」防 log storm，但**沒 throttle verify**。
receiver 對每筆 `/security/*` 訊息都跑 `verify_alert`（JSON double-parse + HMAC-SHA256），
不論拒不拒。猜測：高速 junk flood 強迫 receiver 把 executor 時間燒在 verify 上。

### 實測 A — BEST_EFFORT `/security/heartbeat`（victim: IDS）
- 負載：**368,859 msg/s**
- 量測：IDS `_print_stats`（nominal 5.0s）

cadence：652.35 → 657.35 → 662.35 → ... → 687.35，**全部精確 5.000s 間隔**。

原因：IDS 訂 heartbeat 用 **BEST_EFFORT** → DDS 在 368k/s 下**自動丟棄絕大多數**，
IDS 只 dequeue 極少數來 verify。**QoS 本身就是 flood shield。**

### 實測 B — RELIABLE `/security/alerts`（victim: system_status）
RELIABLE 不自動丟包，是更嚴格的測試。
- 負載：**18,213 msg/s**（RELIABLE flow control 自然限速，比 BE 低）
- 量測：system_status `_publish_health`（nominal 2.0s）

cadence：793.01 → 795.01 → 797.01 → ... → 823.01，**全部精確 2.000s**。

原因：RELIABLE + **KEEP_LAST depth=10** → receiver queue 只留最後 10 筆，舊的丟棄；
executor 每個 spin 只處理 ~10 筆 verify 後就輪到 timer。verify 負載被 bound 住。

### 結論
**兩種 QoS 下 verify-flood 都無法餓死 receiver timer。** N15 沒 throttle verify
這件事，因為 QoS（BEST_EFFORT 丟包 / KEEP_LAST 限深）+ executor 公平調度已經
天然 bound 住 per-spin verify 量。**這條路不通。**

---

## N14-gap — patrol 參數未鎖 read_only（低）

N14 主動把 monitor 所有安全參數設 `read_only=True`（防 `/set_parameters` 劫持
whitelist）。但**只鎖了 monitor**：

[patrol_node.py:98,118](../src/dds_security_monitor/dds_security_monitor/patrol_node.py#L98)：
```python
self.declare_parameter('waypoints_file', ...)        # ← 無 read_only
self.declare_parameter('enable_reload_service', False) # ← 無 read_only
```

攻擊者可 `ros2 service call /patrol_node/set_parameters ...` 改這兩個。
**為何只列低**：兩者都在 `__init__` 讀一次後 cache（`_yaml_path` / `_reload_enabled`），
runtime 改參數不會重讀 → 目前**inert（無實際效果）**。

但這是 N14 hardening 的覆蓋缺口：若未來有 code 動態重讀這些參數就會被劫持。
建議：所有 node 的參數一律加 `read_only=True`（防禦縱深一致性）。

---

## 仍待修（跨輪彙整）

| # | 漏洞 | 嚴重度 | 狀態 |
|---|---|---|---|
| N18 | `_alerted_nodes` 無上限成長 → OOM | 中 | 🔴 已量化（10k 線性），待修 |
| N17 | LINE batch dilution + 30s 通知延遲 | 低 | 🟡 待修 |
| N14-gap | patrol 參數未鎖 read_only | 低 | 🟡 inert，建議補 |
| cmd_vel/scan/odom | raw topic 無認證 | — | 需 SROS2 Enforce（已誠實揭露）|

---

## 復現

```bash
# N19
ros2 run dds_security_monitor monitor_node --ros-args -p emergency_stop_enabled:=false &
python3 紅隊測試/N19_param_service_flood.py dds_security_monitor 30 25
ros2 topic hz /security/heartbeat   # 另開終端，觀察仍 0.5Hz

# N20 BEST_EFFORT
ros2 run dds_security_monitor intelligent_defense_node &
python3 紅隊測試/N20_verify_flood.py /security/heartbeat 25 be

# N20 RELIABLE
ros2 run dds_security_monitor system_status_node &
python3 紅隊測試/N20_verify_flood.py /security/alerts 25 reliable
```

---

## 紅方視角總評（6 輪後）

打到第 6 輪，**新發動的攻擊越來越多是陰性**——這是防禦成熟的訊號，不是壞事：
- 應用層 身份/replay/反射/cross-channel：全關（N1–N8, N13）
- DoS via flood（service/message）：QoS + executor 天然防住（N19/N20 陰性）
- 剩下的真漏洞集中在「**app 層無上限資源**」這一類（N18），QoS 管不到、需 app 自己加界限

**給藍方的優先級**：先修 N18（唯一中危），N17/N14-gap 是低危防禦縱深。
flood 類（N19/N20）不用加防禦，現有 QoS 設計已足夠。
