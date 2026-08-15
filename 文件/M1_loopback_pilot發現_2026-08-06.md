# M1 loopback live pilot：發現與待決事項

日期：2026-08-06
範圍：本機 loopback、`ROS_LOCALHOST_ONLY=1`、SROS2 Enforce、ROS domain 30。
全程無封包離開主機，符合 [`專題執行基準_2026-07-29.md`](專題執行基準_2026-07-29.md) §5。

## 一、結論

`live_multimodal_contract` 仍為 `blocked`，但四個 blocker 中已解決兩個，
並找出第三個的**確切技術原因**。原因不是設定問題，而是
`features.py` 與 ROS 端 producer 使用了**兩套不同的事件詞彙**。

## 二、已完成

### blocker 2：SROS2 deny 模式校準（完成）

| 驗證層級 | 修正前 | 修正後 |
|---|---:|---:|
| 安裝版 `libfastrtps.so.2.14.5` 抽出的真實字串 | 5/28（17.9%） | **28/28** |
| 真實 runtime 拒絕訊息 | 0/2 | **2/2** |
| benign 行誤報 | 0 | 0 |

Fast DDS 多數安全失敗以 `Error …`／`Cannot …`／`Unable to …`／`Not found …`
表述，舊 regex 只認 deny/reject/fail/invalid，因此
`sros_auth_fail_rate`、`sros_permission_deny_rate` 在 live 資料中會近乎恆為 0。
分類順序也已修正：governance 必須先於 authentication，否則
`allow_unauthenticated_participants … rtps_protection_kind` 會被誤判。

### keystore 與政策漂移（修復並加上防再犯機制）

2026-08-03 canonical 政策、稽核腳本、setup 腳本同時更新（mtime 皆
`15:27:45`），新增 `security/heartbeat` 與 `local_outcome_probe`，但 keystore
仍停在 07-27。Enforce 因此在執行期拒絕 `velocity_guard_node` 訂閱
`/security/heartbeat`，節點崩潰、supervisor 拆掉整組，
**Enforce stack 完全起不來**——而結構稽核仍報 47/47。

- 已以 `ros2 security create_permission` 外科式重產 12 個 enclave 權限；
  identity CA、permissions CA 與各節點身分憑證指紋均未變動。
- 新增 [`工具腳本/check_keystore_policy_drift.py`](../工具腳本/check_keystore_policy_drift.py)
  並接入稽核；以 **enclave**（非 node 名）為單位聚合，因為 `/gazebo` 承載
  4 個 node、`/mission_manager` 的 node 名為 `mission_manager_node`。
- 已用修復前的備份驗證檢查器會抓到該漏授權；另加 4 個 pytest 回歸測試。

### localhost-only 與 Enforce 相容性（確認可行）

`01c_啟動系統_enforce.sh` 註解記載「Enforce 與 SHM profile 不相容」，一度
使人懷疑 localhost-only 也不可行。實測結果相反：

```
keystore 修復前： ready=0，240s 逾時
keystore 修復後： ready=1，35s，8 個 supervised process
```

`ROS_LOCALHOST_ONLY=1` 僅產生 Jazzy 棄用警告（建議改用
`ROS_AUTOMATIC_DISCOVERY_RANGE`），節點發現、Gazebo readiness、巡邏行為
全部正常。**§5 合規的 loopback 實驗路徑成立。**

### 平台限制：Unix socket 不能建在 `/mnt/c`

`firewall_lab/live_runtime/` 實際位於 WSL2 的 9p 掛載，
`bind()` 回傳 `OSError [Errno 95] Operation not supported`，
telemetry collector 因此永遠無法啟動。原生 ext4 對照組正常。

**解法**：`FIREWALL_LIVE_RUNTIME` 指向原生路徑（例如
`~/.local/share/sros2-firewall/live_runtime`），與 SROS2 keystore 已採用的
做法一致。`live_stack.sh` 與 `orchestrator.py` 都支援此環境變數。
資料集本身留在 `/mnt/c` 無妨，只有 socket 受限。

## 三、pilot 實際產出

兩個 session 均 `status=complete`、`training_eligible=true`：

| session | 事件數 | 事件型別 |
|---|---:|---|
| `normal_patrol` | 1,122 | collector_tick 45、message_validation 222、guard_output 407、guard_input 221、hmac_result 204、authenticated_action 23 |
| `unauthorized_participant` | 501 | 上列各型別 + detector_state 3 |

來源涵蓋 6 個節點：`sensor_hub_node`、`velocity_guard_node`、
`system_status_node`、`mission_manager_node`、`intelligent_defense_node`
及 `telemetry_collector`。**blocker 3（same-UID 來源歸屬）與 blocker 4
（collector ticks + runtime events）在資料層已得到證據。**

## 四、⛔ 尚未解決：features.py 與 producer 事件詞彙不一致

以 AST 驗證（第一次用 regex 分析曾誤判 `sros2_deny`，已更正）：

| 角色 | 事件型別數 |
|---|---:|
| ROS producer 可發出 | 18 |
| collector 接受 | 33 |
| `features.py` 處理 | 21 |

- **producer 與 collector 完全一致**：producer 能發的 18 種，collector 全部接受（差集為 0）。
- **`features.py` 處理的 21 種裡，有 14 種沒有任何 producer 會發出**：
  `alert_observation`、`control_observation`、`heartbeat_observation`、
  `hmac_validation`、`log_reject`、`odom_cmd_observation`、`parameter_call`、
  `participant_change`、`publisher_observation`、`qos_delivery`、
  `scan_observation`、`sros_auth_failure`、`sros_permission_denied`、
  `unknown_node`。
- **producer 會發、collector 接受、但 `features.py` 直接拋錯的有 12 種**，
  其中 3 種在本次 pilot 就出現：`guard_input`、`guard_output`、
  `authenticated_action`。

因為 `features.py` 對未知型別是 fail-closed，live session 的 feature 建構
在第一個 `guard_input` 就中止：

```
SchemaError: unsupported telemetry event_type: guard_input
```

因此 `telemetry_features.csv` 與 `fusion_features.csv` **尚未產生**，
契約第 3、4 項未達成。

`sros2_deny` 本身三方一致（producer→collector→features），路徑完整。

## 五、已採方案：先 2 後 1

依決議先做「白名單跳過」讓管線跑通，再逐項做語意對齊。

已在 `features.py` 新增 `NON_FEATURE_TELEMETRY_EVENTS`（12 個型別），
對真正未知的型別仍 fail-closed。三項回歸測試固定此行為，並確保白名單
只涵蓋 collector 確實接受的型別——否則會把 producer／collector 的 schema
破裂藏在 feature builder 後面。

結果：三個 CSV 全部產出，且 session／window 對齊完全正確。

```
✅ session=2  network=2  telemetry=2  fusion=2  skipped=0
network_features.csv    rows=2  cols=30   14 個 network 欄位齊全
telemetry_features.csv  rows=2  cols=34   18 個 telemetry 欄位齊全
fusion_features.csv     rows=2  cols=48   32 個 fusion 欄位齊全
network == telemetry keys : True
fusion   == network   keys : True
```

契約的四項要求在**機制上**已全部達成。

## 六、⛔ 但契約仍必須維持 blocked：三個實證發現

### 6.1 18 個 telemetry 特徵全部為 0

pilot 蒐集到 1,623 個事件、涵蓋 6 個節點來源，但實際算出來的
telemetry 特徵值是：

```
carrying signal : 0/18
all-zero        : 18/18
```

欄位存在不等於有訊號。目前有來源的事件（`hmac_result`、
`message_validation`、`detector_state`）在正常運作下本來就不會產生失敗計數，
而 14 個會產生訊號的型別沒有任何 producer。

### 6.2 每個 session 只產出 1 個 window，且永遠是 session 開頭

`features.py:786` 以 network rows 決定 window 集合，而 network window 來自
Zeek `conn.log` 的**連線起始時間**。DDS 使用長壽命 UDP flow：所有 participant
在 session 開始時建立連線，Zeek 每個 flow 只記一筆，之後的流量不再產生新記錄。

實測：

| session | 實際時長 | conn 記錄 | conn 時間跨度 | 產出 window |
|---|---:|---:|---:|---:|
| `normal_patrol` | 46.7s | 67 | **2.7s** | 1 |
| `unauthorized_participant` | 22.3s | 76 | **7.4s** | 1 |

### 6.3 因此本次 pilot 產出 0 個攻擊標籤 window

manifest 與 `labels.jsonl` 都正確（`attack_class=identity_abuse`、
`binary=attack`），但唯一產出的 window 0 落在攻擊開始前的 warmup，
因此正確地標成 `normal`。

**對 1,100-session campaign 的意涵**：照目前的 windowing，會得到約 1,100 個
window、幾乎全部標籤為 `normal`、且 telemetry 區塊整片為 0。這樣的資料集
無法做監督式學習，也無法回答 RQ1／H1。

> 對照：2026-07 的 20-session pilot 得到 80 個 window（每場 4 個）。當時擷取
> 介面與流量結構不同；本次為 loopback + localhost-only，distinct flow 少很多。
> 兩者差異本身也說明 windowing 對擷取條件過度敏感。

## 七、step 1 已完成的部分：windowing 修復

### 7.1 根因不是接線，是 Zeek 的 UDP flow 逾時

複查後更正 §6.1 的初步判讀：`features.py` **早已正確接好**真實 producer
事件（`hmac_result` → nonce/channel/timestamp、`detector_state` d1–d6 →
control/scan/publisher/odom、`graph_state` → log_reject、
`message_validation` → oversized、`sros2_deny` → auth/permission）。
§4 所列的 14 個「無 producer 型別」多為**冗餘舊路徑**，不是缺功能。

真正的原因是 Zeek 只在 UDP flow 靜默逾時後才寫一筆 conn 記錄，且時間戳為
flow 的**第一個封包**。DDS participant 的 flow 整場不關閉，預設 60 秒逾時下
整場塌縮成 window 0。實測攻擊 session：

```
window 0  = [...600.723, ...608.723)
攻擊標籤   = [...604.528, ...616.537]   與 w0 重疊 4.19s
w0 內事件  = 204 個，全部良性（hmac 全 accepted、oversized=0）
detector_state: 3  ← 唯一攻擊訊號，落在 w0 之外被丟棄
```

### 7.2 修法與依據

以封包時間戳作為 ground truth，對同一批 PCAP 掃描不同逾時值：

| `udp_inactivity_timeout` | normal_patrol | attack | 封包推導真值 |
|---|---:|---:|---:|
| 60s（預設） | 1 | 1 | 6 / 3 |
| 30s | 3 | 1 | |
| 10s | 4 | 3 | |
| **5s（採用）** | **6** | **3** | ✅ 完全吻合 |
| 2s | 6 | 3 | conns=1005＝封包數，退化為 per-packet |

選 5 秒的理由：必須**小於 8 秒的特徵窗**，才能保證任何仍在傳輸的 flow 會在
該窗內被重新記錄；同時不能小到讓每個封包各成一筆，否則會摧毀 14 個 network
特徵與 90,000 列合成預訓練集所依賴的「連線」語意。

改動處：`orchestrator.py` 新增 `ZEEK_UDP_INACTIVITY_TIMEOUT_SEC = 5` 並傳入
`zeek -e`；`blue_team_capture.sh` 同步，避免同一份 PCAP 因執行者不同而產生
不同的 window 數。三項回歸測試固定此不變式。

### 7.3 修復後結果

| 指標 | 修復前 | 修復後 |
|---|---:|---:|
| 總 window 數 | 2 | **9** |
| 攻擊標籤 window | **0** | **1**（`identity_abuse`，192 事件） |
| network 特徵跨窗有變異 | — | **9/14** |
| telemetry 帶訊號特徵 | 0/18 | **1/18**（`control_conflict_ratio` = 0.5, 1.0） |

`conn_count` 逐窗為 `[136,110,79,136,101,79,142,122,33]`，不再是單一值。

### 7.4 其餘 17 個特徵為 0 的原因已釐清

大多是**語意正確的 0**：本次兩個情境本來就沒有觸發那些條件（HMAC 全部驗章
通過、無超長訊息、無 heartbeat gap、無 graph fault、無 SROS2 拒絕）。

但有 **5 個特徵確實沒有任何 live producer**，與情境無關：
`participant_churn_rate`、`unknown_node_rate`、`parameter_call_rate`、
`qos_drop_ratio`、`alert_reflection_ratio`。

## 八、step 1 第二部分：補上缺失的 producer

§7.4 指出 5 個特徵與情境無關地沒有來源。已為其中 4 個建立 live producer：

| 特徵 | 新事件 | 發射者 | 資料來源 |
|---|---|---|---|
| `participant_churn_rate` | `participant_change` | `monitor_node` | `_check_graph` 既有的 `new_nodes` ∪ `exited_nodes` |
| `unknown_node_rate` | `unknown_node` | `monitor_node` | 同上，非白名單節點數 |
| `parameter_call_rate` | `parameter_call` | `monitor_node` | `lock_sensitive_params` 的 `_veto` hook（所有 set 嘗試，不只被否決的） |
| `alert_reflection_ratio` | `alert_observation` | `system_status_node` | N8/N13 self-watch：被拒的未簽章／重放／cross-channel 訊息即反射嘗試 |

四處都以 `getattr` 動態分派 + `try/except` 包裹，維持既有慣例——證據蒐集
永遠不得干擾偵測或否決路徑本身。

### 8.1 為何 live pilot 無法單獨證明接線正確

重跑後 `alert_observation` 確實出現（23 / 10 筆），但
`alert_reflection_ratio` 仍為 0——因為所有 health 訊息都正確簽章，
`reflection_count=0`，**比值 0 是語意正確的**。`participant_change`、
`unknown_node`、`parameter_call` 則完全未出現，因為乾淨 session 裡沒有節點
進出、沒有參數設定呼叫。

也就是說：**接線正確與接線損壞，在乾淨 session 上看起來一模一樣。**
因此改用離線測試直接驅動 accumulator，證明每個特徵在對應事件存在時會離開
0、在空窗時回到 0。

### 8.2 附帶發現：Enforce 讓攻擊者對 ROS graph 隱形

`unauthorized_participant` 情境未產生任何 `participant_change` 或
`unknown_node`。原因是無憑證攻擊者建立的是**獨立的非安全 participant**，
根本無法加入受保護的 DDS domain，因此 `monitor_node` 的
`get_node_names_and_namespaces()` 從頭到尾看不到它。

這與 §六「pilot 未觀察到任何 SROS2 拒絕」是同一個現象的兩面：
**Enforce 在 discovery 層就靜默隔離攻擊者，不留下可觀測痕跡。**
對 ML 的意涵是：`unknown_node_rate`、`participant_churn_rate`、
`sros_auth_fail_rate`、`sros_permission_deny_rate` 這四個特徵在
**Enforce 模式下對外部攻擊者可能全部恆為 0**，只有在 Permissive 模式或
攻擊者持有合法憑證（內部威脅）時才有訊號。正式資料收集前必須確認這點，
否則 Enforce 組的 telemetry 區塊會比預期稀疏得多。

## 九、`qos_delivery`：最後一個 producer 已補上

`sensor_hub_node` 的 `/scan`、`/imu` 使用 BEST_EFFORT QoS，正是 DDS 丟包會
出現的地方。已透過 rclpy 的 `SubscriptionEventCallbacks(message_lost=…)`
安裝 QoS 事件，於既有的 1 秒狀態 timer 上發出
`qos_delivery(expected_count=delivered+lost, delivered_count=delivered)`。

關鍵細節：`QoSMessageLostInfo.total_count` 是**訂閱生命週期的累計值**，
直接使用會讓每個後續 window 繼承先前所有丟包、使 `qos_drop_ratio` 單調膨脹。
因此只取 `total_count_change`（增量），並在每次回報後歸零計數器，
讓每個 window 各自獨立。回歸測試固定此不變式。

live pilot 確認 `qos_delivery` 實際發出（45 / 20 筆）。

**至此 18/18 telemetry 特徵皆有 live producer。**

## 十、目前狀態總結

| 項目 | 狀態 |
|---|---|
| windowing | ✅ 已修（Zeek UDP timeout 5s） |
| 攻擊標籤 window | ✅ 0 → 1 |
| 18 特徵的 live producer | ✅ **18/18** |
| 事件→特徵接線 | ✅ 離線測試逐項證明 |
| 契約機制面 4 項欄位檢查 | ✅ 全通過 |
| 契約 4 個宣告 blocker | ✅ 字面上皆已達成 |
| `live_multimodal_contract` | **仍維持 `blocked`** |

### 為何仍不翻成 `validated`

翻牌會授權 1,100 場正式收集，但以下四點會讓那批資料出問題：

1. **9 個情境只跑過 2 個**：另外 7 個攻擊 runner 從未 live 執行。
2. **攻擊 window 產出率過低**：攻擊情境 20s + warmup/cooldown → 3 個 window，
   攻擊區間僅蓋到 1–2 個。推到 800 場攻擊 session ≈ 1,000 個攻擊 window，
   分散到 8 類、再經 session-grouped 切分後，**test 每類僅約 19 個 window**，
   做不出可信的 per-class 指標或 95% CI。建議把攻擊 `duration_sec`
   從 12–20s 拉長到 ≥40s。
3. **Enforce 下 telemetry 可能極稀疏**（見 §8.2）：`unknown_node_rate`、
   `participant_churn_rate`、`sros_auth_fail_rate`、`sros_permission_deny_rate`
   對外部攻擊者恆為 0。若 550 場 Enforce 資料的 telemetry 幾乎全零，
   H1（fusion 優於 network-only）在 Enforce 組不可能成立。
4. **pilot 的 17/18 特徵為 0 是語意正確的**（系統健康、無攻擊觸發），
   但這代表尚未驗證「攻擊發生時特徵確實會動」的 live 證據；
   目前只有離線測試證明路徑可通。

### 建議的翻牌條件

1. 9 個情境各跑過至少 1 場 live，標籤正確。
2. 攻擊情境 duration 調整後，每場產出 ≥3 個攻擊 window。
3. 至少一場 live 攻擊 session 讓 ≥3 個 telemetry 特徵離開 0。
4. 確認 Permissive 組能補上 Enforce 組缺的 telemetry 訊號。

## 十一、攻擊情境 duration 調整（已完成）

### 11.1 窗口模型先以 pilot 反推驗證

特徵以 window 中點的標籤決定歸屬，window 寬 8 秒、自 session 的網路 t0 起算，
攻擊區間為 `[warmup, warmup+duration]`。

> pilot 實測：duration=12、warmup=5 → 區間 [5,17]，窗中點 4/12/20，
> 只有 12 落入 → **1 個攻擊窗**。與實際觀測完全一致，模型成立。

依此模型把 8 個攻擊情境的 `duration_sec` 統一提高到 **40 秒**
（`normal_patrol` 維持 30 秒，其正常窗本來就充足）：

| 情境 | 舊 duration | 新 duration | 舊攻擊窗 | 新攻擊窗 |
|---|---:|---:|---:|---:|
| unauthorized_participant | 12 | 40 | 1 | 5 |
| cmd_vel_injection | 15 | 40 | 2 | 5 |
| sensor_status_spoof | 15 | 40 | 2 | 5 |
| parameter_tamper | 8 | 40 | 1 | 5 |
| oversized_scan | 10 | 40 | 1 | 5 |
| parameter_flood | 12 | 40 | 1 | 5 |
| heartbeat_replay | 15 | 40 | 2 | 5 |
| alert_replay | 15 | 40 | 2 | 5 |

### 11.2 先確認每個 runner 真的會持續整段時間

`orchestrator` 把整個 `[attack_start, attack_end]` 階段標成攻擊區間，
**與攻擊程序是否仍在動作無關**。因此若 runner 提早結束，拉長 duration 只會
把安靜流量標成攻擊，等於污染資料集。逐一檢查 7 個 runner：

- 6 個（N9／N6／N24／N19／N1／N3）都有 `deadline` 時間迴圈 → 安全。
- `unauthorized_participant` 使用 `demo_nodes_cpp talker`，持續到被終止 → 安全。
- **`parameter_tamper`（N14）原本是 one-shot**：呼叫一次、sleep 1 秒即結束。
  若直接把 duration 拉到 40 秒，約 34 秒的正常流量會被標成 `parameter_tamper`。

因此為 N14 加上可選 duration 參數與重試迴圈（不給參數時維持原本單次行為，
向後相容）。攻擊者反覆嘗試竄改參數本來也比單次更接近真實行為。

另外必須處理終止時序：orchestrator 在 duration 到期時送 SIGTERM，rclpy 的
context 會在迴圈中途失效，第一版因此拋出 `RCLError` traceback，使該 session
被判為 `training_eligible=false`（verifier 明訂攻擊器不得含 traceback）。
已加入 signal handler 與 `RCLError` 攔截，讓正常收尾不再是錯誤。

### 11.3 實測結果

`parameter_tamper` live session：

```
攻擊窗 5 個（window 1–5，各 202–216 個 telemetry 事件）
正常窗 2 個
training_eligible = True
```

**模型預測 5、實測 5。**

### 11.4 對正式 campaign 的影響

| 指標 | 調整前 | 調整後 |
|---|---:|---:|
| 攻擊窗總數 | ~1,000 | **4,000** |
| 每攻擊類別 | ~125 | **500** |
| **15% grouped test 每類** | **~19** | **75** |
| 純執行時間 | 8.8 h | 14.8 h |
| 含開銷（+30s/session） | ~17 h | 24 h（分兩批各約 12 h） |

test 每類從 19 提升到 75，才有機會做出可信的 per-class precision／recall
與 95% CI。代價是 campaign 從約 1 個晚上變成 2–3 個晚上，以 2027-05-31 的
時程來看完全可承受。

`scenarios.json` 變更後 catalog 雜湊改變，已重新產生 `campaign_1100.json`
（新雜湊 `c9caf580…`，1,100 筆 pending，Permissive／Enforce 各 550 平衡）。

### 11.5 附帶佐證：Enforce 下 parameter_call_rate 仍為 0

`parameter_tamper` 攻擊確實執行了，但 `parameter_call_rate` 維持 0，因為
Enforce 下攻擊者連 `/dds_security_monitor/set_parameters` 都呼叫不到，
`lock_sensitive_params` 的 `_veto` 回呼從未觸發。這與 §8.2 是同一現象，
也直接說明 **RQ3 有真實可測的差異**：同一個攻擊在 Permissive 與 Enforce 下
會在 telemetry 留下截然不同的痕跡。

## 十二、⛔ Permissive 在同機 loopback 下無法產生網路資料（未解決）

### 12.1 現象

9 個情境全部在 Permissive 下 live 執行成功（事件數 4,000–6,300，遠高於
Enforce 的約 1,300，攻擊確實打進系統），但**每一場的 PCAP 都是 432 bytes**
——只有 pcapng 檔頭，一個封包都沒有。Zeek 因此無資料，9/9 皆
`not_eligible:zeek`。

```
Enforce   （lo，同一 filter）：1,853,772 / 2,438,460 bytes
Permissive（lo，同一 filter）：      432 bytes  × 9
/dev/shm/ 內有數十個 fastrtps 共享記憶體段
```

### 12.2 根因與兩層後果

`ROS_LOCALHOST_ONLY=1` 會讓 Fast DDS 在同機時偏好**共享記憶體**；Enforce 因
DDS Security 被迫走 UDP，Permissive 則留在 SHM。實測：

| 組合 | lo 上的封包 |
|---|---:|
| localhost_only（有無 profile 皆同） | 空 |
| 移除 localhost_only | 有封包 |

後果有兩層，第二層更嚴重：

1. 正式 campaign 的 **550 場 Permissive 會全部不可訓練**，RQ3／H4 的成對
   比較無法進行。
2. **傳輸方式本身完美編碼實驗組別**：「有沒有 UDP 封包」就能 100% 分辨
   Permissive 與 Enforce，完全不必看攻擊行為。模型會學到安全模式而非攻擊，
   正是 RQ3 要排除的洩漏。

### 12.3 已嘗試並否決的修法：UDPv4 + interfaceWhiteList

曾加入 `fastdds_udp_only.xml`（UDPv4-only、`useBuiltinTransports=false`、
`interfaceWhiteList` 127.0.0.1）並接進 Permissive stack 與攻擊者環境。

初步量測看似成功（eth1 上 0 個 DDS 封包），但進一步驗證推翻了它：

```
talker -> listener 實際收到的訊息（12 秒）
  loopback-whitelisted profile : 0     ← DDS 根本不通
  ROS_LOCALHOST_ONLY=1         : 23
  無 profile                    : 22
```

**「沒有外洩」是因為 discovery 被打斷，不是因為流量被侷限。** 這比未修更
危險，已完整撤除（profile 檔、stack 接線、攻擊者環境、相關測試）。

過程中另有兩個量測教訓值得記下：

- 第一次的 eth0 量測回報 0，但當時 eth0 已不存在（WSL 改為 eth1），
  該讀數不具意義。之後所有介面量測都加上**正向對照**，確認擷取本身可用，
  否則「零封包」無法區分「成功限制」與「量測失敗」。
- Fast DDS 對格式錯誤的 profile **靜默退回預設**：XML 註解中一個 `--`
  就讓整份設定失效而毫無警告。已加入 XML 可解析性測試（該測試隨 profile
  一併移除，未來若重新引入 profile 必須恢復）。

### 12.4 目前狀態與下一步

現況是**安全但未修好**：Permissive 仍走 SHM，沒有任何封包離開主機，
但也仍然採集不到網路資料。

已選定的方向是在 WSL 內建立隔離虛擬網路（network namespace + veth），
讓 Permissive 能使用真實 UDP 又不接觸共用網段。這需要 root 權限，
待使用者授權後執行。

### 12.5 根因與解法：WSL 的 mirrored 網路模式

介面在同一天內從 `eth0 10.1.200.52` 變成 `eth1 10.1.200.21`、再變成完全消失。
`wsl --shutdown` 時 WSL 回報了原因：

```
CreateInstance/CreateVm/ConfigureNetworking/0x8007054f
networkingMode Mirrored → 回退到 networkingMode None
```

`.wslconfig` 設定的 `networkingMode=mirrored` 初始化失敗。而 mirrored 模式
**讓 WSL 直接共用 Windows 主機的網卡與 IP**——這正是整條問題鏈的源頭：
DDS 流量因此落在共用的 `10.1.0.0/16` 上，才需要 `ROS_LOCALHOST_ONLY` 去擋，
才退化成 SHM，才採集不到封包。

已改為 NAT（備份 `.wslconfig.bak-20260806`）：

```
mirrored：與主機共用網卡 → DDS 直接出現在 10.1.0.0/16
NAT     ：eth0 172.30.123.103/20 → 私有虛擬網段，multicast 不穿越 NAT
```

實測 NAT 模式無功能損失：Windows 經 `localhost` 存取 WSL 服務正常
（HTTP 200）、DNS 正常、對外 TCP 正常。

### 12.6 對滲透測試安全邊界的影響

[`專題執行基準_2026-07-29.md`](專題執行基準_2026-07-29.md) §5 禁止在共用網段
測試，理由是「`10.1.200.52/16` 位於共享 `10.1.0.0/16` 網段，不符合隔離條件」。

**改用 NAT 後這個前提已經改變**：WSL 不再位於共用網段，而是在 Windows NAT
後方的私有 `172.30.112.0/20`。DDS 的 multicast discovery 不穿越 NAT，因此
同機／loopback 的 DDS 實驗流量在物理上到不了 `10.1.0.0/16`。

這**不等於**可以開始對外滲透測試——對外的單播仍會經 NAT 送出，而且真正的
跨主機驗收仍需第二台實體設備。但它確實移除了「同機 DDS 實驗會污染公司網段」
這項風險。

授權範圍必須重發，且需由使用者確認下列值後生效：

```
舊（已失效）  TARGET_IP = 10.1.200.52     eth0，共用 10.1.0.0/16
新            TARGET_IP = 172.30.123.103  eth0，私有 NAT 172.30.112.0/20
              網段所有權 = Windows 主機獨有的虛擬網路，非公司共用網段
              可回復性   = wsl --shutdown 即可完整重置
```

注意 NAT 位址在 WSL 重啟後可能改變，因此授權書應在每次測試時段開始前重新
確認實際位址，不可沿用舊值。

## 十三、下一步（step 1 剩餘）

原本 step 1 只需對齊事件詞彙，現在還須處理 windowing：

1. **事件詞彙對齊**：把 14 個無來源型別對應到實際發出的事件
   （`control_observation` → `guard_input`/`guard_output`；
   `scan_observation`／`odom_cmd_observation` → `detector_state` 既有欄位等），
   並把 `guard_*`、`authenticated_action` 移出白名單。
2. **windowing 改用封包時間而非 conn 起始時間**：
   否則長壽命 DDS flow 會讓整場 session 塌縮成 window 0。可考慮由 PCAP
   封包時間戳、或 Zeek 的區間統計（如 `conn` 的 duration 展開）產生 window。
3. **驗收條件**：一個含攻擊的 session 必須產出 ≥2 個 window，且至少一個
   帶 `binary=attack` 標籤；telemetry 區塊在攻擊 session 至少有數個特徵非 0。

在上述三點通過前，`live_multimodal_contract` 維持 `blocked`，
正式 campaign 不得啟動。**gate 再次發揮了設計用途。**

## 六、其他待處理

- `local_outcome_probe` enclave 不存在於 keystore（canonical 政策、
  `10_SROS2啟用.sh`、稽核期望清單皆有）。不影響 `01c`（實際只用 9 個
  enclave），但稽核有 2 個 ❌ 指向此根因。修復需產生新身分憑證材料。
- 本次 pilot 未觀察到任何 SROS2 拒絕。無憑證 participant 在 discovery
  階段即被隔離，不會觸發可記錄的握手失敗；有憑證節點違反 ACL 時才會產生
  （如本次 keystore 漂移事件）。**這對 ML 的意涵是：
  `sros_auth_fail_rate`／`sros_permission_deny_rate` 在真實外部攻擊下
  可能仍近乎 0，不宜作為主要偵測訊號。** 建議正式資料收集前先確認此點。

## 十四、待辦：Raspberry Pi 5 部署階段的主機威脅面

`漏洞分析報告.md` §11 假設「物理存取 out-of-scope」。這在 Gazebo 模擬階段
成立，但巡邏機器人的物理可及性是設計前提而非例外，**該假設在 Pi 5 實機部署
階段不再成立**：SD 卡未加密時，SROS2 CA 私鑰與 `alert_secret` 可在短時間
物理接觸下完整提取，使整條認證鏈失效（對應紅隊 N26 的 CA 淪陷發現）。

扣除物理接觸後，`主機攻擊面稽核.sh` 已經標出實際暴露面
（`readiness-20260727T082430197518Z`，`host_risk_count: 2`）：

```
❗ tcp 0.0.0.0:22    SSH 暴力破解（考慮關閉或綁 localhost/管理介面）
❗ tcp [::]:22
```

| 途徑 | Pi 部署後風險 | 現況 |
|---|---|---|
| SSH 暴露於所有介面 | 中高 | 已被自有稽核標記，尚未修 |
| 供應鏈（apt／pip／ROS 套件、模型檔） | 低但無法消除 | 模型檔已由 `verified_joblib_load` 驗章防護 |
| DDS UDP 埠綁 `0.0.0.0` | 屬研究對象本身 | SROS2 Enforce 即為此而設 |
| 傳統惡意程式（瀏覽器／郵件／隨身碟） | 低 | 巡邏機器人無這些使用途徑 |

要做的事（部署前）：改預設帳密、SSH 禁用密碼登入或綁定管理介面、金鑰改放
加密分割區而非 SD 卡明文、部署後重跑 `主機攻擊面稽核.sh`。

寫進報告時的重點是**主動指出信任邊界**：本系統所有保證都以主機完整性為前提，
主機一旦淪陷，DDS 層的認證與簽章全數失效——這是設計上的依賴關係，不是疏漏。
