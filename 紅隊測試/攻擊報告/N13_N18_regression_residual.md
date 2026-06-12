# 紅隊報告 — N13/N4 修補確認 + N17/N18 殘留發現

> 作者：紅方  日期：2026-05-30
> 對象：藍方 N13/N14/N15/N17 修補後的 stack
> 攻擊者能力：**L1**（同 LAN 任意 ROS2 node，無 secret）

---

## Part 1 — 修補確認（誠實 regression）✅

### N13（self-watch 反射放大 + latch 致盲）— 已修補

拿原版 [N13_health_reflection.py](../PoC腳本/N13_health_reflection.py) 打補丁後 stack（system_status + patrol）：

| 指標 | 修補前 | 修補後 | 結論 |
|---|---|---|---|
| 攻擊者 poke（未簽章垃圾）| 5 | 5 | — |
| patrol 因反射 alert 停車 | 1 | **0** | ✅ 反射放大已封 |
| system_status emit CH_ALERTS 反射 | 1 | **0** | ✅ 不再 confused-deputy |
| self-watch 後續偵測 | latch 一次後永久致盲 | **持續**（log「1 筆→4 筆」累計）| ✅ latch 已移除 |

修補後 system_status 對未簽章垃圾只印：
```
⚠️ [N8/N13] /system/health 收到 N 筆未簽章/重放/cross-channel 訊息 — 已忽略（不反射成 alert）
```
**紅方確認：N13 三點修補（移除反射 / 移除 latch / rate-limit）全部生效。**

### N4（cross-channel confusion）— 已修補（上一輪確認）

原版 N4 PoC（heartbeat→alerts forward）對補丁 stack：patrol 拒絕 16 次，理由
明寫 `channel: heartbeat ≠ alerts`，停車 0 次。channel-binding 成立。

---

## Part 2 — N17/N18 殘留發現（誠實標註：低～中嚴重度）

> 註：高嚴重度的應用層漏洞（偽造 alert / 反射 / cross-channel / replay）目前**全部關閉**。
> 以下是新加的 hardening（N17）引入的較低嚴重度殘留，以及一個無上限成長 bug。
> 不灌水成 ✗✗✗，誠實分級。

### N18 — `_alerted_nodes` 無上限成長 → 記憶體耗盡 DoS（中）

[monitor_node.py:502-514](../../src/dds_security_monitor/dds_security_monitor/monitor_node.py#L502-L514)：

```python
with self._lock:
    if node_full in self._alerted_nodes:
        continue
    self._alerted_nodes.add(node_full)        # ← 每個唯一名字都 add
self._alert_new_node(node_full, len(current))

if self._alert_on_exit:                        # ← 預設 False (config: alert_on_node_exit)
    for node_full in exited_nodes:
        ...
        self._alerted_nodes.discard(node_full) # ← 只有這裡 discard，但預設不會執行
```

漏洞：`_alerted_nodes` 是去重集合，但在**預設 config（`alert_on_node_exit: false`）**下
`discard` 永遠不執行 → 集合**只增不減**。

攻擊：攻擊者用「不斷換唯一名字」的節點 churn（spawn→等 monitor poll→kill→換名再 spawn），
每個唯一名字都進 `_alerted_nodes` 且永不移除 → 長時間運行記憶體無上限成長 → monitor OOM。
不需 secret，純 L1。

嚴重度：**中** — 不需 secret、會打掛整個 Layer 2 監控（monitor 死），但成長速度受
poll_interval（預設 5s）+ 節點啟動成本限制，是「慢性」DoS，非瞬殺。且 monitor 死後
IDS D5 心跳 watchdog 會 fire（這部分防禦仍在）。

**量化驗證**（[N18_memory_exhaustion.py](../PoC腳本/N18_memory_exhaustion.py) — 直接驅動真實 `_check_graph()`）：

| poll | `_alerted_nodes` | 記憶體成長 |
|---|---|---|
| 1   | 50     | 27 KB |
| 40  | 2,000  | 462 KB |
| 80  | 4,000  | 766 KB |
| 120 | 6,000  | 1,457 KB |
| 160 | 8,000  | 1,758 KB |
| 200 | 10,000 | 2,063 KB |

10,000 個 churn 唯一名字 → `_alerted_nodes` 精確 = 10,000（**完全線性、零縮減**，~211 bytes/node）。
`discard` 從不執行（已確認 `alert_on_node_exit` 預設 False）。外推：1 名/秒 churn × 24h
= 86,400 entries，持續數天 → monitor RSS 無上限成長 → OOM kill。

修補：`_alerted_nodes` 改為有 TTL 的結構（與 ReplayCache N12 同手法），或限制 maxlen +
LRU evict；或對「短時間大量唯一名字」本身視為攻擊訊號（rate-based）。

### N17 — alert dilution（needle-in-haystack）（低）

[monitor_node.py:563-572](../../src/dds_security_monitor/dds_security_monitor/monitor_node.py#L563-L572)：

```python
names = [p[1] for p in pending]
preview = '\n'.join(f'  • {n}' for n in names[:10])      # ← 只顯示前 10 個
extra = f'\n  ... 還有 {len(names) - 10} 個' if len(names) > 10 else ''
```

漏洞：N17 把 30s 內的 unknown-node alert 聚合成 1 條 LINE，但預覽只列**前 10 個名字**。
攻擊者 flood 大量 decoy unknown nodes，把真正的惡意節點名字埋進「...還有 N 個」裡
→ operator 在 LINE 上看不到真兇的名字。

緩解（為何只列低）：
- batch 仍顯示總數 + 明確標「(可能是 attacker flood 攻擊 N17)」→ operator 知道被攻擊
- 每個 unknown node 仍各自觸發 `/security/alerts` → patrol/burger_env 仍停車（emergency stop 不受影響）
- 真兇雖被埋，但「100 個未知節點」本身就是強烈入侵訊號

修補：batch 預覽顯示「全部名字」（或 hash 後全列），或對「疑似 attacker」與「孤立單一
unknown node」分流通知（後者更可能是真兇，應完整顯示）。

### N17 — operator 通知延遲（低）

LINE 通知改為每 30s flush 一次（`_LINE_BATCH_WINDOW_SEC`）。真實入侵的 LINE 通知
最多延遲 30s。

緩解：`/security/alerts` 的 emergency stop 仍是**即時**（`_trigger_emergency_stop` 在
`_alert_new_node` 內同步呼叫）→ 機器人物理安全不受延遲影響，只有「人類經由 LINE 得知」延遲。

修補：第一筆 alert 立即送（reset batch timer），後續才聚合（leading-edge + trailing batch）。

---

## Part 3 — 仍開放的高價值攻擊面（藍方已誠實揭露）

threat model 自己列出、且尚未根治的：

| 攻擊面 | 狀態 | 根本解 |
|---|---|---|
| `/cmd_vel` 注入（C/J/N9）| 應用層緩解（N9「62% 競爭勝率」），未根治 | SROS2 Enforce |
| `/scan` poisoning（N10）| D6 行為一致性部分擋 | SROS2 Enforce |
| `/odom` poisoning（N11）| D4+D6 部分擋 | SROS2 Enforce |

這些是 message-type 非 String、無法包 HMAC envelope 的 topic，應用層簽章方案天生擋不住，
只能靠 DDS-layer（SROS2）publisher 認證。藍方已誠實標註，紅方確認分析正確。

---

## Part 4 — 復現

### N18 記憶體成長（概念）
```bash
ros2 run dds_security_monitor monitor_node --ros-args -p emergency_stop_enabled:=false &
# 攻擊者：不斷換唯一名字 churn
for i in $(seq 1 200); do
  timeout 3 ros2 run demo_nodes_py listener --ros-args --remap __node:=evil_$RANDOM$i &
  sleep 2
done
# 觀察 monitor RSS 隨 _alerted_nodes 成長（每個唯一名字 +1，永不釋放）
```

### N17 dilution（概念）
```bash
# 30s 內 spawn 20 個唯一名字 + 1 個「真兇」
# → LINE batch 只列前 10，真兇名字落入「...還有 11 個」
```

---

## Part 5 — 累計戰績（N1 ~ N18）

| 輪次 | 攻擊 | 結果 |
|---|---|---|
| 1–2 | N1/N2/N3 | ✅ 已修補 |
| 3 | N4/N5/N6/N7 | ✅ 全部已修補（本輪確認 N4）|
| 藍方主動 | N8–N12 | 大致有效 |
| 4 | **N13**（self-watch 反射 + 致盲）| ✅ **本輪確認已修補** |
| 5 | **N18**（_alerted_nodes 無上限成長）| 🟡 新發現，中嚴重度 |
| 5 | **N17 dilution + 通知延遲** | 🟢 新發現，低嚴重度 |

**誠實總評**：經過 5 輪紅藍對抗，應用層的「身份偽造 / replay / 反射」這一整類
高嚴重度攻擊**已全數關閉**。剩餘攻擊面分兩類：
1. 天生需要 SROS2 的 raw topic（cmd_vel/scan/odom）— 藍方已誠實揭露
2. 新 hardening 引入的低～中嚴重度殘留（N17/N18）— 本報告補上

紅隊的價值在後期已從「找致命洞」轉為「驗證修補 + 抓資源/可用性類殘留」。
