# graph 溢位：fail-safe 被觸發時關掉了它自己要保護的偵測器

**日期**：2026-09-19　**執行**：Claude
**授權**：Jesse 明確授權本輪 live 攻擊、反覆執行與微調
**狀態**：同機 loopback、Permissive、隔離 domain。未使用 `sudo`、未動真實
防火牆、未連第二台主機、未碰樹莓派（重灌中）。
攻擊行程全程**沒有** HMAC 金鑰、**沒有**遙測 socket。收尾四輪都是零殘留行程。

---

## 〇、一句話

`monitor_node._check_graph()` 在 ROS graph 的 node 數超過 `_GRAPH_NODE_MAX`
（256）時會記錄溢位、觸發緊急停止，然後**提早 `return`**——而白名單比對就在
那個 `return` 之後。**溢位期間 monitor 停止偵測未授權節點。**

兩輪獨立 live 實測都重現：越過門檻之後，現場有三百多個未授權節點，而
`unknown_node` 事件歸零。

---

## 一、機制（讀 2026-09-19 的程式）

```python
def _check_graph(self) -> None:
    ...
    graph_nodes = self.get_node_names_and_namespaces()
    if graph_nodes is None or len(graph_nodes) > _GRAPH_NODE_MAX:      # 256
        _record_graph_transition(self, "overflow", len(graph_nodes))
        self.get_logger().error(...)
        if now - self._last_graph_overflow_alert >= 30.0:              # 冷卻
            self._publish(...)
            if self._emergency_stop:
                self._trigger_emergency_stop()
        return                          # ← 白名單比對在這之後
    ...
    current = {f'{ns}/{name}' for name, namespace in graph_nodes}      # ← 到不了
```

三個後果：

| | 後果 |
|---|---|
| 1 | **機器人被緊急停止**（`_trigger_emergency_stop`） |
| 2 | **未授權節點偵測停擺**——`return` 讓白名單比對整段不執行 |
| 3 | **證據極少**：`_record_graph_transition` 只在**狀態改變**時發，所以持續溢位只留下**一筆** `graph_state`；溢位告警有 **30 秒冷卻**，而特徵視窗是 8 秒 |

這是一個 fail-closed 設計——停下來比繼續跑安全，那個判斷本身沒有錯。
問題是**停下來的同時也把偵測器關掉了**，而且幾乎不留痕跡，所以攻擊者可以
拿溢位當掩護。

---

## 二、實測

### 2.1 Permissive 五輪

判準是**溢位視窗之內**（`overflow` → `recovery`）有沒有 `unknown_node`，
不是「溢位之後永遠」——後者會把 recovery 之後恢復偵測的事件也算進去
（第一版腳本就是這樣把第 5 輪誤判成「P2 被推翻」的）。

| 輪次 | 攻擊端峰值 | monitor 看到 | `graph_state` | 溢位前 | **視窗內** | recovery 後 |
|---|---:|---:|---|---|---:|---|
| 1 | 340 | 339 | overflow | 37, 121 | **0** | — |
| 2 | 300 | 309 | overflow | 21, 70 | **0** | — |
| 3 | **254** | ≤232 | **無溢位** | 115, 108（全程正常） | — | — |
| 4 | 322 | 331 | overflow | 60, 134 | **0** | — |
| 5 | 332 | 334 | overflow → recovery | 100 | **0**（視窗 **28.0 s**） | 101 |
| 6 | 332 | 322 | overflow | 61, 151 | **0** | — |

**5 次溢位、5 次視窗內為零。** 第 6 輪同時是唯一一次拿到乾淨判定的
（`rc=0`、`verdict=pass`、6 個專屬訊號）——前五輪都因為 PoC 收尾問題被判作廢，
那是我的缺陷不是資料的（見第四節）。

**第 5 輪是最完整的證據**：偵測正常 → 溢位 → **靜默 28 秒** → recovery →
立刻恢復（`unknown_node` count=101）。一個完整的開／關／開循環。

**第 3 輪是意外拿到的陰性對照**：建立節點太慢，峰值只到 254、沒跨過 256，
而偵測**全程正常**。同一支攻擊、同一套環境，只差在有沒有越過門檻。

### 2.2 Enforce 的受控對照（事前預測 P4）

同一支攻擊、同一台機器、同樣 75 秒，唯一差別是 SROS2 有沒有強制執行：

| 模式 | 攻擊端節點 | monitor 看到 | 溢位 | 偵測空窗 | 專屬訊號 |
|---|---:|---:|---|---|---:|
| Permissive | 300–340 | 309–339 | **有**（4/4 輪） | **有**，最長 28 s | 9–15 |
| **Enforce** | 315 | **0** | **無** | **無** | **0** |

**P4 成立：SROS2 Enforce 把這條路整個關掉。** 未認證的 participant 不進入
握手（C2C-014），不會出現在防守方的 graph 視圖，`_check_graph` 根本看不到
它們，所以 node 數推不上去。

⚠️ 一個機制細節：Enforce 下攻擊者建立 315 個節點只花 **21 秒**，Permissive
下要 **45 秒**。握手失敗就沒有後續的端點發現負擔——**攻擊在 Enforce 下更快，
但完全無效。**

⇒ 這一項的結論對防禦是正面的：**溢位盲點是真的，而 Enforce 是關掉它的那道門。**

---

## 三、這條路上被推翻的兩個假說（都在花 live 之前）

### 3.1 心跳餓死：微基準推翻

原假說：monitor 是單執行緒（`rclpy.spin`，且**不訂閱任何 topic**，純計時器
驅動），`_check_graph` 的成本隨 graph 成長，而守衛心跳租約 **5.0 s** < IDS
告警門檻 **10.0 s** ⇒ 把心跳推進那個區間，機器人停住而沒有告警。

跑 live 之前先量：

| graph 裡的 node 數 | `get_node_names_and_namespaces()` 中位數 |
|---:|---:|
| 0 | 0.01 ms |
| 100 | 0.10 ms |
| 200 | 0.36 ms |
| 400 | 0.05 ms（最大 2.6 ms） |

離餓死一個 2 秒的計時器差三個數量級。**查詢不是成本所在**，這條路到不了那個
不等式。那三個常數的關係仍然存在，只是需要別的推力。

### 3.2 ReplayCache 容量攻擊：讀程式排除

`nonce_reuse_or_capacity` 這個遙測欄位名暗示快取有容量上限，滿了會拒絕。
但 `verify_alert` 的檢查順序是 **HMAC 在第 2 道、nonce 快取在第 5 道**——
只有簽章有效的訊息才進得了快取，而威脅模型裡內鬼沒有 HMAC 金鑰。打不到。

---

## 四、兩個順帶修好的真 bug

### 4.1 `N20_verify_flood.py` 的 `SyntaxError`（卡了三輪）

```
SyntaxError: unterminated f-string literal (detected at line 90)
```

某次修補把 `\n` 寫成了**真正的換行字元**，把 f-string 截成三段。後果是那支
候選在 2026-09-02、09-15、09-19 三輪 smoke 都被判「攻擊沒有執行」。

⚠️ **而 `tests/test_attack_deliverability.py` 每一輪都是綠的**——那一整組
測試都用 regex **讀字串**檢查原始碼，所以一個連 parse 都過不了的檔案照樣通過。
修補本身正確、測試也正確，只是兩者之間沒有人問過「這個檔案跑得起來嗎」。

已補上 `test_every_poc_script_actually_parses`（對全部 PoC 做 `py_compile`），
並以變異測試確認會咬。修好之後 **`verify_flood` 首次通過證據排他性 gate，
12 個專屬訊號**。

### 4.2 收尾太慢會讓整場證據作廢

第 1 輪 N36 被判 `void_attack_did_not_run`，理由是 `return_code=-9`。攻擊其實
完整跑完了（遙測有 `graph_state overflow node_count=339`），但 `finally` 裡
逐一 `destroy_node()` 340 個節點太慢 → 超過寬限期 → SIGKILL。

**gate 的判定是對的**：它無法分辨「被殺是因為卡住」與「根本沒跑」，而那兩者
在資料上長得一樣。

---

## 五、⚠️ 一個不可轉移的量測（第十五次）

隔離 domain 的微基準與真實 domain 差一個量級：

| | 隔離 domain（只有自己） | 真實 domain（完整 stack ＋ Gazebo） |
|---|---:|---:|
| 建立 340 個 node | 4.98 s | 約 35 s |
| 建立 200 個 node | ~3 s | **約 18 s** |
| 收尾 254–340 個 node | 1.92 s | **約 14 s** |

DDS discovery 是 O(n²)，有其他 participant 在跑時成本完全不同。
**拿隔離基準去定 live 的時間預算會失敗**，第 3 輪就是這樣只到 254 個。

---

## 五之二、候選升級：gate 不問的那一題

證據排他性 gate 只比「候選 vs 基線」，**不比候選之間**——而 C2C-013 記過的
失效模式正是「兩個類別觸發同一組通用特徵，兩個都認不出來，表面看起來像
類別太多」。所以自己補算跨輪穩定訊號的兩兩比較：

| 候選 | 穩定訊號 | 自己獨有 | 內容 |
|---|---:|---:|---|
| `verify_flood` | 9 | 5–6 | heartbeat 通道被 HMAC 拒絕（`invalid_signature`） |
| `graph_overflow` | 6 | 2 | `log_reject`、`log_reject.count>0` |
| `baseline_poisoning` | 3 | **0** | 全部是「有參與者加入」的地板 |

- `graph_overflow` ↔ `verify_flood`：**分得開**（各有 2 與 5 個獨有）。
- `baseline_poisoning`：**對另外兩支都沒有任何獨有訊號**。它的 gate pass
  完全來自 C2C-062 記的那個地板（任何會連線的攻擊都會產生 4 次 alert／
  1 次 guard_lock）。

**建議：升 `verify_flood`（19/23 → 20/23，83% → 87%），不要升
`baseline_poisoning`。** 後者升上去就是 C2C-013 的重演——多一個模型認不出來
的類別，只會拖低 balanced accuracy。

⚠️ `graph_overflow` 只有一輪拿到 pass，它的「穩定訊號」是單輪的，證據強度
弱於 `verify_flood` 的兩輪。而且它**沒有 policy 規則**（見第七節）。

---

## 六、對偵測與評估流程的兩個意涵

1. **證據排他性 gate 看不見只發一次的事件。** `graph_state` 整場只有一筆，
   而 gate 的 `min_count` 是 3。這個攻擊最具特徵的訊號**結構上就在 gate 的
   門檻之下**；它算出來的「專屬訊號」全是防禦反應
   （`guard_lock` 166 次、`hmac_result.channel=alerts` 668 次）。
2. **狀態轉換事件可能記在錯的場次。** stack 跨場次連續執行，而
   `_record_graph_transition` 只在改變時發，所以第 3 輪的 `recovery` 落在
   graph_overflow 那一場，但造成它的狀態變化發生在場次之外。

---

## 七、不可宣稱

- **只在 Permissive 驗過。** 事前預測 P4（Enforce 下打不到，因為未認證
  participant 不進握手）**尚未測**。
- 只有 3 個有效樣本（2 次溢位、1 次陰性對照），沒有統計量。
- **這個類別在 `action_policy.json` 裡沒有對應規則。** 若要納入計分，
  攻擊面覆蓋的分母會從 23 變 24，百分比會**下降**（19/23 → 19/24）。
  那是 Jesse 的決定，本輪沒有做。
- 出貨 catalog（`scenarios.json`）一個位元未動，仍是 19 個 scenario。
- 緊急停止確實被觸發，但我**沒有獨立量測機器人停了多久**——那需要另一組
  以速度輸出為準的觀測。
