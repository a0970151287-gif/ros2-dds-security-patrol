# 紅隊報告 — 威脅模型外的 3 個新攻擊（N1 / N2 / N3）

> 作者：紅方  日期：2026-05-27
> 對象：[dds_security_monitor](../../src/dds_security_monitor/) + [SAC patrol](../../src/turtlebot3_dqn/)
> 隔離：`ROS_DOMAIN_ID=99`
> 攻擊者能力：**L1**（同 LAN 任意 ROS2 node — 不需要 `alert_secret`）

---

## TL;DR

| # | 攻擊 | 目標 | 結果 | 修補成本 |
|---|---|---|---|---|
| **N1** | `/security/heartbeat` replay | 殺 monitor 但 IDS D5 watchdog 不察覺 | ✗✗✗ 成功 | 中（加 nonce/timestamp） |
| **N2** | `_INTERNAL_NODE_REGEX` 後門 | 偽裝成 ros2cli 子命令，monitor 永遠看不到 | ✗✗✗ 成功 | 低（白名單收緊） |
| **N3** | `/security/alerts` replay | 永久 patrol DoS（不需 secret） | ✗✗✗ 成功 | 中（同 N1，sign 加 nonce） |

**三者都是 L1 攻擊** — 不需 root、不需 `alert_secret`、不需寫檔權限。
本系統的 THREAT_MODEL.md 把這三個攻擊全部漏掉了。

---

## N1：`/security/heartbeat` Replay

### 漏洞位置

[monitor_node.py:397-404](../../src/dds_security_monitor/dds_security_monitor/monitor_node.py#L397-L404)：

```python
def _publish_heartbeat(self) -> None:
    payload = f'hb|{time.time():.3f}'
    msg = String()
    msg.data = sign_alert(payload, self._alert_secret)  # ← HMAC over payload
    self._heartbeat_pub.publish(msg)
```

[intelligent_defense_node.py:111-119](../../src/dds_security_monitor/dds_security_monitor/intelligent_defense_node.py#L111-L119)：

```python
def _hb_cb(self, msg: String):
    payload = verify_alert(msg.data, self._secret)  # ← 只驗 HMAC
    if payload is None:
        return
    self._last_heartbeat_wall = time.monotonic()     # ★ 不驗 payload 內 timestamp
```

`sign_alert` 的 envelope 是 `{"payload": str, "sig": HMAC(payload, secret)}`
— 沒有 nonce、沒有 freshness 檢查。攻擊者只要錄一筆，就能無限重放。

### 攻擊流程

1. 攻擊者訂閱 `/security/heartbeat`，捕獲 **1 筆**簽章 bytes
2. （或他人）kill 真 monitor — 例如資源耗盡、外部 DoS、誤殺
3. 攻擊者每 0.5s 重發同一筆 bytes（< D5 timeout 10s）
4. IDS `_last_heartbeat_wall` 永遠被刷新 → D5 永不 fire

### 證據（[N1_attacker.log](/tmp/N_attacks/N1_attacker.log)）

```
[ERROR] attacker_hb_replay: 📼 已捕獲簽章心跳 (len=107)
[ERROR] attacker_hb_replay: 🔁 切換為 REPLAY 模式：每 0.5s 重送同一筆心跳
[WARN]  attacker_hb_replay: 已重放 30 次（IDS 視 monitor 為「活著」）

IDS 反應：D5 alert 次數: 0
IDS 統計：hits D1=0, D2=0, D3=0, D4=0, D5=0
```

**G6 修補的核心承諾「kill monitor 會被抓」失效。**

### 影響

- 防禦三層中的「監控層心跳互保」被瓦解
- 攻擊者可在「IDS 仍然認為一切正常」的情況下殺掉 monitor，後續所有 monitor 該抓的（A、prefix bypass、new node 偵測）都漏網

### 修補建議

`sign_alert` envelope 改帶 nonce + 單調 timestamp，receiver 維護「seen nonces / monotonic clock」：

```python
def sign_alert(payload: str, secret: bytes, ts: float|None=None) -> str:
    ts = ts if ts is not None else time.time()
    nonce = secrets.token_hex(8)
    body = json.dumps({"payload": payload, "ts": ts, "nonce": nonce}, sort_keys=True)
    mac = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"body": body, "sig": mac})

def verify_alert(signed, secret, max_age=10.0, seen=None) -> str|None:
    ...
    # 1. HMAC 對
    # 2. ts 在 [now - max_age, now + 1.0] 範圍內
    # 3. nonce 沒看過（LRU）
```

IDS / patrol / burger_env 都需要更新 verify 邏輯。

---

## N2：`_INTERNAL_NODE_REGEX` 後門

### 漏洞位置

[monitor_node.py:36-43](../../src/dds_security_monitor/dds_security_monitor/monitor_node.py#L36-L43)：

```python
_INTERNAL_NODE_REGEX = re.compile(
    r'^(?:'
    r'_ros2cli_daemon_\d+_[0-9a-fA-F]+'
    r'|_ros2cli_[a-z]+_\d+_[0-9a-fA-F]+'       # ← 後門：subcommand 是任意 [a-z]+
    r'|transform_listener_impl_[0-9a-fA-F]+'   # ← 同樣
    r'|launch_ros_\d+'
    r')$'
)
```

`monitor_node._check_graph` 對匹配此正則的節點直接 `continue`，不發 alert、不觸發
emergency stop。攻擊者命名節點為 `_ros2cli_evil_99999_deadbeefcafe` 即可隱身。

### 證據（[N2_monitor.log](/tmp/N_attacks/N2_monitor.log) + [N2_attacker.log](/tmp/N_attacks/N2_attacker.log)）

```
attacker: 🥷 偽裝為「_ros2cli_evil_99999_deadbeefcafe」
attacker: 我還在這（已存活 8 秒），但 monitor 看不到我
attacker: 我還在這（已存活 9 秒），但 monitor 看不到我

monitor: (從未發過任何 alert)
```

### G1 patch 邏輯錯誤

G1 patch 的 commit message 說「移除 `_` prefix 全放行」，但實際做法只是把
「prefix 字串比對」改成「正則比對」，**白名單的存在本身就是漏洞**：

| 攻擊者命名 | G0 (原版) | G1 (現在) |
|---|---|---|
| `_evil` | ✗ 隱身 | ✓ 被偵測 |
| `_ros2cli_evil` | ✗ 隱身 | ✓ 被偵測 |
| `_ros2cli_evil_99999_deadbeefcafe` | ✗ 隱身 | **✗ 隱身（攻擊 N2）** |
| `transform_listener_impl_deadbeef` | ✗ 隱身 | **✗ 隱身** |

### 修補建議

**選項 A（強）**：完全移除 ROS2 內部節點白名單，改用「啟動基準快照」(`_known_nodes`
已有 init phase) 之外的任何新 node 都發 alert，包括 ROS2 內部
（誤判由白名單明確列入而非 prefix）。

**選項 B（弱）**：保留正則但鎖死 daemon/CLI 的 PID 範圍 + hex 長度，配合
監控 `ros2 daemon`/`ros2 cli` 實際使用情境。仍可被偽造但門檻提高。

推薦 A — 設計上「自動信任未知名稱」永遠是壞主意。

---

## N3：`/security/alerts` Replay → 永久 patrol DoS

### 漏洞位置

跟 N1 同根 — `sign_alert` 沒有 nonce/timestamp。但這個攻擊衝擊更大，因為
patrol_node 的暫停邏輯每收到一筆合法簽章 alert 就重置 30 秒 resume timer：

[patrol_node.py:279-296](../../src/dds_security_monitor/dds_security_monitor/patrol_node.py#L279-L296)：

```python
def _cb_alert(self, msg: String) -> None:
    payload = verify_alert(msg.data, self._alert_secret)
    if payload is None: return
    if not self._paused:
        self._paused = True
        self._pub(0, 0)
        self.get_logger().error(...)
    if self._resume_timer is not None:
        self._resume_timer.cancel()
        self._resume_timer = None
    self._resume_timer = self.create_timer(30.0, self._resume)  # ★ 每次都重置
```

### 攻擊流程

| 時間 | 動作 |
|---|---|
| t=0  | 攻擊者啟動 replayer，訂閱 `/security/alerts`（QoS 對齊 monitor 的 TRANSIENT_LOCAL） |
| t=2  | 短暫啟動一個非白名單 node（或等任何 legit alert）→ monitor 發 alert |
| t=4  | 攻擊者捕獲簽章 bytes，立刻開始每 5s replay |
| t=5  | 攻擊者可選擇 kill monitor（或不殺，不影響攻擊成立） |
| t=5+ | patrol 永久 paused — 每 5s 的 replay 把 resume timer 拉回 30s |

### 證據（[N3_patrol.log](/tmp/N_attacks/N3_patrol.log) + [N3_attacker.log](/tmp/N_attacks/N3_attacker.log)）

```
attacker: 📼 捕獲簽章 alert
attacker: 🔁 開始無限重放（每 5s 一次）
attacker: 💀 重放 #1 ~ #8（35 秒內）

patrol:  🚨 安全警報（已驗章）！巡航停止 (t=6)
patrol:  (35 秒過去) — 沒有任何「安全暫停解除」log
```

對比正常情況：30 秒 timer 過去後應該印 `安全暫停解除，恢復巡航`。攻擊下 timer
每 5 秒被重置 → 永遠不會走到 `_resume`。

### 為什麼 HMAC 沒擋下

threat model 寫「攻擊 B 偽造 → HMAC 已修補」。但 HMAC 證明的是
**「這筆 bytes 來自有 secret 的人」**，不是「這筆 bytes 是現在發的」。
攻擊者**不需要 secret**，只需要把合法的 bytes 原封不動再丟一次。

### 影響

- 工廠生產線停擺：patrol 不再巡邏
- 訓練中斷：同樣的 `/security/alerts` subscription 在 `burger_sac_env`，replay 也能讓訓練 reset loop 卡死
- mission_manager / system_status 同樣受影響（共用驗章邏輯）

### 修補建議

同 N1：`sign_alert` 加 `ts` + `nonce`，receiver 驗 freshness（max_age ~ 10s）+
維護 nonce LRU。這個改動一次修掉 N1 + N3。

---

## 三個攻擊的共同根因

| 攻擊 | 根因 |
|---|---|
| N1, N3 | HMAC envelope 缺少 anti-replay 欄位（nonce/timestamp） |
| N2 | 「ROS2 內部節點」白名單以名稱判斷 + 攻擊者控制名稱 |

防禦設計把「**身份驗證**」（你是有 secret 的人）跟「**訊息新鮮度**」（這筆訊息現在發的）
搞混了。HMAC 解決第一個問題，沒解決第二個。

---

## 對 THREAT_MODEL.md 的修正建議

`### 2.3 攻擊者不知道的` 那段宣稱「攻擊者拿到 secret → out of scope」是真的，
但**整個 threat model 假設「有 secret 才能繞 HMAC」是錯的**，因為 replay 不需要
secret。建議在 4.2 已知繞過加入：

```markdown
| N1/N3 | sign_alert 沒包 timestamp/nonce → 攻擊者捕獲後可重放 | envelope 增加 ts+nonce，receiver 驗 freshness |
| N2    | _INTERNAL_NODE_REGEX 接受 `_ros2cli_[a-z]+_*` | 移除內部白名單，改用啟動快照基準 |
```

並更新 4.1：

```markdown
- 完全沒擋：3/13（N1 heartbeat replay, N2 regex 後門, N3 alert replay）
```

---

## 復現步驟

```bash
cd ~/ros2_ws
# 三個一起跑（~90 秒）
bash 紅隊測試/run_N_attacks.sh all
# 個別跑
bash 紅隊測試/run_N_attacks.sh N1
bash 紅隊測試/run_N_attacks.sh N2
bash 紅隊測試/run_N_attacks.sh N3
```

log 在 `/tmp/N_attacks/`。
