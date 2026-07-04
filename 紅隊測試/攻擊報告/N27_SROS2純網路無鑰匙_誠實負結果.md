# N27 — 憑實力打 SROS2（純網路、零鑰匙）：誠實負結果，Enforce 守住了

> 動機：N26/N26b 的「打穿」前提是**已能讀到 CA 私鑰**（同主機檔案，且我本身就是檔案 owner），
> 那不算憑實力攻破 SROS2 機制。本輪當一個**純網路、無任何憑證/金鑰**的 L1 攻擊者，
> 打 governance 自己暴露的傳輸層，看能不能不靠偷鑰匙打穿。
> 環境：隔離 `ROS_DOMAIN_ID=99`，governance **完全照真實系統**
> （`allow_unauthenticated_participants=true`、`discovery/rtps_protection=NONE`、payload `ENCRYPT`+存取控制）。
> 攻擊者全程 `ROS_SECURITY_ENABLE=false`、無 enclave。實測日期 2026-06-14，不碰 domain 30。

---

## 一、裁決：❌ 打不穿（這是誠實的負結果，對藍方是好消息）

純網路、零鑰匙的攻擊者**無法注入、無法竊聽、無法枚舉應用層 topic**。
SROS2 Enforce 即使在「偏弱」的真實 governance 下，仍擋住了真正沒有鑰匙的攻擊者——也就是真實的我。

> 對照前情：N26/N26b 之所以「打穿」，是因為我**有 CA 私鑰**。一旦把這個前提拿掉（憑實力），
> 我打不穿。這正好反證：**SROS2 的安全完全押在「私鑰/keystore 檔案有沒有被保護」上**——
> 機制本身是有效的。

---

## 二、四個零鑰匙測試（含對照，全部實測）

| 測試 | 做法（零鑰匙）| 結果 | 證據 |
|---|---|---|---|
| Baseline（健全性）| secured 合法 talker → secured victim | ✅ victim 收到 1–5 | 證明通道與環境正常 |
| **注入** | 無安全 talker → secured victim | ❌ **被擋** | victim 全程 0 筆 "I heard" |
| **竊聽** | 無安全 `topic echo /chatter`（合法 talker 正發 15 筆加密訊息）| ❌ **偷不到** | echo 全空（Terminated）；對照組合法 talker 確實發了 15 筆 |
| **枚舉** | 無安全 `node list` / `topic list` / `echo` | ❌ **看不到 victim** | node list 空；topic list 只有攻擊者自己的 `/parameter_events`+`/rosout`；victim 的 `/chatter` 訂閱不可見 |

### 為什麼擋得住（機制層面）
- **注入**：topic `*` 有 `enable_write_access_control=true`——未認證 writer 無 permissions token →
  secure reader 不與它配對；且 `data_protection=ENCRYPT`——它也產不出能被解密的密文。
- **竊聽**：`data_protection=ENCRYPT`——即使封包在線上被看到也是密文，零鑰匙無法解。
- **枚舉**：EDP（端點探索）配對被 security manager 拒絕
  （log: `Security manager returns an error ... pairingReader`）→ 拿不到 victim 的 reader/writer/topic 清單。

---

## 三、唯一真的洩漏的東西（誠實標註，但價值有限）

`rtps_protection_kind=NONE` + `discovery_protection_kind=NONE` 的代價是：
- 攻擊者的 DDS 堆疊**能偵測到「這裡有一個 secure participant 存在」**（SPDP 參與者層級可見，
  且我方嘗試配對時會噴 `RTPS_EDP Error`，反證對方存在）+ 看得到其網路 locator（IP/port）。
- 這是**presence / 網路端點層級的 metadata 洩漏**，可用於「鎖定目標、做 RTPS 層 DoS」的前期偵察，
  但**拿不到應用層 topic 名、拿不到資料明文、無法注入**。

> 換句話說：攻擊者知道「門在哪、門後有人」，但**開不了門、聽不到門內、看不到門內格局**。

---

## 四、還沒做、但理論上開著的一條（留給後續，誠實聲明難度）

`rtps_protection_kind=NONE` 表示 RTPS 線路訊息無完整性保護，理論上可嘗試
**raw RTPS 封包偽造 / SPDP 探索洪水 DoS**（不需鑰匙，純封包層）。
但這需要手刻 RTPS 封包（Scapy-RTPS 或自製），且
- 對「注入受保護 topic」大概率仍無效（payload 還是要過 ENCRYPT+存取控制）；
- 比較可能打到的是「**discovery 層 DoS**」（吵雜、屬可用性攻擊）。
本輪未做；要做我會誠實標成「DoS/可用性」而非「注入」，且成敗照實報。

---

## 五、結論寫進報告（金句）

> **把「偷到的鑰匙」這個前提拿掉，紅隊憑實力打不穿 SROS2 Enforce。**
> 注入、竊聽、枚舉三條全部被 `ENCRYPT + 存取控制 + 端點配對拒絕`擋下。
> 所以 SROS2 對你系統的真實風險**不是協定被破**，而是
> **[N26](N26_SROS2信任根淪陷.md) 的金鑰管理**（CA 私鑰 644、單一 CA、keystore 檔案權限）。
> → 防守重點不是「SROS2 本身」，而是「**那把 CA 私鑰 + keystore 檔案權限有沒有顧好**」。
>
> 這也校正了 N26/N26b 的定位：它們是**設定稽核發現（key management）**，
> 不是 SROS2 機制被攻破。誠實分級：
> - 憑實力（純網路無鑰匙）打穿 SROS2 → **沒有**（本輪 N27 證明）。
> - 拿到鑰匙後繞過 SROS2 → 有（N26/N26b，但前提是檔案權限失守）。
