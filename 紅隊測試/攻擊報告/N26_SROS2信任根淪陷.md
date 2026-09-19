# N26 — SROS2 信任根淪陷（CA 私鑰世界可讀 → 身分/權限全可偽造）

> 對象：`/home/jesse/ros2_security_keystore`（專案實際使用的 SROS2 金鑰庫，治理綁 domain 30）
> 實測日期：2026-06-13｜PoC：`紅隊測試/PoC腳本/N26_sros2_ca_forge.sh`（純離線 openssl，零 DDS 流量，**不碰 domain 30**）
> 結論：**SROS2 Enforce（你文件中所有 raw-topic 攻擊 N6/N7/N9/N24… 的「根治解」）被連根拔起。**

---

## 一、白話一句話

> 「整套 SROS2 的安全，建立在一把『公司總印章母模』（CA 私鑰）上——誰有它，誰就能刻出任何部門的合法印章。
> 結果這把母模**放在所有人都能拿的抽屜裡（檔案權限 644，世界可讀）**。
> 我（攻擊者）把它複印走，當場刻出一個『可發布任何指令、任何部門』的全新合法身分。
> 從此 SROS2 的『只有持證節點能通訊』形同虛設。」

---

## 二、根因發現（實測）

### 🔴 主因：CA 私鑰世界可讀 + 身分/權限共用同一把 CA
```
-rw-r--r-- 1 jesse jesse 241  ca.key.pem            ← 權限 644：owner/group/other 全可讀
identity_ca.key.pem    -> ca.key.pem                ← 身分 CA
permissions_ca.key.pem -> ca.key.pem                ← 權限 CA「指向同一把」
```
- **644 = 同主機任何非特權使用者 / 容器 / 被入侵的行程都能讀**到 CA 私鑰。
- identity 與 permissions 用**同一把 CA**：偷一把 = 同時掌握「身分簽發」與「授權簽發」兩個信任根，
  沒有任何縱深。
- 每個節點自己的 `key.pem` 也是 **644**（見下方次因）。

### 🟠 次因 1：節點私鑰世界可讀 → 直接身分竊取（連偽造都不用）
```
-rw-r--r-- patrol_node/key.pem   (+ cert.pem 644)
```
攻擊者直接 `cp` 走 `patrol_node` 的 `cert.pem + key.pem + permissions`，原封不動就**是** patrol_node，
合法發布 `rt/cmd_vel`。比偽造更簡單。

### 🟠 次因 2：governance 弱化（`enclaves/governance.xml`）
```xml
<allow_unauthenticated_participants>true</allow_unauthenticated_participants>  ← 允許未認證參與者入域
<discovery_protection_kind>NONE</discovery_protection_kind>                    ← discovery 明文（可枚舉拓樸）
<liveliness_protection_kind>NONE</liveliness_protection_kind>
<rtps_protection_kind>NONE</rtps_protection_kind>                             ← RTPS 子訊息不保護
<metadata_protection_kind>NONE</metadata_protection_kind>
<data_protection_kind>ENCRYPT</data_protection_kind>                          ← 只有 payload 有加密
```
- payload 有 ENCRYPT + read/write access control（這部分是對的），
  但 **discovery / RTPS / liveliness 全 NONE** → 未認證者可枚舉參與者/topic/QoS（資訊洩漏），
  RTPS 層無完整性保護。
- `allow_unauthenticated_participants=true` 是已知弱化選項，配合 discovery NONE 擴大被動偵察面。

---

## 三、PoC 實測證據（離線，全成功）

`bash 紅隊測試/PoC腳本/N26_sros2_ca_forge.sh` 輸出（已驗證）：

```
[步驟0] -rw-r--r-- ca.key.pem            → 已複製 CA 私鑰（示範可被偷）
[步驟1] 偽造身分 subject=CN=/evil_injector  issuer=CN=sros2CA
[步驟2] openssl verify -CAfile <真identity_ca> evil_identity.cert.pem
        → evil_identity.cert.pem: OK
        ✅ 偽造身分通過真 CA 鏈驗證
[步驟5] openssl smime -verify -CAfile <真permissions_ca> evil_permissions.p7s
        ✅ 偽造『publish *』權限通過真 permissions_ca 驗章
```

→ 攻擊者用偷來的 CA 私鑰，**同時**製造出：
1. 一張 SROS2 認為合法的身分憑證（任意 CN）。
2. 一份授予 `publish/subscribe = *`（所有 topic）的合法授權。

組起來就是一個 SROS2 眼中「完全合法 + 完全授權」的 enclave，可在 domain 30 對 `rt/cmd_vel`、
`rt/security/alerts` 等任意 topic 發布——**Enforce 模式攔不住**。

---

## 四、攻擊者模型誠實標註

| 發現 | 需要的能力 | 在你既有 L1（純網路同 LAN）假設下？ |
|---|---|---|
| CA 私鑰竊取 + 偽造（主因）| **同主機檔案讀取**（local read）| ⚠️ 超出純網路 L1；但多用戶主機/容器掛載 keystore/被入侵行程 = 真實情境 |
| 節點私鑰竊取（次因1）| 同上 local read | 同上 |
| discovery 明文枚舉（次因2）| 純網路（未認證參與者）| ✅ 網路可達（但需在 domain 30 觀測，本輪未 live 跑以免干擾訓練）|

> 誠實話：N26 最強的「偽造」這條，前提是「能讀到 keystore 檔案」。
> 這不是純網路攻擊，但它是 SROS2 部署最常見、最致命的真實誤配——
> **整個 Enforce 的安全等於『keystore 檔案權限』這一個假設**，而這假設目前是破的（644）。

---

## 五、修補建議（藍方）

1. **金鑰檔權限收緊（最優先、一行）**：
   `chmod 400 ca.key.pem 與所有 enclaves/*/key.pem`；keystore 目錄 `chmod 700`；
   理想上 **CA 私鑰離線保存**，簽完所有 enclave 後就**不放在運行主機上**。
2. **身分 CA 與權限 CA 分離**：用兩把不同的 CA（不要 symlink 到同一把），
   讓「偷到一把」無法同時偽造身分與授權（縱深）。
3. **governance 收緊**：
   - `allow_unauthenticated_participants` → `false`（除非有明確相容性需求）。
   - `discovery_protection_kind` / `rtps_protection_kind` → `SIGN`（至少簽章，擋 RTPS 偽造與被動枚舉）。
4. **最小權限**：偽造之所以好用是因為「`*` 全 topic」很好寫；真實節點 permissions 已是最小化的
   （patrol 只 pub `rt/cmd_vel`），維持這個原則，並考慮憑證短效期 + 輪替 + 撤銷（CRL）。
5. **主機層**：keystore 不要放在會被其他使用者/容器共享讀取的路徑；容器以唯讀、最小掛載。

> 關鍵認知：**SROS2 把「應用層信任」換成「PKI 信任」，但 PKI 的安全完全落在『私鑰保護』。
> 私鑰一旦可讀，SROS2 提供的所有保證歸零**——它不是比 HMAC alert_secret 更安全，
> 只是把同一個「保護好那把鑰匙」的問題換了位置。N26 = N2/N6 的 PKI 版本：信任根被冒用。
