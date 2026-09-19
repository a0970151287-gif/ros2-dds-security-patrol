# N26b — SROS2 Enforce 被 live 端到端打穿（偷 CA → 偽造 enclave → 真注入）

> 接續 [N26](N26_SROS2信任根淪陷.md)（離線偽造憑證/權限）。本輪做 **live 端到端**：
> 在隔離 `ROS_DOMAIN_ID=99` 起一個**真 Enforce 模式**的 secured 受害節點，
> 用偷來的 CA 偽造一個「防守方從未授權」的 enclave 去注入，看 Enforce 擋不擋得住。
> 實測日期：2026-06-13｜**全程 domain 99，絕不碰 domain 30 訓練**。

---

## 一、裁決：✅ 打穿（在「攻擊者能讀 keystore 檔案」前提下，已 live 證明）

偽造的 `/evil_injector` 節點——**防守方從未為它建過 enclave、從未授權**——
在 Enforce 模式下成功把訊息送進 secured victim。Enforce「只有持證節點能通訊」的保證失效。

---

## 二、三組對照實驗（這才是嚴謹之處）

| 實驗 | talker 身分 | 用偷來的 CA？ | victim 收到？ | 意義 |
|---|---|---|---|---|
| **1 baseline** | `/legit_talker`（合法授權）| 是 | ✅ 收到 1–5 | 安全通道本身正常 |
| **2 control** | 無安全（沒 enclave）| 否 | ❌ 完全沒收到 | **Enforce 真的在擋外人** |
| **3 attack** | `/evil_injector`（**未授權**）| 是（偷來的）| 🔴 **收到 1–5** | **Enforce 被偽造繞過** |

> 對照組 (2) 是關鍵：無安全 talker 被擋得死死的，證明 Enforce 確實開著、確實有效。
> (2) 與 (3) 唯一差別＝「talker 的 enclave 有沒有用偷來的 CA 簽」。
> 所以 (3) 的成功**不是**「Enforce 沒開」，而是**真正的繞過**。

---

## 三、實測 log 證據（victim 端，已驗證）

**對照組 2（無安全 talker）— victim 沉默：**
```
[rcl]: Found security directory: /tmp/sros2_live/enclaves/victim   ← Enforce 載入
[rclcpp]: signal_handler(SIGINT/SIGTERM)                           ← 全程零 "I heard"
```

**攻擊組 3（偽造 evil_injector talker）— victim 收到：**
```
[rcl]: Found security directory: /tmp/sros2_live/enclaves/victim   ← 同一個 Enforce victim
[listener]: I heard: [Hello World: 1]
[listener]: I heard: [Hello World: 2]
[listener]: I heard: [Hello World: 3]
[listener]: I heard: [Hello World: 4]
[listener]: I heard: [Hello World: 5]                              ← 偽造身分的訊息成功注入
```
evil talker 端：`Found security directory: /tmp/sros2_live/enclaves/evil` → 它自己也是合法 Enforce 參與者。

---

## 四、攻擊步驟（可重現）

PoC：`紅隊測試/PoC腳本/N26b_setup_live_keystore.sh`（建 keystore + enclave）

1. **偷 CA**：`cp /home/jesse/ros2_security_keystore/private/ca.key.pem`（644 世界可讀）。
2. **重簽 governance**：把治理域改 30→99、嚴格 Enforce（`allow_unauthenticated=false`），
   用偷來的 CA 簽 governance.p7s（連 governance 都能被攻擊者重簽）。
3. **偽造 enclave**：用偷來的 CA 簽 `CN=/evil_injector` 身分憑證 + `publish rt/chatter` 權限 p7s。
4. **注入**：
   ```bash
   # 受害端（Enforce）
   ROS_DOMAIN_ID=99 ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce \
   ROS_SECURITY_KEYSTORE=/tmp/sros2_live \
   ros2 run demo_nodes_cpp listener --ros-args --enclave /victim
   # 攻擊端（偽造 enclave）
   ROS_DOMAIN_ID=99 ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce \
   ROS_SECURITY_KEYSTORE=/tmp/sros2_live \
   ros2 run demo_nodes_cpp talker --ros-args --enclave /evil
   ```

---

## 五、誠實邊界（報告必附，避免講過頭）

- **打穿的是信任根，不是密碼學**：SROS2 的 AES/ECDSA/handshake 都正常運作；
  是**鑰匙被偷**（CA 私鑰 644 可讀）後，攻擊者成為「合法持證者」。鎖沒壞，鑰匙外流。
- **前提＝同主機檔案讀取**（local read），非純網路 L1。真實對應情境：多用戶主機、
  容器掛載 keystore、被入侵的同主機行程、備份/映像外洩。
- **隔離域驗證**：在 domain 99 用「真 CA、改域到 99 的 governance」重現；
  domain 30 的真實系統全程未被觸碰。結論可直接外推到 domain 30——因為用的是**同一把** CA。

---

## 六、和應用層攻擊的關係（金句）

> 你的系統有兩道「身分」防線：應用層 HMAC（`alert_secret`）與傳輸層 SROS2（CA PKI）。
> 紅隊在**兩道都示範了「信任根冒用」**：
> - 應用層：N2/N6 冒用「名字像自己人」、N13 借 secret 持有者之手簽章。
> - 傳輸層：**N26/N26b 偷 CA 私鑰，直接成為合法持證節點**。
>
> 共同根因：**安全最終都塌縮成「那把鑰匙/那個信任根有沒有被保護好」**。
> SROS2 不是更安全，是把「保護 `alert_secret`」換成「保護 CA 私鑰 + keystore 檔案權限」——
> 而後者目前是 `chmod 644`。修法見 [N26 報告第五節](N26_SROS2信任根淪陷.md)（chmod 400 / CA 離線 / 身分權限 CA 分離 / governance 收緊）。
