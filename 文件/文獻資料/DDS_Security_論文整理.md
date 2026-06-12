# DDS Security 相關論文整理

> 目的：依教授建議，先從文獻了解 DDS Security 的研究情境與偵測手段，再回來設計自己的切入點。

---

## 論文清單

### 1. On the (In)Security of Secure ROS2
- **連結**：https://dl.acm.org/doi/10.1145/3548606.3560681
- **年份**：2022
- **發表**：ACM CCS 2022（頂級資安會議）
- **情境**：攻擊者利用 SROS2 的設計漏洞，繞過存取控制獲得未授權權限
- **發現的四個漏洞**：
  - V1：權限檔案被替換攻擊
  - V2：過期節點繞過（節點拒絕重啟以保留已撤銷的 Topic 存取權）
  - V3：預設設定錯誤漏洞
  - V4：權限檔案推斷攻擊（攻擊者可推測其他節點的權限）
- **偵測手段**：模型檢查（Model Checking）
- **與本專題的關聯**：我們的 permissions.xml 設計直接對應 V1/V3，V2 說明光有憑證還不夠

---

### 2. ROSPaCe: Intrusion Detection Dataset for ROS2
- **連結**：https://www.nature.com/articles/s41597-024-03311-2
- **ArXiv**：https://arxiv.org/abs/2402.08468
- **年份**：2024
- **發表**：Scientific Data (Nature)
- **情境**：嵌入式 ROS2 機器人系統的真實滲透測試，含 6 種攻擊，3 種針對 ROS2
- **攻擊類型**：
  - DDS Discovery Attack（偽造節點加入）
  - DoS 攻擊
  - ARP Spoofing
- **偵測手段**：多層特徵萃取
  - OS 層（25 個特徵）
  - 網路層（422 個特徵）
  - ROS2 服務層（5 個特徵）
- **資料集**：3,024 萬筆資料，40.5 GB，78% 攻擊 / 22% 正常
- **與本專題的關聯**：ROS2 服務層的 5 個特徵最值得參考——即監控節點圖的變化

---

### 3. RTPS Attack Dataset (HCRL)
- **連結**：https://arxiv.org/html/2311.14496v4
- **資料集**：https://ocslab.hksecurity.net/Datasets/rtps-attack-dataset
- **年份**：2023
- **機構**：Hong Kong Security Lab
- **情境**：無人地面車（UGV）ROS2 系統遭受指令注入攻擊
- **攻擊類型**：
  - 指令注入（修改 RTPS 封包中的序列化資料）
  - ARP Spoofing + 指令注入組合
- **偵測手段（封包層）**：
  - 時間戳比對
  - Entity Identifier 追蹤
  - Checksum 驗證
  - IP 位址分析
  - ARP Operation Code 和 MAC Address 檢查
- **與本專題的關聯**：封包層偵測 vs. 我們做的節點圖偵測，兩種不同深度

---

### 4. A Security Analysis of the DDS Protocol (Trend Micro)
- **連結**：https://documents.trendmicro.com/assets/white_papers/wp-a-security-analysis-of-the-data-distribution-service-dds-protocol.pdf
- **年份**：2022
- **情境**：工業 IoT 和智慧城市應用中的 DDS 實作漏洞
- **發現**：6 大 DDS 實作共 13 個 CVE
- **攻擊類型**：
  - 網路反射放大攻擊（CVSS 8.2）
  - 緩衝區溢位（堆疊 + 堆積）
  - RTPS 封包資訊洩漏（安全元資料以明文傳送）
- **與本專題的關聯**：我們的 governance.xml 加密可防禦明文洩漏問題

---

### 5. SROS2: Usable Cyber Security Tools for ROS2
- **連結**：https://arxiv.org/pdf/2208.02615
- **年份**：2022
- **發表**：IROS 2022
- **情境**：評估現有 SROS2 工具的可用性與實際漏洞暴露程度
- **關鍵發現**：
  - 全球 34 個國家 643 個公開暴露的 DDS 服務
  - 202 個 DDS 實作洩漏私有 IP
- **建議偵測工具**：Suricata 整合，監控 UDP 7400-7600
- **與本專題的關聯**：我們用 Zeek 監控同樣的 Port 範圍（7400-7500）

---

### 6. Attack Simulation on DDS Infrastructure (IoTBDS 2023)
- **連結**：https://www.scitepress.org/Papers/2023/119562/119562.pdf
- **年份**：2023
- **情境**：客戶端攻擊 DDS 基礎設施，利用設定錯誤進行惡意操控
- **攻擊重點**：DDS 的錯誤設定（misconfiguration）是主要攻擊面
- **與本專題的關聯**：我們的 governance.xml 修正正是解決 misconfiguration 問題

---

## 情境對比表

| 論文 | 攻擊情境 | 偵測層次 | 偵測手段 |
|------|---------|---------|---------|
| CCS 2022 | 繞過 SROS2 存取控制 | 應用層 | 模型檢查 |
| ROSPaCe 2024 | 偽造節點加入 ROS2 | OS + 網路 + ROS2 層 | 多層特徵萃取 + ML |
| HCRL 2023 | RTPS 封包指令注入 | 封包層（RTPS） | 封包特徵分析 |
| Trend Micro 2022 | DDS 實作協定漏洞 | 協定層 | 漏洞掃描 + Fuzzing |
| IROS 2022 | 公開暴露的 DDS 服務 | 網路層 | Suricata IDS |
| IoTBDS 2023 | DDS 設定錯誤攻擊 | 設定層 | 攻擊模擬 |

---

## 本專題目前對應的位置

- ✅ **存取控制**（CCS 2022）：SROS2 permissions.xml（Permissive 模式；Enforce 列入未來工作）
- ✅ **加密傳輸**（Trend Micro 2022）：governance.xml
- ✅ **節點圖偵測**（ROSPaCe 2024）：monitor_node 白名單 + baseline+grace
- ✅ **網路層監控**（IROS 2022）：Zeek 監控 UDP 7400-7500
- ✅ **應用層訊息完整性**（本專題主要貢獻）：HMAC envelope v3（channel + ts + nonce）+ ReplayCache，防偽造/重放/跨頻道
- ✅ **行為層異常偵測**（對應 ROSPaCe 的 ROS2 服務層特徵）：intelligent_defense_node D1–D6 + cascade 斷路器
- ❓ **封包層偵測**（HCRL 2023）：RTPS 封包分析 — **尚未實作，可作為深化方向**

> 說明：因 SROS2 採 Permissive 模式（DDS 層不強制擋），本專題的**主要防線是應用層 HMAC 簽章 + 行為 IDS**，而非 DDS 層存取控制。這也是與上述論文最大的差異點：在不依賴 DDS Enforce 的前提下，用應用層補回身份驗證與 anti-replay。

---

## 建議的切入點

根據教授：「偵測未知節點這端如果做深，後面的處置才有說服力。」

**建議深化方向：**
從「節點圖偵測」（目前做法）升級到「RTPS 封包特徵偵測」：
1. 監控 Entity ID 的變化（新節點加入時會有新的 GUID）
2. 分析 DDS Discovery 封包的頻率和來源
3. 與白名單比對，異常行為即時告警

這樣的偵測比只看節點名稱更深入，更難被攻擊者繞過。
