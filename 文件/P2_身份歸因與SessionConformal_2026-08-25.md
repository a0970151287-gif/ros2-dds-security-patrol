# P2：RTPS／DDS 身份歸因與 Session-level Conformal

更新日期：2026-08-25

範圍：離線程式、既有資料唯讀稽核、測試與證據治理

結論：**P2 工程實作完成；身份歸因與 conformal 部署驗收均未通過。**

## 1. 本輪解決了什麼

| 項目 | 已完成 | 目前邊界 |
|---|---|---|
| RTPS／DDS 身份證據契約 | 定義 SPDP locator、SEDP endpoint、authenticated identity 三種嚴格紀錄；綁定 session、時間、capture、decoder、policy、介面、IPv4、GUID、topic 與 subject hash | 現有 campaign 沒有這三種完整證據，不能把五元組或同 UID telemetry 當成來源歸因 |
| 身份特徵 | 建立 participant rate、GUID churn、GUID↔IP 多重綁定、endpoint、topic diversity、ACL deny、authenticated binding、complete evidence 等 9 項特徵 | 所有輸出固定 development-only、`source_ip_attribution_verified=false`、`automatic_ip_block_authorized=false` |
| Session conformal | 以每場 session 的最大 nonconformity score 建參考分布；保守處理 ties；以 group hash 拒絕 calibration／holdout 重疊 | 現有校準 session 數不足，且歷史 validation 已用於開發，不能當獨立 final confirmation |
| 稽核工具 | 建立身份歸因資料盤點與 conformal 有限樣本解析度稽核；輸出存在時拒絕覆寫 | 工具只讀本機檔案，不解析新封包、不啟動 ROS、不送流量 |
| 回歸測試 | 新增 32 項 P2 測試；完整回歸 665 passed | 測試證明 fail-closed 契約，不等於 live／跨主機／kernel 驗收 |

## 2. 現有資料的身份歸因稽核

稽核範圍為 `firewall_lab/dataset_live`，只讀 manifest 與 Zeek header，未解析 PCAP、未建立連線。

| 指標 | 結果 |
|---|---:|
| Session 目錄 | 1,101 |
| `training_eligible=true` | 1,100 |
| 有 PCAP | 1,100 |
| 有 Zeek `conn.log` | 1,100 |
| 有 `rtps_identity.jsonl` | **0** |
| 有 `identity_attestation.json` | **0** |
| 有 `dds_security_audit.jsonl` | **0** |
| Zeek 同時含 GUID、entity、topic、identity subject 欄位 | **0** |

Zeek 現有欄位能描述 IP／port／bytes／packets 等五元組流量，不能證明某個 DDS
participant 的憑證身份、GUID、topic 與來源 IP 是同一個可信主體。同機 WSL mirrored
位址也不能建立唯一外部攻擊者歸因。因此目前固定：

- `source_ip_attribution_verified=false`
- `cross_host_test_ready=false`
- `autonomous_ip_block_ready=false`
- `deployment_eligible=false`

## 3. Conformal 有限樣本準備度

預先保留的顯著水準不放寬：normality `alpha=0.02`，至少需要 49 個校準 session；
known-attack `alpha=0.05`，至少需要 19 個校準 session。每場只貢獻一個 session maximum，
避免長 session 以大量相鄰 window 壟斷參考分布。

| 模式 | 分割 | Normal session | 尚缺 | Known-attack session | 尚缺 | 結果 |
|---|---|---:|---:|---:|---:|---|
| Permissive | registered calibration | 22／49 | 27 | 15／19 | 4 | blocked |
| Enforce | registered calibration | 25／49 | 24 | 18／19 | 1 | blocked |
| Permissive | calibration＋threshold 開發池 | 41／49 | 8 | 27／19 | 0 | blocked |
| Enforce | calibration＋threshold 開發池 | 44／49 | 5 | 30／19 | 0 | blocked |

合併 calibration＋threshold 只適合開發，因 threshold groups 已參與 binary threshold
selection；即使補到最低數量，也不是獨立 final test。若要形成新的乾淨部署證據，應另外
凍結每模式至少 49 場 normal 與 19 場 known attack 校準資料，再使用完全不重疊的 sealed
holdout。最低數量只解決 p-value 解析度，不保證模型召回率或誤報率達標。

## 4. 驗證結果

正確環境為 `Ubuntu-24.04`＋工作區 `.venv`。Canonical r3 稽核結果：

- Python 3.12.3；鎖版依賴 7／7 相符。
- 20／20 reproducibility checks verified。
- 完整回歸：**665 passed、0 failed、265 warnings**。
- warnings 來自載入既有 joblib 時的 NumPy 2.5 deprecation；不是 P2 測試失敗。
- `ros_started=false`、`network_or_attack_traffic_generated=false`、
  `firewall_state_changed=false`、`packages_installed=false`。

前兩次稽核也保留：第一次由系統 Python 啟動而鎖版檢查失敗；第二次進入錯誤 WSL
發行版而缺 ROS Jazzy。它們是環境路由診斷，不是 canonical 成果；r3 明確指定
`Ubuntu-24.04` 後全數通過。

## 5. 對專題進度的影響

P2 把兩個模糊風險改成可量測、可測試、會 fail closed 的工程契約，但尚未產生新的 live
身份證據或獨立校準資料。因此進度不灌水：

| 進度軸 | P2 後 |
|---|---:|
| 工程原型完成度 | 86%（86.40%） |
| AI 評審成熟度 | 86%（85.62%） |
| 房間級自動封鎖部署成熟度 | 38% |
| 保守專題總進度 | 67%（67.1%） |

## 6. 下一個真正會拉高部署進度的工作

1. 在隔離雙主機上配置受信任、唯讀 collector，保存 PCAP、decoder revision、SPDP／SEDP
   與 DDS Security audit sink。
2. 由獨立 attestation 將 GUID、endpoint、topic、identity subject 與觀測介面／來源 IPv4
   綁在同一個 session；不可由模型呼叫端自行聲稱「已驗證」。
3. 先補 development conformal 最低缺額（Permissive normal 8、Enforce normal 5）做方法
   除錯；正式評估另收乾淨、獨立且不重疊的校準與 sealed holdout。
4. 身份歸因、family-LOO、誤報上限、9／9 本機 outcome、真 nftables timeout／解除／重啟
   復原全部通過後，才可由 observe-only 進入人工批准 dry-run。

以上 live、跨主機、kernel 或 Raspberry Pi 操作仍須 Jesse 對當次拓樸、目標、時窗與
禁止事項另行授權。

## 7. 主要產物

- `firewall_lab/identity_attribution.py`
- `firewall_lab/identity_attribution_contract.v1.json`
- `firewall_lab/session_conformal.py`
- `工具腳本/audit_identity_attribution.py`
- `工具腳本/audit_conformal_readiness.py`
- `文件/P2_身份歸因資料稽核_2026-08-25.json`
- `文件/P2_Conformal準備度_2026-08-25/`
- `文件/可重現性稽核_2026-08-25_P2_verified_r3.json`
