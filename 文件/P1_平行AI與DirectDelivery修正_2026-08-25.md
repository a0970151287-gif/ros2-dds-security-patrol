# P1：平行 AI gate 與 direct-delivery 語意修正

日期：2026-08-25
狀態：**實作與離線驗收完成；AI 部署門檻未通過**
P0 checkpoint：`871f58b`

## 1. 結論

P1 修掉兩個真實工程缺陷，但沒有讓模型取得部署資格：

1. 階層 AI 不再以 binary 作為 OOD 的硬前置條件；每列都平行計算 binary、family、
   leaf、normality 與 known-attack OOD。binary miss 只有在 normal 與 known-attack
   兩個 reference 同時拒絕時才升成 unknown，避免 OOD 單獨把正常流量誤判成攻擊。
2. direct-delivery 不再把所有 Enforce 都預期成 zero delivery。預期結果改由 mode、
   credential、ACL permission、enclave 與 topic 共同決定；合法 Enforce control 應完整
   交付。
3. 既有 12 場重算為 12／12，但舊 archive 沒有獨立 pair／authorization attestation，
   所以結果仍是 provisional、non-deployable。
4. session-grouped leave-one-family-out 顯示現有 AI 特徵與 OOD scorer 仍無法泛化；
   四組設定全部未通過 0.70 unknown recall 與 0.05 known false-unknown 約束。

## 2. P1-A：AI 平行 gate

### 2.1 新決策契約

`parallel_binary_normality_attack_ood/v1` 的核心規則：

- normal：binary 不判 attack，且 normality 接受。
- unknown attack：known-attack OOD 拒絕，且 binary 判 attack 或 normality 也拒絕。
- binary attack、OOD 接受、family／leaf 可信且一致：known attack。
- 其餘 disagreement：abstain。
- 所有結果固定 `action=alert`、`adapter=none`、`executable=false`。

完整 8 種 boolean truth table 已鎖入單元測試。known-attack OOD 單獨拒絕不能把
normal 變成 attack，因為 normal 本來就應該在 known-attack distribution 之外。

### 2.2 family-LOO 協定

評估器對每一 fold：

1. 以整場 session 為單位抽掉一個 response family。
2. train split 擬合；validation threshold groups 定門檻；selection groups 量 reference。
3. 官方 novelty holdout session 使用 0 列，test 使用 0 列。
4. 分別量 binary recall、parallel unknown recall、binary-miss recovery、normal false
   unknown 與 known-attack false unknown。

### 2.3 實測結果

| mode | scorer | macro unknown recall | worst family | worst normal false unknown | worst known false unknown | 通過 |
|---|---|---:|---:|---:|---:|---|
| Permissive | IsolationForest | 0.1352 | 0.0179 | 0.0000 | 0.0833 | 否 |
| Permissive | Mahalanobis | 0.2182 | 0.0000 | 0.0000 | 0.2500 | 否 |
| Enforce | IsolationForest | 0.1049 | 0.0229 | 0.0824 | 0.1037 | 否 |
| Enforce | Mahalanobis | 0.1822 | 0.0146 | 0.0784 | 0.2519 | 否 |

binary-miss recovery 在 12 個 fold 中有 11 個為 0；唯一非零 fold 也只有 0.00625。
因此先前的 hard gate 是程式缺陷，但不是低 unknown recall 的唯一原因。現有 148 維
特徵對 quiet／被 SROS2 上游擋掉的 family 缺乏可分證據，不能靠改 if/else 解決。

## 3. P1-B：direct-delivery v2

### 3.1 修正後預期矩陣

| mode | credential | ACL | expected |
|---|---|---|---|
| Permissive | security disabled | not enforced | full delivery |
| Enforce | valid | allow | full delivery |
| Enforce | absent | not reached | zero delivery |
| Enforce | invalid | not reached | zero delivery |
| Enforce | valid | deny | zero delivery |

contract 會拒絕 credential／ACL／authorization case 互相矛盾，以及 enclave 或 topic
與 archive binding 不一致的輸入。混淆矩陣以「policy expected zero/full」為 ground
truth，不再以 Enforce／Permissive 直接代替正負類。

### 3.2 既有 12 場 canonical r3

- 6 reconstructed pair、12 session、120 canary。
- TP 30、FN 0、FP 0、TN 90；balanced accuracy 1.0。
- 12／12 session 符合修正後預期。
- `all_pairings_attested=false`。
- `publisher_authorization_contexts_all_attested=false`。
- `deployment_eligible=false`。

舊 runner 的 P／E 使用不同 trial id，pair map 只能依固定執行順序重建；credential 與
ACL 也沒有獨立簽章 attestation。上述兩項限制留在 aggregate，不得從報告刪除。

### 3.3 未來 runner 修正

- 移除 `rm -rf`；每輪建立新的 UTC evidence 目錄，拒絕覆寫。
- 同一 seed／publisher case 的 P／E 使用相同 trial id，可由兩端 archive 自行證明 pair。
- credentialed source 的 archive enclave 改與真 `/talker` enclave 一致。
- payload 使用 deterministic `trial_id:sequence`，aggregate 以已驗證的 normalized
  stimulus 配對。

## 4. 測試與證據

- 完整回歸：**633 passed、0 failed、265 warnings**。
- P0 的 3 個 FrozenEstimator sample-weight warning 已消除；既有 base estimator 已用
  session-equal weights 擬合，FrozenEstimator 後的 weights 明確只用於 sigmoid
  calibrator。剩餘 265 個 warning 是載入既有 joblib 時的 NumPy 2.5 deprecation。
- P1 reproducibility audit：12／12 verified。
- P1 evidence ledger：3 verified、2 provisional、1 blocked，`valid=true`，ledger
  SHA-256 `0be257c0fed29756c7bfaba611c06926362be350e1807fcb9f3e7d248b3d8f2b`。
- 本輪未啟動 ROS／Gazebo、未產生攻擊或網路流量、未呼叫 sudo／nftables、未開啟任何
  executable class。

## 5. P1 後的正確狀態

P1-B 的 verifier 與未來 runner 可視為工程完成；既有 12 場行為重算可作 provisional
evidence。P1-A 的程式契約完成，但模型 acceptance failed。下一階段不得再靠放寬 threshold
追分，應優先加入封包層 RTPS／DDS identity 與可驗證 source attribution，並做 session-level
conformal calibration。房間級自動封鎖仍 blocked。
