# SROS2 智慧防火牆：模型改善與 grouped-holdout 評估

日期：2026-08-03  
範圍：只做離線合成資料訓練與評估；未啟動 ROS、未送出攻擊流量、未修改防火牆。

## 結論

舊 network-only RandomForest 的 grouped-holdout balanced accuracy 為
`0.4212`。固定既有 session split、加入 18 個 telemetry 特徵、以
validation 選模並校準後，32 維 fusion ExtraTrees 在 final synthetic test
得到：

- balanced accuracy：`0.9392`
- macro-F1：`0.9359`
- macro one-vs-rest PR-AUC：`0.9485`
- attack recall：`0.9999`
- normal FPR：`0.00017`
- unknown-candidate IsolationForest recall：`0.7949`
- anomaly normal FPR：`0.0179`

但是 `deployment_eligible=false`。這些 telemetry 是由 feature-level 合成
profile 直接生成，高分不是 live ROS 2／SROS2 或跨主機證據，不能用來解鎖
自動封鎖 IP。

## 0.4212 的可修正原因

1. 舊訓練器只使用 14 個 DDS 網路統計，無法區分網路形狀相近、但 HMAC、
   SROS2、heartbeat 或 D1-D6 語意不同的攻擊。
2. 舊訓練器忽略資料集已固定的 `train/validation/test`，重新建立 80/20
   grouped holdout；雖然 session 沒有交疊，但沒有獨立 validation 可做選模、
   機率校準與拒答門檻。
3. normal 有 37,200 列，各攻擊類只有 2,400 列。新管線以 balanced class
   weights 比較 RandomForest 與 ExtraTrees。
4. 舊模型沒有獨立校準子集及全域 reject floor；新模型低於 validation-only
   門檻時只能告警，不能執行回應。

## 防資料洩漏協議

| 階段 | rows | sessions | 用途 |
|---|---:|---:|---|
| train | 63,000 | 1,750 | 擬合候選模型 |
| validation | 12,672 | 352 | 選模、校準、拒答門檻 |
| test | 14,328 | 398 | 固定後最終評估一次 |

- split 單位是完整 `group_id/session_id`，train／validation／test session
  overlap 為 `0`。
- 每個攻擊 session 可同時含正常前置視窗與攻擊視窗；整場仍只能落在一個
  split，不會把同場正常片段洩漏到另一邊。
- validation 再依 session 標籤組合拆為：校準 6,336 rows／176 sessions，
  門檻選擇 6,336 rows／176 sessions，兩者 session overlap 為 `0`。
- 候選模型只用 validation 指標選擇；test 不參與選模、校準或門檻調整。
- 本次正式訓練記錄 `test_prediction_passes=1`。
- unknown detector 只用 normal train 擬合；四類 candidate attack 沒有進入
  該 detector 的訓練或門檻選擇。

限制：這個 synthetic test 曾被早期本機 dry-run 抽樣使用，因此只能證明
本次訓練程式沒有拿 test 調參，不能宣稱它是整個專案從未看過的真正 blind
test。正式 live dataset 必須另行封存 untouched test。

## Validation 選模與消融

| 比較 | balanced accuracy | macro-F1 | normal FPR |
|---|---:|---:|---:|
| RandomForest balanced | 0.9312 | 0.9292 | 0.00720 |
| ExtraTrees balanced（選定） | 0.9439 | 0.9432 | 0.00152 |

相同 ExtraTrees、相同 session split 的特徵消融：

| 特徵 | 維度 | balanced accuracy | macro-F1 |
|---|---:|---:|---:|
| network-only | 14 | 0.4024 | 0.4309 |
| telemetry-only | 18 | 0.9430 | 0.9427 |
| fusion | 32 | 0.9439 | 0.9432 |

結果顯示提升幾乎完全來自合成 telemetry；fusion 相對 telemetry-only 的增益
只有約 `0.0009` balanced accuracy。這是必須揭露的 synthetic shortcut，
不能包裝成已證明真實網路＋遙測融合有效。

## Final test 與不確定性

| 指標 | 結果 |
|---|---:|
| balanced accuracy | 0.9392 |
| session bootstrap 95% CI | 0.9290–0.9455 |
| macro-F1 | 0.9359 |
| session bootstrap 95% CI | 0.9247–0.9422 |
| macro PR-AUC | 0.9485 |
| binary attack PR-AUC | 0.9999998 |
| ECE（10 bins） | 0.0241 |
| normal FPR | 0.00017 |

validation 選出的 reject floor 為 `0.50`。套用到 test 後，accepted attack
precision 為 `0.99988`、normal FPR 為 `0.00017`、正確 attack coverage 為
`0.9334`。低於門檻一律降級為 non-executable alert。

## 未知攻擊候選結果

IsolationForest 的 threshold 只由 normal validation 的 2% 分位決定；候選
攻擊未參與 threshold 選擇。

| candidate class | recall |
|---|---:|
| confused_deputy | 0.8776 |
| discovery_recon | 0.7839 |
| replay_dos | 0.8828 |
| sensor_spoof | 0.6354 |
| macro/pooled | 0.7949 |

`sensor_spoof` 仍是明顯弱點；正式 live 資料必須補強感測一致性、來源身分與
HMAC 拒絕事件，不能只靠網路流量 IsolationForest。

## 部署狀態與 artifact

- 32 features、23 classes、模型 HMAC 驗章與安全載入成功。
- `cross_host_admission._check_model` 正確回傳 `false`；即使數值門檻通過，
  synthetic tier 仍不能部署。
- 原始評估 artifact 綁定 action policy SHA-256：
  `158bafdd86e44a7ad4d469cd776eaed5dc9e276b2d44ddb5ec201dacd8d39951`；
  原模型 SHA-256 為
  `b160ea1814fe8724dba3e4362d91eaffbe4859a6fecd50f1cba8b24c91ac9145`。
- `temporary_block` 政策統一後，以 `policy_hash_only_repackage` 重封裝；新 policy
  SHA-256 為
  `11d056145f459df3328701c83fa8a5c7daa52a74070fc33511402a3c4eeb2dd2`，
  新模型 SHA-256 為
  `7550408d87706843fad94342f121907f5341d3e69b03dd5d57bf5e286bb8d5ae`。
- estimator fitted-state SHA-256 重封裝前後皆為
  `b6f2e8c99367a6d016c46233b826bcb5d14f09972f19cbf01618540916458638`。
- 64 個 train canary prediction SHA-256 重封裝前後皆為
  `7d9d478d625d27aeb1500ad3953743974c0004e2baf1e1ee505167355e7ec25b`。
- `training_metrics.json` 原檔與複本 SHA-256 皆為
  `407d9a281e32d6c0784b7a2684b4e08211bbff1355ed3e05b02c9ca9b0e503ee`；
  `test_prediction_passes` 保持 `1`，重封裝沒有重新計算 test prediction。
- 新 artifact 可通過 HMAC 與目前 action policy 完整性驗證，但仍維持
  `deployment_eligible=false`。

真正可以解鎖 deployment 的最低條件仍包括：validated live multimodal
contract、至少 1,100 個獨立 live sessions、23 類完整、final test 一次、
balanced accuracy／macro-F1 至少 0.80、unknown recall 至少 0.70、anomaly
FPR 不高於 0.05，以及外部跨主機與 backend admission 全部通過。
