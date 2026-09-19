# SROS2 Firewall Live Pilot Dataset Card

## 版本與用途

- 版本日期：2026-07-27
- 實驗環境：Windows + WSL2 Ubuntu 24.04、ROS 2 Jazzy、Gazebo、
  TurtleBot3 Burger、ROS domain 30
- 主要用途：驗證 Permissive／SROS2 Enforce 成對資料收集、PCAP→Zeek
  特徵管線與品質 gate
- 不適用：生產部署成效、實體機器人安全認證、企業規模模型最終評估

## 組成

主資料位於 `dataset_pilot/`，由 `campaign_pilot_20.json` 唯一指定：

| 項目 | 數量 |
|---|---:|
| 合格 live session | 20 |
| Permissive／Enforce | 10／10 |
| normal | 4 |
| 8 種攻擊 | 每類 2（每種模式各 1） |
| PCAP | 69,019,124 bytes |
| 封包 | 168,507，drop 0 |
| Zeek conn | 3,036 |
| 證據檔 | 252，全部通過 manifest SHA-256 |
| session／network feature rows | 20／80 |

攻擊類別為 command injection、identity abuse、message DoS、
parameter tamper、replay、replay DoS、sensor spoof、service DoS。
每個 session 有一段精確時間標籤、seed、強度、模式、policy hash、
PCAP、Zeek 輸出與程序證據。

另有 10 個重錄前 session 保留供稽核；它們不由完成後的 campaign
引用，且全部為 `training_eligible=false`。特徵建置預設跳過它們。

## 實驗條件

- Permissive 與 Enforce 都固定 domain 30，避免 RTPS port 直接洩漏模式。
- Enforce 使用未帶本專題憑證的攻擊程序，合法 Gazebo／應用節點使用
  個別 enclave。
- `security_mode` 表示受控實驗條件；它不應被當成逐封包的
  「已阻擋」真值。
- `group_id=session_id` 是強制切分單位；禁止把同一 session 的視窗
  分散到 train／validation／test。

## 品質與完整性

`verify_live_dataset.py` fail-closed 檢查：

1. campaign、manifest、scenario、seed 與模式一致；
2. `live_lab + complete + training_eligible=true`；
3. PCAP 非空且 SHA-256／byte count 與 manifest 相符；
4. dumpcap 任何層級 drop 都必須為 0；
5. Zeek 成功且 `conn.log` 至少一列資料；
6. 每個 session 恰有一段合法標籤，events sequence 連續；
7. 攻擊器不可含 traceback／executor shutdown 異常；
8. 未引用 session 必須不可訓練；
9. Permissive／Enforce 情境數必須平衡；
10. 文字證據不得出現私鑰或明文 secret/token 樣式。

正式結果見 `features_pilot/live_quality_report.json` 與
`features_pilot/live_dataset_index.csv`。

## 已知限制

- 每個攻擊目前只有一個 session／mode，無法支撐穩健的跨 seed、
  跨主機或統計顯著性結論。
- 只涵蓋 8 個 live runner；擴充合成集的其他 14 類攻擊仍沒有 live
  ground truth。
- 單一 WSL2／Gazebo 主機會帶入固定網路拓樸、硬體負載與模擬器特徵；
  模型必須用新主機／新日／新拓樸做外部 holdout。
- Zeek `conn.log` 是流量層第一版；尚缺完整 DDS Security handshake、
  participant identity 與 topic/service 語意特徵。
- 這批資料能證明資料鏈與短時間 Enforce 堆疊可運作，不能證明
  1,100-session 長時間穩定性或生產防護保證。

## 重現

```bash
python3 -m firewall_lab.verify_live_dataset \
  --dataset firewall_lab/dataset_pilot \
  --plan firewall_lab/campaign_pilot_20.json \
  --report firewall_lab/features_pilot/live_quality_report.json \
  --index firewall_lab/features_pilot/live_dataset_index.csv

python3 -m firewall_lab.features \
  --dataset firewall_lab/dataset_pilot \
  --output firewall_lab/features_pilot
```

所有紅隊 runner 僅限已獲授權的隔離 ROS 2 實驗環境。
