# SROS2 智慧防火牆資料工廠

這個目錄是專題的新主軸：以 SROS2 作為預防層，再用 Zeek／ML 判斷已知攻擊與未知異常，最後只把高信心結果映射到受限制的防禦動作。紅隊腳本在這裡只是隔離實驗室內的資料產生器，不是產品本體。

## 目前基準（2026-08-25）

- 正式 Gazebo live campaign：**1,100／1,100 complete**，Permissive／Enforce 各 550。
- 候選資料：排除一場封存後仍增長的 session，實際 **1,099 場**；300 場 corrective
  rerun 在特徵層替換舊缺陷資料，不重複計數。
- 特徵：14 個 DDS network＋18 個 ROS／SROS2 telemetry 原始特徵，展開為 148 個
  causal temporal feature；其中 5 個 telemetry 來源仍不可用或恆零。
- 一次性測試結果：Permissive balanced accuracy 0.8619、macro-F1 0.8630、binary
  PR-AUC 0.9900；Enforce balanced accuracy 0.4155、binary PR-AUC 0.9774。
- 乾淨 whole-model open-set recall：Permissive 0.5499、Enforce 0.6583，皆低於 0.70。
  2026-08-25 Mahalanobis 結果是 experimental／non-deployable，不能覆蓋這組正式數字。
- 完整離線回歸：**615 passed、0 failed、268 warnings**。
- 所有候選維持 `deployment_eligible=false`、`executable=false`；出貨政策
  `executable_classes=[]`，不得解讀成已可自動封鎖 IP。

## 要解決的問題

模型需要學到「DDS 行為是否異常」，不能只記住某個 IP、domain、固定流量或攻擊腳本。資料工廠因此強制：

- 每個 session 有獨立 `session_id`、seed、SROS2 模式、政策雜湊及精確攻擊時間區間。
- Permissive 與 Enforce 都使用 ROS domain 30，避免 RTPS port 洩漏實驗組別。
- train/test 以 `group_id=session_id` 分組，禁止同一場實驗的相鄰視窗跨到兩側。
- smoke 資料永久為 `training_eligible=false`，只測管線，不得餵模型。
- live 資料只有在 PCAP 非空且 Zeek 成功解析後才可訓練。
- scenario 檔只能引用固定 runner 名稱，不能放 shell command。
- 模型只輸出「防禦意圖」；低信心、未知類別及分類器／異常模型意見衝突時，不自動執行。

## 資料流

```text
Gazebo / ROS2 / DDS
        │
        ├─ session manifest + 精確攻擊標籤 + 資源快照
        └─ dumpcap (固定 DDS UDP filter) → PCAP → Zeek conn.log
                                                  │
                                                  ▼
                                  8 秒 network feature windows
                                                  │
                     session-grouped binary → family → leaf + parallel OOD
                                                  │
                                                  ▼
                              信心門檻 → allowlisted 防禦意圖
```

目前決策 adapter 包含 SROS2 identity／ACL、`velocity_guard`、HMAC 驗證及受管制的 network helper。推論程式不會直接執行任意命令。

## 四種資料狀態

| 狀態 | 用途 | 可訓練 |
|---|---|---|
| `simulated_smoke` | 驗證 manifest、標籤、特徵及批次流程 | 否，程式硬性拒絕 |
| `synthetic_pretrain` | 大量原型預訓練與資料管線開發 | 可預訓練；不可作正式評估 |
| `live_lab`，無有效 PCAP／Zeek | 排錯與證據保留 | 否 |
| `live_lab`，PCAP 非空且 Zeek 成功 | 正式 ROS2/DDS 模型資料 | 是 |

「攻擊程式有跑」本身不等於資料合格；正式成效必須通過最後一列的 gate。合成資料的 `evaluation_eligible` 永遠是 false，訓練器也要求用 `--data-tier synthetic-pretrain` 明確選擇，避免誤當 live 資料。

## 已完成的 1100-session campaign

正式 campaign 已完成，固定計畫為：

| 情境 | 數量 | Permissive | Enforce |
|---|---:|---:|---:|
| 正常巡邏 | 300 | 150 | 150 |
| 8 種攻擊情境，各 100 | 800 | 400 | 400 |
| 合計 | 1100 | 550 | 550 |

涵蓋未授權 participant、`/cmd_vel` 注入、sensor spoof、參數竄改、oversized scan、parameter service flood，以及兩種 HMAC replay。每個情境的強度和 seed 都會記錄，兩種 SROS2 模式必須分開執行，不能同時共用 domain 30。

建立或重建計畫：

```bash
cd ~/ros2_ws
python3 -m firewall_lab.campaign plan \
  --output firewall_lab/campaign_1100.json \
  --normal-sessions 300 \
  --attack-sessions-per-scenario 100 \
  --seed 20260727
```

## 歷史基準：已完成的 20-session live pilot

`campaign_pilot_20.json` 已在本機隔離的 Gazebo／ROS2 domain 30
完成一輪成對 live 擷取：

- 20 個主 session：Permissive 10、SROS2 Enforce 10；
- 4 個 normal session；8 種攻擊各 2 個（每種模式各 1）；
- 69,019,124 bytes PCAP、168,507 個封包、capture drop 0；
- Zeek `conn.log` 共 3,036 列、252 個證據檔均通過 SHA-256；
- 20/20 為 `live_lab + training_eligible=true`；
- 10 個重錄前的瑕疵 session 保留供稽核，但全部為
  `training_eligible=false`，特徵建置時自動跳過；
- 產生 20 列 session features 與 80 個 8 秒 network windows。

同一個 parameter-service flood 在 Permissive 實際形成 8,553 次請求
（約 713 req/s），Enforce 組只形成 12 次嘗試（約 1 req/s），可作為
SROS2 開關前後的成對 pilot 證據。這仍是小型 pilot，不足以取代
1,100-session 正式資料或生產環境長時間驗證。詳細使用邊界見
[`LIVE_PILOT_DATASET_CARD.md`](LIVE_PILOT_DATASET_CARD.md)。

可重跑的 fail-closed 驗證與特徵建置：

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

驗證器會拒絕計畫／manifest 不一致、PCAP 空白或重複、dumpcap 丟包、
Zeek 無資料、標籤錯位、證據雜湊不符、攻擊器 traceback、秘密樣式外洩，
以及任何未被 campaign 引用卻仍標記為可訓練的 session。

## 已產生的擴充合成預訓練集

目前本機 `firewall_lab/pretrain_dataset/` 以 1100-session live 計畫為基礎，再加入對應既有紅隊報告的 synthetic-only 情境：

- 2500 個獨立 session；
- 90,000 個 8 秒視窗；
- 23 類：normal 加 22 類攻擊；
- 45,000 個 Permissive 視窗及 45,000 個 Enforce 視窗；
- 63,000 train、12,672 validation、14,328 test；
- 1100 個 live-runner-backed sessions，1400 個 synthetic-only sessions；
- 0 個跨 split session、0 個精確重複特徵列；
- 所有資料均固定 domain 30，避免 RTPS port 洩漏實驗組別。

新增攻擊包含 discovery recon、SPDP flood、節點名稱規則繞過、開機基準汙染、mission／health spoof、`cmd_vel` race、scan drift、odom spoof、node churn、verify flood、跨頻道轉貼、HMAC 偽造及 confused deputy。這些情境對應既有 N2、N4、N5、N7–N11、N13、N18、N20 與 Zeek 威脅方向。

重新產生與驗證：

```bash
python3 -m firewall_lab.synthetic_dataset \
  --plan firewall_lab/campaign_1100.json \
  --output firewall_lab/pretrain_dataset \
  --windows-per-session 36 \
  --window-sec 8 \
  --split-seed 20260727 \
  --extra-sessions-per-scenario 100 \
  --overwrite

python3 -m firewall_lab.synthetic_dataset \
  --output firewall_lab/pretrain_dataset \
  --verify-only
```

主要檔案：

| 檔案 | 用途 |
|---|---|
| `network_features.csv` | 90,000 列、14 個 DDS 網路特徵、label、split 與來源層級 |
| `fusion_features.csv` | 同 90,000 列，再加入 18 個 SROS2／HMAC／ROS telemetry 特徵 |
| `session_index.csv` | session、seed、攻擊強度、SROS2 模式與 split |
| `class_distribution.csv` | 每類／模式／split 的列數與 session 數 |
| `quality_report.json` | 14 項品質 gate、特徵範圍與分布統計 |
| `dataset_card.json`／`DATASET_CARD.md` | 使用邊界與可重現參數 |
| `checksums.json` | 六個資料檔的 SHA-256 與 byte count |

## 先跑無風險 smoke

```bash
cd ~/ros2_ws
python3 -m firewall_lab.orchestrator \
  --mode smoke \
  --scenario all \
  --sessions 90 \
  --seed 20260727 \
  --output firewall_lab/demo_dataset

python3 -m firewall_lab.features \
  --dataset firewall_lab/demo_dataset \
  --output firewall_lab/demo_features \
  --include-nontrainable
```

這會產生 90 個 session 和 1080 筆 smoke observation，但都保留 `training_eligible=false`。

## 正式 live campaign

只在你擁有且隔離的 ROS2 實驗網路執行。先用 `dumpcap -D` 找到只承載本實驗流量的介面；擷取器已固定為 `udp portrange 7400-15200`，但仍應避免共用一般上網介面。

正式啟動前先執行被動、fail-closed preflight。它不啟動 Gazebo、不發 ROS
訊息、不擷取封包，也不執行攻擊；共享介面 `any`、未凍結的 Git 版本、
過期 scenario catalog、磁碟不足或拓樸宣告不一致都會回傳 `BLOCKED`。

同機 loopback 資料只能宣稱 local-adversary evidence：

```bash
export ROS_LOCALHOST_ONLY=1
python3 -m firewall_lab.formal_preflight \
  --plan firewall_lab/campaign_1100.json \
  --dataset firewall_lab/dataset_live \
  --capture-interface lo \
  --topology same_host_loopback \
  --isolation-ack I_CONFIRM_LOCALHOST_ONLY
```

真正隔離、且全部設備與介面均為自己所有的跨主機實驗，才改用：

```bash
python3 -m firewall_lab.formal_preflight \
  --plan firewall_lab/campaign_1100.json \
  --dataset firewall_lab/dataset_live \
  --capture-interface <isolated-interface> \
  --topology isolated_cross_host \
  --isolation-ack I_CONFIRM_OWNED_ISOLATED_LAB
```

只有報告為 `READY` 才能進入下列執行步驟；preflight 不會替使用者猜測
網段所有權，也不會把同機證據升格成跨主機防火牆證據。

Enforce 組：

```bash
cd ~/ros2_ws
bash 展示指令/01c_啟動系統_enforce.sh

# 另一個終端；先用少量 session 驗證
python3 -m firewall_lab.campaign run \
  --plan firewall_lab/campaign_1100.json \
  --dataset firewall_lab/dataset_live \
  --security-mode enforce \
  --capture-interface <lab-interface> \
  --limit 10 \
  --minimum-free-gib 8 \
  --confirm-isolated-lab
```

本機 Permissive 組改用 `展示指令/01_啟動系統.sh`，跨主機實驗才使用
`01b_啟動系統_跨主機.sh`，並把 `--security-mode` 改成
`permissive`。執行器有 resume 狀態；成功後才把該 entry 改為
`complete`。失敗 entry 必須排除原因後以 `--retry-failed` 明確重試。
執行器也會在每個 session 開始前重新檢查磁碟；可用
`--minimum-free-gib` 設定保留空間（預設 8 GiB）。若空間不足，下一個
entry 會保持 `pending`，不會建立半套 session，排除容量問題後可直接續跑。

正式擴大量前，先確認：

1. 啟動腳本的 readiness 成功。
2. `dumpcap` 可由非 root 帳號使用，且選到隔離實驗介面。
3. `zeek` 在 PATH 或 `/opt/zeek/bin/zeek`。
4. 第一批 session 的 `manifest.json` 為 `complete` 且 `training_eligible=true`。
5. Permissive 與 Enforce 都完成相同情境，不以不同 domain、IP 或固定執行順序洩漏標籤。

正式 1,100-session preflight 另有 `live_multimodal_contract` fail-closed
閘門。2026-08-03 已完成 secret-free raw event schema、單一 writer collector、
`session_id + window` 對齊、`telemetry_features.csv`／`fusion_features.csv`
builder，以及缺 tick／缺視窗即拒絕的品質測試。ROS callback 現在透過本機
Unix datagram 非阻塞 producer 接到 session collector；涵蓋 HMAC 驗證結果、
D1–D6 incident/recovery、authenticated heartbeat gap/recovery、ROS graph
fault/overflow/recovery。SROS2 deny adapter 只輸出 authentication／permission／
governance 類別與計數，不保存原始 log、憑證、路徑或身分內容。orchestrator
會為每個 live session 啟動單一 collector，沒有 tick 與至少一筆真實 runtime
event 時維持 `training_eligible=false`。

正式契約仍維持 `blocked`：上述接線只通過離線與本機 socket 單元測試，尚未
重建並啟動 ROS stack 做 loopback live pilot，也尚未用本機實際 RMW vendor
輸出的 SROS2 deny log 校準 pattern。不得用測試 fixture 冒充 live telemetry
完成。這可避免收完大量 PCAP 後，才發現資料無法回答多模態融合的研究問題。

本機 producer 可先把下列固定 schema JSONL 經 stdin 送進 collector；collector
只接受 allowlisted event type 與數值，不接受 secret、command 或任意 feature
名稱：

```bash
python3 -m firewall_lab.live_telemetry_collector \
  --session-id <session_id> \
  --source telemetry_collector \
  --output <session_dir>/telemetry_events.jsonl \
  --input <producer_events.jsonl>
```

正式特徵建置必須加 `--require-multimodal`；任何 eligible live session 缺少
telemetry stream、collector tick、同窗覆蓋或有限數值都會 fail closed：

```bash
python3 -m firewall_lab.features \
  --dataset firewall_lab/dataset_live \
  --output firewall_lab/features \
  --require-multimodal
```

Runtime stack 由 `firewall_lab/live_stack.sh` 設定
`SROS2_FIREWALL_TELEMETRY_SOCKET`；ROS 節點不直接寫 evidence file，collector
才是唯一 writer。socket 不存在或接收佇列已滿時 producer 只增加本機 drop
counter 並立即返回，不能阻塞控制 callback。事件 datagram 上限 4096 bytes，
而且只接受固定 schema；任意 detail、secret 欄位與 producer 偽造的
`collector_tick`／`log_reject` 都會被拒絕。

## 建立特徵與訓練

```bash
python3 -m firewall_lab.features \
  --dataset firewall_lab/dataset_live \
  --output firewall_lab/features

python3 -m firewall_lab.train \
  --features firewall_lab/pretrain_dataset/network_features.csv \
  --output firewall_lab/model_pretrain \
  --data-tier synthetic-pretrain
```

正式的三段 session-grouped 選模／校準管線使用：

```bash
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
python3 -m firewall_lab.grouped_training \
  --features firewall_lab/pretrain_dataset/fusion_features.csv \
  --output .codex_tmp/model_improvement_20260803/final_evaluation \
  --data-tier synthetic-pretrain \
  --feature-set fusion \
  --n-estimators 200 \
  --bootstrap-samples 200 \
  --final-evaluate-test
```

此管線尊重資料集既有 `train/validation/test` session split；validation
再拆成互斥的校準與 reject-threshold sessions，test 只在模型固定後預測
一次。合成資料無論分數多高都維持 `deployment_eligible=false`。

若 response action policy 只改動處置語意、分類特徵與標籤完全不變，使用
可稽核的 hash-only repackage；不得重新訓練或重跑 test：

```bash
python3 -m firewall_lab.rebind_model_policy \
  --source-model .codex_tmp/model_improvement_20260803/final_evaluation/firewall_model.joblib \
  --output-model .codex_tmp/model_improvement_20260803/final_rebound_temporary_block/firewall_model.joblib \
  --action-policy firewall_lab/action_policy.json \
  --metrics .codex_tmp/model_improvement_20260803/final_evaluation/training_metrics.json \
  --canary-csv firewall_lab/pretrain_dataset/fusion_features.csv \
  --report .codex_tmp/model_improvement_20260803/final_rebound_temporary_block/policy_rebind_report.json \
  --copy-artifact .codex_tmp/model_improvement_20260803/final_evaluation/split_manifest.json \
  --copy-artifact .codex_tmp/model_improvement_20260803/final_evaluation/MODEL_CARD.md
```

報告必須同時證明 estimator fitted state、非 test canary prediction、完整
metrics bytes 與 deployment eligibility 都沒有改變，並記錄舊／新 policy
SHA-256 與新 HMAC 驗章結果。

上面只會得到 prototype model；正式 live 模型應改用 `firewall_lab/features/network_features.csv` 與預設的 `--data-tier live`。

訓練器會拒絕：

- `training_eligible` 不全為 true；
- NaN／Infinity；
- 少於 20 個 network windows；
- 沒有 normal 或只有單一類別；
- 任一類別少於兩個獨立 session，無法做防洩漏 holdout。

輸出的 `firewall_model.joblib` 會附 HMAC sidecar。推論端以 `verified_joblib_load` 驗章，並核對模型 schema 與完整 feature 順序。

## Session 證據

每個 session 至少包含：

```text
<session_id>/
├─ manifest.json
├─ events.jsonl
├─ labels.jsonl
├─ resources.jsonl
├─ traffic.pcapng          # live + capture
├─ zeek/conn.log           # live + Zeek 成功
└─ attack/capture logs
```

manifest 最後會列出證據檔 SHA-256；秘密樣式欄位會被遮蔽，證據收集器也拒絕 symlink。

## 尚未假裝完成的部分

- 20-session PCAP／Zeek pilot 已完成原有品質 gate；它早於 runtime telemetry
  接線，不是多模態 loopback pilot，也不能當成即時事件驗收或企業規模資料。
- 目前的 90,000 列是 feature-level 合成預訓練資料，不是原始 PCAP，也不是 live 評估集。
- 14 種新增攻擊目前是 synthetic-only；在有對應安全 runner 與 live 標籤前，不得宣稱已完成真實回歸。
- 合成 `fusion_features.csv` 與 live builder／quality gate 已完成；live producer
  靜態接線已完成，但 ROS loopback pilot 尚未完成。現行原型訓練器仍以 14 個 network
  features 為主，fusion 模型要等合格 live telemetry 後再接。
- `live_stack.sh`／`live_campaign.sh` 已能管理單一模式與批次，但模式切換
  仍是明確的兩階段操作，尚未做無人值守的長時間排程。
- Zeek `conn.log` 是第一批網路特徵；後續應加入 SPDP participant、DDS Security handshake、topic／service 語意與主機行為特徵。
- network helper 目前只應在 dry-run 或人工核准下使用；模型輸出不能直接變成任意防火牆命令。
- 應另外保留「從未參與訓練的新攻擊」作最終 unknown-attack 測試，不能把所有 PoC 都放進訓練集。

## 外部紅隊開始前

先建立唯讀防禦基準；這支工具沒有 target 參數，並硬性拒絕
Metasploit、掃描器與 ROS publisher：

```bash
source /opt/ros/jazzy/setup.bash
cd ~/ros2_ws
python3 -m firewall_lab.blue_team_readiness
```

SROS2 Enforce live stack 已啟動並通過 readiness 後，正式測試改用：

```bash
python3 -m firewall_lab.blue_team_readiness \
  --require-live-enforce \
  --require-capture
```

輸出存於 `firewall_lab/readiness_evidence/`，明確標成
`training_eligible=false`，只用來證明攻擊前防禦狀態，不得混入模型訓練。
給外部 Claude／攻擊機的唯一交接格式見
`紅隊測試/CLAUDE_METASPLOIT_任務.md`。

即時 Zeek 在沒有受限 capture capability 時會 fail closed；不要為此使用
root 啟動整個 Zeek。共用網路上的同機測試只允許兩個固定 capture
profile，不能從環境傳入任意 BPF：

```bash
# R02/R03：只保存 localhost TCP，不離開主機
bash firewall_lab/blue_team_capture.sh start loopback_tcp

# R04/R05：只保存 domain 30 的 RTPS UDP
bash firewall_lab/blue_team_capture.sh start dds_domain30

bash firewall_lab/blue_team_capture.sh status

# 每個案例結束後立即停止、雜湊並離線分析
bash firewall_lab/blue_team_capture.sh stop
bash firewall_lab/blue_team_capture.sh analyze
```

兩者最多約 200 MiB、預設 15 分鐘後自動停止；`analyze` 固定以
`DOS_BLOCK_ENABLED=F` 做離線 Zeek 分析，不會改防火牆。

## 跨主機防禦准入門檻

### Backend 離線 acceptance（不是 production 證據）

新 backend 以 Ed25519 公鑰驗票、SQLite 原子消耗 nonce，並把 desired
timeout state 與 audit 持久化。先用以下命令驗證程式邏輯：

```bash
# 預設模式：production adapter 保持停用，命令以 blocked（exit 2）結束
python3 -m firewall_lab.backend_acceptance \
  --output <new_evidence_directory>

# 明確要求 fake timeout set；只產生 simulation-only 證據
python3 -m firewall_lab.backend_acceptance \
  --adapter in-memory \
  --output <new_simulation_evidence_directory>
```

每次輸出 `acceptance_events.jsonl`、SQLite state、`summary.json` 與
`summary.json.sha256`。可程式化重算檔案 hash、JSONL 筆數、DB integrity、
row counts 與容量 metadata：

```python
from firewall_lab.backend_acceptance import verify_backend_acceptance

offline = verify_backend_acceptance("<dir>/summary.json")
production = verify_backend_acceptance(
    "<dir>/summary.json", purpose="production_admission"
)
```

`in_memory_timeout_set` 報告永遠標記 `simulation_only=true`、
`production_admission_eligible=false`；production purpose 必定拒絕，而且這個
report schema 也不能傳給跨主機准入器的 `--backend-report`。SQLite 預設最多
100,000 筆 consumed tickets 與 200,000 筆 audit；額滿時 fail closed，不能
自動刪除關鍵稽核。保留策略是停止 signer、等待短效票證全部過期、人工封存整個
DB，再由管理者建立新 DB。

### Production nftables service 骨架（仍預設停用）

`nft_backend_service.py` 已把 production 邊界固定為：

- 只執行 `/usr/sbin/nft`，固定 argv 或 stdin transaction，`shell=False`；
- 只管理 `inet sros2_ticket_guard` 的 `blocked_ipv4` timeout set；
- chain 固定在 `input` hook，目前證據邊界是「保護執行 backend 的單一主機」；
  它不是 router/gateway 的 `forward` 或 `egress` 規則，不可誤寫為整個房間網路已被邊界防火牆保護；
- set 固定 1,024 筆、每筆最多 300 秒，chain/rule 名稱及內容必須完全相符；
- privileged service 只提供 `handle_ticket(ticket)`／`apply --ticket-stdin`，沒有
  raw IP 或 TTL 參數；
- action policy、catalog、authorizer、ticket 與 drop adapter 已統一為簽章
  `temporary_block`；adapter 會拒絕任何其他 action，不做隱性語意升級；
- 授權與保護範圍只接受正規化 RFC1918 IPv4 `/24`–`/30`，且
  `protected_sources` 必須是 `authorized_sources` 的子網段；公網、過寬、
  host `/32`、loopback、link-local 或 multicast 範圍一律拒絕；
- 非 root、缺設定、disabled config、mock runner、規則漂移、JSON 版本差異、
  snapshot/reconcile 不一致一律 fail closed；
- 狀態目錄 `/var/lib/sros2-firewall/` 必須預先由 root 建立且為
  `0700`；SQLite DB、`-wal`、`-shm` 必須為 root-owned regular file 且
  精確 `0600`，服務進程必須以 `UMask=0077` 啟動，不符即 fail closed；
- 不會自動建立 table/rule，也沒有安裝、sudoers 或啟用命令。

檢入的 `nft_backend_config.disabled.json` 為 `enabled=false`。真正啟用前，固定
`/etc/sros2-firewall/` 路徑還必須放入 root-owned 設定、公鑰及
`sros2-firewall-nft-live-acceptance/v1` 報告。離線 mock 只能產生
`sros2-firewall-nft-mock-acceptance/v1`、`simulation_only=true` 的報告，不能
被 service 或跨主機准入器採納。

目前仍保留 live blocker：目標主機的實際 nft 版本／JSON schema、核心 timeout
自動到期、真實封包 drop、容量滿載、root-owned `0700/0600` 狀態邊界、
`UMask=0077` 及重啟復原尚未在隔離主機驗收。官方 nft
語法允許 timeout set、固定 size 與 per-element timeout，但 mock 無法證明目標
核心與 userspace 版本完全相容。

為避免「production service 要求 live report，但 service 本身尚未開門」的卡死，
可先輸出不修改防火牆的 bounded acceptance 計畫：

```bash
python3 -m firewall_lab.nft_backend_service plan-live-acceptance
```

這個指令只輸出 JSON 計畫，明確標記 `live_executor_implemented=false`、
`production_ready=false`，不會呼叫 root 或 nft。真實 executor 仍尚未實作；
它必須另行 code review，並只能在兩台自有、無 default route 的隔離主機上，
由人工輸入 `BEGIN_OWNED_ISOLATED_NFT_LIVE_ACCEPTANCE` 後執行一個來源、
最多 30 秒的簽章 `temporary_block` 案例。真實報告審核並將 SHA-256 釘入
root-owned enablement 後，還要另做一次 code review 才能將
`LIVE_NFT_ACTIVATION_ALLOWED` 改為 true。目前任何 mock/config 都無法自行開門。

跨主機前先執行被動准入檢查；此命令不啟動 ROS、不送封包、也不修改防火牆：

```bash
python3 -m firewall_lab.cross_host_admission \
  --model <signed_live_model.joblib> \
  --local-outcomes <local_defense_outcomes.json> \
  --backend-report <response_backend_recovery.json> \
  --topology <isolated_topology.json> \
  --report <cross_host_admission.json>
```

准入器分開輸出 `static_defense_ready`、`cross_host_test_ready` 與
`autonomous_ip_block_ready`。任何證據缺失時，`effective_mode` 固定為
`observe_or_dry_run_only`。必要條件包括：

- 23 類資料標籤、action policy 與 adapter 語意完全一致；
- SROS2 policy 無 wildcard、final `/cmd_vel` 只有 guard 可發布，guard 可直接驗證 heartbeat；
- IP 封鎖需新鮮連續兩個視窗、可信來源綁定、至少兩個獨立訊號、明確授權範圍，且不得為共享 IP；
- 模型必須是 live data tier、與 action policy hash 綁定、完整覆蓋 23 類，且達到固定品質門檻；
- 回應 backend 必須使用 kernel-managed timeout set、有容量上限、可稽核，並有程序重啟與自動解封證據；
- 本機先證明正常流量保留、SROS2 deny、HMAC/replay/input drop、參數未變、guard 歸零與恢復；
- 攻擊端與目標端必須是不同、皆自有、無 default route／Internet 的隔離主機。

Zeek 現在只產生偵測與 suppressed response request；即使把舊
`DOS_BLOCK_ENABLED` 打開，也不會直接呼叫 privileged helper。所有 live IP 動作必須先經
`ResponseAuthorizer`，避免來源 IP spoof、NAT 或同 IP 多 participant 造成誤封。

## 2026-08-17：分層 AI、開發期比較與證據工具

### 分層候選模型

`hierarchical_training.py` 建立的 v2 候選將判斷拆成 binary attack、
response family、family-conditioned leaf 及 OOD；148 項因果時序特徵只使用
目前與過去視窗。候選會綁定 data policy、action policy、程式與套件版本，
但目前固定：

```text
deployment_eligible=false
independent_final_test=false
test_prediction_passes=0
executable=false
adapter=none
```

正式 raw dataset 不會被改寫。`dataset_exclusions.v1.json` 只以外部 registry
釘住一筆封存後仍變動的 Enforce session；候選資料為 1,099 sessions。

### Development-only 公平比較

`development_evaluation.py` 只能使用 frozen train／selection／calibration／
threshold session contract；它不存取、轉換、回傳或預測歷史 test 的 label／
feature，也不保存 estimator。輸出目錄若存在會拒絕覆寫。

```bash
python3 -m firewall_lab.development_evaluation \
  --features firewall_lab/features_per_mode/fusion_features_permissive.csv \
  --contract-metrics <hierarchical-candidate>/permissive/training_metrics.json \
  --security-mode permissive \
  --bootstrap-replicates 200 \
  --output <new-development-output-directory>
```

預設比較 3 個 task、5 個 feature view 與 5 個 sklearn model，共 75 組／模式，
並輸出 session-bootstrap 95% CI、per-class metrics、ECE、Brier、P50／P95
inference time 及 observed RSS delta。這些值是 development validation，不能當
independent final test、Pi benchmark 或部署資格。

### SROS2 direct-delivery 證據驗票

`sros2_delivery_evidence.py` 不會啟動 publisher／subscriber，也不會發封包；
它只驗證已收集的雙端 JSONL 與 contract：

```bash
python3 -m firewall_lab.sros2_delivery_evidence verify \
  --contract <delivery-contract.json> \
  --output <new-verification-report.json>

python3 -m firewall_lab.sros2_delivery_evidence aggregate \
  --contract <paired-permissive-contract.json> \
  --contract <paired-enforce-contract.json> \
  --output <new-aggregate-report.json>
```

驗票器會重新計算 attempt／receipt sequence、collector heartbeat、bytes／SHA-256、
session、mode、policy、source、enclave、topic 與 UTC window。Vendor security log
不是 delivery ground truth；缺少 archive 時只能標 blocked，不能補造 live pass。
所有輸出固定 `source_ip_attribution_verified=false`、`deployment_eligible=false`、
`executable=false`。

### 專案證據總帳與可重現性

`project_evidence.py` 只接受 `verified`、`provisional`、`blocked` 三種主張。
`verified` 必須引用非空、repo-relative、非 symlink 的 artifact，且 bytes／SHA-256
完全一致；ledger JSON 與 Markdown 原子發布並拒絕覆寫。它是證據 inventory，
不是簽章、runtime 授權或 live firewall acceptance。

```python
from firewall_lab.project_evidence import (
    generate_evidence_ledger,
    verify_evidence_ledger,
)

generate_evidence_ledger(
    "firewall_lab/project_claims_20260817.json",
    ".",
    "<new-ledger-directory>",
)
verify_evidence_ledger("<ledger-directory>/evidence_ledger.json", ".")
```

被動重現性稽核不安裝套件、不啟動 ROS、不送流量：

```bash
python3 工具腳本/verify_reproducibility.py --pretty

# 只有明確要求時才呼叫既有完整測試 runner
python3 工具腳本/verify_reproducibility.py --run-tests --pretty
```

完整研究與部署邊界見：

- `文件/核心AI模型升級_2026-08-17.md`
- `文件/專題主計畫與WBS_2026-08-17.md`
- `文件/風險登錄與驗收矩陣_2026-08-17.md`
- `文件/國際標準與社會倫理_2026-08-17.md`

以下是 2026-08-17 的歷史快照，不能代表目前工作樹；目前 P0 會另建
2026-08-25 稽核與證據總帳，不覆寫舊檔：

- `文件/可重現性稽核_2026-08-17.json`：當時 12/12 checks verified；完整測試
  **583 passed、0 failed、268 warnings**。目前回歸為 615 passed，舊 hash 已失效。
- `文件/證據總帳_2026-08-17/evidence_ledger.json`：6 verified、
  2 provisional、1 blocked；`deployment_eligible=false`、
  `runtime_authorization=false`。
- `文件/SROS2智慧防火牆_專題最終報告_自然色系_2026-08-17.pptx`：檔名為歷史相容而
  保留，實際定位是 **29 頁階段成果簡報**，不是最終簡報；每頁含 `[Sources]` 講者備註，
  不把 development／same-host／dry-run 結果升級成 production、跨主機或自動封鎖證據。

目前可引用的 P0 checkpoint：

- `文件/可重現性稽核_2026-08-25_P0_verified.json`：12／12 verified；
  **615 passed、0 failed、268 warnings**，依賴鎖版 7／7 相符。
- `firewall_lab/project_claims_20260825_p0.json`：當前 bytes／SHA-256 與限制敘述。
- `文件/證據總帳_2026-08-25_P0/`：反向驗證 `valid=true`；5 verified、
  4 provisional、1 blocked，且固定 `deployment_eligible=false`。
