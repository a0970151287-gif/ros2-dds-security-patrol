# ML-IDS：兩層融合 AI 防禦模型（PoC）

**目標**（使用者構想）：訓練一個防禦系統，**辨識面對的是哪種攻擊 → 做出相應防禦**。

**狀態**：Phase 1 PoC 完成（網路層，現有 conn.log）。Phase 2 工具已就緒（`資料收集/`），待實際攻防 session 收集乾淨標註資料。

---

## 架構（兩層融合 + 規則出手）

```
                  ┌─────────────── 偵測/分類（ML，學） ───────────────┐
  封包/行為  ──►  │  網路層特徵(Zeek conn.log)  ┐                      │
                  │                              ├─► 融合分類器 ─► 類別 │ ──► 防禦策略表
  ROS2 訊號  ──►  │  行為層特徵(D1-D6, phase2)  ┘  (recon/dos/inject/  │     (class→action,規則)
                  └──────────────────────────────  spoof/behavioral)  ─┘            │
                                                                                     ▼
   縱深第一道（預防，最重要）：SROS2 Enforce — 外部攻擊在認證層就死，根本進不來    出手：告警/限流/
                                                                                封鎖/驗章/急停
```

**設計原則**：
1. **ML 看懂、規則出手**：分類用 ML；防禦動作用 `防禦策略.py` 的 class→action 規則表（可審計、可解釋、安全；不用學出來的策略亂下急停）。
2. **補強 ≠ 取代**：SROS2 Enforce 是預防根治；ML 補「內鬼異常」+「規則沒寫死的變種」+「自動量 FPR/混淆矩陣」。
3. **資料用自家 testbed**：通用 IDS 資料集（CIC-IDS2017 等）是一般 TCP/IP，與 DDS/RTPS 分布不符，不採用。

---

## 檔案
| 檔 | 作用 |
|---|---|
| `特徵抽取.py` | Zeek conn.log → 滑窗 per-source 特徵 CSV（網路層 9 特徵 + bootstrap 標籤） |
| `訓練.py` | 監督式 RandomForest（normal/attack）+ 非監督 IsolationForest，出混淆矩陣/特徵重要度 |
| `防禦策略.py` | class→action 防禦策略表（相應防禦，串接 repo 既有防禦） |
| `回應引擎.py` | **偵測→出手**：吃偵測結果→查策略→經安全閘→執行對應防禦 |
| `端到端_demo.py` | 閉環：RTPS 模型偵測真封包 → 回應引擎出對應防禦 |
| `RTPS資料集_訓練.py` | 用外部乾淨資料集(HCRL)訓練注入偵測（PR-AUC 0.95） |
| `輸出/` | features.csv、model.joblib、rtps_inject_model.joblib |
| `requirements.txt` | 隔離環境相依（venv: /home/jesse/ml_ids_env） |

### 偵測→對應防禦（回應引擎）
ML/規則偵測出類別後，`回應引擎.py` 自動出對應防禦，並經 4 道安全閘：
1. **confidence 門檻**（預設 0.70）：信心不足只觀察，不出手（防 FP 誤封）。
2. **紅隊白名單**：攻防遊戲中不硬封 PEER(10.10.10.1)，除非開 demo。
3. **per-(source,action) cooldown**：同招短時間不重複出手。
4. **預設 dry-run**：只印「會下什麼指令」，live 才真執行。

| 類別 | 對應防禦 | 真實性 |
|---|---|---|
| inject / param | app 層 HMAC 驗章 / F1-b veto **早就在擋** | 已生效，引擎只記錄 |
| dos | `block_source.sh` 封來源自動解封 | 可執行（opt-in、遊戲安全） |
| behavioral | `/cmd_vel` 歸零急停 | 可執行（live 需 ROS 環境） |
| spoof / stealth_dos | 告警 → 指向 SROS2 身分根治 | 網路層擋不死身分偽造 |
| recon | 告警追蹤（不封，免打斷遊戲） | 告警 |

⚠️ **誠實定位**：回應引擎是「反應式」的手——偵測後才出手，有 FP 風險、二進位 topic 只能事後急停。**真正「擋下」（預防）的是 SROS2 Enforce**（攻擊者沒憑證進不來）。ML+回應引擎補的是「進得來的內鬼/變種」這層，不取代牆。

執行：
```bash
/home/jesse/ml_ids_env/bin/python 特徵抽取.py ../conn.log 輸出/features.csv 8
/home/jesse/ml_ids_env/bin/python 訓練.py 輸出/features.csv
/home/jesse/ml_ids_env/bin/python 防禦策略.py
```

---

## Phase 1 PoC 結果（誠實，現有 conn.log）

- **資料**：56,617 筆連線 → 18,868 視窗（8s）。正常 18,642 / 攻擊 226（**僅 1.2%，高度不平衡**）。
- **監督式 RandomForest**：ROC-AUC **0.917**、攻擊 recall **0.926**，但 precision **0.063**（933 正常被誤判）。
- **非監督 IsolationForest**（只學正常）：攻擊偵出 13.7%、FPR 1.99%。
- **特徵重要度**：`spdp_ratio`(0.51) ≫ `conn_rate`(0.11)、`conn_count`(0.11)、`userdata_ratio`(0.08)。

**解讀（不灌水）**：
- ✅ **可行性成立**：AUC 0.92 代表流量特徵**確實能分**攻擊/正常，pipeline 端到端跑通。
- ⚠️ **precision 差 / 非監督偵出低**：因為 (a) 攻擊樣本只佔 1.2% 極不平衡、(b) 用現有 conn.log 的 **bootstrap 弱標籤**（來源身分推得，非乾淨 ground truth）、(c) 此 log 攻擊流量多為低速 recon，特徵空間與稀疏正常流量重疊。
- ➡️ **這恰好量化證明 Phase 2 的必要**：要 precision 上得來、要做多類(recon/dos/inject/spoof/behavioral)，**必須有平衡的、乾淨標註的資料**。

---

## 資料集整合（2026-07-02 首版，2026-07-04 更新）

`資料收集/合併資料集.py` 把手上所有「與本實驗室情境相關」的擷取整合成
`輸出/dataset_combined.csv`（19,336 列）：

| 來源 | 併入？ | 原因 |
|---|---|---|
| `輸出/features.csv`（Phase 1 既有特徵，18,868 列）| ✅ | 唯一含真實攻擊活動的資料（原始 conn.log 已被後續 Zeek 執行覆蓋，但特徵已保存） |
| `網路記錄/conn.log`（2026-07-02 23:09~2026-07-03 00:59，468 列）| ✅ | 內含真實紅隊活動（910筆10.10.10.1連線+1筆偽造來源10.10.10.250），bootstrap弱標籤重抽取 |
| `網路記錄/archive/2026-04-25_舊擷取/`、`2026-05-05_Zeek監控舊擷取/` | ❌ 排除 | 來源 IP `172.30.123.103`，非本實驗室網段(10.10.10.0/24)，無攻擊機活動 → 混入會汙染標籤 |
| `Zeek監控/test/conn.log`（合成 fixture，34 筆）| ⚪ 未併入 | 全落在同一個 8s 視窗，粒度與本管線窗口特徵不合；留作規則偵測的獨立驗證用 |

**誠實結果（兩階段對照）**：
1. 第一次合併（2026-07-02，併入的是**純自身流量、無新攻擊**）→ PR-AUC 0.1825，與 Phase 1 的 0.1996 持平（沒改善，因為沒加進新的攻擊樣本）。
2. **第二次合併（2026-07-04，併入 2026-07-03 那批真實紅隊活動）→ PR-AUC 0.2457（5-fold CV 0.2373），比 Phase 1 提升約 20%。**

**結論更新**：光合併「無關」或「純normal」資料沒用；但併入**同網段、真實、新鮮的攻擊資料**（即使仍是bootstrap弱標籤，非 label.sh 精確標註）就有實質改善。這進一步支持「瓶頸是資料不是演算法」的論點，也證明 Phase 2 乾淨標註資料的投資方向正確——見下方 Phase 2，以及完整分析 [`文件/AI評估_ML-IDS何時有用.md`](../文件/AI評估_ML-IDS何時有用.md)。

---

## Phase 2：乾淨標註資料收集（工具已就緒，見 `資料收集/`）

> 「先 PoC 再補乾淨資料」的後半。每類攻擊**隔離跑 + 精確標註**，取代 bootstrap 弱標籤。

| 檔 | 作用 |
|---|---|
| `資料收集/label.sh` | 攻擊前後打時間戳：`bash label.sh start <class>` / `end <class>`，任意類別名（recon/dos/metasploit_scan/…） |
| `資料收集/精確標註_重抽特徵.py` | 讀 conn.log + labels.txt → 用真實時間窗精確標註（取代 Phase 1 速率門檻猜測） |

**流程**：
```bash
cd ML防禦/資料收集
bash label.sh start normal   # 系統正常巡邏 N 分鐘，先建乾淨基線
bash label.sh end   normal
bash label.sh start recon    # 紅隊單獨跑 recon（同時間只跑一種，最乾淨）
#（紅隊執行 recon）
bash label.sh end   recon
# ...依序 dos / inject / param / spoof / stealth_dos / metasploit_* ...

# 攻擊結束後，重抽精確標註特徵：
/home/jesse/ml_ids_env/bin/python 精確標註_重抽特徵.py ../../conn.log labels.txt ../輸出/features_precise.csv 8
```
標籤設計：來源身分仍是可靠 ground truth（自身/受信來源永遠 normal）；非受信來源的活動用時間窗查出**精確類別**，落在任何窗外的一律誠實標 `unlabeled`（不硬猜，訓練前可剔除或回頭補窗）。

**後續**：
- inject/param 若要更準，另加 **payload 特徵**（Zeek udp_contents 的 INJECTED / set_parameters 命中）——conn.log 流量特徵本身看不到 payload。
- 行為層：Permissive 下跑 /cmd_vel 劫持、scan 投毒，同步錄 D1-D6 訊號 → 標 `behavioral`，融合進網路層特徵訓練多類分類器。

---

## 與既有防禦的關係
- ML-IDS 是 [防禦對照_預防優於反應.md](../文件/防禦對照_預防優於反應.md) 裡「反應式縱深」的**智慧化**版本。
- 偵測出類別後，由 `防禦策略.py` 對應到既有實作：Zeek 告警/封鎖、app 層驗章、`lock_sensitive_params`、SROS2 Enforce、`intelligent_defense_node` 急停。
- **預防仍是第一道**：能上 SROS2 Enforce 就讓攻擊進不來；ML 是「萬一進來了/內鬼」的偵測腦。
