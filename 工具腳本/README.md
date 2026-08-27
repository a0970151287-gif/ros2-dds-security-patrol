# 工具腳本索引

> 38 支腳本，依**你要做什麼**分類，不依檔名排序。
>
> 檔名沒有變動——其他文件與腳本互相引用這些路徑，改名會斷掉。

跑之前先載入 ROS 環境（`run_*.sh` 多半自己會載）：

```bash
source 工具腳本/load_ros_environment.sh
```

⚠️ 標 **需授權** 的會啟動 live runtime 或產生攻擊流量，依 CLAUDE.md 規則 5
每一次都要 Jesse 當次明確授權，不因前一次已授權而延續。

---

## 跨主機身份收集（目前的主線）

照 [`文件/跨主機收集操作手冊_2026-08-27.md`](../文件/跨主機收集操作手冊_2026-08-27.md) 的順序用。

| 腳本 | 做什麼 |
|---|---|
| `check_udp_reachability.py` | **開跑前先量**單播與多播到底通不通。ping 是 ICMP，證明不了 UDP |
| `run_crosshost_identity.sh` | 防守端主控：擷取 ＋ 觀測者 ＋ 解碼 ＋ 交叉比對 ⚠️ **需授權** |
| `decode_rtps_identity.py` | 封包 → GUID ↔ **實際來源 IP**（契約 `spdp_locator` 觀測） |
| `observer_events_to_observations.py` | 觀測者事件 → 契約格式 |
| `crosscheck_identity_attribution.py` | 合併兩半，逐 IP 判定誰可以封鎖 |
| `dryrun_identity_pipeline.py` | 用合成觀測驗證整條管線（離線，不需授權） |
| `audit_identity_attribution.py` | 被動盤點現有 session 有沒有可信身份證據 |

## 測試與環境

| 腳本 | 做什麼 |
|---|---|
| `run_full_tests.sh` | **完整測試**。`bash 工具腳本/run_full_tests.sh tests/ -q` |
| `load_ros_environment.sh` | 共用 ROS2 環境載入器 |
| `setup_ml_test_env.sh` | 建立 Python 機器學習環境 |
| `verify_reproducibility.py` | 可重現性稽核。要 `--run-tests` 才會把測試項目升為 verified |

## AI 模型評估

全部離線，不需授權。

| 腳本 | 做什麼 |
|---|---|
| `evaluate_openset_holdout.py` | 用保留的 holdout 量**整個模型**的 open-set recall（一次性，拒絕覆寫） |
| `diagnose_openset_paths.py` | 拆解 open-set 判定走了哪一條路 |
| `compare_ood_scorers.py` | 比較三種未知攻擊評分器 |
| `calibrate_ood_threshold.py` | 用 leave-one-class-out 當模擬未知校準門檻 |
| `calibrate_ood_transfer.py` | 量門檻的跨場次轉移 |
| `evaluate_parallel_gate_loo.py` | family-LOO 平行閘門評估（Codex 的 P1） |
| `compare_rule_vs_learned.py` | **規則式 vs 學習式的公平對照**，附場次層級 bootstrap 信賴區間 |
| `diagnose_gate_veto.py` | **量 parallel gate 丟掉多少 OOD 頭已經認對的未知**，並掃 normality 預算看代價 |
| `audit_conformal_readiness.py` | session-level conformal 樣本是否足夠 |

## 資料集與特徵

| 腳本 | 做什麼 |
|---|---|
| `build_rerun_plan.py` | 產生 300 場重跑計畫 |
| `run_rerun_campaign.sh` | 跑一個 security mode 的重跑 campaign ⚠️ **需授權** |
| `supervise_rerun_campaign.sh` | 讓 campaign 撐得過偶發的單場失敗 |
| `merge_rerun_features.py` | 把重跑的 300 場**在特徵層**併回原本 800 場，不動原始資料集 |
| `verify_rerun_predictions.py` | 檢核重跑的三個可否證預測 |

## 本機防禦九項 outcome

目前 5／9，狀態見 [`文件/九項本機防禦結果_2026-08-19.md`](../文件/九項本機防禦結果_2026-08-19.md)。

| 腳本 | 做什麼 |
|---|---|
| `run_local_outcomes.sh` | 主驅動 ⚠️ **需授權** |
| `derive_local_outcomes.py` | 從已完成的 session 逐 stage 推導 outcome |
| `check_outcome_windows.py` | 逐 window 檢查證據 |
| `wait_for_telemetry.py` | 等某個 telemetry 事件出現（只讀新增位元組，不重掃整檔） |

## direct-delivery canary

| 腳本 | 做什麼 |
|---|---|
| `run_delivery_canary.sh` | 受保護 canary 的成對驗證 ⚠️ **需授權** |
| `verify_canary_archives.py` | 把封存的 archive 升成 v2 契約並驗票 |

## SROS2 與 Zeek 維運

| 腳本 | 做什麼 |
|---|---|
| `check_keystore_policy_drift.py` | 偵測 keystore 權限與現行 policy 不一致 |
| `install_zeek_helpers.sh` | 安裝 Zeek 的低權限通知 helper |
| `revoke_legacy_zeek_privileges.sh` | 撤銷舊版服務帳號直接改防火牆的權限 |

## 圖表與文件產生

| 腳本 | 做什麼 |
|---|---|
| `make_result_charts.py` | 從**已簽章的 artifact** 產生簡報用圖（8 張，輸出到 `文件/圖表_2026-08-25/`） |
| `chart_provenance.py` | 資料來源與產生管線圖 |
| `generate_topic_graph.py` | ROS2 DDS Topic 架構圖 |

## 其他

| 腳本 | 說明 |
|---|---|
| `run_paired_sessions.sh` | 2026-08-18 的成對執行 ⚠️ **需授權** |
| `stop_robot.sh` | Gazebo 開啟後立刻停止機器人 |
| `generate_permissions.py` | **已停用**的舊 permissions 產生器，保留供對照 |
