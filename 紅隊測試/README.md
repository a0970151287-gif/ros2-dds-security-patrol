# 紅隊測試索引

> 27 支 PoC 加七份報告。這裡按**威脅類型**分，不按編號——找攻擊時通常是
> 「我想測某一類弱點」，不是「我要 N14」。
>
> ⚠️ **每一支都會產生真實攻擊流量。** 依 CLAUDE.md 規則 5，執行前必須取得
> Jesse 對**該次操作**的明確授權，不因先前已授權而延續。

---

## 先讀哪一份

| 文件 | 什麼時候看 |
|---|---|
| [攻擊總表_成功與失敗.md](攻擊總表_成功與失敗.md) | **想知道哪些攻擊成功、哪些被擋** |
| [THREAT_MODEL.md](THREAT_MODEL.md) | 威脅模型與攻擊者能力假設 |
| [系統威脅分析.md](系統威脅分析.md) | 系統面的攻擊面分析 |
| [漏洞分析報告.md](漏洞分析報告.md) | 逐項漏洞與影響 |
| [白話講解_講給外行聽.md](白話講解_講給外行聽.md) | **給教授或同學看的版本** |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 紅隊工具本身的架構 |
| [N1-N20_完整目錄.md](N1-N20_完整目錄.md) | N1–N23 的原始目錄（**N24 之後未收錄**，以本索引為準） |
| [12_紅隊攻擊報告.md](12_紅隊攻擊報告.md) | 早期綜合報告 |

---

## 憑證與信任根（SROS2 本身）

這一組是目前跨主機實驗的主角。

| 攻擊 | 假設 | 結果 |
|---|---|---|
| **`N28_wrong_ca_participant.sh`** | 攻擊者**不需要任何秘密**，自己生一個 CA | 認證**必定失敗** → 產生拒絕證據。**目前跨主機收集用的就是它** |
| `N26_sros2_ca_forge.sh` | CA 私鑰外洩（世界可讀） | 認證**通過** → 繞過 Enforce。與 N28 互補 |
| `N26b_setup_live_keystore.sh` | N26 的環境建置 | 用「偷來的」CA 私鑰在隔離 domain 建 keystore |
| `N27_setup_real_governance.sh` | N26 的環境建置 | 在隔離 domain 99 重建等價 governance |
| **`N29_insider_credentialed.py`** | **內部威脅**：有合法憑證、沒有 HMAC 金鑰 | 證明分層防禦——SROS2 放行，HMAC 仍擋下 |

`N29` 是 `hmac_forgery_dropped` 與 `oversized_input_dropped` 兩項 outcome 的來源。

## 訊息偽造與重放

| 攻擊 | 目標 |
|---|---|
| `N1_heartbeat_replay.py` | `/security/heartbeat` 重放 |
| `N3_alert_replay_dos.py` | `/security/alerts` 重放 → 永久 patrol 停擺 |
| `N4_channel_confusion.py` | 跨頻道簽章混淆（HMAC envelope） |
| `N6_sensor_status_spoof.py` | 白名單同名 ＋ `/sensor/status` 偽造 |
| `N7_mission_cmd_spoof.py` | 直接偽造 `/mission/cmd`，跳過 mission manager |
| `N8_system_health_spoof.py` | `/system/health` 偽造（操作台假象） |
| `N13_health_reflection.py` | `/system/health` 未簽章反射放大 |

**重要發現**：重放在這套系統上**不是靠 ReplayCache 擋住的**，是時間戳窗
（alerts 10 秒、心跳 3 秒）加 ACL 讓重放來不及發生。詳見
[`文件/九項本機防禦結果_2026-08-19.md`](../文件/九項本機防禦結果_2026-08-19.md)。

## 阻斷服務

| 攻擊 | 手法 |
|---|---|
| `N15_log_storm.py` | 未簽章訊息洪水 → 日誌風暴 |
| `N18_memory_exhaustion.py` | `_alerted_nodes` 無上限成長 |
| `N19_param_service_flood.py` | Parameter service 洪水（餓死單執行緒） |
| `N20_verify_flood.py` | 未認證訊息洪水 → 強迫驗章 |
| `N21_detector_induced_dos.py` | **用 IDS 自己的偵測器誘發持續 DoS** |
| `N24_oversized_scan.py` | 單一超大訊息 |
| `N24b_varlen_scan_regression.py` | 變長度 scan 讓 IDS 崩潰（N24 的補洞回歸） |

⚠️ `N24` 的教訓：訊息要取**剛好超過門檻**（4,097 點）而不是「遠遠超過」
（8,192 點）。太大會在**傳輸層**就被丟掉，而「訊息沒到」與「防禦擋下了」
在遙測上完全一樣。

## 權限與身分繞過

| 攻擊 | 手法 |
|---|---|
| `N2_ros2cli_regex_bypass.py` | `_INTERNAL_NODE_REGEX` 後門，偽裝成 ros2cli |
| `N14_param_whitelist_hijack.py` | 用 `/set_parameters` 改 monitor 的 whitelist |
| `N23_behavioral_trigger_whitelisted.py` | 用**合法白名單名字**，純靠行為觸發 |
| `N5_baseline_poison.py` | 啟動前污染基線 |

## 控制與時序

| 攻擊 | 手法 |
|---|---|
| `N9_cmd_vel_race.py` | 緊急停止期間的 `cmd_vel` 競速 |
| `N25_patrol_geometry_crash.py` | 巡邏幾何崩潰（在上層目錄，不在 `PoC腳本/`） |

⚠️ `N9` 目前仍有殘餘風險，見根 `README.md` 的「目前必須保留的限制」。

## 批次執行器

| 腳本 | 說明 |
|---|---|
| `run_N_attacks.sh` | 批次跑多個攻擊 |
| `run_N4_attack.sh` | 單獨跑 N4 |
| `12_紅隊攻擊測試.sh` | 早期批次腳本 |

## 子目錄

| 目錄 | 內容 |
|---|---|
| `攻擊報告/` | 逐次攻擊的詳細報告 |
| `external_redteam_evidence/` | 外部紅隊證據 |
| `跨主機紅隊/` | 跨主機攻擊設定（另見頂層的 `跨主機紅隊/`） |

---

## 編號的空缺

`N10`、`N11`、`N12`、`N16`、`N17`、`N22` 沒有腳本——編號在分析階段配發，
後來或併入其他攻擊、或判定不可行。缺號不是遺失。
