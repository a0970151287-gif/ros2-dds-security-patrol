# 分層線與 family-LOO 以修正後的網路特徵重做（2026-09-02）

> 全程離線。未啟動 ROS、未產生流量、未使用 `sudo`。
> **未修改 `hierarchical_model.py`、`hierarchical_training.py` 或
> `evaluate_parallel_gate_loo.py`**——只換輸入，用 Codex 自己的程式跑。
> 產物：`~/models_hier_pkt/`（未覆寫既有 `~/models_hier/`）

## 為什麼要重做

C2C-050（2026-08-31）發現網路特徵有四個缺陷，其中兩個讓既有數字失去意義：
1,400 場的 Zeek 都沒加 `-C`，checksum offload 讓封包被整批丟棄；而
`conn.log` 依流起點分窗，時間解析度是第一個缺陷的副產物。

當時就寫下：

> **任何引用網路特徵數值的既有結論都要重做**，包含 `models_hier`、
> `.codex_tmp/hierarchical_v1_*` 與 P1 family-LOO。方法結論不受影響。

這一份把那件事做完。

## 分層模型：與舊表相當

以 `features_merged_split_pkt`（逐封包分窗、Zeek 已加 `-C`）重訓兩個模式：

| 層／模式 | 新（封包） | 舊（conn.log） |
|---|---:|---:|
| Permissive binary balanced accuracy | 0.9818 | 0.9743 |
| Permissive binary PR-AUC | 1.0000 | 0.9988 |
| Permissive family balanced accuracy | 0.9722 | 0.9787 |
| Enforce binary balanced accuracy | 0.9823 | 0.9934 |
| Enforce binary PR-AUC | 0.9984 | 1.0000 |
| Enforce family balanced accuracy | 0.6858 | 0.6920 |

**互有高低、幅度都很小。** 二元層本來就接近上限（≥0.97），
所以修正網路特徵在這一層沒有可見空間。

## family-LOO：Permissive／Mahalanobis 相對提升 66%

用 Codex 的 `evaluate_parallel_gate_loo.py`，四組設定：

| 設定 | 舊（conn.log，2026-08-28） | **新（封包分窗）** | 變化 |
|---|---:|---:|---:|
| permissive / isolation_forest | 0.0931 | **0.1125** | +0.019 |
| **permissive / mahalanobis** | 0.2709 | **0.4507** | **+0.180** |
| enforce / isolation_forest | 0.0740 | **0.0708** | −0.003 |
| enforce / mahalanobis | 0.1049 | **0.1708** | +0.066 |

（macro unknown recall。新版的 permissive/mahalanobis
`worst_family_unknown_recall` 為 0.3000。）

### 三件要一起講的

**一、方法結論不變。** 四組的 `all_constraints_satisfied` 全部仍為 `False`
（門檻 `minimum_unknown_recall = 0.70`，另有 normal 與 known-attack 兩個預算）。
**Codex 在 C2C-031 的結論成立，四組全部未達 acceptance。**

**二、但這是保守協定下的提升。** family-LOO 每折移除整個家族的所有 session
再重擬 binary／normality／attack-OOD 三個頭，門檻也逐折重定。它比操作點量測
嚴格得多，所以 0.2709 → 0.4507 不是門檻挑出來的。

**三、Enforce 幾乎不動。** 與先前一致：Enforce 下 SROS2 在 handshake 就擋掉
攻擊，應用層證據不存在，網路特徵修得再好也補不上缺席的證據。
**修正網路特徵幫得到的是有應用層證據的那一邊。**

## 進度百分比不動

未知攻擊那一格引用的是**整個模型在官方 holdout 上的 open-set recall**，
不是 family-LOO 的 macro。本文沒有動官方 holdout，也沒有開 test。

family-LOO 是**開發期證據**，artifact 自己記著
`development_only=true`、`independent_final_test=false`、
`deployment_eligible=false`、`automatic_ip_block_authorized=false`。

## 沒有動的東西

- `models_hier/`（舊）**未覆寫**，新結果寫在 `models_hier_pkt/`。
- Codex 的三個程式檔一個字沒改。
- 出貨 scorer 仍是 `isolation_forest`；Mahalanobis 仍是
  `experimental / non-deployable`（P0 的標記）。
- P1 帳本引用的仍是舊 artifact，**我不覆寫不可變 checkpoint**；
  要更新需另出新 revision ledger。
