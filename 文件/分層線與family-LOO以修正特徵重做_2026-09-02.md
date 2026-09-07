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

## ⚠️ Provenance 更正（2026-09-02 稍晚）

本文原本讀起來像是「今天重訓了分層模型」。**不是。**

`~/models_hier_pkt/` 的模型與 `training_metrics.json` 是 **2026-08-31 17:24
（本地）** 產生的，屬於當天網路特徵修正工作的一部分。我 09-02 那次重訓指令
撞到腳本自己的「輸出已存在，拒絕覆寫」保護，**什麼都沒做**——今天真正跑的
只有 `loo_*.json`（03:48）。

數字本身有效（確實是在封包分窗特徵上訓練的），但「這一份把那件事做完」
只對 **family-LOO** 成立；分層模型那半 08-31 就做完了，我沒有查時間戳就寫成
今天的。**fail-closed 保護做對了事，是我沒讀它的輸出。**

## 分層模型：與舊表相當（訓練於 2026-08-31）

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

## 一個先前沒有被報告的結果：官方 holdout 的 open-set recall

`models_hier_pkt` 裡的 `openset_holdout.json` 是 08-31 產生的，**這份數字
到今天為止沒有出現在任何文件或訊息裡**。

| 官方 holdout 的整個模型 open-set recall | 舊（conn.log） | 新（封包分窗） |
|---|---:|---:|
| Permissive | **0.5789** | **0.2105** |
| Enforce | **0.8562** | **0.9125** |

（兩邊都用出貨預設的 `isolation_forest`，holdout 標籤同為
`sensor_spoof`／`service_dos`，所以協定可比。）

**Permissive 掉了超過一半。** 判定分佈說明了原因：

```
新版 722 列 holdout 的判定
  parameter_tamper  344    ← 自信地填成已知類別
  replay_dos        203    ←
  unknown_attack    152
  normal             23
```

**547 列被自信地指派給已知攻擊類別。** 舊版那個數字是 231
（C2C-026 記過同一個失效形態）。合理的解釋是：**網路特徵變好 → 閉集分類器
更有把握 → 對沒見過的類別更自信地給錯答案 → open-set 更差。**

這與 family-LOO 的方向相反，而**兩者不矛盾**：family-LOO 量的是 OOD 頭在
每折重擬門檻下的表現；官方 holdout 量的是整個模型在出貨門檻下的表現。
改善 OOD 頭的可分性，不等於改善整條鏈。

### ⚠️ 這個 holdout 已經被花掉第三次

artifact 自己寫著：

> `one_shot`: spending these holdout sessions again after any retuning
> invalidates this figure

C2C-035 已經是第二次使用（Mahalanobis 那次）。08-31 的重訓是第三次，
而且**當時沒有記錄下來**。所以上表的兩個新數字**都不是獨立估計**，
只能當診斷用。要拿到可引用的 open-set 數字，需要一批沒有被花過的 holdout。

**未知攻擊那一格因此維持 70%，不因 Enforce 的 0.9125 上調。**

## 進度百分比不動

未知攻擊那一格引用的是**整個模型在官方 holdout 上的 open-set recall**，
不是 family-LOO 的 macro。

**我今天跑的 family-LOO 沒有動官方 holdout，也沒有開 test**——它的協定明文
排除兩者。但上一節那批 08-31 的重訓**確實花掉了官方 holdout 一次**，
所以那兩個新數字不是獨立估計，不可用來調整進度。

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
