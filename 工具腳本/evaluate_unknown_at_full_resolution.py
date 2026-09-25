#!/usr/bin/env python3
"""未知攻擊：`worst_family_unknown_recall = 0.0000` 是真的，還是 n 太小？

## 為什麼問這個

那個約束從 P1 起在四組設定裡**全部**是 0.0000，而它是唯一擋住未知攻擊那一格
的東西——macro 過了門檻也沒用，因為 acceptance 要求兩個都過。

但 C2C-060 記下的每折未知場次數是 **3、18、6、3、6**。三場的統計量只能取
0、1/3、2/3、1 四個值,而 C2C-064 在識別那格已經示範過:在那個解析度下
「永遠是零」與「三次擲硬幣全反面」**分不出來**。

## 那些場次為什麼只有三場

`evaluate_parallel_gate_loo.py` 的協定是（第 155-172 行）：

    held_groups = 該 family 在 train 與 validation 的**所有**場次
    fit_index   = base_train & ~held_group_mask      ← 整個 family 都不參與擬合
    unknown_index = validation & held_group_mask …   ← 只評估 validation 那一塊

**被留出的 family 連 train 列都沒有參與擬合**，門檻與參照分佈也都排除了它
（`threshold_index` 與 `reference_index` 都帶 `~held_group_mask`）。所以那些
train 列對模型**同樣是未見的**——它們只是被丟掉了。

用上它們沒有任何洩漏，而 refresh 資料每類 20 場,最小的 family 從約 3 場變成
40 場,**解析度約十倍**。

## 這支不改 Codex 的檔案

`evaluate_parallel_gate_loo.py` 是 Codex 登記的，SHA-256 釘在帳本裡。本工具
匯入它的 helper 自己重建 fold 迴圈，與 `sweep_unknown_session_pooling.py`
同一個先例。

⚠️ 重建就有分岔的風險，所以有一道硬性檢查：**本工具在舊解析度下算出的數字
必須與他的 artifact 逐位相同**，否則以非零碼結束、不輸出任何新數字。

## 分區

`test` 全程排除，官方 novelty holdout 依他的協定排除。新增的只有被留出 family
自己的 train 列，而那些列在每一個 fold 裡都已經被排除於擬合、門檻與參照之外。

## 用法

    python3 工具腳本/evaluate_unknown_at_full_resolution.py \\
        --features ~/features_refresh_split/fusion_features_permissive.csv \\
        --metrics ~/models_hier_refresh_maha/permissive/training_metrics.json \\
        --attack-ood-scorer mahalanobis \\
        --seed 20260825 --n-estimators 80 \\
        --reference 文件/未知攻擊場次池化_permissive_2026-09-15.json \\
        --output 文件/未知攻擊全解析度_permissive.json

⚠️ `--seed 20260825 --n-estimators 80` 不是裝飾。等價檢查比對的是
`sweep_unknown_session_pooling.py` 產生的 artifact，而那兩個值是**它的**預設；
用本工具自己的預設（20260915／300）會擬合出不同的模型，等價檢查因此失敗，
**而失敗訊息看起來像「重建有分岔」**。2026-09-25 為此查了二十分鐘，先後排除
了非確定性、venv 版本漂移與資料變動（逐折的場次數與列數完全相同），
最後才發現是設定沒被記下來。參照的檔名也更正了（原本多寫一個 `_maha`）。
"""

from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SCHEMA = "sros2-firewall-unknown-full-resolution/v1"
TOLERANCE = 1e-9
# k-of-n：一場要有 ≥k 個視窗喊未知。C2C-060 量到 k=3 讓四組的正常誤報全部降到
# 0.0000，所以兩種解析度都一併用它報一次。
POOLING_K = 3


class ResolutionError(RuntimeError):
    """重建與參照對不上，或輸入不足。刻意不吞。"""


def load_codex_module():
    """匯入 Codex 的評估器以重用它的 helper。**不修改它。**"""
    path = ROOT / "工具腳本" / "evaluate_parallel_gate_loo.py"
    spec = importlib.util.spec_from_file_location("codex_loo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for need in (
        "_fit_attack_ood", "_probability", "_weighted_rate", "_event_rate",
        "family_for_label", "RAW_FEATURES",
    ):
        if not hasattr(module, need):
            raise ResolutionError(f"Codex 的評估器沒有 {need}——介面變了，請先對齊")
    return module


class _NegatedSuspicion:
    """把「可疑度」包成 `score_samples`（越低越異常）。

    `compare_ood_scorers.py` 的評分器回的是可疑度（越高越可疑），而閘門用的是
    `score_samples(x) < threshold`。符號反了會讓每一個數字倒過來，而那看起來
    會像一個災難性的結果而不是一個 bug。
    """

    def __init__(self, suspicion):
        self._suspicion = suspicion

    def score_samples(self, x):
        return -self._suspicion(x)


def fit_attack_ood(codex, name, x, y, weights, *, seed: int, n_estimators: int):
    """Codex 支援的兩個直接轉發；max_softmax 在這裡自己接。

    **不修改他的檔案**——他的 `_fit_attack_ood` 只認得 mahalanobis 與
    isolation_forest，而 max_softmax 問的是完全不同的問題：「有沒有任何已知
    類別敢認領這一列」。對一個坐在已知攻擊雲**中間**的 family，那才是對的
    問法，而距離中心的評分結構上抓不到它。
    """
    if name != "max_softmax":
        return codex._fit_attack_ood(
            name, x, y, weights, seed=seed, n_estimators=n_estimators
        )

    import importlib.util

    import numpy as np

    path = ROOT / "工具腳本" / "compare_ood_scorers.py"
    spec = importlib.util.spec_from_file_location("codex_ood_compare", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suspicion = module._scores_max_softmax(x, y, seed=seed, n_estimators=n_estimators)
    detector = _NegatedSuspicion(suspicion)

    # 符號自我檢查：把擬合列大幅擾動之後，必須比原本**更異常**（分數更低）。
    rng = np.random.default_rng(seed)
    sample = x[rng.choice(len(x), size=min(len(x), 256), replace=False)]
    spread = np.nanstd(x, axis=0)
    spread[~np.isfinite(spread) | (spread == 0)] = 1.0
    perturbed = sample + rng.normal(0.0, 8.0 * spread, size=sample.shape)
    if float(detector.score_samples(perturbed).mean()) >= float(
        detector.score_samples(sample).mean()
    ):
        raise ResolutionError(
            "max_softmax 的符號自我檢查失敗：擾動過的列沒有比擬合列更異常。"
            "方向錯了就整批數字都是反的，不輸出。"
        )
    return detector


def k_of_n_rate(groups, flagged, k: int) -> float:
    hits: collections.Counter = collections.Counter()
    total: collections.Counter = collections.Counter()
    for group, flag in zip(groups, flagged):
        total[group] += 1
        if flag:
            hits[group] += 1
    if not total:
        raise ResolutionError("k-of-n 需要至少一場")
    return sum(1 for group in total if hits[group] >= k) / len(total)


def run(features: Path, metrics_path: Path, *, scorer: str, n_estimators: int,
        seed: int, maximum_normal_fpr: float, maximum_known_attack_ood_fpr: float,
        pooling_k: int = POOLING_K):
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    from firewall_lab.hierarchical_training import (
        _expanded_matrix, _fit_isolation_detector, _quantile_threshold,
        _session_equal_weights, choose_binary_threshold,
    )

    codex = load_codex_module()
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    frame = pd.read_csv(features)

    required = set(codex.RAW_FEATURES) | {
        "group_id", "session_id", "source", "window", "label", "split", "security_mode",
    }
    missing = required - set(frame)
    if missing:
        raise ResolutionError(f"特徵表缺欄位：{sorted(missing)}")
    if set(frame["security_mode"].astype(str)) != {metrics["security_mode"]}:
        raise ResolutionError("特徵表的模式與 training metrics 不符")

    excluded = set(metrics.get("applicable_excluded_sessions", []))
    if excluded:
        frame = frame.loc[
            ~frame["group_id"].astype(str).isin(excluded)
        ].reset_index(drop=True)

    matrix = _expanded_matrix(frame, metrics["source_availability"])
    labels = frame["label"].astype(str).to_numpy()
    groups = frame["group_id"].astype(str).to_numpy()
    split = frame["split"].astype(str).to_numpy()
    families = np.asarray([codex.family_for_label(v) for v in labels], dtype=object)

    holdout_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    holdout_groups = set(
        frame.loc[frame["label"].astype(str).isin(holdout_labels), "group_id"].astype(str)
    )
    official = np.isin(groups, list(holdout_groups))
    attack = labels != "normal"
    base_train = (split == "train") & ~official
    validation = (split == "validation") & ~official

    # 硬性：test 一列都不准進來。
    if int((split == "test").sum()) and bool(((split == "test") & base_train).any()):
        raise ResolutionError("test 列漏進了 base_train")

    known_families = sorted(set(families[base_train & attack]))
    if len(known_families) < 3:
        raise ResolutionError("family LOO 至少需要三個已知攻擊家族")

    threshold_groups = set(metrics["validation_protocol"]["threshold_groups"])
    reference_groups = set(metrics["validation_protocol"]["selection_groups"])
    if threshold_groups & reference_groups:
        raise ResolutionError("threshold 與 reference 的場次重疊")
    tg_mask = np.isin(groups, list(threshold_groups))
    rg_mask = np.isin(groups, list(reference_groups))

    folds = []
    test_rows_used = 0
    for offset, held_family in enumerate(known_families):
        held = set(groups[base_train & attack & (families == held_family)])
        held.update(groups[validation & attack & (families == held_family)])
        held_mask = np.isin(groups, list(held))
        family_mask = held_mask & attack & (families == held_family)

        fit_i = np.flatnonzero(base_train & ~held_mask)
        thr_i = np.flatnonzero(validation & tg_mask & ~held_mask)
        nor_i = np.flatnonzero(validation & rg_mask & ~held_mask & ~attack)
        kno_i = np.flatnonzero(validation & rg_mask & ~held_mask & attack)

        # 舊解析度：只有被留出 family 的 validation 列。
        unk_val = np.flatnonzero(validation & family_mask)
        # 全解析度：再加上它的 train 列。那些列在 fit / threshold / reference
        # 三處都已經被 ~held_mask 排除，所以對模型同樣未見。
        unk_full = np.flatnonzero((base_train | validation) & family_mask)

        if any(not len(i) for i in (fit_i, thr_i, unk_val, nor_i, kno_i)):
            raise ResolutionError(f"fold {held_family} 有空的協定分區")
        if len(unk_full) < len(unk_val):
            raise ResolutionError("全解析度的列數不可能少於舊解析度")
        # 洩漏檢查：新增的列一列都不准出現在擬合集裡。
        if set(unk_full.tolist()) & set(fit_i.tolist()):
            raise ResolutionError("全解析度的未知列與擬合集重疊——會洩漏")

        fit_binary = np.where(labels[fit_i] == "normal", "normal", "attack")
        binary = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=16, min_samples_leaf=2,
            max_features="sqrt", class_weight="balanced_subsample",
            random_state=seed + offset, n_jobs=1)
        binary.fit(matrix[fit_i], fit_binary,
                   sample_weight=_session_equal_weights(frame, fit_i))

        normal_fit = fit_i[labels[fit_i] == "normal"]
        attack_fit = fit_i[labels[fit_i] != "normal"]
        normality = _fit_isolation_detector(
            matrix[normal_fit], _session_equal_weights(frame, normal_fit),
            seed=seed + 100 + offset, n_estimators=n_estimators)
        attack_ood = fit_attack_ood(
            codex, scorer, matrix[attack_fit], labels[attack_fit],
            _session_equal_weights(frame, attack_fit),
            seed=seed + 200 + offset, n_estimators=n_estimators)

        thr_binary = np.where(labels[thr_i] == "normal", "normal", "attack")
        binary_sel = choose_binary_threshold(
            thr_binary, codex._probability(binary, matrix[thr_i], "attack"),
            maximum_normal_fpr=maximum_normal_fpr,
            sample_weight=_session_equal_weights(frame, thr_i))
        normality_thr = _quantile_threshold(
            normality.score_samples(matrix[thr_i[labels[thr_i] == "normal"]]),
            maximum_normal_fpr)
        attack_ood_thr = _quantile_threshold(
            attack_ood.score_samples(matrix[thr_i[labels[thr_i] != "normal"]]),
            maximum_known_attack_ood_fpr)

        def gate_paths(index):
            """三個成分,不只最後的結論。

            閘門是 `rejected AND (binary OR abnormal)`,所以一個被 OOD 頭正確
            拒絕的列仍然可能被否決。分開記才分得出「閘門擋掉」與「證據沒有」
            ——C2C-042 用這個分解證明過 59% 的損失來自閘門,而 C2C-045 又證明
            那 59% 不可回收。這裡要問的是同一個問題,對象換成永遠是零的那一族。
            """
            binary_says = (
                codex._probability(binary, matrix[index], "attack")
                >= float(binary_sel["threshold"])
            )
            abnormal = normality.score_samples(matrix[index]) < normality_thr
            rejected = attack_ood.score_samples(matrix[index]) < attack_ood_thr
            return {
                "binary": binary_says,
                "abnormal": abnormal,
                "rejected": rejected,
                "unknown": rejected & (binary_says | abnormal),
            }

        def unknown_mask(index):
            return gate_paths(index)["unknown"]

        paths_full = gate_paths(unk_full)
        flag_val = unknown_mask(unk_val)
        flag_full = paths_full["unknown"]
        flag_normal = unknown_mask(nor_i)

        folds.append({
            "held_family": held_family,
            "validation_only": {
                "sessions": len(set(groups[unk_val])),
                "rows": int(len(unk_val)),
                "row_recall": codex._weighted_rate(frame, unk_val, flag_val),
                "any_recall": codex._event_rate(frame, unk_val, flag_val),
                f"k{pooling_k}_recall": k_of_n_rate(
                    groups[unk_val], flag_val, pooling_k),
            },
            "full_resolution": {
                "sessions": len(set(groups[unk_full])),
                "rows": int(len(unk_full)),
                "row_recall": codex._weighted_rate(frame, unk_full, flag_full),
                "any_recall": codex._event_rate(frame, unk_full, flag_full),
                f"k{pooling_k}_recall": k_of_n_rate(
                    groups[unk_full], flag_full, pooling_k),
            },
            "gate_paths": {
                # OOD 頭自己的上限:它拒絕了多少。閘門只能比這個少。
                "ood_rejected_rows": float(paths_full["rejected"].mean()),
                "binary_says_attack_rows": float(paths_full["binary"].mean()),
                "abnormal_vs_normal_rows": float(paths_full["abnormal"].mean()),
                "passed_gate_rows": float(paths_full["unknown"].mean()),
                # 被 OOD 正確拒絕、卻因為兩個參照都說「正常」而被否決的比例。
                "vetoed_share_of_rejected": (
                    float(
                        (paths_full["rejected"] & ~paths_full["unknown"]).sum()
                        / max(int(paths_full["rejected"].sum()), 1)
                    )
                ),
            },
            "normal_reference": {
                "sessions": len(set(groups[nor_i])),
                "row_false_unknown_rate": codex._weighted_rate(
                    frame, nor_i, flag_normal),
                f"k{pooling_k}_false_unknown_rate": k_of_n_rate(
                    groups[nor_i], flag_normal, pooling_k),
            },
        })

    return folds, test_rows_used


def summarise(folds, key: str, pooling_k: int = POOLING_K) -> dict:
    out = {}
    for metric in ("row_recall", "any_recall", f"k{pooling_k}_recall"):
        values = [fold[key][metric] for fold in folds]
        out[metric] = {
            "macro": round(statistics.mean(values), 4),
            "worst": round(min(values), 4),
            "per_family": {
                fold["held_family"]: round(fold[key][metric], 4) for fold in folds
            },
        }
    out["sessions_per_family"] = {
        fold["held_family"]: fold[key]["sessions"] for fold in folds
    }
    return out


def check_equivalence(folds, reference: Path) -> dict:
    """舊解析度的數字必須與參照 artifact 逐位相同。"""
    payload = json.loads(reference.read_text(encoding="utf-8"))
    ref_folds = payload.get("folds") or payload.get("per_fold") or []
    by_family = {}
    for entry in ref_folds:
        name = entry.get("held_family") or entry.get("family")
        if name:
            by_family[name] = entry
    checked = 0
    for fold in folds:
        entry = by_family.get(fold["held_family"])
        if entry is None:
            continue
        for ours, theirs in (
            (fold["validation_only"]["row_recall"],
             (entry.get("row") or {}).get("unknown_recall")),
            (fold["validation_only"]["any_recall"],
             (entry.get("any") or {}).get("unknown_recall")),
        ):
            if theirs is None:
                continue
            if abs(float(ours) - float(theirs)) > TOLERANCE:
                raise ResolutionError(
                    f"{fold['held_family']} 對不上參照："
                    f"本工具 {ours!r} 對 artifact {theirs!r}。重建有分岔，不輸出。"
                )
            checked += 1
    if not checked:
        raise ResolutionError(
            "參照 artifact 裡沒有任何可比對的數字——等價檢查形同虛設，不輸出。"
        )
    return {"comparisons": checked, "reference": str(reference)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", required=True)
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--attack-ood-scorer", default="mahalanobis")
    parser.add_argument(
        "--pooling-k", type=int, default=POOLING_K,
        help="一場要有 ≥k 個視窗喊未知才算。預設 3 是 C2C-060 在 "
             "mahalanobis／isolation_forest 上選的；2026-09-25 量到 "
             "max_softmax 的最佳 k 不同，所以它必須可以指定。")
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20260915)
    parser.add_argument("--maximum-normal-fpr", type=float, default=0.02)
    parser.add_argument("--maximum-known-attack-ood-fpr", type=float, default=0.05)
    parser.add_argument("--reference", default=None,
                        help="Codex artifact 或既有結果，用於逐位等價檢查")
    parser.add_argument(
        "--unreferenced-reason",
        default=None,
        help=(
            "沒有參照 artifact 可比對時，必須寫下理由。理由會寫進產物，"
            "所以「這一輪沒有被等價檢查擋過」是讀得到的，不是默默跳過。"
        ),
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    output = Path(args.output).expanduser()
    if output.exists():
        raise ResolutionError(f"輸出已存在，拒絕覆寫：{output}")

    folds, test_rows = run(
        Path(args.features).expanduser(), Path(args.metrics).expanduser(),
        scorer=args.attack_ood_scorer, n_estimators=args.n_estimators,
        seed=args.seed, maximum_normal_fpr=args.maximum_normal_fpr,
        maximum_known_attack_ood_fpr=args.maximum_known_attack_ood_fpr,
        pooling_k=args.pooling_k,
    )
    if args.reference:
        equivalence = check_equivalence(folds, Path(args.reference).expanduser())
    elif args.unreferenced_reason:
        equivalence = {
            "skipped": True,
            "reason": args.unreferenced_reason,
            "comparisons": 0,
        }
        print(f"⚠️ 等價檢查跳過：{args.unreferenced_reason}")
    else:
        raise ResolutionError(
            "沒有 --reference 就必須給 --unreferenced-reason。"
            "無聲地跳過等價檢查，等於讓一次未驗證的重建看起來跟驗過的一樣。"
        )

    report = {
        "schema_version": SCHEMA,
        "features": str(args.features),
        "metrics": str(args.metrics),
        "attack_ood_scorer": args.attack_ood_scorer,
        # ⚠️ 這兩個必須記進產物。2026-09-25 花了二十分鐘以為這支工具漂移了：
        # 用它自己的預設（seed 20260915、n_estimators 300）重現不了 09-24 的
        # artifact，而正確的值是 `--seed 20260825 --n-estimators 80`，也就是
        # 產生參照的那支掃描工具的預設。**一個沒有記下設定的產物，即使當時
        # 等價檢查通過，也沒有人能第二次重跑它**——而「重現不了」與「結果變了」
        # 在錯誤訊息上完全一樣。
        "seed": args.seed,
        "n_estimators": args.n_estimators,
        "test_rows_used": test_rows,
        "equivalence_check": equivalence,
        "pooling_k": args.pooling_k,
        "validation_only": summarise(folds, "validation_only", args.pooling_k),
        "full_resolution": summarise(folds, "full_resolution", args.pooling_k),
        "normal_reference": {
            fold["held_family"]: fold["normal_reference"] for fold in folds
        },
        "gate_paths": {fold["held_family"]: fold["gate_paths"] for fold in folds},
        "folds": folds,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(f"報告：{output}")
    if equivalence.get("skipped"):
        print("等價檢查：已跳過（理由已寫進產物）")
    else:
        print(f"等價檢查：{equivalence['comparisons']} 個數字逐位相同")
    print()
    for key, label in (("validation_only", "舊解析度（只用 validation）"),
                       ("full_resolution", "全解析度（＋被留出 family 的 train）")):
        block = report[key]
        print(f"=== {label} ===")
        print(f"  每個 family 的場次數: {block['sessions_per_family']}")
        for metric in ("row_recall", "any_recall", f"k{args.pooling_k}_recall"):
            item = block[metric]
            print(f"  {metric:<12} macro={item['macro']:.4f}  worst={item['worst']:.4f}")
            print(f"               {item['per_family']}")
        print()
    print("=== 閘門分解（全解析度,逐列）===")
    print("  family                 OOD拒絕   binary   abnormal   過閘    被否決佔拒絕")
    for fold in folds:
        g = fold["gate_paths"]
        print(f"  {fold['held_family']:<22} {g['ood_rejected_rows']:7.4f} "
              f"{g['binary_says_attack_rows']:8.4f} {g['abnormal_vs_normal_rows']:10.4f} "
              f"{g['passed_gate_rows']:7.4f} {g['vetoed_share_of_rejected']:13.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
