#!/usr/bin/env python3
"""未知攻擊的場次池化：`any()` 之外還有沒有更好的規則？

## 為什麼問這個

`evaluate_parallel_gate_loo.py` 其實**已經**輸出場次層級的未知 recall，只是
從來沒有被報出來。它的定義是 `_event_rate`：

    groupby(session)["flagged"].max().mean()

也就是 **`any()`**——一場裡任何一個視窗喊未知就算偵測到。實測（Permissive／
Mahalanobis、family-LOO validation）：

| | 列層級 | 場次層級 | 倍數 |
|---|---:|---:|---:|
| 未知 recall | 0.5592 | 0.7000 | ×1.25 |
| **正常誤報** | 0.0714 | **0.1818** | **×2.55** |

**誤報漲得比 recall 快兩倍——`any()` 是壞交易。** 而 2026-09-15 量到，
在多類識別上 `max`／`any` 類的規則正是最差的一種（0.2519，而投票是 0.9333）。

所以本工具掃 **k-of-n**：一場裡要有 ≥k 個視窗喊未知才算。`any()` 是 k=1。

## 這支不改 Codex 的檔案

`evaluate_parallel_gate_loo.py` 是 Codex 登記的，而且它的 SHA-256 釘在帳本裡。
本工具**匯入**它的 helper（`_fit_attack_ood`、`_probability`、`_weighted_rate`、
`_event_rate`）與 `hierarchical_training` 的協定函式，自己重建 fold 迴圈。

⚠️ **重建就有分岔的風險**，所以有一道硬性的等價檢查：本工具算出的
`parallel_unknown_recall` 與 `normal_false_unknown_rate` 必須與他既有的
artifact **逐位相同**，否則以非零碼結束、不輸出任何新數字。

## 分區

全程 family-LOO，只用 validation。官方 novelty holdout 與 test 依他的協定排除。
`--reference` 指向他的 artifact 以做等價檢查。

## 用法

    python3 工具腳本/sweep_unknown_session_pooling.py \\
        --features ~/features_refresh_split/fusion_features_permissive.csv \\
        --metrics ~/models_hier_refresh_maha/permissive/training_metrics.json \\
        --attack-ood-scorer mahalanobis \\
        --reference 文件/盲點特徵_對familyLOO的影響_2026-09-04/permissive_mahalanobis_full.json \\
        --output 文件/未知攻擊場次池化_permissive.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TOLERANCE = 1e-9


class SweepError(RuntimeError):
    """重建與參照對不上，或輸入不足。刻意不吞。"""


def load_codex_module():
    """匯入 Codex 的評估器以重用它的 helper。**不修改它。**"""
    path = ROOT / "工具腳本" / "evaluate_parallel_gate_loo.py"
    spec = importlib.util.spec_from_file_location("codex_loo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for need in ("_fit_attack_ood", "_probability", "_weighted_rate", "_event_rate",
                 "family_for_label", "RAW_FEATURES"):
        if not hasattr(module, need):
            raise SweepError(f"Codex 的評估器沒有 {need}——介面變了，請先對齊")
    return module


def k_of_n_rate(groups, flagged, k: int) -> float:
    """每場需要 ≥k 個視窗被標記才算。k=1 等於 `any()`。"""
    import collections

    hits = collections.Counter()
    total = collections.Counter()
    for g, f in zip(groups, flagged):
        total[g] += 1
        if f:
            hits[g] += 1
    if not total:
        raise SweepError("k-of-n 需要至少一場")
    return sum(1 for g in total if hits[g] >= k) / len(total)


def fraction_rate(groups, flagged, fraction: float) -> float:
    """每場需要至少 `fraction` 比例的視窗被標記。"""
    import collections

    hits = collections.Counter()
    total = collections.Counter()
    for g, f in zip(groups, flagged):
        total[g] += 1
        if f:
            hits[g] += 1
    if not total:
        raise SweepError("fraction 規則需要至少一場")
    return sum(1 for g in total
               if hits[g] >= math.ceil(fraction * total[g])) / len(total)


def run(features: Path, metrics_path: Path, *, scorer: str, n_estimators: int,
        seed: int, maximum_normal_fpr: float, maximum_known_attack_ood_fpr: float,
        ks, fractions):
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    from firewall_lab.hierarchical_training import (
        _expanded_matrix, _fit_isolation_detector, _quantile_threshold,
        _session_equal_weights, choose_binary_threshold,
    )

    cx = load_codex_module()
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    frame = pd.read_csv(features)
    missing = (set(cx.RAW_FEATURES) | {"group_id", "session_id", "source", "window",
                                       "label", "split", "security_mode"}) - set(frame)
    if missing:
        raise SweepError(f"特徵表缺欄位：{sorted(missing)}")
    if set(frame["security_mode"].astype(str)) != {metrics["security_mode"]}:
        raise SweepError("特徵表的模式與 training metrics 不符")

    excluded = set(metrics.get("applicable_excluded_sessions", []))
    if excluded:
        frame = frame.loc[~frame["group_id"].astype(str).isin(excluded)].reset_index(
            drop=True)

    matrix = _expanded_matrix(frame, metrics["source_availability"])
    labels = frame["label"].astype(str).to_numpy()
    groups = frame["group_id"].astype(str).to_numpy()
    split = frame["split"].astype(str).to_numpy()
    families = np.asarray([cx.family_for_label(v) for v in labels], dtype=object)

    holdout_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    holdout_groups = set(frame.loc[frame["label"].astype(str).isin(holdout_labels),
                                   "group_id"].astype(str))
    official = np.isin(groups, list(holdout_groups))
    attack = labels != "normal"
    base_train = (split == "train") & ~official
    validation = (split == "validation") & ~official
    known_families = sorted(set(families[base_train & attack]))
    if len(known_families) < 3:
        raise SweepError("family LOO 至少需要三個已知攻擊家族")

    threshold_groups = set(metrics["validation_protocol"]["threshold_groups"])
    reference_groups = set(metrics["validation_protocol"]["selection_groups"])
    tg_mask = np.isin(groups, list(threshold_groups))
    rg_mask = np.isin(groups, list(reference_groups))

    folds = []
    for offset, held_family in enumerate(known_families):
        held = set(groups[base_train & attack & (families == held_family)])
        held.update(groups[validation & attack & (families == held_family)])
        held_mask = np.isin(groups, list(held))

        fit_i = np.flatnonzero(base_train & ~held_mask)
        thr_i = np.flatnonzero(validation & tg_mask & ~held_mask)
        unk_i = np.flatnonzero(validation & held_mask & attack
                               & (families == held_family))
        nor_i = np.flatnonzero(validation & rg_mask & ~held_mask & ~attack)
        kno_i = np.flatnonzero(validation & rg_mask & ~held_mask & attack)
        if any(not len(i) for i in (fit_i, thr_i, unk_i, nor_i, kno_i)):
            raise SweepError(f"fold {held_family} 有空的協定分區")

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
        attack_ood = cx._fit_attack_ood(
            scorer, matrix[attack_fit], labels[attack_fit],
            _session_equal_weights(frame, attack_fit),
            seed=seed + 200 + offset, n_estimators=n_estimators)

        thr_binary = np.where(labels[thr_i] == "normal", "normal", "attack")
        binary_sel = choose_binary_threshold(
            thr_binary, cx._probability(binary, matrix[thr_i], "attack"),
            maximum_normal_fpr=maximum_normal_fpr,
            sample_weight=_session_equal_weights(frame, thr_i))
        nor_thr_rows = thr_i[labels[thr_i] == "normal"]
        atk_thr_rows = thr_i[labels[thr_i] != "normal"]
        normality_thr = _quantile_threshold(
            normality.score_samples(matrix[nor_thr_rows]), maximum_normal_fpr)
        attack_ood_thr = _quantile_threshold(
            attack_ood.score_samples(matrix[atk_thr_rows]),
            maximum_known_attack_ood_fpr)

        def unknown_mask(index):
            b = (cx._probability(binary, matrix[index], "attack")
                 >= float(binary_sel["threshold"]))
            a = normality.score_samples(matrix[index]) < normality_thr
            rejected = attack_ood.score_samples(matrix[index]) < attack_ood_thr
            return rejected & (b | a)

        held_unknown = unknown_mask(unk_i)
        normal_unknown = unknown_mask(nor_i)

        entry = {
            "held_family": held_family,
            "unknown_sessions": len(set(groups[unk_i])),
            "normal_sessions": len(set(groups[nor_i])),
            "row": {
                "unknown_recall": cx._weighted_rate(frame, unk_i, held_unknown),
                "normal_false_unknown_rate": cx._weighted_rate(
                    frame, nor_i, normal_unknown),
            },
            "any": {
                "unknown_recall": cx._event_rate(frame, unk_i, held_unknown),
                "normal_false_unknown_rate": cx._event_rate(
                    frame, nor_i, normal_unknown),
            },
            "k_of_n": {}, "fraction": {},
        }
        for k in ks:
            entry["k_of_n"][str(k)] = {
                "unknown_recall": k_of_n_rate(groups[unk_i], held_unknown, k),
                "normal_false_unknown_rate": k_of_n_rate(
                    groups[nor_i], normal_unknown, k),
            }
        for f in fractions:
            entry["fraction"][str(f)] = {
                "unknown_recall": fraction_rate(groups[unk_i], held_unknown, f),
                "normal_false_unknown_rate": fraction_rate(
                    groups[nor_i], normal_unknown, f),
            }
        folds.append(entry)
    return folds


def check_equivalence(folds, reference: Path):
    """重建必須與 Codex 的 artifact 逐位相同，否則本輪不可引用。"""
    ref = json.loads(reference.read_text(encoding="utf-8"))
    ref_folds = {f["held_family"]: f["metrics"] for f in ref["folds"]}
    problems = []
    for fold in folds:
        fam = fold["held_family"]
        if fam not in ref_folds:
            problems.append(f"參照沒有 fold {fam}")
            continue
        m = ref_folds[fam]
        pairs = (
            ("parallel_unknown_recall", fold["row"]["unknown_recall"]),
            ("normal_false_unknown_rate", fold["row"]["normal_false_unknown_rate"]),
            ("parallel_unknown_session_recall", fold["any"]["unknown_recall"]),
            ("normal_false_unknown_session_rate",
             fold["any"]["normal_false_unknown_rate"]),
        )
        for name, mine in pairs:
            theirs = m.get(name)
            if theirs is None:
                problems.append(f"{fam}: 參照沒有 {name}")
            elif abs(float(theirs) - float(mine)) > TOLERANCE:
                problems.append(f"{fam}.{name}: 參照 {theirs!r} ≠ 重建 {mine!r}")
    return problems


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--features", type=Path, required=True)
    p.add_argument("--metrics", type=Path, required=True)
    p.add_argument("--reference", type=Path, required=True,
                   help="Codex 既有的 artifact，用來做等價檢查")
    p.add_argument("--attack-ood-scorer", default="mahalanobis",
                   choices=("isolation_forest", "mahalanobis"))
    p.add_argument("--n-estimators", type=int, default=80)
    p.add_argument("--seed", type=int, default=20260825)
    p.add_argument("--maximum-normal-fpr", type=float, default=0.02)
    p.add_argument("--maximum-known-attack-ood-fpr", type=float, default=0.05)
    p.add_argument("--k", type=int, nargs="+", default=[1, 2, 3, 4])
    p.add_argument("--fraction", type=float, nargs="+", default=[0.25, 0.5, 0.75])
    p.add_argument("--output", type=Path, default=None)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    import numpy as np

    try:
        folds = run(args.features, args.metrics, scorer=args.attack_ood_scorer,
                    n_estimators=args.n_estimators, seed=args.seed,
                    maximum_normal_fpr=args.maximum_normal_fpr,
                    maximum_known_attack_ood_fpr=args.maximum_known_attack_ood_fpr,
                    ks=args.k, fractions=args.fraction)
    except (SweepError, ValueError, KeyError) as exc:
        print(f"⛔ {exc}")
        return 2

    problems = check_equivalence(folds, args.reference)
    if problems:
        print("⛔ 重建與 Codex 的 artifact 對不上——本輪的新數字不可引用：")
        for p in problems[:10]:
            print("   " + p)
        return 3
    print("✅ 等價檢查通過：列層級與 any() 兩個指標逐位重現 Codex 的 artifact")
    print()

    def macro(getter):
        return float(np.mean([getter(f) for f in folds]))

    def worst_fpr(getter):
        return float(np.max([getter(f) for f in folds]))

    rules = [("列層級（現行報的）", lambda f: f["row"])]
    rules += [(f"k-of-n  k={k}" + ("   ← any()" if k == 1 else ""),
               (lambda k: (lambda f: f["k_of_n"][str(k)]))(k)) for k in args.k]
    rules += [(f"比例 ≥{int(fr * 100)}%",
               (lambda fr: (lambda f: f["fraction"][str(fr)]))(fr))
              for fr in args.fraction]

    print("  %-24s %12s %14s" % ("規則", "未知 recall", "最差正常誤報"))
    table = {}
    for name, getter in rules:
        rec = macro(lambda f: getter(f)["unknown_recall"])
        fpr = worst_fpr(lambda f: getter(f)["normal_false_unknown_rate"])
        table[name] = {"macro_unknown_recall": round(rec, 4),
                       "worst_normal_false_unknown_rate": round(fpr, 4)}
        gate = "✅" if rec >= 0.70 else "  "
        budget = "✅" if fpr <= args.maximum_normal_fpr else "⛔"
        print("  %-24s %12.4f %s %12.4f %s" % (name, rec, gate, fpr, budget))

    report = {
        "schema_version": "sros2-firewall-unknown-session-pooling/v1",
        "features_table": str(args.features),
        "reference_artifact": str(args.reference),
        "equivalence_verified": True,
        "attack_ood_scorer": args.attack_ood_scorer,
        "maximum_normal_fpr": args.maximum_normal_fpr,
        "minimum_unknown_recall": 0.70,
        "official_holdout_rows_used": 0,
        "test_rows_used": 0,
        "changes_shipped_defaults": False,
        "summary": table,
        "folds": folds,
    }
    if args.output:
        if args.output.exists():
            print(f"\n⛔ 輸出已存在，拒絕覆寫：{args.output}")
            return 2
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8")
        print(f"\n  報告：{args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
