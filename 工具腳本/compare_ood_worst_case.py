#!/usr/bin/env python3
"""每個 OOD 評分器的**最差情況**，用會針對它的 holdout 去量。

## 為什麼需要對抗性的選法

2026-09-24 量到 Permissive 換 `max_softmax` 之後，family-LOO 的
`worst_family_unknown_recall` 從 **0.0000 跳到 0.9216**，而且正常誤報還更低。
但那是一組固定的 family 切法，而 C2C-028 當初選 `mahalanobis` 的**唯一理由**
就是最差情況：

| 評分器 | 測試 A | 測試 B | 最差 |
|---|---:|---:|---:|
| isolation_forest | 0.4316 | 0.6834 | 0.4316 |
| max_softmax | **0.9950** | 0.6900 | 0.6900 |
| mahalanobis | 0.8781 | 0.8935 | **0.8781** |

`max_softmax` 在測試 A 幾乎完美，**被針對時崩到 0.690**。安全系統看最差情況，
所以當時選了 Mahalanobis。那一輪是在**舊資料**上做的。

不重做這個測試，「Permissive 換 MSP」就只是「在某一批資料的某一種切法上比較
好」——而那正是 C2C-028 已經示範過會騙人的那種說法。

## 協定（照 C2C-028，不改）

1. **只用監督訓練列。** 官方 novelty holdout（`sensor_spoof`、`service_dos`）
   整個排除，validation 與 test 都不碰。
2. 對每個候選做 **leave-one-known-class-out**：把一個已知類別抽掉、用其餘已知
   攻擊擬合，量被抽掉那一類的 AUC。這不需要任何未知樣本。
3. **取每個候選自己最差的兩類**當成一組全新的 holdout。每個候選各產生一組，
   所以沒有人只被自己最不擅長的那組針對。
4. 每個候選在**每一組** holdout 上都量一次，回報它的**最差**。

判準寫在跑之前：**最差情況最高的那個勝出。** macro 只作參考。

## 為什麼不用未知樣本也成立

三個候選都只需要已知類別的標籤——`max_softmax` 問「有沒有已知類別敢認領」，
`mahalanobis` 問「離最近的已知類別中心多遠」，`isolation_forest` 問「在已知
攻擊的密度裡嗎」。都不看未知樣本，所以不違反 open-set 設定。

## 用法

    python3 工具腳本/compare_ood_worst_case.py \\
        --features ~/features_refresh_split/fusion_features_permissive.csv \\
        --metrics ~/models_hier_refresh_maha/permissive/training_metrics.json \\
        --output 文件/OOD最差情況_permissive.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SCHEMA = "sros2-firewall-ood-worst-case/v1"
CANDIDATES = ("isolation_forest", "mahalanobis", "max_softmax")
# 每組 holdout 取候選自己最差的幾類。C2C-028 用兩類。
HOLDOUT_SIZE = 2


class WorstCaseError(RuntimeError):
    """協定不符或輸入不足。刻意不吞。"""


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def auc(positive, negative) -> float:
    """Mann-Whitney U 轉 AUC，平手取平均秩。"""
    import numpy as np

    values = np.concatenate([positive, negative])
    if np.all(values == values[0]):
        return 0.5
    order = values.argsort(kind="mergesort")
    ranks = np.empty(len(values), dtype=float)
    ranks[order] = np.arange(1, len(values) + 1, dtype=float)
    unique, inverse, counts = np.unique(values, return_inverse=True, return_counts=True)
    sums = np.zeros(len(unique))
    np.add.at(sums, inverse, ranks)
    ranks = (sums / counts)[inverse]
    n_pos, n_neg = len(positive), len(negative)
    return float((ranks[:n_pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def make_scorer(name, x, y, *, seed, n_estimators):
    """回一個 `suspicion(x)`：越高越可疑。三個候選統一成這個方向。"""
    import numpy as np

    compare = _load(ROOT / "工具腳本" / "compare_ood_scorers.py", "ood_compare")
    if name == "max_softmax":
        return compare._scores_max_softmax(x, y, seed=seed, n_estimators=n_estimators)
    if name == "mahalanobis":
        return compare._scores_mahalanobis(x, y, seed=seed, n_estimators=n_estimators)
    if name != "isolation_forest":
        raise WorstCaseError(f"未知的候選：{name}")

    from firewall_lab.hierarchical_training import _fit_isolation_detector

    weights = np.ones(len(x), dtype=float)
    detector = _fit_isolation_detector(x, weights, seed=seed, n_estimators=n_estimators)
    # score_samples 越低越異常，而這裡的慣例是越高越可疑。
    return lambda values: -detector.score_samples(values)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", required=True)
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--seed", type=int, default=20260825)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    import numpy as np
    import pandas as pd

    from firewall_lab.hierarchical_training import _expanded_matrix

    output = Path(args.output).expanduser()
    if output.exists():
        raise WorstCaseError(f"輸出已存在，拒絕覆寫：{output}")

    metrics = json.loads(Path(args.metrics).expanduser().read_text(encoding="utf-8"))
    frame = pd.read_csv(Path(args.features).expanduser())
    excluded = set(metrics.get("applicable_excluded_sessions", []))
    if excluded:
        frame = frame.loc[
            ~frame["group_id"].astype(str).isin(excluded)
        ].reset_index(drop=True)

    matrix = _expanded_matrix(frame, metrics["source_availability"])
    labels = frame["label"].astype(str).to_numpy()
    split = frame["split"].astype(str).to_numpy()

    official = set(metrics["novelty_protocol"]["holdout_labels"])
    # 只用監督訓練列，官方 holdout 整個排除。validation 與 test 都不碰。
    usable = (split == "train") & ~np.isin(labels, list(official)) & (labels != "normal")
    known = sorted(set(labels[usable]))
    if len(known) < HOLDOUT_SIZE + 3:
        raise WorstCaseError("已知類別太少，無法做 leave-one-class-out")

    rows_used = {
        "train": int(((split == "train") & usable).sum()),
        "validation": 0,
        "test": 0,
        "official_holdout": 0,
    }

    print(f"已知類別 {len(known)} 個，監督訓練攻擊列 {int(usable.sum())} 列")
    print(f"官方 holdout 排除：{sorted(official)}")
    print()

    # ── 步驟 1-2：每個候選的 leave-one-class-out AUC ──
    per_class = {}
    for candidate in CANDIDATES:
        scores = {}
        for held in known:
            fit_rows = np.flatnonzero(usable & (labels != held))
            held_rows = np.flatnonzero(usable & (labels == held))
            suspicion = make_scorer(
                candidate, matrix[fit_rows], labels[fit_rows],
                seed=args.seed, n_estimators=args.n_estimators)
            scores[held] = round(
                auc(suspicion(matrix[held_rows]), suspicion(matrix[fit_rows])), 4)
        per_class[candidate] = scores
        worst = sorted(scores, key=lambda c: scores[c])[:HOLDOUT_SIZE]
        print(f"  {candidate:<18} macro AUC={statistics.mean(scores.values()):.4f}  "
              f"最差兩類={worst}")

    # ── 步驟 3：每個候選最差的兩類各組成一組 holdout ──
    holdouts = {
        candidate: sorted(
            sorted(scores, key=lambda c: scores[c])[:HOLDOUT_SIZE]
        )
        for candidate, scores in per_class.items()
    }
    unique_holdouts = {}
    for owner, classes in holdouts.items():
        unique_holdouts.setdefault(tuple(classes), []).append(owner)

    print()
    print("=== 步驟 4：每個候選在每一組 holdout 上的 AUC ===")
    header = f"{'scorer':<18}" + "".join(
        f"{'/'.join(h):>34}" for h in unique_holdouts
    ) + f"{'worst':>9}"
    print(header)
    print("-" * len(header))

    results = {}
    for candidate in CANDIDATES:
        row = {}
        for classes in unique_holdouts:
            held = set(classes)
            fit_rows = np.flatnonzero(usable & ~np.isin(labels, list(held)))
            held_rows = np.flatnonzero(usable & np.isin(labels, list(held)))
            suspicion = make_scorer(
                candidate, matrix[fit_rows], labels[fit_rows],
                seed=args.seed, n_estimators=args.n_estimators)
            row["/".join(classes)] = round(
                auc(suspicion(matrix[held_rows]), suspicion(matrix[fit_rows])), 4)
        results[candidate] = {
            "per_holdout": row,
            "worst": round(min(row.values()), 4),
            "macro": round(statistics.mean(row.values()), 4),
        }
        cells = "".join(f"{v:>34.4f}" for v in row.values())
        print(f"{candidate:<18}{cells}{results[candidate]['worst']:>9.4f}")

    winner = max(results, key=lambda c: results[c]["worst"])
    print()
    print(f"最差情況最高者：**{winner}**（{results[winner]['worst']:.4f}）")

    report = {
        "schema_version": SCHEMA,
        "features": str(args.features),
        "metrics": str(args.metrics),
        "rows_used": rows_used,
        "official_holdout_excluded": sorted(official),
        "known_classes": known,
        "holdout_size": HOLDOUT_SIZE,
        "leave_one_class_out_auc": per_class,
        "adversarial_holdouts": {
            "/".join(classes): owners for classes, owners in unique_holdouts.items()
        },
        "results": results,
        "winner_by_worst_case": winner,
        "changes_shipped_defaults": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"報告：{output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
