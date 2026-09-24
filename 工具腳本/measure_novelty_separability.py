#!/usr/bin/env python3
"""被留出的 family 在特徵空間裡，跟已知攻擊分得開嗎？

## 為什麼先問這個

2026-09-24 的閘門分解顯示 Permissive 的 `alert_only`（= `discovery_recon`）
OOD 拒絕率是 **0.0000**——Mahalanobis 認為它落在已知攻擊的分佈**裡面**——
而二元閘門對它的判定是 **1.0000**。所以失敗不是「看不見」，是「看得見但不覺
得新」。

在換評分器或換特徵子集之前，要先知道**有沒有東西可換**：如果沒有任何一個特徵
能把它從已知攻擊裡分出來，那任何只吃這些特徵的偵測器都不可能成功，而搜尋只會
是在雜訊裡撈。

這支量的是上限，不是方法：對每一個特徵算「被留出 family 的列」對「已知攻擊的
列」的 AUC。AUC 離 0.5 越遠代表那個特徵越能分。**不擬合任何模型。**

## 分區

與 `evaluate_parallel_gate_loo.py` 的 family-LOO 相同：被留出的 family 用它
train＋validation 的全部列（那些列在該折裡本來就不參與擬合），已知攻擊用同折
的擬合集。`test` 全程排除。

## 用法

    python3 工具腳本/measure_novelty_separability.py \\
        --features ~/features_refresh_split/fusion_features_permissive.csv \\
        --metrics ~/models_hier_refresh_maha/permissive/training_metrics.json \\
        --output 文件/未知可分性_permissive.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SCHEMA = "sros2-firewall-novelty-separability/v1"
# 一個特徵要「有用」，AUC 至少要離 0.5 這麼遠。與 2026-09-04 盲點稽核同一個
# 判準，那一輪也記過它太窄會漏掉較弱的訊號，所以這裡同時報完整分佈。
USEFUL_MARGIN = 0.10


class SeparabilityError(RuntimeError):
    """輸入不足或協定不符。刻意不吞。"""


def load_codex_module():
    path = ROOT / "工具腳本" / "evaluate_parallel_gate_loo.py"
    spec = importlib.util.spec_from_file_location("codex_loo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def auc(positive, negative) -> float:
    """Mann-Whitney U 轉成 AUC。沒有變異就回 0.5。"""
    import numpy as np

    values = np.concatenate([positive, negative])
    if np.all(values == values[0]):
        return 0.5
    order = values.argsort(kind="mergesort")
    ranks = np.empty(len(values), dtype=float)
    ranks[order] = np.arange(1, len(values) + 1, dtype=float)
    # 平手取平均秩，否則常數欄位會算出假的分離度。
    unique, inverse, counts = np.unique(values, return_inverse=True, return_counts=True)
    sums = np.zeros(len(unique))
    np.add.at(sums, inverse, ranks)
    ranks = (sums / counts)[inverse]
    n_pos, n_neg = len(positive), len(negative)
    rank_sum = ranks[:n_pos].sum()
    return float((rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", required=True)
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--top", type=int, default=12)
    args = parser.parse_args(argv)

    import numpy as np
    import pandas as pd

    from firewall_lab.hierarchical_training import _expanded_matrix

    codex = load_codex_module()
    metrics = json.loads(Path(args.metrics).expanduser().read_text(encoding="utf-8"))
    frame = pd.read_csv(Path(args.features).expanduser())

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
    usable = base_train | validation

    known_families = sorted(set(families[base_train & attack]))
    names = list(codex.RAW_FEATURES)
    if matrix.shape[1] < len(names):
        raise SeparabilityError("展開後的矩陣欄數比原始特徵少，對不上")

    report = {
        "schema_version": SCHEMA,
        "features": str(args.features),
        "metrics": str(args.metrics),
        "test_rows_used": 0,
        "useful_margin": USEFUL_MARGIN,
        "families": {},
    }

    for held_family in known_families:
        held = set(groups[usable & attack & (families == held_family)])
        held_mask = np.isin(groups, list(held))
        unknown_rows = np.flatnonzero(usable & held_mask & attack
                                      & (families == held_family))
        # 已知攻擊：同折的擬合集，也就是排除掉被留出 family 之後的訓練攻擊列。
        known_rows = np.flatnonzero(base_train & attack & ~held_mask)
        if not len(unknown_rows) or not len(known_rows):
            raise SeparabilityError(f"{held_family} 的分區是空的")

        scored = []
        for column, name in enumerate(names):
            value = auc(matrix[unknown_rows, column], matrix[known_rows, column])
            scored.append({
                "feature": name,
                "auc": round(value, 4),
                "margin": round(abs(value - 0.5), 4),
                "constant": bool(
                    np.all(matrix[np.concatenate([unknown_rows, known_rows]), column]
                           == matrix[unknown_rows[0], column])
                ),
            })
        scored.sort(key=lambda item: -item["margin"])
        useful = [item for item in scored if item["margin"] >= USEFUL_MARGIN]

        report["families"][held_family] = {
            "unknown_rows": int(len(unknown_rows)),
            "unknown_sessions": len(set(groups[unknown_rows])),
            "known_rows": int(len(known_rows)),
            "classes_held": sorted(set(labels[unknown_rows])),
            "best_margin": scored[0]["margin"],
            "features_above_margin": len(useful),
            "constant_features": sum(1 for item in scored if item["constant"]),
            "top": scored[: args.top],
        }

    output = Path(args.output).expanduser()
    if output.exists():
        raise SeparabilityError(f"輸出已存在，拒絕覆寫：{output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(f"報告：{output}")
    print()
    for family, block in report["families"].items():
        print(f"=== {family}  ({block['unknown_sessions']} 場 / "
              f"{block['unknown_rows']} 列, 類別 {block['classes_held']}) ===")
        print(f"  最大 margin = {block['best_margin']:.4f}   "
              f"margin ≥ {USEFUL_MARGIN} 的特徵數 = {block['features_above_margin']}   "
              f"恆為常數 = {block['constant_features']}")
        for item in block["top"][:6]:
            print(f"      {item['feature']:<34} AUC={item['auc']:.4f} "
                  f"margin={item['margin']:.4f}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
