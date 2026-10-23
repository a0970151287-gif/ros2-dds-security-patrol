#!/usr/bin/env python3
"""量測 OOD 門檻的跨場次轉移，並比較幾種門檻估計法。

**問題。** 宣告的 `maximum_known_attack_ood_fpr` 是 0.05，但實測已知攻擊被誤否決
為「未知」的比率是 IsolationForest 0.121、Mahalanobis 0.265。門檻沒有轉移。

**懷疑的根因。** `hierarchical_training.py` 把門檻定成
`threshold_validation` 那個分割上的 budget 分位數，而那個分割只有 **19 場**。
用 19 場估一個 5% 分位數，本來就不穩。

但這有兩種完全不同的成因，修法也不同：

    估計集太小      → 改用更多場次的 out-of-fold 分數估計就好
    train→validation 真的偏移 → 換估計集也救不了，得改用 session-level 校準

這支把兩者分開：對每一種估計法，同時回報

    in-sample   在拿來估門檻的那些列上的實現比率（照定義應該 ≈ budget）
    transfer    在**沒有**參與估計的其他 validation 場次上的實現比率

兩者的落差就是轉移誤差。**完全不碰 test，也不碰 novelty holdout。**
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BUDGET_DEFAULT = 0.05


def _weighted_quantile(values, weights, quantile):
    """場次等權的分位數。

    逐列取分位數等於讓視窗多的場次講話大聲；一場就是一個獨立樣本，
    所以權重應該是場次等權，與訓練時 `_session_equal_weights` 的立場一致。
    """
    import numpy as np

    order = np.argsort(values)
    values = np.asarray(values)[order]
    weights = np.asarray(weights, dtype=float)[order]
    cumulative = np.cumsum(weights) - 0.5 * weights
    cumulative /= weights.sum()
    return float(np.interp(quantile, cumulative, values))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--budget", type=float, default=BUDGET_DEFAULT)
    parser.add_argument("--folds", type=int, default=4)
    args = parser.parse_args()

    import numpy as np
    import pandas as pd
    from sklearn.model_selection import GroupKFold

    from firewall_lab.hierarchical_training import (
        _expanded_matrix,
        _fit_isolation_detector,
        _session_equal_weights,
        _validation_partitions,
    )
    from firewall_lab.ood_scorers import MahalanobisNoveltyDetector

    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    availability = metrics["source_availability"]
    novelty_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    excluded = set(metrics.get("applicable_excluded_sessions", []))
    seed = 20260817
    n_estimators = 160

    frame = pd.read_csv(args.features)
    if excluded:
        frame = frame.loc[
            ~frame["session_id"].astype(str).isin(excluded)
        ].reset_index(drop=True)

    labels = frame["label"].astype(str).to_numpy()
    groups = frame["group_id"].astype(str)
    novelty_groups = set(groups[np.isin(labels, list(novelty_labels))])
    matrix = _expanded_matrix(frame, availability)

    # 與訓練程式逐字一致地重建分割
    selection_groups = set(groups) - novelty_groups
    partitions = _validation_partitions(
        frame, allowed_groups=selection_groups, seed=seed
    )
    train_index = np.flatnonzero(
        frame["split"].astype(str).eq("train").to_numpy()
        & ~groups.isin(novelty_groups).to_numpy()
    )
    known_attack = (labels != "normal") & ~np.isin(labels, list(novelty_labels))
    attack_train = train_index[known_attack[train_index]]

    threshold_rows = partitions["threshold"][known_attack[partitions["threshold"]]]
    # 轉移測試集：calibration ＋ selection 兩個分割的已知攻擊列。它們沒有參與
    # 任何一種門檻估計，也不是 test。
    other = np.concatenate([partitions["calibration"], partitions["selection"]])
    transfer_rows = other[known_attack[other]]

    print(f"已知攻擊列：train {len(attack_train)}、"
          f"threshold 分割 {len(threshold_rows)}（{frame.iloc[threshold_rows]['group_id'].nunique()} 場）、"
          f"轉移測試 {len(transfer_rows)}（{frame.iloc[transfer_rows]['group_id'].nunique()} 場）")

    def _fit(name, rows):
        if name == "mahalanobis":
            return MahalanobisNoveltyDetector().fit(matrix[rows], labels[rows])
        return _fit_isolation_detector(
            matrix[rows],
            _session_equal_weights(frame, rows),
            seed=seed + 11,
            n_estimators=n_estimators,
        )

    report: dict[str, dict] = {}
    for scorer in ("isolation_forest", "mahalanobis"):
        detector = _fit(scorer, attack_train)
        threshold_scores = detector.score_samples(matrix[threshold_rows])
        transfer_scores = detector.score_samples(matrix[transfer_rows])

        # out-of-fold 分數：同一場不跨 fold，否則分數是「自己評自己」而偏高。
        oof = np.empty(len(attack_train), dtype=float)
        train_groups = groups.to_numpy()[attack_train]
        for inner_fit, inner_eval in GroupKFold(n_splits=args.folds).split(
            matrix[attack_train], labels[attack_train], groups=train_groups
        ):
            inner = _fit(scorer, attack_train[inner_fit])
            oof[inner_eval] = inner.score_samples(matrix[attack_train[inner_eval]])

        counts = pd.Series(train_groups).value_counts()
        session_weights = np.array([1.0 / counts[g] for g in train_groups])

        methods = {
            # 現行做法：19 場的逐列分位數
            "threshold_validation_quantile": float(
                np.quantile(threshold_scores, args.budget, method="lower")
            ),
            # 改用全部 314 場 train 的 out-of-fold 分數
            "oof_train_quantile": float(
                np.quantile(oof, args.budget, method="lower")
            ),
            # 同上但場次等權：一場算一個獨立樣本，不讓視窗多的場次講話大聲
            "oof_train_session_weighted": _weighted_quantile(
                oof, session_weights, args.budget
            ),
        }
        entry = {}
        for method, threshold in methods.items():
            entry[method] = {
                "threshold": threshold,
                # in-sample 只在該方法自己的估計集上有意義
                "in_sample_rate": float(
                    (threshold_scores < threshold).mean()
                    if method == "threshold_validation_quantile"
                    else (oof < threshold).mean()
                ),
                "transfer_rate": float((transfer_scores < threshold).mean()),
            }
        report[scorer] = entry

    print()
    print("%-32s %12s %12s %12s" % ("估計法", "門檻", "in-sample", "轉移"))
    for scorer, entry in report.items():
        print(f"--- {scorer}（budget {args.budget:.2f}）")
        for method, values in entry.items():
            print("%-32s %12.4f %12.4f %12.4f" % (
                method, values["threshold"], values["in_sample_rate"],
                values["transfer_rate"]))

    if args.output:
        args.output.write_text(
            json.dumps(
                {
                    "schema_version": "sros2-firewall-ood-transfer/v1",
                    "budget": args.budget,
                    "security_mode": metrics["security_mode"],
                    "known_attack_rows": {
                        "train": int(len(attack_train)),
                        "threshold_partition": int(len(threshold_rows)),
                        "transfer": int(len(transfer_rows)),
                    },
                    "scorers": report,
                    "test_rows_used": 0,
                    "novelty_holdout_rows_used": 0,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\n→ {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
