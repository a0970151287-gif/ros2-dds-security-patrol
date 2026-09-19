#!/usr/bin/env python3
"""比較三種未知攻擊評分器，protocol 與 calibrate_ood_threshold.py 相同。

`calibrate_ood_threshold.py` 量到現行 IsolationForest 的逐類 AUC 是
replay 0.9669、parameter_tamper 0.8937，其餘四類**全部低於 0.5**——被抽掉時
它們看起來比已知攻擊還正常。加大 budget 只會放大前兩類，救不了後四類。

`message_dos` 是關鍵反例：它 closed-set recall 0.970（有專屬的
`oversized_message_ratio`），OOD AUC 卻只有 0.3131。所以問題不是「沒有專屬證據」，
而是**評分方式**：IsolationForest 用密度，只認得比已知更極端的樣本，認不得
只是「不一樣」的樣本。安全上這正好是最糟的失效方向——安靜的新型攻擊看不見。

三種評分器：

    isolation_forest  現行做法，密度式
    max_softmax       1 減去已知類別的最大預測機率（MSP，OOD 標準基線）
    mahalanobis       到最近的已知類別中心的馬氏距離（共用組內共變異）

判別式的兩種不需要未知樣本，只需要已知類別的標籤——與現行做法一樣，
不違反 open-set 設定。

**只用監督訓練列。** holdout 類別完全排除，四個 novelty 計數維持為零。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BUDGETS = (0.02, 0.05, 0.10, 0.20)


def _auc(unknown, known) -> float:
    """未知分數高於隨機一個已知分數的機率。分數一律「越高越可疑」。"""
    import numpy as np

    greater = (unknown[:, None] > known[None, :]).mean()
    equal = (unknown[:, None] == known[None, :]).mean()
    return float(greater + 0.5 * equal)


def _scores_isolation_forest(fit_x, fit_y, *, seed, n_estimators):
    from sklearn.ensemble import IsolationForest

    detector = IsolationForest(
        n_estimators=n_estimators,
        contamination="auto",
        max_features=1.0,
        random_state=seed,
        n_jobs=1,
    )
    detector.fit(fit_x)
    # score_samples 越低越異常，取負號統一成「越高越可疑」。
    return lambda x: -detector.score_samples(x)


def _scores_max_softmax(fit_x, fit_y, *, seed, n_estimators):
    """1 − max P(已知類別)。用與階層 family 層相同的估計器族。

    可疑度靠「沒有任何已知類別敢認領」來表達，而不是靠密度。out-of-bag 的
    預測拿來當已知分數，避免用訓練列自己的過度自信分數當基準。
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        oob_score=True,
        bootstrap=True,
        n_jobs=1,
    )
    model.fit(fit_x, fit_y)
    return lambda x: 1.0 - model.predict_proba(x).max(axis=1)


def _scores_mahalanobis(fit_x, fit_y, *, seed, n_estimators):
    """到最近的已知類別中心的馬氏距離，共用組內共變異。

    這是判別式的：一個「不一樣但不極端」的類別仍然離每個已知中心都很遠，
    而密度式評分會把它算進中央的密集區。
    """
    import numpy as np

    classes = np.unique(fit_y)
    centroids = np.stack([fit_x[fit_y == c].mean(axis=0) for c in classes])
    centred = np.concatenate(
        [fit_x[fit_y == c] - centroids[i] for i, c in enumerate(classes)]
    )
    covariance = np.cov(centred, rowvar=False)
    # 148 維裡有恆為零的欄位，共變異必然奇異；用 pinv 而不是 inv。
    precision = np.linalg.pinv(covariance + 1e-6 * np.eye(covariance.shape[0]))

    def distance(x):
        best = None
        for centroid in centroids:
            delta = x - centroid
            value = np.einsum("ij,jk,ik->i", delta, precision, delta)
            best = value if best is None else np.minimum(best, value)
        return np.sqrt(np.maximum(best, 0.0))

    return distance


SCORERS = {
    "isolation_forest": _scores_isolation_forest,
    "max_softmax": _scores_max_softmax,
    "mahalanobis": _scores_mahalanobis,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--n-estimators", type=int, default=160)
    parser.add_argument("--seed", type=int, default=20260817)
    parser.add_argument(
        "--fresh-holdout",
        action="append",
        default=[],
        help="額外保留的類別：完全退出擬合與 LOO 選擇，改用它們做一次真正的"
             "未知驗證。這兩類從未被當過 holdout，所以評估是乾淨的。",
    )
    args = parser.parse_args()

    import numpy as np
    import pandas as pd
    from sklearn.model_selection import GroupKFold

    from firewall_lab.hierarchical_training import _expanded_matrix

    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    availability = metrics["source_availability"]
    novelty_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    excluded_sessions = set(metrics.get("applicable_excluded_sessions", []))

    frame = pd.read_csv(args.features)
    if excluded_sessions:
        frame = frame.loc[
            ~frame["session_id"].astype(str).isin(excluded_sessions)
        ].reset_index(drop=True)

    labels = frame["label"].astype(str)
    novelty_groups = set(frame.loc[labels.isin(novelty_labels), "group_id"].astype(str))
    train_mask = frame["split"].astype(str).eq("train") & ~frame["group_id"].astype(
        str
    ).isin(novelty_groups)
    fresh = set(args.fresh_holdout)
    unknown_labels = novelty_labels | fresh
    usable = train_mask & ~labels.isin(unknown_labels) & (labels != "normal")
    # 全新 holdout 的驗證列也只取監督訓練列，避免動到 validation／test。
    fresh_usable = train_mask & labels.isin(fresh)

    matrix = _expanded_matrix(frame, availability)
    attack_rows = np.flatnonzero(usable.to_numpy())
    attack_labels = labels.to_numpy()[attack_rows]
    classes = sorted(set(attack_labels))
    print(f"已知攻擊 {len(classes)} 類、訓練列 {len(attack_rows)}；"
          f"排除 holdout {sorted(novelty_labels)}")
    if fresh:
        print(f"全新 holdout（不參與擬合也不參與 LOO 選擇）：{sorted(fresh)}")

    results: dict[str, dict] = {}
    for name, scorer in SCORERS.items():
        per_class = {}
        all_unknown: list[float] = []
        all_known: list[float] = []
        for held in classes:
            held_mask = attack_labels == held
            fit_rows = attack_rows[~held_mask]
            eval_rows = attack_rows[held_mask]
            # 未知分數：用全部 fit 列擬合的評分器評 held 的列。
            unknown = scorer(
                matrix[fit_rows],
                attack_labels[~held_mask],
                seed=args.seed,
                n_estimators=args.n_estimators,
            )(matrix[eval_rows])
            # 已知分數必須 out-of-fold。用擬合列自己的分數會偏樂觀——質心由
            # 它們定義、IsolationForest 也擬合在它們身上——門檻因此偏低，
            # 未知拒絕率會被灌水。分組用 group_id，同一場不可跨 fold。
            known = np.empty(len(fit_rows), dtype=float)
            fit_groups = frame["group_id"].astype(str).to_numpy()[fit_rows]
            folds = GroupKFold(n_splits=4)
            for inner_fit, inner_eval in folds.split(
                matrix[fit_rows], attack_labels[~held_mask], groups=fit_groups
            ):
                known[inner_eval] = scorer(
                    matrix[fit_rows][inner_fit],
                    attack_labels[~held_mask][inner_fit],
                    seed=args.seed,
                    n_estimators=args.n_estimators,
                )(matrix[fit_rows][inner_eval])
            per_class[held] = {
                "rows": int(len(eval_rows)),
                "auc_vs_known": _auc(unknown, known),
            }
            all_unknown.append(unknown)
            all_known.append(known)

        # 逐類先各自標準化成「已知分數的百分位」再合併：三種評分器的尺度
        # 完全不同（機率、距離、isolation 分數），直接混在一起沒有意義。
        pooled_unknown = np.concatenate(
            [
                (u[:, None] > k[None, :]).mean(axis=1)
                for u, k in zip(all_unknown, all_known)
            ]
        )
        curve = []
        for budget in BUDGETS:
            # 已知的分位數在百分位尺度上就是 1 − budget。
            recall = float((pooled_unknown > 1.0 - budget).mean())
            curve.append({"budget": budget, "simulated_unknown_recall": recall})
        macro_auc = float(np.mean([v["auc_vs_known"] for v in per_class.values()]))
        results[name] = {
            "per_class": per_class,
            "macro_auc": macro_auc,
            "curve": curve,
        }

    print()
    print("%-20s" % "類別" + "".join("%18s" % n for n in SCORERS))
    for held in classes:
        print("%-20s" % held + "".join(
            "%18.4f" % results[n]["per_class"][held]["auc_vs_known"] for n in SCORERS))
    print("%-20s" % "macro AUC" + "".join(
        "%18.4f" % results[n]["macro_auc"] for n in SCORERS))
    print()
    print("模擬未知拒絕率（已知誤判 = budget）")
    print("%-20s" % "budget" + "".join("%18s" % n for n in SCORERS))
    for index, budget in enumerate(BUDGETS):
        print("%-20.2f" % budget + "".join(
            "%18.4f" % results[n]["curve"][index]["simulated_unknown_recall"]
            for n in SCORERS))

    fresh_report = {}
    if fresh:
        fresh_rows = np.flatnonzero(fresh_usable.to_numpy())
        fresh_labels = labels.to_numpy()[fresh_rows]
        fit_groups = frame["group_id"].astype(str).to_numpy()[attack_rows]
        print("" + chr(10) + "=== 全新 holdout 驗證（這兩類從未被任何選擇步驟看過）===")
        print("%-20s" % "類別" + "".join("%18s" % n for n in SCORERS))
        for name, scorer in SCORERS.items():
            fitted = scorer(
                matrix[attack_rows],
                attack_labels,
                seed=args.seed,
                n_estimators=args.n_estimators,
            )
            # 已知分數同樣 out-of-fold，否則門檻偏低會灌水。
            known = np.empty(len(attack_rows), dtype=float)
            for inner_fit, inner_eval in GroupKFold(n_splits=4).split(
                matrix[attack_rows], attack_labels, groups=fit_groups
            ):
                known[inner_eval] = scorer(
                    matrix[attack_rows][inner_fit],
                    attack_labels[inner_fit],
                    seed=args.seed,
                    n_estimators=args.n_estimators,
                )(matrix[attack_rows][inner_eval])
            entry = {"per_class": {}, "curve": []}
            for held in sorted(fresh):
                subset = fitted(matrix[fresh_rows[fresh_labels == held]])
                entry["per_class"][held] = {
                    "rows": int((fresh_labels == held).sum()),
                    "auc_vs_known": _auc(subset, known),
                }
            pooled = fitted(matrix[fresh_rows])
            for budget in BUDGETS:
                threshold = float(np.quantile(known, 1.0 - budget, method="higher"))
                entry["curve"].append({
                    "budget": budget,
                    "unknown_recall": float((pooled > threshold).mean()),
                    "known_false_unknown_rate": float((known > threshold).mean()),
                })
            entry["macro_auc"] = float(
                np.mean([v["auc_vs_known"] for v in entry["per_class"].values()])
            )
            fresh_report[name] = entry
        for held in sorted(fresh):
            print("%-20s" % held + "".join(
                "%18.4f" % fresh_report[n]["per_class"][held]["auc_vs_known"]
                for n in SCORERS))
        print("%-20s" % "macro AUC" + "".join(
            "%18.4f" % fresh_report[n]["macro_auc"] for n in SCORERS))
        print("" + chr(10) + "未知拒絕率（已知誤判 = budget）")
        print("%-20s" % "budget" + "".join("%18s" % n for n in SCORERS))
        for index, budget in enumerate(BUDGETS):
            print("%-20.2f" % budget + "".join(
                "%18.4f" % fresh_report[n]["curve"][index]["unknown_recall"]
                for n in SCORERS))

    best = max(results, key=lambda n: results[n]["macro_auc"])
    print(f"\nmacro AUC 最高：{best}（{results[best]['macro_auc']:.4f}）")

    if args.output:
        args.output.write_text(
            json.dumps(
                {
                    "schema_version": "sros2-firewall-ood-scorer-comparison/v1",
                    "method": "leave_one_known_class_out_as_simulated_unknown",
                    "holdout_labels_excluded": sorted(novelty_labels),
                    "known_classes": classes,
                    "scorers": results,
                    "best_by_macro_auc": best,
                    "fresh_holdout_labels": sorted(fresh),
                    "fresh_holdout_verification": fresh_report,
                    "holdout_rows_used": 0,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"→ {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
