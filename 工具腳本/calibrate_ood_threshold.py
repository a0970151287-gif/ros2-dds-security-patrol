#!/usr/bin/env python3
"""用 leave-one-class-out 當「模擬未知」來校準 OOD 門檻。

**為什麼現行做法拿不到好的 open-set recall。**

現行 OOD 門檻是這樣定的：把 IsolationForest 擬合在**所有已知攻擊**的訓練列上，
再取那些列分數的 `maximum_known_attack_ood_fpr` 分位數當門檻。也就是說——
**門檻只由「已知攻擊長什麼樣」決定，未知從頭到尾沒有參與**。

而那個 budget 被硬性限制在 0.10 以內（0.20 會被程式拒絕），實測 0.05 → 0.10
只讓門檻從 −0.5581 動到 −0.5296。同時 family／leaf 的 coverage 是 1.000，
代表階層棄權那條路徑幾乎從不觸發。三條通往「未知」的路，實際只有一條在跑，
而那一條的門檻是為了保護已知分類而設的。

**這支做的事。** 對每一個已知攻擊類別 c：

    1. 把 OOD 偵測器重新擬合在「已知攻擊減去 c」上
    2. 用它去評 c 的列 —— 這些就是**模擬未知**
    3. 同時評其餘已知攻擊的列 —— 這些是**已知**

於是可以畫出真正的取捨曲線：**模擬未知的拒絕率** 對 **已知被誤判為未知的比率**。
整個過程只用訓練列，**完全沒有碰保留的 holdout**，所以不會污染之後的評估。

輸出是一個建議操作點，不是直接改模型。要採用它必須重新訓練，並在**未動用過的
holdout 類別**上驗證——已經花掉的那組不能重複使用。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--n-estimators", type=int, default=160)
    parser.add_argument("--seed", type=int, default=20260817)
    args = parser.parse_args()

    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest

    from firewall_lab.hierarchical_training import _expanded_matrix

    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    availability = metrics["source_availability"]
    novelty_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    excluded_sessions = set(metrics.get("applicable_excluded_sessions", []))

    frame = pd.read_csv(args.features)
    if excluded_sessions:
        # 與訓練程式套用同一批釘住的排除，否則列的組成不同、曲線就不能對照。
        frame = frame.loc[
            ~frame["session_id"].astype(str).isin(excluded_sessions)
        ].reset_index(drop=True)

    labels = frame["label"].astype(str)
    # holdout group 與 _resolve_holdout_labels 一樣由標籤推導：只要一個 session
    # 出現過 holdout 類別，整個 session 都退出校準。metrics 裡的 holdout_groups
    # 是個計數不是清單，不能直接拿來用。
    novelty_groups = set(
        frame.loc[labels.isin(novelty_labels), "group_id"].astype(str)
    )
    # 監督訓練列的定義與 hierarchical_training.py 逐字一致：split=="train"
    # 且 group 不屬於 novelty holdout。holdout 是之後要用來驗證的，不能參與校準。
    train_mask = frame["split"].astype(str).eq("train") & ~frame["group_id"].astype(
        str
    ).isin(novelty_groups)
    usable = train_mask & ~labels.isin(novelty_labels) & (labels != "normal")
    if not usable.any():
        print("⛔ 沒有可用的已知攻擊訓練列", file=sys.stderr)
        return 1

    matrix = _expanded_matrix(frame, availability)
    attack_rows = np.flatnonzero(usable.to_numpy())
    attack_labels = labels.to_numpy()[attack_rows]
    classes = sorted(set(attack_labels))
    print(f"已知攻擊類別 {len(classes)} 種、訓練列 {len(attack_rows)}")
    print(f"排除的 holdout 類別：{sorted(novelty_labels)}\n")

    # 每個類別各做一次 leave-one-class-out
    simulated_unknown_scores: list[float] = []
    known_scores: list[float] = []
    per_class = {}
    for held in classes:
        held_mask = attack_labels == held
        fit_rows = attack_rows[~held_mask]
        eval_rows = attack_rows[held_mask]
        detector = IsolationForest(
            n_estimators=args.n_estimators,
            contamination="auto",
            max_features=1.0,
            random_state=args.seed,
            n_jobs=1,
        )
        detector.fit(matrix[fit_rows])
        unknown = detector.score_samples(matrix[eval_rows])
        known = detector.score_samples(matrix[fit_rows])
        simulated_unknown_scores.extend(unknown.tolist())
        known_scores.extend(known.tolist())
        # 逐類 AUC：模擬未知的分數低於隨機一個已知分數的機率。0.5 是亂猜，
        # 低於 0.5 代表該類被抽掉時「看起來比已知還正常」——偵測器不可能標它。
        auc = float(
            (unknown[:, None] < known[None, :]).mean()
            + 0.5 * (unknown[:, None] == known[None, :]).mean()
        )
        per_class[held] = {
            "rows": int(len(eval_rows)),
            "unknown_score_median": float(np.median(unknown)),
            "known_score_median": float(np.median(known)),
            "auc_vs_known": auc,
            "scores": unknown,
        }
        print(f"  {held:20s} n={len(eval_rows):5d}  "
              f"模擬未知中位數 {np.median(unknown):+.4f}  "
              f"已知中位數 {np.median(known):+.4f}  AUC {auc:.4f}")

    print("" + chr(10) + "逐類模擬未知拒絕率（門檻取自已知分數的分位數）")
    header = "%-20s" % "類別" + "".join("%10s" % f"b={b:.2f}" for b in (0.02, 0.05, 0.10, 0.20))
    print(header)
    known_all = np.asarray(known_scores)
    per_class_recall = {}
    for held, info in per_class.items():
        row = {}
        cells = []
        for budget in (0.02, 0.05, 0.10, 0.20):
            threshold = float(np.quantile(known_all, budget, method="lower"))
            recall = float((info["scores"] < threshold).mean())
            row[f"{budget:.2f}"] = recall
            cells.append("%10.4f" % recall)
        per_class_recall[held] = row
        print("%-20s" % held + "".join(cells))
    for info in per_class.values():
        info.pop("scores")

    unknown_arr = np.asarray(simulated_unknown_scores)
    known_arr = np.asarray(known_scores)

    print("\n取捨曲線（門檻取自已知分數的分位數）")
    print("%-10s %14s %18s %20s" % (
        "budget", "threshold", "模擬未知拒絕率", "已知誤判為未知"))
    curve = []
    for budget in (0.02, 0.05, 0.10, 0.15, 0.20, 0.30, 0.40, 0.50):
        threshold = float(np.quantile(known_arr, budget, method="lower"))
        unknown_recall = float((unknown_arr < threshold).mean())
        known_false = float((known_arr < threshold).mean())
        curve.append({
            "budget": budget,
            "threshold": threshold,
            "simulated_unknown_recall": unknown_recall,
            "known_false_unknown_rate": known_false,
        })
        print("%-10.2f %14.4f %18.4f %20.4f" % (
            budget, threshold, unknown_recall, known_false))

    # 建議操作點：在「已知誤判 ≤ 0.20」的限制下，取模擬未知拒絕率最高者。
    # 這個規則**寫在看到結果之前**，避免事後挑一個好看的點。
    eligible = [c for c in curve if c["known_false_unknown_rate"] <= 0.20]
    best = max(eligible, key=lambda c: c["simulated_unknown_recall"]) if eligible else None
    print()
    if best:
        print(f"建議操作點（規則：已知誤判 ≤ 0.20 之下最大化未知拒絕率）")
        print(f"  budget {best['budget']:.2f}　門檻 {best['threshold']:.4f}")
        print(f"  模擬未知拒絕率 {best['simulated_unknown_recall']:.4f}"
              f"　已知誤判 {best['known_false_unknown_rate']:.4f}")
        print(f"\n⚠️ 現行程式把 budget 硬性限制在 0.10 以內；"
              f"要採用 {best['budget']:.2f} 必須放寬那個上限。")
    else:
        print("在 0.20 的已知誤判限制下沒有可用操作點。")

    if args.output:
        args.output.write_text(
            json.dumps(
                {
                    "schema_version": "sros2-firewall-ood-calibration/v1",
                    "method": "leave_one_known_class_out_as_simulated_unknown",
                    "holdout_labels_excluded": sorted(novelty_labels),
                    "known_classes": classes,
                    "per_class": per_class,
                    "per_class_recall": per_class_recall,
                    "curve": curve,
                    "recommended": best,
                    "selection_rule": "maximise simulated-unknown recall subject to "
                                      "known false-unknown rate <= 0.20",
                    "holdout_rows_used": 0,
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
