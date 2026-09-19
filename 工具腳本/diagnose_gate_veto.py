#!/usr/bin/env python3
"""量化 parallel gate 丟掉了多少 OOD 頭已經認對的未知攻擊。

## 為什麼要問這個

處女 holdout（`command_injection`／`identity_abuse`）上，Mahalanobis 的
**OOD 頭單獨**在 budget 0.05 拿到 unknown recall **0.3290**，
但**整個模型**只有 **0.0273**（C2C-035 更正後的值）。中間掉了約 12 倍。

`hierarchical_model.py` 的 parallel gate 是：

    unknown = attack_rejected & (binary_attack | abnormal_vs_normal)

也就是 OOD 頭認出來還不夠——二元閘門要說是攻擊，**或者** normality 參考也要
說這列不正常。兩個都不成立時，OOD 頭正確的判斷會被丟掉。

`normality_false_reject_budget` 出貨值是 **0.02**，收得很緊。假設是：大量正確
的 OOD 判斷正是在這裡被否決的。本工具把它量出來，並掃 normality 預算看代價。

## 協定

用 **leave-one-family-out**，每一折都重新擬合 binary、normality 與 attack OOD，
被抽掉的家族完全不進擬合、不進門檻選擇。官方 novelty holdout
（`sensor_spoof`／`service_dos`）與 test 全程不碰。

⚠️ 這是**診斷**，不是門檻選擇。它不會改動出貨預設值，artifact 也明白標記
`changes_shipped_defaults=false`。處女 holdout 已經在整個模型層級用過兩次，
本工具刻意不再用它。

## 分解方式

對被抽掉那一族的每一列，先看 OOD 頭有沒有認出來（`attack_rejected`），
認出來的再分三類：

| 類別 | 條件 | 意義 |
|---|---|---|
| `via_binary` | `binary_attack` | 二元閘門本來就抓到了 |
| `via_normality` | `~binary_attack & abnormal` | 靠 normality 參考救回來 |
| **`vetoed`** | `~binary_attack & ~abnormal` | **OOD 頭認對了但被丟掉** |

`vetoed` 就是可以爭取的空間。代價記在 `cost` 底下：正常參考列與已知攻擊
參考列被誤判成未知的比率。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.hierarchical_model import (  # noqa: E402
    RAW_FEATURES,
    family_for_label,
)
from firewall_lab.ood_scorers import MahalanobisNoveltyDetector  # noqa: E402
from firewall_lab.schema import sha256_file  # noqa: E402

SCHEMA = "sros2-firewall-gate-veto-diagnosis/v1"
DEFAULT_NORMALITY_SWEEP = (0.02, 0.05, 0.10, 0.20, 0.30, 0.50)


def _probability(estimator, matrix, label: str):
    import numpy as np

    classes = list(estimator.classes_)
    if label not in classes:
        raise ValueError(f"estimator does not expose the {label!r} class")
    return np.asarray(estimator.predict_proba(matrix))[:, classes.index(label)]


def _fit_attack_ood(name, x, y, weights, *, seed: int, n_estimators: int):
    from firewall_lab.hierarchical_training import _fit_isolation_detector

    if name == "mahalanobis":
        return MahalanobisNoveltyDetector().fit(x, y, sample_weight=weights)
    if name == "isolation_forest":
        return _fit_isolation_detector(
            x, weights, seed=seed, n_estimators=n_estimators
        )
    raise ValueError(f"unknown attack OOD scorer: {name}")


def decompose_paths(binary_attack, abnormal, ood_rejected) -> dict:
    """把「OOD 頭認對的列」拆成三條互斥的路徑。

    gate 的規則是 `unknown = ood_rejected & (binary_attack | abnormal)`，
    所以在 `ood_rejected` 之下恰好有三種去向，而且必然互斥且窮盡：

        via_binary    二元閘門本來就抓到了
        via_normality 二元漏掉，但 normality 參考救回來
        vetoed        兩個都沒說話 → **正確的判斷被丟掉**

    抽成獨立函式是為了讓這個不變量可以被測試——三者相加必須等於
    `ood_rejected`，前兩者相加必須等於 `unknown`。分解錯了會讓「被否決」
    這個數字失去意義，而整份分析就是建立在它上面。
    """
    import numpy as np

    binary_attack = np.asarray(binary_attack, dtype=bool)
    abnormal = np.asarray(abnormal, dtype=bool)
    ood_rejected = np.asarray(ood_rejected, dtype=bool)
    if not (binary_attack.shape == abnormal.shape == ood_rejected.shape):
        raise ValueError("path decomposition needs three equal-length masks")

    unknown = ood_rejected & (binary_attack | abnormal)
    return {
        "ood_rejected": int(ood_rejected.sum()),
        "via_binary": int((ood_rejected & binary_attack).sum()),
        "via_normality": int((ood_rejected & ~binary_attack & abnormal).sum()),
        "vetoed": int((ood_rejected & ~binary_attack & ~abnormal).sum()),
        "unknown": int(unknown.sum()),
    }


def _rate(numerator: int, denominator: int) -> float:
    # 空分母回 0.0 會讓「沒有樣本」看起來像「量到零」，這在這個專案是被明確
    # 禁止的混淆，所以直接讓呼叫端保證分母非零。
    if denominator <= 0:
        raise ValueError("refusing to report a rate over an empty denominator")
    return numerator / denominator


def evaluate(
    feature_csv: Path,
    metrics_path: Path,
    *,
    attack_ood_scorer: str,
    n_estimators: int,
    seed: int,
    binary_normal_fpr: float,
    attack_ood_fpr: float,
    normality_sweep: tuple[float, ...],
) -> dict:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    from firewall_lab.hierarchical_training import (
        _expanded_matrix,
        _fit_isolation_detector,
        _quantile_threshold,
        _session_equal_weights,
        choose_binary_threshold,
    )

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    frame = pd.read_csv(feature_csv)
    required = set(RAW_FEATURES) | {
        "group_id", "session_id", "source", "window",
        "label", "split", "security_mode",
    }
    missing = required - set(frame)
    if missing:
        raise ValueError(f"feature CSV is missing columns: {sorted(missing)}")
    if set(frame["security_mode"].astype(str)) != {metrics["security_mode"]}:
        raise ValueError("feature mode differs from training metrics")

    excluded = set(metrics.get("applicable_excluded_sessions", []))
    if excluded:
        frame = frame.loc[
            ~frame["group_id"].astype(str).isin(excluded)
        ].reset_index(drop=True)

    matrix = _expanded_matrix(frame, metrics["source_availability"])
    labels = frame["label"].astype(str).to_numpy()
    groups = frame["group_id"].astype(str).to_numpy()
    split = frame["split"].astype(str).to_numpy()
    families = np.asarray([family_for_label(x) for x in labels], dtype=object)

    # 官方 novelty holdout 全程排除——它保留給整個模型層級的一次性評估。
    official_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    official_groups = set(
        frame.loc[frame["label"].astype(str).isin(official_labels), "group_id"]
        .astype(str)
    )
    official_mask = np.isin(groups, list(official_groups))

    attack_mask = labels != "normal"
    base_train = (split == "train") & ~official_mask
    validation = (split == "validation") & ~official_mask
    known_families = sorted(set(families[base_train & attack_mask]))
    if len(known_families) < 3:
        raise ValueError("family LOO requires at least three known families")

    threshold_groups = set(metrics["validation_protocol"]["threshold_groups"])
    reference_groups = set(metrics["validation_protocol"]["selection_groups"])
    if threshold_groups & reference_groups:
        raise ValueError("threshold and reference validation groups overlap")
    threshold_mask = np.isin(groups, list(threshold_groups))
    reference_mask = np.isin(groups, list(reference_groups))

    folds: list[dict] = []
    for offset, held in enumerate(known_families):
        held_groups = set(groups[base_train & attack_mask & (families == held)])
        held_groups.update(groups[validation & attack_mask & (families == held)])
        held_mask = np.isin(groups, list(held_groups))

        fit_index = np.flatnonzero(base_train & ~held_mask)
        threshold_index = np.flatnonzero(validation & threshold_mask & ~held_mask)
        unknown_index = np.flatnonzero(
            validation & held_mask & attack_mask & (families == held)
        )
        normal_index = np.flatnonzero(
            validation & reference_mask & ~held_mask & ~attack_mask
        )
        known_index = np.flatnonzero(
            validation & reference_mask & ~held_mask & attack_mask
        )
        partitions = (fit_index, threshold_index, unknown_index,
                      normal_index, known_index)
        if any(len(index) == 0 for index in partitions):
            raise ValueError(f"fold {held} has an empty protocol partition")

        fit_binary = np.where(labels[fit_index] == "normal", "normal", "attack")
        binary_model = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=16, min_samples_leaf=2,
            max_features="sqrt", class_weight="balanced_subsample",
            random_state=seed + offset, n_jobs=1,
        )
        binary_model.fit(
            matrix[fit_index], fit_binary,
            sample_weight=_session_equal_weights(frame, fit_index),
        )
        normal_fit = fit_index[labels[fit_index] == "normal"]
        attack_fit = fit_index[labels[fit_index] != "normal"]
        normality = _fit_isolation_detector(
            matrix[normal_fit], _session_equal_weights(frame, normal_fit),
            seed=seed + 100 + offset, n_estimators=n_estimators,
        )
        attack_ood = _fit_attack_ood(
            attack_ood_scorer, matrix[attack_fit], labels[attack_fit],
            _session_equal_weights(frame, attack_fit),
            seed=seed + 200 + offset, n_estimators=n_estimators,
        )

        threshold_binary = np.where(
            labels[threshold_index] == "normal", "normal", "attack"
        )
        binary_selection = choose_binary_threshold(
            threshold_binary,
            _probability(binary_model, matrix[threshold_index], "attack"),
            maximum_normal_fpr=binary_normal_fpr,
            sample_weight=_session_equal_weights(frame, threshold_index),
        )
        binary_threshold = float(binary_selection["threshold"])
        normal_threshold_rows = threshold_index[
            labels[threshold_index] == "normal"
        ]
        attack_threshold_rows = threshold_index[
            labels[threshold_index] != "normal"
        ]
        attack_ood_threshold = _quantile_threshold(
            attack_ood.score_samples(matrix[attack_threshold_rows]),
            attack_ood_fpr,
        )
        normality_scores_for_threshold = normality.score_samples(
            matrix[normal_threshold_rows]
        )

        # 三個頭的原始分數只算一次，掃預算時只換 normality 門檻。
        cache = {}
        for name, index in (("unknown", unknown_index),
                            ("normal", normal_index),
                            ("known", known_index)):
            cache[name] = {
                "binary": _probability(binary_model, matrix[index], "attack")
                >= binary_threshold,
                "normality": normality.score_samples(matrix[index]),
                "ood": attack_ood.score_samples(matrix[index])
                < attack_ood_threshold,
                "n": int(len(index)),
            }

        sweep = []
        for budget in normality_sweep:
            normality_threshold = _quantile_threshold(
                normality_scores_for_threshold, budget
            )

            def split_paths(entry):
                return decompose_paths(
                    entry["binary"],
                    entry["normality"] < normality_threshold,
                    entry["ood"],
                )

            held_paths = split_paths(cache["unknown"])
            normal_paths = split_paths(cache["normal"])
            known_paths = split_paths(cache["known"])
            n_held = cache["unknown"]["n"]
            sweep.append({
                "normality_false_reject_budget": budget,
                "normality_threshold": float(normality_threshold),
                "held_out_family": {
                    **held_paths,
                    "rows": n_held,
                    # OOD 頭單獨能達到的上限，與整個模型實際達到的
                    "ood_head_ceiling_recall": _rate(
                        held_paths["ood_rejected"], n_held),
                    "whole_model_recall": _rate(held_paths["unknown"], n_held),
                    "vetoed_share_of_correct": (
                        _rate(held_paths["vetoed"], held_paths["ood_rejected"])
                        if held_paths["ood_rejected"] else None
                    ),
                },
                "cost": {
                    "normal_false_unknown_rate": _rate(
                        normal_paths["unknown"], cache["normal"]["n"]),
                    "known_attack_false_unknown_rate": _rate(
                        known_paths["unknown"], cache["known"]["n"]),
                },
            })

        folds.append({
            "held_family": held,
            "held_labels": sorted(set(labels[unknown_index])),
            "rows": {
                "fit": int(len(fit_index)),
                "threshold": int(len(threshold_index)),
                "held_out": int(len(unknown_index)),
                "normal_reference": int(len(normal_index)),
                "known_attack_reference": int(len(known_index)),
            },
            "binary_threshold": binary_threshold,
            "attack_ood_threshold": float(attack_ood_threshold),
            "sweep": sweep,
        })

    # 跨折彙總：每一折等權（macro），避免列數多的家族主導結論。
    summary = []
    for position, budget in enumerate(normality_sweep):
        points = [fold["sweep"][position] for fold in folds]
        ceilings = [p["held_out_family"]["ood_head_ceiling_recall"] for p in points]
        wholes = [p["held_out_family"]["whole_model_recall"] for p in points]
        shares = [p["held_out_family"]["vetoed_share_of_correct"]
                  for p in points
                  if p["held_out_family"]["vetoed_share_of_correct"] is not None]
        summary.append({
            "normality_false_reject_budget": budget,
            "macro_ood_head_ceiling_recall": sum(ceilings) / len(ceilings),
            "macro_whole_model_recall": sum(wholes) / len(wholes),
            "worst_fold_whole_model_recall": min(wholes),
            "macro_vetoed_share_of_correct": (
                sum(shares) / len(shares) if shares else None),
            "macro_normal_false_unknown_rate": sum(
                p["cost"]["normal_false_unknown_rate"] for p in points
            ) / len(points),
            "macro_known_attack_false_unknown_rate": sum(
                p["cost"]["known_attack_false_unknown_rate"] for p in points
            ) / len(points),
        })

    return {
        "schema_version": SCHEMA,
        "evaluated_utc": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "security_mode": metrics["security_mode"],
        "attack_ood_scorer": attack_ood_scorer,
        "protocol": {
            "method": "leave_one_family_out_with_refit",
            "official_novelty_holdout_rows_used": 0,
            "virgin_holdout_rows_used": 0,
            "test_rows_used": 0,
            "binary_normal_fpr": binary_normal_fpr,
            "attack_ood_fpr": attack_ood_fpr,
            "normality_sweep": list(normality_sweep),
        },
        "inputs": {
            "features": str(feature_csv),
            "features_sha256": sha256_file(feature_csv),
            "metrics": str(metrics_path),
        },
        "folds": folds,
        "summary": summary,
        # 這是診斷，不是門檻選擇。出貨預設值不受影響。
        "changes_shipped_defaults": False,
        "deployment_eligible": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--attack-ood-scorer",
                        choices=("isolation_forest", "mahalanobis"),
                        default="mahalanobis")
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--seed", type=int, default=20260827)
    parser.add_argument("--binary-normal-fpr", type=float, default=0.02)
    parser.add_argument("--attack-ood-fpr", type=float, default=0.05)
    parser.add_argument("--normality-sweep", type=float, nargs="+",
                        default=list(DEFAULT_NORMALITY_SWEEP))
    args = parser.parse_args(argv)

    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {args.output}")
    if not 20 <= args.n_estimators <= 500:
        raise ValueError("n_estimators must be in 20..500")
    for name, value in (("binary_normal_fpr", args.binary_normal_fpr),
                        ("attack_ood_fpr", args.attack_ood_fpr)):
        if not 0.0 < value < 1.0:
            raise ValueError(f"{name} must be in (0, 1)")
    sweep = tuple(sorted(set(args.normality_sweep)))
    if not sweep or any(not 0.0 < value < 1.0 for value in sweep):
        raise ValueError("every normality sweep value must be in (0, 1)")

    report = evaluate(
        args.features, args.metrics,
        attack_ood_scorer=args.attack_ood_scorer,
        n_estimators=args.n_estimators,
        seed=args.seed,
        binary_normal_fpr=args.binary_normal_fpr,
        attack_ood_fpr=args.attack_ood_fpr,
        normality_sweep=sweep,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")

    print(f"=== parallel gate 否決診斷（{report['security_mode']}，"
          f"{report['attack_ood_scorer']}）===")
    print(f"  折數 {len(report['folds'])}，"
          f"binary FPR {args.binary_normal_fpr}，"
          f"attack-OOD FPR {args.attack_ood_fpr}")
    print()
    print(f"  {'normality':>10} {'OOD頭上限':>11} {'整個模型':>10} "
          f"{'被否決佔比':>11} {'正常誤判':>10} {'已知誤判':>10}")
    for point in report["summary"]:
        share = point["macro_vetoed_share_of_correct"]
        print(f"  {point['normality_false_reject_budget']:>10.2f} "
              f"{point['macro_ood_head_ceiling_recall']:>11.4f} "
              f"{point['macro_whole_model_recall']:>10.4f} "
              f"{(f'{share:.4f}' if share is not None else '—'):>11} "
              f"{point['macro_normal_false_unknown_rate']:>10.4f} "
              f"{point['macro_known_attack_false_unknown_rate']:>10.4f}")
    print()
    print("  「被否決佔比」= OOD 頭認對了、卻因為二元與 normality 都沒說話"
          "而被丟掉的比率。")
    print(f"\n→ {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
