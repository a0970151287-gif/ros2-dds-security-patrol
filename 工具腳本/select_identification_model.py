#!/usr/bin/env python3
"""選定識別模型：把單一固定折換成重複分層 CV，並以**配對**統計比較。

## 為什麼要重做 2026-09-16 那個比較

那一輪給出 24 個學習法的排名，而 2026-09-17 量到這條線的**雜訊地板是
±0.024**——前七名的寬度只有 0.02。也就是那個排名**沒有解析度**：
「第 1 名比第 7 名好」在資料上站不住。

而且量測本身有一個缺陷（2026-09-17 查到）：`GroupKFold` **不洗牌、不吃
seed**，所以 2026-09-15／16 的每一個數字都來自**同一個折分割**，而那個
分割在兩個模式上都是偏的——

    訓練側每類場次數  Enforce 9–17、Permissive 9–16（分層之後都是 13–14）
    Enforce 每一折的測試側還缺 2–3 個完整類別

每一場仍然恰好被預測一次，所以逐類 recall 的**分母**沒問題；壞掉的是
**每一折的訓練條件差很多**，而那個擾動對 24 個模型是同一份、不會抵銷。

## 這一支怎麼量

| | 2026-09-16 | 本工具 |
|---|---|---|
| 折 | `GroupKFold`，**固定一個分割** | `StratifiedGroupKFold(shuffle)`，**R 個分割** |
| 每類訓練場次 | 9–17 | 13–14 |
| 一個臂得到 | 1 個數 | R 個數 → 平均 ± 標準差 |
| 比較 | 直接比大小 | **配對**（每一輪所有臂看同一個分割）＋ 勝率 |

配對是重點：絕對分數的輪間擾動就是那個 ±0.024，但兩個臂在**同一個分割**
上的差把共同擾動消掉，解析度高一個量級。

## 三道強制對照（任一未過就以非零碼結束）

1. **同源檢查**：參考臂用**舊協定**（`GroupKFold` ＋ 3 seed 多數決）跑一次，
   必須重現 `--legacy-artifact` 裡的分數。重現不了代表這一支與既有流程分岔，
   不輸出任何新數字。C2C-060 記過同一個風險。
2. **打亂對照**：把場次標籤打亂後跑同一套重複 CV，必須掉到亂猜附近。
3. **test 永遠不碰**：`--eval-split` 只接受 `train_validation`，而且實際數一次
   test 列。

## 臂的寫法

    <model>[/<variant>[/<temporal>]]

`variant` 是特徵變體，一律**只用訓練折**決定（否則就是洩漏）：

    full        全部 6 個統計量、全部欄位（預設）
    drop_dead   丟掉在**訓練折上**恆為常數的欄位
    stats_*     只留指定的統計量，見 `STAT_SUBSETS`

## 用法

    python3 工具腳本/select_identification_model.py \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --eval-split train_validation \\
        --legacy-artifact 文件/全學習法比較_enforce_2026-09-16.json \\
        --reference hist_gradient_boosting \\
        --arms hist_gradient_boosting voting_soft catboost \\
        --repeats 15 --output 文件/選型_enforce.json
"""
from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import pathlib
import statistics
import sys
import time

_HERE = pathlib.Path(__file__).resolve().parent

# `compare_session_models.aggregate_sessions` 的統計量順序，必須一致。
# 這裡不重寫聚合——重寫就會有兩個版本各自漂移（C2C-054 記過）。
AGGREGATE_STATS = ("mean", "std", "min", "max", "max_abs_delta", "trend")

# 預先宣告的統計量子集。跑完不追加。
STAT_SUBSETS = {
    "stats_level": ("mean", "std", "min", "max"),
    "stats_shape": ("max_abs_delta", "trend"),
    "stats_no_std": ("mean", "min", "max", "max_abs_delta", "trend"),
    "stats_no_minmax": ("mean", "std", "max_abs_delta", "trend"),
    "stats_mean_max": ("mean", "max"),
}
VARIANTS = ("full", "drop_dead") + tuple(STAT_SUBSETS)
TEMPORALS = ("none", "d1_m3_x3", "d1_m3_x3_m5_x5")

# 預先宣告的 HistGB 超參數格點（`--mode grid`）。判讀用**邊際平均**不是挑極值
# ——2026-09-15 的網格就是這樣讀的，因為第 1 名與第 2 名只差 0.0035。
HGB_GRID = {
    "learning_rate": (0.05, 0.1, 0.2),
    "max_leaf_nodes": (7, 15, 31),
    "min_samples_leaf": (5, 20),
    "l2_regularization": (0.0, 1.0),
}


class SelectError(RuntimeError):
    pass


def _load_compare():
    path = _HERE / "compare_session_models.py"
    spec = importlib.util.spec_from_file_location("_cmp_models", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    for need in ("aggregate_sessions", "make_model", "_load_cv",
                 "AGGREGATE_STATS"):
        if not hasattr(module, need):
            raise SelectError(f"{path.name} 缺少 {need}，介面變了")
    if tuple(module.AGGREGATE_STATS) != AGGREGATE_STATS:
        raise SelectError(
            "聚合統計量的順序與 compare_session_models.py 不一致："
            f"{module.AGGREGATE_STATS} vs {AGGREGATE_STATS}——"
            "欄位切片會切錯，統計量子集那些臂會變成別的東西")
    return module


def parse_arm(text: str) -> tuple[str, str, str]:
    parts = text.split("/")
    if not 1 <= len(parts) <= 3:
        raise SelectError(f"臂的寫法是 model[/variant[/temporal]]：{text!r}")
    model = parts[0]
    variant = parts[1] if len(parts) > 1 else "full"
    temporal = parts[2] if len(parts) > 2 else "none"
    if variant not in VARIANTS:
        raise SelectError(f"未宣告的 variant {variant!r}；可用：{VARIANTS}")
    if temporal not in TEMPORALS:
        raise SelectError(f"未知的 temporal {temporal!r}")
    return model, variant, temporal


def apply_variant(variant: str, width: int, Xtr, Xte):
    """回傳 (Xtr', Xte')。決定保留哪些欄位**只看訓練折**。"""
    import numpy as np

    if variant == "full":
        return Xtr, Xte
    if variant == "drop_dead":
        keep = [j for j in range(Xtr.shape[1])
                if Xtr[:, j].min() != Xtr[:, j].max()]
        if not keep:
            raise SelectError("drop_dead 之後沒有任何欄位")
        return Xtr[:, keep], Xte[:, keep]
    wanted = STAT_SUBSETS[variant]
    keep = []
    for stat in wanted:
        base = AGGREGATE_STATS.index(stat) * width
        keep.extend(range(base, base + width))
    index = np.array(keep)
    return Xtr[:, index], Xte[:, index]


def session_matrix(cmp, cv, helpers, rows, temporal):
    """(Xs, ys, sessions, base_width)。一場一列。"""
    import numpy as np

    X, _resets = cv.build_matrix(helpers, rows, temporal)
    sid = [r["session_id"] for r in rows]
    sessions = sorted(set(sid))
    truth = helpers.session_labels(rows, sessions)
    Xs = cmp.aggregate_sessions(rows, X, sessions)
    ys = np.array([truth[s] for s in sessions])
    if Xs.shape[1] != X.shape[1] * len(AGGREGATE_STATS):
        raise SelectError("聚合後的寬度不是 基礎欄數 × 統計量數，切片會切錯")
    return Xs, ys, sessions, X.shape[1]


def repeated_cv(cmp, Xs, ys, sessions, width, *, model, variant, folds,
                repeats, model_kwargs=None, shuffle_labels=False):
    """R 輪重複分層 CV。第 r 輪的分割由 random_state=r 決定，所有臂共用。

    回傳一個 dict：

        scores            每輪的 balanced accuracy
        hits / totals     逐類命中與總數，**跨全部輪次**累加
        per_repeat_class  每一輪的逐類 recall（算 `ceiling` 要用逐輪的）

    ⚠️ 逐輪與累加的「恆零」是兩件事。累加之後 204 次裡對 1 次就不算零，
    那是「這個模型對這一類到底有沒有訊號」；逐輪 17 次裡全錯才是零，那才能
    與 CLAUDE.md 既有的算術上限（Enforce 0.9412）比。兩個都要記。
    """
    import numpy as np
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import StratifiedGroupKFold

    groups = np.array(sessions)
    per_repeat = []
    per_repeat_class = []
    hits = collections.Counter()
    totals = collections.Counter()

    for r in range(repeats):
        y = ys
        if shuffle_labels:
            rng = np.random.default_rng(90000 + r)
            y = ys.copy()
            rng.shuffle(y)
        splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True,
                                        random_state=r)
        predicted = np.empty(len(sessions), dtype=object)
        covered = np.zeros(len(sessions), dtype=int)
        for train_index, test_index in splitter.split(Xs, y, groups=groups):
            Xtr, Xte = apply_variant(variant, width, Xs[train_index],
                                     Xs[test_index])
            estimator = cmp.make_model(model, r)
            if model_kwargs:
                estimator.set_params(**model_kwargs)
            estimator.fit(Xtr, y[train_index])
            choice = np.asarray(estimator.predict(Xte))
            if choice.ndim != 1:
                raise SelectError(
                    f"{model} 的 predict 回傳 {choice.ndim} 維 {choice.shape}，"
                    "必須是一維（CatBoost 2026-09-16 就是這樣量到 0.0000）")
            predicted[test_index] = [str(c) for c in choice]
            covered[test_index] += 1
        if not (covered == 1).all():
            raise SelectError(
                f"第 {r} 輪有場次被預測 {sorted(set(covered.tolist()))} 次，"
                "必須恰好一次")
        per_repeat.append(float(balanced_accuracy_score(y, predicted)))
        round_hits = collections.Counter()
        round_totals = collections.Counter()
        for actual, guess in zip(y, predicted):
            totals[actual] += 1
            round_totals[actual] += 1
            if actual == guess:
                hits[actual] += 1
                round_hits[actual] += 1
        per_repeat_class.append(
            {label: round_hits[label] / round_totals[label]
             for label in sorted(round_totals)})
    return {"scores": per_repeat, "hits": hits, "totals": totals,
            "per_repeat_class": per_repeat_class}


def ceilings(result):
    """算術上限：恆零的類別鎖死 balanced accuracy 的上限。

    定義沿用 `cross_validate_identification.ceiling()`——
    （類別數 − 恆零類別數）／類別數。這裡多給兩個尺度：

        per_repeat   每一輪各自算一次,再取平均／最小。可與既有的單次數字比。
        pooled       全部輪次累加後才算。回答「這個模型對這一類有沒有訊號」。
    """
    import statistics as _stats

    labels = sorted(result["totals"])
    n = len(labels)
    if not n:
        raise SelectError("沒有任何類別，算不出上限")
    per_repeat = []
    zero_rounds = collections.Counter()
    for recalls in result["per_repeat_class"]:
        zero = [k for k in labels if recalls.get(k, 0.0) == 0.0]
        zero_rounds.update(zero)
        per_repeat.append((n - len(zero)) / n)
    never = sorted(k for k in labels if result["hits"][k] == 0)
    pooled_recall = {k: result["hits"][k] / result["totals"][k]
                     for k in labels}
    worst = min(pooled_recall, key=lambda k: pooled_recall[k])
    return {
        "classes": n,
        # 上限打平時的自然細分:綁住 balanced accuracy 的是最差的那一類。
        "worst_class": worst,
        "worst_class_recall": round(pooled_recall[worst], 4),
        "ceiling_per_repeat_mean": round(_stats.mean(per_repeat), 4),
        "ceiling_per_repeat_min": round(min(per_repeat), 4),
        "ceiling_per_repeat_max": round(max(per_repeat), 4),
        "ceiling_pooled": round((n - len(never)) / n, 4),
        "never_correct_classes": never,
        "zero_in_how_many_repeats": {k: zero_rounds[k]
                                     for k in sorted(zero_rounds)},
    }


def legacy_cv(cmp, Xs, ys, sessions, *, model, folds, seeds):
    """舊協定：`GroupKFold`（不洗牌）＋ 多 seed 多數決。只為了同源檢查。"""
    import numpy as np
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import GroupKFold

    groups = np.array(sessions)
    votes = collections.defaultdict(list)
    for train_index, test_index in GroupKFold(n_splits=folds).split(
            Xs, ys, groups=groups):
        for seed in range(seeds):
            estimator = cmp.make_model(model, seed)
            estimator.fit(Xs[train_index], ys[train_index])
            guesses = np.asarray(estimator.predict(Xs[test_index]))
            for pos, guess in zip(test_index, guesses):
                votes[pos].append(str(guess))
    predicted = [collections.Counter(votes[i]).most_common(1)[0][0]
                 for i in range(len(sessions))]
    return float(balanced_accuracy_score(ys, predicted))


def paired_summary(scores, reference, *, boots=10000, seed=20260917):
    """對照參考臂的**配對**差：平均、bootstrap 95% CI、勝率。"""
    import numpy as np

    rng = np.random.default_rng(seed)
    base = np.array(scores[reference])
    out = {}
    for arm, values in scores.items():
        v = np.array(values)
        if len(v) != len(base):
            raise SelectError(f"{arm} 的輪數與參考臂不同，配對不成立")
        diff = v - base
        idx = rng.integers(0, len(diff), size=(boots, len(diff)))
        means = diff[idx].mean(axis=1)
        out[arm] = {
            "mean": round(float(v.mean()), 4),
            "std": round(float(v.std(ddof=1)) if len(v) > 1 else 0.0, 4),
            "min": round(float(v.min()), 4),
            "max": round(float(v.max()), 4),
            "paired_delta_vs_reference": round(float(diff.mean()), 4),
            "paired_delta_ci95": [round(float(np.percentile(means, 2.5)), 4),
                                  round(float(np.percentile(means, 97.5)), 4)],
            "paired_std": round(
                float(diff.std(ddof=1)) if len(diff) > 1 else 0.0, 4),
            "wins_vs_reference": int((diff > 0).sum()),
            "ties_vs_reference": int((diff == 0).sum()),
            "per_repeat": [round(float(x), 4) for x in v],
        }
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--features", required=True, type=pathlib.Path)
    parser.add_argument(
        "--eval-split", required=True, choices=("train_validation",),
        help="只接受 train_validation。test 已於 2026-09-03 開過一次。")
    parser.add_argument("--mode", default="arms", choices=("arms", "grid"))
    parser.add_argument("--arms", nargs="+", default=())
    parser.add_argument("--reference", required=True)
    parser.add_argument("--grid-model", default="hist_gradient_boosting")
    parser.add_argument(
        "--legacy-artifact", type=pathlib.Path,
        help="舊協定同源檢查要比對的 artifact；省略則跳過（會記在輸出裡）")
    parser.add_argument("--legacy-seeds", type=int, default=3)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=15)
    parser.add_argument("--tolerance", type=float, default=1e-9)
    parser.add_argument("--skip-control", action="store_true",
                        help="只在偵錯時用；輸出會標記對照未跑。")
    parser.add_argument("--output", type=pathlib.Path)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cmp = _load_compare()
    cv = cmp._load_cv()
    helpers = cv._load_helpers()

    all_rows = cv.load_rows(args.features.expanduser())
    rows = [r for r in all_rows if r["split"] in ("train", "validation")]
    test_rows = sum(1 for r in all_rows if r["split"] == "test")
    used_test = sum(1 for r in rows if r["split"] == "test")
    if used_test:
        raise SelectError(f"有 {used_test} 列 test 混進來了")
    if not rows:
        raise SelectError("train+validation 沒有任何列")

    cache = {}

    def matrices(temporal):
        if temporal not in cache:
            cache[temporal] = session_matrix(cmp, cv, helpers, rows, temporal)
        return cache[temporal]

    Xs0, ys0, sessions0, width0 = matrices("none")
    print(f"[{args.features.name}] {len(rows)} 列 / {len(sessions0)} 場 / "
          f"{len(set(ys0))} 類；聚合 {Xs0.shape[1]} 維（基礎 {width0}）")
    print(f"  test 列 {test_rows} 個，用了 {used_test} 個")
    dead = int(sum(1 for j in range(Xs0.shape[1])
                   if Xs0[:, j].min() == Xs0[:, j].max()))
    print(f"  聚合後在全表恆為常數的欄位：{dead} / {Xs0.shape[1]}")

    # ── 對照一：同源檢查 ──
    legacy = {"ran": False}
    if args.legacy_artifact:
        want = json.loads(args.legacy_artifact.read_text(encoding="utf-8"))
        key = f"session_aggregate/{args.reference}"
        if key not in want.get("scores", {}):
            raise SelectError(f"{args.legacy_artifact} 沒有 {key}")
        expected = float(want["scores"][key])
        got = legacy_cv(cmp, Xs0, ys0, sessions0, model=args.reference,
                        folds=args.folds, seeds=args.legacy_seeds)
        legacy = {"ran": True, "model": args.reference,
                  "expected": expected, "got": round(got, 4),
                  "artifact": str(args.legacy_artifact)}
        print(f"  同源檢查 {args.reference}：舊協定 {got:.4f}，"
              f"artifact {expected:.4f}")
        if abs(round(got, 4) - expected) > args.tolerance:
            raise SelectError(
                f"同源檢查失敗：舊協定重跑 {got:.4f} 與 artifact "
                f"{expected:.4f} 不符。這一支與既有流程分岔了，不輸出數字。")

    started = time.time()
    scores = {}
    per_class = {}
    ceiling = {}
    meta = {}

    if args.mode == "arms":
        specs = [(a, *parse_arm(a)) for a in args.arms]
        if args.reference not in [s[0] for s in specs]:
            raise SelectError(f"參考臂 {args.reference} 不在 --arms 裡")
    else:
        specs = []
        for lr in HGB_GRID["learning_rate"]:
            for leaves in HGB_GRID["max_leaf_nodes"]:
                for leaf in HGB_GRID["min_samples_leaf"]:
                    for l2 in HGB_GRID["l2_regularization"]:
                        name = f"lr{lr}_leaves{leaves}_leaf{leaf}_l2{l2}"
                        specs.append((name, args.grid_model, "full", "none"))
                        meta[name] = {"learning_rate": lr,
                                      "max_leaf_nodes": leaves,
                                      "min_samples_leaf": leaf,
                                      "l2_regularization": l2}
        if args.reference not in meta:
            raise SelectError(
                "grid 模式的參考臂要是格點名稱之一，例如 "
                f"{specs[0][0]}；收到 {args.reference}")

    for name, model, variant, temporal in specs:
        Xs, ys, sessions, width = matrices(temporal)
        t0 = time.time()
        result = repeated_cv(
            cmp, Xs, ys, sessions, width, model=model, variant=variant,
            folds=args.folds, repeats=args.repeats,
            model_kwargs=meta.get(name))
        values = result["scores"]
        scores[name] = values
        per_class[name] = {
            label: round(result["hits"][label] / result["totals"][label], 4)
            for label in sorted(result["totals"])}
        ceiling[name] = ceilings(result)
        print(f"  {name:40s} BA {statistics.mean(values):.4f} "
              f"± {statistics.pstdev(values):.4f}   上限 "
              f"{ceiling[name]['ceiling_per_repeat_mean']:.4f} / 累加 "
              f"{ceiling[name]['ceiling_pooled']:.4f}  "
              f"({time.time() - t0:5.1f}s)", flush=True)

    # ── 對照二：打亂場次標籤 ──
    control = {"ran": False}
    if not args.skip_control:
        if args.mode == "arms":
            ref_model, ref_variant, ref_temporal = parse_arm(args.reference)
        else:
            ref_model, ref_variant, ref_temporal = args.grid_model, "full", "none"
        Xs, ys, sessions, width = matrices(ref_temporal)
        shuffled = repeated_cv(
            cmp, Xs, ys, sessions, width, model=ref_model,
            variant=ref_variant, folds=args.folds, repeats=args.repeats,
            model_kwargs=meta.get(args.reference),
            shuffle_labels=True)["scores"]
        chance = 1.0 / len(set(ys0))
        real = statistics.mean(scores[args.reference])
        # 判準相對**亂猜**,不是相對真實分數的一半。類別數不同時亂猜差很多
        # （17 類是 0.059、2 類是 0.5）,拿「真實的一半」當門檻在類別少的時候
        # 會誤殺、在類別多的時候又鬆到沒有作用。
        bar = chance + 0.5 * (real - chance)
        control = {
            "ran": True, "arm": args.reference,
            "chance": round(chance, 4),
            "shuffled_mean": round(statistics.mean(shuffled), 4),
            "shuffled_max": round(max(shuffled), 4),
            "real_mean": round(real, 4),
            "bar": round(bar, 4),
        }
        print(f"  打亂對照 {control['shuffled_mean']:.4f} "
              f"（亂猜 {chance:.4f}，真實 {real:.4f}，門檻 {bar:.4f}）")
        if control["shuffled_mean"] > bar:
            raise SelectError(
                f"打亂對照 {control['shuffled_mean']:.4f} 高過門檻 {bar:.4f}"
                "（亂猜與真實的中點），量測有問題，不輸出數字")

    summary = paired_summary(scores, args.reference)
    for arm, block in summary.items():
        block.update({k: v for k, v in ceiling[arm].items()
                      if k != "zero_in_how_many_repeats"})
    # 主排序用**算術上限**（恆零的類別鎖死 balanced accuracy 的天花板），
    # 同上限再比平均分。只比平均分會選到一個「多對幾場、但某一類永遠是零」
    # 的模型,而那一類在調參與加特徵之後仍然是零。
    ranked = sorted(summary.items(),
                    key=lambda kv: (-kv[1]["ceiling_per_repeat_mean"],
                                    -kv[1]["ceiling_pooled"],
                                    -kv[1]["worst_class_recall"],
                                    -kv[1]["mean"]))
    by_score = sorted(summary, key=lambda a: -summary[a]["mean"])
    print("  ── 依上限排序（打平再看最差類別，再看平均分）──")
    for arm, block in ranked:
        print(f"    上限 {block['ceiling_per_repeat_mean']:.4f} "
              f"(最差輪 {block['ceiling_per_repeat_min']:.4f}) "
              f"最差類 {block['worst_class_recall']:.3f} "
              f"{block['worst_class']:<20s} BA {block['mean']:.4f}  {arm}")

    marginal = {}
    if args.mode == "grid":
        for axis, levels in HGB_GRID.items():
            marginal[axis] = {
                str(level): round(statistics.mean(
                    [statistics.mean(scores[n]) for n in scores
                     if meta[n][axis] == level]), 4)
                for level in levels
            }

    payload = {
        "schema_version": "sros2-firewall-model-selection/v1",
        "mode": args.mode,
        "features_table": str(args.features.expanduser()),
        "eval_split": args.eval_split,
        "test_rows_in_table": test_rows,
        "test_rows_used": used_test,
        "rows": len(rows),
        "sessions": len(sessions0),
        "classes": len(set(ys0)),
        "formulation": "session_aggregate",
        "folds": args.folds,
        "repeats": args.repeats,
        "splitter": "StratifiedGroupKFold(shuffle=True, random_state=repeat)",
        "reference_arm": args.reference,
        "declared_variants": list(VARIANTS),
        "declared_grid": ({k: list(v) for k, v in HGB_GRID.items()}
                          if args.mode == "grid" else None),
        "grid_parameters": meta or None,
        "dead_aggregate_columns_whole_table": dead,
        "aggregate_width": int(Xs0.shape[1]),
        "same_source_check": legacy,
        "shuffle_control": control,
        "changes_shipped_defaults": False,
        "ranking_key": "ceiling_per_repeat_mean, then ceiling_pooled, then mean",
        "ranking_by_ceiling": [a for a, _ in ranked],
        "ranking_by_score": by_score,
        "summary": dict(ranked),
        "ceiling_detail": ceiling,
        "per_class_recall": per_class,
        "marginal_means": marginal or None,
        "elapsed_sec": round(time.time() - started, 1),
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(f"  → {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SelectError as exc:
        print(f"錯誤：{exc}", file=sys.stderr)
        sys.exit(2)
