#!/usr/bin/env python3
"""能不能知道「這一次的答案」對不對——把可信度變成量測軸。

## 為什麼要有這一支

到 2026-09-19 為止，本專案比較模型一律只看 balanced accuracy。但一個會**採取
行動**的防火牆，真正要的不是平均分高，而是**它說有把握的時候是對的**：

- 說 0.9 卻只有 0.6 對 → 會去封鎖無辜的來源。
- 說 0.4 但其實都對 → 會放過該擋的。

而隨機森林的「機率」是**投票比例**，不是機率；文獻上樹系集成的輸出會被推向
0 與 1，本來就需要後處理校準。所以「RF 分數最高」與「RF 可以信」是兩件事，
**必須分開量**。

## 量什麼

| 指標 | 回答 |
|---|---|
| `ece` | 說 p 的時候，是不是真的有 p 的比例是對的（top-label，15 個等寬箱） |
| `brier` | 整個機率向量離真相多遠（多類 Brier） |
| `nll` | 對數損失 |
| `overconfidence` | 平均信心 − 實際正確率。**正值＝高估自己** |
| `risk_coverage` | **只在夠有把握時才行動**：覆蓋前 X% 最有信心的場次時，正確率多少 |
| `aurc` | 風險－覆蓋曲線下面積，越低越好 |

`risk_coverage` 是把「能不能知道答案對不對」直接操作化的那一個：
如果覆蓋 60% 時正確率 0.95，那就代表**這個模型知道自己哪裡不確定**，
剩下 40% 可以退回 alert 而不是自動封鎖。

## 折與既有選型工具逐位相同

折、seed、聚合一律沿用 `select_identification_model.py`。這一支需要
`predict_proba`，所以自己跑一次迴圈——**而重建就有分岔的風險**，
所以有一道硬檢查：參考臂的 balanced accuracy 必須與
`select_identification_model.repeated_cv` **逐位相同**，否則以非零碼結束、
不輸出任何數字。C2C-060 記過同一個風險。

## 用法

    python3 工具腳本/measure_prediction_confidence.py \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --eval-split train_validation \\
        --arms random_forest extra_trees hist_gradient_boosting \\
        --reference random_forest --repeats 12 \\
        --output 文件/可信度_enforce.json
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

COVERAGE_GRID = (1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.3)
ECE_BINS = 15


class ConfidenceError(RuntimeError):
    pass


def _load_selector():
    path = _HERE / "select_identification_model.py"
    spec = importlib.util.spec_from_file_location("_selector_conf", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    for need in ("repeated_cv", "session_matrix", "_load_compare",
                 "apply_variant", "parse_arm"):
        if not hasattr(module, need):
            raise ConfidenceError(f"{path.name} 缺少 {need}，介面變了")
    return module


def collect_probabilities(sel, cmp, Xs, ys, sessions, width, *, model,
                          variant, folds, repeats):
    """跑與選型工具相同的折，但記下機率。回傳 (confidence, correct, proba列表)。"""
    import numpy as np
    from sklearn.model_selection import StratifiedGroupKFold

    groups = np.array(sessions)
    confidence, correct, chosen, truth = [], [], [], []
    latency = []
    per_repeat_ba = []

    for r in range(repeats):
        splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True,
                                        random_state=r)
        predicted = np.empty(len(sessions), dtype=object)
        conf = np.zeros(len(sessions))
        for train_index, test_index in splitter.split(Xs, ys, groups=groups):
            Xtr, Xte = sel.apply_variant(variant, width, Xs[train_index],
                                         Xs[test_index])
            estimator = cmp.make_model(model, r)
            estimator.fit(Xtr, ys[train_index])
            if not hasattr(estimator, "predict_proba"):
                raise ConfidenceError(
                    f"{model} 沒有 predict_proba，量不了可信度")
            t0 = time.perf_counter()
            proba = np.asarray(estimator.predict_proba(Xte))
            latency.append((time.perf_counter() - t0) / max(len(test_index), 1))
            if proba.ndim != 2:
                raise ConfidenceError(
                    f"{model} 的 predict_proba 回傳 {proba.ndim} 維，必須是二維")
            classes = [str(c) for c in estimator.classes_]
            if proba.shape[1] != len(classes):
                raise ConfidenceError(
                    f"{model} 的機率寬度 {proba.shape[1]} 與 classes_ "
                    f"{len(classes)} 不符")
            best = proba.argmax(axis=1)
            for pos, row, k in zip(test_index, proba, best):
                predicted[pos] = classes[k]
                conf[pos] = float(row[k])
                # Brier 與 NLL 要完整向量,不是只有最大值。
                chosen.append(row)
                truth.append(classes.index(str(ys[pos]))
                             if str(ys[pos]) in classes else -1)
        from sklearn.metrics import balanced_accuracy_score
        per_repeat_ba.append(float(balanced_accuracy_score(ys, predicted)))
        confidence.extend(conf.tolist())
        correct.extend((predicted == ys).tolist())

    return {
        "confidence": np.array(confidence),
        "correct": np.array(correct, dtype=bool),
        "proba": np.array(chosen),
        "truth_index": np.array(truth),
        "per_repeat_ba": per_repeat_ba,
        "seconds_per_prediction": float(np.mean(latency)),
    }


def calibration_metrics(bundle):
    """ECE／Brier／NLL／過度自信。"""
    import numpy as np

    conf = bundle["confidence"]
    correct = bundle["correct"]
    n = len(conf)
    if n == 0:
        raise ConfidenceError("沒有任何預測，算不了校準")

    edges = np.linspace(0.0, 1.0, ECE_BINS + 1)
    ece = 0.0
    bins = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (conf > lo) & (conf <= hi) if lo > 0 else (conf >= lo) & (conf <= hi)
        if not mask.any():
            continue
        acc = float(correct[mask].mean())
        avg = float(conf[mask].mean())
        weight = float(mask.sum()) / n
        ece += weight * abs(avg - acc)
        bins.append({"lo": round(float(lo), 3), "hi": round(float(hi), 3),
                     "count": int(mask.sum()), "mean_confidence": round(avg, 4),
                     "accuracy": round(acc, 4)})

    proba = bundle["proba"]
    truth = bundle["truth_index"]
    if (truth < 0).any():
        raise ConfidenceError("有真值不在 classes_ 裡，Brier 會算錯")
    onehot = np.zeros_like(proba)
    onehot[np.arange(len(truth)), truth] = 1.0
    brier = float(((proba - onehot) ** 2).sum(axis=1).mean())
    picked = np.clip(proba[np.arange(len(truth)), truth], 1e-12, 1.0)
    nll = float(-np.log(picked).mean())

    return {
        "ece": round(float(ece), 4),
        "brier": round(brier, 4),
        "nll": round(nll, 4),
        "mean_confidence": round(float(conf.mean()), 4),
        "accuracy": round(float(correct.mean()), 4),
        "overconfidence": round(float(conf.mean() - correct.mean()), 4),
        "reliability_bins": bins,
    }


def risk_coverage(bundle):
    """只在夠有把握時才行動：覆蓋前 X% 最有信心的場次，正確率多少。"""
    import numpy as np

    conf = bundle["confidence"]
    correct = bundle["correct"]
    order = np.argsort(-conf, kind="stable")
    ordered = correct[order]
    n = len(ordered)
    running = np.cumsum(ordered) / np.arange(1, n + 1)

    curve = {}
    for coverage in COVERAGE_GRID:
        k = max(int(round(coverage * n)), 1)
        curve[f"{coverage:.1f}"] = {
            "n": k,
            "accuracy": round(float(running[k - 1]), 4),
            "confidence_threshold": round(float(conf[order][k - 1]), 4),
        }
    aurc = float((1.0 - running).mean())
    return {"curve": curve, "aurc": round(aurc, 4)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--features", required=True, type=pathlib.Path)
    parser.add_argument("--eval-split", required=True,
                        choices=("train_validation",))
    parser.add_argument("--arms", nargs="+", required=True)
    parser.add_argument("--reference", required=True,
                        help="要與選型工具逐位相同的那一個臂")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=12)
    parser.add_argument("--skip-equivalence", action="store_true",
                        help="只在偵錯時用；輸出會標記等價檢查未跑。")
    parser.add_argument("--output", type=pathlib.Path)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    sel = _load_selector()
    cmp = sel._load_compare()
    cv = cmp._load_cv()
    helpers = cv._load_helpers()

    all_rows = cv.load_rows(args.features.expanduser())
    rows = [r for r in all_rows if r["split"] in ("train", "validation")]
    used_test = sum(1 for r in rows if r["split"] == "test")
    if used_test:
        raise ConfidenceError(f"有 {used_test} 列 test 混進來了")

    specs = [(a, *sel.parse_arm(a)) for a in args.arms]
    if args.reference not in [s[0] for s in specs]:
        raise ConfidenceError(f"參考臂 {args.reference} 不在 --arms 裡")

    cache = {}

    def matrices(temporal):
        if temporal not in cache:
            cache[temporal] = sel.session_matrix(cmp, cv, helpers, rows,
                                                 temporal)
        return cache[temporal]

    Xs0, ys0, sessions0, _w = matrices("none")
    print(f"[{args.features.name}] {len(sessions0)} 場 / {len(set(ys0))} 類")

    results = {}
    started = time.time()
    for name, model, variant, temporal in specs:
        Xs, ys, sessions, width = matrices(temporal)
        t0 = time.time()
        bundle = collect_probabilities(
            sel, cmp, Xs, ys, sessions, width, model=model, variant=variant,
            folds=args.folds, repeats=args.repeats)
        block = calibration_metrics(bundle)
        block.update(risk_coverage(bundle))
        block["balanced_accuracy"] = round(
            statistics.mean(bundle["per_repeat_ba"]), 4)
        block["seconds_per_prediction"] = round(
            bundle["seconds_per_prediction"], 6)
        results[name] = block
        cov = block["curve"]
        print(f"  {name:34s} BA {block['balanced_accuracy']:.4f} "
              f"ECE {block['ece']:.4f} Brier {block['brier']:.4f} "
              f"過度自信 {block['overconfidence']:+.4f} | "
              f"覆蓋 100%→{cov['1.0']['accuracy']:.3f} "
              f"60%→{cov['0.6']['accuracy']:.3f} "
              f"30%→{cov['0.3']['accuracy']:.3f}  "
              f"({time.time() - t0:5.1f}s)", flush=True)

    # ── 硬檢查：折必須與選型工具逐位相同 ──
    equivalence = {"ran": False}
    if not args.skip_equivalence:
        ref_model, ref_variant, ref_temporal = sel.parse_arm(args.reference)
        Xs, ys, sessions, width = matrices(ref_temporal)
        official = sel.repeated_cv(
            cmp, Xs, ys, sessions, width, model=ref_model,
            variant=ref_variant, folds=args.folds, repeats=args.repeats)
        want = round(statistics.mean(official["scores"]), 10)
        got = round(results[args.reference]["balanced_accuracy"], 10)
        equivalence = {"ran": True, "arm": args.reference,
                       "selector_mean": round(statistics.mean(
                           official["scores"]), 4), "here": got}
        print(f"  等價檢查 {args.reference}：選型工具 {want:.6f} / 本支 {got:.6f}")
        if abs(want - got) > 1e-4:
            raise ConfidenceError(
                f"等價檢查失敗：選型工具 {want} 與本支 {got} 不符——"
                "折或模型建構分岔了，不輸出任何數字")

    payload = {
        "schema_version": "sros2-firewall-prediction-confidence/v1",
        "features_table": str(args.features.expanduser()),
        "eval_split": args.eval_split,
        "test_rows_used": used_test,
        "sessions": len(sessions0),
        "classes": len(set(ys0)),
        "folds": args.folds,
        "repeats": args.repeats,
        "splitter": "StratifiedGroupKFold(shuffle=True, random_state=repeat)",
        "coverage_grid": list(COVERAGE_GRID),
        "ece_bins": ECE_BINS,
        "changes_shipped_defaults": False,
        "equivalence_check": equivalence,
        "results": results,
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
    except ConfidenceError as exc:
        print(f"錯誤：{exc}", file=sys.stderr)
        sys.exit(2)
