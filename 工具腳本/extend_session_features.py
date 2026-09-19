#!/usr/bin/env python3
"""場次聚合的統計量加料——這是「加資訊」，不是「換模型」。

## 為什麼是這一條

2026-09-16 之後累積的三個量測指向同一件事：

| 換什麼 | 值多少 |
|---|---:|
| 問題表述（逐視窗 → 場次聚合） | **+0.093** |
| 換遍 23 個學習法 | +0.021（而雜訊地板 ±0.024） |
| 逐視窗時序展開（換表述之後） | +0.003 |

換模型已經走完了。**還沒試過的是聚合時到底摘要了什麼。** 現行 6 個統計量
（`mean/std/min/max/max_abs_delta/trend`）是 2026-09-16 一次宣告的，從來
沒有被檢驗過，也從來沒有被加過。

## 宣告的加料（跑完不追加）

每一個基礎特徵，在一場之內：

| 臂 | 加什麼 | 為什麼可能有用 |
|---|---|---|
| `plus_quantiles` | p25／median／p75 | `mean` 會被單一尖峰拉走，分位數不會 |
| `plus_endpoints` | 第一個與最後一個視窗的值（逐 stream 取平均） | `trend` 只有**差**，沒有**落在哪裡** |
| `plus_volatility` | 相鄰差的平均絕對值、相鄰差的標準差 | 現行只有 `max_abs_delta`，分不出「持續抖」與「抖一次」 |
| `plus_all` | 上面全部 | |

**刻意不加的**：視窗數、視窗編號、任何 argmax 的位置。2026-09-15 的位置混淆
檢定就是為了排除這一類——實測攻擊起始視窗 274／280 固定在 window 1，
任何編碼位置的東西都會有效，而那在攻擊時間任意的真實部署上不會轉移。

**刻意不加的（但值得記下來）**：一場有幾個不同的 `source`。它是真的沒被用到
的資訊（聚合把多來源的列平均掉了），但它同時與場次長度相關，要當成特徵需要
自己的位置／長度對照，不在本輪宣告的空間內。

## 怎麼比

重複分層 CV 與配對統計**完全沿用** `select_identification_model.py`——
重寫一份就會有兩個版本各自漂移（C2C-054 的程式碼稽核記過這件事）。
這一支只負責「把矩陣做出來」，評估與統計都是 import 進來的。

## 用法

    python3 工具腳本/extend_session_features.py \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --eval-split train_validation --model hist_gradient_boosting \\
        --repeats 12 --output 文件/聚合統計量加料_enforce.json
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

# 加料的區塊順序，固定。跑完不追加。
EXTRA_BLOCKS = {
    "plus_quantiles": ("p25", "median", "p75"),
    "plus_endpoints": ("first", "last"),
    "plus_volatility": ("mean_abs_delta", "std_abs_delta"),
}
EXTRA_BLOCKS["plus_all"] = tuple(
    name for group in ("plus_quantiles", "plus_endpoints", "plus_volatility")
    for name in EXTRA_BLOCKS[group])
ARMS = ("base",) + tuple(EXTRA_BLOCKS)


class ExtendError(RuntimeError):
    pass


def _load_selector():
    path = _HERE / "select_identification_model.py"
    spec = importlib.util.spec_from_file_location("_selector", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    for need in ("repeated_cv", "paired_summary", "session_matrix",
                 "_load_compare", "AGGREGATE_STATS"):
        if not hasattr(module, need):
            raise ExtendError(f"{path.name} 缺少 {need}，介面變了")
    return module


def streams_of(rows):
    """`(session_id, source)` → 依視窗排序的 `(window, 列索引)`。

    保留視窗編號是刻意的：相鄰差只能在 `window == 前一個 + 1` 時算。
    跨過缺口去算差,等於宣稱兩個不相鄰的視窗在時間上相接——C2C-026 記過,
    而 `aggregate_sessions` 的 `max_abs_delta` 也是這樣跳過缺口的。
    """
    streams = collections.defaultdict(list)
    for i, row in enumerate(rows):
        streams[(row["session_id"], row["source"])].append(
            (int(row["window"]), i))
    per_session = collections.defaultdict(list)
    for (session, _source), seq in streams.items():
        per_session[session].append(sorted(seq))
    return per_session


def extra_matrix(rows, X, sessions, names):
    """回傳 (len(sessions), len(names) * width)。區塊順序照 `names`。

    分位數對**整場所有列**取（與 `mean/std/min/max` 同一個母體）；
    端點與波動度逐 stream 算完再對 stream 取平均（與 `trend` 同一個作法）。
    """
    import numpy as np

    by_session = collections.defaultdict(list)
    for i, row in enumerate(rows):
        by_session[row["session_id"]].append(i)
    per_session = streams_of(rows)

    width = X.shape[1]
    out = np.zeros((len(sessions), width * len(names)))
    for k, session in enumerate(sessions):
        block = X[by_session[session]]
        firsts, lasts, mean_abs, std_abs = [], [], [], []
        for seq in per_session[session]:
            firsts.append(X[seq[0][1]])
            lasts.append(X[seq[-1][1]])
            deltas = [np.abs(X[i] - X[previous])
                      for (window, i), (before, previous)
                      in zip(seq[1:], seq[:-1]) if window == before + 1]
            if deltas:
                stacked = np.vstack(deltas)
                mean_abs.append(stacked.mean(axis=0))
                std_abs.append(stacked.std(axis=0))
            else:
                # 沒有任何相鄰的一對（單一視窗,或整條串流都是缺口）。
                # 補零代表「沒有觀測到變化」——與 `aggregate_sessions` 對
                # `max_abs_delta` 的處置一致。
                mean_abs.append(np.zeros(width))
                std_abs.append(np.zeros(width))
        computed = {
            "p25": np.percentile(block, 25, axis=0),
            "median": np.percentile(block, 50, axis=0),
            "p75": np.percentile(block, 75, axis=0),
            "first": np.mean(firsts, axis=0),
            "last": np.mean(lasts, axis=0),
            "mean_abs_delta": np.mean(mean_abs, axis=0),
            "std_abs_delta": np.mean(std_abs, axis=0),
        }
        missing = [n for n in names if n not in computed]
        if missing:
            raise ExtendError(f"未定義的加料區塊：{missing}")
        out[k] = np.hstack([computed[n] for n in names])
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--features", required=True, type=pathlib.Path)
    parser.add_argument("--eval-split", required=True,
                        choices=("train_validation",))
    parser.add_argument("--model", required=True)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=12)
    parser.add_argument("--skip-control", action="store_true")
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
        raise ExtendError(f"有 {used_test} 列 test 混進來了")

    import numpy as np

    Xs, ys, sessions, width = sel.session_matrix(cmp, cv, helpers, rows, "none")
    X, _resets = cv.build_matrix(helpers, rows, "none")
    if X.shape[1] != width:
        raise ExtendError("基礎寬度對不上，加料的區塊會與基礎欄位錯位")

    print(f"[{args.features.name}] {len(sessions)} 場 / {len(set(ys))} 類；"
          f"基礎 {width} 欄 → 聚合 {Xs.shape[1]} 維")

    matrices = {"base": Xs}
    for arm, names in EXTRA_BLOCKS.items():
        extra = extra_matrix(rows, X, sessions, names)
        matrices[arm] = np.hstack([Xs, extra])
        print(f"  {arm:16s} +{len(names)} 區塊 → {matrices[arm].shape[1]} 維")

    scores, per_class, ceiling = {}, {}, {}
    started = time.time()
    for arm in ARMS:
        t0 = time.time()
        result = sel.repeated_cv(
            cmp, matrices[arm], ys, sessions, width, model=args.model,
            variant="full", folds=args.folds, repeats=args.repeats)
        values = result["scores"]
        scores[arm] = values
        per_class[arm] = {
            label: round(result["hits"][label] / result["totals"][label], 4)
            for label in sorted(result["totals"])}
        ceiling[arm] = sel.ceilings(result)
        print(f"  {arm:16s} BA {statistics.mean(values):.4f} "
              f"± {statistics.pstdev(values):.4f}   上限 "
              f"{ceiling[arm]['ceiling_per_repeat_mean']:.4f}  "
              f"({time.time() - t0:5.1f}s)", flush=True)

    control = {"ran": False}
    if not args.skip_control:
        shuffled = sel.repeated_cv(
            cmp, matrices["plus_all"], ys, sessions, width, model=args.model,
            variant="full", folds=args.folds, repeats=args.repeats,
            shuffle_labels=True)["scores"]
        chance = 1.0 / len(set(ys))
        real = statistics.mean(scores["plus_all"])
        bar = chance + 0.5 * (real - chance)
        control = {"ran": True, "arm": "plus_all", "chance": round(chance, 4),
                   "shuffled_mean": round(statistics.mean(shuffled), 4),
                   "real_mean": round(real, 4), "bar": round(bar, 4)}
        print(f"  打亂對照 {control['shuffled_mean']:.4f} "
              f"（亂猜 {chance:.4f}，門檻 {bar:.4f}）")
        if control["shuffled_mean"] > bar:
            raise ExtendError("打亂對照高過門檻，量測有問題，不輸出數字")

    summary = sel.paired_summary(scores, "base")
    payload = {
        "schema_version": "sros2-firewall-aggregate-extension/v1",
        "features_table": str(args.features.expanduser()),
        "eval_split": args.eval_split,
        "test_rows_used": used_test,
        "sessions": len(sessions),
        "classes": len(set(ys)),
        "model": args.model,
        "folds": args.folds,
        "repeats": args.repeats,
        "splitter": "StratifiedGroupKFold(shuffle=True, random_state=repeat)",
        "base_stats": list(sel.AGGREGATE_STATS),
        "declared_extra_blocks": {k: list(v) for k, v in EXTRA_BLOCKS.items()},
        "dimensions": {a: int(matrices[a].shape[1]) for a in ARMS},
        "changes_shipped_defaults": False,
        "shuffle_control": control,
        "summary": dict(sorted(
            summary.items(),
            key=lambda kv: (-ceiling[kv[0]]["ceiling_per_repeat_mean"],
                            -kv[1]["mean"]))),
        "ceiling_detail": ceiling,
        "per_class_recall": per_class,
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
    except ExtendError as exc:
        print(f"錯誤：{exc}", file=sys.stderr)
        sys.exit(2)
