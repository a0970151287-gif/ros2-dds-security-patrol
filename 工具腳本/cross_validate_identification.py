#!/usr/bin/env python3
"""攻擊識別的交叉驗證評估——因為 validation 每類只有 3 場，量不動。

## 為什麼要換量法

`evaluate_pooling_and_temporal.py`（2026-09-15）報的 Enforce 場次層級
0.3218 → 0.5621 是在 **validation 每類 3 場**上量的。逐類 recall 因此只能是
0、0.333、0.667、1.000——**一場的差別就是 0.333**。在那個解析度下：

- 「某一類從 0.000 升到 0.333」可能只是一場剛好猜對；
- 任何超參數搜尋都會擬合那 3 場的雜訊；
- 而 5 個恆零類別到底是「永遠零」還是「3 場剛好全錯」，分不出來。

這支改用 **GroupKFold 依場次切 K 折，跨 train ＋ validation**。每一場恰好被
預測一次，所以逐類 recall 是在**全部約 17 場**上算的，解析度提高約 5 倍。

## test 永遠不碰

`--eval-split` 只接受 `train_validation`。final test 已於 2026-09-03 開過一次，
artifact 會記 `test_rows_used: 0`，而且程式會**實際數**一次 test 列有沒有進來，
不是宣告了就算。

## 上限：balanced accuracy 是逐類 recall 的平均

有 Z 類恆為零、共 K 類，上限就是 `(K-Z)/K`，與模型無關。Enforce 若有 5 類
恆零、共 17 類，上限是 **0.7059**——**低於 0.80 的門檻**。這支把那個數字
算出來並寫進 artifact，因為它決定「還值不值得調模型」。

## 強制對照

打亂場次標籤後重跑。掉不到亂猜附近就代表流程有洩漏，以非零碼結束。

## 用法

    python3 工具腳本/cross_validate_identification.py \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --eval-split train_validation --folds 5 --seeds 3 \\
        --output 文件/識別交叉驗證_enforce.json
"""
from __future__ import annotations

import argparse
import collections
import csv
import importlib.util
import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent


class EvalError(RuntimeError):
    pass


def _load_helpers():
    """重用 `evaluate_pooling_and_temporal.py` 的特徵與池化程式。

    重寫一份就會有兩個版本各自漂移——2026-09-03 的程式碼稽核已經記過
    「讀 manifest ＋ 掃 telemetry 有 21 個檔案各自實作」這個問題。
    """
    path = _HERE / "evaluate_pooling_and_temporal.py"
    spec = importlib.util.spec_from_file_location("_pooling_eval", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    for need in ("live_matrix", "temporal_matrix", "session_labels", "pool",
                 "NON_FEATURE"):
        if not hasattr(module, need):
            raise EvalError(f"{path.name} 缺少 {need}，介面變了")
    return module


def load_rows(path: pathlib.Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise EvalError(f"特徵表是空的：{path}")
    for need in ("session_id", "source", "window", "label", "split"):
        if need not in rows[0]:
            raise EvalError(f"特徵表缺少必要欄位：{need}")
    return rows


def deeper_temporal(rows: list[dict], X):
    """在 delta1／mean3／max3 之外再加 mean5／max5。缺口一樣重置。"""
    import numpy as np

    streams = collections.defaultdict(list)
    for i, row in enumerate(rows):
        streams[(row["session_id"], row["source"])].append((int(row["window"]), i))

    mean5 = X.copy()
    max5 = X.copy()
    for _, seq in streams.items():
        seq.sort()
        buf: list[int] = []
        previous = None
        for window, i in seq:
            if previous is None or window != previous + 1:
                buf = []
            recent = [X[j] for j in buf[-4:]] + [X[i]]
            mean5[i] = np.mean(recent, axis=0)
            max5[i] = np.max(recent, axis=0)
            buf.append(i)
            previous = window
    return np.hstack([mean5, max5])


def build_matrix(helpers, rows, temporal: str):
    X, names = helpers.live_matrix(rows)
    if temporal == "none":
        return X, 0
    expanded, resets = helpers.temporal_matrix(rows, X)
    if temporal == "d1_m3_x3":
        return expanded, resets
    if temporal == "d1_m3_x3_m5_x5":
        import numpy as np
        return np.hstack([expanded, deeper_temporal(rows, X)]), resets
    raise EvalError(f"unknown temporal mode: {temporal}")


def cross_validate(helpers, rows, *, temporal, rule, folds, seeds,
                   n_estimators, class_weight, shuffle_labels=False):
    """每一場恰好被預測一次。回傳 (逐類 recall, 混淆, 總分)。"""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import GroupKFold

    X, _resets = build_matrix(helpers, rows, temporal)
    y = np.array([r["label"] for r in rows])
    sid = np.array([r["session_id"] for r in rows])
    sessions = sorted(set(sid))
    truth = helpers.session_labels(rows, sessions)

    if shuffle_labels:
        # 打亂的是**場次 → 攻擊類別**這個對應，不是逐列標籤。
        #
        # 每場內部的結構要保留：攻擊場次裡本來就有攻擊前後的 normal 列，
        # 把它們一起改掉會讓對照臂的資料結構與真實臂不同，那樣掉下來
        # 就不能歸因於「標籤被打亂」。
        rng = np.random.default_rng(20260915)
        labels = [truth[s] for s in sessions]
        rng.shuffle(labels)
        truth = dict(zip(sessions, labels))
        y = np.array([row_label if row_label == "normal" else truth[session]
                      for session, row_label in zip(sid, y)])

    predicted: dict[str, list[str]] = collections.defaultdict(list)
    splitter = GroupKFold(n_splits=folds)
    for train_index, test_index in splitter.split(X, y, groups=sid):
        fold_sessions = sorted(set(sid[test_index]))
        for seed in seeds:
            model = RandomForestClassifier(
                n_estimators=n_estimators,
                class_weight=class_weight,
                random_state=seed,
                n_jobs=-1,
            )
            model.fit(X[train_index], y[train_index])
            proba = np.asarray(model.predict_proba(X[test_index]))
            classes = list(model.classes_)
            pooled = helpers.pool(rule, classes, proba, sid[test_index],
                                  fold_sessions)
            for session, prediction in zip(fold_sessions, pooled):
                predicted[session].append(str(prediction))

    # 每一場有 len(seeds) 個預測；取多數決當該場的判定。
    final = {}
    for session, votes in predicted.items():
        final[session] = collections.Counter(votes).most_common(1)[0][0]

    y_true = [truth[s] for s in sessions]
    y_pred = [final[s] for s in sessions]
    score = balanced_accuracy_score(y_true, y_pred)

    per_class: dict[str, dict] = {}
    confusion: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: collections.defaultdict(int))
    counts = collections.Counter(y_true)
    hits = collections.Counter()
    for actual, prediction in zip(y_true, y_pred):
        confusion[actual][prediction] += 1
        if actual == prediction:
            hits[actual] += 1
    for label, total in sorted(counts.items()):
        per_class[label] = {
            "sessions": total,
            "correct": hits[label],
            "recall": round(hits[label] / total, 4),
        }
    return per_class, {k: dict(v) for k, v in confusion.items()}, float(score)


def ceiling(per_class: dict) -> dict:
    zero = sorted(k for k, v in per_class.items() if v["recall"] == 0.0)
    total = len(per_class)
    return {
        "classes": total,
        "zero_recall_classes": zero,
        "arithmetic_ceiling": round((total - len(zero)) / total, 4) if total else 0.0,
        "note": "balanced accuracy 是逐類 recall 的平均；恆零的類別鎖死上限。",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--features", required=True, type=pathlib.Path)
    parser.add_argument(
        "--eval-split", required=True, choices=("train_validation",),
        help="只接受 train_validation：final test 已於 2026-09-03 開過一次",
    )
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--trees", type=int, default=300)
    parser.add_argument(
        "--class-weight", default="balanced_subsample",
        choices=("balanced_subsample", "balanced", "none"),
    )
    parser.add_argument(
        "--temporal", default="d1_m3_x3",
        choices=("none", "d1_m3_x3", "d1_m3_x3_m5_x5"),
    )
    parser.add_argument(
        "--rule", default="session_attack_only",
        choices=("session_attack_only", "session_vote", "session_mean"),
    )
    parser.add_argument("--skip-control", action="store_true",
                        help="跳過打亂標籤的對照。要刻意加才會生效。")
    parser.add_argument("--output", type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 輸出檢查放在**最前面**。放在後面等於先算十分鐘的交叉驗證再拒絕，
    # 而且那十分鐘的結果會被丟掉。
    if args.output and args.output.exists():
        print("⛔ %s 已存在，不覆寫" % args.output, file=sys.stderr)
        return 2

    helpers = _load_helpers()

    every_row = load_rows(args.features)
    rows = [r for r in every_row if r.get("split") in ("train", "validation")]
    test_rows_used = sum(1 for r in rows if r.get("split") == "test")
    if test_rows_used:
        print("⛔ test 的列混進來了，這不該發生", file=sys.stderr)
        return 2
    if not rows:
        print("⛔ 沒有 train／validation 的列", file=sys.stderr)
        return 2

    sessions = {r["session_id"] for r in rows}
    print("特徵表 %s" % args.features)
    print("  %d 列 / %d 場（train ＋ validation；test %d 列排除在外）"
          % (len(rows), len(sessions),
             sum(1 for r in every_row if r.get("split") == "test")))
    print("  %d 折 × %d seed，池化 %s，時序 %s，%d 棵樹，class_weight=%s"
          % (args.folds, args.seeds, args.rule, args.temporal,
             args.trees, args.class_weight))
    print()

    weight = None if args.class_weight == "none" else args.class_weight
    seeds = list(range(args.seeds))
    per_class, confusion, score = cross_validate(
        helpers, rows, temporal=args.temporal, rule=args.rule,
        folds=args.folds, seeds=seeds, n_estimators=args.trees,
        class_weight=weight,
    )
    cap = ceiling(per_class)

    print("場次層級 balanced accuracy = %.4f" % score)
    print("算術上限 = %.4f（%d 類，其中 %d 類恆零）"
          % (cap["arithmetic_ceiling"], cap["classes"],
             len(cap["zero_recall_classes"])))
    print()
    print("%-24s %8s %8s %8s" % ("class", "場次", "答對", "recall"))
    for label in sorted(per_class, key=lambda k: (per_class[k]["recall"], k)):
        v = per_class[label]
        print("%-24s %8d %8d %8.3f" % (label, v["sessions"], v["correct"], v["recall"]))
    print()
    if cap["zero_recall_classes"]:
        print("恆零的類別被判到哪裡去了：")
        for label in cap["zero_recall_classes"]:
            got = sorted(confusion.get(label, {}).items(), key=lambda kv: -kv[1])
            print("  %-24s → %s" % (label, ", ".join("%s×%d" % kv for kv in got)))
        print()

    control = None
    if not args.skip_control:
        _pc, _cm, shuffled = cross_validate(
            helpers, rows, temporal=args.temporal, rule=args.rule,
            folds=args.folds, seeds=seeds[:1], n_estimators=args.trees,
            class_weight=weight, shuffle_labels=True,
        )
        chance = 1.0 / cap["classes"] if cap["classes"] else 0.0
        control = {"shuffled_balanced_accuracy": round(shuffled, 4),
                   "chance": round(chance, 4),
                   "share_of_real": round(shuffled / score, 4) if score else None}
        print("對照・打亂場次標籤 = %.4f（亂猜 %.4f，佔真實 %.1f%%）"
              % (shuffled, chance, 100 * shuffled / score if score else 0))
        if shuffled > max(0.35 * score, 2.5 * chance):
            print("⛔ 打亂之後仍然太高，流程可能有洩漏。不輸出。", file=sys.stderr)
            return 1

    report = {
        "schema_version": "sros2-firewall-identification-cv/v1",
        "features_table": str(args.features),
        "eval_split": args.eval_split,
        "test_rows_used": 0,
        "rows": len(rows),
        "sessions": len(sessions),
        "folds": args.folds,
        "seeds": args.seeds,
        "trees": args.trees,
        "class_weight": args.class_weight,
        "temporal": args.temporal,
        "pooling_rule": args.rule,
        "session_balanced_accuracy": round(score, 4),
        "ceiling": cap,
        "per_class": per_class,
        "session_confusion": confusion,
        "control": control,
        "changes_shipped_defaults": False,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8")
        print("wrote %s" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
