#!/usr/bin/env python3
"""兩個不新增觀測通道的改善：時序特徵與場次池化。

## 為什麼問這個

到 2026-09-04 為止的結論是「識別率的上限由觀測層決定」。那句話**部分是錯的**：
它把兩件事混在一起——

| 缺口 | 能不能靠現有資料修 |
|---|---|
| **模型沒有用到已有的資訊** | 可以。逐視窗獨立判斷等於丟掉場次內的相關性與時間動態 |
| **資料裡根本沒有那個資訊** | 不行。2026-09-02 量到 Enforce 下八類沒有排他訊號 |

本工具量的是第一種。出貨的扁平模型**只看當前 8 秒視窗的 32 維**，沒有任何
時間脈絡；而一場 session 有 6–7 個視窗 × 2 個來源，最後卻是逐列獨立輸出。

## 兩個改動

**時序特徵**：對每條 `(session_id, source)` 串流加上 `delta1`（與前一視窗的差）、
`mean3`／`max3`（最近三個視窗的滾動統計）。⚠️ **視窗不相鄰就重置**——
C2C-026 記過：把兩個不相鄰的視窗當成接續是錯的。

**場次池化**：一場 session 就是一種攻擊。把該場所有列的機率取平均後才 argmax。
預設規則是 `attack_only`：只平均「模型自己判成非 normal」的視窗，
沒有的話退回全部。這在推論時不需要任何標籤。

## 兩道強制對照（不能關）

改善幅度大的時候，先懷疑量測——本專案已被這類問題咬過六次。

1. **打亂場次標籤**：整場換標籤後重跑，必須掉到亂猜附近。不掉 → 有洩漏。
2. **位置混淆**：攻擊起始視窗 98% 固定在 window 1，所以任何編碼「第幾個視窗」
   的東西都會有效，而那在攻擊時間任意的真實部署上不會轉移。
   所以另跑一臂「base ＋ 視窗編號」：若它就足以解釋提升，那提升是 harness 產物。

兩道都通不過就以非零碼結束，不會安靜地給出一張漂亮的表。

## ⚠️ 這支不產生可引用的成績

`--split` 的評估分區**只接受 validation**。final test 已於 2026-09-03 開過一次，
再開就不是獨立評估。本工具的輸出只能回答「值不值得在下一批資料上驗」。

## 用法

    python3 工具腳本/evaluate_pooling_and_temporal.py \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --output 文件/池化與時序_enforce.json
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
from pathlib import Path

NON_FEATURE = frozenset({
    "session_id", "group_id", "capture_id", "scenario_id", "security_mode",
    "ros_domain_id", "origin", "source", "window", "window_start_unix",
    "label", "binary", "label_scope", "training_eligible",
    "evaluation_eligible", "policy_sha256", "split", "novelty_role",
})

POOLING_RULES = ("window", "session_mean", "session_vote", "session_attack_only")


class EvalError(RuntimeError):
    """輸入或對照不足以支撐結論。刻意不吞。"""


def load_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise EvalError(f"特徵表是空的：{path}")
    for need in ("session_id", "source", "window", "label", "split"):
        if need not in rows[0]:
            raise EvalError(f"特徵表缺少必要欄位：{need}")
    return rows


def live_matrix(rows: list[dict]):
    """回傳 (X, 特徵名)。恆為常數的欄位剔除——它們對任何模型都沒有作用。"""
    import numpy as np

    names = sorted(n for n in rows[0] if n not in NON_FEATURE)
    X = np.zeros((len(rows), len(names)))
    for i, row in enumerate(rows):
        for j, name in enumerate(names):
            raw = row.get(name)
            try:
                X[i, j] = float(raw) if raw not in (None, "") else 0.0
            except (TypeError, ValueError):
                X[i, j] = 0.0
    live = [j for j in range(len(names)) if X[:, j].min() != X[:, j].max()]
    if not live:
        raise EvalError("沒有任何有變異的特徵")
    return X[:, live], [names[j] for j in live]


def temporal_matrix(rows: list[dict], X):
    """加上 delta1 / mean3 / max3。串流鍵 `(session_id, source)`，缺口重置。

    不加 `history` 旗標：實測它們沒有幫助（0.5621 對 0.5556），而且它們直接
    編碼「有幾個過去視窗」，也就是位置資訊——正是位置混淆檢定要排除的東西。
    """
    import numpy as np

    streams = collections.defaultdict(list)
    for i, row in enumerate(rows):
        streams[(row["session_id"], row["source"])].append((int(row["window"]), i))

    delta = np.zeros_like(X)
    mean3 = X.copy()
    max3 = X.copy()
    resets = 0
    for _, seq in streams.items():
        seq.sort()
        buf: list[int] = []
        previous = None
        for window, i in seq:
            if previous is None or window != previous + 1:
                if previous is not None:
                    resets += 1
                buf = []
            if buf:
                delta[i] = X[i] - X[buf[-1]]
            recent = [X[j] for j in buf[-2:]] + [X[i]]
            mean3[i] = np.mean(recent, axis=0)
            max3[i] = np.max(recent, axis=0)
            buf.append(i)
            previous = window
    return np.hstack([X, delta, mean3, max3]), resets


def session_labels(rows: list[dict], sessions) -> dict[str, str]:
    """一場的標籤＝該場出現過的非 normal 標籤；全部 normal 就是 normal。"""
    seen = collections.defaultdict(set)
    for row in rows:
        seen[row["session_id"]].add(row["label"])
    out = {}
    for s in sessions:
        attack = seen[s] - {"normal"}
        if len(attack) > 1:
            raise EvalError(f"場次 {s} 有多個攻擊標籤：{sorted(attack)}")
        out[s] = sorted(attack)[0] if attack else "normal"
    return out


def pool(rule: str, classes, probabilities, session_ids, sessions):
    """把逐列機率合成每場一個判定。回傳與 `sessions` 同序的預測。"""
    import numpy as np

    grouped = collections.defaultdict(list)
    for row_index, sid in enumerate(session_ids):
        grouped[sid].append(probabilities[row_index])

    out = []
    for s in sessions:
        block = grouped[s]
        if rule == "session_mean":
            out.append(classes[np.mean(block, axis=0).argmax()])
        elif rule == "session_vote":
            counts = collections.Counter(classes[p.argmax()] for p in block)
            out.append(counts.most_common(1)[0][0])
        elif rule == "session_attack_only":
            chosen = [p for p in block if classes[p.argmax()] != "normal"]
            out.append(classes[np.mean(chosen or block, axis=0).argmax()])
        else:
            raise EvalError(f"unknown pooling rule: {rule}")
    return np.array(out)


def fit_predict(X, y, train, evaluate, seed):
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(
        n_estimators=300, class_weight="balanced_subsample",
        random_state=seed, n_jobs=-1,
    )
    model.fit(X[train], y[train])
    return np.asarray(model.predict_proba(X[evaluate])), list(model.classes_)


def score_arm(X, y, sid, train, evaluate, sessions, truth, seeds, rule):
    import numpy as np
    from sklearn.metrics import balanced_accuracy_score

    window_scores, session_scores = [], []
    last_prediction = None
    for seed in seeds:
        proba, classes = fit_predict(X, y, train, evaluate, seed)
        window_prediction = np.array([classes[k] for k in proba.argmax(axis=1)])
        window_scores.append(balanced_accuracy_score(y[evaluate], window_prediction))
        pooled = pool(rule, classes, proba, sid[evaluate], sessions)
        session_scores.append(balanced_accuracy_score(truth, pooled))
        last_prediction = pooled
    return {
        "window_balanced_accuracy": round(float(np.mean(window_scores)), 4),
        "session_balanced_accuracy": round(float(np.mean(session_scores)), 4),
        "session_per_seed": [round(float(v), 4) for v in session_scores],
    }, last_prediction


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--fit-split", default="train")
    parser.add_argument("--eval-split", default="validation", choices=("validation",),
                        help="只接受 validation：final test 已經開過一次")
    parser.add_argument("--pooling", default="session_attack_only",
                        choices=[r for r in POOLING_RULES if r != "window"])
    parser.add_argument("--seeds", type=int, nargs="+", default=[20260915, 7, 991])
    parser.add_argument("--max-shuffled-ratio", type=float, default=0.35,
                        help="打亂對照的場次分數不得超過真實分數的這個比例")
    parser.add_argument("--max-position-ratio", type=float, default=0.60,
                        help="只加視窗編號所解釋的提升不得超過時序提升的這個比例")
    parser.add_argument("--no-controls", action="store_true",
                        help="關掉兩道強制對照（只在對照本身除錯時使用）")
    parser.add_argument("--output", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    import numpy as np

    try:
        rows = load_rows(args.features)
        X_base, names = live_matrix(rows)
        X_temporal, resets = temporal_matrix(rows, X_base)
        window_index = np.array([[int(r["window"])] for r in rows], dtype=float)
        X_position = np.hstack([X_base, window_index])

        y = np.array([r["label"] for r in rows])
        split = np.array([r["split"] for r in rows])
        sid = np.array([r["session_id"] for r in rows])
        train = np.flatnonzero(split == args.fit_split)
        evaluate = np.flatnonzero(split == args.eval_split)
        if train.size == 0 or evaluate.size == 0:
            raise EvalError(f"分區是空的：fit={train.size} eval={evaluate.size}")
        if set(sid[train]) & set(sid[evaluate]):
            raise EvalError("訓練與評估分區共用 session——切分洩漏")

        sessions = sorted(set(sid[evaluate]))
        truth_map = session_labels(rows, sessions)
        truth = np.array([truth_map[s] for s in sessions])
    except EvalError as exc:
        print(f"⛔ {exc}")
        return 2

    seeds = tuple(args.seeds)
    arms = {}
    for arm, X in (("base", X_base), ("base+position", X_position),
                   ("base+temporal", X_temporal)):
        arms[arm], _ = score_arm(X, y, sid, train, evaluate, sessions, truth,
                                 seeds, args.pooling)

    print("=== 池化與時序 ===")
    print(f"  特徵表   : {args.features}")
    print(f"  活特徵   : {len(names)}   時序後 {X_temporal.shape[1]}   串流重置 {resets}")
    print(f"  擬合／評估: {args.fit_split} {train.size} 列 ／ "
          f"{args.eval_split} {evaluate.size} 列、{len(sessions)} 場")
    print(f"  池化規則 : {args.pooling}")
    print()
    print("  %-18s %12s %12s" % ("臂", "視窗層級", "場次層級"))
    for arm in ("base", "base+position", "base+temporal"):
        print("  %-18s %12.4f %12.4f"
              % (arm, arms[arm]["window_balanced_accuracy"],
                 arms[arm]["session_balanced_accuracy"]))

    controls = {}
    if not args.no_controls:
        # 對照一：整場換標籤
        rng = np.random.default_rng(seeds[0])
        y_shuffled = y.copy()
        for subset in (train, evaluate):
            subs = sorted(set(sid[subset]))
            relabel = [truth_map.get(s) or session_labels(rows, [s])[s] for s in subs]
            rng.shuffle(relabel)
            mapping = dict(zip(subs, relabel))
            for i in subset:
                y_shuffled[i] = mapping[sid[i]]
        shuffled_truth = np.array([y_shuffled[np.flatnonzero(sid == s)[0]]
                                   for s in sessions])
        shuffled, _ = score_arm(X_temporal, y_shuffled, sid, train, evaluate,
                                sessions, shuffled_truth, seeds[:1], args.pooling)
        chance = 1.0 / max(1, len(set(truth)))
        real = arms["base+temporal"]["session_balanced_accuracy"]
        ratio = shuffled["session_balanced_accuracy"] / real if real else 1.0
        controls["shuffled_labels"] = {
            "session_balanced_accuracy": shuffled["session_balanced_accuracy"],
            "chance_level": round(chance, 4),
            "ratio_to_real": round(float(ratio), 4),
            "passed": bool(ratio <= args.max_shuffled_ratio),
        }

        # 對照二：位置能解釋多少
        gain_temporal = (arms["base+temporal"]["session_balanced_accuracy"]
                         - arms["base"]["session_balanced_accuracy"])
        gain_position = (arms["base+position"]["session_balanced_accuracy"]
                         - arms["base"]["session_balanced_accuracy"])
        explained = (gain_position / gain_temporal) if gain_temporal > 1e-9 else 0.0
        controls["position_confound"] = {
            "temporal_gain": round(float(gain_temporal), 4),
            "position_gain": round(float(gain_position), 4),
            "explained_by_position": round(float(explained), 4),
            "passed": bool(explained <= args.max_position_ratio),
        }

        print()
        print("=== 強制對照 ===")
        c1, c2 = controls["shuffled_labels"], controls["position_confound"]
        print("  打亂場次標籤 : %.4f（亂猜 %.4f，佔真實 %.1f%%）%s"
              % (c1["session_balanced_accuracy"], c1["chance_level"],
                 100 * c1["ratio_to_real"], "  ✅" if c1["passed"] else "  ⛔"))
        print("  位置可解釋度 : 時序 %+.4f、位置 %+.4f → %.1f%%%s"
              % (c2["temporal_gain"], c2["position_gain"],
                 100 * c2["explained_by_position"], "  ✅" if c2["passed"] else "  ⛔"))
        if not (c1["passed"] and c2["passed"]):
            print("\n⛔ 對照未通過，這一輪的提升不可引用。")
            return 3

    report = {
        "schema_version": "sros2-firewall-pooling-temporal/v1",
        "features_table": str(args.features),
        "fit_split": args.fit_split,
        "eval_split": args.eval_split,
        "test_rows_used": 0,
        "pooling_rule": args.pooling,
        "seeds": list(seeds),
        "live_features": len(names),
        "temporal_features": int(X_temporal.shape[1]),
        "stream_resets": resets,
        "evaluation_sessions": len(sessions),
        "arms": arms,
        "controls": controls,
        "controls_enforced": not args.no_controls,
        "changes_shipped_defaults": False,
    }
    if args.output:
        if args.output.exists():
            print(f"\n⛔ 輸出已存在，拒絕覆寫：{args.output}")
            return 2
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8")
        print(f"\n  報告：{args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
