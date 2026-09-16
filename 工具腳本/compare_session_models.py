#!/usr/bin/env python3
"""換模型類別與問題表述，看識別率還有沒有空間。

## 為什麼做這個

2026-09-15 的超參數網格（`識別超參數網格_2026-09-15.json`）掃完 36 組後結論是
**只有時序深度有用**，class_weight 與樹數都是雜訊。也就是說**在
「RandomForest 逐視窗分類 ＋ 池化」這個框架裡，旋鈕已經轉完了**
（Enforce 0.5571，上限 1.0000）。

所以這一輪換的是框架本身，兩個軸：

| 軸 | 選項 |
|---|---|
| **問題表述** | `per_window_pooled`（現行）／ `session_aggregate` |
| 模型類別 | random_forest（現行）／extra_trees／hist_gradient_boosting／mlp／logistic |

**問題表述那一軸才是重點。** 現行做法把每個視窗獨立分類，再把**機率**平均；
整條軌跡的形狀只透過 `delta1／mean3／max3／mean5／max5` 間接進到每一列。
`session_aggregate` 改成在**特徵層**合併：一場一個向量，直接做場次分類。

第三個表述 `window_sequence` 是 C2C-007 提過的那條路：把一場當成一串視窗
餵進小型 **TCN／GRU**。2026-09-15 修好 WSL 網路（mirrored 初始化失敗、退回
`None`，改回 NAT）之後裝了 torch／xgboost／lightgbm。

⚠️ 套件裝在**平行的** `~/.venvs/sros2-seqmodel`，**沒有動
`~/.venvs/sros2-firewall`**——那個 venv 的 numpy 2.5.0／scikit-learn 1.9.0 是
專案目前每一個模型數字的來源，而可重現性稽核釘著鎖版依賴。新 venv 把
numpy／sklearn／scipy 釘成完全相同的版本，兩邊的 RandomForest 基準才可比；
安裝後已逐字驗過舊 venv 未變。

⚠️ **289 場、17 類，神經網路必然容易過擬合。** 所以網路刻意很小（hidden 32、
dropout 0.3、early stopping）。這一輪要回答的是「序列模型在這個樣本數上有沒有
幫助」，不是「調到最好能多少」。

## 聚合的統計量（先宣告，跑完不追加）

對每一個基礎特徵，在一場之內：

    mean, std, min, max                 ← 全部列（跨 source）
    max_abs_delta                       ← 相鄰視窗差的絕對值最大，**逐 stream**、缺口跳過
    trend                               ← 該 stream 最後一個視窗減第一個，對 stream 取平均

7 個統計量 × 基礎特徵數。

**刻意不放「視窗數」。** 它是場次長度，與視窗編號同一類的位置資訊——
2026-09-15 的位置混淆檢定就是為了排除這種東西。

## 內建的有效性檢查

`per_window_pooled` ＋ `random_forest` 必須重現既有 artifact 的分數
（容差 0.01）。重現不了就代表這支的折、聚合或評分與既有流程分岔，
以非零碼結束、不輸出任何新數字。

## test 永遠不碰

`--eval-split` 只接受 `train_validation`，而且會實際數一次 test 列。

## 用法

    python3 工具腳本/compare_session_models.py \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --eval-split train_validation \\
        --baseline-artifact 文件/識別交叉驗證_enforce_deep_2026-09-15.json \\
        --output 文件/模型類別比較_enforce.json
"""
from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent

FORMULATIONS = ("per_window_pooled", "session_aggregate", "window_sequence")
MODELS = ("random_forest", "extra_trees", "hist_gradient_boosting",
          "xgboost", "lightgbm", "mlp", "logistic")
SEQUENCE_MODELS = ("tcn", "gru")
AGGREGATE_STATS = ("mean", "std", "min", "max", "max_abs_delta", "trend")


class CompareError(RuntimeError):
    pass


def _load_cv():
    path = _HERE / "cross_validate_identification.py"
    spec = importlib.util.spec_from_file_location("_id_cv", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    for need in ("build_matrix", "load_rows", "_load_helpers", "ceiling"):
        if not hasattr(module, need):
            raise CompareError(f"{path.name} 缺少 {need}，介面變了")
    return module


def make_sequence_model(kind: str, in_dim: int, n_classes: int, seed: int):
    """小型序列模型。刻意小——289 場、17 類，大網路量到的是過擬合。"""
    import torch
    from torch import nn

    torch.manual_seed(seed)

    class MaskedPool(nn.Module):
        """padding 不可以參與池化，否則補的零會被當成觀測值。"""

        def forward(self, h, mask):          # h:(B,H,T)  mask:(B,T)
            m = mask.unsqueeze(1)
            total = (h * m).sum(dim=2)
            count = m.sum(dim=2).clamp(min=1.0)
            mean = total / count
            filled = h.masked_fill(m == 0, float("-inf"))
            peak = filled.amax(dim=2)
            peak = torch.nan_to_num(peak, neginf=0.0)
            return torch.cat([mean, peak], dim=1)

    class TinyTCN(nn.Module):
        def __init__(self):
            super().__init__()
            self.body = nn.Sequential(
                nn.Conv1d(in_dim, 32, kernel_size=3, padding=1), nn.ReLU(),
                nn.Dropout(0.3),
                nn.Conv1d(32, 32, kernel_size=3, padding=2, dilation=2),
                nn.ReLU(), nn.Dropout(0.3),
            )
            self.pool = MaskedPool()
            self.head = nn.Linear(64, n_classes)

        def forward(self, x, mask):          # x:(B,T,F)
            return self.head(self.pool(self.body(x.transpose(1, 2)), mask))

    class TinyGRU(nn.Module):
        def __init__(self):
            super().__init__()
            self.gru = nn.GRU(in_dim, 32, batch_first=True)
            self.pool = MaskedPool()
            self.head = nn.Linear(64, n_classes)

        def forward(self, x, mask):
            out, _ = self.gru(x)
            return self.head(self.pool(out.transpose(1, 2), mask))

    if kind == "tcn":
        return TinyTCN()
    if kind == "gru":
        return TinyGRU()
    raise CompareError(f"unknown sequence model: {kind}")


def make_model(name: str, seed: int):
    from sklearn.ensemble import (
        ExtraTreesClassifier,
        HistGradientBoostingClassifier,
        RandomForestClassifier,
    )
    from sklearn.linear_model import LogisticRegression
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    if name == "random_forest":
        return RandomForestClassifier(
            n_estimators=300, class_weight="balanced_subsample",
            random_state=seed, n_jobs=-1)
    if name == "extra_trees":
        return ExtraTreesClassifier(
            n_estimators=300, class_weight="balanced_subsample",
            random_state=seed, n_jobs=-1)
    if name == "hist_gradient_boosting":
        return HistGradientBoostingClassifier(random_state=seed)
    if name == "xgboost":
        from xgboost import XGBClassifier
        from sklearn.preprocessing import LabelEncoder

        class _XGB:
            """XGBClassifier 要數值標籤，這裡包一層 LabelEncoder。"""

            def __init__(self):
                self._encoder = LabelEncoder()
                self._model = XGBClassifier(
                    n_estimators=300, max_depth=6, learning_rate=0.1,
                    subsample=0.9, colsample_bytree=0.9,
                    tree_method="hist", random_state=seed, n_jobs=-1,
                    verbosity=0)

            def fit(self, X, y):
                self._model.fit(X, self._encoder.fit_transform(y))
                self.classes_ = self._encoder.classes_
                return self

            def predict(self, X):
                return self._encoder.inverse_transform(self._model.predict(X))

            def predict_proba(self, X):
                return self._model.predict_proba(X)

        return _XGB()
    if name == "lightgbm":
        from lightgbm import LGBMClassifier
        return LGBMClassifier(
            n_estimators=300, learning_rate=0.1, num_leaves=31,
            class_weight="balanced", random_state=seed, n_jobs=-1,
            verbosity=-1)
    if name == "mlp":
        # 樣本只有約 289 場,網路必須小,否則量到的是過擬合不是模型類別。
        return make_pipeline(
            StandardScaler(),
            MLPClassifier(hidden_layer_sizes=(64,), max_iter=2000,
                          early_stopping=True, random_state=seed))
    if name == "logistic":
        # 線性地板。樹模型贏不過它就代表非線性沒有帶來東西。
        return make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=4000, class_weight="balanced",
                               random_state=seed))
    raise CompareError(f"unknown model: {name}")


def aggregate_sessions(rows, X, sessions):
    """一場一個向量。統計量見模組 docstring,順序固定。"""
    import numpy as np

    by_session = collections.defaultdict(list)
    streams = collections.defaultdict(list)
    for i, row in enumerate(rows):
        by_session[row["session_id"]].append(i)
        streams[(row["session_id"], row["source"])].append((int(row["window"]), i))

    stream_of_session = collections.defaultdict(list)
    for (session, _source), seq in streams.items():
        stream_of_session[session].append(sorted(seq))

    width = X.shape[1]
    out = np.zeros((len(sessions), width * len(AGGREGATE_STATS)))
    for k, session in enumerate(sessions):
        block = X[by_session[session]]
        deltas = []
        trends = []
        for seq in stream_of_session[session]:
            previous_window = None
            previous_index = None
            per_stream = []
            for window, i in seq:
                if previous_window is not None and window == previous_window + 1:
                    per_stream.append(np.abs(X[i] - X[previous_index]))
                previous_window, previous_index = window, i
            deltas.append(np.max(per_stream, axis=0) if per_stream
                          else np.zeros(width))
            trends.append(X[seq[-1][1]] - X[seq[0][1]])
        pieces = [
            block.mean(axis=0),
            block.std(axis=0),
            block.min(axis=0),
            block.max(axis=0),
            np.max(deltas, axis=0) if deltas else np.zeros(width),
            np.mean(trends, axis=0) if trends else np.zeros(width),
        ]
        out[k] = np.hstack(pieces)
    return out


def build_sequences(rows, X, sessions):
    """一場 → (T, F) 的視窗序列，加上長度遮罩。

    同一個視窗可能有多個 `source` 的列，先對 source 取平均再排成序列——
    序列的軸是**時間**，不是 source。
    """
    import numpy as np

    per_session = collections.defaultdict(lambda: collections.defaultdict(list))
    for i, row in enumerate(rows):
        per_session[row["session_id"]][int(row["window"])].append(i)

    lengths = [len(per_session[s]) for s in sessions]
    max_len = max(lengths)
    width = X.shape[1]
    seq = np.zeros((len(sessions), max_len, width))
    mask = np.zeros((len(sessions), max_len))
    for k, session in enumerate(sessions):
        windows = sorted(per_session[session])
        for t, window in enumerate(windows):
            seq[k, t] = X[per_session[session][window]].mean(axis=0)
            mask[k, t] = 1.0
    return seq, mask, max_len


def fit_sequence_model(kind, seq_train, mask_train, y_train, classes,
                       seed, epochs=200, patience=25):
    """訓練一個小序列模型。內部再切一小塊做 early stopping，不看外層的折。"""
    import numpy as np
    import torch
    from torch import nn

    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    index = np.arange(len(y_train))
    rng.shuffle(index)
    cut = max(1, int(0.15 * len(index)))
    inner_validation, inner_train = index[:cut], index[cut:]

    lookup = {c: i for i, c in enumerate(classes)}
    y_index = np.array([lookup[v] for v in y_train])

    # 類別權重：與樹模型的 balanced 對齊，否則比較的是加權方式不是模型類別。
    counts = np.bincount(y_index[inner_train], minlength=len(classes))
    weight = torch.tensor(
        np.where(counts > 0, len(inner_train) / (len(classes) * np.maximum(counts, 1)), 0.0),
        dtype=torch.float32)

    model = make_sequence_model(kind, seq_train.shape[2], len(classes), seed)
    optimiser = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
    loss_function = nn.CrossEntropyLoss(weight=weight)

    Xt = torch.tensor(seq_train, dtype=torch.float32)
    Mt = torch.tensor(mask_train, dtype=torch.float32)
    Yt = torch.tensor(y_index, dtype=torch.long)

    best_loss, best_state, bad = float("inf"), None, 0
    for _epoch in range(epochs):
        model.train()
        optimiser.zero_grad()
        loss = loss_function(model(Xt[inner_train], Mt[inner_train]), Yt[inner_train])
        loss.backward()
        optimiser.step()
        model.eval()
        with torch.no_grad():
            held = loss_function(model(Xt[inner_validation], Mt[inner_validation]),
                                 Yt[inner_validation]).item()
        if held < best_loss - 1e-4:
            best_loss, bad = held, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= patience:
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()
    return model


def evaluate(cv, helpers, rows, *, formulation, model_name, folds, seeds,
             temporal, rule, shuffle_labels=False):
    import numpy as np
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import GroupKFold

    X, _resets = cv.build_matrix(helpers, rows, temporal)
    y = np.array([r["label"] for r in rows])
    sid = np.array([r["session_id"] for r in rows])
    sessions = sorted(set(sid))
    truth = helpers.session_labels(rows, sessions)

    if shuffle_labels:
        rng = np.random.default_rng(20260915)
        labels = [truth[s] for s in sessions]
        rng.shuffle(labels)
        truth = dict(zip(sessions, labels))
        y = np.array([row_label if row_label == "normal" else truth[session]
                      for session, row_label in zip(sid, y)])

    predicted: dict[str, list[str]] = collections.defaultdict(list)

    if formulation == "session_aggregate":
        Xs = aggregate_sessions(rows, X, sessions)
        ys = np.array([truth[s] for s in sessions])
        groups = np.array(sessions)
        for train_index, test_index in GroupKFold(n_splits=folds).split(
                Xs, ys, groups=groups):
            for seed in seeds:
                model = make_model(model_name, seed)
                model.fit(Xs[train_index], ys[train_index])
                for pos, prediction in zip(test_index,
                                           model.predict(Xs[test_index])):
                    predicted[sessions[pos]].append(str(prediction))
    elif formulation == "window_sequence":
        import torch
        from sklearn.preprocessing import StandardScaler

        seq, mask, _max_len = build_sequences(rows, X, sessions)
        ys = np.array([truth[s] for s in sessions])
        groups = np.array(sessions)
        classes = sorted(set(ys))
        for train_index, test_index in GroupKFold(n_splits=folds).split(
                seq, ys, groups=groups):
            # 標準化只用訓練折的統計量，而且只用真實（非 padding）的視窗。
            scaler = StandardScaler()
            flat_train = seq[train_index][mask[train_index] > 0]
            scaler.fit(flat_train)
            scaled = np.zeros_like(seq)
            for k in range(len(sessions)):
                live = mask[k] > 0
                scaled[k, live] = scaler.transform(seq[k, live])
            for seed in seeds:
                model = fit_sequence_model(
                    model_name, scaled[train_index], mask[train_index],
                    ys[train_index], classes, seed)
                with torch.no_grad():
                    logits = model(
                        torch.tensor(scaled[test_index], dtype=torch.float32),
                        torch.tensor(mask[test_index], dtype=torch.float32))
                choice = logits.argmax(dim=1).numpy()
                for pos, k in zip(test_index, choice):
                    predicted[sessions[pos]].append(classes[k])
    elif formulation == "per_window_pooled":
        for train_index, test_index in GroupKFold(n_splits=folds).split(
                X, y, groups=sid):
            fold_sessions = sorted(set(sid[test_index]))
            for seed in seeds:
                model = make_model(model_name, seed)
                model.fit(X[train_index], y[train_index])
                proba = np.asarray(model.predict_proba(X[test_index]))
                classes = list(model.classes_)
                pooled = helpers.pool(rule, classes, proba, sid[test_index],
                                      fold_sessions)
                for session, prediction in zip(fold_sessions, pooled):
                    predicted[session].append(str(prediction))
    else:
        raise CompareError(f"unknown formulation: {formulation}")

    final = {s: collections.Counter(v).most_common(1)[0][0]
             for s, v in predicted.items()}
    y_true = [truth[s] for s in sessions]
    y_pred = [final[s] for s in sessions]

    counts = collections.Counter(y_true)
    hits = collections.Counter(a for a, p in zip(y_true, y_pred) if a == p)
    per_class = {
        label: {"sessions": total, "correct": hits[label],
                "recall": round(hits[label] / total, 4)}
        for label, total in sorted(counts.items())
    }
    return float(balanced_accuracy_score(y_true, y_pred)), per_class


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--features", required=True, type=pathlib.Path)
    parser.add_argument("--eval-split", required=True,
                        choices=("train_validation",))
    parser.add_argument("--baseline-artifact", type=pathlib.Path,
                        help="既有的 CV artifact；用來確認這支沒有分岔")
    parser.add_argument("--tolerance", type=float, default=0.01)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--temporal", default="d1_m3_x3_m5_x5")
    parser.add_argument("--rule", default="session_attack_only")
    parser.add_argument("--skip-control", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output and args.output.exists():
        print("⛔ %s 已存在，不覆寫" % args.output, file=sys.stderr)
        return 2

    cv = _load_cv()
    helpers = cv._load_helpers()
    every_row = cv.load_rows(args.features)
    rows = [r for r in every_row if r.get("split") in ("train", "validation")]
    if not rows:
        print("⛔ 沒有 train／validation 的列", file=sys.stderr)
        return 2
    if any(r.get("split") == "test" for r in rows):
        print("⛔ test 的列混進來了", file=sys.stderr)
        return 2

    sessions = {r["session_id"] for r in rows}
    seeds = list(range(args.seeds))
    print("特徵表 %s" % args.features)
    print("  %d 列 / %d 場（test %d 列排除在外）"
          % (len(rows), len(sessions),
             sum(1 for r in every_row if r.get("split") == "test")))
    print("  %d 折 × %d seed，時序 %s，池化 %s"
          % (args.folds, args.seeds, args.temporal, args.rule))
    print()

    results = {}
    per_class_of = {}
    for formulation in FORMULATIONS:
        names = SEQUENCE_MODELS if formulation == "window_sequence" else MODELS
        for model_name in names:
            score, per_class = evaluate(
                cv, helpers, rows, formulation=formulation,
                model_name=model_name, folds=args.folds, seeds=seeds,
                temporal=args.temporal, rule=args.rule)
            key = f"{formulation}/{model_name}"
            results[key] = round(score, 4)
            per_class_of[key] = per_class
            print("  %-42s %.4f" % (key, score))

    baseline_key = "per_window_pooled/random_forest"
    if args.baseline_artifact:
        known = json.loads(args.baseline_artifact.read_text(encoding="utf-8"))
        expected = float(known["session_balanced_accuracy"])
        got = results[baseline_key]
        print()
        print("有效性檢查：%s 應重現 %.4f，實測 %.4f（容差 %.3f）"
              % (baseline_key, expected, got, args.tolerance))
        if abs(got - expected) > args.tolerance:
            print("⛔ 基準重現不了，這支與既有流程分岔了。不輸出。", file=sys.stderr)
            return 1

    best = max(results, key=lambda k: results[k])
    print()
    print("最佳 %s = %.4f（現行 %s = %.4f，差 %+0.4f）"
          % (best, results[best], baseline_key, results[baseline_key],
             results[best] - results[baseline_key]))

    control = None
    if not args.skip_control:
        shuffled, _pc = evaluate(
            cv, helpers, rows,
            formulation=best.split("/")[0], model_name=best.split("/")[1],
            folds=args.folds, seeds=seeds[:1], temporal=args.temporal,
            rule=args.rule, shuffle_labels=True)
        classes = len(per_class_of[best])
        chance = 1.0 / classes if classes else 0.0
        control = {"configuration": best,
                   "shuffled_balanced_accuracy": round(shuffled, 4),
                   "chance": round(chance, 4)}
        print("對照・打亂場次標籤（%s）= %.4f（亂猜 %.4f，佔真實 %.1f%%）"
              % (best, shuffled, chance,
                 100 * shuffled / results[best] if results[best] else 0))
        if shuffled > max(0.35 * results[best], 2.5 * chance):
            print("⛔ 打亂之後仍然太高，流程可能有洩漏。不輸出。", file=sys.stderr)
            return 1

    report = {
        "schema_version": "sros2-firewall-model-comparison/v1",
        "features_table": str(args.features),
        "eval_split": args.eval_split,
        "test_rows_used": 0,
        "rows": len(rows),
        "sessions": len(sessions),
        "folds": args.folds,
        "seeds": args.seeds,
        "temporal": args.temporal,
        "pooling_rule": args.rule,
        "declared_space": {"formulation": list(FORMULATIONS),
                           "model": list(MODELS),
                           "sequence_model": list(SEQUENCE_MODELS),
                           "aggregate_stats": list(AGGREGATE_STATS)},
        "torch_available": True,
        "environment_note": (
            "torch／xgboost／lightgbm 裝在平行的 ~/.venvs/sros2-seqmodel；"
            "numpy 2.5.0／scikit-learn 1.9.0／scipy 1.18.0 與 "
            "~/.venvs/sros2-firewall 釘成相同版本，安裝後已逐字驗過舊 venv 未變。"),
        "scores": results,
        "best": {"configuration": best, "score": results[best],
                 "per_class": per_class_of[best],
                 "ceiling": cv.ceiling(per_class_of[best])},
        "baseline": {"configuration": baseline_key,
                     "score": results[baseline_key],
                     "per_class": per_class_of[baseline_key]},
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
