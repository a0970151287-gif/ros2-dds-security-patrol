#!/usr/bin/env python3
"""Leave-batch-out 識別 CV ＋ 批次內良性參考校準。

為 `文件/預測_新campaign的批次校準_2026-10-28.md`（事前註冊）量 H1／H2。
新 campaign 的資料還不存在時，這一支先寫好並以合成 fixture 測過——C2C-091／114
的教訓是「這種接線錯誤只有真的執行一次才會現形」，所以在資料到之前把它跑通。

兩個折策略，同一個凍結的 arm（`random_forest`／`full`／`d1_m3_x3`／
`session_aggregate`）：

    SGK   StratifiedGroupKFold，分組 = 場次           ← C2C-116 用的那個
    LBO   leave-batch-out，分組 = stack 實例（批次）   ← H1 量的那個

落差 SGK − LBO 是「單批次上限」在受控設計下的大小（H1）。

三個校準臂（C2C-127 的定義，只在 LBO 下跑）：

    V0  原始特徵
    V1  x − med( 同批次的合格 normal 場次 )，對 normal 自己留一法
    V3  x − med( 全部合格 normal 場次 )                   ← 內部參照，見 C2C-127 §四

H2 = V1_LBO − V0_LBO。

⚠️ `holdout_reads: 0`：只讀 `split in (train, validation)` 並斷言 test 列為 0。
不訓練任何出貨模型、不碰封印、不改出貨設定。批次 id 由
`--batch-assignment`（session_id → batch id 的 JSON）提供，與
`文件/批次身份_*.json` 的 `session_to_batch` 同形狀；新 campaign 的 manifest
另記 `result.stack_instance.id`，可用 `--batch-from-manifests` 直接從資料集產生。

匯入 `select_identification_model.py` 自己的 `session_matrix`／`apply_variant`
與 `compare_session_models` 的 `make_model`，不寫第二份實作（C2C-060）。
"""
from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import pathlib
import statistics
import time

_HERE = pathlib.Path(__file__).resolve().parent
_ARM = ("random_forest", "full", "d1_m3_x3")
_NORMAL_LABEL = "normal"


class BatchCvError(RuntimeError):
    pass


def _load_select():
    path = _HERE / "select_identification_model.py"
    spec = importlib.util.spec_from_file_location("_sel_model", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    for need in ("session_matrix", "apply_variant", "_load_compare"):
        if not hasattr(module, need):
            raise BatchCvError(f"{path.name} 缺少 {need}，介面變了")
    return module


def batch_centre(Xs, ys, sessions, batch_of, *, scope):
    """回傳 Xs 的校準副本。`scope` ∈ {none, batch, global}。

    scope=batch 是 V1：每一場減掉它所屬批次的 normal 中位；對 normal 場次自己
    用留一法（排除它自己）。拿不到本地 normal 的批次退回全域（C2C-127 §三）。
    scope=global 是 V3：全部減全域 normal 中位。
    """
    import numpy as np

    if scope == "none":
        return Xs
    normal_mask = np.array([y == _NORMAL_LABEL for y in ys])
    if not normal_mask.any():
        raise BatchCvError("沒有任何 normal 場次可當良性基線")
    global_med = np.median(Xs[normal_mask], axis=0)
    if scope == "global":
        return Xs - global_med
    if scope != "batch":
        raise BatchCvError(f"未知的 scope {scope!r}")

    out = Xs.astype(float).copy()
    batches = [batch_of[s] for s in sessions]
    by_batch: dict[object, list[int]] = collections.defaultdict(list)
    for i, b in enumerate(batches):
        by_batch[b].append(i)
    for i, (sess, b) in enumerate(zip(sessions, batches)):
        peers = [
            j for j in by_batch[b]
            if normal_mask[j] and j != i  # ← 留一法（界線 2）
        ]
        med = np.median(Xs[peers], axis=0) if peers else global_med
        out[i] = Xs[i] - med
    return out


def _run_cv(select, cmp, Xs, ys, sessions, width, *, splitter_factory,
            groups, repeats, shuffle_labels=False):
    """R 輪 CV。splitter_factory(r) 回傳一個 sklearn 切分器。arm 凍結在 _ARM。"""
    import numpy as np
    from sklearn.metrics import balanced_accuracy_score

    _model, variant, _temporal = _ARM
    per_repeat = []
    leak = 0
    for r in range(repeats):
        y = ys
        if shuffle_labels:
            rng = np.random.default_rng(70000 + r)
            y = ys.copy()
            rng.shuffle(y)
        predicted = np.empty(len(sessions), dtype=object)
        covered = np.zeros(len(sessions), dtype=int)
        for tr, te in splitter_factory(r).split(Xs, y, groups=groups):
            # 界線 3：同一組不得同時在 train 與 test。
            if set(groups[tr]) & set(groups[te]):
                leak += 1
            Xtr, Xte = select.apply_variant(variant, width, Xs[tr], Xs[te])
            est = cmp.make_model(_ARM[0], r)
            est.fit(Xtr, y[tr])
            choice = np.asarray(est.predict(Xte))
            if choice.ndim != 1:
                raise BatchCvError(f"predict 回傳 {choice.ndim} 維")
            predicted[te] = [str(c) for c in choice]
            covered[te] += 1
        if not (covered == 1).all():
            raise BatchCvError(
                f"第 {r} 輪有場次被預測 {sorted(set(covered.tolist()))} 次")
        per_repeat.append(float(balanced_accuracy_score(y, predicted)))
    if leak:
        raise BatchCvError(f"{leak} 次分組把同一批次放進 train 與 test（界線 3）")
    return per_repeat


def _sgk(folds):
    from sklearn.model_selection import StratifiedGroupKFold
    return lambda r: StratifiedGroupKFold(
        n_splits=folds, shuffle=True, random_state=r)


def _lbo(folds, n_batches):
    from sklearn.model_selection import GroupKFold
    # 批次數少於 folds 時用 LeaveOneGroupOut。
    if n_batches < folds:
        from sklearn.model_selection import LeaveOneGroupOut
        return lambda r: LeaveOneGroupOut()
    return lambda r: GroupKFold(n_splits=folds)


def _batch_from_manifests(dataset: pathlib.Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for manifest in sorted(dataset.glob("*/manifest.json")):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        inst = data.get("result", {}).get("stack_instance", {})
        if inst.get("status") == "observed" and inst.get("id"):
            mapping[str(data.get("session_id"))] = str(inst["id"])
    return mapping


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--features", required=True, type=pathlib.Path)
    parser.add_argument(
        "--eval-split", required=True, choices=("train_validation",),
        help="只接受 train_validation。新 campaign 的 test 要留給封印 holdout。")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--batch-assignment", type=pathlib.Path,
        help="session_id → batch id 的 JSON（如 批次身份_*.json 的 session_to_batch）")
    group.add_argument(
        "--batch-from-manifests", type=pathlib.Path,
        help="從資料集的 manifest.result.stack_instance.id 產生批次指派")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=15)
    parser.add_argument("--output", type=pathlib.Path)
    return parser


def _load_assignment(args) -> dict[str, str]:
    if args.batch_assignment:
        raw = json.loads(args.batch_assignment.read_text(encoding="utf-8"))
        table = raw.get("session_to_batch", raw)
        return {str(k): str(v) for k, v in table.items()}
    return _batch_from_manifests(args.batch_from_manifests.expanduser())


def main(argv=None) -> int:
    import numpy as np

    args = build_parser().parse_args(argv)
    select = _load_select()
    cmp = select._load_compare()
    cv = cmp._load_cv()
    helpers = cv._load_helpers()

    all_rows = cv.load_rows(args.features.expanduser())
    rows = [r for r in all_rows if r["split"] in ("train", "validation")]
    used_test = sum(1 for r in rows if r["split"] == "test")
    if used_test:
        raise BatchCvError(f"有 {used_test} 列 test 混進來了")
    if not rows:
        raise BatchCvError("train+validation 沒有任何列")

    Xs, ys, sessions, width = select.session_matrix(cmp, cv, helpers, rows,
                                                     _ARM[2])
    batch_of = _load_assignment(args)
    missing = [s for s in sessions if s not in batch_of]
    if missing:
        raise BatchCvError(
            f"{len(missing)} 場沒有批次指派，例如 {missing[0]}")
    groups = np.array([batch_of[s] for s in sessions])
    n_batches = len(set(groups.tolist()))

    test_rows = sum(1 for r in all_rows if r["split"] == "test")
    print(f"[{args.features.name}] {len(rows)} 列 / {len(sessions)} 場 / "
          f"{len(set(ys))} 類 / {n_batches} 批次；聚合 {Xs.shape[1]} 維")
    print(f"  test 列 {test_rows} 個，用了 {used_test} 個")

    chance = 1.0 / len(set(ys))
    out: dict[str, object] = {
        "schema_version": "sros2-firewall-batch-reference-cv/v1",
        "prediction_file": "文件/預測_新campaign的批次校準_2026-10-28.md",
        "arm": {"model": _ARM[0], "variant": _ARM[1], "temporal": _ARM[2],
                "formulation": "session_aggregate"},
        "features": str(args.features),
        "sessions": len(sessions), "classes": len(set(ys)),
        "batches": n_batches, "aggregate_width": int(Xs.shape[1]),
        "test_rows_in_table": test_rows, "test_rows_used": used_test,
        "holdout_reads": 0, "changes_shipped_defaults": False,
        "folds": args.folds, "repeats": args.repeats, "chance": round(chance, 4),
    }

    def summary(scores):
        return {"mean": round(statistics.mean(scores), 4),
                "pstdev": round(statistics.pstdev(scores), 4),
                "scores": [round(s, 4) for s in scores]}

    sgk = _run_cv(select, cmp, Xs, ys, sessions, width,
                  splitter_factory=_sgk(args.folds), groups=groups,
                  repeats=args.repeats)
    out["SGK_V0"] = summary(sgk)
    print(f"  SGK V0   BA {out['SGK_V0']['mean']:.4f}")

    lbo_factory = _lbo(args.folds, n_batches)
    arms = {}
    for scope, label in (("none", "V0"), ("batch", "V1"), ("global", "V3")):
        Xc = batch_centre(Xs, ys, sessions, batch_of, scope=scope)
        scores = _run_cv(select, cmp, Xc, ys, sessions, width,
                         splitter_factory=lbo_factory, groups=groups,
                         repeats=args.repeats)
        arms[label] = summary(scores)
        print(f"  LBO {label}  BA {arms[label]['mean']:.4f}")
    out["LBO"] = arms

    # C2：打亂標籤的 LBO 必須落在亂猜附近。
    shuffled = _run_cv(select, cmp, Xs, ys, sessions, width,
                       splitter_factory=lbo_factory, groups=groups,
                       repeats=args.repeats, shuffle_labels=True)
    out["C2_shuffled_LBO"] = summary(shuffled)

    h1 = out["SGK_V0"]["mean"] - arms["V0"]["mean"]
    h2 = arms["V1"]["mean"] - arms["V0"]["mean"]
    c3 = arms["V3"]["mean"] - arms["V0"]["mean"]
    out["H1_SGK_minus_LBO"] = round(h1, 4)
    out["H2_V1_minus_V0_LBO"] = round(h2, 4)
    out["C3_V3_minus_V0_LBO"] = round(c3, 4)
    out["verdicts"] = {
        "H1": "成立" if h1 >= 0.08 else ("否證" if h1 < 0.03 else "未定"),
        "H2": "成立" if h2 >= 0.05 else ("否證" if h2 <= 0.01 else "未定"),
    }
    print(f"  H1 (SGK-LBO) {h1:+.4f}  H2 (V1-V0) {h2:+.4f}  C3 (V3-V0) {c3:+.4f}")
    print(f"  判定 H1={out['verdicts']['H1']}  H2={out['verdicts']['H2']}")

    if args.output:
        args.output.write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
