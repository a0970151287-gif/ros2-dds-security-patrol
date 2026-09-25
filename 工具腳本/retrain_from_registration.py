#!/usr/bin/env python3
"""照預先註冊重訓識別模型，並把封存的 test 開封**一次**。

## 為什麼需要它

`preregister_retraining.py` 把設定釘死了，`seal_holdout.py` 把 test 封起來了，
但**沒有任何東西會去執行那些設定**。勝出的表述 `session_aggregate` 只活在
`compare_session_models.py` 裡，而那是一支比較工具——它跑 CV、不產出模型、
也不碰 test。所以在這一支之前，「註冊」與「重訓」之間是一段要靠人手接的縫，
而那正是設定會漂掉的地方。

這一支把三件事變成一條不可分割的路徑：

    驗註冊 → 驗封印 → 擬合 → **開封（一次性）** → 評估一次 → 寫產物

## 它拒絕做的事

| 情況 | 行為 |
|---|---|
| 註冊自己的雜湊對不上 | 拒絕 |
| 實際設定與註冊不符 | 拒絕，並逐項列出差異 |
| 註冊裡該項是 `undecided` | 拒絕（未定就是未定，不可以隨手填一個） |
| 封印已經開過 | 拒絕，**在讀 test 列之前** |
| 封印與這批特徵不符 | 拒絕 |
| 輸出已存在 | 拒絕覆寫 |

⚠️ **開封在擬合之後才發生。** 擬合只用 train＋validation，所以即使評估失敗，
test 也不會被多花一次；反過來若先開封再擬合，一次擬合失敗就浪費掉整個 holdout。

## 它做不到的事（刻意的）

只做**識別**（多類）那一半。未知攻擊那一半的設定
（`ood_scorer_permissive`、`unknown_session_pooling`）由 family-LOO 那套工具評估，
硬塞進來只會讓兩件事互相綁死。本工具會**檢查**那些設定有被註冊，
但不會執行它們。

## 產物記得住自己

⚠️ 2026-09-25 的教訓：`evaluate_unknown_at_full_resolution.py` 的產物沒有記
`seed` 與 `n_estimators`，於是它**重現不了自己前一天的結果**，而「重現不了」
與「結果變了」在錯誤訊息上完全一樣——查了二十分鐘。所以這裡把每一個能影響
數字的東西都寫進產物。

## 用法

    python3 工具腳本/retrain_from_registration.py \\
        --registration 文件/重訓預先註冊_2026-09-25_r3.json \\
        --features ~/features_mega/fusion_features_enforce.csv \\
        --seal 文件/封存holdout_enforce_<日期>.json \\
        --output 文件/重訓結果_enforce_<日期>.json
"""

from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCHEMA = "sros2-firewall-registered-retraining/v1"

# 這四項由本工具執行,所以必須與註冊逐字相符。
EXECUTED_SETTINGS = (
    "formulation", "model", "temporal_expansion", "feature_variant",
)
# 這些由別的工具執行。本工具只確認它們有被註冊,不碰它們。
DELEGATED_SETTINGS = (
    "ood_scorer_permissive", "ood_scorer_enforce",
    "unknown_session_pooling", "blind_spot_features",
)


class RetrainError(RuntimeError):
    """註冊、封印或設定不符。刻意不吞。"""


def _load(name: str, filename: str, needs: tuple[str, ...]):
    path = ROOT / "工具腳本" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    for need in needs:
        if not hasattr(module, need):
            raise RetrainError(f"{filename} 缺少 {need}——介面變了，請先對齊")
    return module


def check_settings(registration: dict) -> dict:
    """實際要用的設定必須與註冊逐字相符,而且未定的不能被填。"""
    prereg = _load("_prereg", "preregister_retraining.py",
                   ("verify_registration", "UNDECIDED"))
    settings = registration["settings"]

    missing = [k for k in EXECUTED_SETTINGS + DELEGATED_SETTINGS
               if k not in settings]
    if missing:
        raise RetrainError(
            f"註冊少了這些項目，無法確認會照它跑：{missing}。"
            "一份不完整的註冊比沒有註冊更危險——它看起來像有保證。"
        )

    undecided = [k for k in EXECUTED_SETTINGS
                 if settings[k]["value"] == prereg.UNDECIDED]
    if undecided:
        raise RetrainError(
            f"註冊把這些項目寫成未定，本工具需要它們才能跑：{undecided}。"
            "隨手填一個值會讓這一輪的 test 變成一次不可重複的猜測。"
        )

    actual = {k: settings[k]["value"] for k in EXECUTED_SETTINGS}
    result = prereg.verify_registration(registration, actual=actual)
    if result["settings_mismatched"]:
        raise RetrainError(f"設定與註冊不符：{result['settings_mismatched']}")
    return {
        "registration_sha256": result["registration_sha256"],
        "evidence_drifted": result["evidence_drifted"],
        "executed": actual,
        "delegated": {k: settings[k]["value"] for k in DELEGATED_SETTINGS},
    }


def fit_and_evaluate(features: Path, *, formulation: str, model_name: str,
                     temporal: str, feature_variant: str, seed: int,
                     open_seal) -> dict:
    """擬合只用 train＋validation;`open_seal()` 之後才碰 test。

    `open_seal` 是一個 callable 而不是一個旗標,因為順序在這裡是安全性質:
    它必須在**讀 test 列之前**、而且在擬合**之後**被呼叫一次。
    """
    import numpy as np
    from sklearn.metrics import (
        balanced_accuracy_score, confusion_matrix, f1_score,
    )

    cv = _load("_id_cv", "cross_validate_identification.py",
               ("build_matrix", "load_rows", "_load_helpers", "ceiling"))
    compare = _load("_compare", "compare_session_models.py",
                    ("aggregate_sessions", "make_model", "AGGREGATE_STATS"))
    helpers = cv._load_helpers()

    if formulation != "session_aggregate":
        raise RetrainError(
            f"本工具只實作 session_aggregate，註冊要的是 {formulation!r}。"
            "沒實作的表述要另外寫，不可以用近似的那一個代替。"
        )
    if feature_variant != "full":
        raise RetrainError(
            f"本工具只實作 full（六個聚合統計量全用、不丟死欄位），"
            f"註冊要的是 {feature_variant!r}。"
        )

    rows = cv.load_rows(features)
    X, _resets = cv.build_matrix(helpers, rows, temporal)

    sid = np.array([r["session_id"] for r in rows])
    split = np.array([r["split"] for r in rows])
    sessions = sorted(set(sid))
    truth = helpers.session_labels(rows, sessions)

    # 一個場次的 split 必須一致,否則它同時在兩邊,而那會讓 test 被污染。
    per_session_split = {}
    for session, value in zip(sid, split):
        per_session_split.setdefault(session, set()).add(value)
    mixed = sorted(s for s, values in per_session_split.items() if len(values) > 1)
    if mixed:
        raise RetrainError(
            f"{len(mixed)} 個場次的 split 不一致（例：{mixed[:3]}）。"
            "一場跨兩個分區代表切分是按列做的，那個 test 不是獨立的。"
        )

    Xs = compare.aggregate_sessions(rows, X, sessions)
    ys = np.array([truth[s] for s in sessions])
    where = np.array([next(iter(per_session_split[s])) for s in sessions])

    fit_mask = np.isin(where, ("train", "validation"))
    test_mask = where == "test"
    if not fit_mask.any():
        raise RetrainError("沒有 train／validation 場次可以擬合")
    if not test_mask.any():
        raise RetrainError("沒有 test 場次——沒有東西可以評估")

    model = compare.make_model(model_name, seed)
    model.fit(Xs[fit_mask], ys[fit_mask])

    # ⚠️ 擬合成功之後才開封。順序反過來,一次擬合失敗就浪費掉整個 holdout。
    seal_record = open_seal()

    predicted = np.asarray(model.predict(Xs[test_mask]))
    if predicted.ndim != 1:
        raise RetrainError(
            f"{model_name} 的 predict 回傳 {predicted.ndim} 維。"
            "二維會讓 str() 產生 \"['normal']\" 而永遠比對不上，"
            "分數變成 0.0000 卻看起來像模型很差（CatBoost 2026-09-16）。"
        )
    actual_labels = ys[test_mask]
    predicted = np.array([str(p) for p in predicted])

    classes = sorted(set(actual_labels) | set(predicted))
    per_class = {}
    for label in sorted(set(actual_labels)):
        hit = actual_labels == label
        per_class[label] = {
            "sessions": int(hit.sum()),
            "recall": round(float((predicted[hit] == label).mean()), 4),
        }

    return {
        "seal": seal_record,
        "fit_sessions": int(fit_mask.sum()),
        "test_sessions": int(test_mask.sum()),
        "classes": len(set(actual_labels)),
        "balanced_accuracy": round(
            float(balanced_accuracy_score(actual_labels, predicted)), 4),
        "macro_f1": round(float(f1_score(
            actual_labels, predicted, average="macro", zero_division=0)), 4),
        "per_class_recall": per_class,
        "ceiling": cv.ceiling(per_class),
        "confusion": {
            "labels": classes,
            "matrix": confusion_matrix(
                actual_labels, predicted, labels=classes).tolist(),
        },
        "aggregate_width": int(Xs.shape[1]),
        "aggregate_stats": list(compare.AGGREGATE_STATS),
        "predicted_distribution": dict(
            sorted(collections.Counter(predicted.tolist()).items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--seal", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260803)
    parser.add_argument(
        "--reason", default="registered final evaluation",
        help="寫進封印的開封理由。沒有理由的開封事後看不出是哪一次。")
    args = parser.parse_args(argv)

    if args.output.exists():
        print(f"⛔ 輸出已存在，拒絕覆寫：{args.output}", file=sys.stderr)
        return 2

    registration = json.loads(args.registration.read_text(encoding="utf-8"))
    try:
        checked = check_settings(registration)
    except RetrainError as exc:
        print(f"⛔ {exc}", file=sys.stderr)
        return 3

    seal_mod = _load("_seal", "seal_holdout.py",
                     ("require_unopened", "open_once", "verify_seal"))
    try:
        # 先確認沒開過,再確認封印配得上這批資料——兩道都在讀 test 列之前。
        seal = seal_mod.require_unopened(args.seal)
        state = seal_mod.verify_seal(seal, args.features)
        if not state["valid"]:
            raise RetrainError(f"封印不成立：{state['problems']}")
    except (seal_mod.SealError, RetrainError) as exc:
        print(f"⛔ {exc}", file=sys.stderr)
        return 4

    print("✅ 註冊反查通過：", checked["registration_sha256"])
    for key, value in checked["executed"].items():
        print(f"     {key:<20} {value}")
    if checked["evidence_drifted"]:
        print("   ⚠️ 引用的證據檔已變動（演進，不是造假）：")
        for path in checked["evidence_drifted"]:
            print(f"        {path}")
    print(f"✅ 封印未開封，涵蓋 {state['test_session_count']} 場 test")
    print()

    started = time.monotonic()
    try:
        result = fit_and_evaluate(
            args.features,
            formulation=checked["executed"]["formulation"],
            model_name=checked["executed"]["model"],
            temporal=checked["executed"]["temporal_expansion"],
            feature_variant=checked["executed"]["feature_variant"],
            seed=args.seed,
            open_seal=lambda: seal_mod.open_once(args.seal, args.reason),
        )
    except RetrainError as exc:
        print(f"⛔ {exc}", file=sys.stderr)
        return 5

    report = {
        "schema_version": SCHEMA,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "registration_path": str(args.registration),
        "registration_sha256": checked["registration_sha256"],
        "seal_path": str(args.seal),
        "features_path": str(args.features),
        "features_sha256": seal["features_sha256"],
        "test_sessions_sha256": seal["test_sessions_sha256"],
        # ⚠️ 每一個能影響數字的東西都要在這裡。2026-09-25 有一支工具因為漏了
        # seed 與 n_estimators 而重現不了自己前一天的結果。
        "seed": args.seed,
        "executed_settings": checked["executed"],
        "delegated_settings": checked["delegated"],
        "elapsed_sec": round(time.monotonic() - started, 1),
        "result": result,
        "independent_final_test": True,
        "note": (
            "設定在看到這批 test 之前就被註冊並雜湊，封印在擬合之前就綁住了 "
            "test 場次清單，而開封是一次性的。"
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    r = result
    print(f"  test 場次            : {r['test_sessions']}（{r['classes']} 類）")
    print(f"  balanced accuracy    : {r['balanced_accuracy']:.4f}")
    print(f"  macro F1             : {r['macro_f1']:.4f}")
    print(f"  算術上限             : {r['ceiling']['arithmetic_ceiling']:.4f}"
          f"（恆零類別 {len(r['ceiling']['zero_recall_classes'])}）")
    print(f"  聚合寬度             : {r['aggregate_width']}")
    print(f"⚠️ holdout 已於 {r['seal']['opened_utc']} 花掉。下一個數字需要新資料。")
    print(f"報告：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
