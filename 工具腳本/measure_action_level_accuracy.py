#!/usr/bin/env python3
"""同一個模型，在「類別」與「動作」兩個粒度上各量一次。

## 問的問題

部署時模型的預測是用來**查一個動作**的：`action_policy.json` 是
類別 → 動作，而多個類別映到同一個動作。所以把 `replay` 誤判成 `message_dos`
在回應鏈上**零代價**——兩者都是 `application_drop`。

Enforce 的識別率 0.2819（逐視窗 test）與 0.6851（CV 場次層級）都是**類別**粒度。
這一支量同一個模型在**動作**粒度上的表現，因為那才是回應鏈真正需要對的東西。

## ⚠️ 這不是「把標準改寬」的藉口

C2C-012（2026-08-18）試過把類別合併成家族，結論是**相對亂猜反而下降**：
Enforce 從 0.3192（九選一，2.9× 亂猜）到 0.5172（五選一，2.6× 亂猜）。
**類別變少本來就比較容易**，所以絕對數字一定會上升，而那不代表系統變好。

所以這一支**一律成對報告**：

    絕對分數  ＋  亂猜基線（1／類別數）  ＋  相對亂猜的倍數

而且兩個粒度都跑打亂對照。只看絕對數字的比較是沒有意義的。

⚠️ 與 C2C-012 的差別在於這裡是**事後改判**而不是重新訓練成家族：模型仍然
預測 17 類，只是把預測與真值都映到動作再計分。那正是部署時發生的事
（類別預測去查 adapter），所以它回答的是一個部署問題，不是一個建模問題。

## 設定來自預先註冊

表述、模型、時序展開與特徵變體全部讀 `--registration`，不接受命令列覆寫
——這一支的用途是量「已註冊的那個設定」在另一個粒度上的樣子。

## 用法

    python3 工具腳本/measure_action_level_accuracy.py \\
        --registration 文件/重訓預先註冊_2026-09-25_r3.json \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --output 文件/動作層準確率_enforce_<日期>.json
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

SCHEMA = "sros2-firewall-action-level-accuracy/v1"


class ActionError(RuntimeError):
    """設定、對應或分區不成立。刻意不吞。"""


def _load(name: str, filename: str, needs: tuple[str, ...]):
    path = ROOT / "工具腳本" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    for need in needs:
        if not hasattr(module, need):
            raise ActionError(f"{filename} 缺少 {need}——介面變了，請先對齊")
    return module


def run(features: Path, *, model_name: str, temporal: str, variant: str,
        folds: int, repeats: int, eval_split: str) -> dict:
    import numpy as np
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import StratifiedGroupKFold

    # 正式的類別 → 動作對應。**匯入不抄**：抄一份就會與出貨的決策路徑漂移,
    # 而那會讓這個量測回答一個沒有人會部署的問題。
    from firewall_lab.hierarchical_model import FAMILY_BY_LABEL, family_for_label

    select = _load("_select", "select_identification_model.py",
                   ("session_matrix", "apply_variant"))
    cv = _load("_id_cv", "cross_validate_identification.py",
               ("build_matrix", "load_rows", "_load_helpers"))
    compare = _load("_compare", "compare_session_models.py",
                    ("aggregate_sessions", "make_model"))
    helpers = cv._load_helpers()

    rows = cv.load_rows(features)
    if eval_split == "train_validation":
        kept = [r for r in rows if r["split"] in ("train", "validation")]
        used_test = sum(1 for r in rows if r["split"] == "test")
        rows = kept
    else:
        raise ActionError(
            f"--eval-split 只接受 train_validation，收到 {eval_split!r}。"
            "test 是一次性的，不可以用在一個探索性的粒度比較上。"
        )

    Xs, ys, sessions, width = select.session_matrix(
        compare, cv, helpers, rows, temporal)

    unmapped = sorted(set(ys) - set(FAMILY_BY_LABEL))
    if unmapped:
        raise ActionError(
            f"這些類別沒有對應的動作：{unmapped}。"
            "缺一個對應就等於在計分時默默把它丟掉。"
        )
    actions = np.array([family_for_label(label) for label in ys], dtype=object)

    groups = np.array(sessions)
    out: dict = {}

    for shuffle in (False, True):
        class_scores, action_scores = [], []
        class_hits = collections.Counter()
        class_totals = collections.Counter()
        action_hits = collections.Counter()
        action_totals = collections.Counter()
        wrong_total = [0]
        wrong_inside = [0]

        for r in range(repeats):
            y = ys
            if shuffle:
                rng = np.random.default_rng(90000 + r)
                y = ys.copy()
                rng.shuffle(y)
            a = np.array([family_for_label(label) for label in y], dtype=object)

            splitter = StratifiedGroupKFold(
                n_splits=folds, shuffle=True, random_state=r)
            pred = np.empty(len(sessions), dtype=object)
            for train_index, test_index in splitter.split(Xs, y, groups=groups):
                Xtr, Xte = select.apply_variant(
                    variant, width, Xs[train_index], Xs[test_index])
                model = compare.make_model(model_name, 20260803 + r)
                model.fit(Xtr, y[train_index])
                choice = np.asarray(model.predict(Xte))
                if choice.ndim != 1:
                    raise ActionError(
                        f"{model_name} 的 predict 回傳 {choice.ndim} 維")
                pred[test_index] = [str(c) for c in choice]

            pred_action = np.array(
                [family_for_label(p) for p in pred], dtype=object)
            class_scores.append(balanced_accuracy_score(y, pred))
            action_scores.append(balanced_accuracy_score(a, pred_action))

            # ⚠️ 這才是能回答 C2C-012 的數字。
            #
            # 「動作層分數較高」可以完全用「六選一比十七選一容易」解釋,所以它
            # 本身不構成論點。但「類別層的誤判有多少**留在同一個動作家族裡**」
            # 與類別數無關——它是混淆**結構**的性質。留在家族內的誤判對回應鏈
            # 零代價（`replay` 誤判成 `message_dos`,兩者都 application_drop）,
            # 留在家族外的才真的會觸發錯的動作。
            wrong = pred != y
            wrong_total[0] += int(wrong.sum())
            wrong_inside[0] += int((wrong & (pred_action == a)).sum())
            for truth_label, guess in zip(y, pred):
                class_totals[truth_label] += 1
                class_hits[truth_label] += int(guess == truth_label)
            for truth_action, guess in zip(a, pred_action):
                action_totals[truth_action] += 1
                action_hits[truth_action] += int(guess == truth_action)

        n_classes = len(set(ys))
        n_actions = len(set(actions))
        key = "shuffled" if shuffle else "real"
        out[key] = {
            "class_level": {
                "balanced_accuracy": round(float(np.mean(class_scores)), 4),
                "std": round(float(np.std(class_scores)), 4),
                "categories": n_classes,
                "chance": round(1.0 / n_classes, 4),
                "times_chance": round(
                    float(np.mean(class_scores)) * n_classes, 2),
                "per_category_recall": {
                    k: round(class_hits[k] / class_totals[k], 4)
                    for k in sorted(class_totals)
                },
            },
            "error_structure": {
                "class_level_errors": wrong_total[0],
                "errors_inside_the_same_action": wrong_inside[0],
                "share_inside": (
                    round(wrong_inside[0] / wrong_total[0], 4)
                    if wrong_total[0] else None),
                "note": (
                    "留在同一個動作家族裡的誤判對回應鏈零代價。"
                    "這個比例與類別數無關,所以它是「動作層比較容易」之外的"
                    "獨立證據。"
                ),
            },
            "action_level": {
                "balanced_accuracy": round(float(np.mean(action_scores)), 4),
                "std": round(float(np.std(action_scores)), 4),
                "categories": n_actions,
                "chance": round(1.0 / n_actions, 4),
                "times_chance": round(
                    float(np.mean(action_scores)) * n_actions, 2),
                "per_category_recall": {
                    k: round(action_hits[k] / action_totals[k], 4)
                    for k in sorted(action_totals)
                },
            },
        }

    out["action_map"] = {
        label: family_for_label(label) for label in sorted(set(ys))
    }
    out["sessions"] = len(sessions)
    out["rows"] = len(rows)
    out["test_rows_in_table"] = used_test
    out["test_rows_used"] = 0
    out["aggregate_width"] = int(Xs.shape[1])
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=12)
    parser.add_argument("--eval-split", default="train_validation")
    args = parser.parse_args(argv)

    if args.output.exists():
        print(f"⛔ 輸出已存在，拒絕覆寫：{args.output}", file=sys.stderr)
        return 2

    registration = json.loads(args.registration.read_text(encoding="utf-8"))
    prereg = _load("_prereg", "preregister_retraining.py",
                   ("verify_registration",))
    verified = prereg.verify_registration(registration)
    settings = {k: v["value"] for k, v in registration["settings"].items()}
    for need in ("formulation", "model", "temporal_expansion", "feature_variant"):
        if need not in settings:
            raise ActionError(f"註冊少了 {need}")
    if settings["formulation"] != "session_aggregate":
        raise ActionError(
            f"本工具只實作 session_aggregate，註冊要的是 "
            f"{settings['formulation']!r}")

    print(f"✅ 註冊 {verified['registration_sha256'][:16]}…"
          f"（{settings['model']}／{settings['feature_variant']}／"
          f"{settings['temporal_expansion']}）")
    started = time.monotonic()
    result = run(
        args.features,
        model_name=settings["model"],
        temporal=settings["temporal_expansion"],
        variant=settings["feature_variant"],
        folds=args.folds, repeats=args.repeats, eval_split=args.eval_split)

    report = {
        "schema_version": SCHEMA,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "registration_path": str(args.registration),
        "registration_sha256": verified["registration_sha256"],
        "features": str(args.features),
        "settings": settings,
        "folds": args.folds,
        "repeats": args.repeats,
        "splitter": "StratifiedGroupKFold(shuffle=True, random_state=repeat)",
        "eval_split": args.eval_split,
        "changes_shipped_defaults": False,
        "elapsed_sec": round(time.monotonic() - started, 1),
        **result,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    print()
    print(f"  {'':22} {'絕對':>8} {'亂猜':>8} {'倍數':>7} {'類別數':>7}")
    for arm, label in (("real", "真實"), ("shuffled", "打亂對照")):
        for level, name in (("class_level", "類別層"), ("action_level", "動作層")):
            b = result[arm][level]
            print(f"  {label + ' ' + name:<22} {b['balanced_accuracy']:>8.4f} "
                  f"{b['chance']:>8.4f} {b['times_chance']:>6.2f}× "
                  f"{b['categories']:>7}")
    print()
    print()
    print("=== 誤判結構（與類別數無關,所以不受「六選一比較容易」影響）")
    for arm, label in (("real", "真實"), ("shuffled", "打亂對照")):
        e = result[arm]["error_structure"]
        share = e["share_inside"]
        print(f"  {label:<10} 類別層誤判 {e['class_level_errors']:>5} 次，"
              f"其中 {e['errors_inside_the_same_action']:>5} 次留在同一個動作內"
              f"（{share:.1%}）" if share is not None else f"  {label}: 無誤判")
    print()
    print("⚠️ 絕對數字在動作層一定較高——類別變少本來就比較容易。"
          "有意義的比較是**倍數**（C2C-012 記過這件事）。")
    print(f"報告：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
