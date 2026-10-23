#!/usr/bin/env python3
"""兩階段識別（先判動作族、再判族內類別）對上扁平 17 路,端到端量一次。

## 為什麼

2026-09-27 量到族內可分性：每一族都遠高於打亂對照,而 `control_lock` 的專屬
分類器是 **0.9951**,扁平模型只有 0.6127——差 **+0.38**。那一族正是把機器人
速度歸零的那個,也是昨天量到最弱的動作。

但「專屬」是**假設族已經判對**的第二階段上限,不是可達成的數字。真正的兩階段
模型要自己判族,而判錯的那些**整個算錯**。所以上限與實得之間有多少,只能量。

## 兩個臂,同一組折

| 臂 | 做法 |
|---|---|
| `flat` | 現行:一個 17 路分類器 |
| `two_stage` | 先一個動作族分類器,再依預測的族路由到該族的專屬分類器 |

兩臂**共用同一批折與同一顆種子**,所以差異不會來自切分運氣。
只有一類的族（`normal`）直接回傳那一類,不訓練第二階段。

⚠️ 第二階段只能用**訓練折裡屬於該族的場次**擬合。用真值族去路由測試折會把
第一階段的錯誤藏起來,那量到的就是上限而不是實得——這支工具要回答的正好是
兩者的差。

## 不可宣稱

validation／CV,不是 held-out test。這一支產出的是「下次重訓要不要改結構」的
證據,不是成績。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCHEMA = "sros2-firewall-two-stage-identification/v1"


class TwoStageError(RuntimeError):
    """設定或分區不成立。刻意不吞。"""


def _load(name: str, filename: str, needs: tuple[str, ...]):
    path = ROOT / "工具腳本" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    for need in needs:
        if not hasattr(module, need):
            raise TwoStageError(f"{filename} 缺少 {need}——介面變了")
    return module


def run(features: Path, *, model_name: str, temporal: str, variant: str,
        folds: int, repeats: int) -> dict:
    import collections

    import numpy as np
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import StratifiedGroupKFold

    from firewall_lab.hierarchical_model import family_for_label

    select = _load("_select", "select_identification_model.py",
                   ("session_matrix", "apply_variant"))
    cv = _load("_id_cv", "cross_validate_identification.py",
               ("build_matrix", "load_rows", "_load_helpers", "ceiling"))
    compare = _load("_compare", "compare_session_models.py",
                    ("aggregate_sessions", "make_model"))
    helpers = cv._load_helpers()

    rows = [r for r in cv.load_rows(features)
            if r["split"] in ("train", "validation")]
    Xs, ys, sessions, width = select.session_matrix(
        compare, cv, helpers, rows, temporal)
    groups = np.array(sessions)
    actions = np.array([family_for_label(v) for v in ys], dtype=object)

    scores = {"flat": [], "two_stage": []}
    stage1 = []
    hits = {arm: collections.Counter() for arm in scores}
    totals = collections.Counter()

    for r in range(repeats):
        splitter = StratifiedGroupKFold(
            n_splits=folds, shuffle=True, random_state=r)
        flat_pred = np.empty(len(ys), dtype=object)
        two_pred = np.empty(len(ys), dtype=object)
        fam_pred = np.empty(len(ys), dtype=object)

        for tr, te in splitter.split(Xs, ys, groups=groups):
            Xtr, Xte = select.apply_variant(variant, width, Xs[tr], Xs[te])

            flat = compare.make_model(model_name, 20260803 + r)
            flat.fit(Xtr, ys[tr])
            flat_pred[te] = [str(c) for c in np.asarray(flat.predict(Xte))]

            # 第一階段：動作族。
            stage_a = compare.make_model(model_name, 20260803 + r)
            stage_a.fit(Xtr, actions[tr])
            predicted_family = np.asarray(stage_a.predict(Xte))
            fam_pred[te] = [str(f) for f in predicted_family]

            # 第二階段：每一族一個專屬分類器,**只用訓練折裡該族的場次**擬合。
            specialists: dict[str, object] = {}
            single: dict[str, str] = {}
            for family in sorted(set(actions[tr])):
                members = actions[tr] == family
                labels_here = sorted(set(ys[tr][members]))
                if len(labels_here) == 1:
                    single[family] = labels_here[0]
                    continue
                inner = compare.make_model(model_name, 20260803 + r)
                inner.fit(Xtr[members], ys[tr][members])
                specialists[family] = inner

            routed = []
            for position, family in enumerate(predicted_family):
                family = str(family)
                if family in single:
                    routed.append(single[family])
                elif family in specialists:
                    guess = specialists[family].predict(Xte[position:position + 1])
                    routed.append(str(np.asarray(guess).ravel()[0]))
                else:
                    # 訓練折裡沒有這一族——退回扁平模型的預測,而不是猜。
                    routed.append(flat_pred[te][position])
            two_pred[te] = routed

        scores["flat"].append(balanced_accuracy_score(ys, flat_pred))
        scores["two_stage"].append(balanced_accuracy_score(ys, two_pred))
        stage1.append(balanced_accuracy_score(actions, fam_pred))
        for truth, a, b in zip(ys, flat_pred, two_pred):
            totals[truth] += 1
            hits["flat"][truth] += int(a == truth)
            hits["two_stage"][truth] += int(b == truth)

    per_class = {
        label: {
            "sessions": totals[label],
            "flat": round(hits["flat"][label] / totals[label], 4),
            "two_stage": round(hits["two_stage"][label] / totals[label], 4),
            "delta": round(
                (hits["two_stage"][label] - hits["flat"][label]) / totals[label], 4),
            "family": family_for_label(label),
        }
        for label in sorted(totals)
    }
    paired = [b - a for a, b in zip(scores["flat"], scores["two_stage"])]
    return {
        "sessions": len(sessions),
        "classes": len(set(ys)),
        "families": len(set(actions)),
        "flat": {
            "balanced_accuracy": round(float(np.mean(scores["flat"])), 4),
            "std": round(float(np.std(scores["flat"])), 4),
        },
        "two_stage": {
            "balanced_accuracy": round(float(np.mean(scores["two_stage"])), 4),
            "std": round(float(np.std(scores["two_stage"])), 4),
        },
        "stage1_family_balanced_accuracy": round(float(np.mean(stage1)), 4),
        "paired_delta_mean": round(float(np.mean(paired)), 4),
        "paired_delta_std": round(float(np.std(paired)), 4),
        "two_stage_wins_of_repeats": int(sum(1 for d in paired if d > 0)),
        "repeats": repeats,
        "per_class": per_class,
        "test_rows_used": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=6)
    args = parser.parse_args(argv)

    if args.output.exists():
        print(f"⛔ 輸出已存在，拒絕覆寫：{args.output}", file=sys.stderr)
        return 2

    registration = json.loads(args.registration.read_text(encoding="utf-8"))
    prereg = _load("_prereg", "preregister_retraining.py",
                   ("verify_registration",))
    verified = prereg.verify_registration(registration)
    s = {k: v["value"] for k, v in registration["settings"].items()}
    print(f"✅ 註冊 {verified['registration_sha256'][:16]}…"
          f"（{s['model']}／{s['feature_variant']}／{s['temporal_expansion']}）")

    started = time.monotonic()
    result = run(args.features, model_name=s["model"],
                 temporal=s["temporal_expansion"], variant=s["feature_variant"],
                 folds=args.folds, repeats=args.repeats)

    report = {
        "schema_version": SCHEMA,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "registration_sha256": verified["registration_sha256"],
        "features": str(args.features),
        "settings": s,
        "folds": args.folds,
        "eval_split": "train_validation",
        "changes_shipped_defaults": False,
        "elapsed_sec": round(time.monotonic() - started, 1),
        **result,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    print()
    print(f"  扁平 17 路          {result['flat']['balanced_accuracy']:.4f}"
          f"  ± {result['flat']['std']:.4f}")
    print(f"  兩階段              {result['two_stage']['balanced_accuracy']:.4f}"
          f"  ± {result['two_stage']['std']:.4f}")
    print(f"  配對差              {result['paired_delta_mean']:+.4f}"
          f"  ± {result['paired_delta_std']:.4f}"
          f"（{result['two_stage_wins_of_repeats']}／{result['repeats']} 輪勝）")
    print(f"  第一階段（族）      {result['stage1_family_balanced_accuracy']:.4f}")
    print()
    movers = sorted(result["per_class"].items(),
                    key=lambda kv: -abs(kv[1]["delta"]))[:6]
    print(f"  {'類別':<22} {'族':<18} {'扁平':>8} {'兩階段':>8} {'差':>8}")
    for label, block in movers:
        print(f"  {label:<22} {block['family']:<18} {block['flat']:>8.4f} "
              f"{block['two_stage']:>8.4f} {block['delta']:>+8.4f}")
    print()
    print(f"報告：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
