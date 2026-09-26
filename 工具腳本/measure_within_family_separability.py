#!/usr/bin/env python3
"""族裡面分得開嗎——兩階段模型值不值得做,先用一個量測回答。

## 為什麼問這個

2026-09-26 量到 Enforce 的誤判有 **66.5% 留在同一個動作家族內**（亂猜只有
23.9%），而家族本身預測對 **91%**。也就是說：

> **模型知道是哪一族,不知道是族裡哪一個。**

那給出一個具體的假設：先判族、再用**該族專屬**的分類器判類,可能比一個 17 路
分類器好——因為專門訓練在 `application_drop` 那 8 類上的模型,不必同時分辨
與它無關的 9 個類別,可能找得到被稀釋掉的區分。

Codex 的分層線（binary → family → leaf）存在,但它是為**逐視窗**表述建的,
**從來沒有在 `session_aggregate` 上試過**。在寫一條新的訓練線之前,先問一個
更便宜的問題:**族裡面到底分不分得開?**

## 怎麼問

對每一個含 ≥2 類的動作家族,**只拿那一族的場次**訓練一個分類器,量它在族內的
平衡準確率。對照兩個基線:

| 臂 | 意思 |
|---|---|
| `specialist` | 只看這一族的專屬分類器——兩階段的第二階段上限 |
| `flat_within_family` | 現行 17 路模型在同一批場次上的族內表現 |
| `shuffled` | 打亂族內標籤。**這個才是真正的對照** |

⚠️ 專屬分類器一定不會比 `flat` 差很多,因為它的問題比較小（2–8 類而不是 17）。
所以**絕對值不構成論點**,要看的是：

* `specialist` 有沒有明顯**高於** `flat_within_family`（兩階段才有價值）
* `specialist` 有沒有明顯**高於** `shuffled`（族內真的有訊號）

若 `specialist ≈ shuffled`,那一族的類別在這個觀測層上就是不可分的,
再多的結構也救不了——那是 C2C-054「Enforce 下八類零排他訊號」的直接後果。

## 設定

表述、模型、時序、特徵變體全部讀預先註冊,不接受命令列覆寫。
`--eval-split` 只接受 `train_validation`。

## 用法

    python3 工具腳本/measure_within_family_separability.py \\
        --registration 文件/重訓預先註冊_2026-09-27_r4.json \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --output 文件/族內可分性_enforce_<日期>.json
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

SCHEMA = "sros2-firewall-within-family-separability/v1"


class SeparabilityError(RuntimeError):
    """設定、對應或分區不成立。刻意不吞。"""


def _load(name: str, filename: str, needs: tuple[str, ...]):
    path = ROOT / "工具腳本" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    for need in needs:
        if not hasattr(module, need):
            raise SeparabilityError(f"{filename} 缺少 {need}——介面變了")
    return module


def run(features: Path, *, model_name: str, temporal: str, variant: str,
        folds: int, repeats: int) -> dict:
    import numpy as np
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import StratifiedGroupKFold

    from firewall_lab.hierarchical_model import family_for_label

    select = _load("_select", "select_identification_model.py",
                   ("session_matrix", "apply_variant"))
    cv = _load("_id_cv", "cross_validate_identification.py",
               ("build_matrix", "load_rows", "_load_helpers"))
    compare = _load("_compare", "compare_session_models.py",
                    ("aggregate_sessions", "make_model"))
    helpers = cv._load_helpers()

    rows = [r for r in cv.load_rows(features)
            if r["split"] in ("train", "validation")]
    Xs, ys, sessions, width = select.session_matrix(
        compare, cv, helpers, rows, temporal)
    actions = np.array([family_for_label(v) for v in ys], dtype=object)

    out: dict = {"families": {}}
    for family in sorted(set(actions)):
        members = actions == family
        labels_here = sorted(set(ys[members]))
        if len(labels_here) < 2:
            out["families"][family] = {
                "classes": labels_here,
                "skipped": "只有一類，族內沒有東西可分",
            }
            continue

        Xf = Xs[members]
        yf = ys[members]
        gf = np.array(sessions)[members]
        counts = {c: int((yf == c).sum()) for c in labels_here}
        smallest = min(counts.values())
        use_folds = min(folds, smallest)
        if use_folds < 2:
            out["families"][family] = {
                "classes": labels_here, "sessions_per_class": counts,
                "skipped": f"最小的類別只有 {smallest} 場，切不出兩折",
            }
            continue

        arms: dict[str, list[float]] = {"specialist": [], "shuffled": [],
                                        "flat_within_family": []}
        for r in range(repeats):
            splitter = StratifiedGroupKFold(
                n_splits=use_folds, shuffle=True, random_state=r)

            # 專屬：只用這一族的場次擬合,也只在這一族上評估。
            pred = np.empty(len(yf), dtype=object)
            for tr, te in splitter.split(Xf, yf, groups=gf):
                Xtr, Xte = select.apply_variant(variant, width, Xf[tr], Xf[te])
                m = compare.make_model(model_name, 20260803 + r)
                m.fit(Xtr, yf[tr])
                pred[te] = [str(c) for c in np.asarray(m.predict(Xte))]
            arms["specialist"].append(balanced_accuracy_score(yf, pred))

            # 打亂：族內標籤洗掉。這才是「族內有沒有訊號」的對照。
            rng = np.random.default_rng(70000 + r)
            ysh = yf.copy()
            rng.shuffle(ysh)
            pred_sh = np.empty(len(ysh), dtype=object)
            for tr, te in splitter.split(Xf, ysh, groups=gf):
                Xtr, Xte = select.apply_variant(variant, width, Xf[tr], Xf[te])
                m = compare.make_model(model_name, 20260803 + r)
                m.fit(Xtr, ysh[tr])
                pred_sh[te] = [str(c) for c in np.asarray(m.predict(Xte))]
            arms["shuffled"].append(balanced_accuracy_score(ysh, pred_sh))

            # 扁平：17 路模型擬合在**全部**場次上,只在這一族上計分。
            flat = np.empty(len(ys), dtype=object)
            big = StratifiedGroupKFold(
                n_splits=folds, shuffle=True, random_state=r)
            for tr, te in big.split(Xs, ys, groups=np.array(sessions)):
                Xtr, Xte = select.apply_variant(variant, width, Xs[tr], Xs[te])
                m = compare.make_model(model_name, 20260803 + r)
                m.fit(Xtr, ys[tr])
                flat[te] = [str(c) for c in np.asarray(m.predict(Xte))]
            arms["flat_within_family"].append(
                balanced_accuracy_score(yf, flat[members]))

        summary = {
            arm: {
                "balanced_accuracy": round(float(np.mean(v)), 4),
                "std": round(float(np.std(v)), 4),
            }
            for arm, v in arms.items()
        }
        chance = 1.0 / len(labels_here)
        summary.update({
            "classes": labels_here,
            "sessions_per_class": counts,
            "folds_used": use_folds,
            "chance": round(chance, 4),
            "specialist_minus_flat": round(
                summary["specialist"]["balanced_accuracy"]
                - summary["flat_within_family"]["balanced_accuracy"], 4),
            "specialist_minus_shuffled": round(
                summary["specialist"]["balanced_accuracy"]
                - summary["shuffled"]["balanced_accuracy"], 4),
        })
        out["families"][family] = summary

    out["sessions"] = len(sessions)
    out["test_rows_used"] = 0
    return out


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
                 temporal=s["temporal_expansion"],
                 variant=s["feature_variant"],
                 folds=args.folds, repeats=args.repeats)

    report = {
        "schema_version": SCHEMA,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "registration_sha256": verified["registration_sha256"],
        "features": str(args.features),
        "settings": s,
        "folds": args.folds,
        "repeats": args.repeats,
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
    print(f"  {'動作家族':<20} {'類':>3} {'專屬':>8} {'扁平':>8} {'打亂':>8} "
          f"{'亂猜':>7} {'專屬−扁平':>10} {'專屬−打亂':>10}")
    for family, block in sorted(result["families"].items()):
        if "skipped" in block:
            print(f"  {family:<20} {len(block['classes']):>3}  "
                  f"— {block['skipped']}")
            continue
        print(f"  {family:<20} {len(block['classes']):>3} "
              f"{block['specialist']['balanced_accuracy']:>8.4f} "
              f"{block['flat_within_family']['balanced_accuracy']:>8.4f} "
              f"{block['shuffled']['balanced_accuracy']:>8.4f} "
              f"{block['chance']:>7.4f} "
              f"{block['specialist_minus_flat']:>+10.4f} "
              f"{block['specialist_minus_shuffled']:>+10.4f}")
    print()
    print("⚠️ 專屬分類器的問題比較小（2–8 類對 17 類），所以絕對值不構成論點。")
    print("   要看的是「專屬 − 扁平」（兩階段值不值得）與")
    print("   「專屬 − 打亂」（族內到底有沒有訊號）。")
    print(f"報告：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
