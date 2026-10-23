#!/usr/bin/env python3
"""量二元閘門對**沒見過的攻擊類別**的 recall，比較有無身份通道特徵。

## 為什麼量這個

C2C-042 量到：處女 holdout 的整個模型 open-set recall 只有 **0.0273**，
而瓶頸**不在 OOD 頭**——是二元閘門：

    439 列裡 324 列（73.8%）被二元閘門判成 normal，OOD 頭連看都沒看到。

閘門對未見類別的 recall 是 **0.2620**，而那就是整條鏈的天花板：閘門攔下來的
東西，後面再聰明也救不回來。

2026-09-01 的平衡試跑量到，身份通道對**每一個**攻擊類別都有訊號、對正常為零：

    command_injection 18   identity_abuse 18   …   normal 0

一個「對每類攻擊都相同」的特徵，拿來分辨類別沒用——但拿來回答「這是不是
攻擊」，它的價值恰恰在於**對每類都相同，包括模型沒見過的類**。

## 這支怎麼量

留出兩個類別完全不參與訓練，在剩下的類別上訓練二元閘門，然後看它對那兩個
**沒見過**的類別的 recall。兩臂唯一的差別是有沒有身份通道特徵。

    A 臂：全部特徵
    B 臂：全部特徵 **減去** sros_auth_fail_rate、sros_permission_deny_rate

切分依 `session_id` 分組——同一場的視窗不可以跨越訓練與測試。

## 用法

    python3 工具腳本/measure_unseen_gate_recall.py \\
        --features <fusion_features>.csv \\
        --holdout command_injection identity_abuse \\
        --output <報告>.json
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

IDENTITY_FEATURES = ("sros_auth_fail_rate", "sros_permission_deny_rate")

NON_FEATURE = {
    "session_id", "group_id", "capture_id", "scenario_id", "security_mode",
    "ros_domain_id", "origin", "source", "window", "window_start_unix",
    "label", "binary", "label_scope", "training_eligible",
    "evaluation_eligible", "policy_sha256", "split",
}


def _rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _matrix(rows: list[dict], names: list[str]):
    import numpy as np

    out = np.zeros((len(rows), len(names)), dtype=float)
    for i, row in enumerate(rows):
        for j, name in enumerate(names):
            try:
                out[i, j] = float(row.get(name) or 0.0)
            except ValueError:
                out[i, j] = 0.0
    return out


def run_arm(train_rows, unseen_rows, normal_rows, names, seed):
    """訓練二元閘門，回傳它對未見類別的 recall 與正常誤報率。"""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    x = _matrix(train_rows, names)
    y = np.array([0 if r["label"] == "normal" else 1 for r in train_rows])
    model = RandomForestClassifier(
        n_estimators=300, class_weight="balanced",
        random_state=seed, n_jobs=-1,
    )
    model.fit(x, y)

    unseen_pred = model.predict(_matrix(unseen_rows, names))
    normal_pred = model.predict(_matrix(normal_rows, names))
    return {
        "unseen_recall": float(unseen_pred.mean()),
        "normal_false_positive_rate": float(normal_pred.mean()),
        "unseen_rows": len(unseen_rows),
        "normal_rows": len(normal_rows),
        "train_rows": len(train_rows),
        "features_used": len(names),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--holdout", nargs="+", required=True,
                        help="完全不參與訓練的攻擊類別")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=20260901)
    args = parser.parse_args()

    rows = _rows(args.features)
    if not rows:
        print("⛔ 特徵表是空的")
        return 2

    holdout = set(args.holdout)
    names = sorted(
        n for n in rows[0]
        if n not in NON_FEATURE
    )
    missing = [f for f in IDENTITY_FEATURES if f not in names]
    if missing:
        print(f"⛔ 特徵表裡沒有身份通道特徵：{missing}")
        return 2

    # 留出的類別**整場**排除，不是只排除該類別的列——同一場裡攻擊區間外的
    # normal 視窗也帶著攻擊者的痕跡，留在訓練集裡等於讓模型看過它。
    holdout_sessions = {
        r["session_id"] for r in rows if r["label"] in holdout
    }
    train_rows = [r for r in rows if r["session_id"] not in holdout_sessions]
    unseen_rows = [
        r for r in rows
        if r["session_id"] in holdout_sessions and r["label"] in holdout
    ]
    # 正常誤報只用**純正常場次**量：攻擊場次裡標成 normal 的視窗帶著攻擊者
    # 的痕跡，拿它們當正常會低估誤報。
    normal_rows = [
        r for r in train_rows
        if r["label"] == "normal" and r["scenario_id"] == "normal_patrol"
    ]

    if not unseen_rows or not normal_rows:
        print("⛔ 留出類別或純正常場次是空的")
        return 2

    without = [n for n in names if n not in IDENTITY_FEATURES]

    print(f"=== 二元閘門對未見類別的 recall ===")
    print(f"  留出類別   : {sorted(holdout)}")
    print(f"  留出場次   : {len(holdout_sessions)}")
    print(f"  訓練列     : {len(train_rows)}")
    print(f"  未見列     : {len(unseen_rows)}")
    print(f"  純正常列   : {len(normal_rows)}")
    print()

    with_id = run_arm(train_rows, unseen_rows, normal_rows, names, args.seed)
    no_id = run_arm(train_rows, unseen_rows, normal_rows, without, args.seed)

    print(f"  {'':<26}{'未見 recall':>14}{'正常誤報':>12}{'特徵數':>8}")
    print(f"  {'有身份通道':<26}{with_id['unseen_recall']:>14.4f}"
          f"{with_id['normal_false_positive_rate']:>12.4f}"
          f"{with_id['features_used']:>8}")
    print(f"  {'無身份通道':<26}{no_id['unseen_recall']:>14.4f}"
          f"{no_id['normal_false_positive_rate']:>12.4f}"
          f"{no_id['features_used']:>8}")
    delta = with_id["unseen_recall"] - no_id["unseen_recall"]
    print(f"  {'差':<26}{delta:>+14.4f}")

    report = {
        "schema_version": "sros2-firewall-unseen-gate-recall/v1",
        "features": str(args.features),
        "holdout_labels": sorted(holdout),
        "holdout_sessions": len(holdout_sessions),
        "seed": args.seed,
        "identity_features": list(IDENTITY_FEATURES),
        "with_identity": with_id,
        "without_identity": no_id,
        "unseen_recall_delta": delta,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\n  報告：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
