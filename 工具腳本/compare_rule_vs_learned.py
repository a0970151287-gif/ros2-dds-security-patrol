#!/usr/bin/env python3
"""規則式 vs 學習式的公平對照，附場次層級的 bootstrap 信賴區間。

## 為什麼需要這張表

「你怎麼知道 AI 比規則好？」是這個題目一定會被問的問題，而目前**沒有**這張表。
既有的消融（network 0.3235／telemetry 0.8484／fusion 0.8602）只比較了餵給
同一個模型的特徵集，**沒有規則式對照組**，也沒有信賴區間。

## 兩個方法論要點

**一、信賴區間必須在場次層級重抽。**
4,397 個視窗來自 550 場 session，同一場內的視窗高度相關。把視窗當成獨立樣本
重抽會讓區間被嚴重低估——C2C-013 已經記過這個問題。本工具重抽的是**場次**，
一場被抽中就整場的視窗一起進來。

**二、規則式對照組必須是「一個懂這個系統的人會寫的規則」，不是稻草人。**
所以規則直接取自本專案自己記錄的證據通道（C2C-025 §二），每一條都是
「某個專屬特徵大於零就判該類」。這是最有利於規則式的寫法：
它用的正是模型認為最有鑑別力的那些訊號。

## 誠實邊界

- 只用 **validation**，不碰 test（test 已經開過一次，不是 sealed）。
- 官方 novelty holdout 的場次全程排除。
- 規則式沒有機率輸出，所以不比 PR-AUC，改比 precision／recall／F1／
  balanced accuracy——這些對兩邊都有定義。
- `sros_auth_fail_rate`／`sros_permission_deny_rate` 在本技術棧是
  `source_unavailable`，依它們寫的規則**必然永遠不觸發**。這不是規則寫壞了，
  是證據通道不存在，而這正是要呈現的結論之一。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SCHEMA = "sros2-firewall-rule-vs-learned/v1"

NETWORK_FEATURES = (
    "conn_count", "conn_rate", "uniq_dst_ports", "uniq_dst_hosts",
    "spdp_ratio", "meta_ratio", "userdata_ratio", "mcast_ratio",
    "dst_port_entropy", "interarrival_cv", "burstiness",
    "dominant_port_ratio", "dominant_host_ratio", "tuple_repeat_ratio",
)
TELEMETRY_FEATURES = (
    "sros_auth_fail_rate", "sros_permission_deny_rate",
    "participant_churn_rate", "unknown_node_rate", "hmac_failure_rate",
    "nonce_reuse_ratio", "channel_mismatch_ratio", "timestamp_violation_ratio",
    "publisher_violation_ratio", "parameter_call_rate",
    "oversized_message_ratio", "qos_drop_ratio", "heartbeat_gap_sec",
    "control_conflict_ratio", "scan_static_ratio", "odom_cmd_mismatch_ratio",
    "alert_reflection_ratio", "log_reject_rate",
)

# 規則取自本專案記錄的專屬證據通道（C2C-025 §二）。
# 順序即優先序：先命中的先判定。這個順序是刻意的，理由記在下面。
RULES: tuple[tuple[str, str], ...] = (
    # 專屬性最高的三條先走——它們各自只有一個攻擊類會觸發。
    ("hmac_failure_rate", "sensor_spoof"),
    ("oversized_message_ratio", "message_dos"),
    ("alert_reflection_ratio", "replay_dos"),
    # nonce 早於 parameter：重放要走到 nonce 檢查本來就困難（時間戳先擋），
    # 所以它一旦非零，證據力比 parameter 那條強。
    ("nonce_reuse_ratio", "replay"),
    # parameter_call_rate 同時被 parameter_tamper 與 service_dos 觸發，
    # 規則無法分辨——這是要呈現的限制，不是把它藏起來。
    ("parameter_call_rate", "parameter_tamper"),
    # 這兩個在本技術棧是 source_unavailable，永遠不會觸發。保留是為了誠實：
    # 規則寫得出來，證據拿不到。
    ("sros_auth_fail_rate", "identity_abuse"),
    ("sros_permission_deny_rate", "identity_abuse"),
)


def rule_predict(frame):
    """套用規則。任何一條都沒命中就判 normal。"""
    import numpy as np

    predictions = np.full(len(frame), "normal", dtype=object)
    decided = np.zeros(len(frame), dtype=bool)
    fired: dict[str, int] = {}
    for column, label in RULES:
        if column not in frame:
            continue
        hit = (frame[column].to_numpy() > 0) & ~decided
        fired[column] = int(hit.sum())
        predictions[hit] = label
        decided |= hit
    return predictions, fired


def _metrics(truth, predicted):
    import numpy as np
    from sklearn.metrics import (
        balanced_accuracy_score, f1_score, precision_score, recall_score,
    )

    truth = np.asarray(truth, dtype=object)
    predicted = np.asarray(predicted, dtype=object)
    binary_truth = truth != "normal"
    binary_pred = predicted != "normal"
    return {
        "binary_precision": float(precision_score(
            binary_truth, binary_pred, zero_division=0)),
        "binary_recall": float(recall_score(
            binary_truth, binary_pred, zero_division=0)),
        "binary_f1": float(f1_score(
            binary_truth, binary_pred, zero_division=0)),
        "binary_balanced_accuracy": float(
            balanced_accuracy_score(binary_truth, binary_pred)),
        "multiclass_balanced_accuracy": float(
            balanced_accuracy_score(truth, predicted)),
        "multiclass_macro_f1": float(f1_score(
            truth, predicted, average="macro", zero_division=0)),
    }


def _bootstrap(truth, predicted, groups, *, iterations: int, seed: int):
    """場次層級重抽。

    重抽視窗會把區間壓得太窄，因為同一場內的視窗不是獨立的。
    這裡抽的是場次；一場被抽中，它的所有視窗一起進來。
    """
    import numpy as np

    rng = np.random.default_rng(seed)
    truth = np.asarray(truth, dtype=object)
    predicted = np.asarray(predicted, dtype=object)
    groups = np.asarray(groups, dtype=object)
    unique = np.unique(groups)
    index_by_group = {name: np.flatnonzero(groups == name) for name in unique}

    samples: dict[str, list[float]] = {}
    for _ in range(iterations):
        drawn = rng.choice(unique, size=len(unique), replace=True)
        index = np.concatenate([index_by_group[name] for name in drawn])
        if len(np.unique(truth[index])) < 2:
            # 重抽出來只剩一類時指標沒有定義，跳過而不是補 0——
            # 補 0 會把區間往下拉，那是憑空造出來的悲觀。
            continue
        for key, value in _metrics(truth[index], predicted[index]).items():
            samples.setdefault(key, []).append(value)

    return {
        key: {
            "ci95_low": float(np.percentile(values, 2.5)),
            "ci95_high": float(np.percentile(values, 97.5)),
            "bootstrap_samples": len(values),
        }
        for key, values in samples.items()
    }


def evaluate(feature_csv: Path, *, iterations: int, seed: int,
             n_estimators: int) -> dict:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    frame = pd.read_csv(feature_csv)
    mode = sorted(set(frame["security_mode"].astype(str)))
    if len(mode) != 1:
        raise ValueError(f"feature table mixes modes: {mode}")

    # 官方 novelty holdout 的場次全程排除：它保留給整個模型層級的一次性評估。
    holdout_groups = set(
        frame.loc[frame["novelty_role"].astype(str) == "holdout", "group_id"]
        .astype(str)) if "novelty_role" in frame else set()
    frame = frame.loc[
        ~frame["group_id"].astype(str).isin(holdout_groups)].reset_index(drop=True)

    train = frame.loc[frame["split"].astype(str) == "train"]
    validation = frame.loc[frame["split"].astype(str) == "validation"]
    if train.empty or validation.empty:
        raise ValueError("train or validation split is empty")

    truth = validation["label"].astype(str).to_numpy()
    groups = validation["group_id"].astype(str).to_numpy()

    results: dict[str, dict] = {}

    rule_pred, fired = rule_predict(validation)
    results["rule_based"] = {
        "point": _metrics(truth, rule_pred),
        "ci": _bootstrap(truth, rule_pred, groups,
                         iterations=iterations, seed=seed),
        "rules_fired": fired,
        "rules": [{"feature": column, "label": label}
                  for column, label in RULES],
    }

    feature_sets = {
        "learned_network_only": NETWORK_FEATURES,
        "learned_telemetry_only": TELEMETRY_FEATURES,
        "learned_fusion": NETWORK_FEATURES + TELEMETRY_FEATURES,
    }
    for name, columns in feature_sets.items():
        usable = [c for c in columns if c in frame]
        model = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=16, min_samples_leaf=2,
            max_features="sqrt", class_weight="balanced_subsample",
            random_state=seed, n_jobs=1)
        model.fit(train[usable].to_numpy(),
                  train["label"].astype(str).to_numpy())
        predicted = model.predict(validation[usable].to_numpy())
        results[name] = {
            "point": _metrics(truth, predicted),
            "ci": _bootstrap(truth, predicted, groups,
                             iterations=iterations, seed=seed),
            "features_used": len(usable),
        }

    return {
        "schema_version": SCHEMA,
        "evaluated_utc": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "security_mode": mode[0],
        "protocol": {
            "evaluation_split": "validation",
            "test_rows_used": 0,
            "novelty_holdout_groups_excluded": len(holdout_groups),
            "bootstrap": "session_level_resampling",
            "bootstrap_iterations": iterations,
        },
        "counts": {
            "train_rows": int(len(train)),
            "validation_rows": int(len(validation)),
            "validation_sessions": int(len(set(groups))),
        },
        "results": results,
        "deployment_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20260827)
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    if args.output.exists():
        print(f"⛔ {args.output} 已存在，拒絕覆寫", file=sys.stderr)
        return 1

    report = evaluate(args.features, iterations=args.iterations,
                      seed=args.seed, n_estimators=args.n_estimators)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")

    print(f"=== 規則式 vs 學習式（{report['security_mode']}，"
          f"validation {report['counts']['validation_sessions']} 場）===")
    print(f"  bootstrap：場次層級重抽 {args.iterations} 次")
    print()
    header = f"  {'方法':<24}{'二元 F1':>20}{'多類 balanced acc':>24}"
    print(header)
    for name, block in report["results"].items():
        point = block["point"]
        ci = block["ci"]
        f1 = point["binary_f1"]
        f1_ci = ci.get("binary_f1", {})
        acc = point["multiclass_balanced_accuracy"]
        acc_ci = ci.get("multiclass_balanced_accuracy", {})
        print(f"  {name:<24}"
              f"{f1:>8.4f} [{f1_ci.get('ci95_low', 0):.3f},{f1_ci.get('ci95_high', 0):.3f}]"
              f"{acc:>10.4f} [{acc_ci.get('ci95_low', 0):.3f},{acc_ci.get('ci95_high', 0):.3f}]")
    print()
    fired = report["results"]["rule_based"]["rules_fired"]
    print("  規則命中次數：")
    for column, count in sorted(fired.items(), key=lambda kv: -kv[1]):
        note = "  ← 來源不可得，必然為 0" if count == 0 and column.startswith(
            "sros_") else ""
        print(f"     {column:28s} {count:6d}{note}")
    print(f"\n→ {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
