#!/usr/bin/env python3
"""用保留的 novelty holdout 場次，量測整個模型的 open-set recall。

為什麼需要這一支：grouped 模型報的 0.7627 是**異常偵測頭**的數字——同一個
bundle 裡的分類器**看過**那兩個 holdout 類別，所以那不能寫成整個模型的 open-set
結果。分層線的協定是乾淨的（supervised train／calibration／selection／threshold
四個計數全為零），但它刻意**從不評估**：`test_prediction_passes` 是寫死的 0，
100 場 holdout 原封不動地保留著。

這支就是去花掉那 100 場。它只讀已簽章的 bundle 與特徵表，不訓練、不調任何門檻。

**一次性。** 花掉之後若再調架構或門檻，這個數字就跟舊 test 一樣被燒掉了。
artifact 會記下 bundle 的 sha256 與特徵表的 sha256，之後可以驗證「評估的是這一版」。

必須一起帶上的前提：分層架構（binary → family → OOD）當初是在**看過歷史 test**
的情況下設計的。holdout **類別**從未被看過，所以 open-set 數字有效；但**架構
選擇**不是盲的，因此 artifact 仍記 `independent_final_test=false`。

用法：
    python3 工具腳本/evaluate_openset_holdout.py \\
        --model <models_hier/permissive>/hierarchical_model.joblib \\
        --metrics <models_hier/permissive>/training_metrics.json \\
        --features <features>/fusion_features_permissive.csv \\
        --output <models_hier/permissive>/openset_holdout.json
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.stream_replay import replay_in_order, tally  # noqa: E402
from firewall_lab.hierarchical_model import (  # noqa: E402
    HierarchicalFirewallModel,
    TELEMETRY_FEATURES,
)

HOLDOUT_ROLE = "novelty_holdout_candidate"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument(
        "--release-manifest",
        type=Path,
        default=None,
        help="預設取 --metrics 同目錄的 release_manifest.json（policy hash 在那裡）",
    )
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.output.exists():
        print(
            f"⛔ {args.output} 已存在。這個評估是一次性的，拒絕覆寫。",
            file=sys.stderr,
        )
        return 1

    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    novelty = metrics["novelty_protocol"]
    # 先確認協定真的乾淨；四個計數任一非零就不該宣稱 open-set。
    dirty = {
        name: novelty[name]
        for name in (
            "supervised_train_rows_used",
            "calibration_rows_used",
            "selection_rows_used",
            "threshold_rows_used",
        )
        if novelty.get(name)
    }
    if dirty:
        print(f"⛔ novelty 協定不乾淨：{dirty}", file=sys.stderr)
        return 1

    holdout_labels = set(novelty["holdout_labels"])
    availability = metrics["source_availability"]
    security_mode = metrics["security_mode"]

    manifest_path = args.release_manifest or args.metrics.with_name(
        "release_manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    model = HierarchicalFirewallModel(
        args.model,
        data_policy_sha256=manifest["data_policy_sha256"],
        action_policy_sha256=manifest["action_policy_sha256"],
    )

    with args.features.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    # 依 (session, source, window) 因果排序：模型自己維護串流歷史，亂序會讓
    # 時序特徵失去意義。
    rows.sort(key=lambda r: (r["session_id"], r["source"], int(r["window"])))

    # ⚠️ 不可以先過濾再餵模型。550 場裡有 393 場同時含 normal 與攻擊列，
    # 依標籤過濾會讓 485 條串流從 window 1 開始，該有歷史的列拿到 cold-start
    # 特徵——而訓練端 `_expanded_matrix` 用的是完整 session。先前版本就是這樣
    # 量的，數字全部偏掉。現在改成：整個 session 逐列依序餵進模型維持歷史，
    # 只在統計時挑要算的列。
    holdout_sessions = {r["session_id"] for r in rows if r["label"] in holdout_labels}
    if holdout_labels == {"sensor_spoof", "service_dos"}:
        marked = {r["session_id"] for r in rows if r.get("novelty_role") == HOLDOUT_ROLE}
        if marked and marked != holdout_sessions:
            print("⛔ holdout 標籤與 novelty_role 欄位不一致", file=sys.stderr)
            return 1
    holdout_rows = [r for r in rows if r["label"] in holdout_labels]
    normal_rows = [
        r
        for r in rows
        if r["label"] == "normal" and r["session_id"] not in holdout_sessions
    ]
    if not holdout_rows:
        print("⛔ 特徵表裡沒有任何 holdout 列", file=sys.stderr)
        return 1

    # 只取模型自己宣告的 32 個原始特徵。用「排除已知欄位」的黑名單會誤帶
    # ros_domain_id／window／window_start_unix 這類非特徵欄位進去，而
    # build_expanded_row 會逐一比對欄位集合並拒絕——那道檢查是對的。
    raw_features = list(model.bundle["raw_features"])

    # 餵列與統計刻意分開，且用共用的 `replay_in_order`——不是在這裡再抄一份
    # 迴圈。契約（每條串流從 window 0 起、逐一遞增）由 helper 強制，
    # `tests/test_stream_replay.py` 守著它，`tests/test_openset_cli.py` 再驗
    # 這條 CLI 真的走那條路徑。
    pairs = replay_in_order(
        rows,
        predict=lambda row, window: model.predict(
            {name: float(row[name]) for name in raw_features},
            security_mode=security_mode,
            source_availability=availability,
            session_id=row["session_id"],
            source=row["source"],
            window=window,
        ),
        reset=lambda session, source: model.reset_stream(
            session_id=session, source=source
        ),
    )
    holdout_counts, normal_counts = tally(
        pairs,
        [
            lambda row: row["label"] in holdout_labels,
            lambda row: row["label"] == "normal"
            and row["session_id"] not in holdout_sessions,
        ],
        label_of=lambda verdict: verdict["predicted_class"],
    )
    tallies = [sum(holdout_counts.values()), sum(normal_counts.values())]
    if tallies != [len(holdout_rows), len(normal_rows)]:
        print("⛔ 統計到的列數與預期不符", file=sys.stderr)
        return 1

    holdout_unknown = holdout_counts["unknown_attack"]
    normal_unknown = normal_counts["unknown_attack"]
    recall = holdout_unknown / len(holdout_rows)
    fpr = normal_unknown / len(normal_rows) if normal_rows else 0.0

    report = {
        "schema_version": "sros2-firewall-openset-holdout/v1",
        "evaluated_utc": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "security_mode": security_mode,
        "holdout_labels": sorted(holdout_labels),
        "model_sha256": _sha256(args.model),
        "features_sha256": _sha256(args.features),
        "holdout_rows": len(holdout_rows),
        "holdout_sessions": len({r["session_id"] for r in holdout_rows}),
        "holdout_flagged_unknown": holdout_unknown,
        "open_set_recall": recall,
        "normal_rows": len(normal_rows),
        "normal_flagged_unknown": normal_unknown,
        "normal_false_unknown_rate": fpr,
        "holdout_verdict_distribution": dict(holdout_counts),
        # 整份表逐列跑過一次；cold start 次數應等於串流數。
        "history_matches_training_semantics": True,
        # 架構是在看過歷史 test 的情況下設計的；holdout 類別未被看過，所以
        # recall 有效，但架構選擇不是盲的。
        "independent_final_test": False,
        "architecture_informed_by_historical_test": True,
        "one_shot": "spending these holdout sessions again after any retuning "
        "invalidates this figure",
    }
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"=== open-set holdout 評估（{security_mode}）===")
    print(f"  holdout 類別      : {sorted(holdout_labels)}")
    print(f"  holdout 場次／列數 : {report['holdout_sessions']} / {len(holdout_rows)}")
    print(f"  判為 unknown_attack: {holdout_unknown}")
    print(f"  **open-set recall** : {recall:.4f}")
    print(f"  normal 誤判為 unknown: {normal_unknown} / {len(normal_rows)} = {fpr:.4f}")
    print(f"  holdout 判定分佈    : {dict(holdout_counts)}")
    print(f"  → {args.output}")
    return 0


def _is_number(value: str) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


if __name__ == "__main__":
    raise SystemExit(main())
