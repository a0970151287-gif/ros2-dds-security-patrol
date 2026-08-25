#!/usr/bin/env python3
"""拆解 open-set 判定走了哪一條路。

`evaluate_openset_holdout.py` 只給最終 recall。但「整個模型認不出未知」有兩種
完全不同的成因，修法也完全不同：

    binary_missed   二元閘門就把它當成 normal —— OOD 頭**連看都沒看到**
    ood_missed      閘門放行了，但 OOD 頭沒把它標成未知

實測差異極大：`sensor_spoof`／`service_dos` 只有 10.8% 被閘門擋在外面，
`command_injection`／`identity_abuse` 卻有 73.8%。所以換 OOD 評分器對前者
有效、對後者無效——瓶頸根本不在同一層。

這支不訓練、不調門檻，只讀已簽章的 bundle 跑推論並統計路徑。
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.hierarchical_model import HierarchicalFirewallModel  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    holdout_labels = set(metrics["novelty_protocol"]["holdout_labels"])
    availability = metrics["source_availability"]
    security_mode = metrics["security_mode"]
    manifest = json.loads(
        args.metrics.with_name("release_manifest.json").read_text(encoding="utf-8")
    )
    model = HierarchicalFirewallModel(
        args.model,
        data_policy_sha256=manifest["data_policy_sha256"],
        action_policy_sha256=manifest["action_policy_sha256"],
    )

    with args.features.open(encoding="utf-8", newline="") as handle:
        rows = [r for r in csv.DictReader(handle) if r["label"] in holdout_labels]
    rows.sort(key=lambda r: (r["session_id"], r["source"], int(r["window"])))

    raw_features = list(model.bundle["raw_features"])
    paths: collections.Counter = collections.Counter()
    per_label: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    last: dict[tuple[str, str], int] = {}
    for row in rows:
        key = (row["session_id"], row["source"])
        window = int(row["window"])
        # 特徵表有視窗斷點；跨斷點餵歷史等於宣稱兩個不相鄰的視窗相接。
        if last.get(key) != window - 1:
            model.reset_stream(session_id=key[0], source=key[1])
        last[key] = window
        verdict = model.predict(
            {name: float(row[name]) for name in raw_features},
            security_mode=security_mode,
            source_availability=availability,
            session_id=row["session_id"],
            source=row["source"],
            window=window,
        )
        binary_fired = verdict["attack_probability"] >= verdict["binary_threshold"]
        if verdict["predicted_class"] == "unknown_attack":
            path = "flagged_unknown_via_ood" if binary_fired else "flagged_unknown_via_normality"
        elif not binary_fired:
            path = "binary_missed"
        else:
            path = "ood_missed"
        paths[path] += 1
        per_label[row["label"]][path] += 1

    total = sum(paths.values())
    reachable = total - paths["binary_missed"]
    report = {
        "schema_version": "sros2-firewall-openset-paths/v1",
        "security_mode": security_mode,
        "holdout_labels": sorted(holdout_labels),
        "rows": total,
        "paths": dict(paths),
        "per_label": {k: dict(v) for k, v in per_label.items()},
        "binary_gate_recall": (reachable / total) if total else 0.0,
        # OOD 頭在「有機會看到的列」裡抓到多少。這才是評分器本身的成績；
        # 整體 recall 還要乘上閘門的 recall。
        "ood_recall_among_reachable": (
            paths["flagged_unknown_via_ood"] / reachable if reachable else 0.0
        ),
    }

    print(f"=== open-set 路徑拆解（{security_mode}, {sorted(holdout_labels)}）===")
    print(f"  總列數                    : {total}")
    print(f"  二元閘門就漏掉            : {paths['binary_missed']}"
          f"  ({paths['binary_missed'] / total:.1%})")
    print(f"  閘門放行但 OOD 沒抓到     : {paths['ood_missed']}")
    print(f"  OOD 標成未知              : {paths['flagged_unknown_via_ood']}")
    print(f"  normality 頭標成未知      : {paths['flagged_unknown_via_normality']}")
    print(f"  **二元閘門 recall**       : {report['binary_gate_recall']:.4f}"
          f"   ← open-set recall 的上限")
    print(f"  OOD 在可及列中的 recall   : {report['ood_recall_among_reachable']:.4f}")
    for label in sorted(per_label):
        print(f"    {label:20s} {dict(per_label[label])}")

    if args.output:
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"  → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
