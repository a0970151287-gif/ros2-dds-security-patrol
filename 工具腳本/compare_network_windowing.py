#!/usr/bin/env python3
"""比較三種網路特徵建表方式，讓「換分窗方式」是量出來的決定而不是偏好。

三張表：

| 代號 | Zeek | 分窗依據 |
|---|---|---|
| `conn_broken` | 沒有 `-C`，校驗和丟包 | 流起點 |
| `conn_fixed` | 加了 `-C` | 流起點 |
| `packet` | 加了 `-C` | **逐封包時間** |

比的不是模型分數，是**表本身的性質**：每場有幾個視窗、攻擊視窗佔多少、
量體欄位是不是真的有值、以及各類別的視窗數是否還夠訓練。模型分數要另外跑，
而且要在決定用哪張表之後才跑一次。

用法：

    python3 工具腳本/compare_network_windowing.py \\
        --table conn_broken=/home/jesse/features_live_raw/fusion_features.csv \\
        --table conn_fixed=/home/jesse/features_live_raw_cfix/fusion_features.csv \\
        --table packet=/home/jesse/features_live_raw_pkt/fusion_features.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

VOLUME_FEATURES = (
    "orig_bytes_rate",
    "orig_pkts_rate",
    "mean_bytes_per_packet",
    "max_conn_bytes",
    "amplification_ratio",
)


def summarise(path: Path) -> dict:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        return {"rows": 0}

    per_session: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    attack_windows: Counter[str] = Counter()
    for row in rows:
        per_session[row["session_id"]] += 1
        labels[row["label"]] += 1
        if row["label"] != "normal":
            attack_windows[row["session_id"]] += 1

    nonzero = {}
    for feature in VOLUME_FEATURES:
        if feature not in rows[0]:
            nonzero[feature] = None
            continue
        hits = 0
        for row in rows:
            try:
                if float(row[feature] or 0) > 0:
                    hits += 1
            except ValueError:
                pass
        nonzero[feature] = round(hits / len(rows), 4)

    # 每場攻擊視窗數：只看確實含攻擊列的場次。
    attack_counts = [v for v in attack_windows.values() if v]

    manifest = path.parent / "feature_build.json"
    provenance = {}
    if manifest.is_file():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        provenance = {
            k: data.get(k)
            for k in ("network_source", "zeek_conn_sources", "window_sec")
        }

    return {
        "rows": len(rows),
        "sessions": len(per_session),
        "windows_per_session_median": statistics.median(per_session.values()),
        "windows_per_session_min": min(per_session.values()),
        "windows_per_session_max": max(per_session.values()),
        "attack_sessions": len(attack_counts),
        "attack_windows_per_session_median": (
            statistics.median(attack_counts) if attack_counts else 0
        ),
        "labels": dict(labels.most_common()),
        "volume_feature_nonzero_rate": nonzero,
        "provenance": provenance,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", action="append", required=True,
                        metavar="NAME=PATH")
    parser.add_argument("--report", type=Path,
                        default=Path("文件/網路分窗方式對照_2026-08-31.json"))
    args = parser.parse_args()

    tables = {}
    for item in args.table:
        name, _, path = item.partition("=")
        tables[name] = summarise(Path(path))

    names = list(tables)
    print(f"  {'':<34}" + "".join(f"{n:>18}" for n in names))

    def line(caption, key, fmt="{}"):
        values = []
        for n in names:
            value = tables[n].get(key)
            values.append(fmt.format(value) if value is not None else "—")
        print(f"  {caption:<34}" + "".join(f"{v:>18}" for v in values))

    line("特徵列數", "rows", "{:,}")
    line("場次", "sessions", "{:,}")
    line("每場視窗數（中位數）", "windows_per_session_median")
    line("每場視窗數（最少）", "windows_per_session_min")
    line("每場視窗數（最多）", "windows_per_session_max")
    line("有攻擊視窗的場次", "attack_sessions", "{:,}")
    line("每場攻擊視窗（中位數）", "attack_windows_per_session_median")

    print()
    print("  量體特徵的非零率")
    for feature in VOLUME_FEATURES:
        values = []
        for n in names:
            rate = tables[n]["volume_feature_nonzero_rate"].get(feature)
            values.append("（無此欄）" if rate is None else f"{rate:.2%}")
        print(f"    {feature:<32}" + "".join(f"{v:>18}" for v in values))

    print()
    print("  每個標籤的視窗數")
    all_labels = sorted({k for t in tables.values() for k in t["labels"]})
    for label in all_labels:
        values = [f"{tables[n]['labels'].get(label, 0):,}" for n in names]
        print(f"    {label:<32}" + "".join(f"{v:>18}" for v in values))

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(tables, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\n  報告：{args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
