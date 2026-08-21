#!/usr/bin/env python3
"""把重跑的 300 場特徵併回原本的 800 場，不動任何原始資料。

三個 scenario 的舊場次因為兩個已修的 bug，攻擊專屬證據是空的。重跑產生了新的
300 場，但**原始 `dataset_live` 必須保留**——它是「bug 存在時長什麼樣」的唯一
實證，也是前後對照的基準。

所以合併在**特徵層**做，而不是搬動資料集：

    舊特徵表  去掉 scenario_id ∈ {三個受影響的 scenario} 的列
    ＋
    新特徵表  全部

規則只有這一條，可以逐列稽核。若之後要回到修正前的狀態，重跑一次抽特徵即可，
不需要還原任何檔案。

用法：
    python3 工具腳本/merge_rerun_features.py \\
        --old firewall_lab/features_per_mode/fusion_features_permissive.csv \\
        --new <重跑特徵>/fusion_features_permissive.csv \\
        --output <合併後>/fusion_features_permissive.csv
"""

from __future__ import annotations

import argparse
import collections
import csv
import sys
from pathlib import Path

AFFECTED_SCENARIOS = frozenset(
    {"heartbeat_replay", "parameter_tamper", "parameter_flood"}
)


def _read(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SystemExit(f"{path} 沒有表頭")
        return list(reader.fieldnames), list(reader)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    old_columns, old_rows = _read(args.old)
    new_columns, new_rows = _read(args.new)

    # 欄位必須逐一相符。若抽特徵的版本不同，直接停下來而不是悄悄對齊——
    # 錯位的欄位會產生看起來正常但意義錯誤的訓練資料。
    if old_columns != new_columns:
        only_old = [c for c in old_columns if c not in new_columns]
        only_new = [c for c in new_columns if c not in old_columns]
        print("⛔ 兩份特徵表的欄位不一致，拒絕合併", file=sys.stderr)
        if only_old:
            print(f"   只在舊表：{only_old}", file=sys.stderr)
        if only_new:
            print(f"   只在新表：{only_new}", file=sys.stderr)
        if not only_old and not only_new:
            print("   欄位相同但順序不同", file=sys.stderr)
        return 1

    kept = [r for r in old_rows if r["scenario_id"] not in AFFECTED_SCENARIOS]
    dropped = len(old_rows) - len(kept)

    # 新表只應該含受影響的三個 scenario；混進別的代表抽錯資料集。
    unexpected = {
        r["scenario_id"] for r in new_rows if r["scenario_id"] not in AFFECTED_SCENARIOS
    }
    if unexpected:
        print(
            f"⛔ 新特徵表含非受影響的 scenario：{sorted(unexpected)}", file=sys.stderr
        )
        return 1

    # session_id 不可重疊：重疊代表同一場被算了兩次。
    overlap = {r["session_id"] for r in kept} & {r["session_id"] for r in new_rows}
    if overlap:
        print(f"⛔ session_id 重疊 {len(overlap)} 個，拒絕合併", file=sys.stderr)
        return 1

    merged = kept + new_rows
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=old_columns)
        writer.writeheader()
        writer.writerows(merged)

    def _by_scenario(rows):
        counter = collections.Counter(r["scenario_id"] for r in rows)
        return counter

    print(f"舊表 {args.old}")
    print(f"  總列數 {len(old_rows)}，剔除受影響 {dropped}，保留 {len(kept)}")
    print(f"新表 {args.new}")
    print(f"  總列數 {len(new_rows)}")
    for scenario, count in sorted(_by_scenario(new_rows).items()):
        print(f"    {scenario:20s} {count}")
    print(f"合併 → {args.output}")
    print(f"  總列數 {len(merged)}")
    print(f"  session 數 {len({r['session_id'] for r in merged})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
