#!/usr/bin/env python3
"""把側表（獨立算出來的候選特徵）接回既有特徵表，接不齊就拒絕。

## 為什麼需要一支專門的工具

候選特徵一律先算成**獨立一張表**，不動 `features.py`（`build_behavioural_features.py`
與 `build_hmac_channel_features.py` 都是這樣）。但「接回去」這一步如果隨手寫，
會安靜地出兩種錯：

| 錯 | 後果 |
|---|---|
| 側表缺列，用 0 補 | 「沒有訊號」與「沒有算到」變成同一個值，模型學到的是後者 |
| 只保留兩邊都有的列 | 基準臂與實驗臂的**列數不同**，兩邊的分數不可比 |

第二種特別陰險：兩個模型各自的分數都合理，差異卻完全來自樣本不同。

所以這支的預設是 **fail-closed**：兩邊的 `(session_id, window)` 必須**完全相同**，
少一列或多一列都直接拒絕並印出缺哪些。要放寬必須明講 `--allow-partial`，
而那時會印出被丟掉的列數——不會安靜發生。

## 用法

    python3 工具腳本/join_side_features.py \\
        --base ~/features_refresh_split/fusion_features_enforce.csv \\
        --side ~/hmac_channel_enforce.csv \\
        --columns hmac_ch_alerts_rate hmac_ch_alerts_share \\
        --output ~/joined_enforce.csv

`--columns` 省略時接入側表的**全部**欄位（`session_id`／`window` 除外）。
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

KEY = ("session_id", "window")


class JoinError(RuntimeError):
    """接不起來就中止。"""


def read_table(path: Path) -> tuple[list[dict], list[str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        names = list(reader.fieldnames or ())
    if not rows:
        raise JoinError(f"empty table: {path}")
    for key in KEY:
        if key not in names:
            raise JoinError(f"{path} lacks the join key {key!r}")
    return rows, names


def key_of(row: dict) -> tuple[str, str]:
    return (row["session_id"], str(int(row["window"])))


def join(base_path: Path, side_paths: list[Path], columns: list[str] | None,
         *, allow_partial: bool) -> tuple[list[dict], list[str]]:
    base, base_names = read_table(base_path)
    merged_names = list(base_names)
    # 基表是 (session, window, source) 粒度：同一個視窗有幾個來源就有幾列，
    # 而**遙測特徵在那幾列上是相同的**（實測 enforce 2,076／permissive 1,900
    # 個多來源視窗，遙測欄位變異的有 0 個；網路欄位則每一個都變）。側表算的是
    # 視窗層級的遙測，所以正確語意是**一對多廣播**，與 `features.py` 一致。
    merged: list[dict] = [dict(row) for row in base]
    by_key: dict[tuple[str, str], list[dict]] = {}
    for row in merged:
        by_key.setdefault(key_of(row), []).append(row)
    index = by_key

    for side_path in side_paths:
        side, side_names = read_table(side_path)
        wanted = [n for n in side_names if n not in KEY]
        if columns is not None:
            missing = sorted(set(columns) - set(wanted))
            if missing:
                raise JoinError(f"{side_path} lacks requested columns: {missing}")
            wanted = [n for n in wanted if n in set(columns)]
        clash = sorted(set(wanted) & set(merged_names))
        if clash:
            raise JoinError(f"{side_path} would overwrite existing columns: {clash}")

        side_index: dict[tuple[str, str], dict] = {}
        for row in side:
            k = key_of(row)
            if k in side_index:
                raise JoinError(f"{side_path} has a duplicate key: {k}")
            side_index[k] = row

        only_base = sorted(set(index) - set(side_index))
        only_side = sorted(set(side_index) - set(index))
        if (only_base or only_side) and not allow_partial:
            raise JoinError(
                f"{side_path}: key sets differ — base-only {len(only_base)}, "
                f"side-only {len(only_side)}; first base-only {only_base[:3]}, "
                f"first side-only {only_side[:3]}. "
                "補零會讓「沒有訊號」與「沒有算到」變成同一件事；"
                "只留交集會讓兩臂列數不同而分數不可比。要放寬請明講 --allow-partial")
        if only_base:
            dropped_rows = sum(len(index[k]) for k in only_base)
            for k in only_base:
                index.pop(k)
            sys.stderr.write(
                f"  ⚠ --allow-partial：丟掉 {len(only_base)} 個視窗／"
                f"{dropped_rows} 列（側表沒有）\n")
        if only_side:
            sys.stderr.write(
                f"  ⚠ --allow-partial：忽略 {len(only_side)} 個視窗（基表沒有）\n")

        for k, rows_for_key in index.items():
            values = {n: side_index[k][n] for n in wanted}
            for row in rows_for_key:
                row.update(values)
        merged_names.extend(wanted)

    kept = {id(row) for rows_for_key in index.values() for row in rows_for_key}
    ordered = [row for row in merged if id(row) in kept]
    return ordered, merged_names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--side", type=Path, nargs="+", required=True)
    parser.add_argument("--columns", nargs="*", default=None,
                        help="只接這些欄位；省略則接側表全部")
    parser.add_argument("--allow-partial", action="store_true",
                        help="容許兩邊列不齊（會印出丟掉幾列）")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output.exists():
        print(f"⛔ 輸出已存在，拒絕覆寫：{args.output}")
        return 2
    try:
        rows, names = join(args.base, args.side, args.columns,
                           allow_partial=args.allow_partial)
    except (JoinError, OSError, ValueError) as exc:
        print(f"⛔ {exc}")
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names)
        writer.writeheader()
        writer.writerows(rows)
    added = len(names) - len(read_table(args.base)[1])
    print(f"  {len(rows)} 列 × {len(names)} 欄（新增 {added}）-> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
