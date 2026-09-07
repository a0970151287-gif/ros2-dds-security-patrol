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
import json
import sys
from pathlib import Path

AFFECTED_SCENARIOS = frozenset(
    {"heartbeat_replay", "parameter_tamper", "parameter_flood"}
)


# 建表方式必須一致的欄位。欄位名相同但意義不同，是最難發現的一種污染。
PROVENANCE_KEYS = ("network_source", "zeek_conn_sources", "window_sec")
MISSING = "（無此欄位）"


def _build_provenance(features_csv: Path) -> dict | None:
    """讀特徵表旁邊的 feature_build.json。沒有就回 None。"""
    manifest = features_csv.parent / "feature_build.json"
    if not manifest.is_file():
        return None
    return json.loads(manifest.read_text(encoding="utf-8"))


def _check_provenance(old_csv: Path, new_csv: Path) -> list[str]:
    """回傳不一致的說明；空清單代表可以合併。"""
    old = _build_provenance(old_csv)
    new = _build_provenance(new_csv)
    if old is None or new is None:
        missing = [
            str(p.parent / "feature_build.json")
            for p, m in ((old_csv, old), (new_csv, new))
            if m is None
        ]
        return [
            "找不到 feature_build.json，無法確認兩張表的建表方式相同："
            + "、".join(missing)
        ]
    problems = []
    for key in PROVENANCE_KEYS:
        if key == "zeek_conn_sources":
            # 只比**來源種類**，不比場次數：兩個資料集的場次數必然不同
            # （1,100 對 305），拿計數去比會擋掉正確的合併。要擋的是
            # 「一邊重建過、一邊沒有」，那是 key 的差異。
            if key not in old or key not in new:
                problems.append(
                    f"{key}：舊表 {old.get(key, MISSING)}，"
                    f"新表 {new.get(key, MISSING)}"
                )
            elif sorted(old[key]) != sorted(new[key]):
                problems.append(
                    f"{key} 的來源種類不同：舊表 {sorted(old[key])}，"
                    f"新表 {sorted(new[key])}"
                )
            continue
        # 舊的 build manifest 可能還沒有這些欄位（schema 早於它們）。缺欄位
        # 不能當成相符——那正是「不知道」而不是「一樣」。
        if key not in old or key not in new:
            problems.append(
                f"{key}：舊表 {old.get(key, MISSING)}，"
                f"新表 {new.get(key, MISSING)}"
            )
        elif old[key] != new[key]:
            problems.append(f"{key}：舊表 {old[key]}，新表 {new[key]}")
    return problems


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
    parser.add_argument(
        "--allow-mixed-provenance",
        action="store_true",
        help=(
            "略過建表方式一致性檢查。只在明確知道兩張表為何不同、且該差異"
            "與特徵語意無關時使用。"
        ),
    )
    args = parser.parse_args()

    if not args.allow_mixed_provenance:
        problems = _check_provenance(args.old, args.new)
        if problems:
            print("⛔ 兩張表的建表方式不同，拒絕合併", file=sys.stderr)
            for problem in problems:
                print(f"   {problem}", file=sys.stderr)
            print(
                "   欄位名一樣但意義不同，合併後模型會學到「這列出自哪一次"
                "建表」。請用同一組設定重抽兩邊。",
                file=sys.stderr,
            )
            return 1

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

    # 合併後的表也要能被下一段檢查。少了這一環，鏈條在第二段就斷了：
    # 拿合併結果去做下一次合併時，一致性檢查只會說「找不到
    # feature_build.json」，而那和「兩邊不一樣」是完全不同的狀況。
    old_build = _build_provenance(args.old) or {}
    new_build = _build_provenance(args.new) or {}
    inherited = {
        key: old_build.get(key)
        for key in PROVENANCE_KEYS
        if key != "zeek_conn_sources"
    }
    sources: dict[str, int] = {}
    for build in (old_build, new_build):
        for kind, count in (build.get("zeek_conn_sources") or {}).items():
            sources[kind] = sources.get(kind, 0) + count
    (args.output.parent / "feature_build.json").write_text(
        json.dumps(
            {
                "schema_version": "sros2-firewall-feature-merge/v1",
                **inherited,
                "zeek_conn_sources": dict(sorted(sources.items())),
                "merged_from": {
                    "old": str(args.old),
                    "new": str(args.new),
                    "old_rows_kept": len(kept),
                    "old_rows_dropped": dropped,
                    "new_rows": len(new_rows),
                },
                "rows": len(merged),
                "sessions": len({r["session_id"] for r in merged}),
                "affected_scenarios": sorted(AFFECTED_SCENARIOS),
                "allow_mixed_provenance": bool(args.allow_mixed_provenance),
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

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
