#!/usr/bin/env python3
"""這個觀測層支撐得起幾個可分辨的攻擊類別？

證據排他性 gate 原本只用在 smoke 的單場候選上。同一個問法套到整批資料，
回答的是一個更根本的問題——如果答案小於類別數，那識別率就有結構性解釋，
而不只是「模型不夠好」。

2026-09-02 用它量到：**Enforce 下八個攻擊類別沒有任何一個產生 normal 流量
不會產生的訊號**，而 Permissive 下每一類都有 3–17 個專屬訊號。那解釋了
識別率 0.42 對 0.86 的差距。

## ⚠️ 這支曾經因為選錯資料集而報出錯的結論

第一版直接掃 `dataset_live`，得到 6／28 對不可分，其中
`parameter_tamper ←→ replay` 完全相同。**那是一個已知且已修的歷史缺陷**——
C2C-024 的 300 場受控重跑正是修這三個 scenario。拿舊資料量它們，等於把
修好的 bug 報成現況。改取重跑版之後是 2／28。

所以資料來源**必須明示**：`--dataset` 可重複，後面的覆蓋前面的同名 scenario。
不再有「預設掃某個目錄」這種會靜默選錯的行為。

## 用法

    # 單一資料集
    python3 工具腳本/measure_class_separability.py \\
        --dataset ~/refresh_.../enforce/dataset --security-mode enforce

    # 舊資料 ＋ 重跑版（後者覆蓋同名 scenario）
    python3 工具腳本/measure_class_separability.py \\
        --dataset firewall_lab/dataset_live \\
        --dataset ~/dataset_rerun300 \\
        --override-scenario heartbeat_replay \\
        --override-scenario parameter_tamper \\
        --override-scenario parameter_flood \\
        --security-mode permissive
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.session_reader import (  # noqa: E402
    SessionReadError,
    iter_sessions,
    signal_counts,
)


def collect(
    datasets: list[Path],
    *,
    security_mode: str,
    override_scenarios: set[str],
    per_class: int,
) -> tuple[dict[str, collections.Counter], dict[str, int], dict[str, set[str]]]:
    """把每個類別的訊號集合合起來。

    後面的 dataset 覆蓋前面的同名 scenario——那是「重跑版取代原版」的語意，
    而且必須由 `--override-scenario` 明示，不可猜。
    """
    by_class: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    taken: collections.Counter = collections.Counter()
    sources: dict[str, set[str]] = collections.defaultdict(set)

    # 先掃後面的（優先），再掃前面的並跳過被覆蓋的 scenario
    for index, root in enumerate(reversed(datasets)):
        is_override_source = index < len(datasets) - 1
        for session in iter_sessions(root, security_mode=security_mode):
            if not is_override_source and session.scenario_id in override_scenarios:
                continue
            if taken[session.attack_class] >= per_class:
                continue
            try:
                by_class[session.attack_class] += signal_counts(session)
            except SessionReadError:
                continue
            taken[session.attack_class] += 1
            sources[session.attack_class].add(root.name)
    return dict(by_class), dict(taken), dict(sources)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, action="append", required=True,
                        help="可重複；後面的覆蓋前面的同名 scenario")
    parser.add_argument("--security-mode", choices=("permissive", "enforce"),
                        required=True)
    parser.add_argument("--override-scenario", action="append", default=[],
                        help="要由後面的 dataset 取代的 scenario_id")
    parser.add_argument("--per-class", type=int, default=12,
                        help="每類取幾場（訊號種類在十幾場內就收斂）")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    if len(args.dataset) > 1 and not args.override_scenario:
        print("⛔ 給了多個 dataset 卻沒有 --override-scenario："
              "覆蓋關係必須明示，否則會靜默選錯版本")
        return 2

    by_class, taken, sources = collect(
        args.dataset,
        security_mode=args.security_mode,
        override_scenarios=set(args.override_scenario),
        per_class=args.per_class,
    )
    if "normal" not in by_class:
        print("⛔ 沒有 normal 場次——排他性無從判斷")
        return 2

    print("=== %s：取樣來源 ===" % args.security_mode)
    for name in sorted(taken):
        print("  %-22s %2d 場   %s" % (name, taken[name],
                                       ",".join(sorted(sources[name]))))

    normal = set(by_class["normal"])
    exclusive = {k: set(v) - normal for k, v in by_class.items() if k != "normal"}

    print()
    print("=== 對 normal 排他的訊號數 ===")
    for name in sorted(exclusive):
        example = sorted(exclusive[name])[:2]
        print("  %-22s %3d  %s" % (name, len(exclusive[name]),
                                   ", ".join(example) if example else "（無）"))

    names = sorted(exclusive)
    unseparable = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            only_a = exclusive[a] - exclusive[b]
            only_b = exclusive[b] - exclusive[a]
            if not (only_a and only_b):
                unseparable.append((a, b, len(only_a), len(only_b)))

    total = len(names) * (len(names) - 1) // 2
    print()
    print("=== 兩兩不可分：%d / %d ===" % (len(unseparable), total))
    for a, b, ua, ub in unseparable:
        print("  ⛔ %-22s ←→ %-22s  a獨有 %d  b獨有 %d" % (a, b, ua, ub))
    if not unseparable:
        print("  ✅ 全部兩兩可分")

    report = {
        "schema_version": "sros2-firewall-class-separability/v1",
        "security_mode": args.security_mode,
        "datasets": [str(d) for d in args.dataset],
        "override_scenarios": sorted(args.override_scenario),
        "sessions_per_class": taken,
        "sources_per_class": {k: sorted(v) for k, v in sources.items()},
        "exclusive_signal_counts": {k: len(v) for k, v in exclusive.items()},
        "unseparable_pairs": [
            {"a": a, "b": b, "only_a": ua, "only_b": ub}
            for a, b, ua, ub in unseparable
        ],
        "pair_count": total,
    }
    if args.output:
        if args.output.exists():
            print("\n⛔ 輸出已存在，拒絕覆寫：%s" % args.output)
            return 2
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        print("\n  報告：%s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
