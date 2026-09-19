#!/usr/bin/env python3
"""比較「有觀測者」與「無觀測者」兩臂的遙測組成。

判準不是「數字要一模一樣」——同一個 stack 兩次啟動本來就會有差異（機器人位置、
偵測器抖動）。要找的是**系統性**差異：某一類事件只在有觀測者時出現，或出現率
差一個數量級。

特別盯這幾類，因為它們正是「有東西加入 graph」會產生的：

| 事件 | 為什麼盯它 |
|---|---|
| `unknown_node` | monitor 把觀測者判成未知節點就會發這個 |
| `participant_change` | graph 成員變動 |
| `authenticated_action` / `guard_state` | 警報導致的緊急停止與守衛鎖定 |
| `detector_state` | 偵測器被誘發 |

任何一項只出現在 observer 臂，就代表觀測者會擾動被防禦的系統，**不可以直接
接進 campaign**——那會讓整批資料帶上一個與攻擊無關的訊號。
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

# 這幾類是「有東西加入 ROS graph」的直接後果，最可能被觀測者觸發。
WATCHED = (
    "unknown_node",
    "participant_change",
    "log_reject",
    "guard_state",
    "detector_state",
)

# 2026-08-30 校準：第一輪的觀測者因為缺環境變數而立刻退出，所以那一對其實是
# **兩個完全相同的對照組**。它們的 detector_state 是 10 對 4——也就是說，小計數
# 事件在兩次相同執行之間本來就會差 2 倍以上。原本的 2 倍門檻因此把純雜訊判成
# 擾動。意外拿到的 null-vs-null 校準，比我憑感覺設的門檻可靠。
MIN_COUNT_FOR_RATIO = 20   # 低於這個數的事件，比值沒有意義
MIN_COUNT_FOR_PRESENCE = 3  # 只在一臂出現，也要夠多次才算訊號
MIN_PAIRS_FOR_VERDICT = 2   # 一對不足以下結論


def load_arm(root: Path, arm: str) -> list[Counter]:
    runs = []
    for directory in sorted(root.glob(f"{arm}_*")):
        path = directory / "telemetry_events.jsonl"
        if not path.exists():
            continue
        counts: Counter = Counter()
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            counts[event.get("event_type", "?")] += 1
            if event.get("event_type") == "authenticated_action":
                counts["_action_" + str(event.get("details", {}).get("action"))] += 1
        runs.append(counts)
    return runs


def summarise(runs: list[Counter]) -> dict[str, float]:
    """逐事件取**中位數**，不取平均。

    2026-08-30 實測：三個對照場的 guard_input 是 3571 / 425 / 426。第一場是批次
    的第一次啟動，明顯是離群值，但平均 1474 讓比較器報「差 0.3 倍」，而中位數
    426 對 442 只差 3.6%。一個離群值就足以讓平均值編出一個不存在的擾動。
    """
    if not runs:
        return {}
    keys = set().union(*runs)
    summary = {}
    for key in keys:
        values = sorted(r.get(key, 0) for r in runs)
        middle = len(values) // 2
        summary[key] = (
            float(values[middle])
            if len(values) % 2
            else (values[middle - 1] + values[middle]) / 2
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()

    control = load_arm(args.root, "control")
    observer = load_arm(args.root, "observer")
    if not control or not observer:
        print(f"⛔ 兩臂都要有資料（control={len(control)} observer={len(observer)}）")
        return 1

    a, b = summarise(control), summarise(observer)
    print(f"  對數：control {len(control)} / observer {len(observer)}")
    print()
    header = "事件類型"
    print(f"  {header:<34}{'中位數(無)':>10}{'中位數(有)':>10}   判讀")
    verdicts = []
    for key in sorted(set(a) | set(b)):
        left, right = a.get(key, 0.0), b.get(key, 0.0)
        note = ""
        # 只在一臂出現是最強的訊號，但單一事件可能只是抖動。
        if left == 0 and right >= MIN_COUNT_FOR_PRESENCE:
            note = "⚠️ 只在有觀測者時出現"
            verdicts.append((key, "observer_only"))
        elif right == 0 and left >= MIN_COUNT_FOR_PRESENCE:
            note = "只在無觀測者時出現"
            verdicts.append((key, "control_only"))
        elif min(left, right) >= MIN_COUNT_FOR_RATIO and (
            right / left > 2 or right / left < 0.5
        ):
            note = f"⚠️ 差 {right / left:.1f} 倍"
            verdicts.append((key, "ratio"))
        elif left or right:
            note = "（計數太小，不判讀）" if min(left, right) < MIN_COUNT_FOR_RATIO else ""
        flag = "  " if key not in WATCHED else "* "
        print(f"  {flag}{key:<32}{left:>10.1f}{right:>10.1f}   {note}")

    print()
    pairs = min(len(control), len(observer))
    if pairs < MIN_PAIRS_FOR_VERDICT:
        print(f"  ⚠️ 只有 {pairs} 對，不下結論。")
        print(f"     小計數事件在兩次相同執行之間本來就會差 2 倍以上（2026-08-30")
        print(f"     實測 detector_state 10 對 4，而那兩臂其實完全相同）。")
        print(f"     至少要 {MIN_PAIRS_FOR_VERDICT} 對才判讀。")
        return 2

    watched_hits = [k for k, _ in verdicts if k in WATCHED]
    if watched_hits:
        print("  ⛔ 觀測者會擾動被防禦的系統：" + "、".join(watched_hits))
        print("     **不要**直接接進 campaign——那會讓整批資料帶上一個與攻擊")
        print("     無關的訊號。改用被動封包擷取，或先讓 monitor 認得觀測者。")
        return 1
    if verdicts:
        print("  ⚠️ 有差異，但不在關鍵事件上：" + "、".join(k for k, _ in verdicts))
        print("     可能是 stack 兩次啟動的自然抖動。加大對數再確認。")
        return 0
    print("  ✅ 兩臂沒有系統性差異——觀測者未擾動被防禦的系統。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
