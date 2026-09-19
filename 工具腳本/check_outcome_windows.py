#!/usr/bin/env python3
"""逐 window 檢查 local outcome 證據，不會因為單一 window 缺證據就全滅。

`derive_marked_campaign` 是一個 list comprehension：任何一個 window 丟出
SchemaError，整批 campaign 就中止，而且 observations 檔是 immutable 的，事後
無法補救。所以正式跑之前先用這支對排練資料做乾式檢查，確認哪些 stage 真的有
證據可以站住，再決定正式那一輪要標記哪幾個 check。

這支只讀不寫，也不產生任何 artifact；它算出來的 facts 不是判定結果，判定一律
由 local_outcomes 依既有規則重算。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.local_outcome_probe import (  # noqa: E402
    _load_telemetry,
    _matching,
    _window_events,
    derive_facts,
)


def paired_windows(events):
    """Pair start/end markers without requiring the full 25-stage campaign.

    ``discover_marked_windows`` demands exactly 50 boundaries because a real
    campaign has to cover all nine outcomes.  This checker deliberately does
    not: its whole purpose is to find out which stages have evidence before a
    campaign is attempted, so it pairs whatever markers are present and reports
    the rest as absent.
    """
    markers = _matching(events, "outcome_marker", source="local_outcome_controller")
    open_windows: dict[tuple[str, str], int] = {}
    windows: list[tuple[str, str, int, int]] = []
    for event in markers:
        key = (event["details"]["check_id"], event["details"]["stage"])
        if event["details"]["boundary"] == "start":
            open_windows[key] = event["monotonic_ns"]
        elif key in open_windows:
            windows.append((key[0], key[1], open_windows.pop(key), event["monotonic_ns"]))
    return windows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telemetry", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    args = parser.parse_args()

    events = _load_telemetry(args.telemetry, expected_session_id=args.session_id)
    windows = paired_windows(events)
    print(f"marked windows: {len(windows)}\n")

    good: list[str] = []
    bad: list[str] = []
    for index, (check_id, stage, start, end) in enumerate(windows, 1):
        label = f"{check_id}/{stage}"
        try:
            window = _window_events(
                events, start_monotonic_ns=start, end_monotonic_ns=end
            )
            facts = derive_facts(check_id, stage, window)
        except Exception as exc:  # noqa: BLE001 - report, never abort
            bad.append(label)
            span = round((end - start) / 1e9, 1)
            print(f"{index:02d} ✗ {label}")
            print(f"      span={span}s  {type(exc).__name__}: {exc}")
            continue
        good.append(label)
        print(f"{index:02d} ✓ {label}")
        print(f"      events={len(window)}  {json.dumps(facts, ensure_ascii=False, sort_keys=True)}")

    print(f"\n有證據 {len(good)} / 缺證據 {len(bad)}")
    if bad:
        print("缺證據：" + ", ".join(bad))
    checks = sorted({label.split("/")[0] for label in good})
    complete = sorted(
        check
        for check in checks
        if not any(label.startswith(f"{check}/") for label in bad)
    )
    print("完整可標記的 check：" + (" ".join(complete) if complete else "（無）"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
