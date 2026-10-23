#!/usr/bin/env python3
"""從一場已完成的 session，逐 stage 推導 local outcome 語意觀測。

官方 campaign 路徑（local_outcome_campaign）要求剛好 50 個 boundary，也就是九項
25 個 stage 全部到齊；少一個就整批中止，而且 observations 檔是 immutable 的，事
後補不了。目前有四項在 Enforce＋外部威脅模型下取不到證據（攻擊訊息根本送不到
驗證器那一層），所以改走單階段 CLI，把真的有證據的項目逐一入帳，其餘照實留白。

這支不做任何判定：facts 由 local_outcome_probe 依既有規則重算，pass/fail 由
local_outcomes 依既有門檻決定。這裡只負責挑出窗的邊界並依序呼叫。
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

LIVE_ACK = "I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument(
        "--check",
        action="append",
        required=True,
        help="要推導的 check_id；可重複。該 check 的所有 stage 都必須有證據。",
    )
    args = parser.parse_args()

    root = args.evidence_root
    telemetry = root / "telemetry_events.jsonl"
    wanted = set(args.check)

    opened: dict[tuple[str, str], int] = {}
    windows: list[tuple[str, str, int, int]] = []
    with telemetry.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event_type") != "outcome_marker":
                continue
            details = event["details"]
            key = (details["check_id"], details["stage"])
            if key[0] not in wanted:
                continue
            if details["boundary"] == "start":
                opened[key] = event["monotonic_ns"]
            elif key in opened:
                windows.append((key[0], key[1], opened.pop(key), event["monotonic_ns"]))

    print(f"要推導 {len(windows)} 個窗")
    failures = 0
    for index, (check_id, stage, start, end) in enumerate(windows, 1):
        artifact = root / f"{index:02d}_{check_id}_{stage}.semantic.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "firewall_lab.local_outcome_probe",
                "--evidence-root", str(root),
                "--telemetry", str(telemetry),
                "--artifact", str(artifact),
                "--observations", str(root / "observations.jsonl"),
                "--session-id", args.session_id,
                "--check-id", check_id,
                "--stage", stage,
                "--start-monotonic-ns", str(start),
                "--end-monotonic-ns", str(end),
                "--live-loopback-ack", LIVE_ACK,
            ],
            capture_output=True,
            text=True,
        )
        status = "ok" if result.returncode == 0 else "FAILED"
        print(f"  {check_id}/{stage}: {status}")
        if result.returncode != 0:
            failures += 1
            print("    " + result.stderr.strip().splitlines()[-1][:200])
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
