#!/usr/bin/env python3
"""等待某個 telemetry 事件出現，最多等到逾時為止。

固定 sleep 對這批證據不管用：guard_state、graph_state 與 detector_state 都只在
狀態「轉換」時發一次，D5 又要 10 秒才 fire。前兩次排練有四個窗是空的，原因都
是同一個——窗開在轉換的前面或後面，不是證據不存在。

這支只讀 collector 已經寫下的 JSONL，不送出任何東西，也不改變任何狀態；它只
決定「什麼時候關窗」。找不到就以非零離開，讓呼叫端照實記錄成未取得。

用法：
  wait_for_telemetry.py --telemetry <jsonl> --event-type guard_state \
      --source velocity_guard_node --detail state=locked \
      --since-line 1234 --timeout-sec 20
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def matches(
    event: dict,
    event_type: str,
    source: str | None,
    details: list[str],
    any_nonzero: list[str] | None = None,
) -> bool:
    if event.get("event_type") != event_type:
        return False
    if source and event.get("source") != source:
        return False
    payload = event.get("details", {})
    for pair in details:
        key, _, value = pair.partition("=")
        if str(payload.get(key)) != value:
            return False
    # 至少一個指名的欄位非零。velocity_guard_recovered 的 recovery 需要
    # 「未封鎖**而且**輸出非零」，而 linear_x 與 angular_z 是 OR 關係——
    # 機器人可以只轉不進。用等值比對表達不了這件事，所以單獨一個述詞。
    if any_nonzero:
        found = False
        for key in any_nonzero:
            raw = payload.get(key)
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                continue
            if abs(float(raw)) > 1e-6:
                found = True
                break
        if not found:
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telemetry", type=Path, required=True)
    parser.add_argument("--event-type", required=True)
    parser.add_argument("--source", default=None)
    parser.add_argument("--detail", action="append", default=[])
    parser.add_argument("--detail-any-nonzero", action="append", default=[],
                        help="至少一個指名欄位非零（OR）")
    parser.add_argument("--since-line", type=int, default=0)
    parser.add_argument("--timeout-sec", type=float, default=20.0)
    parser.add_argument("--poll-sec", type=float, default=0.4)
    args = parser.parse_args()

    deadline = time.monotonic() + args.timeout_sec
    # 只讀新增的部分。原本每次輪詢重讀整個檔案，而 telemetry 一個窗就可能有
    # 五千筆以上，單次掃描要十幾秒；逾時只在掃完後才檢查，於是 22 秒的等待做出
    # 137 秒的窗，整個窗因為超過 60 秒安全上限而作廢。
    offset = 0
    index = 0
    while True:
        try:
            with args.telemetry.open("rb") as handle:
                handle.seek(offset)
                for raw in handle:
                    if not raw.endswith(b"\n"):
                        # 寫到一半的行：不要前進 offset，下一輪重讀。
                        break
                    offset += len(raw)
                    current = index
                    index += 1
                    if current < args.since_line:
                        continue
                    try:
                        event = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if matches(event, args.event_type, args.source,
                               args.detail, args.detail_any_nonzero):
                        print(f"found line={current}")
                        return 0
                    if time.monotonic() >= deadline:
                        print("not found", file=sys.stderr)
                        return 1
        except FileNotFoundError:
            pass
        if time.monotonic() >= deadline:
            print("not found", file=sys.stderr)
            return 1
        time.sleep(args.poll_sec)


if __name__ == "__main__":
    raise SystemExit(main())
