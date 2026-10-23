#!/usr/bin/env python3
"""把 2026-08-30 那批的歸因報告重新產生成 schema v2。

## 為什麼要做

2026-09-25 的 `run_attribution_driven_block.py` 拒絕本專案擁有的每一份歸因
證據，而 89／91 是被**第 1 項**（schema 必須是 v2）擋下的。那批 79／80 的
跨主機證據產生於 2026-08-31 加上第四條判定（鏈路層綁定）**之前**。

C2C-051 用 `check_link_layer_binding.py` 回驗過那批、**80／80 零撤回**，
而每一場的 `link_layer_binding.json` 都還在磁碟上。缺的只是把那份證據餵回
報告產生器——**證據早就有了，只是沒有進到機器可讀的那條路**。

## 這一支不做什麼

- **不覆寫任何既有的 `crosscheck.json`。** 輸出寫成 `crosscheck_v2.json`。
  舊報告是「第四條加上去之前長什麼樣」的唯一實證，而 C2C-051 明寫過未動它。
- **不重新收證據。** 封包觀測與觀測者事件都直接用場次裡原本那兩份。
- **不放寬任何判定。** 呼叫的是既有的 `crosscheck_identity_attribution.py`，
  只是多給它 `--link-layer`。

## 這是一次獨立的交叉驗證

C2C-051 的回驗走的是 `check_link_layer_binding.py` 這支獨立工具；這一輪走的是
**報告產生器自己**的第四條判定。兩條路徑對同一批原始資料，結論應該一致。
不一致的話，那本身就是結果——所以這支工具會把兩者逐場比對並在最後印出來。

## 用法

    python3 工具腳本/regenerate_crosscheck_v2.py --batch ~/crosshost
    python3 工具腳本/regenerate_crosscheck_v2.py --batch ~/crosshost --apply
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "工具腳本" / "crosscheck_identity_attribution.py"

V1 = "sros2-firewall-identity-crosscheck/v1"
V2 = "sros2-firewall-identity-crosscheck/v2"

REQUIRED = ("rtps_identity_packets.jsonl", "observer_events.jsonl", "link_layer_binding.json")
OUTPUT_NAME = "crosscheck_v2.json"


def _read(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def regenerate(session: Path, *, apply: bool) -> dict:
    """回一筆逐場結果。`apply=False` 時只檢查輸入齊不齊,不寫任何檔案。"""
    row: dict = {"session": session.name}
    missing = [name for name in REQUIRED if not (session / name).is_file()]
    if missing:
        row["status"] = "missing_inputs"
        row["missing"] = missing
        return row

    old = _read(session / "crosscheck.json") or {}
    row["old_schema"] = old.get("schema_version")
    row["old_blockable"] = sorted(old.get("blockable_ips") or [])

    output = session / OUTPUT_NAME
    if output.exists():
        row["status"] = "already_present"
        new = _read(output) or {}
    elif not apply:
        row["status"] = "would_regenerate"
        return row
    else:
        result = subprocess.run(
            [
                sys.executable, str(TOOL),
                "--packet-observations", str(session / "rtps_identity_packets.jsonl"),
                "--observer-events", str(session / "observer_events.jsonl"),
                "--link-layer", str(session / "link_layer_binding.json"),
                "--output", str(output),
            ],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0 or not output.is_file():
            row["status"] = "failed"
            row["stderr"] = (result.stderr or "")[-300:]
            return row
        row["status"] = "regenerated"
        new = _read(output) or {}

    row["new_schema"] = new.get("schema_version")
    row["new_blockable"] = sorted(new.get("blockable_ips") or [])
    row["verified"] = bool(new.get("source_ip_attribution_verified"))
    # 這裡才是重點:同一批原始資料,兩條獨立路徑的結論一不一致。
    row["agrees_with_v1"] = row["new_blockable"] == row["old_blockable"]
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--apply", action="store_true",
                        help="真的產生檔案。預設只列出會做什麼。")
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args(argv)

    sessions = sorted(p for p in Path(args.batch).expanduser().iterdir() if p.is_dir())
    if not sessions:
        print(f"⛔ {args.batch} 底下沒有場次目錄", file=sys.stderr)
        return 2

    rows = [regenerate(s, apply=args.apply) for s in sessions]

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    print(f"=== {len(rows)} 場 ===")
    for status, count in sorted(counts.items()):
        print(f"  {status:<18} {count}")

    done = [r for r in rows if r.get("new_schema")]
    if done:
        v2 = sum(1 for r in done if r["new_schema"] == V2)
        verified = sum(1 for r in done if r["verified"])
        agree = sum(1 for r in done if r["agrees_with_v1"])
        print()
        print(f"  schema v2            : {v2}／{len(done)}")
        print(f"  attribution verified : {verified}／{len(done)}")
        print(f"  **與 v1 結論一致**   : {agree}／{len(done)}")
        disagreements = [r for r in done if not r["agrees_with_v1"]]
        if disagreements:
            print()
            print("  ⚠️ 不一致的場次（這本身就是結果，不要當成雜訊）：")
            for row in disagreements[:10]:
                print(f"    {row['session']}: v1={row['old_blockable']} "
                      f"v2={row['new_blockable']}")

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(
                {
                    "batch": str(args.batch),
                    "applied": bool(args.apply),
                    "counts": counts,
                    "sessions": rows,
                },
                ensure_ascii=False, indent=2, sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        print(f"\n報告：{args.report}")

    failed = counts.get("failed", 0) + counts.get("missing_inputs", 0)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
