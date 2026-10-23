#!/usr/bin/env python3
"""檢核 300 場重跑的三個可否證預測。

重跑的價值不在「再收點資料」，而在它是一個**有明確假設、可被推翻的實驗**。
兩個 bug 已修，因此在重跑之前就能寫下預測；跑完直接對照，成立或推翻都算結果。

| # | 預測 | 依據 | 若被推翻代表 |
|---|---|---|---|
| 1 | `parameter_tamper`／`parameter_flood` 的 Permissive 場次 `parameter_call` > 0 | hook 已從 rcl 拒絕之下移到服務層 | 修正沒有生效，或攻擊沒打到節點 |
| 2 | `heartbeat_replay` 的 Permissive 場次出現 `nonce_reuse_or_capacity` | N1 的 QoS 已改為 RELIABLE＋TRANSIENT_LOCAL | 重放仍未送達，或被時間戳先擋 |
| 3 | `identity_abuse`（未重跑）仍無 `sros2_deny` | 本技術棧無法啟用 DDS Security audit log | 該結論需要重新檢視 |

第 3 項是**對照組**：它沒有被修，所以應該維持不變。若它也「改善」了，那代表
變的是別的東西，前兩項的因果就不成立——這是防止把環境漂移誤讀成修正生效。

用法：
    python3 工具腳本/verify_rerun_predictions.py --dataset <重跑資料集根目錄>
    # 可加 --baseline <原始 dataset_live> 做前後對照
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

SCENARIO_OF_INTEREST = ("parameter_tamper", "parameter_flood", "heartbeat_replay")


def _sessions(root: Path):
    """回傳 (session_dir, manifest) — 只看真的有 manifest 的目錄。"""
    for entry in sorted(root.iterdir()):
        manifest = entry / "manifest.json"
        if entry.is_dir() and manifest.is_file():
            try:
                yield entry, json.loads(manifest.read_text(encoding="utf-8"))
            except ValueError:
                continue


def _scenario(manifest: dict) -> str:
    for key in ("scenario_id", "scenario"):
        value = manifest.get(key)
        if isinstance(value, str):
            return value
    return str(manifest.get("attack_class", "unknown"))


def _mode(manifest: dict) -> str:
    for key in ("security_mode", "mode"):
        value = manifest.get(key)
        if isinstance(value, str):
            return value
    return "unknown"


def _telemetry_counts(session: Path) -> dict[str, int]:
    """數這一場的關鍵事件。只讀既有 JSONL，不重算任何判定。"""
    counts: collections.Counter[str] = collections.Counter()
    path = session / "telemetry_events.jsonl"
    if not path.is_file():
        return counts
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            kind = event.get("event_type")
            details = event.get("details", {})
            if kind == "parameter_call":
                counts["parameter_call"] += int(details.get("count", 0) or 0)
            elif kind == "hmac_result":
                counts[f"hmac:{details.get('reason')}"] += 1
            elif kind == "sros2_deny":
                counts["sros2_deny"] += int(details.get("count", 0) or 0)
    return counts


def _summarise(root: Path) -> dict[tuple[str, str], collections.Counter]:
    grouped: dict[tuple[str, str], collections.Counter] = {}
    for session, manifest in _sessions(root):
        key = (_scenario(manifest), _mode(manifest))
        bucket = grouped.setdefault(key, collections.Counter())
        bucket.update(_telemetry_counts(session))
        bucket["sessions"] += 1
    return grouped


def _verdict(passed: bool) -> str:
    return "✅ 成立" if passed else "❌ 被推翻"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=None)
    args = parser.parse_args()

    if not args.dataset.is_dir():
        print(f"找不到資料集：{args.dataset}", file=sys.stderr)
        return 2

    grouped = _summarise(args.dataset)
    if not grouped:
        print("資料集裡沒有任何含 manifest 的場次", file=sys.stderr)
        return 2

    print(f"重跑資料集：{args.dataset}")
    for (scenario, mode), counts in sorted(grouped.items()):
        if scenario not in SCENARIO_OF_INTEREST:
            continue
        print(
            f"  {scenario:18s} {mode:11s} sessions={counts['sessions']:3d}"
            f"  parameter_call={counts['parameter_call']:6d}"
            f"  nonce={counts['hmac:nonce_reuse_or_capacity']:5d}"
            f"  ts_violation={counts['hmac:timestamp_violation']:5d}"
        )

    print("\n預測檢核")
    failures = 0

    # 預測 1：parameter 兩類的 Permissive 場次應有 parameter_call
    param_calls = sum(
        counts["parameter_call"]
        for (scenario, mode), counts in grouped.items()
        if scenario in ("parameter_tamper", "parameter_flood") and mode == "permissive"
    )
    ok1 = param_calls > 0
    failures += not ok1
    print(f"  1. parameter_call > 0（Permissive）: {param_calls}  {_verdict(ok1)}")

    # 預測 2：heartbeat_replay 的 Permissive 場次應出現 nonce 重用
    nonce = sum(
        counts["hmac:nonce_reuse_or_capacity"]
        for (scenario, mode), counts in grouped.items()
        if scenario == "heartbeat_replay" and mode == "permissive"
    )
    ok2 = nonce > 0
    failures += not ok2
    print(f"  2. nonce_reuse_or_capacity > 0（Permissive）: {nonce}  {_verdict(ok2)}")

    # 預測 3（對照組）：sros2_deny 應維持為 0，因為它沒有被修
    denies = sum(counts["sros2_deny"] for counts in grouped.values())
    ok3 = denies == 0
    failures += not ok3
    print(f"  3. sros2_deny 維持 0（對照組）: {denies}  {_verdict(ok3)}")
    if not ok3:
        print("     ⚠️ 對照組變動代表環境有其他改變，前兩項的因果不能直接歸給修正。")

    if args.baseline and args.baseline.is_dir():
        print(f"\n對照原始資料集：{args.baseline}")
        base = _summarise(args.baseline)
        for scenario in SCENARIO_OF_INTEREST:
            for mode in ("permissive", "enforce"):
                before = base.get((scenario, mode), collections.Counter())
                after = grouped.get((scenario, mode), collections.Counter())
                if not before["sessions"] and not after["sessions"]:
                    continue
                print(
                    f"  {scenario:18s} {mode:11s}"
                    f"  parameter_call {before['parameter_call']:6d} → {after['parameter_call']:6d}"
                    f"   nonce {before['hmac:nonce_reuse_or_capacity']:5d} → "
                    f"{after['hmac:nonce_reuse_or_capacity']:5d}"
                )

    print(f"\n三項預測：{3 - failures} 成立 / {failures} 被推翻")
    # 預測被推翻不是執行失敗——它一樣是結果，所以離開碼仍為 0。
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
