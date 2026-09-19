#!/usr/bin/env python3
"""產生「300 場失效場次」的重跑計畫。

為什麼只重跑 300 場而不是全部 1,100 場：正式資料集裡有三個 scenario 的**攻擊
專屬證據是空的**，成因是兩個已修好的 bug，其餘 800 場不受影響。

| scenario | 場次 | 失效原因 |
|---|---:|---|
| `heartbeat_replay` | 100 | N1 是 BEST_EFFORT publisher 對 RELIABLE subscriber，DDS 直接不投遞 |
| `parameter_tamper` | 100 | `parameter_call` hook 掛在 rcl read-only 拒絕之下 |
| `parameter_flood` | 100 | `get_parameters` 當時完全沒有 hook |

這些場次對**二元偵測**仍然有效（流量層訊號是真的），但對**攻擊識別**等於沒有
內容——而 `replay` 與 `parameter_tamper` 正好就是識別率最差的兩類。

計畫刻意沿用原本的 `seed`、`scenario_id`、`security_mode` 與 `expected_action`，
所以這是**受控比較**：唯一的變因是那兩個修正，不是重新抽樣。

用法：
    python3 工具腳本/build_rerun_plan.py --output firewall_lab/campaign_rerun_300.json
    # 之後（需要 Jesse 授權 live）：
    python3 -m firewall_lab.campaign run --plan <output> --security-mode permissive ...
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.campaign import load_campaign_plan  # noqa: E402

# 三個 scenario 對應到兩個已修的 bug；其餘 scenario 的證據是完好的。
AFFECTED_SCENARIOS = {
    "heartbeat_replay": "N1 QoS 不相容，重放從未送達（BEST_EFFORT → RELIABLE）",
    "parameter_tamper": "parameter_call hook 掛在 rcl read-only 拒絕之下",
    "parameter_flood": "get_parameters 當時沒有任何 hook",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=Path("firewall_lab/campaign_1100.json")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("firewall_lab/campaign_rerun_300.json")
    )
    args = parser.parse_args()

    source = json.loads(args.source.read_text(encoding="utf-8"))
    selected = [
        entry
        for entry in source["entries"]
        if entry["scenario_id"] in AFFECTED_SCENARIOS
    ]
    if not selected:
        print("找不到任何受影響的場次", file=sys.stderr)
        return 1

    stamp = datetime.now(timezone.utc)
    entries = []
    for index, entry in enumerate(selected, 1):
        fresh = dict(entry)
        # 重設執行狀態；execute_campaign 只跑 pending。
        fresh["entry_id"] = f"rerun_{index:05d}"
        fresh["session_id"] = None
        fresh["status"] = "pending"
        fresh["error"] = None
        entries.append(fresh)

    # requested_counts 的形狀由驗證器決定：每個 scenario 一個
    # {"total", "permissive", "enforce"}，而且必須與 entries 逐項相符。
    counts: dict[str, dict[str, int]] = {}
    for entry in entries:
        per = counts.setdefault(
            entry["scenario_id"], {"total": 0, "permissive": 0, "enforce": 0}
        )
        per["total"] += 1
        per[entry["security_mode"]] += 1

    plan = {
        "schema_version": source["schema_version"],
        # campaign_id 必須符合 ^[a-z][a-z0-9_]{0,63}$，不能有大寫的 T／Z。
        "campaign_id": f"rerun300_{stamp.strftime('%Y%m%d_%H%M%S')}",
        "catalog_sha256": source["catalog_sha256"],
        "created_utc": stamp.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "experiment_mode": source["experiment_mode"],
        "requested_counts": counts,
        "seed": source["seed"],
        "entries": entries,
    }
    args.output.write_text(
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # 用正式載入器驗證，而不是自己相信自己寫出來的格式。
    loaded = load_campaign_plan(args.output)
    modes: dict[str, int] = {}
    for entry in loaded["entries"]:
        modes[entry["security_mode"]] = modes.get(entry["security_mode"], 0) + 1

    print(f"寫出 {args.output}")
    print(f"  campaign_id : {plan['campaign_id']}")
    print(f"  總場次      : {len(entries)}")
    for scenario, per in sorted(counts.items()):
        print(
            f"    {scenario:20s} {per['total']:4d}"
            f"  (P {per['permissive']} / E {per['enforce']})"
            f"   （{AFFECTED_SCENARIOS[scenario]}）"
        )
    for mode, count in sorted(modes.items()):
        print(f"  {mode:12s}: {count}")
    print("  正式載入器驗證通過")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
