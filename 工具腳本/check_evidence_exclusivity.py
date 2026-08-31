#!/usr/bin/env python3
"""擴充攻擊面之前的 gate：這個攻擊類別有沒有**專屬**的證據通道。

## 為什麼需要這道 gate

C2C-013 量到的規律：**識別率由證據排他性決定**。

| 類別 | 觸發的特徵 | test recall |
|---|---|---|
| `message_dos` | 含專屬的 `oversized_message_ratio` | **1.000** |
| `sensor_spoof` | 含專屬的 `hmac_failure_rate` | **1.000** |
| `parameter_tamper` | 只有 5 個通用特徵 | 0.429 |
| `replay` | **與 `parameter_tamper` 完全相同的 5 個** | 0.375 |

`parameter_tamper` 與 `replay` 認不出來，不是模型不好，是**模型手上沒有任何
資訊可以分開它們**。

2026-09-01 的盤點發現：policy 有 14 個空類別，其中 9 類的攻擊腳本已經寫好。
但**六支打的是已經修好的缺陷**（它們的 docstring 自己寫著「已修補」「回歸
測試」）。漏洞修好之後再跑，很可能完全沒有應用層訊號——那樣新增的類別會是
模型認不出來的，重演上表的失敗。

所以在排 campaign 之前，每支候選先跑 **1 場 smoke**，用這支判它有沒有資格。

## 判準

    通過 ⟺ 至少一個特徵「在候選場次非零」且「在 normal 基線恆零」

## 兩種失敗必須分開

這個專案被「兩種原因產生同一個觀測」咬過七次，所以這支**先確認攻擊真的執行
過**，再談有沒有訊號：

| 觀測 | 意義 |
|---|---|
| 攻擊沒執行（rc≠0、或根本沒有 attack_process） | **作廢**，不是「沒有專屬證據」 |
| 攻擊執行了、但沒有專屬特徵 | 拒絕：這個類別會變成另一個 `identity_abuse` |
| 攻擊執行了、有專屬特徵 | 通過 |

## 用法

    python3 工具腳本/check_evidence_exclusivity.py \\
        --candidate <候選 session 目錄> \\
        --baseline <一個或多個 normal_patrol session 目錄> \\
        --output <報告>.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "sros2-firewall-evidence-exclusivity/v1"


def _load_manifest(session: Path) -> dict:
    path = session / "manifest.json"
    if not path.is_file():
        raise SystemExit(f"⛔ 找不到 manifest：{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def attack_actually_ran(manifest: dict) -> tuple[bool, str]:
    """攻擊到底有沒有執行——先回答這個，再談訊號。

    `normal` 場次沒有攻擊行程，那是正常的；其餘類別若沒有 attack_process
    或 return_code 不是 0，這一場就沒有資格談「有沒有專屬證據」。
    """
    if manifest.get("attack_class") == "normal":
        return True, "normal 場次，無攻擊行程"
    result = manifest.get("result") or {}
    process = result.get("attack_process")
    if not isinstance(process, dict):
        return False, "manifest 裡沒有 attack_process——攻擊沒有執行"
    code = process.get("return_code")
    if code != 0:
        return False, f"攻擊行程 return_code={code}，不是 0"
    duration = process.get("duration_sec")
    if not isinstance(duration, (int, float)) or duration < 1.0:
        return False, f"攻擊行程只跑了 {duration} 秒——太短，視為沒有執行"
    return True, f"攻擊執行 {duration:.1f} 秒，return_code=0"


def telemetry_signals(session: Path) -> Counter:
    """一場 session 裡每種遙測事件的出現次數。

    用事件層而不是特徵層，因為 smoke 階段還沒有抽特徵；而且事件層更直接——
    「這個攻擊有沒有讓系統產生它專屬的事件」。
    """
    path = session / "telemetry_events.jsonl"
    counts: Counter = Counter()
    if not path.is_file():
        return counts
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            kind = event.get("event_type") or event.get("event")
            if not kind:
                continue
            counts[str(kind)] += 1
            # 判別性的欄位在 `details` 裡，不是頂層。第一版讀頂層，於是
            # oversized_scan 的專屬訊號完全看不到——實測那個訊號是
            # message_validation 的 `oversized_count>0`（候選 56、基線 0）。
            details = event.get("details")
            if not isinstance(details, dict):
                continue
            for field, value in details.items():
                if isinstance(value, bool):
                    counts[f"{kind}.{field}={value}"] += 1
                elif isinstance(value, (int, float)):
                    # 數值欄位看的是**零與非零**，不是值本身：`count=7` 與
                    # `count=8` 是同一件事，而「計數器從恆零變成有值」才是
                    # 「這個攻擊讓系統產生了它專屬的東西」。
                    counts[f"{kind}.{field}" + (">0" if value else "=0")] += 1
                elif isinstance(value, str) and value:
                    counts[f"{kind}.{field}={value}"] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True,
                        help="候選攻擊的 session 目錄")
    parser.add_argument("--baseline", type=Path, nargs="+", required=True,
                        help="一個或多個 normal_patrol session 目錄")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--min-count", type=int, default=3,
                        help="專屬事件至少要出現幾次才算數（防單筆雜訊）")
    args = parser.parse_args()

    manifest = _load_manifest(args.candidate)
    ran, why = attack_actually_ran(manifest)

    candidate = telemetry_signals(args.candidate)
    baseline: Counter = Counter()
    for path in args.baseline:
        baseline |= telemetry_signals(path)

    exclusive = {
        name: count for name, count in candidate.items()
        if count >= args.min_count and baseline.get(name, 0) == 0
    }

    if not ran:
        verdict = "void_attack_did_not_run"
    elif exclusive:
        verdict = "pass"
    else:
        verdict = "reject_no_exclusive_evidence"

    report = {
        "schema_version": SCHEMA,
        "candidate": str(args.candidate),
        "scenario_id": manifest.get("scenario_id"),
        "attack_class": manifest.get("attack_class"),
        "security_mode": manifest.get("security_mode"),
        "baseline_sessions": [str(p) for p in args.baseline],
        "attack_ran": ran,
        "attack_evidence": why,
        "min_count": args.min_count,
        "candidate_event_kinds": len(candidate),
        "baseline_event_kinds": len(baseline),
        "exclusive_signals": dict(sorted(exclusive.items())),
        "verdict": verdict,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )

    print(f"=== 證據排他性 gate：{manifest.get('scenario_id')} ===")
    print(f"  攻擊執行     : {'是' if ran else '否'}——{why}")
    print(f"  候選事件種類 : {len(candidate)}")
    print(f"  基線事件種類 : {len(baseline)}")
    print()
    if verdict == "void_attack_did_not_run":
        print("  ⛔ **本場作廢**：攻擊沒有執行。")
        print("     這**不是**「沒有專屬證據」——兩者在資料上長得一樣，")
        print("     但意義完全不同。先修好執行，再談有沒有訊號。")
    elif exclusive:
        print(f"  ✅ **通過**：{len(exclusive)} 個專屬訊號（基線恆零）")
        for name, count in sorted(exclusive.items(),
                                  key=lambda kv: -kv[1])[:10]:
            print(f"       {name:<48}{count:>6}")
    else:
        print("  ❌ **拒絕**：攻擊執行了，但沒有任何專屬訊號。")
        print("     這個類別進了資料集會是模型認不出來的——")
        print("     它只會拖低 balanced accuracy，而且看起來像「類別太多」。")
        print("     若這支打的是已經修好的缺陷，這就是預期結果。")
    if args.output:
        print(f"\n  報告：{args.output}")

    return 0 if verdict == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
