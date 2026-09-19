#!/usr/bin/env python3
"""檢查一個特徵的「來源覆蓋」是否跨類別均等，再決定它能不能進訓練。

## 為什麼需要這道檢查

2026-08-30 用 sidecar 觀測者替 `sros_auth_fail_rate` 補上來源，但只重跑了
`identity_abuse` 與 `normal`。如果直接把新列併進舊的 1,100 場：

| 類別 | sros_auth_fail_rate | 原因 |
|---|---|---|
| identity_abuse（新） | 非零 | 有觀測者 |
| replay、message_dos…（舊） | 全零 | **沒有觀測者** |

模型會學到「這個特徵非零 → identity_abuse」，而那是**哪些場次有觀測者**的
假象，不是攻擊的性質。識別率會漂亮地跳升，數字卻沒有意義。

8/21 的 300 場重跑沒有這個問題，因為 `parameter_call_rate` 與 `nonce_reuse`
本來就是 scenario 專屬的——別的 scenario 就算跑了也不會產生那些事件。認證
拒絕不同：其他攻擊類別在有觀測者時會不會也產生，**沒有人測過**。

所以這支的判準是：**一個特徵只有在「所有類別都有機會產生它」時，才可以進訓練。**
覆蓋不均等時它會擋下來，並說明缺哪些類別。

## 用法

    python3 工具腳本/check_channel_coverage.py \\
        --features <特徵表>.csv --feature sros_auth_fail_rate
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def coverage_by_label(
    rows: list[dict[str, str]], feature: str
) -> dict[str, dict[str, float]]:
    """逐 label 統計：多少視窗、多少非零、多少個 session 出現過非零。"""
    windows: dict[str, int] = defaultdict(int)
    nonzero: dict[str, int] = defaultdict(int)
    sessions: dict[str, set[str]] = defaultdict(set)
    sessions_nonzero: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        label = row.get("label", "?")
        session = row.get("session_id", "?")
        windows[label] += 1
        sessions[label].add(session)
        try:
            value = float(row.get(feature, "0") or 0)
        except ValueError:
            value = 0.0
        if value > 0:
            nonzero[label] += 1
            sessions_nonzero[label].add(session)
    return {
        label: {
            "windows": windows[label],
            "nonzero_windows": nonzero[label],
            "sessions": len(sessions[label]),
            "sessions_with_signal": len(sessions_nonzero[label]),
        }
        for label in sorted(windows)
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--feature", required=True)
    args = parser.parse_args()

    with args.features.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or args.feature not in reader.fieldnames:
            print(f"⛔ 特徵表沒有 {args.feature} 這一欄")
            return 1
        rows = list(reader)

    stats = coverage_by_label(rows, args.feature)
    print(f"  特徵：{args.feature}")
    print()
    print(f"  {'label':<20}{'視窗':>8}{'非零視窗':>10}{'場次':>8}{'有訊號的場次':>14}")
    for label, s in stats.items():
        print(f"  {label:<20}{s['windows']:>8}{s['nonzero_windows']:>10}"
              f"{s['sessions']:>8}{s['sessions_with_signal']:>14}")
    print()

    attacks = {k: v for k, v in stats.items() if k != "normal"}
    if len(attacks) < 2:
        print("  ⚠️ 只有一個攻擊類別，覆蓋均等性無從判斷。")
        print("     這批只能做「該類別 vs normal」的二類比較，**不可**用來")
        print("     宣稱多類識別率的改變。")
        return 2

    silent = [k for k, v in attacks.items() if v["sessions_with_signal"] == 0]
    if silent:
        print(f"  ⛔ 這些攻擊類別完全沒有訊號：{'、'.join(silent)}")
        print("     如果它們只是**沒有在有觀測者的情況下跑過**，那麼把這個特徵")
        print("     餵進訓練，模型學到的會是「哪些場次有觀測者」而不是攻擊性質。")
        print("     要嘛全部類別都用同一組來源重跑，要嘛這個特徵不進訓練。")
        return 1

    print("  ✅ 每個攻擊類別都有機會產生這個特徵，覆蓋均等。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
