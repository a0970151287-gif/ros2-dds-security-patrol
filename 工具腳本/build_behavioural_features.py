#!/usr/bin/env python3
"""從被「停放」的遙測事件建行為特徵，並分成兩類測試它們的泛化。

## 為什麼

2026-09-04 量到：現有 26 個活特徵是為「擋外人」設計的，對持證內鬼只剩 0.6010，
而且那還是拿掉兩個盲點特徵之後。同一天也量到，資料裡**最強的內鬼訊號完全沒有
被特徵化**：

| event | normal | outsider | hmac_forgery | confused_deputy |
|---|---:|---:|---:|---:|
| `guard_input` | 1295 | 1270 | **7170** | **18160** |

`features.py` 把 `guard_input` 列在 `NON_FEATURE_TELEMETRY_EVENTS`，註解寫著
「until their feature semantics are agreed; step 1 of the contract alignment
moves them out」——**那一步從來沒做**。

## 兩類特徵，以及為什麼要分開

今天證明了「以防禦的反應為特徵」會對繞過防禦的攻擊製造盲點。所以新特徵
一律先分類，再分開測：

| 類別 | 意思 | 例子 |
|---|---|---|
| `behavioural` | **攻擊者自己做了什麼** | 送了幾個速度命令、命令的形狀 |
| `defence_reaction` | **防禦反應了什麼** | 守衛擋掉幾個、參數被否決幾次 |

**可否證的預測**：behavioural 會跨內鬼類型泛化，defence_reaction 只在觸發它
的那一種上有用。用 leave-one-insider-out 直接檢驗——只有兩種內鬼，所以這是
n=2 的檢驗，弱，但方向可看。

## 這支不改任何既有東西

`features.py` 一行未改。新特徵算成一張獨立的表，用 `session_id` ＋ `window`
接回既有特徵表。要不要進正式契約是另一個決定。

## 用法

    python3 工具腳本/build_behavioural_features.py \\
        --dataset ~/refresh_20260902T111358Z/enforce/dataset \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --output ~/behavioural_enforce.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.session_reader import SessionReadError, iter_sessions  # noqa: E402

WINDOW_SEC = 8.0

# 攻擊者自己的行為。這些**不看防禦有沒有反應**。
BEHAVIOURAL = (
    "guard_input_rate",
    "guard_input_nonzero_ratio",
    "guard_input_angular_abs_mean",
    "guard_input_linear_abs_mean",
    "authenticated_action_rate",
)
# 防禦的反應。刻意一起建，好證明它們的泛化比較差。
DEFENCE_REACTION = (
    "guard_block_ratio",
    "guard_lock_rate",
    "parameter_veto_rate",
)
ALL_FEATURES = BEHAVIOURAL + DEFENCE_REACTION


class BuildError(RuntimeError):
    """建不出來就中止。安靜補零會讓「沒有訊號」與「沒有讀到」長得一樣。"""


def window_index(ts_ns: int, start_unix: float) -> int:
    return int((ts_ns / 1e9 - start_unix) // WINDOW_SEC)


def session_windows(features_path: Path) -> dict[str, dict[int, float]]:
    """從既有特徵表拿每一場的視窗起點——不要自己重新定義視窗。"""
    out: dict[str, dict[int, float]] = defaultdict(dict)
    with features_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                out[row["session_id"]][int(row["window"])] = float(
                    row["window_start_unix"])
            except (KeyError, TypeError, ValueError) as exc:
                raise BuildError(f"feature row lacks window geometry: {exc}")
    if not out:
        raise BuildError(f"no rows in {features_path}")
    return out


def accumulate(session, windows: dict[int, float]) -> dict[int, dict[str, float]]:
    if not windows:
        return {}
    base = windows[min(windows)]
    acc: dict[int, dict[str, float]] = {
        w: defaultdict(float) for w in windows
    }
    for event in session.telemetry():
        ts = event.get("ts_unix_ns")
        if not isinstance(ts, int):
            continue
        w = window_index(ts, base)
        if w not in acc:
            continue
        bucket = acc[w]
        kind = event.get("event_type")
        details = event.get("details")
        details = details if isinstance(details, dict) else {}

        if kind == "guard_input":
            bucket["guard_input_count"] += 1
            lin = details.get("linear_x")
            ang = details.get("angular_z")
            lin = float(lin) if isinstance(lin, (int, float)) else 0.0
            ang = float(ang) if isinstance(ang, (int, float)) else 0.0
            bucket["lin_abs"] += abs(lin)
            bucket["ang_abs"] += abs(ang)
            if lin or ang:
                bucket["guard_input_nonzero"] += 1
        elif kind == "guard_output":
            bucket["guard_output_count"] += 1
            if details.get("blocked") is True:
                bucket["guard_blocked"] += 1
        elif kind == "guard_state":
            if details.get("state") == "locked":
                bucket["guard_locked"] += 1
        elif kind == "authenticated_action":
            bucket["authenticated_action_count"] += 1
        elif kind == "parameter_veto":
            bucket["parameter_veto_count"] += 1
    return acc


def finalise(bucket: dict[str, float]) -> dict[str, float]:
    inputs = bucket.get("guard_input_count", 0.0)
    outputs = bucket.get("guard_output_count", 0.0)
    return {
        "guard_input_rate": round(inputs / WINDOW_SEC, 6),
        "guard_input_nonzero_ratio": round(
            bucket.get("guard_input_nonzero", 0.0) / inputs, 6) if inputs else 0.0,
        "guard_input_angular_abs_mean": round(
            bucket.get("ang_abs", 0.0) / inputs, 6) if inputs else 0.0,
        "guard_input_linear_abs_mean": round(
            bucket.get("lin_abs", 0.0) / inputs, 6) if inputs else 0.0,
        "authenticated_action_rate": round(
            bucket.get("authenticated_action_count", 0.0) / WINDOW_SEC, 6),
        "guard_block_ratio": round(
            bucket.get("guard_blocked", 0.0) / outputs, 6) if outputs else 0.0,
        "guard_lock_rate": round(bucket.get("guard_locked", 0.0) / WINDOW_SEC, 6),
        "parameter_veto_rate": round(
            bucket.get("parameter_veto_count", 0.0) / WINDOW_SEC, 6),
    }


def build(dataset: Path, features: Path, security_mode: str) -> list[dict]:
    geometry = session_windows(features)
    rows: list[dict] = []
    covered = 0
    for session in iter_sessions(dataset, security_mode=security_mode):
        windows = geometry.get(session.session_id)
        if not windows:
            continue
        covered += 1
        try:
            acc = accumulate(session, windows)
        except SessionReadError as exc:
            raise BuildError(f"{session.session_id}: {exc}")
        for w in sorted(acc):
            row = {"session_id": session.session_id, "window": w}
            row.update(finalise(acc[w]))
            rows.append(row)
    if covered == 0:
        raise BuildError(
            "no session in the dataset matched the feature table; "
            "wrong dataset or wrong mode")
    missing = len(geometry) - covered
    if missing:
        sys.stderr.write(
            "  ⚠ %d 場在特徵表裡但資料集裡找不到（不補零，直接不輸出）\n" % missing)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--features", type=Path, required=True,
                        help="既有特徵表；視窗幾何從這裡拿，不自己定義")
    parser.add_argument("--security-mode", default="enforce",
                        choices=("enforce", "permissive"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.output.exists():
        print(f"⛔ 輸出已存在，拒絕覆寫：{args.output}")
        return 2
    try:
        rows = build(args.dataset, args.features, args.security_mode)
    except (BuildError, SessionReadError) as exc:
        print(f"⛔ {exc}")
        return 2

    names = ["session_id", "window", *ALL_FEATURES]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names)
        writer.writeheader()
        writer.writerows(rows)

    meta = args.output.with_suffix(".meta.json")
    meta.write_text(json.dumps({
        "schema_version": "sros2-firewall-behavioural-features/v1",
        "dataset": str(args.dataset),
        "features_geometry_from": str(args.features),
        "security_mode": args.security_mode,
        "window_sec": WINDOW_SEC,
        "behavioural": list(BEHAVIOURAL),
        "defence_reaction": list(DEFENCE_REACTION),
        "rows": len(rows),
        "changes_shipped_features": False,
    }, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")

    print(f"  {len(rows)} 列 -> {args.output}")
    print(f"  behavioural      : {list(BEHAVIOURAL)}")
    print(f"  defence_reaction : {list(DEFENCE_REACTION)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
