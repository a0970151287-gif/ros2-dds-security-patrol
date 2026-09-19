#!/usr/bin/env python3
"""把 `hmac_result.channel` 建成特徵，並**先分成兩半**再測它安不安全。

## 為什麼是現在

`hmac_result.channel` 從 2026-08 起就一直被發出來，卻從來沒有進過特徵表。
`features.py` 只讀 `outcome` 與 `reason`，產生 `hmac_failure_rate`、
`nonce_reuse_ratio`、`channel_mismatch_ratio`、`timestamp_violation_ratio`
四個特徵——**四個都對「打哪一個頻道」完全無感**。

而 `runtime_telemetry.py:45-48` 當初加這個欄位時就寫下了理由：

> `malformed_envelope` 這個理由本身不足以分辨攻擊。實測 N7、N8 都是
> 「對受保護 topic publish 未簽章字串」，撞的是同一個分支；真正不同的是
> **打哪一個頻道**。沒有這個欄位，兩者在遙測上完全相同。

所以這是一個**已經被記錄下來、但從未被兌現**的缺口。活狀態表的待辦寫著
「`hmac_result.channel` 接成特徵——**先確認它不會重蹈身份特徵的覆轍**」。
這支就是那個「先確認」。

## 為什麼要分成兩半

2026-09-04 量到兩次：**用「防禦的反應」當特徵，會讓模型對防禦不反應的攻擊
視而不見**（`sros_auth_fail_rate` 對持證內鬼 −0.2125；`guard_input_rate`
後來也被查出其實是防禦反應，所以它沒有泛化）。

`hmac_result` 是驗章器發出的，整包看起來就像「防禦反應」。但它其實混了兩種
完全不同的東西，而**只有一半有那個毛病**：

| 半 | 欄位 | 這個數字由誰決定 |
|---|---|---|
| `behavioural` | `_rate`、`_share` | **攻擊者往哪個 topic 送了多少** |
| `defence_reaction` | `_reject_ratio` | **驗章器拒絕了多少** |

到達量是攻擊者自己的選擇（`mission_spoof` 打 `mission/cmd`、`health_spoof`
打 `system/health`）；拒絕比例才是防禦的判斷。兩者放在同一個 `hmac_result`
事件裡，所以很容易被當成一件事一起接進去——**那正是要避免的**。

分開建、分開測，才能回答「哪一半可以用」，而不是只能整包要或整包不要。

## 每個視窗、每個頻道三個數字

    hmac_ch_<C>_rate           該頻道到達數 / 8 秒
    hmac_ch_<C>_share          該頻道到達數 / 該視窗全部 hmac 到達數
    hmac_ch_<C>_reject_ratio   該頻道被拒數 / 該頻道到達數

頻道詞彙**取自 `runtime_telemetry.HMAC_CHANNELS`，不是取自資料**。這很重要：
某一批資料剛好沒出現的頻道仍然要有欄位並保持 0，否則換一批資料欄位就會變，
兩批之間不可比。（實測 `patrol/goto` 在 640 場裡一次都沒出現。）

## 這支不改任何既有東西

`features.py` 一行未改。新特徵是獨立一張表，用 `session_id` ＋ `window` 接回。
視窗幾何**從既有特徵表讀**，不自己定義——否則兩張表對不起來而不會有徵兆。

## 用法

    python3 工具腳本/build_hmac_channel_features.py \\
        --dataset ~/refresh_20260902T111358Z/enforce/dataset \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --security-mode enforce \\
        --output ~/hmac_channel_enforce.csv
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

# 詞彙取自防守端的宣告，不是取自資料——見 docstring。
# 與 `src/dds_security_monitor/dds_security_monitor/runtime_telemetry.py` 的
# `HMAC_CHANNELS` 必須相同，有一個測試釘住這一條。
HMAC_CHANNELS = (
    "alerts",
    "heartbeat",
    "mission/cmd",
    "patrol/goto",
    "sensor/status",
    "system/health",
)


def column(channel: str, suffix: str) -> str:
    """`sensor/status` -> `hmac_ch_sensor_status_rate`。"""
    return f"hmac_ch_{channel.replace('/', '_')}_{suffix}"


# 攻擊者往哪裡送了多少。**不看防禦有沒有接受。**
BEHAVIOURAL = tuple(
    column(c, s) for c in HMAC_CHANNELS for s in ("rate", "share")
)
# 驗章器拒絕了多少。與身份通道同一種形狀，所以刻意分開測。
DEFENCE_REACTION = tuple(column(c, "reject_ratio") for c in HMAC_CHANNELS)
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
    """數每個視窗、每個頻道的到達與拒絕。

    ⚠️ 未知頻道**不吞掉**。`_require_choice` 在發送端已經擋過一次，這裡再擋
    一次是因為新增頻道時如果只改發送端，這張表會安靜地少算——那會讓 `share`
    的分母錯掉而完全沒有徵兆。
    """
    if not windows:
        return {}
    base = windows[min(windows)]
    acc: dict[int, dict[str, float]] = {
        w: defaultdict(float) for w in windows
    }
    for event in session.telemetry():
        if event.get("event_type") != "hmac_result":
            continue
        try:
            when = int(event["ts_unix_ns"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SessionReadError(f"hmac_result lacks a usable timestamp: {exc}")
        w = window_index(when, base)
        if w not in acc:
            continue
        details = event.get("details") or {}
        channel = details.get("channel")
        if channel not in HMAC_CHANNELS:
            raise SessionReadError(
                f"unknown HMAC channel {channel!r}; the vocabulary in this "
                "tool and in runtime_telemetry.HMAC_CHANNELS have diverged")
        bucket = acc[w]
        bucket["total"] += 1.0
        bucket[f"n::{channel}"] += 1.0
        if details.get("outcome") != "accepted":
            bucket[f"r::{channel}"] += 1.0
    return acc


def finalise(bucket: dict[str, float]) -> dict[str, float]:
    total = bucket.get("total", 0.0)
    out: dict[str, float] = {}
    for channel in HMAC_CHANNELS:
        arrivals = bucket.get(f"n::{channel}", 0.0)
        rejected = bucket.get(f"r::{channel}", 0.0)
        out[column(channel, "rate")] = round(arrivals / WINDOW_SEC, 6)
        out[column(channel, "share")] = (
            round(arrivals / total, 6) if total else 0.0)
        out[column(channel, "reject_ratio")] = (
            round(rejected / arrivals, 6) if arrivals else 0.0)
    return out


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
        "schema_version": "sros2-firewall-hmac-channel-features/v1",
        "dataset": str(args.dataset),
        "features_geometry_from": str(args.features),
        "security_mode": args.security_mode,
        "window_sec": WINDOW_SEC,
        "channels": list(HMAC_CHANNELS),
        "behavioural": list(BEHAVIOURAL),
        "defence_reaction": list(DEFENCE_REACTION),
        "rows": len(rows),
        "changes_shipped_features": False,
    }, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")

    print(f"  {len(rows)} 列 -> {args.output}")
    print(f"  behavioural      : {len(BEHAVIOURAL)} 欄（rate + share）")
    print(f"  defence_reaction : {len(DEFENCE_REACTION)} 欄（reject_ratio）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
