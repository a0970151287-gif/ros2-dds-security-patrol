#!/usr/bin/env python3
"""Report how long the most recent sessions took, for the supervisor to watch.

The mega campaign's 2026-09-19 run degraded from a ~95s session to a ~385s one
and stayed there for 103 sessions, about ten hours. The supervisor's existing
circuit breaker could not see it: that breaker counts sessions produced, and a
degraded campaign still produces sessions -- just four times slower. "Nothing is
being produced" and "everything is being produced too slowly" are different
failures, and only the first one was being watched.

This prints the median wall clock of the newest sessions so the supervisor can
watch the second. It is read-only and deliberately tiny: it reuses
``measure_campaign_throughput.load_sessions`` rather than re-deriving how a
manifest records its timestamps, because two parsers of the same field is how
the two halves of a measurement drift apart.

Exit codes are the interface:

* ``0`` -- the pace is within bounds, or there are not yet enough sessions to
  judge. Not enough data is not a failure, but it is also not a pass, so the
  reason is printed either way.
* ``4`` -- the median residual exceeds ``--slow-threshold-sec``.
* ``2`` -- the dataset could not be read at all.

Why a residual and not the wall clock. Session duration tracks how much traffic
was captured -- measured over 502 sessions, ``inside ~ 85.7s + 0.376 s/MB``,
running from 86s at 4MB to 453s at 750MB. An absolute threshold fires on any
batch of heavy scenarios (300MB costs 198s on volume alone) and would stop a
healthy campaign. What this guard is for is degradation: the same work taking
longer. Residuals separate cleanly where raw durations do not:

    2026-09-19 slow block   n=103  residual median +116.8s
    everything else         n=400  residual median   -2.8s  (p75 +6.3s)

The model was fitted on the sessions outside the slow block, so it is not shaped
by the thing it is used to judge.
"""

from __future__ import annotations

import argparse
import pathlib
import statistics
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL = _ROOT / "工具腳本" / "measure_campaign_throughput.py"

# Session wall clock against capture size, fitted over the 400 sessions outside
# the 2026-09-19 slow block. Re-fit these with measure_campaign_throughput.py if
# the capture pipeline changes; they describe this machine and this pipeline,
# not a law.
VOLUME_FIXED_SEC = 85.7
VOLUME_SLOPE_SEC_PER_MB = 0.376

# 這個模型對大擷取量已經失效,而且是結構性的。
#
# 它是在逐封包抽取被 **300 秒固定逾時砍斷**的資料上配的（2026-09-24）。
# 2026-09-25 把逾時改成跟著量體走之後,抽取會跑到完,`inside` 因此變長,
# 而模型不知道這件事。
#
# 量了才知道有多嚴重。180 場補跑（四路併行、機器沒跑 campaign）實測
# `extraction_sec ≈ 17.2 + 0.533 × MB`（R² 0.767）：
#
#     pcap    舊模型對**整場**的預測    光抽取一步就要
#     263 MB        184.6s                 157.4s
#     500 MB        273.7s                 283.7s   ← 在這裡交叉
#     795 MB        384.6s                 441.0s
#
# **在 500 MB 以上,抽取一個步驟就超過模型對整場的預測。** 那時候殘差不再
# 是「有沒有退化」的度量,而是「模型錯得多離譜」的度量,拿它當熔斷器會對
# 健康的 campaign 誤判——而那正是 2026-09-24 把絕對中位數換成殘差要修的
# 同一種錯誤,只是換了一個方向。
#
# ⚠️ 為什麼不直接配一個新的:配不出來。補跑是四路併行、而且機器上沒有
# campaign 在跑;campaign 裡抽取是序列的但要跟 ROS stack、Gazebo、Zeek、
# dumpcap 搶。兩個效應方向相反且都量不到——**同一批 pcap 在補跑時只有
# 14／180 超過 300 秒,在 campaign 裡卻逾時了 94 場**,所以慢的不是 tshark,
# 是 campaign 自己的負載。真正的重配需要新 campaign 的場次。
MODEL_INVALID_ABOVE_MB = 500.0


def _load_sessions(dataset: pathlib.Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("_campaign_throughput", _TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_sessions(dataset)


def _capture_megabytes(directory: pathlib.Path) -> float:
    pcap = directory / "traffic.pcapng"
    try:
        return pcap.stat().st_size / 1e6
    except OSError:
        return 0.0


def expected_sec(megabytes: float) -> float:
    """What a session of this capture size should cost when nothing is wrong."""

    return VOLUME_FIXED_SEC + VOLUME_SLOPE_SEC_PER_MB * megabytes


def recent_pace(dataset: pathlib.Path, window: int) -> dict:
    sessions, skipped = _load_sessions(dataset)
    recent = sessions[-window:] if window > 0 else sessions
    durations = [session["inside_sec"] for session in recent]
    megabytes = [_capture_megabytes(session["directory"]) for session in recent]
    residuals = [
        duration - expected_sec(size)
        for duration, size in zip(durations, megabytes)
    ]
    return {
        "sessions_total": len(sessions),
        "sessions_considered": len(recent),
        "skipped": skipped,
        "median_sec": round(statistics.median(durations), 1) if durations else None,
        "max_sec": round(max(durations), 1) if durations else None,
        "median_pcap_mb": round(statistics.median(megabytes), 1) if megabytes else None,
        "median_residual_sec": (
            round(statistics.median(residuals), 1) if residuals else None
        ),
        "max_residual_sec": round(max(residuals), 1) if residuals else None,
        "modes": sorted({s["security_mode"] for s in recent if s["security_mode"]}),
        "model_applicable": (
            bool(megabytes)
            and statistics.median(megabytes) <= MODEL_INVALID_ABOVE_MB
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument(
        "--window", type=int, default=10, help="how many of the newest sessions to judge"
    )
    parser.add_argument(
        "--slow-threshold-sec",
        type=float,
        default=60.0,
        help=(
            "median residual above this is a degraded campaign. Residual is the "
            "wall clock minus what the capture size predicts. Healthy runs sit "
            "at -2.8s (p75 +6.3s); the 2026-09-19 degradation sat at +116.8s, "
            "so 60s sits well clear of both."
        ),
    )
    parser.add_argument(
        "--minimum-sessions",
        type=int,
        default=5,
        help="below this many, report the pace but never call it slow",
    )
    args = parser.parse_args(argv)

    dataset = pathlib.Path(args.dataset).expanduser()
    if not dataset.is_dir():
        print(f"pace: dataset not found: {dataset}")
        return 2

    pace = recent_pace(dataset, args.window)
    if pace["median_sec"] is None:
        print("pace: no timed sessions yet")
        return 0

    modes = ",".join(pace["modes"]) or "unknown"
    line = (
        f"pace: newest {pace['sessions_considered']} of {pace['sessions_total']} "
        f"median={pace['median_sec']}s pcap={pace['median_pcap_mb']}MB "
        f"residual={pace['median_residual_sec']:+}s modes={modes} "
        f"threshold={args.slow_threshold_sec:+g}s"
    )

    if pace["sessions_considered"] < args.minimum_sessions:
        print(f"{line} (too few to judge)")
        return 0
    if not pace["model_applicable"]:
        # 拒絕判斷,而不是套一個已知失效的模型。沉默地套下去會在大擷取量的
        # 批次上把健康的 campaign 停掉,而停掉的訊息會看起來完全合理。
        print(f"{line} 模型不適用（中位 pcap > {MODEL_INVALID_ABOVE_MB:g}MB，"
              "抽取一步就超過模型對整場的預測；需要新場次重配）")
        return 0
    if pace["median_residual_sec"] > args.slow_threshold_sec:
        print(f"{line} SLOW")
        return 4
    print(f"{line} ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
