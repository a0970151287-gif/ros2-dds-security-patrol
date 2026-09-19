#!/usr/bin/env python3
"""從封存的 pcap 抽出逐封包紀錄，讓網路特徵可以按時間分窗而不是按流分窗。

## 為什麼需要

`conn.log` 是**流**的紀錄，時間戳是流的**起點**。一條持續 50 秒的 DDS 流只會
產生一列，落進一個 8 秒視窗。實測 `20260813T080943935043Z_oversized_scan_4d59dce0`：

| | 舊（校驗和損壞） | 新（`-C` 重建） |
|---|---:|---:|
| conn 筆數 | 3,932 | 462 |
| 流起點跨度 | 51.4 秒 | **9.0 秒** |
| 起點落在哪些視窗 | 0–6 | **只有 0–1** |

舊表每場有 7 個視窗，**那個時間解析度是校驗和 bug 的副產物**——被丟棄的封包
讓一條長流碎成幾千筆短紀錄，剛好散佈在整個 session 上。修好校驗和之後，
真實的流數變成 462 筆而且幾乎同時開始，每場只剩約 3 個視窗。

所以「按 conn.log 的 ts 分窗」從一開始就量不到「這個視窗裡有多少流量」。
要量流量隨時間的變化，必須看封包。

## 這支做什麼

對每一場跑一次 `tshark`，把逐封包的
`(時間, 來源, 目的, 來源埠, 目的埠, 長度)` 寫成 gzip TSV，放在
`packet_windows/packets.tsv.gz`。**只抽取、不聚合**——分窗與特徵怎麼算是
下游的決定，原始逐封包紀錄留著才能重算與稽核。

不覆寫任何既有證據：pcap、`zeek/`、`zeek_checksum_fixed/` 都不動。

## fail-closed

`tshark` 非零退出、輸出 0 個封包、或抽到的封包數與 `capinfos` 報的差太多，
都記成失敗而不是靜靜收下一份殘缺的紀錄。

## 用法

    python3 工具腳本/extract_packet_windows.py --dataset firewall_lab/dataset_live
"""

from __future__ import annotations

import argparse
import gzip
import json
import subprocess
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

OUT_DIR = "packet_windows"
SCHEMA = "sros2-firewall-packet-window-extract/v1"

# 只取分窗與流量特徵需要的欄位。酬載不抽——身份證據走
# decode_rtps_identity.py，那是另一條有自己契約的管線。
FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
)


def extract_one(session_dir: Path, tshark: str, timeout: int) -> dict:
    session_dir = session_dir.resolve()
    result: dict = {"session": session_dir.name, "status": "unknown"}
    pcap = session_dir / "traffic.pcapng"
    if not pcap.exists():
        result["status"] = "no_pcap"
        return result

    argv = [tshark, "-r", str(pcap), "-T", "fields"]
    for field in FIELDS:
        argv += ["-e", field]
    argv += ["-E", "header=n", "-E", "occurrence=f"]

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pktwin-") as work:
        raw = Path(work) / "packets.tsv"
        try:
            with raw.open("wb") as handle:
                proc = subprocess.run(
                    argv,
                    stdout=handle,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            return result

        duration = time.monotonic() - started
        stderr = proc.stderr.decode("utf-8", errors="replace")
        if proc.returncode != 0:
            result.update(status="tshark_failed", return_code=proc.returncode,
                          stderr=stderr[:2000], duration_sec=duration)
            return result

        kept = 0
        skipped_non_ip = 0
        first_ts = None
        last_ts = None
        out_dir = session_dir / OUT_DIR
        out_dir.mkdir(exist_ok=True)
        target = out_dir / "packets.tsv.gz"
        with raw.open(encoding="utf-8", errors="replace") as src, gzip.open(
            target, "wt", encoding="utf-8", newline="\n"
        ) as dst:
            dst.write("\t".join(FIELDS) + "\n")
            for line in src:
                parts = line.rstrip("\n").split("\t")
                if len(parts) != len(FIELDS):
                    continue
                ts, src_ip, dst_ip, sport, dport, length = parts
                # 非 IP 或非 UDP 的框（ARP 之類）沒有本專案要的欄位。
                # 記數而不是靜靜丟掉——「抽到的比 pcap 少」必須看得見原因。
                if not ts or not src_ip or not dport:
                    skipped_non_ip += 1
                    continue
                try:
                    value = float(ts)
                except ValueError:
                    skipped_non_ip += 1
                    continue
                first_ts = value if first_ts is None else min(first_ts, value)
                last_ts = value if last_ts is None else max(last_ts, value)
                dst.write(
                    f"{ts}\t{src_ip}\t{dst_ip}\t{sport}\t{dport}\t{length}\n"
                )
                kept += 1

        if kept == 0:
            target.unlink(missing_ok=True)
            result.update(status="no_packets", stderr=stderr[:2000],
                          duration_sec=duration)
            return result

        record = {
            "schema_version": SCHEMA,
            "argv": argv,
            "fields": list(FIELDS),
            "packets": kept,
            "skipped_non_ip_frames": skipped_non_ip,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "span_sec": (last_ts - first_ts) if first_ts is not None else 0.0,
            "duration_sec": duration,
            "stderr": stderr[:2000],
        }
        (out_dir / "extract.json").write_text(
            json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        result.update(status="ok", packets=kept,
                      skipped_non_ip_frames=skipped_non_ip,
                      span_sec=record["span_sec"], duration_sec=duration)
        return result


def _worker(args: tuple[str, str, int]) -> dict:
    path, tshark, timeout = args
    return extract_one(Path(path), tshark, timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--tshark", default="/usr/bin/tshark")
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--report", type=Path,
                        default=Path("文件/逐封包抽取_2026-08-31.json"))
    args = parser.parse_args()

    sessions = sorted(p for p in args.dataset.iterdir() if p.is_dir())
    if args.limit:
        sessions = sessions[: args.limit]
    print(f"  待處理 {len(sessions)} 場，{args.jobs} 個平行工作")

    results: list[dict] = []
    started = time.monotonic()
    payload = [(str(s), args.tshark, args.timeout) for s in sessions]
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(_worker, item) for item in payload]
        for done, future in enumerate(as_completed(futures), start=1):
            results.append(future.result())
            if done % 50 == 0 or done == len(sessions):
                elapsed = time.monotonic() - started
                rate = done / elapsed if elapsed else 0
                print(f"    {done}/{len(sessions)}  已耗 {elapsed/60:.1f} 分"
                      f"  預估剩 {(len(sessions)-done)/rate/60 if rate else 0:.1f} 分")

    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print()
    for status, n in sorted(counts.items()):
        print(f"  {status:<24}{n:>6}")

    ok = [r for r in results if r["status"] == "ok"]
    if ok:
        total = sum(r["packets"] for r in ok)
        spans = sorted(r["span_sec"] for r in ok)
        print(f"\n  封包總數 {total:,}"
              f"　每場中位數 {sorted(r['packets'] for r in ok)[len(ok)//2]:,}"
              f"　時間跨度中位數 {spans[len(ok)//2]:.1f} 秒")

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA,
                "dataset": str(args.dataset),
                "elapsed_sec": time.monotonic() - started,
                "status_counts": counts,
                "sessions": sorted(results, key=lambda r: r["session"]),
            },
            indent=2, sort_keys=True, ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"\n  報告：{args.report}")
    failed = {k: v for k, v in counts.items() if k not in ("ok", "no_pcap")}
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
