#!/usr/bin/env python3
"""用 `-C` 重跑全部已封存 pcap 的 Zeek，修掉校驗和卸載造成的資料損毀。

## 缺陷

1,100 場的 Zeek 都在沒有 `-C` 的情況下執行，於是「校驗和不正確」的封包被整批
丟棄。Zeek **自己每一場都警告過**，警告就存在各場的 `zeek_process.json` 裡，
只是沒有人讀：

    Your trace file likely has invalid UDP checksums, most likely from NIC
    checksum offloading. ... packets with invalid checksums are discarded

同一份 pcap 的實測差異：

| | 不加 `-C` | 加 `-C` |
|---|---:|---:|
| conn 列數 | 582 | 76 |
| `orig_bytes` | 未設定 | 12840 |
| `duration` | 未設定 | 40.78 |
| `history` | `CC`（校驗和錯誤） | `D` |

**比拿不到位元組更嚴重的是連線數差 7.6 倍。** `conn_count` 與 `conn_rate` 是
一直在用的特徵，它們量到的是校驗和造成的流碎裂，不是連線行為。

## 為什麼可以離線修

pcap 全部還在。這是純粹的後處理缺陷，**一場 live 都不用重跑**。

## 不覆寫原始證據

`zeek/conn.log` 的大小與 SHA-256 記在各場 `manifest.json` 裡，覆寫它會讓
`verify_manifest_evidence()` 對整個資料集失敗。重建結果因此寫到平行目錄
`zeek_checksum_fixed/`；manifest 只檢查它自己列出的檔案，多出來的目錄不影響。
原始的壞資料保留，它是「缺陷長什麼樣」的唯一實證。

## 這支自己的 fail-closed

`-C` 生效時 Zeek 就不會再發那則校驗和警告。所以「新的 stderr 仍含該警告」
直接代表旗標沒吃到，該場標為 `flag_ineffective` 而不是靜靜地收下壞結果。
同樣地 rc≠0、conn.log 空、或欄位仍全空，都會被記成失敗而不是成功。

## 用法

    python3 工具腳本/rebuild_zeek_checksum.py --dataset firewall_lab/dataset_live
    python3 工具腳本/rebuild_zeek_checksum.py --dataset ... --limit 5   # 先試跑
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

CHECKSUM_WARNING = "invalid UDP checksums"
REBUILD_DIR = "zeek_checksum_fixed"
SCHEMA = "sros2-firewall-zeek-checksum-rebuild/v1"


def _conn_rows(conn_log: Path) -> int:
    """conn.log 的資料列數（Zeek TSV 的 # 開頭是標頭與註腳）。"""
    if not conn_log.exists():
        return 0
    n = 0
    with conn_log.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line and not line.startswith("#"):
                n += 1
    return n


def _column(conn_log: Path, name: str) -> list[str]:
    """取 conn.log 某一欄的所有值，用標頭列定位而不是寫死索引。"""
    if not conn_log.exists():
        return []
    fields: list[str] = []
    values: list[str] = []
    with conn_log.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if name not in fields:
                return []
            parts = line.rstrip("\n").split("\t")
            idx = fields.index(name)
            if idx < len(parts):
                values.append(parts[idx])
    return values


def rebuild_one(session_dir: Path, zeek: str, timeout: int) -> dict:
    """單場重建。回傳一律是 dict，不拋例外——一場壞掉不該中止整批。"""
    result: dict = {"session": session_dir.name, "status": "unknown"}
    session_dir = session_dir.resolve()
    pcap = session_dir / "traffic.pcapng"
    if not pcap.exists():
        result["status"] = "no_pcap"
        return result

    process_json = session_dir / "zeek_process.json"
    extra: list[str] = []
    if process_json.exists():
        try:
            argv = json.loads(process_json.read_text(encoding="utf-8"))["argv"]
            if "-e" in argv:
                extra = ["-e", argv[argv.index("-e") + 1]]
            if "-C" in argv:
                # 這一場當初就加了 -C，沒有要修的東西。
                result["status"] = "already_had_flag"
                return result
        except (KeyError, ValueError, OSError) as exc:
            result["status"] = "unreadable_process_json"
            result["error"] = str(exc)
            return result

    original = session_dir / "zeek" / "conn.log"
    result["original_conn_rows"] = _conn_rows(original)

    argv = [zeek, "-C", "-r", str(pcap), *extra]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="zeekrebuild-") as work:
        # cwd 放在 Linux 檔案系統上：Zeek 把 log 寫到 cwd，而資料集在 /mnt/c
        # （drvfs）上寫入很慢。pcap 只能從那裡讀，但輸出不必也繞過去。
        try:
            proc = subprocess.run(
                argv,
                cwd=work,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            result["duration_sec"] = time.monotonic() - started
            return result

        duration = time.monotonic() - started
        stderr = proc.stderr or ""

        if proc.returncode != 0:
            result.update(status="zeek_failed", return_code=proc.returncode,
                          argv=argv, stderr=stderr[:2000], duration_sec=duration)
            return result

        if CHECKSUM_WARNING in stderr:
            # -C 應該讓這則警告消失。它還在就代表旗標沒生效。
            result.update(status="flag_ineffective", stderr=stderr[:2000],
                          duration_sec=duration)
            return result

        work_dir = Path(work)
        new_conn = work_dir / "conn.log"
        rows = _conn_rows(new_conn)
        if rows == 0:
            result.update(status="empty_conn_log", stderr=stderr[:2000],
                          duration_sec=duration)
            return result

        orig_bytes = [v for v in _column(new_conn, "orig_bytes") if v not in ("", "-")]
        if not orig_bytes:
            result.update(status="still_no_bytes", stderr=stderr[:2000],
                          duration_sec=duration)
            return result

        out_dir = session_dir / REBUILD_DIR
        out_dir.mkdir(exist_ok=True)
        copied = []
        for log in sorted(work_dir.glob("*.log")):
            shutil.copy2(log, out_dir / log.name)
            copied.append(log.name)

        record = {
            "schema_version": SCHEMA,
            "argv": argv,
            "return_code": proc.returncode,
            "duration_sec": duration,
            "stderr": stderr[:4000],
            "logs": copied,
            "conn_rows": rows,
            "original_conn_rows": result["original_conn_rows"],
        }
        (out_dir / "rebuild.json").write_text(
            json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )

        result.update(status="ok", conn_rows=rows, logs=copied,
                      duration_sec=duration)
        return result


def _worker(args: tuple[str, str, int]) -> dict:
    path, zeek, timeout = args
    return rebuild_one(Path(path), zeek, timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--zeek", default="/usr/local/bin/zeek")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--limit", type=int, default=0,
                        help="只處理前 N 場（試跑用）")
    parser.add_argument("--report", type=Path,
                        default=Path("文件/Zeek校驗和重建_2026-08-31.json"))
    args = parser.parse_args()

    sessions = sorted(p for p in args.dataset.iterdir() if p.is_dir())
    if args.limit:
        sessions = sessions[: args.limit]
    print(f"  待處理 {len(sessions)} 場，{args.jobs} 個平行工作")

    results: list[dict] = []
    started = time.monotonic()
    payload = [(str(s), args.zeek, args.timeout) for s in sessions]
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(_worker, item): item[0] for item in payload}
        for done, future in enumerate(as_completed(futures), start=1):
            results.append(future.result())
            if done % 25 == 0 or done == len(sessions):
                elapsed = time.monotonic() - started
                rate = done / elapsed if elapsed else 0
                remain = (len(sessions) - done) / rate if rate else 0
                print(f"    {done}/{len(sessions)}  已耗 {elapsed/60:.1f} 分"
                      f"  預估剩 {remain/60:.1f} 分")

    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    ok = [r for r in results if r["status"] == "ok"]
    print()
    for status, n in sorted(counts.items()):
        print(f"  {status:<26}{n:>6}")

    if ok:
        old = sum(r["original_conn_rows"] for r in ok)
        new = sum(r["conn_rows"] for r in ok)
        print()
        print(f"  conn.log 總列數  舊 {old:,} → 新 {new:,}"
              f"  （{old / new:.2f}× 膨脹）")

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA,
                "dataset": str(args.dataset),
                "zeek": args.zeek,
                "elapsed_sec": time.monotonic() - started,
                "status_counts": counts,
                "sessions": sorted(results, key=lambda r: r["session"]),
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"\n  報告：{args.report}")

    failed = {k: v for k, v in counts.items()
              if k not in ("ok", "no_pcap", "already_had_flag")}
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
