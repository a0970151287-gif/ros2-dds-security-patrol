#!/usr/bin/env python3
"""這一批的封包擷取，到底看得到 ROS 2 的資料流量嗎？

## 為什麼要查

2026-09-15 重新檢視 2026-09-02 的候選 smoke 時發現：那一批每一場的擷取檔裡
**一個單播封包都沒有**。

    normal       3320 個封包 = 3186 個 UDP(239.255.0.7) + 134 個 RTPS(239.255.0.1)
    odom_spoof   3336 個封包，而攻擊自己回報「送出 1480 筆偽造 odometry」

1,480 筆訊息、0 個對應封包。原因是 `dumpcap -i eth1`——同機的 ROS 2 流量走
loopback，而擷取開在區網介面上，所以只看得到漏出去的多播：其中 96% 還是
**Gazebo 的 gz-transport**（239.255.0.7），跟 DDS 一點關係都沒有。

正式資料集不是這樣（`dumpcap -i lo`，單播 RTPS 佔 93–100%），**所以這是那一批
專屬的缺陷，不是全域問題。** 但那一批正是「三支候選彼此不可分」這個判定的
依據，而那個判定寫進了「至少 4 類在目前的觀測層結構上做不到」。

這是本專案第八次同一個形態：**量測工具自己的缺陷，偽裝成被觀測系統的問題。**

## 判準

只用擷取檔自己就能回答，不需要知道攻擊做了什麼：

| verdict | 條件 | 意思 |
|---|---|---|
| `void_no_unicast` | 單播封包 = 0 | 同機 DDS 的使用者資料**不可能**在裡面 |
| `degraded_low_unicast` | 單播佔比 < `--min-unicast-ratio` | 大部分流量沒被擷到 |
| `skipped_not_eligible` | 場次 `status != complete` 或未進訓練 | 本來就沒有擷取，不是缺陷 |
| `ok` | 其餘 | |

**單播佔比**是判準而不是總封包數，因為多播會把數字撐起來，讓一份空的擷取
看起來很忙——那正是 smoke 那一批的樣子（3,320 個封包，全部是多播）。

## 內建的有效性檢查

多播判定寫錯的話，整張表會安靜地全綠。所以跑之前先驗一組已知答案
（`239.255.0.1`、`224.0.0.1` 是多播；`127.0.0.1`、`192.168.0.129`、`10.0.0.5`
不是），對不上就以 **exit 3** 結束。

## 用法

    python3 工具腳本/audit_capture_scope.py \\
        --batch /home/jesse/candidate_smoke_20260902T081833Z \\
        --output 文件/擷取範圍稽核.json

批次目錄底下若是 `<mode>/dataset/<session>` 的兩層結構，加 `--nested`。
"""
from __future__ import annotations

import argparse
import gzip
import json
import pathlib
import subprocess
import sys
from collections import Counter

# 多播判定的已知答案。改壞了整張表會安靜地全綠，所以拿它當自我檢查。
MULTICAST_FIXTURE: tuple[tuple[str, bool], ...] = (
    ("239.255.0.1", True),      # RTPS SPDP
    ("239.255.0.7", True),      # Gazebo gz-transport
    ("224.0.0.1", True),        # all-hosts
    ("239.0.0.0", True),
    ("223.255.255.255", False),  # 多播區間的下界外
    ("240.0.0.1", False),        # 上界外（保留位址）
    ("127.0.0.1", False),
    ("192.168.0.129", False),
    ("10.0.0.5", False),
)

PACKET_TSV = pathlib.Path("packet_windows") / "packets.tsv.gz"


def is_multicast_ipv4(address: str) -> bool:
    """224.0.0.0/4。非 IPv4 點分十進位一律回 False（當成單播，保守）。"""
    parts = address.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
    except ValueError:
        return False
    return 224 <= first <= 239


def check_multicast_classifier() -> list[str]:
    """回傳分類錯誤的項目；空清單代表通過。"""
    wrong = []
    for address, expected in MULTICAST_FIXTURE:
        if is_multicast_ipv4(address) != expected:
            wrong.append(f"{address} 應為 {expected}")
    return wrong


def capture_interface_from_manifest(manifest: dict) -> str | None:
    """從 manifest 裡的 dumpcap argv 取出 `-i` 的介面名。

    介面沒有被記在 manifest 頂層，只埋在 `result.capture_process.argv`——
    這本身就是缺陷的一部分：擷取範圍不是一等公民，所以沒有人去檢查它。
    """
    result = manifest.get("result")
    capture = (result or {}).get("capture_process") if isinstance(result, dict) else None
    argv = capture.get("argv") if isinstance(capture, dict) else None
    if isinstance(argv, str):
        argv = argv.split()
    if not isinstance(argv, list):
        return None
    tokens = [str(item) for item in argv]
    for index, token in enumerate(tokens):
        if token == "-i" and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith("-i") and len(token) > 2:
            return token[2:]
    return None


def classify(total: int, unicast: int, *, min_unicast_ratio: float) -> str:
    if total == 0:
        return "void_no_packets"
    if unicast == 0:
        return "void_no_unicast"
    if unicast / total < min_unicast_ratio:
        return "degraded_low_unicast"
    return "ok"


def count_from_packet_tsv(path: pathlib.Path) -> tuple[int, int, Counter]:
    """回傳 (總數, 多播數, 目的位址計數)。"""
    total = 0
    multicast = 0
    destinations: Counter = Counter()
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        handle.readline()  # 表頭
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 6:
                continue
            destination = parts[2]
            total += 1
            destinations[destination] += 1
            if is_multicast_ipv4(destination):
                multicast += 1
    return total, multicast, destinations


def count_from_pcap(path: pathlib.Path) -> tuple[int, int, Counter]:
    result = subprocess.run(
        ["tshark", "-r", str(path), "-T", "fields", "-e", "ip.dst"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"tshark 讀 {path} 失敗：{result.stderr.strip()[:200]}")
    total = 0
    multicast = 0
    destinations: Counter = Counter()
    for line in result.stdout.splitlines():
        destination = line.strip()
        if not destination:
            continue
        total += 1
        destinations[destination] += 1
        if is_multicast_ipv4(destination):
            multicast += 1
    return total, multicast, destinations


def audit_session(
    session_dir: pathlib.Path, *, min_unicast_ratio: float
) -> dict | None:
    manifest_path = session_dir / "manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # 中止的場次本來就沒有擷取，那不是儀器缺陷。它們也沒有進特徵表
    # （`training_eligible=False`），所以把它們算成 void 會製造假警報。
    if manifest.get("status") != "complete" or not manifest.get("training_eligible"):
        return {
            "session": session_dir.name,
            "attack_class": manifest.get("attack_class"),
            "security_mode": manifest.get("security_mode"),
            "capture_interface": capture_interface_from_manifest(manifest),
            "packet_source": None,
            "session_status": manifest.get("status"),
            "training_eligible": bool(manifest.get("training_eligible")),
            "verdict": "skipped_not_eligible",
        }

    tsv = session_dir / PACKET_TSV
    pcap = session_dir / "traffic.pcapng"
    if tsv.is_file():
        total, multicast, destinations = count_from_packet_tsv(tsv)
        source = "packet_windows"
    elif pcap.is_file():
        total, multicast, destinations = count_from_pcap(pcap)
        source = "pcapng"
    else:
        return {
            "session": session_dir.name,
            "attack_class": manifest.get("attack_class"),
            "security_mode": manifest.get("security_mode"),
            "capture_interface": capture_interface_from_manifest(manifest),
            "packet_source": None,
            "verdict": "void_no_capture",
        }

    unicast = total - multicast
    return {
        "session": session_dir.name,
        "attack_class": manifest.get("attack_class"),
        "security_mode": manifest.get("security_mode"),
        "capture_interface": capture_interface_from_manifest(manifest),
        "packet_source": source,
        "packets_total": total,
        "packets_multicast": multicast,
        "packets_unicast": unicast,
        "unicast_ratio": round(unicast / total, 6) if total else 0.0,
        "top_destinations": destinations.most_common(4),
        "verdict": classify(total, unicast, min_unicast_ratio=min_unicast_ratio),
    }


def iter_sessions(batch: pathlib.Path, *, nested: bool):
    if nested:
        for mode in sorted(child for child in batch.iterdir() if child.is_dir()):
            dataset = mode / "dataset"
            root = dataset if dataset.is_dir() else mode
            for session in sorted(child for child in root.iterdir() if child.is_dir()):
                yield session
    else:
        for session in sorted(child for child in batch.iterdir() if child.is_dir()):
            yield session


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, type=pathlib.Path)
    parser.add_argument(
        "--nested",
        action="store_true",
        help="批次是 <mode>/dataset/<session> 兩層結構",
    )
    parser.add_argument(
        "--min-unicast-ratio",
        type=float,
        default=0.5,
        help="單播佔比低於此值判為 degraded（預設 0.5）",
    )
    parser.add_argument("--limit", type=int, default=0, help="只看前 N 場（抽查用）")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument(
        "--no-sanity-check",
        action="store_true",
        help="關掉多播分類器的自我檢查。要刻意加才會生效。",
    )
    args = parser.parse_args()

    if not args.no_sanity_check:
        wrong = check_multicast_classifier()
        if wrong:
            print("⛔ 多播分類器對已知答案就錯了：" + "；".join(wrong), file=sys.stderr)
            return 3

    if not args.batch.is_dir():
        print(f"⛔ 找不到批次目錄 {args.batch}", file=sys.stderr)
        return 2

    rows = []
    for session in iter_sessions(args.batch, nested=args.nested):
        row = audit_session(session, min_unicast_ratio=args.min_unicast_ratio)
        if row is not None:
            rows.append(row)
        if args.limit and len(rows) >= args.limit:
            break

    if not rows:
        print(f"⛔ {args.batch} 底下沒有任何帶 manifest 的場次", file=sys.stderr)
        return 2

    verdicts = Counter(row["verdict"] for row in rows)
    if verdicts.get("skipped_not_eligible", 0) == len(rows):
        print(
            f"⛔ {args.batch} 底下每一場都不可訓練，這次稽核等於什麼都沒檢查",
            file=sys.stderr,
        )
        return 2
    # 介面可能是 None（少數場次沒記 capture_process）。混著 None 排序會炸，
    # 而稽核工具自己炸掉正是最糟的失效方向——整批會安靜地沒被檢查。
    interfaces = Counter(
        row.get("capture_interface") or "<未記錄>" for row in rows
    )

    print(f"批次 {args.batch}")
    print(f"場次 {len(rows)}   擷取介面 {dict(interfaces)}")
    print()
    print("%-22s %-10s %8s %8s %8s  %s" % ("class", "mode", "總封包", "單播", "占比", "verdict"))
    for row in rows[: args.limit or 12]:
        print(
            "%-22s %-10s %8s %8s %7.1f%%  %s"
            % (
                str(row.get("attack_class"))[:22],
                str(row.get("security_mode"))[:10],
                row.get("packets_total", "—"),
                row.get("packets_unicast", "—"),
                100.0 * row.get("unicast_ratio", 0.0),
                row["verdict"],
            )
        )
    if len(rows) > (args.limit or 12):
        print("  …（共 %d 場，完整結果在 JSON）" % len(rows))
    print()
    print("verdict 分布：" + "  ".join(f"{k}={v}" for k, v in verdicts.most_common()))

    report = {
        "schema_version": "sros2-firewall-capture-scope/v1",
        "batch": str(args.batch),
        "sessions": len(rows),
        "min_unicast_ratio": args.min_unicast_ratio,
        "capture_interfaces": dict(interfaces),
        "verdicts": dict(verdicts),
        "rows": rows,
        "changes_shipped_features": False,
    }
    if args.output:
        if args.output.exists():
            print(f"⛔ {args.output} 已存在，不覆寫", file=sys.stderr)
            return 2
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"wrote {args.output}")

    bad = sum(count for verdict, count in verdicts.items() if verdict.startswith("void"))
    if bad:
        print(
            f"\n⛔ {bad} 場的擷取不可能包含同機 DDS 使用者資料。"
            "任何以這批的網路特徵做出的判定都是無效的，不是陰性。",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
