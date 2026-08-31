#!/usr/bin/env python3
"""N32：被動 discovery 偵察——只聽不說，把整個系統的拓撲畫出來。

## 為什麼需要這一支

現有八個攻擊**全部會送流量**，而 14 個網路特徵全部是速率、比例或連線數：

    conn_count, conn_rate, uniq_dst_ports, uniq_dst_hosts, spdp_ratio,
    meta_ratio, userdata_ratio, mcast_ratio, dst_port_entropy,
    interarrival_cv, burstiness, dominant_port_ratio, dominant_host_ratio,
    tuple_repeat_ratio, orig_bytes_rate, orig_pkts_rate,
    mean_bytes_per_packet, max_conn_bytes, amplification_ratio

**沒有一個看得見一個不說話的攻擊者。** 這一類在 `action_policy.json` 裡有規則
（`discovery_recon` → `alert`），但資料集裡從來沒有出現過。

CCS 2022 的 *On the (In)Security of Secure ROS2* 把它列為 V3：
discovery 協定向被動攻擊者洩漏網路拓撲。

## 兩種模式，代表兩種不同的威脅

| 模式 | 產生的流量 | 誰看得見 |
|---|---|---|
| `sniff` | **零** | 沒有任何被動網路感測器看得見。這是一個**上限**，要如實寫進論文 |
| `silent-participant` | 只有 SPDP 週期公告 | 流量特徵看不見；**身份層看得見**——participant 的存在本身就是痕跡 |

`silent-participant` 才是這個專案能防的那一種，也是 2026-08-31 補起來的身份
通道**唯一能證明價值的場景**。`sniff` 存在的意義是誠實標出邊界：那種攻擊者
在防守方主機上是量不到的。

## 這支不做什麼

不送任何應用層訊息、不建立任何 publisher、不呼叫任何 service、不寫入任何
遠端狀態。它只讀 discovery 已經公告出來的東西——**那正是威脅所在**：
這些資訊是 DDS 主動送給每一個加入者的。

## rclpy 會偷偷替你建東西

`Node()` 預設會建六個參數服務、一個 `~/get_type_description` 服務、以及
rosout publisher。**那些都會送流量**，會讓「被動」這個前提失效。三個開關
缺一不可，而 type description service 只能在建構當下用
`parameter_overrides` 關掉——漏掉它的錯誤訊息是
「Failed to initialize type description service」，一個字都不提你少關了什麼。

## 用法

    python3 紅隊測試/PoC腳本/N32_discovery_recon.py 40
    python3 紅隊測試/PoC腳本/N32_discovery_recon.py 40 --mode sniff
"""

from __future__ import annotations

import argparse
import json
import sys
import time


def _run_silent_participant(duration_sec: float, interval: float) -> int:
    """加入 domain 但不建立任何 publisher／subscriber，只讀 discovery。"""
    import rclpy
    from rclpy.node import Node
    from rclpy.parameter import Parameter

    class SilentNode(Node):
        def __init__(self, name: str) -> None:
            # 三個開關缺一不可，否則「被動」就不成立：
            #   start_parameter_services=False  → 關掉六個參數服務
            #   start_type_description_service  → 只能在建構當下關
            #   enable_rosout=False             → 否則每筆 log 都會上 /rosout
            super().__init__(
                name,
                start_parameter_services=False,
                enable_rosout=False,
                parameter_overrides=[
                    Parameter(
                        "start_type_description_service",
                        Parameter.Type.BOOL,
                        False,
                    )
                ],
            )

    rclpy.init()
    # 節點名刻意平凡。偵察的重點是不引起注意，取名 attacker 沒有意義。
    node = SilentNode("diagnostics_probe")

    seen_nodes: set[tuple[str, str]] = set()
    seen_topics: dict[str, list[str]] = {}
    endpoints: dict[str, set[str]] = {}
    samples = 0

    deadline = time.monotonic() + duration_sec
    try:
        while time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.0)
            samples += 1

            for name, namespace in node.get_node_names_and_namespaces():
                seen_nodes.add((namespace, name))

            for topic, types in node.get_topic_names_and_types():
                seen_topics[topic] = sorted(types)
                # 每個 topic 上有誰在發、誰在收——這是拓撲的核心，
                # 而 DDS 主動把它公告給每一個加入者。
                try:
                    for info in node.get_publishers_info_by_topic(topic):
                        endpoints.setdefault(topic, set()).add(
                            f"pub:{info.node_namespace}{info.node_name}"
                        )
                    for info in node.get_subscriptions_info_by_topic(topic):
                        endpoints.setdefault(topic, set()).add(
                            f"sub:{info.node_namespace}{info.node_name}"
                        )
                except Exception:
                    # 個別 topic 查不到不該中止整場偵察。
                    pass

            time.sleep(interval)
    finally:
        node.destroy_node()
        rclpy.shutdown()

    report = {
        "mode": "silent-participant",
        "duration_sec": duration_sec,
        "discovery_polls": samples,
        "nodes": sorted(f"{ns}{n}" for ns, n in seen_nodes),
        "topics": {t: v for t, v in sorted(seen_topics.items())},
        "endpoints": {t: sorted(v) for t, v in sorted(endpoints.items())},
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(
        f"\n偵察完成：{len(seen_nodes)} 個節點、{len(seen_topics)} 個 topic、"
        f"{sum(len(v) for v in endpoints.values())} 個端點。",
        file=sys.stderr,
    )
    print(
        "全程未送出任何應用層訊息——這些是 DDS 主動公告給每個加入者的。",
        file=sys.stderr,
    )
    return 0


def _run_sniff(duration_sec: float, interface: str) -> int:
    """完全被動：不建立 participant，只讀線上的 SPDP／SEDP。

    這種攻擊者產生 **0 個封包**，所以任何以速率、比例或連線數為基礎的
    網路特徵都看不見它。放進資料集的意義是**標出上限**，不是期待模型抓到。
    """
    import shutil
    import subprocess

    tshark = shutil.which("tshark")
    if tshark is None:
        print("⛔ 找不到 tshark，sniff 模式需要它", file=sys.stderr)
        return 2

    argv = [
        tshark, "-i", interface, "-a", f"duration:{int(duration_sec)}",
        "-Y", "rtps", "-T", "fields",
        "-e", "ip.src", "-e", "rtps.guidPrefix", "-e", "rtps.sm.id",
        "-E", "separator=|", "-E", "occurrence=f",
    ]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=duration_sec + 30, check=False,
        )
    except subprocess.TimeoutExpired:
        print("⛔ tshark 逾時", file=sys.stderr)
        return 1
    if completed.returncode != 0:
        print(f"⛔ tshark 失敗：{completed.stderr[:400]}", file=sys.stderr)
        return 1

    guids: dict[str, set[str]] = {}
    for line in completed.stdout.splitlines():
        parts = line.split("|")
        if len(parts) != 3:
            continue
        source, prefix, _ = parts
        prefix = prefix.replace(":", "").strip().lower()
        if source.strip() and len(prefix) == 24:
            guids.setdefault(source.strip(), set()).add(prefix)

    report = {
        "mode": "sniff",
        "duration_sec": duration_sec,
        "interface": interface,
        "packets_sent_by_attacker": 0,
        "hosts": {ip: sorted(v) for ip, v in sorted(guids.items())},
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(
        f"\n偵察完成：{len(guids)} 台主機、"
        f"{sum(len(v) for v in guids.values())} 個 participant。",
        file=sys.stderr,
    )
    print(
        "攻擊者送出 0 個封包。任何以速率／比例／連線數為基礎的網路特徵"
        "都看不見這種攻擊者——這是量到的上限，不是模型不夠好。",
        file=sys.stderr,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("duration_sec", type=float,
                        help="偵察持續秒數（runner 契約要求有界）")
    parser.add_argument("--mode", choices=("silent-participant", "sniff"),
                        default="silent-participant")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="silent-participant 模式下的 discovery 輪詢間隔")
    parser.add_argument("--interface", default="lo",
                        help="sniff 模式的擷取介面")
    args = parser.parse_args()

    if not 1.0 <= args.duration_sec <= 300.0:
        print("⛔ duration 必須在 1..300 秒之間", file=sys.stderr)
        return 2

    if args.mode == "sniff":
        return _run_sniff(args.duration_sec, args.interface)
    return _run_silent_participant(args.duration_sec, args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
