#!/usr/bin/env python3
"""在燒掉一輪 live 收集之前，先確認封包真的到得了。

**為什麼需要這個**：DDS 的 discovery 走 UDP。如果封包根本沒到，
產出的證據會是「觀測者什麼都沒記到」——與**防禦成功攔阻**外觀完全相同。
這個專案已經被同一類混淆咬過五次（N1 的 QoS 不相容、8,192 點 scan 在傳輸層
被丟、marker 全檔掃描撐爆視窗、FastCDR 不一致讓 discovery 靜默失效、
攻擊機位址從未出現在擷取檔）。所以先量，不要賭。

`ping` 不夠：那是 ICMP。防火牆放行 ICMP 而擋掉 UDP 是很常見的設定，
而 Wi-Fi 的 AP 可能只吃掉多播、單播照常。**這兩條路要分開量。**

本工具同時測兩條路，因為它們的失敗意義完全不同：

| 路徑 | 通了代表 | 不通代表 |
|---|---|---|
| **單播** SPDP 埠 | 觀測者的 `OBSERVER_PEERS` 可用 | 防火牆擋 UDP，或跨網段 |
| **多播** 239.255.0.1 | 預設 discovery 可用 | AP 吃掉多播（Wi-Fi 常見），但單播仍可救 |

單播通、多播不通**仍然可以跑**——那正是 `OBSERVER_PEERS` 存在的理由。
兩條都不通才是真的要先修網路。

## 用法

防守端（先跑，會佔用 SPDP 埠，所以不能與觀測者同時跑）：

    python3 工具腳本/check_udp_reachability.py --listen --domain 30 --seconds 60

攻擊端：

    python3 check_udp_reachability.py --send --target <防守機IP> --domain 30

送的是自訂的探測字串，不是 RTPS 封包——這不是攻擊流量，只是可達性量測。
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
from pathlib import Path

MULTICAST_GROUP = "239.255.0.1"
PROBE_MAGIC = b"SROS2-FIREWALL-REACHABILITY-PROBE/v1"


def spdp_ports(domain: int) -> tuple[int, int]:
    """RTPS 的 well-known 埠。

    多播  : PB + DG*domain + d0
    單播  : PB + DG*domain + d1 + PG*participant_id
    以 OMG 預設 PB=7400、DG=250、PG=2、d0=0、d1=10、participant_id=0 計算。
    """
    base = 7400 + 250 * domain
    return base, base + 10


def listen(domain: int, seconds: int, output: Path | None) -> int:
    multicast_port, unicast_port = spdp_ports(domain)

    unicast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    unicast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        unicast.bind(("", unicast_port))
    except OSError as error:
        print(f"⛔ 綁不上單播埠 {unicast_port}：{error}", file=sys.stderr)
        print("   最可能的原因是觀測者或某個 ROS 節點正在跑，先把它停掉。",
              file=sys.stderr)
        return 2

    multicast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    multicast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    multicast.bind(("", multicast_port))
    membership = struct.pack("4s4s", socket.inet_aton(MULTICAST_GROUP),
                             socket.inet_aton("0.0.0.0"))
    multicast.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                         membership)

    unicast.setblocking(False)
    multicast.setblocking(False)

    print(f"監聽 {seconds} 秒 —— domain {domain}")
    print(f"  單播 UDP :{unicast_port}")
    print(f"  多播 {MULTICAST_GROUP}:{multicast_port}")
    print("  請在這段時間內於攻擊機執行 --send")
    print()

    seen: dict[str, dict[str, int]] = {}
    deadline = time.monotonic() + seconds
    import selectors
    selector = selectors.DefaultSelector()
    selector.register(unicast, selectors.EVENT_READ, "unicast")
    selector.register(multicast, selectors.EVENT_READ, "multicast")

    while time.monotonic() < deadline:
        for key, _ in selector.select(timeout=0.5):
            payload, address = key.fileobj.recvfrom(4096)
            if not payload.startswith(PROBE_MAGIC):
                # 真的 RTPS 流量也會打到這些埠。只算我們自己的探測，
                # 否則「有封包」會被既有節點的雜訊灌成永遠成立。
                continue
            entry = seen.setdefault(address[0], {"unicast": 0, "multicast": 0})
            entry[key.data] += 1
            print(f"  ← {key.data:9s} 來自 {address[0]}")

    selector.close()
    unicast.close()
    multicast.close()

    unicast_ok = any(v["unicast"] for v in seen.values())
    multicast_ok = any(v["multicast"] for v in seen.values())

    print()
    print("=== 結果 ===")
    for address, counts in sorted(seen.items()):
        print(f"  {address:16s} 單播 {counts['unicast']:3d}  "
              f"多播 {counts['multicast']:3d}")
    if not seen:
        print("  （沒有收到任何探測）")
    print()

    if unicast_ok and multicast_ok:
        verdict = "both"
        print("  ✅ 兩條路都通。可以直接跑跨主機收集。")
    elif unicast_ok:
        verdict = "unicast_only"
        print("  ⚠️ 只有單播通，多播被吃掉了（Wi-Fi 很常見）。")
        print("     **仍然可以跑**，但必須設 ATTACKER_IP，讓觀測者用")
        print("     unicast initial peer，不要依賴多播。")
    elif multicast_ok:
        verdict = "multicast_only"
        print("  ⚠️ 只有多播通，單播不通——這個組合很少見，")
        print("     通常是防火牆針對特定埠。跑之前先弄清楚。")
    else:
        verdict = "none"
        print("  ⛔ 兩條路都不通。**現在跑一定會拿到空證據**，")
        print("     而空證據跟「防禦成功」長得一模一樣。先修網路。")
        print("     常見原因：防火牆擋 UDP、AP isolation、兩台不同網段。")

    if output is not None:
        output.write_text(json.dumps({
            "domain": domain,
            "unicast_port": unicast_port,
            "multicast_port": multicast_port,
            "sources": seen,
            "unicast_reachable": unicast_ok,
            "multicast_reachable": multicast_ok,
            "verdict": verdict,
            "safe_to_collect": unicast_ok,
        }, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(f"\n→ {output}")

    return 0 if unicast_ok else 1


def send(target: str, domain: int, count: int) -> int:
    multicast_port, unicast_port = spdp_ports(domain)
    payload = PROBE_MAGIC + b" from sender"

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)

    for index in range(count):
        sender.sendto(payload, (target, unicast_port))
        sender.sendto(payload, (MULTICAST_GROUP, multicast_port))
        print(f"  → {index + 1}/{count}  單播 {target}:{unicast_port}  "
              f"多播 {MULTICAST_GROUP}:{multicast_port}")
        time.sleep(0.5)
    sender.close()

    print()
    print("送完了。結果要看**防守端**的輸出——這邊送出去成功不代表對面收到，")
    print("UDP 沒有回執。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--listen", action="store_true", help="防守端")
    mode.add_argument("--send", action="store_true", help="攻擊端")
    parser.add_argument("--domain", type=int, default=30)
    parser.add_argument("--seconds", type=int, default=60,
                        help="--listen：監聽多久")
    parser.add_argument("--target", help="--send：防守機的 IPv4")
    parser.add_argument("--count", type=int, default=10,
                        help="--send：送幾組")
    parser.add_argument("--output", type=Path, default=None,
                        help="--listen：把結果寫成 JSON")
    args = parser.parse_args()

    if not 0 <= args.domain <= 232:
        print("⛔ domain 必須在 0–232", file=sys.stderr)
        return 2

    if args.send:
        if not args.target:
            print("⛔ --send 需要 --target", file=sys.stderr)
            return 2
        return send(args.target, args.domain, args.count)
    return listen(args.domain, args.seconds, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
