#!/usr/bin/env python3
"""產生把 Fast DDS 釘在單一介面位址上的 profile。

## 為什麼需要

WSL 的 `networkingMode=mirrored` 會在 `lo` 上放一個 **scope global** 的
`10.255.255.254/32`。Fast DDS 列舉介面時會把它當成可用的單播 locator，
locator 選擇因此走錯，**discovery 完全靜默失敗**——沒有錯誤訊息、沒有例外、
節點正常啟動，只是永遠收不到對方。

2026-08-27 實測（同機 talker／listener，domain 隔離）：

| whitelist | 發 | 收 |
|---|---:|---:|
| 不設（預設） | 10 | **0** |
| 只有 `127.0.0.1` | 10 | **0** |
| 介面位址 ＋ `127.0.0.1` | 10 | **0** |
| **只有真實介面位址** | 10 | **8** ✅ |

**把 loopback 放進 whitelist 就會壞**，所以這支刻意不提供「加上 loopback」的
選項。

## 為什麼要產生而不是放一份固定檔

位址跟著網路走。家裡是 `192.168.0.x`、在外面是 `10.1.x.x`，而 mirrored 之後
介面名也不固定（實測看過 `eth1` 與 `eth2`）。寫死一份檔案的後果是換個網路
就靜默失效——與它要修的那個問題一模一樣。

## 用法

    eval "$(python3 工具腳本/make_fastdds_profile.py --print-export)"

或

    python3 工具腳本/make_fastdds_profile.py --output /tmp/fastdds.xml
    export FASTRTPS_DEFAULT_PROFILES_FILE=/tmp/fastdds.xml

⚠️ 這只影響**經由 rmw 建立**的 participant（ROS 節點）。用 Fast DDS API 直接
建立並自帶 QoS 的程式（本專案的 `security_observer`、`guard_filter` 之外的
觀測者）不吃這份 profile，要在程式裡自己設。
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import sys
from pathlib import Path

TEMPLATE = """<?xml version="1.0" encoding="UTF-8" ?>
<!-- 產生者：工具腳本/make_fastdds_profile.py
     釘住的介面：{interface} ({address})
     不要手改：位址跟著網路走，改壞了 discovery 會靜默失敗。 -->
<dds xmlns="http://www.eprosima.com">
  <profiles>
    <transport_descriptors>
      <transport_descriptor>
        <transport_id>udp_pinned</transport_id>
        <type>UDPv4</type>
        <interfaceWhiteList>
          <address>{address}</address>
        </interfaceWhiteList>
      </transport_descriptor>
    </transport_descriptors>
    <participant profile_name="pinned" is_default_profile="true">
      <rtps>
        <userTransports>
          <transport_id>udp_pinned</transport_id>
        </userTransports>
        <useBuiltinTransports>false</useBuiltinTransports>
      </rtps>
    </participant>
  </profiles>
</dds>
"""


def discover_interface(preferred: str | None) -> tuple[str, str]:
    """找出要釘住的介面與位址。

    刻意排除 loopback、docker 與 mirrored 塞在 `lo` 上的那個位址——
    把它們任何一個放進 whitelist 都會讓 discovery 靜默失敗。
    """
    if shutil.which("ip") is None:
        raise SystemExit("⛔ 找不到 ip 指令")
    output = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                            capture_output=True, text=True, check=True).stdout

    candidates: list[tuple[str, str]] = []
    for line in output.splitlines():
        match = re.match(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)",
                         line.strip())
        if not match:
            continue
        interface, address, prefix = match.groups()
        if interface == "lo" or interface.startswith(("docker", "br-", "veth")):
            continue
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.is_loopback or parsed.is_link_local:
            continue
        # /32 在真實介面上不是常態，而 mirrored 塞的那個正好是 /32。
        if int(prefix) >= 32:
            continue
        candidates.append((interface, address))

    if preferred:
        for interface, address in candidates:
            if interface == preferred:
                return interface, address
        raise SystemExit(
            f"⛔ 介面 {preferred} 沒有可用的 IPv4，候選：{candidates}")
    if not candidates:
        raise SystemExit("⛔ 找不到任何可用的非 loopback IPv4 介面")
    if len(candidates) > 1:
        print(f"ℹ️  有多個候選 {candidates}，採用第一個。"
              f"要指定請用 --interface。", file=sys.stderr)
    return candidates[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default=None,
                        help="指定介面；不給就自動挑第一個非 loopback 的")
    parser.add_argument("--output", type=Path,
                        default=Path.home() / ".fastdds_pinned.xml")
    parser.add_argument("--print-export", action="store_true",
                        help="印出可以 eval 的 export 指令")
    args = parser.parse_args()

    interface, address = discover_interface(args.interface)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        TEMPLATE.format(interface=interface, address=address),
        encoding="utf-8", newline="\n")

    if args.print_export:
        print(f'export FASTRTPS_DEFAULT_PROFILES_FILE="{args.output}"')
    else:
        print(f"釘住 {interface} = {address}")
        print(f"→ {args.output}")
        print(f'export FASTRTPS_DEFAULT_PROFILES_FILE="{args.output}"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
