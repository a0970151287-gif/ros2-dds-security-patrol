#!/usr/bin/env python3
"""Generate deterministic offline pcaps for ``dds_monitor.zeek``.

The fixtures use only the Python standard library and never send network
traffic.  They model domain-30 RTPS-looking UDP flows closely enough for Zeek
connection and payload events.
"""
from __future__ import annotations

import argparse
import socket
import struct
from pathlib import Path

def ipv4_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return (~s) & 0xFFFF

def eth(dst, src):
    return dst + src + b"\x08\x00"

def ipv4(src_ip, dst_ip, payload_len, proto=17):
    ver_ihl = 0x45
    tos = 0
    total = 20 + payload_len
    ident = 0
    flags_frag = 0
    ttl = 64
    chk = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ident,
                      flags_frag, ttl, proto, chk, src, dst)
    chk = ipv4_checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ident,
                       flags_frag, ttl, proto, chk, src, dst)

def udp(sport, dport, payload):
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload

def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))

MAC_A = mac("02:00:00:00:00:01")
MAC_T = mac("34:5a:60:96:c3:ca")
MAC_MC = mac("01:00:5e:7f:00:01")
RTPS = b"RTPS\x02\x03" + b"\x00" * 20

def frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    u = udp(sport, dport, payload)
    ip = ipv4(src_ip, dst_ip, len(u))
    return eth(dst_mac, src_mac) + ip + u


def spdp_packets(
    source: str,
    count: int,
    *,
    start: float,
    step: float = 0.1,
    first_port: int = 40000,
):
    """Return unique SPDP flows so Zeek emits one new_connection per packet."""
    return [
        (
            start + index * step,
            frame(
                MAC_A,
                MAC_MC,
                source,
                "239.255.0.1",
                first_port + index,
                14900,
                RTPS,
            ),
        )
        for index in range(count)
    ]


def baseline_packets():
    """Existing five-rule regression plus one trusted-source FPR check."""
    packets = [
        (
            0.0,
            frame(
                MAC_T,
                MAC_MC,
                "10.10.10.2",
                "239.255.0.1",
                14900,
                14900,
                RTPS,
            ),
        ),
        (
            1.0,
            frame(
                MAC_A,
                MAC_MC,
                "10.10.10.1",
                "239.255.0.1",
                14910,
                14900,
                RTPS,
            ),
        ),
    ]
    injected = (
        b"RTPS\x02\x03" + b"\x00" * 8 + b"[INJECTED] forged cmd_vel"
    )
    packets.append(
        (
            2.0,
            frame(
                MAC_A,
                MAC_T,
                "10.10.10.1",
                "10.10.10.2",
                14913,
                14913,
                injected,
            ),
        )
    )
    packets.extend(
        spdp_packets("10.10.10.1", 30, start=3.0, first_port=40000)
    )
    parameter = (
        b"RTPS\x02\x03"
        + b"\x00" * 8
        + b"rq/listener/set_parametersRequest use_sim_time"
    )
    packets.append(
        (
            7.0,
            frame(
                MAC_A,
                MAC_T,
                "10.10.10.1",
                "10.10.10.2",
                14914,
                14913,
                parameter,
            ),
        )
    )
    packets.append(
        (
            8.0,
            frame(
                MAC_A,
                MAC_MC,
                "10.10.10.2",
                "239.255.0.1",
                14910,
                14900,
                RTPS,
            ),
        )
    )
    return packets


def build_case(case: str):
    if case == "baseline":
        return baseline_packets()
    if case == "single-source-threshold":
        return spdp_packets("10.10.10.1", 25, start=1.0)
    if case == "mixed-sources":
        packets = spdp_packets("10.10.10.1", 24, start=1.0)
        packets.extend(
            spdp_packets(
                "10.10.10.3",
                1,
                start=3.4,
                first_port=50000,
            )
        )
        return packets
    if case == "cross-window":
        packets = spdp_packets("10.10.10.1", 24, start=1.0)
        packets.extend(
            spdp_packets(
                "10.10.10.1",
                1,
                start=12.0,
                first_port=50000,
            )
        )
        return packets
    if case == "capacity":
        packets = []
        for index, source in enumerate(
            ("10.20.0.1", "10.20.0.2", "10.20.0.3")
        ):
            packets.extend(
                spdp_packets(
                    source,
                    1,
                    start=1.0 + index * 0.1,
                    first_port=50000 + index,
                )
            )
        return packets
    raise ValueError(f"unknown fixture case: {case}")


def write_pcap(path: Path, packets) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        # pcap global header: magic, v2.4, UTC, snaplen, Ethernet.
        handle.write(
            struct.pack("!IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        )
        for timestamp, data in sorted(packets, key=lambda item: item[0]):
            seconds = int(timestamp)
            microseconds = int((timestamp - seconds) * 1_000_000)
            handle.write(
                struct.pack(
                    "!IIII",
                    seconds,
                    microseconds,
                    len(data),
                    len(data),
                )
            )
            handle.write(data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=Path(
            "/home/jesse/ros2_ws/Zeek監控/test/dds_attack_test.pcap"
        ),
    )
    parser.add_argument(
        "--case",
        choices=(
            "baseline",
            "single-source-threshold",
            "mixed-sources",
            "cross-window",
            "capacity",
        ),
        default="baseline",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    packets = build_case(args.case)
    write_pcap(args.output, packets)
    print(f"寫出 {args.output}：{len(packets)} 個封包（{args.case}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
