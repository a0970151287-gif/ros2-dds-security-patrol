#!/usr/bin/env python3
"""用鏈路層綁定鑑別「來源位址偽造」，這是自動封鎖最危險的失效方向。

## 威脅

同一個 L2 網段上的攻擊者可以偽造 UDP 來源位址：

1. 攻擊者以**受害者的 IP** 為來源，送出帶自己 GUID 的 RTPS
2. 握手必然失敗（防守方的回應被送到受害者那裡去了）→ 觀測者記下 `UNAUTHORIZED`
3. 封包層把那個 GUID 綁到**受害者的 IP**
4. 現行三條判定全部成立 → **系統宣告受害者的 IP 可封鎖**

2026-08-30 那批 79／80 的陰性對照**測不到它**：對照組是防守方自己，
不是被偽造的第三方。

## 鑑別方式（完全被動，不需要送任何封包）

防守方送往某個 IP 時，`eth.dst` 是**它自己的 ARP 解析結果**；從該 IP 收到的
封包，`eth.src` 是**實際發送者**的 MAC。偽造來源時這兩個必然不同——回應會被
送到真正持有那個 IP 的主機。

    收到  ip.src=X  eth.src=<攻擊者的 MAC>
    送出  ip.dst=X  eth.dst=<X 真正持有者的 MAC>   ← ARP 解析出來的

所以判準是：**`eth.src(收到 X 的封包)` 必須等於 `eth.dst(送往 X 的封包)`。**

受害者若根本不存在，防守方連 ARP 都解析不到，就不會有送往該 IP 的單播流量
——那時同樣不可封鎖（無法驗證，不是驗證通過）。

## 界線

- 攻擊者若同時偽造 MAC，這個檢查會被繞過。但那樣它也收不到回應，而且在
  WPA2／WPA3 下 AP 以 MAC 對應 station，偽造 MAC 的代價與可見度都更高。
- 多播／廣播的目的 MAC 是從 IP 算出來的、不經 ARP，所以一律排除。
- 這是**必要條件不是充分條件**。它擋掉的是「偽造來源」這一種失效，
  不代表通過的位址就一定該封鎖。
- `other_ips_on_same_mac` 是**正面證據但不是定論**：路由器與 NAT 會用一張
  MAC 送出許多來源位址。它不會讓 verdict 升級成 `spoofing_evidence`，
  只讓理由從「查不到」變成「這張網卡還宣稱了別的位址」。

## 用法

    python3 工具腳本/check_link_layer_binding.py \\
        --capture <session>/traffic.pcapng \\
        --output <session>/link_layer_binding.json
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

SCHEMA = "sros2-firewall-link-layer-binding/v1"
FIELDS = ("eth.src", "eth.dst", "ip.src", "ip.dst")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_group_mac(mac: str) -> bool:
    """多播／廣播 MAC：第一個位元組的最低位為 1。

    這種目的 MAC 是從 IP 算出來的，不經 ARP，所以不能拿來當「解析結果」。
    """
    try:
        return bool(int(mac.split(":")[0], 16) & 1)
    except (ValueError, IndexError):
        return True


def _unicast_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.version == 4
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def run_tshark(capture: Path, display_filter: str) -> list[tuple[str, ...]]:
    argv = ["tshark", "-r", str(capture)]
    if display_filter:
        argv += ["-Y", display_filter]
    argv += ["-T", "fields"]
    for field in FIELDS:
        argv += ["-e", field]
    argv += ["-E", "separator=|", "-E", "occurrence=f"]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, check=True, timeout=600
        )
    except FileNotFoundError:
        raise SystemExit("⛔ 找不到 tshark。請安裝 wireshark-common。")
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"⛔ tshark 失敗：{error.stderr[:400]}")
    rows = []
    for line in completed.stdout.splitlines():
        parts = line.split("|")
        if len(parts) == len(FIELDS):
            rows.append(tuple(p.strip().lower() for p in parts))
    return rows


def build_bindings(rows: list[tuple[str, ...]]) -> dict[str, dict]:
    """逐 IP 統計「收到時的來源 MAC」與「送出時解析到的目的 MAC」。"""
    observed: dict[str, set[str]] = defaultdict(set)   # ip -> eth.src
    resolved: dict[str, set[str]] = defaultdict(set)   # ip -> eth.dst（單播）
    frames_from: dict[str, int] = defaultdict(int)
    frames_to: dict[str, int] = defaultdict(int)
    mac_to_ips: dict[str, set[str]] = defaultdict(set)

    for eth_src, eth_dst, ip_src, ip_dst in rows:
        if eth_src and ip_src and _unicast_ipv4(ip_src):
            observed[ip_src].add(eth_src)
            frames_from[ip_src] += 1
            mac_to_ips[eth_src].add(ip_src)
        if eth_dst and ip_dst and _unicast_ipv4(ip_dst) \
                and not _is_group_mac(eth_dst):
            resolved[ip_dst].add(eth_dst)
            frames_to[ip_dst] += 1

    result: dict[str, dict] = {}
    for address in sorted(set(observed) | set(resolved)):
        seen = sorted(observed.get(address, set()))
        arp = sorted(resolved.get(address, set()))

        reasons: list[str] = []
        if not seen:
            reasons.append("沒有從此位址收到任何封包")
        if not arp:
            reasons.append(
                "沒有送往此位址的單播流量，取不到 ARP 解析出的 MAC"
                "（無法驗證，不是驗證通過）"
            )
        disjoint = bool(seen and arp and not (set(seen) & set(arp)))
        if disjoint:
            # 發送者與該位址的 ARP 持有者完全沒有交集。回應會被送到別人那裡，
            # 所以發送者收不到——這是偽造來源的確證。
            reasons.append(
                f"來源 MAC {seen} 與解析出的 MAC {arp} 完全不相交："
                "發送者不是此位址的持有者，回應送不到它手上"
            )
        elif len(seen) > 1 or len(arp) > 1:
            # 陳述觀測，不自行選一個成因。實測防守方自己的位址就會這樣：
            # WSL mirrored 讓同一個 IP 同時出現在實體與虛擬介面上。
            reasons.append(
                f"此位址有 {len(seen)} 個來源 MAC、{len(arp)} 個解析 MAC。"
                "可能是同一台主機的多張介面（WSL mirrored 會讓實體與虛擬 MAC "
                "同時出現），也可能是有人在偽造這個位址。分不出來就不可封鎖"
            )

        consistent = (
            len(seen) == 1 and len(arp) == 1 and set(seen) == set(arp)
        )
        # 同一個 MAC 帶著多個 IP。路由器與 NAT 本來就會這樣，所以單獨不足以
        # 斷定偽造——但它是**正面證據**，比「查不到」有力得多，要講出來。
        #
        # 2026-09-01 的 live 偽造測試實測到：
        #   192.168.0.200  來源 MAC e8:65:…:2f  同 MAC 其他 IP: ['192.168.0.30']
        # 攻擊者一邊用自己的位址、一邊偽造別人的，兩者共用同一張網卡。
        shared = sorted(
            mac_to_ips.get(seen[0], set()) - {address}
        ) if len(seen) == 1 else []
        notes: list[str] = []
        if shared:
            notes.append(
                f"此位址的來源 MAC {seen[0]} 還宣稱了 {shared}"
                "——同一張網卡同時使用多個位址。路由器與 NAT 也會這樣，"
                "所以不足以單獨斷定偽造；但封鎖此位址並不會擋住那個發送端，"
                "它換另一個位址就繼續"
            )
            if not consistent:
                # 判定不是 consistent 時，這是不可封鎖的一個**正面**理由，
                # 比「查不到」有力。
                reasons.extend(notes)

        result[address] = {
            "source_macs": seen,
            "resolved_macs": arp,
            "frames_from": frames_from.get(address, 0),
            "frames_to": frames_to.get(address, 0),
            "bidirectional": bool(
                frames_from.get(address) and frames_to.get(address)
            ),
            "link_layer_consistent": consistent,
            # 三級：consistent（可用）／spoofing_evidence（確證偽造）／
            # unverifiable（觀測不足或有歧義）。下游只在 consistent 時放行。
            "verdict": (
                "consistent" if consistent
                else "spoofing_evidence" if disjoint
                else "unverifiable"
            ),
            "other_ips_on_same_mac": shared,
            # 讓下游不必自己重算。判定仍然保守，這只是把證據攤開。
            "mac_claims_multiple_addresses": bool(shared),
            # 與 reasons_inconsistent 分開：consistent 的位址也可能帶著這條
            # 資訊（實測 192.168.0.30 就是——它自己合規，同時在偽造別人）。
            "notes": notes,
            "reasons_inconsistent": reasons,
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--display-filter",
        default="",
        help=(
            "只看某些封包。預設看全部——ARP 解析出的 MAC 可能出現在非 RTPS "
            "的流量上，限制成 rtps 會漏掉它。"
        ),
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        print(f"⛔ {args.output} 已存在，拒絕覆寫", file=sys.stderr)
        return 1
    if not args.capture.is_file():
        print(f"⛔ 找不到擷取檔：{args.capture}", file=sys.stderr)
        return 1

    rows = run_tshark(args.capture, args.display_filter)
    bindings = build_bindings(rows)

    payload = {
        "schema_version": SCHEMA,
        "capture": str(args.capture),
        "capture_sha256": _sha256_file(args.capture),
        "checker_sha256": _sha256_file(Path(__file__)),
        "display_filter": args.display_filter,
        "frames_examined": len(rows),
        "per_ip": bindings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"  檢查 {len(rows)} 個框，{len(bindings)} 個 IPv4 單播位址")
    for address, info in bindings.items():
        mark = "✅" if info["link_layer_consistent"] else "⚠️ "
        print(f"  {mark} {address:<18}"
              f"來源 MAC {info['source_macs'] or '—'}  "
              f"解析 MAC {info['resolved_macs'] or '—'}")
        for reason in info["reasons_inconsistent"]:
            print(f"        {reason}")
    print(f"\n  輸出：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
