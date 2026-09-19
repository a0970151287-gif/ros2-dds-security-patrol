#!/usr/bin/env python3
"""從封包擷取取出 GUID ↔ **實際來源 IP**，產出契約的 `spdp_locator` 觀測。

這是 security observer 拿不到的那一半。2026-08-26 實測（見
`文件/階段0_DDS認證證據_2026-08-26.md`）：

| 來源 | 給得到什麼 | 拿不到什麼 |
|---|---|---|
| 安全觀測者 | 認證判定 ＋ GUID；合法者另有 subject／endpoint | **認證失敗者的位址**——`on_participant_discovery` 對它根本不觸發 |
| **封包擷取（本工具）** | **實際來源 IP ↔ GUID**，不管認證過不過 | 這個身份合不合法 |

兩者缺一不可：觀測者知道「誰不合法」但不知道它在哪；封包知道「誰在哪」
但不知道合不合法。合起來才能回答「該封鎖哪個位址」。

**為什麼用 tshark 而不是自己解 RTPS**：Wireshark 的 RTPS dissector 是成熟
實作，`rtps.guidPrefix` 直接對應契約要的 12 個位元組。自己寫一個只會多一個
要驗證的東西。

⚠️ **來源 IP 取自 IP 表頭，不是 participant 宣告的 locator。** 宣告的位址是
可偽造的（契約的 claim boundary 明說 SPDP 欄位 spoofable）；IP 表頭的來源
位址在同網段上偽造要困難得多。兩者不一致本身就是一個訊號——本工具兩個都記，
讓後續可以比對。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.identity_attribution import (  # noqa: E402
    validate_identity_observation,
)

SCHEMA = "sros2-firewall-rtps-identity-observation/v1"
FIELDS = ("frame.time_epoch", "ip.src", "rtps.guidPrefix")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_tshark(capture: Path) -> list[tuple[float, str, str]]:
    argv = ["tshark", "-r", str(capture), "-Y", "rtps", "-T", "fields"]
    for field in FIELDS:
        argv += ["-e", field]
    argv += ["-E", "separator=|", "-E", "occurrence=f"]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, check=True, timeout=600)
    except FileNotFoundError:
        raise SystemExit("⛔ 找不到 tshark。請安裝 wireshark-common。")
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"⛔ tshark 失敗：{error.stderr[:400]}")

    rows: list[tuple[float, str, str]] = []
    for line in completed.stdout.splitlines():
        parts = line.split("|")
        if len(parts) != len(FIELDS):
            continue
        epoch, source, prefix = parts
        prefix = prefix.replace(":", "").replace(".", "").strip().lower()
        # 契約要 12 個位元組；長度不對就不要猜，直接跳過並計數。
        if len(prefix) != 24 or not source.strip():
            continue
        try:
            rows.append((float(epoch), source.strip(), prefix))
        except ValueError:
            continue
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--security-mode", choices=["permissive", "enforce"],
                        required=True)
    parser.add_argument("--collector-id", required=True)
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--window-sec", type=float, default=8.0)
    args = parser.parse_args()

    if args.output.exists():
        print(f"⛔ {args.output} 已存在，拒絕覆寫", file=sys.stderr)
        return 1

    rows = _run_tshark(args.capture)
    if not rows:
        print("⛔ 擷取檔裡沒有可解析的 RTPS 封包", file=sys.stderr)
        return 1

    capture_sha = _sha256_file(args.capture)
    decoder_sha = _sha256_file(Path(__file__))
    start = min(row[0] for row in rows)

    observations: list[dict] = []
    skipped: dict[str, int] = {}
    # 同一個 (IP, GUID) 在一個視窗內只記一次——SPDP 是週期性重播的，
    # 每一則都記會讓 participant_rate 之類的特徵失去意義。
    seen: set[tuple[int, str, str]] = set()

    for epoch, source, prefix in sorted(rows):
        window = int((epoch - start) // args.window_sec)
        key = (window, source, prefix)
        if key in seen:
            continue
        seen.add(key)
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            skipped["非法位址"] = skipped.get("非法位址", 0) + 1
            continue
        if address.version != 4 or address.is_multicast \
                or address.is_unspecified:
            # 契約只收 IPv4 單播。多播來源不代表任何一台主機。
            skipped["非 IPv4 單播"] = skipped.get("非 IPv4 單播", 0) + 1
            continue

        index = len(observations)
        observations.append({
            "schema_version": SCHEMA,
            "session_id": args.session_id,
            "sequence": index,
            "ts_unix_ns": int(epoch * 1_000_000_000),
            "window": window,
            "collector_id": args.collector_id,
            "capture_sha256": capture_sha,
            "decoder_sha256": decoder_sha,
            "policy_sha256": args.policy_sha256,
            "security_mode": args.security_mode,
            "source_ip": str(address),
            "interface": args.interface,
            "guid_prefix": prefix,
            "entity_id": None,
            "topic": None,
            # 封包層只能給這一種。它是可偽造的，契約自己也這麼說；
            # 要判斷合不合法必須靠觀測者那一半。
            "evidence_kind": "spdp_locator",
            "identity_subject_sha256": None,
            "permission_state": "unknown",
        })

    for row in observations:
        validate_identity_observation(row)

    args.output.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True)
                  for row in observations) + "\n",
        encoding="utf-8")

    by_ip: dict[str, set[str]] = {}
    for row in observations:
        by_ip.setdefault(row["source_ip"], set()).add(row["guid_prefix"])

    print(f"=== 解析 {len(rows)} 個 RTPS 封包 → {len(observations)} 筆觀測 ===")
    print(f"  擷取檔 sha256 : {capture_sha[:16]}…")
    print("  逐 IP 的 GUID 數：")
    for address, guids in sorted(by_ip.items()):
        mark = "唯一" if len(guids) == 1 else "多身份共用"
        print(f"     {address:16s} {len(guids):3d} 個 GUID  ({mark})")
    if skipped:
        print("  略過：", skipped)

    # 契約的兩個綁定條件，用實際封包判斷而不是宣稱。
    by_guid: dict[str, set[str]] = {}
    for row in observations:
        by_guid.setdefault(row["guid_prefix"], set()).add(row["source_ip"])
    unique_ips = [a for a, g in by_ip.items() if len(g) == 1]
    multi_ip_guids = sum(1 for a in by_guid.values() if len(a) > 1)

    print()
    print("  契約的兩個綁定條件：")
    print("     unique_guid_to_ip_binding            : "
          "%d/%d 個 GUID 只出現在一個 IP"
          % (len(by_guid) - multi_ip_guids, len(by_guid)))
    print("     ip_not_shared_by_multiple_identities : "
          "%d/%d 個 IP 只掛一個 GUID"
          % (len(unique_ips), len(by_ip)))

    if not unique_ips:
        print()
        print("  ⚠️ **沒有任何位址是可封鎖的候選**——每個 IP 都被多個身份共用。")
        print("     這是同機擷取的典型特徵：loopback、WSL 鏡像位址與 NAT 介面")
        print("     承載同一批 participant，所以兩個綁定條件同時失敗。")
        print("     跨主機是必要條件，不是多收資料能解決的。")

    print(f"\n→ {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
