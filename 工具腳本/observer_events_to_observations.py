#!/usr/bin/env python3
"""把 security_observer 的事件轉成 P2 契約格式的身份觀測。

輸入是 `firewall_lab/security_observer` 產生的事件 JSONL；輸出是契約要求的
`rtps_identity.jsonl`，每一列都通過 P2 的 `validate_identity_observation`。

**三種證據等級各自從哪裡來**（2026-08-26 實測，見
`文件/階段0_DDS認證證據_2026-08-26.md`）：

| 契約的 kind | 來源事件 | 備註 |
|---|---|---|
| `spdp_locator` | `participant_discovery` | GUID ＋ 宣告的 locator |
| `sedp_endpoint` | `endpoint_discovery` | GUID ＋ entity ＋ topic |
| `authenticated_identity` | `participant_discovery` ＋ `participant_authentication` | 需要 **AUTHORIZED** ＋ subject |

⚠️ **兩個必須講清楚的限制。**

1. **`source_ip` 取自對方宣告的 locator，不是封包的實際來源位址。**
   participant 可以宣告任意位址；契約的 claim boundary 說 SPDP 欄位是
   spoofable，指的就是這個。真正的歸因要拿封包擷取的來源 IP 與這裡的宣告值
   交叉比對，兩者不一致本身就是訊號。這支工具**不做**那個比對，
   因為封包解碼器還沒寫。

2. **認證失敗的 participant 產不出任何一種契約證據。**
   它沒有經驗證的 subject（連宣稱的都沒有），所以不能記成
   `authenticated_identity`；剩下只能記成 `spdp_locator`，而那是可偽造的。
   契約缺一種「嘗試認證並被拒絕」的類型，已回報 Codex（C2C-040）。
   本工具會把這些 GUID 列在輸出旁的摘要裡，但**不會**塞進觀測檔假裝它是證據。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.identity_attribution import (  # noqa: E402
    validate_identity_observation,
)

SCHEMA = "sros2-firewall-rtps-identity-observation/v1"
_LOCATOR_IPV4 = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hex_bytes(dotted: str, expected: int) -> str | None:
    """Fast DDS 把 GUID 與 EntityId 印成點分隔的十六進位位元組，不補零。

    `0.0.1.c1` → `000001c1`。每一段都是十六進位，不是十進位——`10` 是 0x10。
    """

    parts = dotted.split(".")
    if len(parts) != expected:
        return None
    try:
        return "".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError:
        return None


def _first_ipv4(locators: str) -> str | None:
    for match in _LOCATOR_IPV4.finditer(locators or ""):
        candidate = match.group(1)
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4 and not address.is_multicast \
                and not address.is_unspecified:
            return str(address)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--security-mode", choices=["permissive", "enforce"],
                        required=True)
    parser.add_argument("--collector-id", required=True)
    parser.add_argument("--interface", default="lo")
    parser.add_argument("--capture", type=Path, default=None,
                        help="擷取檔；沒有的話用事件檔本身的雜湊，並在摘要標明")
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--decoder-sha256", default=None,
                        help="預設用本腳本自身的雜湊，讓 lineage 可追")
    parser.add_argument("--window-sec", type=float, default=8.0)
    parser.add_argument("--start-unix-ns", type=int, default=None)
    args = parser.parse_args()

    if args.output.exists():
        print(f"⛔ {args.output} 已存在，拒絕覆寫", file=sys.stderr)
        return 1

    rows = [json.loads(line) for line in
            args.events.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        print("⛔ 事件檔是空的", file=sys.stderr)
        return 1

    capture_sha = _sha256_file(args.capture) if args.capture else \
        _sha256_file(args.events)
    decoder_sha = args.decoder_sha256 or _sha256_file(Path(__file__))

    # 先把每個 GUID 的樣貌拼起來：認證結果、宣稱的 subject、宣告的位址。
    profile: dict[str, dict] = {}
    for row in rows:
        prefix = str(row.get("guid", "")).split("|")[0]
        if not prefix:
            continue
        entry = profile.setdefault(prefix, {
            "authorized": False, "rejected": False,
            "subject": "", "locators": "", "endpoints": []})
        if row["event"] == "participant_authentication":
            if row["status"] == "AUTHORIZED":
                entry["authorized"] = True
            else:
                entry["rejected"] = True
        elif row["event"] == "participant_discovery":
            entry["subject"] = row.get("claimed_subject") or entry["subject"]
            entry["locators"] = row.get("announced_locators") or entry["locators"]
        elif row["event"] == "endpoint_discovery":
            entity = str(row.get("guid", "")).split("|")[-1]
            entry["endpoints"].append((entity, row.get("topic", "")))

    base_ns = args.start_unix_ns or 1_787_000_000_000_000_000
    observations: list[dict] = []
    skipped: list[str] = []

    def add(prefix: str, kind: str, *, source_ip: str, entity=None, topic=None,
            subject=None, permission_state="unknown") -> None:
        index = len(observations)
        observations.append({
            "schema_version": SCHEMA,
            "session_id": args.session_id,
            "sequence": index,
            "ts_unix_ns": base_ns + index * 1_000_000,
            "window": int(index * 0.001 / args.window_sec),
            "collector_id": args.collector_id,
            "capture_sha256": capture_sha,
            "decoder_sha256": decoder_sha,
            "policy_sha256": args.policy_sha256,
            "security_mode": args.security_mode,
            "source_ip": source_ip,
            "interface": args.interface,
            "guid_prefix": prefix,
            "entity_id": entity,
            "topic": topic,
            "evidence_kind": kind,
            "identity_subject_sha256": subject,
            "permission_state": permission_state,
        })

    for dotted, entry in profile.items():
        prefix = _hex_bytes(dotted, 12)
        if prefix is None:
            skipped.append(f"{dotted}: GUID prefix 解析失敗")
            continue
        address = _first_ipv4(entry["locators"])
        if address is None:
            # 沒有宣告位址就沒有 source_ip，契約要求它必須是合法 IPv4。
            # 不要編一個出來——那會把「沒觀測到」變成「觀測到某個位址」。
            skipped.append(f"{dotted}: 沒有可用的 IPv4 宣告位址")
            continue

        add(prefix, "spdp_locator", source_ip=address)

        for entity_dotted, topic in entry["endpoints"]:
            entity = _hex_bytes(entity_dotted, 4)
            if entity is None or not topic:
                skipped.append(f"{dotted}/{entity_dotted}: entity 或 topic 缺漏")
                continue
            add(prefix, "sedp_endpoint", source_ip=address,
                entity=entity, topic=topic, permission_state="allow")

        if entry["authorized"] and entry["subject"]:
            add(prefix, "authenticated_identity", source_ip=address,
                subject=_sha256_text(entry["subject"]), permission_state="allow")
        elif entry["rejected"]:
            # 認證被拒的 participant 沒有經驗證的 subject，契約沒有對應的
            # 證據類型。不要塞進去假裝它是證據——這是刻意的空缺。
            skipped.append(f"{dotted}: 認證遭拒，契約無對應證據類型")

    if not observations:
        print("⛔ 沒有產生任何合法觀測", file=sys.stderr)
        for line in skipped:
            print(f"   略過 {line}", file=sys.stderr)
        return 1

    for row in observations:
        validate_identity_observation(row)

    args.output.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True)
                  for row in observations) + "\n",
        encoding="utf-8")

    kinds: dict[str, int] = {}
    for row in observations:
        kinds[row["evidence_kind"]] = kinds.get(row["evidence_kind"], 0) + 1
    print(f"=== 產生 {len(observations)} 筆觀測（全部通過 P2 驗證器）===")
    for kind, count in sorted(kinds.items()):
        print(f"  {kind:24s} {count}")
    if skipped:
        print(f"\n略過 {len(skipped)} 項：")
        for line in skipped:
            print(f"  {line}")
    if args.capture is None:
        print("\n⚠️ 沒有提供 --capture，capture_sha256 用的是事件檔本身的雜湊。")
    print(f"\n→ {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
