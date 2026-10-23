#!/usr/bin/env python3
"""把身份歸因接到真核心封鎖——這條鏈從來沒有連著跑過一次。

## 為什麼需要這一支

四個零件現在各自都有 live 證據：

| 零件 | 證據 |
|---|---|
| 身份歸因 | 2026-08-30 跨主機 79／80，四條判定，鏈路層回驗零撤回 |
| 可撤銷票 | 2026-08-27 守衛鏈 7／7，啟用 0.0365s、撤銷 0.0109s |
| 真核心 nftables | 2026-09-24 Pi 5 上九項全過，`production_ready=True` |
| Pi 當 ROS 閘道 | 2026-09-24 八節點 Enforce 8／8 |

**但它們從來沒有當成一條鏈跑過**，而那正是 r5 帳本裡唯一一個 `blocked` 的
claim（`autonomous_ip_block`）。這一支就是那條缺掉的縫。

## 它刻意不做的事

- **不分類、不跑模型。** `executable_classes` 是空清單，沒有任何模型判定到得了
  backend，這一支也不繞過它。
- **不收證據。** 歸因報告由 `run_crosshost_identity.sh` 那條既有流程產生；
  這一支只讀一份**已經完成**的報告。
- **不自己決定要不要動手。** 見下一節。

## 授權從哪裡來——這一點不可以含糊

`crosscheck_identity_attribution.py` 的報告裡明寫著 `authorizes_action: false`。
它回答的是「證據支不支持」，不是「可不可以動手」。

所以這一支把兩件事分開：

    封鎖的**對象**   ← 來自證據（報告裡唯一那個 blockable IP）
    動手的**權限**   ← 來自人（Jesse 手打的核准片語）

`evidence_id` 取**那份報告檔案自己的 SHA-256**。票因此在密碼學上綁定到
justify 它的那份證據——事後可以證明「是這份證據授權了這次封鎖」。
2026-09-24 的 nft 驗收做不到這件事：它自己給自己的票貼標籤。

## 九項檢查

前四項在碰到核心**之前**跑完，任一不過就中止：

1. `attribution_report_schema_v2` — v1 沒有鏈路層那一條
2. `attribution_verified_and_single_target` — 剛好一個目標
3. `target_independently_reblockable` — 從 `per_ip` **重新推導**四條判定，
   不相信摘要。同一份報告讀兩次，一次靠 `blockable_ips`、一次靠原始欄位
4. `target_is_not_self_or_gateway` — 本機位址、SSH 對端、預設閘道一律拒絕

之後才動核心：

5. `ticket_bound_to_evidence_digest`
6. `block_applied_to_kernel`
7. `packets_dropped` — 需要攻擊端真的送流量
8. `revocation_removed_element`
9. `post_revocation_packets_pass`

第 7 與第 9 項**需要第二台主機**。那不是缺點，是這支工具的定義：
沒有另一端就沒有「端到端」。

## 用法（需要 Jesse 對該次操作的明確授權）

    sudo python3 工具腳本/run_attribution_driven_block.py \\
        --attribution <session>/crosscheck.json \\
        --output 文件/歸因驅動封鎖_<date>/report.json

核准片語由**人**在 stdin 打，這支程式不會替他打。
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_acceptance():
    """借用 2026-09-24 驗收執行器的 helper,而不是抄一份。

    抄一份正是 C2C-060 記過的失效模式:兩份實作會各自演進,而分岔時沒有人會
    知道。這裡匯入的都是那一輪在真核心上被走過的程式。
    """
    path = ROOT / "工具腳本" / "run_nft_live_acceptance.py"
    spec = importlib.util.spec_from_file_location("_nft_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve their own module out of sys.modules, so a
    # module loaded this way must be registered before it executes.
    sys.modules["_nft_acceptance"] = module
    spec.loader.exec_module(module)
    return module


ATTRIBUTION_SCHEMA = "sros2-firewall-identity-crosscheck/v2"
CHAIN_SCHEMA = "sros2-firewall-attribution-driven-block/v1"

# 與 nft 驗收**不同**的片語。核准一件事不等於核准另一件。
CHAIN_APPROVAL = "BEGIN_OWNED_ISOLATED_ATTRIBUTION_DRIVEN_BLOCK"

REQUIRED_CHAIN_CHECKS = (
    "attribution_report_schema_v2",
    "attribution_verified_and_single_target",
    "target_independently_reblockable",
    "target_is_not_self_or_gateway",
    "ticket_bound_to_evidence_digest",
    "block_applied_to_kernel",
    "packets_dropped",
    "revocation_removed_element",
    "post_revocation_packets_pass",
)

# 比 nft 驗收長一些:撤銷後還要等攻擊端再送一輪。核心到期仍是第三道保證。
APPLIED_TTL_SEC = 90
TRAFFIC_WAIT_SEC = 45
POST_REVOKE_WAIT_SEC = 45


class ChainError(RuntimeError):
    """前置條件不成立或鏈斷掉。刻意不吞。"""


# ─────────────────────────── 證據 ───────────────────────────


@dataclass(frozen=True)
class AttributionEvidence:
    """一份已完成的歸因報告,連同它自己的摘要。"""

    path: Path
    sha256: str
    report: dict

    @property
    def evidence_id(self) -> str:
        """票的 evidence_id 就是報告檔案的 SHA-256。

        `ResponseAuthorizer` 要求 64 個小寫十六進位字元,而 SHA-256 正好是。
        這不是巧合湊上的——它讓票與證據的綁定變成可驗證的,而不是靠命名慣例。
        """
        return self.sha256


def load_attribution(path: Path) -> AttributionEvidence:
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        report = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChainError(f"歸因報告不是合法 JSON：{exc}") from exc
    if not isinstance(report, dict):
        raise ChainError("歸因報告的頂層必須是物件")
    return AttributionEvidence(path=Path(path), sha256=digest, report=report)


def check_schema(evidence: AttributionEvidence) -> tuple[bool, str]:
    """v1 沒有第四條(鏈路層綁定),拿它來封鎖會漏掉來源位址偽造。"""
    found = evidence.report.get("schema_version")
    ok = found == ATTRIBUTION_SCHEMA
    return ok, f"schema_version={found!r} expected={ATTRIBUTION_SCHEMA!r}"


def check_verified_single_target(
    evidence: AttributionEvidence, requested: str | None
) -> tuple[bool, str, str]:
    """剛好一個目標。

    多於一個時**不自己挑**:一次核准就是一次封鎖。操作者要封第二個,
    就再核准一次。安靜地封掉兩個不是那個片語同意的事。
    """
    report = evidence.report
    verified = report.get("source_ip_attribution_verified")
    blockable = report.get("blockable_ips")
    if verified is not True:
        return False, f"source_ip_attribution_verified={verified!r}", ""
    if not isinstance(blockable, list) or not blockable:
        return False, f"blockable_ips={blockable!r}", ""
    if requested is not None:
        if requested not in blockable:
            return False, f"{requested} 不在 blockable_ips={blockable}", ""
        return True, f"operator selected {requested} from {blockable}", requested
    if len(blockable) != 1:
        return (
            False,
            f"{len(blockable)} 個位址可封鎖 {blockable}；"
            "用 --target 明確指定，不要讓程式替你挑",
            "",
        )
    return True, f"single blockable target {blockable[0]}", str(blockable[0])


def check_independently_reblockable(
    evidence: AttributionEvidence, target: str
) -> tuple[bool, str]:
    """從 `per_ip` 重新推導四條判定,不相信 `blockable_ips` 那個摘要。

    同一份報告讀兩次是刻意的:摘要與明細由同一支程式產生,但它們是兩條不同的
    程式路徑,而這裡要封鎖的是真的封包。兩條路徑不一致時寧可中止。
    """
    entry = (evidence.report.get("per_ip") or {}).get(target)
    if not isinstance(entry, dict):
        return False, f"per_ip 裡沒有 {target} 的明細"
    conditions = {
        "unique_guid": entry.get("unique_guid") is True,
        "no_authorized_identity": entry.get("has_authorized_identity") is False,
        "has_rejection_record": entry.get("has_rejection_record") is True,
        "link_layer_consistent": entry.get("link_layer_verdict") == "consistent",
        "summary_agrees": entry.get("blockable") is True,
    }
    failed = sorted(name for name, ok in conditions.items() if not ok)
    detail = ", ".join(f"{k}={v}" for k, v in sorted(conditions.items()))
    if failed:
        return False, f"未成立：{failed}；{detail}"
    return True, detail


def check_not_self_or_gateway(
    acceptance, target: str
) -> tuple[bool, str]:
    """封自己是這條鏈最糟的失效方向,而且它是會發生的。

    2026-08-30 那批每一輪防守方自己的位址都滿足前兩條判定,只差沒有拒絕記錄。
    這裡再加一道與證據**無關**的檢查:不論證據怎麼說,本機位址、當前 SSH 對端、
    預設閘道一律拒絕。
    """
    reasons: list[str] = []
    peers, peer_source = acceptance._ssh_peers()
    if target in peers:
        reasons.append(f"目標是當前 SSH 對端（來源：{peer_source}）")
    local = _local_addresses()
    if target in local:
        reasons.append("目標是本機自己的位址")
    gateway = _default_gateway()
    if gateway and target == gateway:
        reasons.append(f"目標是預設閘道 {gateway}")
    detail = (
        f"ssh_peers={sorted(peers)} source={peer_source} "
        f"local={sorted(local)} gateway={gateway or 'none'}"
    )
    if reasons:
        return False, f"{'；'.join(reasons)}；{detail}"
    return True, detail


def _ip(*args: str) -> str:
    result = subprocess.run(
        ("/usr/sbin/ip", *args),
        capture_output=True, text=True, shell=False, timeout=5, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    return result.stdout


def _local_addresses() -> set[str]:
    found: set[str] = set()
    for line in _ip("-4", "-o", "addr", "show").splitlines():
        parts = line.split()
        if "inet" in parts:
            found.add(parts[parts.index("inet") + 1].split("/")[0])
    return found


def _default_gateway() -> str:
    for line in _ip("-4", "route", "show", "default").splitlines():
        parts = line.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    return ""


# ─────────────────────────── 鏈 ───────────────────────────


def issue_attribution_ticket(
    issuer, evidence: AttributionEvidence, target: str, *, interface: str, ttl_sec: int
):
    """這條鏈唯一的一張票,綁定到歸因報告的摘要。

    與 `run_nft_live_acceptance.issue_block_ticket` 的差別只有一處,而那一處
    就是這支工具存在的理由:`evidence_id` 不是一個標籤,是證據本身的雜湊。
    """
    acceptance = _load_acceptance()
    return issuer.issue(
        evidence_id=evidence.evidence_id,
        source=target,
        source_kind="network_ip",
        action=acceptance.NETWORK_ACTION,
        adapter=acceptance.NETWORK_ADAPTER,
        backend_id=acceptance.PRODUCTION_BACKEND_ID,
        interface=interface,
        identity="attribution-driven-block",
        response_ttl_sec=ttl_sec,
    )


def check_ticket_bound(ticket, evidence: AttributionEvidence, verifier) -> tuple[bool, str]:
    """票必須驗得過,而且它指的證據必須是這一份。

    兩個條件都要,而且順序重要:先驗簽章,再比 `evidence_id`。只比後者的話,
    一張偽造的票只要抄對摘要就過得了。
    """
    try:
        claims = verifier.verify(ticket)
    except Exception as exc:  # TicketVerificationError 或其子類
        return False, f"票驗不過：{type(exc).__name__}: {exc}"
    found = getattr(claims, "evidence_id", None)
    ok = found == evidence.evidence_id and found is not None
    return ok, (
        f"evidence_id={found} report_sha256={evidence.sha256} "
        f"source={getattr(claims, 'source', None)} report={evidence.path.name}"
    )


def wait_for_counter_move(acceptance, label: str, wait_sec: int) -> tuple[int, str]:
    """等核心計數器動。回傳增量,呼叫端決定該增量代表通過還是失敗。"""
    before_packets, before_bytes = acceptance._rule_counter()
    acceptance._log("")
    acceptance._log("  ┌──────────────────────────────────────────────────────────────┐")
    acceptance._log(f"  │ {label:<60} │")
    acceptance._log(f"  │ waiting up to {wait_sec}s                                          │")
    acceptance._log("  └──────────────────────────────────────────────────────────────┘")
    deadline = time.monotonic() + wait_sec
    after_packets, after_bytes = before_packets, before_bytes
    while time.monotonic() < deadline:
        after_packets, after_bytes = acceptance._rule_counter()
        if after_packets > before_packets:
            break
        time.sleep(0.5)
    moved = after_packets - before_packets
    return moved, (
        f"counter packets {before_packets}->{after_packets} (+{moved}), "
        f"bytes {before_bytes}->{after_bytes}"
    )


def check_block_applied(acceptance, target: str) -> tuple[bool, str]:
    """核心的集合裡真的有這個位址,而且到期時間在未來。"""
    elements = acceptance._set_elements()
    present = target in elements
    return present, f"set elements={elements}"


def check_revocation_removed(acceptance, target: str, result: dict) -> tuple[bool, str]:
    """撤銷之後元素必須不在集合裡——由核心確認,不是由回傳值確認。

    `revoke_source` 自己已經 fail-closed 檢查過轉接器的 snapshot,這裡再獨立
    問一次核心。兩者走的是不同路徑(轉接器 vs `nft -j list set`),而這條鏈
    最怕的就是「我以為我解封了」。
    """
    elements = acceptance._set_elements()
    gone = target not in elements
    return gone, (
        f"existed={result.get('existed')} active_count={result.get('active_count')} "
        f"set elements={elements}"
    )


def check_post_revocation_pass(acceptance, target: str) -> tuple[bool, str]:
    """撤銷之後,新的流量**不可以**再被丟。

    這一項與第 7 項成對。只量「元素不見了」不夠——集合空了但規則仍在丟包
    是想像得到的失效,而它在遙測上看起來會像撤銷成功。
    """
    moved, detail = wait_for_counter_move(
        acceptance,
        f"SEND TRAFFIC AGAIN from {target} (must NOT be dropped)",
        POST_REVOKE_WAIT_SEC,
    )
    return moved == 0, f"{detail}; expected +0 after revocation"


# ─────────────────────────── 報告 ───────────────────────────


def build_report(
    *,
    evidence: AttributionEvidence,
    target: str,
    checks: dict[str, dict],
    approval_phrase_supplied: bool,
) -> dict:
    passed = all(entry["passed"] for entry in checks.values())
    complete = set(checks) == set(REQUIRED_CHAIN_CHECKS)
    return {
        "schema_version": CHAIN_SCHEMA,
        "attribution": {
            "report_path": str(evidence.path),
            "report_sha256": evidence.sha256,
            "report_authorizes_action": bool(
                evidence.report.get("authorizes_action", False)
            ),
            "target": target,
        },
        "checks": checks,
        "summary": {
            "required": list(REQUIRED_CHAIN_CHECKS),
            "all_required_present": complete,
            "all_passed": passed,
            "chain_demonstrated": bool(passed and complete),
        },
        "authorization": {
            # 這兩行是這份報告最重要的地方,不要拿掉。
            "subject_came_from": "attribution evidence digest",
            "authority_came_from": "human approval phrase on stdin",
            "human_phrase_supplied": approval_phrase_supplied,
            "note": (
                "The attribution report sets authorizes_action=false. It says the "
                "evidence supports naming this address; it does not say anything "
                "may be done about it. The authority for this run is the operator's "
                "phrase, and nothing here changes executable_classes or "
                "LIVE_NFT_ACTIVATION_ALLOWED."
            ),
        },
        "shipping_defaults_unchanged": True,
    }


def verify_chain_report(report: dict) -> dict:
    """獨立重讀一份鏈報告。與 nft 驗收同樣的姿態:產生者不是驗證者。"""
    expected = {
        "schema_version",
        "attribution",
        "checks",
        "summary",
        "authorization",
        "shipping_defaults_unchanged",
    }
    found = set(report)
    if found != expected:
        raise ChainError(
            f"鏈報告的頂層鍵必須剛好是 {sorted(expected)}，實際是 {sorted(found)}"
        )
    if report["schema_version"] != CHAIN_SCHEMA:
        raise ChainError(f"未知的 schema_version：{report['schema_version']!r}")
    checks = report["checks"]
    missing = sorted(set(REQUIRED_CHAIN_CHECKS) - set(checks))
    if missing:
        raise ChainError(f"缺少必要檢查：{missing}")
    extra = sorted(set(checks) - set(REQUIRED_CHAIN_CHECKS))
    if extra:
        raise ChainError(f"出現未宣告的檢查：{extra}")
    failed = sorted(name for name, entry in checks.items() if not entry["passed"])
    return {
        "chain_demonstrated": not failed,
        "failed_checks": failed,
        "target": report["attribution"]["target"],
        "evidence_sha256": report["attribution"]["report_sha256"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attribution", type=Path, required=True,
                        help="crosscheck_identity_attribution.py 的輸出（schema v2）")
    parser.add_argument("--target", default=None,
                        help="報告有多個可封鎖位址時明確指定；只有一個時不要給")
    parser.add_argument("--interface", required=True,
                        help="封鎖生效的介面")
    parser.add_argument("--ttl-sec", type=int, default=APPLIED_TTL_SEC)
    parser.add_argument("--authorized-scope", required=False, default="",
                        help="允許封鎖的網段，例如 192.168.0.0/24")
    parser.add_argument("--protected-source", action="append", default=[],
                        help="永不封鎖的網段，可重複給")
    parser.add_argument("--state-db", default="/var/lib/sros2-firewall/chain-state.sqlite3")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true",
                        help="只跑前四項前置檢查，完全不碰核心，也不要求 root 與片語")
    return parser


def preflight(evidence: AttributionEvidence, requested: str | None, acceptance) -> tuple[dict, str]:
    """碰核心之前的四項。回傳 (checks, target);任一不過時 target 為空字串。"""
    checks: dict[str, dict] = {}

    ok, detail = check_schema(evidence)
    checks["attribution_report_schema_v2"] = {"passed": ok, "detail": detail}
    if not ok:
        return checks, ""

    ok, detail, target = check_verified_single_target(evidence, requested)
    checks["attribution_verified_and_single_target"] = {"passed": ok, "detail": detail}
    if not ok:
        return checks, ""

    ok, detail = check_independently_reblockable(evidence, target)
    checks["target_independently_reblockable"] = {"passed": ok, "detail": detail}
    if not ok:
        return checks, ""

    ok, detail = check_not_self_or_gateway(acceptance, target)
    checks["target_is_not_self_or_gateway"] = {"passed": ok, "detail": detail}
    if not ok:
        return checks, ""

    return checks, target


def main(argv: list[str] | None = None, stdin=None) -> int:
    args = build_parser().parse_args(argv)
    stdin = stdin if stdin is not None else sys.stdin
    acceptance = _load_acceptance()

    if args.output.exists():
        print(f"⛔ 輸出已存在，拒絕覆寫：{args.output}", file=sys.stderr)
        return 2

    evidence = load_attribution(args.attribution)
    checks, target = preflight(evidence, args.target, acceptance)

    for name in REQUIRED_CHAIN_CHECKS:
        entry = checks.get(name)
        if entry is None:
            continue
        mark = "✅" if entry["passed"] else "❌"
        print(f"  {mark} {name}: {entry['detail']}")

    if args.dry_run:
        print()
        print("--dry-run：只跑前置檢查，核心一個位元組都沒碰。")
        print(f"目標：{target or '（前置未通過，沒有目標）'}")
        return 0 if target else 1

    if not target:
        print("⛔ 前置檢查未通過，不進行任何封鎖。", file=sys.stderr)
        return 1

    if os.geteuid() != 0:
        print("⛔ 套用核心規則需要 UID 0", file=sys.stderr)
        return 2

    if not args.authorized_scope:
        print("⛔ --authorized-scope 是必填：backend 的範圍檢查不可以是空的，"
              "否則任何位址都在範圍內。", file=sys.stderr)
        return 2

    phrase = stdin.readline().strip() if stdin else ""
    if phrase != CHAIN_APPROVAL:
        print("⛔ 未在 stdin 取得完整核准片語；拒絕執行。", file=sys.stderr)
        return 2

    print()
    print(f"前置四項通過，目標 = {target}")
    print("⚠️ 本程式不會自行產生攻擊流量——第 7 與第 9 項需要攻擊端配合，")
    print("   而那是另一端、另一次授權。這裡只會提示並等待計數器。")
    print()

    run_chain(acceptance, evidence, target, checks, args)

    report = build_report(
        evidence=evidence,
        target=target,
        checks=checks,
        approval_phrase_supplied=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    verdict = verify_chain_report(report)
    print()
    print(f"報告：{args.output}")
    print(f"chain_demonstrated = {verdict['chain_demonstrated']}")
    if not verdict["chain_demonstrated"]:
        print(f"未通過：{verdict['failed_checks']}")
        return 1
    print()
    print("這一次是**人核准的驗收**，不是自動封鎖。")
    print("`executable_classes` 仍為空清單，`LIVE_NFT_ACTIVATION_ALLOWED` 仍為 False。")
    return 0


def run_chain(acceptance, evidence, target: str, checks: dict, args) -> None:
    """套用、量、撤銷、再量。整段包在 finally 裡拆掉規則。

    第三道保證仍在:票帶 TTL,所以就算這個行程死掉,核心也會自己到期——
    2026-09-24 在真核心上量過(`kernel_timeout_expiry_verified`)。這裡不重複
    量它,這一支要證明的是**不等到期也能解掉**。
    """
    from firewall_lab.response_backend import (
        Ed25519TicketIssuer,
        Ed25519TicketVerifier,
        ResponseBackend,
        SQLiteResponseState,
    )

    def record(name: str, ok: bool, detail: str) -> None:
        checks[name] = {"passed": bool(ok), "detail": detail}
        print(f"  {'✅' if ok else '❌'} {name}: {detail[:160]}")

    installed = False
    try:
        acceptance._install_fixed_ruleset()
        installed = True

        issuer = Ed25519TicketIssuer.generate()
        verifier = Ed25519TicketVerifier(issuer.public_key_bytes())
        backend = ResponseBackend(
            verifier=verifier,
            state=SQLiteResponseState(Path(args.state_db)),
            timeout_set=acceptance.NftablesTimeoutSetAdapter(
                acceptance.SubprocessNftRunner()
            ),
            backend_id=acceptance.PRODUCTION_BACKEND_ID,
            authorized_sources=[str(args.authorized_scope)],
            protected_sources=[str(p) for p in args.protected_source],
        )

        ticket = issue_attribution_ticket(
            issuer, evidence, target, interface=args.interface, ttl_sec=args.ttl_sec
        )
        record("ticket_bound_to_evidence_digest",
               *check_ticket_bound(ticket, evidence, verifier))

        backend.apply_ticket(ticket)
        record("block_applied_to_kernel", *check_block_applied(acceptance, target))

        moved, detail = wait_for_counter_move(
            acceptance, f"SEND TRAFFIC NOW from {target}", TRAFFIC_WAIT_SEC
        )
        record("packets_dropped", moved > 0, detail)

        result = backend.revoke_source(target, reason="attribution-driven acceptance")
        record("revocation_removed_element",
               *check_revocation_removed(acceptance, target, result))

        record("post_revocation_packets_pass",
               *check_post_revocation_pass(acceptance, target))
    finally:
        if installed:
            acceptance._remove_fixed_ruleset()
            print("  teardown: 專用規則集已移除")


if __name__ == "__main__":
    raise SystemExit(main())
