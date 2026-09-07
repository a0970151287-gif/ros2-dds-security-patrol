#!/usr/bin/env python3
"""量測「授權器 → 驗票 → 守衛 → 撤銷」整條鏈，在真實 ROS runtime 上。

## 為什麼需要這一支

程式與單元測試證明不了這一層真的擋得住訊息。依 CLAUDE.md 規則 4，`完成`
只能代表有可重現證據，離線模擬與程式骨架不得寫成 live pass。

## 五個階段

| 階段 | 量什麼 | 為什麼重要 |
|---|---|---|
| A 基準 | 未封鎖時全部放行 | 沒有這一段，「封鎖生效」可能只是守衛壞掉 |
| B 封鎖 | 啟用延遲、**漏放行數** | 漏放行不是零就等於沒擋住 |
| C 撤銷 | 撤銷延遲、恢復筆數 | 可撤銷是這一層存在的理由 |
| D 裸 GUID | 未授權的行**必須被忽略** | 這是這一版格式變更的全部重點 |
| E 到期 | 不撤銷也會自己解除 | 守衛自己到期，不依賴 Python 行程活著 |

階段 A 與 D 是對照組。只做 B、C 的話，「訊息沒到」與「守衛擋住了」在日誌上
完全一樣——這個專案已經被同一類混淆咬過五次。

## 這不是部署證據

演練用的是**測試用的證據簽發金鑰**，而且把 runtime attestation 全部設為
True 才走得到 live。它證明的是**鏈的機制**成立，不是系統可以部署：
出貨 policy 的 `executable_classes` 仍為空，沒有任何規則指向 `dds_guard`。
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.dds_guard_backend import DdsGuardBackend  # noqa: E402
from firewall_lab.decision import FirewallDecision  # noqa: E402
from firewall_lab.evidence import EvidenceAuthority, feature_sha256  # noqa: E402
from firewall_lab.response_authorizer import (  # noqa: E402
    ResponseAuthorizer,
    ResponseContext,
)

MODEL_HASH = "5" * 64
POLICY_HASH = "6" * 64
GUARD_ID = "rehearsal-dds-guard"
TOPIC = "guard_rehearsal"


def _read_decisions(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _decisions_since(path: Path, since_ns: int) -> list[dict]:
    return [row for row in _read_decisions(path)
            if row.get("event") == "decision"
            and int(row.get("ts_unix_ns", 0)) >= since_ns]


def _authorize(guid_prefix: str, ttl_sec: int):
    authority = EvidenceAuthority(b"rehearsal-evidence-secret" * 2,
                                  collector_id="rehearsal")
    decision = FirewallDecision(
        predicted_class="identity_abuse",
        confidence=0.99,
        anomaly=False,
        action="revocable_participant_block",
        adapter="dds_guard",
        executable=True,
        reason="rehearsal",
    )
    envelope = authority.issue(
        source=guid_prefix,
        source_kind="dds_identity",
        interface="lo",
        identity="rehearsal-publisher",
        feature_digest=feature_sha256({"packets": 42.0}),
        session_id="session-rehearsal",
        window_id="window-rehearsal",
        model_sha256=MODEL_HASH,
        policy_sha256=POLICY_HASH,
        backend_id=GUARD_ID,
        attribution_confidence=0.99,
        signals={"sros2": 0.95, "telemetry": 0.90},
        source_shared=False,
        confirmation_windows=2,
        decision=decision,
    )
    authorizer = ResponseAuthorizer(
        evidence_verifier=authority.verifier(),
        model_deployment_eligible=True,
        model_artifact_sha256=MODEL_HASH,
        policy_verified=True,
        policy_sha256=POLICY_HASH,
        dds_guard_id=GUARD_ID,
        dds_guard_present=True,
        dds_guard_revocation_verified=True,
    )
    return authorizer.authorize(
        replace(decision, evidence_id=envelope.evidence_id),
        ResponseContext(
            requested_mode="live",
            source=guid_prefix,
            source_kind="dds_identity",
            evidence=envelope,
            requested_ttl_sec=ttl_sec,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard-bin", default=str(
        Path.home() / "observer_build" / "guard_filter"))
    parser.add_argument("--domain", type=int, default=41)
    parser.add_argument("--rate", type=int, default=50)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path,
                        default=Path.home() / "guard_rehearsal")
    args = parser.parse_args()

    if args.output.exists():
        print(f"⛔ {args.output} 已存在，拒絕覆寫", file=sys.stderr)
        return 1

    work = args.work_dir
    work.mkdir(parents=True, exist_ok=True)
    blocklist = work / "blocklist.txt"
    journal = work / "journal.jsonl"
    decisions = work / "decisions.jsonl"
    for path in (blocklist, journal, decisions):
        path.unlink(missing_ok=True)

    env = dict(os.environ, ROS_DOMAIN_ID=str(args.domain))
    guard = subprocess.Popen(
        [args.guard_bin, "--ros-args",
         "-p", f"guarded_topic:={TOPIC}",
         "-p", f"blocklist_path:={blocklist}",
         "-p", f"decisions_path:={decisions}",
         "-p", "reload_sec:=0.05"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        start_new_session=True)
    talker = None
    report: dict = {
        "schema_version": "sros2-firewall-guard-chain-rehearsal/v1",
        "domain": args.domain,
        "publish_rate_hz": args.rate,
        # 演練用測試金鑰與人工的 runtime attestation，只證明機制成立。
        "demonstrates_chain_mechanics_only": True,
        "deployment_eligible": False,
        "phases": {},
    }

    try:
        time.sleep(2.0)
        if guard.poll() is not None:
            print("⛔ 守衛沒有啟動：", guard.stderr.read().decode()[:400],
                  file=sys.stderr)
            return 2

        talker = subprocess.Popen(
            ["ros2", "topic", "pub", "-r", str(args.rate), f"/{TOPIC}",
             "std_msgs/msg/String", "{data: rehearsal}"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)

        # ── A 基準 ──────────────────────────────────────────────────────────
        time.sleep(4.0)
        baseline_start = time.time_ns() - int(2.5e9)
        baseline = _decisions_since(decisions, baseline_start)
        if not baseline:
            print("⛔ 基準期間沒有任何判定——守衛沒有收到訊息，"
                  "後面全部無效。", file=sys.stderr)
            return 3
        guid = baseline[-1]["guid_prefix"]
        report["phases"]["baseline"] = {
            "decisions": len(baseline),
            "allowed": sum(1 for r in baseline if r["action"] == "allow"),
            "dropped": sum(1 for r in baseline if r["action"] == "drop"),
            "guid_prefix": guid,
        }

        backend = DdsGuardBackend(blocklist, journal, guard_id=GUARD_ID)

        # ── B 封鎖 ──────────────────────────────────────────────────────────
        applied = backend.apply(_authorize(guid, ttl_sec=30), guid_prefix=guid)
        write_ns = time.time_ns()
        if not applied.get("applied"):
            print(f"⛔ 授權未通過，無法演練：{applied}", file=sys.stderr)
            return 4
        time.sleep(4.0)
        during = _decisions_since(decisions, write_ns)
        drops = [r for r in during if r["action"] == "drop"]
        leaks = [r for r in during if r["action"] == "allow"]
        # 「守衛漏放行」與「守衛還沒生效」是兩件不同的事，分開算。
        # 混在一起的話，啟用延遲會被誤報成防禦失效——而在 50 Hz 下，
        # 27 毫秒的啟用延遲必然會讓一則訊息通過，那不是漏洞。
        first_drop_ns = drops[0]["ts_unix_ns"] if drops else None
        during_activation = [r for r in leaks
                             if first_drop_ns is not None
                             and r["ts_unix_ns"] < first_drop_ns]
        after_activation = [r for r in leaks
                            if first_drop_ns is not None
                            and r["ts_unix_ns"] > first_drop_ns]
        report["phases"]["blocked"] = {
            "activation_sec": ((first_drop_ns - write_ns) / 1e9
                               if first_drop_ns is not None else None),
            "dropped": len(drops),
            # 啟用視窗內通過的則數：由發布速率與啟用延遲決定，是量測值不是缺陷。
            "allows_during_activation": len(during_activation),
            # **生效之後**的漏放行。這一格必須是 0，不是 0 就等於沒擋住。
            "leaked_after_activation": len(after_activation),
            "publish_interval_sec": 1.0 / args.rate,
        }

        # ── C 撤銷 ──────────────────────────────────────────────────────────
        backend.revoke(guid, reason="rehearsal")
        revoke_ns = time.time_ns()
        time.sleep(3.0)
        after = _decisions_since(decisions, revoke_ns)
        allows = [r for r in after if r["action"] == "allow"]
        first_allow_ns = allows[0]["ts_unix_ns"] if allows else None
        report["phases"]["revoked"] = {
            "revocation_sec": ((first_allow_ns - revoke_ns) / 1e9
                               if first_allow_ns is not None else None),
            "resumed_allows": len(allows),
            # 同樣分開：撤銷生效前的丟棄是延遲，生效後還丟才是撤銷失敗。
            "drops_during_revocation": sum(
                1 for r in after if r["action"] == "drop"
                and first_allow_ns is not None
                and r["ts_unix_ns"] < first_allow_ns),
            "drops_after_revocation": sum(
                1 for r in after if r["action"] == "drop"
                and first_allow_ns is not None
                and r["ts_unix_ns"] > first_allow_ns),
        }

        # ── D 裸 GUID 對照組 ────────────────────────────────────────────────
        # 未授權的行必須被忽略。這是格式變更的全部重點。
        blocklist.write_text(f"{guid}\n", encoding="utf-8")
        bare_ns = time.time_ns()
        time.sleep(3.0)
        bare = _decisions_since(decisions, bare_ns)
        report["phases"]["bare_guid_ignored"] = {
            "decisions": len(bare),
            "allowed": sum(1 for r in bare if r["action"] == "allow"),
            # 這一格必須是 0：裸 GUID 不該讓任何訊息被丟棄。
            "dropped": sum(1 for r in bare if r["action"] == "drop"),
            "rejected_entry_events": sum(
                1 for r in _read_decisions(decisions)
                if r.get("event") == "blocklist_rejected_entries"),
        }

        # ── E 自動到期 ──────────────────────────────────────────────────────
        blocklist.unlink(missing_ok=True)
        time.sleep(1.0)
        backend = DdsGuardBackend(blocklist, journal, guard_id=GUARD_ID)
        backend.apply(_authorize(guid, ttl_sec=3), guid_prefix=guid)
        expiry_ns = time.time_ns()
        time.sleep(2.0)
        mid = _decisions_since(decisions, expiry_ns)
        # 刻意**不撤銷**，也不呼叫 expire_due()：要證明守衛自己會放行。
        time.sleep(4.0)
        late = _decisions_since(decisions, expiry_ns + int(4e9))
        report["phases"]["expired_without_revocation"] = {
            "dropped_before_expiry": sum(1 for r in mid if r["action"] == "drop"),
            "allowed_after_expiry": sum(1 for r in late if r["action"] == "allow"),
            "dropped_after_expiry": sum(1 for r in late if r["action"] == "drop"),
            "marked_expired": sum(1 for r in late if r.get("expired") is True),
            "backend_still_lists_it": bool(backend.active()),
        }
    finally:
        for process in (talker, guard):
            if process is not None and process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        time.sleep(1.0)

    blocked = report["phases"].get("blocked", {})
    bare_phase = report["phases"].get("bare_guid_ignored", {})
    expired = report["phases"].get("expired_without_revocation", {})
    report["pass_conditions"] = {
        "baseline_saw_traffic":
            report["phases"]["baseline"]["decisions"] > 0,
        "block_activated": blocked.get("activation_sec") is not None,
        "zero_leaks_after_activation":
            blocked.get("leaked_after_activation") == 0,
        "revocation_restored_traffic":
            report["phases"]["revoked"].get("resumed_allows", 0) > 0,
        "no_drops_after_revocation":
            report["phases"]["revoked"].get("drops_after_revocation") == 0,
        "bare_guid_dropped_nothing": bare_phase.get("dropped") == 0,
        "expired_without_revocation":
            expired.get("dropped_before_expiry", 0) > 0
            and expired.get("allowed_after_expiry", 0) > 0,
    }
    report["all_conditions_met"] = all(report["pass_conditions"].values())

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")

    print("=== 守衛回應鏈演練 ===")
    for name, phase in report["phases"].items():
        print(f"  {name}: {json.dumps(phase, ensure_ascii=False)}")
    print()
    for name, ok in report["pass_conditions"].items():
        print(f"  {'✅' if ok else '❌'} {name}")
    print(f"\n  全部通過：{report['all_conditions_met']}")
    print(f"\n→ {args.output}")
    return 0 if report["all_conditions_met"] else 5


if __name__ == "__main__":
    raise SystemExit(main())
