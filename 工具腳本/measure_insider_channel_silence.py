#!/usr/bin/env python3
"""量身份通道對**持證內鬼**的沉默程度，並證明那個沉默是真的。

## 為什麼需要這支

2026-09-01 的 B″ 量到身份通道（`sros_auth_fail_rate`）對未認證外部者是近乎
完美的二元訊號：九類攻擊各 20／20 有 deny、`normal` 20／20 為零，換 holdout
五組全部 recall ≥ 0.9667 而正常誤報 0.0000。

那份文件的第三節寫「對內部威脅無效」——**那是斷言不是量測**。出貨 catalog
當時的十個 scenario 全部是未認證的外部者，內鬼根本不在裡面。

## 這支要防的錯誤

「內鬼場次 deny = 0」有兩種完全不同的成因，**在資料上長得一模一樣**：

    (a) 攻擊在身份層是合法的，所以沒有認證拒絕     ← 要證明的
    (b) 攻擊根本沒跑起來，所以什麼都沒有           ← 毫無意義

這個專案已經被同一個形態咬過六次（N1 的 QoS 不相容、8,192 點 scan 在傳輸層
被丟、marker 全檔掃描撐爆窗、FastCDR 不一致讓 discovery 靜默失效、發送端
字彙表缺一項、驅動器自己觸發 cascade-DoS）。所以這支把兩件事寫成**硬條件**：

1. **正向對照必須開火。** 同一輪要有一個未認證外部者，且它的 deny > 0。
   沒有它，整輪作廢——因為「觀測者壞了」與「內鬼是合法的」分不開。
2. **內鬼必須有第二層證據。** 攻擊要真的抵達節點並被擋下：

       hmac_forgery     → hmac_result 的 outcome=rejected reason=invalid_signature
       confused_deputy  → parameter_veto 的 layer=rcl_read_only

   沒有第二層證據的沉默一律判 `void`，不判 pass。

## 用法

    python3 工具腳本/measure_insider_channel_silence.py \\
        --dataset <campaign>/dataset \\
        --insider hmac_forgery confused_deputy \\
        --positive-control identity_abuse \\
        --negative-control normal \\
        --output <報告>.json
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

# 內鬼類別 → 該類別的第二層拒絕證據長什麼樣。
# 這是「攻擊真的抵達並被擋下」的定義，不是輔助資訊——沒有它就沒有結論。
SECOND_LAYER = {
    "hmac_forgery": ("hmac_result", "reason", "invalid_signature"),
    "confused_deputy": ("parameter_veto", "layer", "rcl_read_only"),
}


def _scan_session(session_dir: Path) -> dict:
    """讀一場的 telemetry，數身份層拒絕與各種第二層證據。"""
    counts: collections.Counter = collections.Counter()
    telemetry = session_dir / "telemetry_events.jsonl"
    if not telemetry.is_file():
        return {"telemetry_present": False, "counts": counts}
    with telemetry.open(encoding="utf-8") as handle:
        for line in handle:
            if '"sros2_deny"' not in line and '"hmac_result"' not in line \
                    and '"parameter_veto"' not in line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            kind = event.get("event_type")
            details = event.get("details") or {}
            if kind == "sros2_deny":
                # count 缺席時算一次：寧可高估身份層訊號，不可低估。
                try:
                    counts["sros2_deny"] += int(details.get("count", 1))
                except (TypeError, ValueError):
                    counts["sros2_deny"] += 1
            elif kind == "hmac_result":
                counts["hmac_result:%s" % details.get("reason")] += 1
            elif kind == "parameter_veto":
                counts["parameter_veto:%s" % details.get("layer")] += 1
    return {"telemetry_present": True, "counts": counts}


def collect(dataset: Path) -> dict[str, list[dict]]:
    by_class: dict[str, list[dict]] = collections.defaultdict(list)
    for manifest_path in sorted(dataset.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("status") != "complete":
            continue
        scanned = _scan_session(manifest_path.parent)
        by_class[manifest["attack_class"]].append(
            {
                "session_id": manifest["session_id"],
                "security_mode": manifest.get("security_mode"),
                "deny": scanned["counts"]["sros2_deny"],
                "counts": dict(scanned["counts"]),
                "telemetry_present": scanned["telemetry_present"],
            }
        )
    return dict(by_class)


def _second_layer_total(rows: list[dict], attack_class: str) -> int | None:
    spec = SECOND_LAYER.get(attack_class)
    if spec is None:
        return None
    _, _, value = spec
    prefix = {
        "hmac_forgery": "hmac_result:",
        "confused_deputy": "parameter_veto:",
    }[attack_class]
    return sum(row["counts"].get(prefix + value, 0) for row in rows)


def evaluate(
    by_class: dict[str, list[dict]],
    *,
    insider: list[str],
    positive_control: str,
    negative_control: str,
) -> dict:
    report: dict = {
        "schema_version": "sros2-firewall-insider-channel-silence/v1",
        "classes": {},
    }

    for name, rows in sorted(by_class.items()):
        with_signal = sum(1 for row in rows if row["deny"] > 0)
        report["classes"][name] = {
            "sessions": len(rows),
            "sessions_with_identity_signal": with_signal,
            "deny_values": sorted({row["deny"] for row in rows}),
            "second_layer_rejections": _second_layer_total(rows, name),
        }

    # ---- 硬條件 1：正向對照必須開火，否則整輪作廢 -------------------------
    control = report["classes"].get(positive_control)
    if control is None or control["sessions"] == 0:
        report["verdict"] = "void_no_positive_control"
        report["verdict_reason"] = (
            f"同一輪沒有 {positive_control} 的場次。缺少正向對照時，"
            "「內鬼沉默」與「觀測者壞掉」在資料上無法分辨。"
        )
        return report
    if control["sessions_with_identity_signal"] != control["sessions"]:
        report["verdict"] = "void_positive_control_did_not_fire"
        report["verdict_reason"] = (
            f"{positive_control} 只有 "
            f"{control['sessions_with_identity_signal']}/{control['sessions']} "
            "場有身份層訊號。觀測者在這一輪不可信，內鬼的零不能解讀。"
        )
        return report

    # ---- 硬條件 2：負向對照必須安靜 ---------------------------------------
    negative = report["classes"].get(negative_control)
    if negative and negative["sessions_with_identity_signal"] > 0:
        report["verdict"] = "void_negative_control_fired"
        report["verdict_reason"] = (
            f"{negative_control} 有 {negative['sessions_with_identity_signal']} "
            "場出現身份層訊號。訊號不乾淨，沉默無法歸因。"
        )
        return report

    # ---- 硬條件 3：每個內鬼類別都要有第二層證據 ---------------------------
    findings: dict[str, dict] = {}
    for name in insider:
        entry = report["classes"].get(name)
        if entry is None or entry["sessions"] == 0:
            findings[name] = {"verdict": "void_no_sessions"}
            continue
        second = entry["second_layer_rejections"]
        if not second:
            findings[name] = {
                "verdict": "void_attack_may_not_have_run",
                "reason": (
                    "沒有任何第二層拒絕證據。攻擊可能根本沒抵達節點，"
                    "那樣的零毫無意義。"
                ),
            }
            continue
        silent = entry["sessions_with_identity_signal"] == 0
        findings[name] = {
            "verdict": "silent_and_blocked_downstream" if silent
            else "identity_channel_fired",
            "sessions": entry["sessions"],
            "sessions_with_identity_signal": entry["sessions_with_identity_signal"],
            "second_layer_rejections": second,
        }
    report["insider_findings"] = findings

    voided = [n for n, f in findings.items() if f["verdict"].startswith("void")]
    if voided:
        report["verdict"] = "void_insufficient_second_layer_evidence"
        report["verdict_reason"] = f"這些類別沒有第二層證據：{sorted(voided)}"
        return report

    fired = [n for n, f in findings.items() if f["verdict"] == "identity_channel_fired"]
    if fired:
        report["verdict"] = "identity_channel_not_silent_for_insiders"
        report["verdict_reason"] = (
            f"這些內鬼類別觸發了身份層訊號：{sorted(fired)}。"
            "「對內部威脅無效」這個說法要修正。"
        )
        return report

    report["verdict"] = "identity_channel_silent_for_insiders"
    report["verdict_reason"] = (
        "所有內鬼類別的身份層訊號皆為零，且都有第二層拒絕證據證明攻擊確實"
        "抵達並被擋下；同一輪的正向對照全數開火、負向對照全數安靜。"
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--insider", nargs="+", default=["hmac_forgery", "confused_deputy"])
    parser.add_argument("--positive-control", default="identity_abuse")
    parser.add_argument("--negative-control", default="normal")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    if not args.dataset.is_dir():
        print(f"⛔ 找不到 dataset：{args.dataset}")
        return 2

    by_class = collect(args.dataset)
    if not by_class:
        print("⛔ 沒有任何完成的場次")
        return 2

    report = evaluate(
        by_class,
        insider=args.insider,
        positive_control=args.positive_control,
        negative_control=args.negative_control,
    )

    print("=== 身份通道對持證內鬼的沉默程度 ===\n")
    print("  %-18s %6s %10s  %-14s %s"
          % ("attack_class", "場次", "有訊號", "deny 值", "第二層拒絕"))
    for name, entry in sorted(report["classes"].items()):
        second = entry["second_layer_rejections"]
        print("  %-18s %6d %6d/%-3d  %-14s %s"
              % (name, entry["sessions"], entry["sessions_with_identity_signal"],
                 entry["sessions"], entry["deny_values"],
                 "—" if second is None else second))
    print()
    print(f"  判定：{report['verdict']}")
    print(f"  理由：{report['verdict_reason']}")

    if args.output:
        if args.output.exists():
            print(f"\n⛔ 輸出已存在，拒絕覆寫：{args.output}")
            return 2
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\n  報告：{args.output}")

    return 0 if report["verdict"].startswith("identity_channel_silent") else 1


if __name__ == "__main__":
    raise SystemExit(main())
