#!/usr/bin/env python3
"""Fail-closed quality and integrity checks for live firewall datasets."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .campaign import load_campaign_plan
from .schema import (
    LABEL_SCHEMA_VERSION,
    SCHEMA_VERSION,
    SessionManifest,
    atomic_write_json,
    sha256_file,
    utc_now,
)


REPORT_SCHEMA_VERSION = "sros2-firewall-live-quality/v1"
INDEX_COLUMNS = [
    "entry_id",
    "session_id",
    "scenario_id",
    "attack_class",
    "binary",
    "security_mode",
    "defense_condition",
    "expected_action",
    "ros_domain_id",
    "seed",
    "pcap_bytes",
    "captured_packets",
    "dropped_packets",
    "zeek_conn_rows",
    "label_duration_sec",
    "attack_return_code",
    "attack_terminated_by_factory",
    "training_eligible",
    "quality_status",
    "manifest_sha256",
]
CAPTURE_RE = re.compile(
    r"Packets received/dropped.*?:\s*(?P<received>\d+)/(?P<dropped>\d+)"
    r".*?\(pcap:(?P<pcap>\d+)/dumpcap:(?P<dumpcap>\d+)/"
    r"flushed:(?P<flushed>\d+)/ps_ifdrop:(?P<ps_ifdrop>\d+)\)"
)
PACKETS_RE = re.compile(r"Packets captured:\s*(\d+)")
TRACEBACK_RE = re.compile(
    r"Traceback \(most recent call last\)|"
    r"ExternalShutdownException|"
    r"Executor is already spinning|"
    r"rcl_shutdown already called",
    re.IGNORECASE,
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"\bDDS_ALERT_SECRET\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bLINE_CHANNEL_TOKEN\s*[:=]\s*\S+", re.IGNORECASE),
)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(
                    f"expected JSON object at {path}:{line_number}"
                )
            rows.append(value)
    return rows


def _zeek_data_rows(path: Path) -> int:
    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(
            1
            for line in handle
            if line.strip() and not line.startswith("#")
        )


def _capture_diagnostics(path: Path) -> dict[str, int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    captured_match = PACKETS_RE.search(text)
    drop_match = CAPTURE_RE.search(text)
    if captured_match is None or drop_match is None:
        raise ValueError("unrecognized dumpcap diagnostics")
    values = {
        "captured": int(captured_match.group(1)),
        "received": int(drop_match.group("received")),
        "dropped": int(drop_match.group("dropped")),
        "pcap_dropped": int(drop_match.group("pcap")),
        "dumpcap_dropped": int(drop_match.group("dumpcap")),
        "flushed_dropped": int(drop_match.group("flushed")),
        "interface_dropped": int(drop_match.group("ps_ifdrop")),
    }
    return values


def _evidence_errors(
    session_dir: Path,
    evidence: Any,
) -> list[str]:
    if not isinstance(evidence, dict) or not evidence:
        return ["manifest evidence inventory is empty"]
    errors: list[str] = []
    for relative_name, metadata in sorted(evidence.items()):
        if not isinstance(relative_name, str) or not isinstance(metadata, dict):
            errors.append("invalid evidence inventory entry")
            continue
        path = session_dir / relative_name
        try:
            path.relative_to(session_dir)
        except ValueError:
            errors.append(f"evidence escapes session directory: {relative_name}")
            continue
        if not path.is_file() or path.is_symlink():
            errors.append(f"evidence file missing or symlinked: {relative_name}")
            continue
        expected_bytes = metadata.get("bytes")
        expected_hash = metadata.get("sha256")
        if path.stat().st_size != expected_bytes:
            errors.append(f"evidence size mismatch: {relative_name}")
        if sha256_file(path) != expected_hash:
            errors.append(f"evidence hash mismatch: {relative_name}")
    return errors


def _secret_hits(session_dir: Path) -> list[str]:
    hits: list[str] = []
    for path in sorted(session_dir.rglob("*")):
        if (
            not path.is_file()
            or path.is_symlink()
            or path.suffix.lower() in {".pcap", ".pcapng"}
        ):
            continue
        if path.stat().st_size > 8 * 1024 * 1024:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            hits.append(str(path.relative_to(session_dir)))
    return hits


def _defense_condition(attack_class: str, security_mode: str) -> str:
    if attack_class == "normal":
        return "normal_operation"
    if security_mode == "enforce":
        return "sros2_enforce"
    return "prevention_off"


def _write_index(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=INDEX_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def verify_live_dataset(
    *,
    dataset_root: str | Path,
    plan_path: str | Path,
    report_path: str | Path | None = None,
    index_path: str | Path | None = None,
) -> dict[str, Any]:
    """Verify every plan-referenced session and inventory quarantined data."""
    root = Path(dataset_root).expanduser().resolve()
    plan_file = Path(plan_path).expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("dataset root must be a real directory")
    plan = load_campaign_plan(plan_file)

    errors: list[str] = []
    warnings: list[str] = []
    session_rows: list[dict[str, Any]] = []
    active_ids: set[str] = set()
    mode_counts: Counter[str] = Counter()
    class_counts: Counter[str] = Counter()
    scenario_mode_counts: dict[str, Counter[str]] = defaultdict(Counter)
    policy_hashes: set[str] = set()
    code_revisions: set[str] = set()
    pcap_hashes: set[str] = set()
    total_evidence_files = 0
    total_pcap_bytes = 0
    total_captured_packets = 0
    total_zeek_rows = 0

    for entry in plan["entries"]:
        prefix = entry["entry_id"]
        session_id = entry.get("session_id")
        if entry.get("status") != "complete":
            errors.append(f"{prefix}: campaign status is not complete")
            continue
        if not isinstance(session_id, str) or not session_id:
            errors.append(f"{prefix}: missing completed session_id")
            continue
        if session_id in active_ids:
            errors.append(f"{prefix}: duplicate session_id {session_id}")
            continue
        active_ids.add(session_id)
        session_dir = root / session_id
        if not session_dir.is_dir() or session_dir.is_symlink():
            errors.append(f"{prefix}: session directory missing or symlinked")
            continue

        session_errors: list[str] = []
        manifest_path = session_dir / "manifest.json"
        try:
            manifest = _read_json(manifest_path)
            SessionManifest(**manifest).validate()
        except Exception as exc:
            errors.append(
                f"{prefix}: invalid manifest: {type(exc).__name__}: {exc}"
            )
            continue

        expected = {
            "session_id": session_id,
            "scenario_id": entry["scenario_id"],
            "attack_class": entry["attack_class"],
            "security_mode": entry["security_mode"],
            "ros_domain_id": entry["domain_id"],
            "seed": entry["seed"],
            "expected_action": entry["expected_action"],
        }
        for key, expected_value in expected.items():
            if manifest.get(key) != expected_value:
                session_errors.append(f"manifest {key} does not match plan")
        if manifest.get("schema_version") != SCHEMA_VERSION:
            session_errors.append("unsupported manifest schema")
        if manifest.get("status") != "complete":
            session_errors.append("manifest status is not complete")
        if manifest.get("origin") != "live_lab":
            session_errors.append("manifest origin is not live_lab")
        if manifest.get("training_eligible") is not True:
            session_errors.append("manifest is not training eligible")

        result = manifest.get("result")
        if not isinstance(result, dict):
            session_errors.append("manifest result is missing")
            result = {}
        zeek = result.get("zeek")
        if (
            not isinstance(zeek, dict)
            or zeek.get("status") != "complete"
            or zeek.get("return_code") != 0
            or zeek.get("conn_log") is not True
        ):
            session_errors.append("offline Zeek result is not complete")
        capture_process = result.get("capture_process")
        if (
            not isinstance(capture_process, dict)
            or capture_process.get("return_code") != 0
        ):
            session_errors.append("capture process did not exit cleanly")

        pcap_path = session_dir / "traffic.pcapng"
        if (
            not pcap_path.is_file()
            or pcap_path.is_symlink()
            or pcap_path.stat().st_size <= 128
        ):
            session_errors.append("PCAP is missing, symlinked, or empty")
            pcap_bytes = 0
        else:
            pcap_bytes = pcap_path.stat().st_size
            pcap_hash = sha256_file(pcap_path)
            if pcap_hash in pcap_hashes:
                session_errors.append("duplicate PCAP SHA-256")
            pcap_hashes.add(pcap_hash)

        try:
            capture = _capture_diagnostics(
                session_dir / "capture.stderr.log"
            )
            if any(
                capture[name] != 0
                for name in (
                    "dropped",
                    "pcap_dropped",
                    "dumpcap_dropped",
                    "flushed_dropped",
                    "interface_dropped",
                )
            ):
                session_errors.append("dumpcap reported dropped packets")
        except Exception as exc:
            session_errors.append(f"invalid capture diagnostics: {exc}")
            capture = {"captured": 0, "dropped": -1}

        conn_path = session_dir / "zeek" / "conn.log"
        try:
            conn_rows = _zeek_data_rows(conn_path)
            if conn_rows <= 0:
                session_errors.append("Zeek conn.log has no data rows")
        except Exception as exc:
            session_errors.append(f"invalid Zeek conn.log: {exc}")
            conn_rows = 0

        try:
            labels = _read_jsonl(session_dir / "labels.jsonl")
            if len(labels) != 1:
                session_errors.append("labels.jsonl must contain one interval")
                label = {}
            else:
                label = labels[0]
            expected_binary = (
                "normal"
                if entry["attack_class"] == "normal"
                else "attack"
            )
            label_expected = {
                "schema_version": LABEL_SCHEMA_VERSION,
                "session_id": session_id,
                "attack_class": entry["attack_class"],
                "binary": expected_binary,
                "scope": "session_window",
            }
            for key, expected_value in label_expected.items():
                if label.get(key) != expected_value:
                    session_errors.append(f"label {key} does not match plan")
            start_ns = label.get("start_unix_ns")
            end_ns = label.get("end_unix_ns")
            if (
                isinstance(start_ns, bool)
                or isinstance(end_ns, bool)
                or not isinstance(start_ns, int)
                or not isinstance(end_ns, int)
                or end_ns <= start_ns
            ):
                session_errors.append("label interval is invalid")
                label_duration = 0.0
            else:
                label_duration = (end_ns - start_ns) / 1_000_000_000
        except Exception as exc:
            session_errors.append(f"invalid labels.jsonl: {exc}")
            label_duration = 0.0

        events_path = session_dir / "events.jsonl"
        try:
            events = _read_jsonl(events_path)
            sequences = [event.get("sequence") for event in events]
            if sequences != list(range(len(events))):
                session_errors.append("event sequence is not contiguous")
            event_types = {event.get("event_type") for event in events}
            for required in (
                "session_started",
                "attack_started",
                "attack_completed",
                "session_completed",
            ):
                if required not in event_types:
                    session_errors.append(f"missing event {required}")
        except Exception as exc:
            session_errors.append(f"invalid events.jsonl: {exc}")

        stderr_path = session_dir / "attack.stderr.log"
        stderr_text = (
            stderr_path.read_text(encoding="utf-8", errors="replace")
            if stderr_path.is_file()
            else ""
        )
        if TRACEBACK_RE.search(stderr_text):
            session_errors.append("attack stderr contains runtime traceback")
        secret_hits = _secret_hits(session_dir)
        if secret_hits:
            session_errors.append(
                "secret-like material found in " + ", ".join(secret_hits)
            )
        session_errors.extend(
            _evidence_errors(session_dir, manifest.get("evidence"))
        )

        attack_process = result.get("attack_process")
        if entry["attack_class"] == "normal":
            if attack_process is not None:
                session_errors.append("normal session has an attack process")
            attack_return_code: int | str = ""
            factory_stop: bool | str = ""
        elif not isinstance(attack_process, dict):
            session_errors.append("attack session has no process evidence")
            attack_return_code = ""
            factory_stop = ""
        else:
            attack_return_code = attack_process.get("return_code", "")
            factory_stop = attack_process.get("terminated_by_factory", "")

        policy_hashes.add(str(manifest.get("policy_sha256", "")))
        code_revisions.add(str(manifest.get("code_revision", "")))
        mode_counts[entry["security_mode"]] += 1
        class_counts[entry["attack_class"]] += 1
        scenario_mode_counts[entry["scenario_id"]][
            entry["security_mode"]
        ] += 1
        total_evidence_files += len(manifest.get("evidence", {}))
        total_pcap_bytes += pcap_bytes
        total_captured_packets += capture["captured"]
        total_zeek_rows += conn_rows

        if session_errors:
            errors.extend(f"{prefix}: {message}" for message in session_errors)
            quality_status = "failed"
        else:
            quality_status = "passed"
        session_rows.append(
            {
                "entry_id": prefix,
                "session_id": session_id,
                "scenario_id": entry["scenario_id"],
                "attack_class": entry["attack_class"],
                "binary": (
                    "normal"
                    if entry["attack_class"] == "normal"
                    else "attack"
                ),
                "security_mode": entry["security_mode"],
                "defense_condition": _defense_condition(
                    entry["attack_class"],
                    entry["security_mode"],
                ),
                "expected_action": entry["expected_action"],
                "ros_domain_id": entry["domain_id"],
                "seed": entry["seed"],
                "pcap_bytes": pcap_bytes,
                "captured_packets": capture["captured"],
                "dropped_packets": capture["dropped"],
                "zeek_conn_rows": conn_rows,
                "label_duration_sec": round(label_duration, 6),
                "attack_return_code": attack_return_code,
                "attack_terminated_by_factory": factory_stop,
                "training_eligible": manifest["training_eligible"],
                "quality_status": quality_status,
                "manifest_sha256": sha256_file(manifest_path),
            }
        )

    all_session_dirs = {
        manifest.parent.name
        for manifest in root.glob("*/manifest.json")
        if manifest.parent.is_dir() and not manifest.parent.is_symlink()
    }
    quarantine_ids = sorted(all_session_dirs - active_ids)
    quarantine_violations: list[str] = []
    for session_id in quarantine_ids:
        try:
            manifest = _read_json(root / session_id / "manifest.json")
        except Exception as exc:
            quarantine_violations.append(f"{session_id}: invalid manifest: {exc}")
            continue
        if manifest.get("training_eligible") is not False:
            quarantine_violations.append(
                f"{session_id}: unreferenced session is training eligible"
            )
    errors.extend(quarantine_violations)

    if len(policy_hashes) != 1:
        errors.append("active sessions do not share one policy SHA-256")
    if len(code_revisions) != 1:
        errors.append("active sessions span multiple code revisions")
    elif not re.fullmatch(r"[0-9a-f]{40,64}", next(iter(code_revisions))):
        errors.append("active sessions do not have a frozen Git revision")
    for scenario_id, counts in sorted(scenario_mode_counts.items()):
        if counts["permissive"] != counts["enforce"]:
            errors.append(
                f"{scenario_id}: permissive/enforce counts are not balanced"
            )

    session_rows.sort(key=lambda row: row["entry_id"])
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "verified_utc": utc_now(),
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "plan": {
            "campaign_id": plan["campaign_id"],
            "plan_sha256": sha256_file(plan_file),
            "entries": len(plan["entries"]),
            "complete_entries": sum(
                entry["status"] == "complete"
                for entry in plan["entries"]
            ),
        },
        "active_dataset": {
            "sessions": len(session_rows),
            "passed_sessions": sum(
                row["quality_status"] == "passed"
                for row in session_rows
            ),
            "training_eligible_sessions": sum(
                row["training_eligible"] is True
                for row in session_rows
            ),
            "security_modes": dict(sorted(mode_counts.items())),
            "attack_classes": dict(sorted(class_counts.items())),
            "scenario_security_matrix": {
                scenario_id: dict(sorted(counts.items()))
                for scenario_id, counts in sorted(
                    scenario_mode_counts.items()
                )
            },
            "pcap_bytes": total_pcap_bytes,
            "captured_packets": total_captured_packets,
            "dropped_packets": sum(
                row["dropped_packets"] for row in session_rows
            ),
            "zeek_conn_rows": total_zeek_rows,
            "evidence_files": total_evidence_files,
            "policy_sha256": (
                next(iter(policy_hashes))
                if len(policy_hashes) == 1
                else None
            ),
            "code_revisions": sorted(code_revisions),
        },
        "quarantine": {
            "sessions": len(quarantine_ids),
            "session_ids": quarantine_ids,
            "all_excluded_from_training": not quarantine_violations,
        },
        "sessions": session_rows,
    }
    if report_path is not None:
        atomic_write_json(report_path, report)
    if index_path is not None:
        _write_index(Path(index_path), session_rows)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a live SROS2 firewall dataset fail-closed",
    )
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--index", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = verify_live_dataset(
        dataset_root=args.dataset,
        plan_path=args.plan,
        report_path=args.report,
        index_path=args.index,
    )
    print(
        "live dataset verification: "
        f"passed={report['passed']} "
        f"sessions={report['active_dataset']['sessions']} "
        f"errors={len(report['errors'])} "
        f"quarantined={report['quarantine']['sessions']}"
    )
    if not report["passed"]:
        for error in report["errors"]:
            print(f"ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
