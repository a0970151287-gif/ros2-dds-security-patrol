#!/usr/bin/env python3
"""Passive, fail-closed readiness checks for the formal live dataset.

This module never launches Gazebo, publishes ROS messages, captures packets, or
runs an attack.  It only validates the experiment plan, local tools, topology
declaration, source freeze, storage, and evidence prerequisites.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import stat
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .campaign import DEFAULT_LIVE_OUTPUT, DEFAULT_PLAN, load_campaign_plan
from .catalog import load_catalog
from .orchestrator import POLICY_PATH, WORKSPACE_ROOT
from .runners import build_attack_argv
from .schema import atomic_write_json, sha256_file, utc_now


REPORT_SCHEMA_VERSION = "sros2-firewall-formal-preflight/v1"
DEFAULT_REPORT_DIR = Path(__file__).resolve().parent / "readiness_evidence"
FORMAL_SESSION_COUNT = 1_100
LOCALHOST_ACK = "I_CONFIRM_LOCALHOST_ONLY"
ISOLATED_LAB_ACK = "I_CONFIRM_OWNED_ISOLATED_LAB"
TOPOLOGIES = ("same_host_loopback", "isolated_cross_host")
REQUIRED_TOOLS = ("ros2", "gz", "dumpcap")
LIVE_MULTIMODAL_CONTRACT_SCHEMA = (
    "sros2-firewall-live-multimodal-contract/v1"
)
LIVE_MULTIMODAL_CONTRACT_PATH = (
    Path(__file__).resolve().parent / "live_multimodal_contract.json"
)
REQUIRED_LIVE_FEATURE_OUTPUTS = frozenset(
    {
        "network_features.csv",
        "telemetry_features.csv",
        "fusion_features.csv",
    }
)


def _check(
    name: str,
    passed: bool,
    detail: str,
    *,
    severity: str = "blocker",
) -> dict[str, Any]:
    return {
        "name": name,
        "passed": bool(passed),
        "severity": severity,
        "detail": str(detail)[:2048],
    }


def _run_read_only(
    argv: list[str],
    *,
    timeout: float = 10.0,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            argv,
            cwd=WORKSPACE_ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _topology_check(
    *,
    topology: str,
    capture_interface: str,
    isolation_ack: str,
    environment: dict[str, str],
) -> tuple[bool, str, str]:
    """Validate topology/interface/environment agreement without guessing."""
    if topology == "same_host_loopback":
        localhost_only = (
            environment.get("ROS_LOCALHOST_ONLY") == "1"
            or environment.get("ROS_AUTOMATIC_DISCOVERY_RANGE", "").upper()
            == "LOCALHOST"
        )
        passed = (
            capture_interface == "lo"
            and localhost_only
            and isolation_ack == LOCALHOST_ACK
        )
        return (
            passed,
            (
                "same_host_loopback requires interface=lo, "
                "ROS_LOCALHOST_ONLY=1 (or discovery range LOCALHOST), and "
                f"ack={LOCALHOST_ACK}"
            ),
            "local_adversary_only_not_cross_host",
        )
    if topology == "isolated_cross_host":
        localhost_only = (
            environment.get("ROS_LOCALHOST_ONLY") == "1"
            or environment.get("ROS_AUTOMATIC_DISCOVERY_RANGE", "").upper()
            == "LOCALHOST"
        )
        passed = (
            capture_interface not in {"", "any", "lo"}
            and not localhost_only
            and isolation_ack == ISOLATED_LAB_ACK
        )
        return (
            passed,
            (
                "isolated_cross_host requires an explicit non-loopback "
                "interface, localhost-only disabled, and "
                f"ack={ISOLATED_LAB_ACK}"
            ),
            "owned_isolated_cross_host_lab",
        )
    return False, f"unsupported topology: {topology}", "invalid"


def _nearest_existing_parent(path: Path) -> Path:
    candidate = path.expanduser().resolve()
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def _live_multimodal_contract_check(
    contract_path: Path = LIVE_MULTIMODAL_CONTRACT_PATH,
    *,
    workspace_root: Path = WORKSPACE_ROOT,
) -> tuple[bool, str]:
    """Require an implemented and tested live 14+18 feature contract."""
    try:
        value = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return False, f"contract unreadable: {type(exc).__name__}: {exc}"
    if not isinstance(value, dict):
        return False, "contract must be a JSON object"
    if value.get("schema_version") != LIVE_MULTIMODAL_CONTRACT_SCHEMA:
        return False, "unsupported live multimodal contract schema"

    status = value.get("status")
    blockers = value.get("blockers")
    if status != "validated":
        blocker_text = (
            ", ".join(str(item) for item in blockers[:8])
            if isinstance(blockers, list)
            else "unspecified"
        )
        return False, f"status={status!r}; blockers={blocker_text}"

    try:
        from .synthetic_dataset import TELEMETRY_FEATURES
    except Exception as exc:
        return False, f"feature contract import failed: {type(exc).__name__}: {exc}"
    if value.get("network_feature_count") != 14:
        return False, "network_feature_count must be 14"
    if value.get("telemetry_features") != TELEMETRY_FEATURES:
        return False, "telemetry feature names/order do not match the model contract"
    if value.get("alignment_keys") != ["session_id", "window"]:
        return False, "alignment_keys must be ['session_id', 'window']"
    outputs = value.get("required_outputs")
    if (
        not isinstance(outputs, list)
        or set(outputs) != REQUIRED_LIVE_FEATURE_OUTPUTS
    ):
        return False, "required live feature outputs are incomplete"

    artifacts = value.get("implementation_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return False, "implementation_artifacts are missing"
    missing = []
    for relative_name in artifacts:
        if (
            not isinstance(relative_name, str)
            or not relative_name
            or Path(relative_name).is_absolute()
            or ".." in Path(relative_name).parts
            or not (workspace_root / relative_name).is_file()
        ):
            missing.append(str(relative_name))
    if missing:
        return False, "missing implementation artifacts: " + ", ".join(missing)
    return (
        True,
        (
            "validated 14 network + 18 telemetry feature contract; "
            "session/window alignment and implementation artifacts present"
        ),
    )


def _pilot_pcap_average() -> tuple[int, int]:
    pilot = Path(__file__).resolve().parent / "dataset_pilot"
    sizes: list[int] = []
    if not pilot.is_dir():
        return 0, 0
    for manifest_path in pilot.glob("*/manifest.json"):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            pcap = manifest_path.parent / "traffic.pcapng"
            if (
                manifest.get("training_eligible") is True
                and pcap.is_file()
                and not pcap.is_symlink()
            ):
                sizes.append(pcap.stat().st_size)
        except (OSError, ValueError, TypeError):
            continue
    return (sum(sizes) // len(sizes), len(sizes)) if sizes else (0, 0)


def _default_report_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_REPORT_DIR / f"formal_dataset_preflight_{stamp}.json"


def run_preflight(
    *,
    plan_path: str | Path,
    dataset_root: str | Path,
    capture_interface: str,
    topology: str,
    isolation_ack: str,
    report_path: str | Path,
    minimum_free_gib: float = 8.0,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run passive checks and persist a non-training readiness report."""
    env = dict(os.environ if environment is None else environment)
    checks: list[dict[str, Any]] = []
    plan_summary: dict[str, Any] = {}
    plan: dict[str, Any] | None = None

    try:
        plan = load_campaign_plan(plan_path)
        statuses = Counter(entry["status"] for entry in plan["entries"])
        modes = Counter(entry["security_mode"] for entry in plan["entries"])
        plan_summary = {
            "campaign_id": plan["campaign_id"],
            "sha256": sha256_file(plan_path),
            "entries": len(plan["entries"]),
            "statuses": dict(sorted(statuses.items())),
            "security_modes": dict(sorted(modes.items())),
        }
        checks.append(
            _check(
                "campaign_plan",
                len(plan["entries"]) == FORMAL_SESSION_COUNT,
                (
                    f"valid plan with {len(plan['entries'])} entries; "
                    f"expected {FORMAL_SESSION_COUNT}"
                ),
            )
        )
        checks.append(
            _check(
                "campaign_resume_state",
                statuses.get("running", 0) == 0
                and statuses.get("failed", 0) == 0,
                f"statuses={dict(sorted(statuses.items()))}",
            )
        )
    except Exception as exc:
        checks.append(
            _check(
                "campaign_plan",
                False,
                f"{type(exc).__name__}: {exc}",
            )
        )

    interfaces = {name for _, name in socket.if_nameindex()}
    checks.append(
        _check(
            "capture_interface",
            capture_interface in interfaces and capture_interface != "any",
            (
                f"requested={capture_interface!r}; "
                f"available={sorted(interfaces)}; interface 'any' is forbidden"
            ),
        )
    )

    topology_ok, topology_detail, claim_scope = _topology_check(
        topology=topology,
        capture_interface=capture_interface,
        isolation_ack=isolation_ack,
        environment=env,
    )
    checks.append(_check("topology_isolation", topology_ok, topology_detail))

    tool_paths: dict[str, str | None] = {
        name: shutil.which(name) for name in REQUIRED_TOOLS
    }
    zeek = shutil.which("zeek")
    if zeek is None and Path("/opt/zeek/bin/zeek").is_file():
        zeek = "/opt/zeek/bin/zeek"
    tool_paths["zeek"] = zeek
    checks.append(
        _check(
            "required_tools",
            all(tool_paths.values()),
            ", ".join(
                f"{name}={path or 'missing'}"
                for name, path in sorted(tool_paths.items())
            ),
        )
    )

    dumpcap = tool_paths.get("dumpcap")
    dumpcap_result = (
        _run_read_only([dumpcap, "-D"]) if isinstance(dumpcap, str) else None
    )
    dumpcap_text = (
        (dumpcap_result.stdout + dumpcap_result.stderr)
        if dumpcap_result is not None
        else ""
    )
    interface_pattern = re.compile(
        rf"(^|[\s.(]){re.escape(capture_interface)}([\s)]|$)",
        re.MULTILINE,
    )
    checks.append(
        _check(
            "dumpcap_permission",
            dumpcap_result is not None
            and dumpcap_result.returncode == 0
            and bool(interface_pattern.search(dumpcap_text)),
            (
                "dumpcap -D must succeed and list the selected interface; "
                f"return_code={getattr(dumpcap_result, 'returncode', None)}"
            ),
        )
    )

    required_paths = [
        POLICY_PATH,
        WORKSPACE_ROOT / "展示指令" / "01_啟動系統.sh",
        WORKSPACE_ROOT / "展示指令" / "01c_啟動系統_enforce.sh",
        WORKSPACE_ROOT / "sros2_keystore" / "enclaves",
    ]
    missing_paths = [
        str(path.relative_to(WORKSPACE_ROOT))
        for path in required_paths
        if not path.exists()
    ]
    checks.append(
        _check(
            "required_project_artifacts",
            not missing_paths,
            "missing=" + (", ".join(missing_paths) if missing_paths else "none"),
        )
    )
    multimodal_ok, multimodal_detail = _live_multimodal_contract_check()
    checks.append(
        _check(
            "live_multimodal_contract",
            multimodal_ok,
            multimodal_detail,
        )
    )

    secret_path = Path.home() / ".config" / "dds-monitor" / "alert_secret"
    secret_ok = False
    secret_detail = f"path={secret_path}; missing"
    try:
        secret_mode = stat.S_IMODE(secret_path.stat().st_mode)
        secret_ok = (
            secret_path.is_file()
            and not secret_path.is_symlink()
            and secret_mode == 0o600
            and secret_path.stat().st_size >= 32
        )
        secret_detail = (
            f"path={secret_path}; mode={oct(secret_mode)}; "
            f"bytes={secret_path.stat().st_size}"
        )
    except OSError:
        pass
    checks.append(_check("hmac_secret_file", secret_ok, secret_detail))

    runner_errors: list[str] = []
    try:
        for scenario in load_catalog().values():
            build_attack_argv(
                scenario,
                workspace_root=WORKSPACE_ROOT,
                duration_sec=scenario.duration_sec,
                intensity=0.5,
            )
    except Exception as exc:
        runner_errors.append(f"{type(exc).__name__}: {exc}")
    checks.append(
        _check(
            "allowlisted_runners",
            not runner_errors,
            runner_errors[0] if runner_errors else "all runner argv resolved",
        )
    )

    git_status = _run_read_only(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"]
    )
    git_lines = (
        [line for line in git_status.stdout.splitlines() if line.strip()]
        if git_status is not None and git_status.returncode == 0
        else []
    )
    checks.append(
        _check(
            "source_snapshot_clean",
            git_status is not None
            and git_status.returncode == 0
            and not git_lines,
            (
                f"dirty_paths={len(git_lines)}; formal collection requires "
                "one frozen revision"
            ),
        )
    )
    git_head = _run_read_only(["git", "rev-parse", "HEAD"])
    revision = (
        git_head.stdout.strip().lower()
        if git_head is not None and git_head.returncode == 0
        else "unknown"
    )

    dataset = Path(dataset_root).expanduser()
    dataset_parent = _nearest_existing_parent(dataset)
    disk = shutil.disk_usage(dataset_parent)
    pilot_average, pilot_sessions = _pilot_pcap_average()
    remaining = (
        FORMAL_SESSION_COUNT
        - int(plan_summary.get("statuses", {}).get("complete", 0))
    )
    estimated_bytes = pilot_average * max(0, remaining)
    minimum_bytes = max(
        int(minimum_free_gib * 1024**3),
        estimated_bytes * 2,
    )
    checks.append(
        _check(
            "storage_capacity",
            disk.free >= minimum_bytes,
            (
                f"free_bytes={disk.free}; required_bytes={minimum_bytes}; "
                f"pilot_average_bytes={pilot_average}; "
                f"pilot_sessions={pilot_sessions}; remaining={remaining}"
            ),
        )
    )
    checks.append(
        _check(
            "dataset_path",
            not dataset.is_symlink(),
            f"path={dataset.resolve()}; symlink={dataset.is_symlink()}",
        )
    )

    lock_path = Path(plan_path).with_suffix(Path(plan_path).suffix + ".lock")
    checks.append(
        _check(
            "campaign_lock",
            not lock_path.exists(),
            f"path={lock_path}; exists={lock_path.exists()}",
        )
    )

    processes = _run_read_only(
        [
            "pgrep",
            "-af",
            "gz sim|ros2 launch dds_security_monitor|"
            "python3 -m firewall_lab.campaign run",
        ]
    )
    process_lines = (
        [line for line in processes.stdout.splitlines() if line.strip()]
        if processes is not None and processes.returncode == 0
        else []
    )
    checks.append(
        _check(
            "runtime_idle",
            not process_lines,
            f"matching_processes={len(process_lines)}",
        )
    )

    blockers = [
        check["name"]
        for check in checks
        if not check["passed"] and check["severity"] == "blocker"
    ]
    warnings = [
        check["name"]
        for check in checks
        if not check["passed"] and check["severity"] == "warning"
    ]
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "created_utc": utc_now(),
        "ready": not blockers,
        "training_eligible": False,
        "network_activity": "none_passive_checks_only",
        "topology": topology,
        "claim_scope": claim_scope,
        "capture_interface": capture_interface,
        "source_revision": revision,
        "plan": plan_summary,
        "storage_estimate": {
            "pilot_average_pcap_bytes": pilot_average,
            "pilot_sessions": pilot_sessions,
            "estimated_remaining_pcap_bytes": estimated_bytes,
            "safety_factor": 2,
            "free_bytes": disk.free,
        },
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
    }
    destination = Path(report_path).expanduser()
    if destination.is_symlink():
        raise ValueError("preflight report path may not be a symlink")
    atomic_write_json(destination, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passive fail-closed preflight for the 1100-session dataset"
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_LIVE_OUTPUT)
    parser.add_argument("--capture-interface", required=True)
    parser.add_argument("--topology", choices=TOPOLOGIES, required=True)
    parser.add_argument("--isolation-ack", default="")
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--minimum-free-gib", type=float, default=8.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 1.0 <= args.minimum_free_gib <= 1024.0:
        raise SystemExit("--minimum-free-gib must be in 1..1024")
    report_path = args.report or _default_report_path()
    report = run_preflight(
        plan_path=args.plan,
        dataset_root=args.dataset,
        capture_interface=args.capture_interface,
        topology=args.topology,
        isolation_ack=args.isolation_ack,
        report_path=report_path,
        minimum_free_gib=args.minimum_free_gib,
    )
    state = "READY" if report["ready"] else "BLOCKED"
    print(
        f"{state} blockers={','.join(report['blockers']) or 'none'} "
        f"report={Path(report_path).resolve()}"
    )
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
