"""Create a read-only, hash-inventoried baseline before red-team testing.

This command deliberately contains no target argument and cannot launch
Metasploit, scanners, ROS publishers, or exploit helpers.  Its only job is to
prove what defensive state existed immediately before an authorized test.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .evidence import evidence_inventory, run_snapshot
from .schema import atomic_write_json, sha256_file, utc_now


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = ROOT / "firewall_lab" / "readiness_evidence"
SCHEMA_VERSION = "sros2-blue-team-readiness/v1"
FORBIDDEN_EXECUTABLES = frozenset(
    {
        "hydra",
        "masscan",
        "msfconsole",
        "msfvenom",
        "nmap",
        "ros2",
    }
)


@dataclass(frozen=True)
class Check:
    name: str
    argv: tuple[str, ...]
    required: bool
    cwd: Path
    timeout_sec: float = 30.0


def _windows_path(path: Path) -> str | None:
    if os.name == "nt":
        return str(path)
    converter = shutil.which("wslpath")
    if converter is None:
        return None
    result = subprocess.run(
        [converter, "-w", str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def _zeek_executable() -> str:
    path = shutil.which("zeek")
    if path:
        return path
    fallback = Path("/opt/zeek/bin/zeek")
    return str(fallback) if fallback.is_file() else "zeek"


def build_checks(run_dir: Path) -> list[Check]:
    zeek_runtime = run_dir / "zeek_runtime"
    zeek_runtime.mkdir(parents=True, exist_ok=True)
    checks = [
        Check(
            "sros2_audit",
            ("bash", str(ROOT / "展示指令" / "sros2_稽核.sh")),
            True,
            ROOT,
            90,
        ),
        Check(
            "live_preflight",
            ("bash", str(ROOT / "firewall_lab" / "preflight_live.sh")),
            True,
            ROOT,
        ),
        Check(
            "host_surface",
            ("bash", str(ROOT / "展示指令" / "主機攻擊面稽核.sh")),
            True,
            ROOT,
        ),
        Check(
            "zeek_policy_load",
            (
                _zeek_executable(),
                "-b",
                str(ROOT / "Zeek監控" / "dds_monitor.zeek"),
            ),
            True,
            zeek_runtime,
            60,
        ),
        Check(
            "focused_regression",
            (
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/test_sros2_policy.py",
                "tests/test_zeek_helpers.py",
            ),
            True,
            ROOT,
            120,
        ),
        Check(
            "live_enforce_status",
            (
                "bash",
                str(ROOT / "firewall_lab" / "live_stack.sh"),
                "status",
                "enforce",
            ),
            False,
            ROOT,
        ),
        Check(
            "evidence_capture_status",
            (
                "bash",
                str(ROOT / "firewall_lab" / "blue_team_capture.sh"),
                "status",
            ),
            False,
            ROOT,
        ),
        Check("interfaces", ("ip", "-brief", "address"), False, ROOT),
        Check("listeners", ("ss", "-tulpen"), False, ROOT),
        Check(
            "git_status",
            ("git", "status", "--short", "--branch"),
            False,
            ROOT,
        ),
    ]

    powershell = shutil.which("powershell.exe")
    snapshot_script = _windows_path(
        ROOT / "firewall_lab" / "windows_defense_snapshot.ps1"
    )
    if powershell and snapshot_script:
        checks.append(
            Check(
                "windows_defense",
                (
                    powershell,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    snapshot_script,
                ),
                False,
                ROOT,
                45,
            )
        )
    return checks


def validate_check(check: Check) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", check.name):
        raise ValueError(f"invalid check name: {check.name}")
    if not check.argv:
        raise ValueError("empty readiness command")
    executable = Path(check.argv[0]).name.lower()
    if executable in FORBIDDEN_EXECUTABLES:
        raise ValueError(f"attack executable forbidden in readiness: {executable}")


def _safe_output_root(value: str | Path) -> Path:
    output = Path(value).resolve()
    workspace = ROOT.resolve()
    if output != workspace and workspace not in output.parents:
        raise ValueError("readiness evidence must stay inside the workspace")
    if output.exists() and output.is_symlink():
        raise ValueError("readiness output root may not be a symlink")
    return output


def _host_risk_count(stdout: str) -> int | None:
    match = re.search(r"風險暴露項[：:]\s*([0-9]+)", stdout)
    return int(match.group(1)) if match else None


def create_readiness_bundle(
    *,
    output_root: str | Path = DEFAULT_OUTPUT_ROOT,
    require_live_enforce: bool = False,
    require_capture: bool = False,
) -> tuple[Path, dict]:
    destination = _safe_output_root(output_root)
    run_id = (
        "readiness-"
        + utc_now().replace("-", "").replace(":", "").replace(".", "")
        .replace("+0000", "Z")
    )
    run_dir = destination / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    if os.name != "nt":
        os.chmod(run_dir, 0o700)

    env = dict(os.environ)
    env["ROS_DOMAIN_ID"] = "30"
    checks = build_checks(run_dir)
    results = []
    records_by_name = {}
    for check in checks:
        validate_check(check)
        record = run_snapshot(
            argv=list(check.argv),
            cwd=check.cwd,
            env=env,
            output_path=run_dir / "checks" / f"{check.name}.json",
            timeout_sec=check.timeout_sec,
        )
        records_by_name[check.name] = record
        results.append(
            {
                "name": check.name,
                "required": check.required,
                "return_code": record["return_code"],
                "passed": record["return_code"] == 0,
                "evidence_file": f"checks/{check.name}.json",
            }
        )

    by_name = {item["name"]: item for item in results}
    enforce_record = records_by_name.get("live_enforce_status", {})
    enforce_result = by_name.get("live_enforce_status")
    stack_ready = bool(
        enforce_result
        and enforce_result["passed"]
        and "readiness=ready" in str(enforce_record.get("stdout", ""))
    )
    capture_record = records_by_name.get("evidence_capture_status", {})
    capture_result = by_name.get("evidence_capture_status")
    capture_ready = bool(
        capture_result
        and capture_result["passed"]
        and "state=running" in str(capture_record.get("stdout", ""))
    )

    host_record = records_by_name.get("host_surface", {})
    host_risk_count = _host_risk_count(str(host_record.get("stdout", "")))

    required_passed = all(
        item["passed"] for item in results if item["required"]
    )
    baseline_ready = required_passed
    attack_ready = required_passed and stack_ready and capture_ready
    command_passed = (
        baseline_ready
        and (stack_ready if require_live_enforce else True)
        and (capture_ready if require_capture else True)
    )
    warnings = []
    if not stack_ready:
        warnings.append("SROS2 Enforce stack is not confirmed ready")
    if not capture_ready:
        warnings.append("bounded packet evidence capture is not confirmed running")
    if host_risk_count:
        warnings.append(
            f"host exposure audit reports {host_risk_count} risky listener entries"
        )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_utc": utc_now(),
        "origin": "read_only_blue_team_baseline",
        "training_eligible": False,
        "require_live_enforce": require_live_enforce,
        "require_capture": require_capture,
        "baseline_ready": baseline_ready,
        "required_checks_passed": required_passed,
        "live_enforce_ready": stack_ready,
        "evidence_capture_ready": capture_ready,
        "attack_ready": attack_ready,
        "command_passed": command_passed,
        "host_risk_count": host_risk_count,
        "warnings": warnings,
        "checks": results,
        "policy_sha256": sha256_file(
            ROOT / "展示指令" / "sros2_policy_least_privilege.xml"
        ),
        "zeek_policy_sha256": sha256_file(
            ROOT / "Zeek監控" / "dds_monitor.zeek"
        ),
        "evidence": {},
    }
    manifest_path = run_dir / "manifest.json"
    atomic_write_json(manifest_path, manifest)
    manifest["evidence"] = evidence_inventory(run_dir)
    atomic_write_json(manifest_path, manifest)
    return run_dir, manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture a read-only defensive readiness baseline"
    )
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="workspace-local evidence directory",
    )
    parser.add_argument(
        "--require-live-enforce",
        action="store_true",
        help="fail unless live_stack reports SROS2 Enforce ready",
    )
    parser.add_argument(
        "--require-capture",
        action="store_true",
        help="fail unless the bounded external-red-team capture is running",
    )
    args = parser.parse_args()
    run_dir, manifest = create_readiness_bundle(
        output_root=args.output_root,
        require_live_enforce=args.require_live_enforce,
        require_capture=args.require_capture,
    )
    print(
        f"run_dir={run_dir}\n"
        f"required_checks_passed={manifest['required_checks_passed']}\n"
        f"live_enforce_ready={manifest['live_enforce_ready']}\n"
        f"evidence_capture_ready={manifest['evidence_capture_ready']}\n"
        f"attack_ready={manifest['attack_ready']}\n"
        f"host_risk_count={manifest['host_risk_count']}"
    )
    return 0 if manifest["command_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
