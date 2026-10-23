#!/usr/bin/env python3
"""Passive reproducibility audit for the SROS2 firewall repository.

Default execution only reads local files and installed-package metadata.  It
does not install packages, source or start ROS, send network traffic, invoke an
attack tool, or modify firewall state.  ``--run-tests`` is the sole opt-in
execution step and calls the repository's existing ``run_full_tests.sh``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


AUDIT_SCHEMA = "sros2-firewall-reproducibility-audit/v1"
STATUSES = frozenset({"verified", "provisional", "blocked"})
DEFAULT_CRITICAL_FILES = (
    "firewall_lab/action_policy.json",
    "firewall_lab/live_multimodal_contract.json",
    "firewall_lab/dataset_exclusions.v1.json",
    "firewall_lab/hierarchical_model.py",
    "firewall_lab/hierarchical_training.py",
    "firewall_lab/project_evidence.py",
    "工具腳本/run_full_tests.sh",
    "工具腳本/verify_reproducibility.py",
)
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        raise ValueError("path must use POSIX repo-relative syntax")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("path must stay inside repository")
    candidate = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"path is symlinked: {relative}")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root)
    if not resolved.is_file() or resolved.stat().st_size <= 0:
        raise ValueError(f"file is missing or empty: {relative}")
    return resolved


def _check(name: str, status: str, detail: str, **extra: Any) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError("invalid audit status")
    return {"name": name, "status": status, "detail": detail[:2048], **extra}


def _read_expected_python(root: Path) -> str:
    config = _safe_file(root, ".venv/pyvenv.cfg")
    for line in config.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "version":
            expected = value.strip()
            if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected):
                return expected
    raise ValueError(".venv/pyvenv.cfg has no exact Python version")


def _python_check(root: Path) -> dict[str, Any]:
    actual = ".".join(str(item) for item in sys.version_info[:3])
    try:
        expected = _read_expected_python(root)
        status = "verified" if actual == expected else "blocked"
        return _check(
            "python_version",
            status,
            f"expected={expected}; actual={actual}",
            expected=expected,
            actual=actual,
            executable=sys.executable,
        )
    except (OSError, ValueError) as exc:
        return _check("python_version", "blocked", f"{type(exc).__name__}: {exc}")


def _ros_check() -> dict[str, Any]:
    setup = Path("/opt/ros/jazzy/setup.bash")
    ros2 = Path("/opt/ros/jazzy/bin/ros2")
    present = setup.is_file() and setup.stat().st_size > 0 and ros2.is_file()
    return _check(
        "ros_jazzy_installation",
        "verified" if present else "blocked",
        (
            "ROS 2 Jazzy setup and ros2 executable are present; neither was invoked"
            if present
            else "missing /opt/ros/jazzy/setup.bash or /opt/ros/jazzy/bin/ros2"
        ),
        expected_distro="jazzy",
        environment_ros_distro=os.environ.get("ROS_DISTRO"),
        ros_started=False,
    )


def _dependency_checks(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    relative = "ML防禦/requirements.txt"
    try:
        path = _safe_file(root, relative)
        pins: list[tuple[str, str]] = []
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = PIN_RE.fullmatch(line)
            if match is None:
                raise ValueError(f"line {line_number} is not an exact == pin")
            pins.append((match.group(1), match.group(2)))
        if not pins:
            raise ValueError("requirements file has no pins")
    except (OSError, ValueError) as exc:
        return _check("dependency_lock", "blocked", f"{type(exc).__name__}: {exc}"), []

    packages = []
    all_match = True
    for name, expected in pins:
        try:
            actual = importlib.metadata.version(name)
            matches = actual == expected
        except importlib.metadata.PackageNotFoundError:
            actual = None
            matches = False
        all_match = all_match and matches
        packages.append(
            {
                "name": name,
                "expected": expected,
                "actual": actual,
                "matches": matches,
            }
        )
    return (
        _check(
            "dependency_lock",
            "verified" if all_match else "blocked",
            f"exact pins matched {sum(item['matches'] for item in packages)}/{len(packages)}",
            path=relative,
            bytes=path.stat().st_size,
            sha256=_sha256_file(path),
        ),
        packages,
    )


def _critical_file_checks(root: Path, relative_paths: list[str]) -> list[dict[str, Any]]:
    results = []
    for relative in relative_paths:
        try:
            path = _safe_file(root, relative)
            results.append(
                _check(
                    f"critical_file:{relative}",
                    "verified",
                    "regular non-empty repository file hashed",
                    path=PurePosixPath(relative).as_posix(),
                    bytes=path.stat().st_size,
                    sha256=_sha256_file(path),
                )
            )
        except (OSError, ValueError, RuntimeError) as exc:
            results.append(
                _check(
                    f"critical_file:{relative}",
                    "blocked",
                    f"{type(exc).__name__}: {exc}",
                    path=relative,
                )
            )
    return results


def _bounded_output(payload: bytes, maximum: int = 8000) -> str:
    return payload[-maximum:].decode("utf-8", "replace")


def _run_full_tests(root: Path, timeout_sec: int) -> dict[str, Any]:
    try:
        script = _safe_file(root, "工具腳本/run_full_tests.sh")
    except (OSError, ValueError, RuntimeError) as exc:
        return _check("full_test_execution", "blocked", f"{type(exc).__name__}: {exc}")
    bash = shutil.which("bash")
    if bash is None:
        return _check("full_test_execution", "blocked", "bash executable is unavailable")
    argv = [bash, str(script), "tests/", "-q"]
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_sec)
        return_code = int(process.returncode if process.returncode is not None else -9)
        return _check(
            "full_test_execution",
            "verified" if return_code == 0 else "blocked",
            f"run_full_tests.sh return_code={return_code}",
            argv=["bash", "工具腳本/run_full_tests.sh", "tests/", "-q"],
            return_code=return_code,
            duration_sec=round(time.monotonic() - started, 6),
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            stdout_tail=_bounded_output(stdout),
            stderr_tail=_bounded_output(stderr),
        )
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (AttributeError, OSError, ProcessLookupError):
            process.kill()
        process.communicate()
        return _check(
            "full_test_execution",
            "blocked",
            f"run_full_tests.sh exceeded {timeout_sec} seconds",
            duration_sec=round(time.monotonic() - started, 6),
        )


def audit_reproducibility(
    repo_root: str | Path,
    *,
    run_tests: bool = False,
    test_timeout_sec: int = 900,
    critical_files: tuple[str, ...] = DEFAULT_CRITICAL_FILES,
) -> dict[str, Any]:
    root = Path(repo_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("repo root must be a real directory")
    root = root.resolve(strict=True)
    if isinstance(test_timeout_sec, bool) or not 10 <= test_timeout_sec <= 3600:
        raise ValueError("test timeout must be in 10..3600 seconds")

    dependency, packages = _dependency_checks(root)
    checks = [_python_check(root), _ros_check(), dependency]
    checks.extend(_critical_file_checks(root, list(critical_files)))
    if run_tests:
        checks.append(_run_full_tests(root, test_timeout_sec))
    else:
        checks.append(
            _check(
                "full_test_execution",
                "provisional",
                "not run; pass --run-tests to invoke the existing test runner",
            )
        )

    counts = {status: sum(item["status"] == status for item in checks) for status in STATUSES}
    overall = "blocked" if counts["blocked"] else ("provisional" if counts["provisional"] else "verified")
    return {
        "schema_version": AUDIT_SCHEMA,
        "created_utc": _utc_now(),
        "overall_status": overall,
        "summary": {"total": len(checks), **counts},
        "checks": checks,
        "dependencies": packages,
        "safety": {
            "packages_installed": False,
            "ros_started": False,
            "network_or_attack_traffic_generated": False,
            "firewall_state_changed": False,
            "tests_explicitly_requested": bool(run_tests),
            "test_runner": "工具腳本/run_full_tests.sh" if run_tests else None,
        },
        "limitations": [
            "File hashes are observations, not signatures or a trusted remote attestation.",
            "ROS presence is checked from files only; no ROS process is started.",
            "Without --run-tests the audit is necessarily provisional.",
            "This audit is not live, cross-host, Raspberry Pi, or firewall-backend evidence.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a passive reproducibility audit")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--test-timeout-sec", type=int, default=900)
    parser.add_argument("--critical-file", action="append")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "atomically publish the JSON report to a new file; an existing "
            "file or symlink is never overwritten"
        ),
    )
    return parser


def _serialize_report(report: dict[str, Any], *, pretty: bool) -> bytes:
    return (
        json.dumps(
            report,
            ensure_ascii=False,
            sort_keys=True,
            indent=2 if pretty else None,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def atomic_publish_report(output: str | Path, payload: bytes) -> Path:
    """Publish ``payload`` as one new regular file without overwriting.

    The fully flushed staging file is hard-linked into place.  Creating that
    final directory entry is atomic and fails closed when another file or
    symlink already owns the requested name.  The caller must provide an
    existing, non-symlink parent directory so an output typo cannot silently
    create a different directory tree.
    """

    if not isinstance(payload, bytes) or not payload:
        raise ValueError("report payload must be non-empty bytes")
    destination = Path(output)
    if not destination.name or destination.name in {".", ".."}:
        raise ValueError("output must name a file")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to overwrite audit report: {destination}")

    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("output parent must be an existing non-symlink directory")
    parent = parent.resolve(strict=True)
    destination = parent / destination.name
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to overwrite audit report: {destination}")

    descriptor, staging_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=parent
    )
    staging = Path(staging_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staging, destination)
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to overwrite audit report: {destination}"
            ) from exc
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
        except (AttributeError, OSError):
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            except OSError:
                pass
            finally:
                os.close(directory_fd)
        return destination
    finally:
        try:
            staging.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    critical = tuple(args.critical_file) if args.critical_file else DEFAULT_CRITICAL_FILES
    try:
        report = audit_reproducibility(
            args.repo_root,
            run_tests=args.run_tests,
            test_timeout_sec=args.test_timeout_sec,
            critical_files=critical,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        report = {
            "schema_version": AUDIT_SCHEMA,
            "created_utc": _utc_now(),
            "overall_status": "blocked",
            "error": f"{type(exc).__name__}: {exc}",
            "safety": {
                "packages_installed": False,
                "ros_started": False,
                "network_or_attack_traffic_generated": False,
                "firewall_state_changed": False,
            },
        }
    payload = _serialize_report(report, pretty=args.pretty)
    if args.output is not None:
        try:
            atomic_publish_report(args.output, payload)
        except (OSError, ValueError) as exc:
            print(f"output_error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
    sys.stdout.buffer.write(payload)
    return 0 if report.get("overall_status") in {"verified", "provisional"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
