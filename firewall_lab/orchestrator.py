#!/usr/bin/env python3
"""Generate precisely labelled SROS2 firewall experiment sessions.

Smoke mode validates the pipeline but is permanently marked non-trainable.
Live mode executes only allowlisted runners and requires an explicit isolated
lab confirmation.  No runner is loaded from a command string in the catalog.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .catalog import Scenario, load_catalog
from .evidence import (
    JsonlWriter,
    ManagedProcess,
    ResourceSampler,
    evidence_inventory,
    run_snapshot,
)
from .runners import attacker_environment, build_attack_argv
from .schema import (
    SessionManifest,
    atomic_write_json,
    make_event,
    make_label,
    new_session_id,
    sha256_file,
    utc_now,
)


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "dataset"
POLICY_PATH = (
    WORKSPACE_ROOT / "展示指令" / "sros2_policy_least_privilege.xml"
)
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
MAX_SESSIONS_PER_INVOCATION = 10_000
TELEMETRY_SOCKET_NAME = "runtime_telemetry.sock"
# Written by the Fast DDS built-in security logging plugin; the path is
# set in firewall_lab/fastdds_security_log.xml and must match it.
SECURITY_AUDIT_LOG_NAME = "dds_security_audit.log"


class SessionEvents:
    def __init__(self, path: Path, session_id: str, attack_class: str):
        self.writer = JsonlWriter(path)
        self.session_id = session_id
        self.attack_class = attack_class
        self.sequence = 0

    def emit(
        self,
        event_type: str,
        phase: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = make_event(
            session_id=self.session_id,
            sequence=self.sequence,
            event_type=event_type,
            phase=phase,
            attack_class=self.attack_class,
            details=details,
        )
        self.sequence += 1
        self.writer.append(event)
        return event


def _git_revision() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
        )
        revision = result.stdout.strip().lower()
        if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", revision):
            return revision
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _resolve_domain(security_mode: str, requested: int | None) -> int:
    if requested is not None:
        if not 0 <= requested <= 232:
            raise ValueError("domain id must be in 0..232")
        domain = requested
    else:
        # Keep Permissive/Enforce comparisons on the same RTPS port family.
        # Otherwise a model can learn the domain-derived port instead of the
        # attack behavior.  The two modes must be run at different times.
        domain = 30
    if security_mode == "enforce" and domain != 30:
        raise ValueError(
            "canonical SROS2 policy is signed for domain 30; "
            "regenerate a dedicated lab keystore before using another domain"
        )
    return domain


def _prepare_output_root(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path.exists() and path.is_symlink():
        raise ValueError("dataset output root may not be a symlink")
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("dataset output root may not be a symlink")
    return path


def _phase_sleep(seconds: float, mode: str) -> None:
    if mode == "smoke":
        time.sleep(min(0.02, max(0.0, seconds)))
    else:
        time.sleep(seconds)


def _write_smoke_observations(
    path: Path,
    *,
    rng: random.Random,
    attack_class: str,
    intensity: float,
) -> None:
    writer = JsonlWriter(path)
    for index in range(12):
        attack = attack_class != "normal" and 3 <= index <= 8
        multiplier = 1.0 + (intensity * 8.0 if attack else 0.0)
        writer.append(
            {
                "schema_version": "sros2-firewall-smoke-observation/v1",
                "training_eligible": False,
                "sample_index": index,
                "ts_unix_ns": time.time_ns(),
                "participant_count": int(8 + rng.randint(0, 2) + attack),
                "spdp_rate": round(
                    (2.0 + rng.random()) * multiplier, 4
                ),
                "data_rate": round(
                    (20.0 + rng.random() * 5.0) * multiplier, 4
                ),
                "auth_failures": int(attack and intensity > 0.25),
                "permission_denies": int(attack and intensity > 0.5),
                "label": attack_class if attack else "normal",
            }
        )


def _start_capture(
    *,
    interface: str | None,
    session_dir: Path,
    env: dict[str, str],
) -> ManagedProcess | None:
    if interface is None:
        return None
    if not INTERFACE_RE.fullmatch(interface):
        raise ValueError("capture interface contains invalid characters")
    dumpcap = shutil.which("dumpcap")
    if dumpcap is None:
        raise FileNotFoundError(
            "dumpcap is not on PATH; configure non-root packet capture first"
        )
    process = ManagedProcess(
        argv=[
            dumpcap,
            "-q",
            "-i",
            interface,
            "-f",
            "udp portrange 7400-15200",
            "-w",
            str(session_dir / "traffic.pcapng"),
        ],
        cwd=WORKSPACE_ROOT,
        env=env,
        stdout_path=session_dir / "capture.stdout.log",
        stderr_path=session_dir / "capture.stderr.log",
    )
    process.start()
    return process


def _live_runtime_dir() -> Path:
    configured = os.environ.get("FIREWALL_LIVE_RUNTIME")
    return Path(configured) if configured else WORKSPACE_ROOT / "firewall_lab" / "live_runtime"


def _start_runtime_telemetry(
    *,
    session_dir: Path,
    session_id: str,
    env: dict[str, str],
) -> tuple[ManagedProcess, Path]:
    socket_path = _live_runtime_dir() / TELEMETRY_SOCKET_NAME
    process = ManagedProcess(
        argv=[
            sys.executable,
            "-m",
            "firewall_lab.live_telemetry_collector",
            "--session-id",
            session_id,
            "--source",
            "telemetry_collector",
            "--output",
            str(session_dir / "telemetry_events.jsonl"),
            "--socket",
            str(socket_path),
            "--tick-sec",
            "1.0",
        ],
        cwd=WORKSPACE_ROOT,
        env=env,
        stdout_path=session_dir / "telemetry_collector.stdout.log",
        stderr_path=session_dir / "telemetry_collector.stderr.log",
    )
    process.start()
    # A slow start is not a failure.  The collector has to spawn an interpreter
    # and import this package, which costs ~0.8s when the workspace sits on the
    # WSL 9p mount; measured socket-bind time is 0.9-1.1s idle and 1.9s under
    # the load a campaign generates.  Against the original 2.0s deadline that
    # left 50-120ms of margin, so the Permissive arm ran 856 sessions and then
    # lost the whole batch to a coin flip at session 857.
    #
    # Waiting longer costs nothing when the collector is healthy: the loop
    # returns the moment the socket appears.  To keep genuine failures fast,
    # stop as soon as the process exits rather than sitting out the deadline,
    # and report its stderr instead of a bare timeout.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if socket_path.is_socket() and not socket_path.is_symlink():
            return process, socket_path
        if process.poll() is not None:
            break
        time.sleep(0.02)
    result = process.stop(grace_sec=1.0)
    detail = ""
    try:
        stderr = (session_dir / "telemetry_collector.stderr.log").read_text(
            encoding="utf-8", errors="replace"
        ).strip()
        if stderr:
            detail = f"; collector stderr: {stderr.splitlines()[-1][:200]}"
    except OSError:
        pass
    raise RuntimeError(
        "runtime telemetry collector did not create its local socket "
        f"(exit={result.return_code}){detail}"
    )


def _start_sros2_log_adapter(
    *,
    security_mode: str,
    socket_path: Path,
    session_dir: Path,
    env: dict[str, str],
) -> ManagedProcess | None:
    # Prefer the dedicated DDS Security audit sink over the generic stack
    # stdout. The stack log is whatever the nodes chose to print, where any
    # node can emit prose that looks like a security record; across the
    # 1,100-session campaign the adapter read 249,670 lines of it and could
    # classify none. The audit log carries BuiltinLoggingType records with
    # facility 0x0A and a fixed hostname/procid/msgid header, which is what
    # makes a record trustworthy. Falling back keeps older runtime directories
    # working, and the adapter's own counters record which source it followed.
    audit_log = _live_runtime_dir() / SECURITY_AUDIT_LOG_NAME
    stack_log = audit_log
    if stack_log.is_symlink() or not stack_log.is_file():
        stack_log = _live_runtime_dir() / f"{security_mode}.log"
    if stack_log.is_symlink() or not stack_log.is_file():
        return None
    process = ManagedProcess(
        argv=[
            sys.executable,
            "-m",
            "firewall_lab.sros2_deny_adapter",
            "--socket",
            str(socket_path),
            "--source",
            "sros2_log_adapter",
            "--follow",
            str(stack_log),
        ],
        cwd=WORKSPACE_ROOT,
        env=env,
        stdout_path=session_dir / "sros2_adapter.stdout.log",
        stderr_path=session_dir / "sros2_adapter.stderr.log",
    )
    process.start()
    return process


def _telemetry_stream_succeeded(
    session_dir: Path,
    result: dict[str, Any] | None,
) -> bool:
    if not isinstance(result, dict) or result.get("return_code") != 0:
        return False
    path = session_dir / "telemetry_events.jsonl"
    if path.is_symlink() or not path.is_file():
        return False
    try:
        events = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    has_tick = any(item.get("event_type") == "collector_tick" for item in events)
    has_runtime = any(
        item.get("source") != "telemetry_collector"
        and item.get("event_type") != "collector_tick"
        for item in events
    )
    return has_tick and has_runtime


# Zeek closes a UDP flow only after this much inactivity, and writes one
# conn.log record per closed flow stamped with the flow's FIRST packet.  DDS
# keeps its participant flows open for the whole session, so at Zeek's 60s
# default a 45s session yields a single burst of records at t0 and nothing
# afterwards -- the 2026-08-06 loopback pilot collapsed every session into
# window 0, discarding all attack-interval signal.
#
# The timeout must stay below the 8s feature window (features.build_features
# window_sec / synthetic_dataset.DEFAULT_WINDOW_SEC) so any flow still carrying
# traffic during a window is re-logged inside it.  Measured on the pilot PCAPs,
# 5s reproduces exactly the window count that packet timestamps give as ground
# truth (6 and 3), whereas 10s misses windows and 2s degenerates to one record
# per packet, destroying the connection semantics the 14 network features and
# the synthetic pretraining set are built on.
ZEEK_UDP_INACTIVITY_TIMEOUT_SEC = 5


def _run_offline_zeek(session_dir: Path, env: dict[str, str]) -> dict[str, Any]:
    pcap = session_dir / "traffic.pcapng"
    if not pcap.is_file() or pcap.stat().st_size <= 128:
        return {"status": "skipped", "reason": "missing_or_empty_pcap"}
    zeek = shutil.which("zeek")
    if zeek is None and Path("/opt/zeek/bin/zeek").is_file():
        zeek = "/opt/zeek/bin/zeek"
    if zeek is None:
        return {"status": "skipped", "reason": "zeek_not_found"}
    zeek_dir = session_dir / "zeek"
    zeek_dir.mkdir()
    record = run_snapshot(
        argv=[
            zeek,
            "-r",
            str(pcap),
            "-e",
            "redef udp_inactivity_timeout = "
            f"{ZEEK_UDP_INACTIVITY_TIMEOUT_SEC}sec;",
        ],
        cwd=zeek_dir,
        env=env,
        output_path=session_dir / "zeek_process.json",
        timeout_sec=120,
    )
    return {
        "status": "complete" if record["return_code"] == 0 else "failed",
        "return_code": record["return_code"],
        "conn_log": (zeek_dir / "conn.log").is_file(),
        "udp_inactivity_timeout_sec": ZEEK_UDP_INACTIVITY_TIMEOUT_SEC,
    }


def _ros_snapshots(
    *,
    prefix: str,
    session_dir: Path,
    env: dict[str, str],
) -> list[dict[str, Any]]:
    ros2 = shutil.which("ros2")
    if ros2 is None:
        return []
    return [
        run_snapshot(
            argv=[ros2, "node", "list"],
            cwd=WORKSPACE_ROOT,
            env=env,
            output_path=session_dir / f"{prefix}_ros_nodes.json",
            timeout_sec=12,
        ),
        run_snapshot(
            argv=[ros2, "topic", "list", "-t"],
            cwd=WORKSPACE_ROOT,
            env=env,
            output_path=session_dir / f"{prefix}_ros_topics.json",
            timeout_sec=12,
        ),
    ]


def _attack_process_succeeded(
    scenario: Scenario,
    result: dict[str, Any] | None,
) -> bool:
    """Return whether the allowlisted runner produced credible process evidence.

    Most bounded PoCs handle the factory's end-of-window signal and exit zero.
    The ROS demo talker is intentionally long-running, so it is valid only when
    the factory terminated it at the window boundary.  A runner that crashes
    early must never leave an attack-labelled session training eligible.
    """
    if scenario.runner == "normal":
        return result is None
    if not isinstance(result, dict):
        return False
    return_code = result.get("return_code")
    if isinstance(return_code, bool) or not isinstance(return_code, int):
        return False
    if scenario.runner == "unauthorized_participant":
        return (
            result.get("terminated_by_factory") is True
            and return_code in {0, -9, -15}
        )
    return return_code == 0


def run_session(
    *,
    scenario: Scenario,
    output_root: Path,
    mode: str,
    security_mode: str,
    domain_id: int,
    seed: int,
    duration_override: float | None,
    capture_interface: str | None,
    ros_snapshots: bool,
) -> Path:
    rng = random.Random(seed)
    intensity = rng.uniform(
        scenario.intensity_min, scenario.intensity_max
    )
    duration = (
        float(duration_override)
        if duration_override is not None
        else scenario.duration_sec
    )
    if not 1.0 <= duration <= 300.0:
        raise ValueError("session duration must be in 1..300 seconds")

    session_id = new_session_id(scenario.scenario_id)
    session_dir = output_root / session_id
    session_dir.mkdir(mode=0o700)
    if session_dir.is_symlink():
        raise ValueError("session directory may not be a symlink")

    policy_digest = sha256_file(POLICY_PATH) if POLICY_PATH.is_file() else ""
    manifest = SessionManifest(
        session_id=session_id,
        scenario_id=scenario.scenario_id,
        attack_class=scenario.attack_class,
        binary_label=(
            "normal" if scenario.attack_class == "normal" else "attack"
        ),
        security_mode=security_mode,
        ros_domain_id=domain_id,
        seed=seed,
        origin="live_lab" if mode == "live" else "simulated_smoke",
        training_eligible=False,
        expected_action=scenario.expected_action,
        policy_sha256=policy_digest,
        code_revision=_git_revision(),
        randomization={
            "intensity": intensity,
            "duration_sec": duration,
            "warmup_sec": scenario.warmup_sec,
            "cooldown_sec": scenario.cooldown_sec,
            "requires_gazebo": scenario.requires_gazebo,
        },
    )
    manifest_path = session_dir / "manifest.json"
    manifest.write(manifest_path)
    events = SessionEvents(
        session_dir / "events.jsonl",
        session_id,
        scenario.attack_class,
    )
    labels = JsonlWriter(session_dir / "labels.jsonl")
    resources = ResourceSampler(session_dir / "resources.jsonl")
    attack_process: ManagedProcess | None = None
    capture_process: ManagedProcess | None = None
    telemetry_process: ManagedProcess | None = None
    sros_adapter_process: ManagedProcess | None = None
    attack_result = None
    capture_result = None
    telemetry_result = None
    sros_adapter_result = None
    env = attacker_environment(domain_id=domain_id)

    try:
        manifest.status = "running"
        manifest.started_utc = utc_now()
        manifest.write(manifest_path)
        events.emit(
            "session_started",
            "setup",
            {
                "mode": mode,
                "security_mode": security_mode,
                "domain_id": domain_id,
                "intensity": intensity,
            },
        )
        resources.start()
        if mode == "live":
            telemetry_process, telemetry_socket = _start_runtime_telemetry(
                session_dir=session_dir,
                session_id=session_id,
                env=env,
            )
            sros_adapter_process = _start_sros2_log_adapter(
                security_mode=security_mode,
                socket_path=telemetry_socket,
                session_dir=session_dir,
                env=env,
            )
            capture_process = _start_capture(
                interface=capture_interface,
                session_dir=session_dir,
                env=env,
            )
            if ros_snapshots:
                _ros_snapshots(
                    prefix="pre",
                    session_dir=session_dir,
                    env=env,
                )
        else:
            _write_smoke_observations(
                session_dir / "smoke_observations.jsonl",
                rng=rng,
                attack_class=scenario.attack_class,
                intensity=intensity,
            )

        events.emit("warmup_started", "warmup")
        _phase_sleep(scenario.warmup_sec, mode)
        events.emit("warmup_completed", "warmup")

        attack_start = time.time_ns()
        events.emit(
            "attack_started",
            "attack",
            {
                "runner": scenario.runner,
                "credential_mode": "none",
            },
        )
        if mode == "live":
            argv = build_attack_argv(
                scenario,
                workspace_root=WORKSPACE_ROOT,
                duration_sec=duration,
                intensity=intensity,
            )
            if argv is not None:
                attack_process = ManagedProcess(
                    argv=argv,
                    cwd=WORKSPACE_ROOT,
                    env=env,
                    stdout_path=session_dir / "attack.stdout.log",
                    stderr_path=session_dir / "attack.stderr.log",
                )
                attack_process.start()
        _phase_sleep(duration, mode)
        attack_end = time.time_ns()
        events.emit("attack_completed", "attack")
        labels.append(
            make_label(
                session_id=session_id,
                attack_class=scenario.attack_class,
                start_unix_ns=attack_start,
                end_unix_ns=attack_end,
                source="allowlisted_runner" if mode == "live" else "smoke",
            )
        )

        if attack_process is not None:
            attack_result = attack_process.stop().to_dict()
            attack_process = None

        events.emit("cooldown_started", "cooldown")
        _phase_sleep(scenario.cooldown_sec, mode)
        events.emit("cooldown_completed", "cooldown")

        if mode == "live" and ros_snapshots:
            _ros_snapshots(
                prefix="post",
                session_dir=session_dir,
                env=env,
            )
        if capture_process is not None:
            capture_result = capture_process.stop().to_dict()
            capture_process = None
        if sros_adapter_process is not None:
            sros_adapter_result = sros_adapter_process.stop().to_dict()
            sros_adapter_process = None
        if telemetry_process is not None:
            telemetry_result = telemetry_process.stop().to_dict()
            telemetry_process = None

        zeek_result = (
            _run_offline_zeek(session_dir, env)
            if mode == "live"
            else {"status": "skipped", "reason": "smoke"}
        )
        pcap = session_dir / "traffic.pcapng"
        pcap_ok = (
            mode == "live"
            and pcap.is_file()
            and pcap.stat().st_size > 128
        )
        zeek_ok = (
            mode == "live"
            and zeek_result.get("status") == "complete"
            and zeek_result.get("return_code") == 0
            and zeek_result.get("conn_log") is True
        )
        capture_ok = (
            mode == "live"
            and isinstance(capture_result, dict)
            and capture_result.get("return_code") == 0
        )
        attack_ok = _attack_process_succeeded(scenario, attack_result)
        telemetry_ok = (
            mode == "live"
            and _telemetry_stream_succeeded(session_dir, telemetry_result)
        )
        gate_failures = [
            name
            for name, passed in (
                ("pcap", pcap_ok),
                ("zeek", zeek_ok),
                ("capture_process", capture_ok),
                ("attack_process", attack_ok),
                ("runtime_telemetry", telemetry_ok),
            )
            if not passed
        ]
        manifest.training_eligible = not gate_failures
        manifest.result = {
            "attack_process": attack_result,
            "capture_process": capture_result,
            "telemetry_process": telemetry_result,
            "sros2_adapter_process": sros_adapter_result,
            "zeek": zeek_result,
            "label_interval_written": True,
            "training_gate": (
                "eligible"
                if not gate_failures
                else "not_eligible:" + ",".join(gate_failures)
            ),
        }
        manifest.status = "complete"
        events.emit(
            "session_completed",
            "finalize",
            {
                "training_eligible": manifest.training_eligible,
                "zeek_status": zeek_result.get("status"),
            },
        )
    except Exception as exc:
        manifest.status = "failed"
        manifest.training_eligible = False
        manifest.result = {
            "error_type": type(exc).__name__,
            "error": str(exc)[:2048],
            "attack_process": attack_result,
            "capture_process": capture_result,
            "telemetry_process": telemetry_result,
            "sros2_adapter_process": sros_adapter_result,
        }
        try:
            events.emit(
                "session_failed",
                "finalize",
                {
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        except Exception:
            pass
        raise
    finally:
        if attack_process is not None:
            try:
                manifest.result["attack_process"] = (
                    attack_process.stop().to_dict()
                )
            except Exception as stop_exc:
                manifest.result["attack_stop_error"] = str(stop_exc)[:1024]
        if capture_process is not None:
            try:
                manifest.result["capture_process"] = (
                    capture_process.stop().to_dict()
                )
            except Exception as stop_exc:
                manifest.result["capture_stop_error"] = str(stop_exc)[:1024]
        if sros_adapter_process is not None:
            try:
                manifest.result["sros2_adapter_process"] = (
                    sros_adapter_process.stop().to_dict()
                )
            except Exception as stop_exc:
                manifest.result["sros2_adapter_stop_error"] = str(stop_exc)[:1024]
        if telemetry_process is not None:
            try:
                manifest.result["telemetry_process"] = (
                    telemetry_process.stop().to_dict()
                )
            except Exception as stop_exc:
                manifest.result["telemetry_stop_error"] = str(stop_exc)[:1024]
        resources.stop()
        manifest.ended_utc = utc_now()
        try:
            manifest.evidence = evidence_inventory(session_dir)
        except Exception as inventory_exc:
            manifest.status = "failed"
            manifest.training_eligible = False
            manifest.result["inventory_error"] = str(inventory_exc)[:1024]
        manifest.write(manifest_path)

    return session_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SROS2 intelligent firewall dataset session factory"
    )
    parser.add_argument(
        "--scenario",
        default="all",
        help="scenario id or 'all' for seeded catalog rotation",
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=1,
        help=f"number of sessions (1..{MAX_SESSIONS_PER_INVOCATION})",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--mode",
        choices=("smoke", "live"),
        default="smoke",
    )
    parser.add_argument(
        "--security-mode",
        choices=("permissive", "enforce"),
        default=None,
    )
    parser.add_argument("--domain-id", type=int, default=None)
    parser.add_argument("--duration", type=float, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )
    parser.add_argument(
        "--capture-interface",
        default=None,
        help="non-root dumpcap interface; omit to create a non-trainable live session",
    )
    parser.add_argument(
        "--ros-snapshots",
        action="store_true",
        help="capture ros2 node/topic CLI snapshots (best for Permissive)",
    )
    parser.add_argument(
        "--confirm-isolated-lab",
        action="store_true",
        help="required for live attack execution",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if (
        isinstance(args.sessions, bool)
        or not 1 <= args.sessions <= MAX_SESSIONS_PER_INVOCATION
    ):
        raise SystemExit(
            f"--sessions must be in 1..{MAX_SESSIONS_PER_INVOCATION}"
        )
    if args.mode == "live" and not args.confirm_isolated_lab:
        raise SystemExit(
            "live mode refused: add --confirm-isolated-lab only after "
            "verifying the ROS domain/network is isolated and authorized"
        )
    if args.capture_interface and args.mode != "live":
        raise SystemExit("--capture-interface is only valid in live mode")

    catalog = load_catalog()
    if args.scenario != "all" and args.scenario not in catalog:
        raise SystemExit(
            f"unknown scenario {args.scenario!r}; "
            f"choose one of {sorted(catalog)} or all"
        )
    output_root = _prepare_output_root(args.output)
    ordered = [catalog[key] for key in sorted(catalog)]
    generated = []
    for index in range(args.sessions):
        scenario = (
            catalog[args.scenario]
            if args.scenario != "all"
            else ordered[(args.seed + index) % len(ordered)]
        )
        security_mode = (
            args.security_mode or scenario.default_security_mode
        )
        domain = _resolve_domain(security_mode, args.domain_id)
        session_seed = args.seed + index
        generated.append(
            run_session(
                scenario=scenario,
                output_root=output_root,
                mode=args.mode,
                security_mode=security_mode,
                domain_id=domain,
                seed=session_seed,
                duration_override=args.duration,
                capture_interface=args.capture_interface,
                ros_snapshots=args.ros_snapshots,
            )
        )
        print(
            f"✅ {generated[-1].name}: {scenario.scenario_id} "
            f"({args.mode}, {security_mode}, seed={session_seed})"
        )

    index_record = {
        "schema_version": "sros2-firewall-batch/v1",
        "created_utc": utc_now(),
        "mode": args.mode,
        "sessions": [path.name for path in generated],
    }
    atomic_write_json(
        output_root / f"batch_{time.time_ns()}.json",
        index_record,
    )
    print(f"輸出：{output_root}")
    if args.mode == "smoke":
        print("注意：smoke session 永久標記 training_eligible=false。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
