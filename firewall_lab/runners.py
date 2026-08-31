"""Fixed attack runner registry for the isolated firewall lab."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .catalog import Scenario

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]


SECRET_ENV_NAMES = frozenset(
    {
        "DDS_ALERT_SECRET",
        "LINE_CHANNEL_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    }
)
SECURITY_ENV_NAMES = frozenset(
    {
        "ROS_SECURITY_KEYSTORE",
        "ROS_SECURITY_ENABLE",
        "ROS_SECURITY_STRATEGY",
        "ROS_SECURITY_ENCLAVE_OVERRIDE",
        "SROS2_FIREWALL_TELEMETRY_SOCKET",
    }
)


def attacker_environment(
    *,
    domain_id: int,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Create an uncredentialed attacker environment for before/after tests."""
    env = dict(os.environ if base is None else base)
    for name in SECRET_ENV_NAMES | SECURITY_ENV_NAMES:
        env.pop(name, None)
    env["ROS_DOMAIN_ID"] = str(domain_id)
    env.setdefault("RMW_IMPLEMENTATION", "rmw_fastrtps_cpp")
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _script(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"allowlisted attack script missing: {path}")
    return str(path)


def build_attack_argv(
    scenario: Scenario,
    *,
    workspace_root: str | Path,
    duration_sec: float,
    intensity: float,
) -> list[str] | None:
    """Translate one catalog runner key to a fixed argv list."""
    root = Path(workspace_root).resolve()
    duration = max(1.0, min(float(duration_sec), 300.0))
    intensity = max(0.0, min(float(intensity), 1.0))
    python = sys.executable
    poc = "紅隊測試/PoC腳本"

    if scenario.runner == "normal":
        return None
    if scenario.runner == "unauthorized_participant":
        ros2 = shutil.which("ros2")
        if ros2 is None:
            raise FileNotFoundError("ros2 executable is not on PATH")
        return [ros2, "run", "demo_nodes_cpp", "talker"]
    if scenario.runner == "cmd_vel_injection":
        return [
            python,
            _script(root, f"{poc}/N9_cmd_vel_race.py"),
            f"{duration:.3f}",
        ]
    if scenario.runner == "sensor_status_spoof":
        return [
            python,
            _script(root, f"{poc}/N6_sensor_status_spoof.py"),
            f"{duration:.3f}",
        ]
    if scenario.runner == "parameter_tamper":
        # Duration is required, not optional: the orchestrator labels the whole
        # [attack_start, attack_end] phase as this attack class, so a one-shot
        # runner would mark the rest of the phase as attack traffic while the
        # system sat idle.
        return [
            python,
            _script(root, f"{poc}/N14_param_whitelist_hijack.py"),
            f"{duration:.3f}",
        ]
    if scenario.runner == "oversized_scan":
        # Dataset generation must not turn one sample into a host OOM.  Scale
        # only within a bounded 5k..50k points and 1..3 Hz.
        points = int(5_000 + intensity * 45_000)
        rate_hz = 1.0 + intensity * 2.0
        return [
            python,
            _script(root, f"{poc}/N24_oversized_scan.py"),
            str(points),
            f"{rate_hz:.3f}",
            f"{duration:.3f}",
        ]
    if scenario.runner == "parameter_flood":
        workers = int(2 + intensity * 6)
        return [
            python,
            _script(root, f"{poc}/N19_param_service_flood.py"),
            "dds_security_monitor",
            str(workers),
            f"{duration:.3f}",
        ]
    if scenario.runner == "heartbeat_replay":
        return [
            python,
            _script(root, f"{poc}/N1_heartbeat_replay.py"),
            f"{duration:.3f}",
        ]
    if scenario.runner == "discovery_recon":
        # 被動偵察：加入 domain 但不建立任何 publisher／subscriber，
        # 只讀 DDS 主動公告出來的拓撲。intensity 只影響輪詢密度，
        # **不影響送出的流量**——這一類的定義就是不送東西。
        interval = 2.0 - intensity * 1.5      # 0.5 .. 2.0 秒
        return [
            python,
            _script(root, f"{poc}/N32_discovery_recon.py"),
            f"{duration:.3f}",
            "--mode", "silent-participant",
            "--interval", f"{interval:.3f}",
        ]
    if scenario.runner == "alert_replay":
        return [
            python,
            _script(root, f"{poc}/N3_alert_replay_dos.py"),
            f"{duration:.3f}",
        ]
    raise ValueError(f"runner has no fixed argv implementation: {scenario.runner}")
