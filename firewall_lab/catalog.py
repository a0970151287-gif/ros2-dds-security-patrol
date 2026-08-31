"""Load the declarative scenario catalog without allowing arbitrary commands."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .schema import (
    SchemaError,
    require_finite_number,
    require_identifier,
)


CATALOG_SCHEMA_VERSION = "sros2-firewall-catalog/v1"
ALLOWED_RUNNERS = frozenset(
    {
        "normal",
        "unauthorized_participant",
        "cmd_vel_injection",
        "sensor_status_spoof",
        "parameter_tamper",
        "oversized_scan",
        "parameter_flood",
        "heartbeat_replay",
        "alert_replay",
        # 被動偵察：只聽不說。policy 早就有 discovery_recon 這條規則，
        # 缺的一直是產生資料的 runner。
        "discovery_recon",
    }
)
ALLOWED_ACTIONS = frozenset(
    {
        "allow",
        "deny_participant",
        "drop_message",
        "lock_velocity",
        # Retained only so immutable completed campaign manifests from the
        # 2026-07 pilot remain parseable. DecisionPolicy has no executable
        # adapter for this legacy label; new catalogs use temporary_block.
        "rate_limit",
        "temporary_block",
        # 第二層可撤銷守衛：阻斷單一 DDS participant，不碰網路層。
        # 與 deny_participant 的差別是它**在 runtime 生效且可撤銷**，
        # 而 deny_participant 走 SROS2 的靜態 ACL，只能在啟動前決定。
        "revocable_participant_block",
        "quarantine",
        "alert",
    }
)
SCENARIO_KEYS = frozenset(
    {
        "id",
        "attack_class",
        "runner",
        "description",
        "default_security_mode",
        "duration_sec",
        "warmup_sec",
        "cooldown_sec",
        "intensity_min",
        "intensity_max",
        "expected_action",
        "requires_gazebo",
    }
)


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    attack_class: str
    runner: str
    description: str
    default_security_mode: str
    duration_sec: float
    warmup_sec: float
    cooldown_sec: float
    intensity_min: float
    intensity_max: float
    expected_action: str
    requires_gazebo: bool


def _parse_scenario(raw: dict) -> Scenario:
    if not isinstance(raw, dict):
        raise SchemaError("each scenario must be an object")
    unknown = set(raw) - SCENARIO_KEYS
    missing = SCENARIO_KEYS - set(raw)
    if unknown or missing:
        raise SchemaError(
            f"scenario keys invalid; missing={sorted(missing)}, "
            f"unknown={sorted(unknown)}"
        )
    scenario_id = require_identifier(raw["id"], "scenario.id")
    attack_class = require_identifier(
        raw["attack_class"], "scenario.attack_class"
    )
    runner = require_identifier(raw["runner"], "scenario.runner")
    if runner not in ALLOWED_RUNNERS:
        raise SchemaError(f"runner is not allowlisted: {runner}")
    description = str(raw["description"]).strip()
    if not 1 <= len(description) <= 300:
        raise SchemaError("scenario.description must be 1..300 characters")
    security_mode = raw["default_security_mode"]
    if security_mode not in {"permissive", "enforce"}:
        raise SchemaError("invalid default_security_mode")
    duration = require_finite_number(
        raw["duration_sec"], "duration_sec", minimum=1, maximum=300
    )
    warmup = require_finite_number(
        raw["warmup_sec"], "warmup_sec", minimum=0, maximum=120
    )
    cooldown = require_finite_number(
        raw["cooldown_sec"], "cooldown_sec", minimum=0, maximum=120
    )
    intensity_min = require_finite_number(
        raw["intensity_min"], "intensity_min", minimum=0, maximum=1
    )
    intensity_max = require_finite_number(
        raw["intensity_max"], "intensity_max", minimum=0, maximum=1
    )
    if intensity_min > intensity_max:
        raise SchemaError("intensity_min may not exceed intensity_max")
    action = require_identifier(raw["expected_action"], "expected_action")
    if action not in ALLOWED_ACTIONS:
        raise SchemaError(f"invalid expected_action: {action}")
    if not isinstance(raw["requires_gazebo"], bool):
        raise SchemaError("requires_gazebo must be bool")
    if runner == "normal" and attack_class != "normal":
        raise SchemaError("normal runner must have attack_class=normal")
    if runner != "normal" and attack_class == "normal":
        raise SchemaError("attack runner may not use normal label")
    return Scenario(
        scenario_id=scenario_id,
        attack_class=attack_class,
        runner=runner,
        description=description,
        default_security_mode=security_mode,
        duration_sec=duration,
        warmup_sec=warmup,
        cooldown_sec=cooldown,
        intensity_min=intensity_min,
        intensity_max=intensity_max,
        expected_action=action,
        requires_gazebo=raw["requires_gazebo"],
    )


def load_catalog(path: str | Path | None = None) -> dict[str, Scenario]:
    catalog_path = (
        Path(path)
        if path is not None
        else Path(__file__).with_name("scenarios.json")
    )
    raw = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "scenarios",
    }:
        raise SchemaError("catalog must contain schema_version and scenarios")
    if raw["schema_version"] != CATALOG_SCHEMA_VERSION:
        raise SchemaError("unsupported catalog schema_version")
    if not isinstance(raw["scenarios"], list) or not raw["scenarios"]:
        raise SchemaError("catalog scenarios must be a non-empty list")
    scenarios = [_parse_scenario(item) for item in raw["scenarios"]]
    result = {scenario.scenario_id: scenario for scenario in scenarios}
    if len(result) != len(scenarios):
        raise SchemaError("duplicate scenario id")
    return result
