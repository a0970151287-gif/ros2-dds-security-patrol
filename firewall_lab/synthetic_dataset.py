#!/usr/bin/env python3
"""Generate a deterministic, session-grouped synthetic pretraining dataset.

This dataset is deliberately feature-level and is never evaluation eligible.
It is useful for pipeline development and model warm starts while the slower
Gazebo/SROS2/PCAP campaign is collected.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import random
import statistics
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .campaign import DEFAULT_PLAN, load_campaign_plan
from .catalog import ALLOWED_ACTIONS
from .features import NETWORK_COLUMNS, TELEMETRY_FEATURES
from .orchestrator import POLICY_PATH
from .schema import (
    SchemaError,
    atomic_write_json,
    require_identifier,
    sha256_file,
    utc_now,
)
from .train import FEATURES


DATASET_SCHEMA_VERSION = "sros2-firewall-synthetic-features/v1"
GENERATOR_VERSION = "1.0.0"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "pretrain_dataset"
DEFAULT_WINDOWS = 36
DEFAULT_WINDOW_SEC = 8.0
DEFAULT_HOLDOUT_CLASSES = frozenset(
    {
        "sensor_spoof",
        "replay_dos",
        "discovery_recon",
        "confused_deputy",
    }
)
DEFAULT_EXTRA_SESSIONS_PER_SCENARIO = 100
SYNTHETIC_SCENARIO_SCHEMA_VERSION = (
    "sros2-firewall-synthetic-scenarios/v1"
)
SYNTHETIC_SCENARIO_PATH = Path(__file__).with_name(
    "synthetic_scenarios.json"
)
SYNTHETIC_EXTRA_COLUMNS = [
    "campaign_entry_id",
    "split",
    "novelty_role",
    "defense_outcome",
    "attack_active",
    "intensity",
    "seed",
    "generator_version",
    "scenario_origin",
]
SYNTHETIC_COLUMNS = NETWORK_COLUMNS + SYNTHETIC_EXTRA_COLUMNS
FUSION_FEATURES = FEATURES + TELEMETRY_FEATURES
FUSION_COLUMNS = SYNTHETIC_COLUMNS + TELEMETRY_FEATURES
SESSION_COLUMNS = [
    "session_id",
    "group_id",
    "campaign_entry_id",
    "scenario_id",
    "attack_class",
    "security_mode",
    "ros_domain_id",
    "source",
    "seed",
    "intensity",
    "split",
    "novelty_role",
    "windows",
    "attack_windows",
    "origin",
    "training_eligible",
    "evaluation_eligible",
    "expected_action",
    "scenario_origin",
]


# Targets intentionally overlap.  A model should need several signals rather
# than a single perfectly separated feature.
ATTACK_PROFILES: dict[str, dict[str, float]] = {
    "identity_abuse": {
        "rate_mult": 3.2,
        "spdp": 0.58,
        "meta": 0.26,
        "userdata": 0.06,
        "mcast": 0.72,
        "ports": 5.0,
        "hosts": 11.0,
        "cv": 1.45,
        "dominant_port": 0.58,
        "dominant_host": 0.34,
        "repeat": 0.62,
        "enforce_factor": 0.90,
    },
    "command_injection": {
        "rate_mult": 4.5,
        "spdp": 0.03,
        "meta": 0.07,
        "userdata": 0.84,
        "mcast": 0.08,
        "ports": 3.0,
        "hosts": 2.0,
        "cv": 0.34,
        "dominant_port": 0.82,
        "dominant_host": 0.88,
        "repeat": 0.89,
        "enforce_factor": 0.38,
    },
    "sensor_spoof": {
        "rate_mult": 2.7,
        "spdp": 0.04,
        "meta": 0.08,
        "userdata": 0.82,
        "mcast": 0.11,
        "ports": 3.0,
        "hosts": 3.0,
        "cv": 0.58,
        "dominant_port": 0.74,
        "dominant_host": 0.78,
        "repeat": 0.82,
        "enforce_factor": 0.42,
    },
    "parameter_tamper": {
        "rate_mult": 2.3,
        "spdp": 0.07,
        "meta": 0.49,
        "userdata": 0.37,
        "mcast": 0.12,
        "ports": 7.0,
        "hosts": 4.0,
        "cv": 1.08,
        "dominant_port": 0.48,
        "dominant_host": 0.64,
        "repeat": 0.58,
        "enforce_factor": 0.48,
    },
    "message_dos": {
        "rate_mult": 18.0,
        "spdp": 0.01,
        "meta": 0.03,
        "userdata": 0.93,
        "mcast": 0.03,
        "ports": 2.0,
        "hosts": 2.0,
        "cv": 2.35,
        "dominant_port": 0.95,
        "dominant_host": 0.94,
        "repeat": 0.97,
        "enforce_factor": 0.24,
    },
    "service_dos": {
        "rate_mult": 11.0,
        "spdp": 0.02,
        "meta": 0.43,
        "userdata": 0.50,
        "mcast": 0.05,
        "ports": 4.0,
        "hosts": 2.0,
        "cv": 1.85,
        "dominant_port": 0.79,
        "dominant_host": 0.90,
        "repeat": 0.91,
        "enforce_factor": 0.30,
    },
    "replay": {
        "rate_mult": 2.9,
        "spdp": 0.02,
        "meta": 0.08,
        "userdata": 0.86,
        "mcast": 0.06,
        "ports": 2.0,
        "hosts": 2.0,
        "cv": 0.10,
        "dominant_port": 0.91,
        "dominant_host": 0.92,
        "repeat": 0.97,
        "enforce_factor": 0.58,
    },
    "replay_dos": {
        "rate_mult": 9.5,
        "spdp": 0.01,
        "meta": 0.05,
        "userdata": 0.91,
        "mcast": 0.04,
        "ports": 2.0,
        "hosts": 2.0,
        "cv": 0.16,
        "dominant_port": 0.94,
        "dominant_host": 0.95,
        "repeat": 0.985,
        "enforce_factor": 0.35,
    },
    "discovery_recon": {
        "rate_mult": 2.4,
        "spdp": 0.47,
        "meta": 0.29,
        "userdata": 0.08,
        "mcast": 0.68,
        "ports": 8.0,
        "hosts": 14.0,
        "cv": 1.30,
        "dominant_port": 0.51,
        "dominant_host": 0.28,
        "repeat": 0.52,
        "enforce_factor": 0.84,
    },
    "spdp_flood": {
        "rate_mult": 16.0,
        "spdp": 0.84,
        "meta": 0.10,
        "userdata": 0.01,
        "mcast": 0.91,
        "ports": 2.0,
        "hosts": 20.0,
        "cv": 1.95,
        "dominant_port": 0.96,
        "dominant_host": 0.22,
        "repeat": 0.91,
        "enforce_factor": 0.72,
    },
    "node_name_evasion": {
        "rate_mult": 1.25,
        "spdp": 0.09,
        "meta": 0.17,
        "userdata": 0.66,
        "mcast": 0.12,
        "ports": 8.0,
        "hosts": 6.0,
        "cv": 0.94,
        "dominant_port": 0.34,
        "dominant_host": 0.39,
        "repeat": 0.52,
        "enforce_factor": 0.45,
    },
    "baseline_poisoning": {
        "rate_mult": 1.18,
        "spdp": 0.12,
        "meta": 0.18,
        "userdata": 0.63,
        "mcast": 0.16,
        "ports": 8.0,
        "hosts": 7.0,
        "cv": 0.88,
        "dominant_port": 0.33,
        "dominant_host": 0.36,
        "repeat": 0.49,
        "enforce_factor": 0.42,
    },
    "mission_spoof": {
        "rate_mult": 1.75,
        "spdp": 0.04,
        "meta": 0.09,
        "userdata": 0.81,
        "mcast": 0.07,
        "ports": 3.0,
        "hosts": 3.0,
        "cv": 0.52,
        "dominant_port": 0.72,
        "dominant_host": 0.74,
        "repeat": 0.80,
        "enforce_factor": 0.50,
    },
    "health_spoof": {
        "rate_mult": 1.60,
        "spdp": 0.04,
        "meta": 0.09,
        "userdata": 0.80,
        "mcast": 0.07,
        "ports": 3.0,
        "hosts": 3.0,
        "cv": 0.46,
        "dominant_port": 0.75,
        "dominant_host": 0.76,
        "repeat": 0.83,
        "enforce_factor": 0.50,
    },
    "cmd_vel_race": {
        "rate_mult": 6.8,
        "spdp": 0.02,
        "meta": 0.04,
        "userdata": 0.91,
        "mcast": 0.04,
        "ports": 2.0,
        "hosts": 2.0,
        "cv": 1.20,
        "dominant_port": 0.94,
        "dominant_host": 0.94,
        "repeat": 0.96,
        "enforce_factor": 0.30,
    },
    "scan_drift": {
        "rate_mult": 2.2,
        "spdp": 0.03,
        "meta": 0.07,
        "userdata": 0.86,
        "mcast": 0.06,
        "ports": 3.0,
        "hosts": 2.0,
        "cv": 0.43,
        "dominant_port": 0.85,
        "dominant_host": 0.88,
        "repeat": 0.87,
        "enforce_factor": 0.40,
    },
    "odom_spoof": {
        "rate_mult": 2.0,
        "spdp": 0.03,
        "meta": 0.08,
        "userdata": 0.84,
        "mcast": 0.06,
        "ports": 3.0,
        "hosts": 2.0,
        "cv": 0.56,
        "dominant_port": 0.82,
        "dominant_host": 0.86,
        "repeat": 0.84,
        "enforce_factor": 0.40,
    },
    "node_churn": {
        "rate_mult": 8.2,
        "spdp": 0.52,
        "meta": 0.34,
        "userdata": 0.06,
        "mcast": 0.66,
        "ports": 10.0,
        "hosts": 24.0,
        "cv": 2.10,
        "dominant_port": 0.52,
        "dominant_host": 0.18,
        "repeat": 0.55,
        "enforce_factor": 0.76,
    },
    "verify_flood": {
        "rate_mult": 15.0,
        "spdp": 0.01,
        "meta": 0.05,
        "userdata": 0.92,
        "mcast": 0.03,
        "ports": 2.0,
        "hosts": 2.0,
        "cv": 1.72,
        "dominant_port": 0.96,
        "dominant_host": 0.96,
        "repeat": 0.98,
        "enforce_factor": 0.36,
    },
    "cross_channel_relay": {
        "rate_mult": 1.35,
        "spdp": 0.05,
        "meta": 0.12,
        "userdata": 0.76,
        "mcast": 0.08,
        "ports": 4.0,
        "hosts": 3.0,
        "cv": 0.66,
        "dominant_port": 0.67,
        "dominant_host": 0.70,
        "repeat": 0.76,
        "enforce_factor": 0.62,
    },
    "hmac_forgery": {
        "rate_mult": 2.1,
        "spdp": 0.04,
        "meta": 0.10,
        "userdata": 0.80,
        "mcast": 0.07,
        "ports": 3.0,
        "hosts": 3.0,
        "cv": 0.82,
        "dominant_port": 0.70,
        "dominant_host": 0.72,
        "repeat": 0.78,
        "enforce_factor": 0.55,
    },
    "confused_deputy": {
        "rate_mult": 1.55,
        "spdp": 0.04,
        "meta": 0.10,
        "userdata": 0.79,
        "mcast": 0.07,
        "ports": 4.0,
        "hosts": 3.0,
        "cv": 0.72,
        "dominant_port": 0.68,
        "dominant_host": 0.73,
        "repeat": 0.74,
        "enforce_factor": 0.64,
    },
}


TELEMETRY_PROFILES: dict[str, dict[str, float]] = {
    "identity_abuse": {
        "sros_auth_fail_rate": 7.0,
        "sros_permission_deny_rate": 4.0,
        "unknown_node_rate": 1.8,
    },
    "command_injection": {
        "sros_permission_deny_rate": 5.0,
        "publisher_violation_ratio": 0.72,
        "control_conflict_ratio": 0.66,
    },
    "sensor_spoof": {
        "hmac_failure_rate": 4.0,
        "publisher_violation_ratio": 0.70,
        "scan_static_ratio": 0.52,
    },
    "parameter_tamper": {
        "sros_permission_deny_rate": 4.5,
        "parameter_call_rate": 8.0,
    },
    "message_dos": {
        "oversized_message_ratio": 0.84,
        "qos_drop_ratio": 0.66,
        "log_reject_rate": 7.0,
    },
    "service_dos": {
        "parameter_call_rate": 25.0,
        "qos_drop_ratio": 0.58,
        "log_reject_rate": 5.0,
    },
    "replay": {
        "nonce_reuse_ratio": 0.79,
        "hmac_failure_rate": 2.5,
    },
    "replay_dos": {
        "nonce_reuse_ratio": 0.92,
        "qos_drop_ratio": 0.63,
        "log_reject_rate": 11.0,
    },
    "discovery_recon": {
        "sros_auth_fail_rate": 3.0,
        "participant_churn_rate": 1.8,
        "unknown_node_rate": 1.4,
    },
    "spdp_flood": {
        "sros_auth_fail_rate": 16.0,
        "participant_churn_rate": 18.0,
        "qos_drop_ratio": 0.72,
    },
    "node_name_evasion": {
        "unknown_node_rate": 2.0,
        "publisher_violation_ratio": 0.31,
    },
    "baseline_poisoning": {
        "unknown_node_rate": 1.4,
        "participant_churn_rate": 0.9,
    },
    "mission_spoof": {
        "hmac_failure_rate": 3.5,
        "publisher_violation_ratio": 0.78,
    },
    "health_spoof": {
        "hmac_failure_rate": 3.2,
        "publisher_violation_ratio": 0.75,
    },
    "cmd_vel_race": {
        "publisher_violation_ratio": 0.88,
        "control_conflict_ratio": 0.93,
        "qos_drop_ratio": 0.34,
    },
    "scan_drift": {
        "publisher_violation_ratio": 0.72,
        "scan_static_ratio": 0.88,
        "odom_cmd_mismatch_ratio": 0.68,
    },
    "odom_spoof": {
        "publisher_violation_ratio": 0.76,
        "odom_cmd_mismatch_ratio": 0.91,
    },
    "node_churn": {
        "participant_churn_rate": 22.0,
        "unknown_node_rate": 13.0,
        "sros_auth_fail_rate": 8.0,
    },
    "verify_flood": {
        "hmac_failure_rate": 32.0,
        "qos_drop_ratio": 0.79,
        "log_reject_rate": 28.0,
    },
    "cross_channel_relay": {
        "channel_mismatch_ratio": 0.86,
        "hmac_failure_rate": 1.8,
    },
    "hmac_forgery": {
        "hmac_failure_rate": 8.0,
        "timestamp_violation_ratio": 0.22,
    },
    "confused_deputy": {
        "alert_reflection_ratio": 0.82,
        "publisher_violation_ratio": 0.44,
        "log_reject_rate": 2.5,
    },
}


def load_synthetic_scenarios(
    path: str | Path = SYNTHETIC_SCENARIO_PATH,
) -> dict[str, dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "scenarios"}
        or value["schema_version"] != SYNTHETIC_SCENARIO_SCHEMA_VERSION
        or not isinstance(value["scenarios"], list)
        or not value["scenarios"]
    ):
        raise SchemaError("invalid synthetic scenario catalog")
    expected_keys = {
        "id",
        "attack_class",
        "description",
        "reference",
        "expected_action",
        "modalities",
    }
    allowed_modalities = {
        "network",
        "sros2",
        "application_hmac",
        "ros_graph",
        "ros_behavior",
    }
    scenarios: dict[str, dict[str, Any]] = {}
    for raw in value["scenarios"]:
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise SchemaError("synthetic scenario has unexpected keys")
        scenario_id = require_identifier(raw["id"], "synthetic scenario id")
        attack_class = require_identifier(
            raw["attack_class"], "synthetic attack_class"
        )
        if scenario_id in scenarios:
            raise SchemaError("duplicate synthetic scenario id")
        if (
            not isinstance(raw["description"], str)
            or not 1 <= len(raw["description"]) <= 300
            or not isinstance(raw["reference"], str)
            or not 1 <= len(raw["reference"]) <= 200
            or raw["expected_action"] not in ALLOWED_ACTIONS
            or not isinstance(raw["modalities"], list)
            or not raw["modalities"]
            or not set(raw["modalities"]) <= allowed_modalities
        ):
            raise SchemaError(f"invalid synthetic scenario: {scenario_id}")
        scenarios[scenario_id] = {
            **raw,
            "attack_class": attack_class,
        }
    attack_classes = {
        scenario["attack_class"] for scenario in scenarios.values()
    }
    base_classes = {
        "identity_abuse",
        "command_injection",
        "sensor_spoof",
        "parameter_tamper",
        "message_dos",
        "service_dos",
        "replay",
        "replay_dos",
    }
    expected_extra = set(ATTACK_PROFILES) - base_classes
    if attack_classes != expected_extra:
        raise SchemaError(
            "synthetic scenario/profile inventory mismatch"
        )
    if set(TELEMETRY_PROFILES) != set(ATTACK_PROFILES):
        raise SchemaError(
            "network and telemetry attack profiles must have identical classes"
        )
    return scenarios


def _synthetic_extra_entries(
    plan: dict[str, Any],
    *,
    sessions_per_scenario: int,
) -> list[dict[str, Any]]:
    if (
        isinstance(sessions_per_scenario, bool)
        or not isinstance(sessions_per_scenario, int)
    ):
        raise ValueError(
            "extra_sessions_per_scenario must be zero or an even integer "
            "in 2..2000"
        )
    if sessions_per_scenario == 0:
        return []
    if (
        not 2 <= sessions_per_scenario <= 2_000
        or sessions_per_scenario % 2
    ):
        raise ValueError(
            "extra_sessions_per_scenario must be zero or an even integer "
            "in 2..2000"
        )
    scenarios = load_synthetic_scenarios()
    used_seeds = {int(entry["seed"]) for entry in plan["entries"]}
    entries: list[dict[str, Any]] = []
    half = sessions_per_scenario // 2
    for scenario_id in sorted(scenarios):
        scenario = scenarios[scenario_id]
        for index in range(sessions_per_scenario):
            entry_id = f"synthetic_{scenario_id}_{index + 1:04d}"
            digest = hashlib.sha256(
                (
                    f"{plan['campaign_id']}:{entry_id}:"
                    f"{plan['seed']}"
                ).encode("utf-8")
            ).digest()
            entry_seed = int.from_bytes(digest[:8], "big")
            entry_seed = entry_seed % 2_147_483_646 + 1
            while entry_seed in used_seeds:
                entry_seed = entry_seed % 2_147_483_646 + 1
            used_seeds.add(entry_seed)
            entries.append(
                {
                    "entry_id": entry_id,
                    "scenario_id": scenario_id,
                    "attack_class": scenario["attack_class"],
                    "security_mode": (
                        "permissive" if index < half else "enforce"
                    ),
                    "domain_id": 30,
                    "seed": entry_seed,
                    "expected_action": scenario["expected_action"],
                    "status": "pending",
                    "session_id": None,
                    "error": None,
                    "scenario_origin": "synthetic_only",
                }
            )
    return entries


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _blend(start: float, target: float, weight: float) -> float:
    return start + (target - start) * _clamp(weight, 0.0, 1.0)


def _jitter(
    rng: random.Random,
    value: float,
    relative_sigma: float,
    minimum: float,
    maximum: float,
) -> float:
    sigma = max(abs(value) * relative_sigma, relative_sigma / 100.0)
    return _clamp(rng.gauss(value, sigma), minimum, maximum)


def _stable_order_key(seed: int, value: str) -> str:
    return hashlib.sha256(f"{seed}:{value}".encode("utf-8")).hexdigest()


def _assign_splits(
    entries: list[dict[str, Any]],
    *,
    split_seed: int,
) -> dict[str, str]:
    strata: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        strata[(entry["scenario_id"], entry["security_mode"])].append(entry)
    result: dict[str, str] = {}
    for stratum in strata.values():
        ordered = sorted(
            stratum,
            key=lambda item: _stable_order_key(
                split_seed, item["entry_id"]
            ),
        )
        count = len(ordered)
        if count < 3:
            train_count, validation_count = count, 0
        else:
            train_count = max(1, int(count * 0.70))
            validation_count = max(1, int(count * 0.15))
            if train_count + validation_count >= count:
                train_count = count - 2
                validation_count = 1
        for index, entry in enumerate(ordered):
            if index < train_count:
                split = "train"
            elif index < train_count + validation_count:
                split = "validation"
            else:
                split = "test"
            result[entry["entry_id"]] = split
    return result


def _source_address(rng: random.Random) -> str:
    # RFC 5737 documentation networks; never a real experiment target.
    prefix = rng.choice(("192.0.2", "198.51.100", "203.0.113"))
    return f"{prefix}.{rng.randint(1, 254)}"


def _normal_features(
    rng: random.Random,
    *,
    base_rate: float,
    base_ports: int,
    base_hosts: int,
    security_mode: str,
) -> dict[str, float]:
    overhead = 1.03 if security_mode == "enforce" else 1.0
    rate = _jitter(rng, base_rate * overhead, 0.18, 0.5, 5000.0)
    ports = int(
        round(_jitter(rng, float(base_ports), 0.20, 2.0, 32.0))
    )
    hosts = int(
        round(_jitter(rng, float(base_hosts), 0.22, 1.0, 32.0))
    )
    spdp = _jitter(rng, 0.065, 0.26, 0.005, 0.20)
    meta = _jitter(rng, 0.15, 0.22, 0.03, 0.34)
    userdata = _jitter(rng, 0.70, 0.14, 0.40, 0.90)
    total = spdp + meta + userdata
    if total > 0.97:
        scale = 0.97 / total
        spdp, meta, userdata = (
            spdp * scale,
            meta * scale,
            userdata * scale,
        )
    mcast = _jitter(rng, 0.09, 0.35, 0.01, 0.32)
    cv = _jitter(rng, 0.92, 0.32, 0.10, 2.4)
    burstiness = _clamp((cv - 1.0) / (cv + 1.0), -1.0, 1.0)
    entropy_max = max(math.log2(max(ports, 2)), 0.1)
    entropy = _jitter(
        rng, entropy_max * 0.78, 0.16, 0.05, entropy_max
    )
    dominant_port = _jitter(
        rng,
        max(0.30, 1.0 / ports),
        0.28,
        1.0 / ports,
        0.78,
    )
    dominant_host = _jitter(
        rng,
        max(0.36, 1.0 / hosts),
        0.27,
        1.0 / hosts,
        0.82,
    )
    repeat = _jitter(rng, 0.48, 0.30, 0.05, 0.86)

    # Normal systems sometimes burst during discovery/restart.  Keeping these
    # hard negatives reduces the chance of learning "high rate == attack".
    if rng.random() < 0.035:
        rate *= rng.uniform(1.8, 4.0)
        spdp = _clamp(spdp * rng.uniform(1.8, 3.2), 0.0, 0.45)
        cv = _clamp(cv * rng.uniform(1.2, 2.0), 0.0, 3.5)
        burstiness = _clamp((cv - 1.0) / (cv + 1.0), -1.0, 1.0)
    total = spdp + meta + userdata
    if total > 0.985:
        scale = 0.985 / total
        spdp, meta, userdata = (
            spdp * scale,
            meta * scale,
            userdata * scale,
        )

    return {
        "conn_rate": rate,
        "uniq_dst_ports": float(ports),
        "uniq_dst_hosts": float(hosts),
        "spdp_ratio": spdp,
        "meta_ratio": meta,
        "userdata_ratio": userdata,
        "mcast_ratio": mcast,
        "dst_port_entropy": entropy,
        "interarrival_cv": cv,
        "burstiness": burstiness,
        "dominant_port_ratio": dominant_port,
        "dominant_host_ratio": dominant_host,
        "tuple_repeat_ratio": repeat,
    }


def _normal_telemetry(rng: random.Random) -> dict[str, float]:
    values = {
        "sros_auth_fail_rate": _jitter(rng, 0.008, 0.70, 0.0, 0.08),
        "sros_permission_deny_rate": _jitter(
            rng, 0.006, 0.70, 0.0, 0.06
        ),
        "participant_churn_rate": _jitter(
            rng, 0.04, 0.55, 0.0, 0.30
        ),
        "unknown_node_rate": _jitter(rng, 0.004, 0.80, 0.0, 0.05),
        "hmac_failure_rate": _jitter(rng, 0.004, 0.75, 0.0, 0.05),
        "nonce_reuse_ratio": _jitter(rng, 0.001, 0.75, 0.0, 0.02),
        "channel_mismatch_ratio": _jitter(
            rng, 0.001, 0.75, 0.0, 0.02
        ),
        "timestamp_violation_ratio": _jitter(
            rng, 0.002, 0.70, 0.0, 0.025
        ),
        "publisher_violation_ratio": _jitter(
            rng, 0.003, 0.70, 0.0, 0.03
        ),
        "parameter_call_rate": _jitter(rng, 0.08, 0.60, 0.0, 0.60),
        "oversized_message_ratio": _jitter(
            rng, 0.001, 0.75, 0.0, 0.02
        ),
        "qos_drop_ratio": _jitter(rng, 0.008, 0.65, 0.0, 0.08),
        "heartbeat_gap_sec": _jitter(rng, 0.25, 0.55, 0.0, 1.5),
        "control_conflict_ratio": _jitter(
            rng, 0.004, 0.70, 0.0, 0.04
        ),
        "scan_static_ratio": _jitter(rng, 0.12, 0.45, 0.01, 0.42),
        "odom_cmd_mismatch_ratio": _jitter(
            rng, 0.015, 0.65, 0.0, 0.12
        ),
        "alert_reflection_ratio": _jitter(
            rng, 0.001, 0.75, 0.0, 0.02
        ),
        "log_reject_rate": _jitter(rng, 0.02, 0.65, 0.0, 0.18),
    }
    # Hard negatives: benign restarts, clock jitter, packet loss, and a stopped
    # robot should occasionally resemble one detector in isolation.
    choice = rng.random()
    if choice < 0.02:
        values["participant_churn_rate"] = rng.uniform(0.5, 2.5)
        values["unknown_node_rate"] = rng.uniform(0.1, 0.7)
    elif choice < 0.04:
        values["heartbeat_gap_sec"] = rng.uniform(2.0, 7.0)
        values["qos_drop_ratio"] = rng.uniform(0.05, 0.22)
    elif choice < 0.06:
        values["scan_static_ratio"] = rng.uniform(0.55, 0.92)
        values["odom_cmd_mismatch_ratio"] = rng.uniform(0.02, 0.18)
    elif choice < 0.08:
        values["hmac_failure_rate"] = rng.uniform(0.1, 0.8)
        values["log_reject_rate"] = rng.uniform(0.1, 0.7)
    return values


def _attack_telemetry(
    normal: dict[str, float],
    *,
    attack_class: str,
    intensity: float,
    security_mode: str,
    rng: random.Random,
) -> dict[str, float]:
    targets = TELEMETRY_PROFILES[attack_class]
    base_weight = _clamp(
        intensity * rng.uniform(0.72, 1.08),
        0.08,
        1.0,
    )
    effect_weight = base_weight
    if security_mode == "enforce":
        effect_weight *= ATTACK_PROFILES[attack_class]["enforce_factor"]
    detection_signals = {
        "sros_auth_fail_rate",
        "sros_permission_deny_rate",
        "participant_churn_rate",
        "unknown_node_rate",
        "hmac_failure_rate",
        "nonce_reuse_ratio",
        "channel_mismatch_ratio",
        "timestamp_violation_ratio",
        "publisher_violation_ratio",
        "oversized_message_ratio",
        "log_reject_rate",
    }
    ratio_features = {
        "nonce_reuse_ratio",
        "channel_mismatch_ratio",
        "timestamp_violation_ratio",
        "publisher_violation_ratio",
        "oversized_message_ratio",
        "qos_drop_ratio",
        "control_conflict_ratio",
        "scan_static_ratio",
        "odom_cmd_mismatch_ratio",
        "alert_reflection_ratio",
    }
    result = {}
    for name in TELEMETRY_FEATURES:
        target = targets.get(name, normal[name])
        weight = base_weight if name in detection_signals else effect_weight
        maximum = (
            1.0
            if name in ratio_features
            else 120.0
            if name == "heartbeat_gap_sec"
            else 100_000.0
        )
        result[name] = _jitter(
            rng,
            _blend(normal[name], target, weight),
            0.12,
            0.0,
            maximum,
        )
    return result


def _round_telemetry(
    values: dict[str, float],
) -> dict[str, float]:
    return {
        name: round(float(values[name]), 6)
        for name in TELEMETRY_FEATURES
    }


def _attack_features(
    normal: dict[str, float],
    *,
    attack_class: str,
    intensity: float,
    security_mode: str,
    rng: random.Random,
) -> dict[str, float]:
    profile = ATTACK_PROFILES[attack_class]
    weight = _clamp(
        intensity * rng.uniform(0.72, 1.08),
        0.08,
        1.0,
    )
    if security_mode == "enforce":
        effect_weight = weight * profile["enforce_factor"]
        # Authentication/discovery abuse is still visible before rejection.
        signature_weight = (
            weight if attack_class == "identity_abuse" else effect_weight
        )
    else:
        effect_weight = weight
        signature_weight = weight

    rate_multiplier = _blend(
        1.0,
        profile["rate_mult"],
        effect_weight,
    )
    rate = normal["conn_rate"] * rate_multiplier
    values = {
        "conn_rate": _jitter(rng, rate, 0.14, 0.5, 50_000.0),
        "uniq_dst_ports": float(
            max(
                1,
                round(
                    _jitter(
                        rng,
                        _blend(
                            normal["uniq_dst_ports"],
                            profile["ports"],
                            signature_weight,
                        ),
                        0.16,
                        1.0,
                        64.0,
                    )
                ),
            )
        ),
        "uniq_dst_hosts": float(
            max(
                1,
                round(
                    _jitter(
                        rng,
                        _blend(
                            normal["uniq_dst_hosts"],
                            profile["hosts"],
                            signature_weight,
                        ),
                        0.18,
                        1.0,
                        64.0,
                    )
                ),
            )
        ),
    }
    for name, target in (
        ("spdp_ratio", profile["spdp"]),
        ("meta_ratio", profile["meta"]),
        ("userdata_ratio", profile["userdata"]),
        ("mcast_ratio", profile["mcast"]),
        ("interarrival_cv", profile["cv"]),
        ("dominant_port_ratio", profile["dominant_port"]),
        ("dominant_host_ratio", profile["dominant_host"]),
        ("tuple_repeat_ratio", profile["repeat"]),
    ):
        values[name] = _jitter(
            rng,
            _blend(normal[name], target, signature_weight),
            0.10,
            0.0,
            4.0 if name == "interarrival_cv" else 1.0,
        )

    ratio_total = (
        values["spdp_ratio"]
        + values["meta_ratio"]
        + values["userdata_ratio"]
    )
    if ratio_total > 0.985:
        scale = 0.985 / ratio_total
        for name in ("spdp_ratio", "meta_ratio", "userdata_ratio"):
            values[name] *= scale
    cv = values["interarrival_cv"]
    base_burstiness = (cv - 1.0) / (cv + 1.0) if cv + 1.0 else 0.0
    values["burstiness"] = _jitter(
        rng, base_burstiness, 0.12, -1.0, 1.0
    )
    ports = max(int(values["uniq_dst_ports"]), 1)
    entropy_max = max(math.log2(max(ports, 2)), 0.1)
    concentration = values["dominant_port_ratio"]
    target_entropy = entropy_max * _clamp(1.15 - concentration, 0.05, 1.0)
    values["dst_port_entropy"] = _jitter(
        rng, target_entropy, 0.16, 0.0, entropy_max
    )
    values["dominant_port_ratio"] = _clamp(
        values["dominant_port_ratio"],
        1.0 / ports,
        1.0,
    )
    hosts = max(int(values["uniq_dst_hosts"]), 1)
    values["dominant_host_ratio"] = _clamp(
        values["dominant_host_ratio"],
        1.0 / hosts,
        1.0,
    )
    return values


def _round_features(
    values: dict[str, float],
    *,
    window_sec: float,
) -> dict[str, int | float]:
    count = max(1, int(round(values["conn_rate"] * window_sec)))
    result: dict[str, int | float] = {
        "conn_count": count,
        "conn_rate": round(count / window_sec, 6),
        "uniq_dst_ports": int(values["uniq_dst_ports"]),
        "uniq_dst_hosts": int(values["uniq_dst_hosts"]),
    }
    for name in FEATURES:
        if name in result:
            continue
        result[name] = round(float(values[name]), 6)
    return result


def _write_csv_atomic(
    path: Path,
    columns: list[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SchemaError(f"dataset output may not be a symlink: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            writer = csv.DictWriter(
                handle,
                fieldnames=columns,
                extrasaction="raise",
            )
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _write_text_atomic(path: Path, value: str) -> None:
    if path.is_symlink():
        raise SchemaError(f"dataset output may not be a symlink: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _quality_report(
    *,
    rows: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    expected_sessions: int,
    windows_per_session: int,
    expected_attack_classes: set[str],
) -> dict[str, Any]:
    groups: dict[str, set[str]] = defaultdict(set)
    class_modes: dict[str, set[str]] = defaultdict(set)
    campaign_modes: Counter[tuple[str, str]] = Counter()
    finite = True
    ratios_valid = True
    domains = set()
    split_rows: Counter[str] = Counter()
    label_rows: Counter[str] = Counter()
    mode_rows: Counter[str] = Counter()
    signatures: Counter[tuple[Any, ...]] = Counter()
    for row in rows:
        groups[row["group_id"]].add(row["split"])
        class_modes[row["label"]].add(row["security_mode"])
        domains.add(row["ros_domain_id"])
        split_rows[row["split"]] += 1
        label_rows[row["label"]] += 1
        mode_rows[row["security_mode"]] += 1
        signatures[
            tuple(row[feature] for feature in FUSION_FEATURES)
            + (row["label"], row["security_mode"])
        ] += 1
        for feature in FUSION_FEATURES:
            value = float(row[feature])
            finite = finite and math.isfinite(value)
        ratio_names = (
            "spdp_ratio",
            "meta_ratio",
            "userdata_ratio",
            "mcast_ratio",
            "dominant_port_ratio",
            "dominant_host_ratio",
            "tuple_repeat_ratio",
            "nonce_reuse_ratio",
            "channel_mismatch_ratio",
            "timestamp_violation_ratio",
            "publisher_violation_ratio",
            "oversized_message_ratio",
            "qos_drop_ratio",
            "control_conflict_ratio",
            "scan_static_ratio",
            "odom_cmd_mismatch_ratio",
            "alert_reflection_ratio",
        )
        ratios_valid = ratios_valid and all(
            0.0 <= float(row[name]) <= 1.0 for name in ratio_names
        )
        ratios_valid = ratios_valid and (
            float(row["spdp_ratio"])
            + float(row["meta_ratio"])
            + float(row["userdata_ratio"])
            <= 1.000001
        )
    for session in sessions:
        campaign_modes[
            (session["attack_class"], session["security_mode"])
        ] += 1
    balanced_modes = all(
        campaign_modes[(attack_class, "permissive")]
        == campaign_modes[(attack_class, "enforce")]
        for attack_class in {"normal", *expected_attack_classes}
    )
    feature_statistics = {}
    for feature in FUSION_FEATURES:
        values = [float(row[feature]) for row in rows]
        feature_statistics[feature] = {
            "min": min(values),
            "max": max(values),
            "mean": round(statistics.fmean(values), 6),
            "std": round(statistics.pstdev(values), 6),
        }
    exact_duplicate_rows = sum(
        count - 1 for count in signatures.values() if count > 1
    )
    expected_classes = {"normal", *expected_attack_classes}
    checks = {
        "session_count": len(sessions) == expected_sessions,
        "row_count": len(rows) == expected_sessions * windows_per_session,
        "unique_session_ids": (
            len({item["session_id"] for item in sessions})
            == expected_sessions
        ),
        "group_split_isolation": all(
            len(splits) == 1 for splits in groups.values()
        ),
        "all_features_finite": finite,
        "ratios_in_range": ratios_valid,
        "constant_domain_30": domains == {30},
        "both_security_modes_per_class": (
            set(class_modes) == expected_classes
            and all(
                modes == {"permissive", "enforce"}
                for modes in class_modes.values()
            )
        ),
        "balanced_security_sessions_per_scenario": balanced_modes,
        "train_validation_test_present": (
            set(split_rows) == {"train", "validation", "test"}
        ),
        "all_features_have_variance": all(
            summary["max"] > summary["min"]
            for summary in feature_statistics.values()
        ),
        "exact_duplicate_ratio_below_0_1pct": (
            exact_duplicate_rows / max(len(rows), 1) < 0.001
        ),
        "synthetic_never_evaluation_eligible": not any(
            bool(row["evaluation_eligible"]) for row in rows
        ),
        "all_rows_pretraining_eligible": all(
            bool(row["training_eligible"]) for row in rows
        ),
    }
    return {
        "schema_version": "sros2-firewall-synthetic-quality/v1",
        "passed": all(checks.values()),
        "checks": checks,
        "sessions": len(sessions),
        "rows": len(rows),
        "classes": sorted(class_modes),
        "domains": sorted(domains),
        "label_rows": dict(sorted(label_rows.items())),
        "split_rows": dict(sorted(split_rows.items())),
        "security_mode_rows": dict(sorted(mode_rows.items())),
        "exact_duplicate_rows": exact_duplicate_rows,
        "feature_statistics": feature_statistics,
    }


def verify_synthetic_dataset(dataset_dir: str | Path) -> dict[str, Any]:
    root = Path(dataset_dir).expanduser()
    if not root.is_dir() or root.is_symlink():
        raise FileNotFoundError(f"invalid synthetic dataset: {root}")
    checksums_path = root / "checksums.json"
    if checksums_path.is_symlink():
        raise SchemaError("checksums.json may not be a symlink")
    checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
    if (
        not isinstance(checksums, dict)
        or set(checksums) != {"schema_version", "files"}
        or checksums["schema_version"]
        != "sros2-firewall-dataset-checksums/v1"
        or not isinstance(checksums["files"], dict)
    ):
        raise SchemaError("invalid dataset checksum manifest")
    expected_files = {
        "network_features.csv",
        "fusion_features.csv",
        "session_index.csv",
        "class_distribution.csv",
        "dataset_card.json",
        "quality_report.json",
        "DATASET_CARD.md",
    }
    if set(checksums["files"]) != expected_files:
        raise SchemaError("dataset checksum file inventory mismatch")
    for name, record in checksums["files"].items():
        if Path(name).name != name or not isinstance(record, dict):
            raise SchemaError("unsafe dataset checksum entry")
        if set(record) != {"sha256", "bytes"}:
            raise SchemaError("invalid dataset checksum record")
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise SchemaError(f"dataset file missing or symlinked: {name}")
        if path.stat().st_size != record["bytes"]:
            raise SchemaError(f"dataset byte count mismatch: {name}")
        if sha256_file(path) != record["sha256"]:
            raise SchemaError(f"dataset SHA-256 mismatch: {name}")
    card = json.loads((root / "dataset_card.json").read_text(encoding="utf-8"))
    quality = json.loads(
        (root / "quality_report.json").read_text(encoding="utf-8")
    )
    if (
        card.get("schema_version") != DATASET_SCHEMA_VERSION
        or card.get("origin") != "synthetic_pretrain"
        or card.get("evaluation_eligible") is not False
        or card.get("deployment_evidence") is not False
    ):
        raise SchemaError("dataset card violates synthetic tier boundary")
    if quality.get("passed") is not True:
        raise SchemaError("synthetic dataset quality gate is not passing")
    network_rows = sum(
        1
        for _ in (root / "network_features.csv").open(
            "r", encoding="utf-8"
        )
    ) - 1
    fusion_rows = sum(
        1
        for _ in (root / "fusion_features.csv").open(
            "r", encoding="utf-8"
        )
    ) - 1
    session_rows = sum(
        1
        for _ in (root / "session_index.csv").open(
            "r", encoding="utf-8"
        )
    ) - 1
    if network_rows != card.get("rows"):
        raise SchemaError("network row count does not match dataset card")
    if fusion_rows != card.get("rows"):
        raise SchemaError("fusion row count does not match dataset card")
    if session_rows != card.get("sessions"):
        raise SchemaError("session count does not match dataset card")
    return {
        "dataset": str(root.resolve()),
        "sessions": session_rows,
        "rows": network_rows,
        "files": len(expected_files),
        "valid": True,
    }


def generate_synthetic_dataset(
    *,
    plan_path: str | Path,
    output_dir: str | Path,
    windows_per_session: int = DEFAULT_WINDOWS,
    window_sec: float = DEFAULT_WINDOW_SEC,
    split_seed: int = 20260727,
    extra_sessions_per_scenario: int = (
        DEFAULT_EXTRA_SESSIONS_PER_SCENARIO
    ),
    overwrite: bool = False,
) -> dict[str, Any]:
    if (
        isinstance(windows_per_session, bool)
        or not isinstance(windows_per_session, int)
        or not 12 <= windows_per_session <= 240
    ):
        raise ValueError("windows_per_session must be an integer in 12..240")
    if (
        isinstance(window_sec, bool)
        or not isinstance(window_sec, (int, float))
        or not math.isfinite(float(window_sec))
        or not 0.5 <= float(window_sec) <= 300.0
    ):
        raise ValueError("window_sec must be finite and in 0.5..300")
    if (
        isinstance(split_seed, bool)
        or not isinstance(split_seed, int)
        or not 0 <= split_seed <= 2_147_483_647
    ):
        raise ValueError("split_seed must be an integer in 0..2147483647")

    plan_file = Path(plan_path).expanduser()
    plan = load_campaign_plan(plan_file)
    base_entries = [
        {
            **entry,
            "scenario_origin": "live_runner_backed",
        }
        for entry in plan["entries"]
    ]
    extra_entries = _synthetic_extra_entries(
        plan,
        sessions_per_scenario=extra_sessions_per_scenario,
    )
    entries = base_entries + extra_entries
    output = Path(output_dir).expanduser()
    if output.exists() and output.is_symlink():
        raise SchemaError("synthetic dataset output may not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    targets = [
        output / "network_features.csv",
        output / "fusion_features.csv",
        output / "session_index.csv",
        output / "class_distribution.csv",
        output / "dataset_card.json",
        output / "quality_report.json",
        output / "DATASET_CARD.md",
        output / "checksums.json",
    ]
    if not overwrite and any(path.exists() for path in targets):
        raise FileExistsError(
            "synthetic dataset already exists; use --overwrite to regenerate"
        )

    splits = _assign_splits(entries, split_seed=split_seed)
    policy_hash = sha256_file(POLICY_PATH) if POLICY_PATH.is_file() else ""
    attack_start = max(3, windows_per_session // 6)
    attack_end = windows_per_session - attack_start
    rows: list[dict[str, Any]] = []
    fusion_rows: list[dict[str, Any]] = []
    sessions: list[dict[str, Any]] = []
    base_epoch = 1_767_225_600.0

    for session_index, entry in enumerate(entries):
        rng = random.Random(entry["seed"])
        digest = plan["campaign_id"].removeprefix("campaign_")
        session_id = f"synthetic_{digest}_{entry['entry_id']}"
        source = _source_address(rng)
        split = splits[entry["entry_id"]]
        intensity = round(rng.uniform(0.15, 0.98), 6)
        base_rate = rng.uniform(3.0, 18.0)
        base_ports = rng.randint(4, 13)
        base_hosts = rng.randint(3, 10)
        attack_class = entry["attack_class"]
        novelty_role = (
            "novelty_holdout_candidate"
            if attack_class in DEFAULT_HOLDOUT_CLASSES
            else "known_class"
        )
        attack_windows = 0
        for window in range(windows_per_session):
            normal = _normal_features(
                rng,
                base_rate=base_rate,
                base_ports=base_ports,
                base_hosts=base_hosts,
                security_mode=entry["security_mode"],
            )
            normal_telemetry = _normal_telemetry(rng)
            attack_active = (
                attack_class != "normal"
                and attack_start <= window < attack_end
            )
            if attack_active:
                attack_windows += 1
                values = _attack_features(
                    normal,
                    attack_class=attack_class,
                    intensity=intensity,
                    security_mode=entry["security_mode"],
                    rng=rng,
                )
                telemetry = _attack_telemetry(
                    normal_telemetry,
                    attack_class=attack_class,
                    intensity=intensity,
                    security_mode=entry["security_mode"],
                    rng=rng,
                )
                label = attack_class
                outcome = (
                    "blocked_attempt"
                    if entry["security_mode"] == "enforce"
                    else "impact_observed"
                )
            else:
                values = normal
                telemetry = normal_telemetry
                label = "normal"
                outcome = "normal"
            feature_values = _round_features(
                values,
                window_sec=float(window_sec),
            )
            row = {
                "session_id": session_id,
                "group_id": session_id,
                "capture_id": session_id,
                "scenario_id": entry["scenario_id"],
                "security_mode": entry["security_mode"],
                "ros_domain_id": 30,
                "origin": "synthetic_pretrain",
                "source": source,
                "window": window,
                "window_start_unix": round(
                    base_epoch
                    + session_index * (windows_per_session + 10) * window_sec
                    + window * window_sec,
                    6,
                ),
                **feature_values,
                "label": label,
                "binary": "normal" if label == "normal" else "attack",
                "label_scope": "synthetic_window",
                "training_eligible": True,
                "evaluation_eligible": False,
                "policy_sha256": policy_hash,
                "campaign_entry_id": entry["entry_id"],
                "split": split,
                "novelty_role": novelty_role,
                "defense_outcome": outcome,
                "attack_active": attack_active,
                "intensity": intensity,
                "seed": entry["seed"],
                "generator_version": GENERATOR_VERSION,
                "scenario_origin": entry["scenario_origin"],
            }
            rows.append(row)
            fusion_rows.append(
                {
                    **row,
                    **_round_telemetry(telemetry),
                }
            )
        sessions.append(
            {
                "session_id": session_id,
                "group_id": session_id,
                "campaign_entry_id": entry["entry_id"],
                "scenario_id": entry["scenario_id"],
                "attack_class": attack_class,
                "security_mode": entry["security_mode"],
                "ros_domain_id": 30,
                "source": source,
                "seed": entry["seed"],
                "intensity": intensity,
                "split": split,
                "novelty_role": novelty_role,
                "windows": windows_per_session,
                "attack_windows": attack_windows,
                "origin": "synthetic_pretrain",
                "training_eligible": True,
                "evaluation_eligible": False,
                "expected_action": entry["expected_action"],
                "scenario_origin": entry["scenario_origin"],
            }
        )

    quality = _quality_report(
        rows=fusion_rows,
        sessions=sessions,
        expected_sessions=len(entries),
        windows_per_session=windows_per_session,
        expected_attack_classes={
            item["attack_class"]
            for item in sessions
            if item["attack_class"] != "normal"
        },
    )
    if not quality["passed"]:
        failed = [
            name
            for name, passed in quality["checks"].items()
            if not passed
        ]
        raise RuntimeError(f"synthetic dataset quality gate failed: {failed}")

    distribution_counter: Counter[tuple[str, str, str]] = Counter()
    distribution_sessions: dict[
        tuple[str, str, str], set[str]
    ] = defaultdict(set)
    for row in rows:
        key = (row["label"], row["security_mode"], row["split"])
        distribution_counter[key] += 1
        distribution_sessions[key].add(row["session_id"])
    distribution = [
        {
            "label": key[0],
            "security_mode": key[1],
            "split": key[2],
            "rows": count,
            "sessions": len(distribution_sessions[key]),
        }
        for key, count in sorted(distribution_counter.items())
    ]

    _write_csv_atomic(
        output / "network_features.csv",
        SYNTHETIC_COLUMNS,
        rows,
    )
    _write_csv_atomic(
        output / "fusion_features.csv",
        FUSION_COLUMNS,
        fusion_rows,
    )
    _write_csv_atomic(
        output / "session_index.csv",
        SESSION_COLUMNS,
        sessions,
    )
    _write_csv_atomic(
        output / "class_distribution.csv",
        ["label", "security_mode", "split", "rows", "sessions"],
        distribution,
    )
    card = {
        "schema_version": DATASET_SCHEMA_VERSION,
        "created_utc": utc_now(),
        "generator_version": GENERATOR_VERSION,
        "origin": "synthetic_pretrain",
        "training_eligible": True,
        "evaluation_eligible": False,
        "deployment_evidence": False,
        "campaign_id": plan["campaign_id"],
        "campaign_plan_sha256": sha256_file(plan_file),
        "synthetic_scenario_catalog_sha256": sha256_file(
            SYNTHETIC_SCENARIO_PATH
        ),
        "policy_sha256": policy_hash,
        "sessions": len(sessions),
        "live_runner_backed_sessions": len(base_entries),
        "synthetic_only_sessions": len(extra_entries),
        "synthetic_only_sessions_per_scenario": (
            extra_sessions_per_scenario
        ),
        "windows_per_session": windows_per_session,
        "rows": len(rows),
        "window_sec": float(window_sec),
        "features": FEATURES,
        "telemetry_features": TELEMETRY_FEATURES,
        "fusion_features": FUSION_FEATURES,
        "splitting": {
            "unit": "session_id",
            "seed": split_seed,
            "ratios": {"train": 0.70, "validation": 0.15, "test": 0.15},
        },
        "novelty_protocol": {
            "holdout_candidates": sorted(DEFAULT_HOLDOUT_CLASSES),
            "rule": (
                "exclude candidate classes from training when measuring "
                "unknown-attack detection"
            ),
        },
        "limitations": [
            "feature-level synthetic data, not captured ROS2/DDS packets",
            "may be used for prototype pretraining only",
            "must not be used for final accuracy or SROS2 blocking claims",
            "final evaluation requires untouched live_lab sessions",
        ],
    }
    atomic_write_json(output / "dataset_card.json", card)
    atomic_write_json(output / "quality_report.json", quality)
    markdown = (
        "# SROS2 智慧防火牆合成預訓練資料集\n\n"
        f"- Session：{len(sessions)}\n"
        f"- 8 秒特徵視窗：{len(rows)}\n"
        f"- 視窗長度：{float(window_sec):g} 秒\n"
        f"- 攻擊類別：{len(ATTACK_PROFILES)} 種，加 normal 共 "
        f"{len(ATTACK_PROFILES) + 1} 類\n"
        f"- Live-runner-backed 情境：{len(base_entries)} sessions\n"
        f"- Synthetic-only 擴充情境：{len(extra_entries)} sessions\n"
        "- 來源：`synthetic_pretrain`\n"
        "- 可作正式評估：**否**\n"
        "- 分組單位：`session_id`\n"
        "- Permissive／Enforce 均使用 domain 30\n"
        "- Split：70% train／15% validation／15% test（以 session 分組）\n\n"
        "用途是資料管線開發與模型原型預訓練。它不是 ROS2/DDS "
        "封包擷取證據，不得用來宣稱最終攻擊偵測準確率或 SROS2 live "
        "阻擋成效。正式評估必須使用未參與生成規則調整的 live_lab "
        "PCAP sessions。\n\n"
        "主要檔案：\n\n"
        "- `network_features.csv`：模型視窗與完整來源標記。\n"
        "- `fusion_features.csv`：網路特徵加 SROS2／HMAC／ROS "
        "行為 telemetry。\n"
        "- `session_index.csv`：session、seed、split、強度與模式。\n"
        "- `class_distribution.csv`：每類／模式／split 分布。\n"
        "- `quality_report.json`：品質 gate 與特徵統計。\n"
        "- `checksums.json`：各檔案 SHA-256 與 byte count。\n"
    )
    markdown_path = output / "DATASET_CARD.md"
    _write_text_atomic(markdown_path, markdown)

    checksum_files = [
        output / "network_features.csv",
        output / "fusion_features.csv",
        output / "session_index.csv",
        output / "class_distribution.csv",
        output / "dataset_card.json",
        output / "quality_report.json",
        output / "DATASET_CARD.md",
    ]
    checksums = {
        "schema_version": "sros2-firewall-dataset-checksums/v1",
        "files": {
            path.name: {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for path in checksum_files
        },
    }
    atomic_write_json(output / "checksums.json", checksums)
    return {
        "output": str(output.resolve()),
        "sessions": len(sessions),
        "rows": len(rows),
        "classes": len({row["label"] for row in rows}),
        "quality_passed": quality["passed"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate prototype-only synthetic SROS2 firewall features"
        )
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--windows-per-session",
        type=int,
        default=DEFAULT_WINDOWS,
    )
    parser.add_argument(
        "--window-sec",
        type=float,
        default=DEFAULT_WINDOW_SEC,
    )
    parser.add_argument("--split-seed", type=int, default=20260727)
    parser.add_argument(
        "--extra-sessions-per-scenario",
        type=int,
        default=DEFAULT_EXTRA_SESSIONS_PER_SCENARIO,
        help=(
            "synthetic-only sessions per added attack; must be even "
            "(default: 100)"
        ),
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify checksums, counts, tier boundary and quality report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.verify_only:
        result = verify_synthetic_dataset(args.output)
        print(
            f"✅ synthetic dataset verified：{result['sessions']} sessions / "
            f"{result['rows']} windows / {result['files']} files"
        )
        return 0
    result = generate_synthetic_dataset(
        plan_path=args.plan,
        output_dir=args.output,
        windows_per_session=args.windows_per_session,
        window_sec=args.window_sec,
        split_seed=args.split_seed,
        extra_sessions_per_scenario=(
            args.extra_sessions_per_scenario
        ),
        overwrite=args.overwrite,
    )
    print(
        f"✅ synthetic pretraining dataset：{result['sessions']} sessions / "
        f"{result['rows']} windows / {result['classes']} classes"
    )
    print(f"輸出：{result['output']}")
    print("注意：evaluation_eligible=false，不得當成 live 成效證據。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
