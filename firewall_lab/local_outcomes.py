#!/usr/bin/env python3
"""Assemble tamper-evident same-host defense outcome evidence.

This module never starts ROS, sends traffic, or changes a firewall.  Dedicated
live probes write one bounded observation per required stage and preserve their
raw log as an artifact.  The assembler verifies stage coverage, safety facts,
artifact hashes, ordering, and recovery before it can emit the report consumed
by the cross-host admission gate.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Callable


from .schema import SchemaError, atomic_write_json, require_identifier, sha256_file, utc_now


OUTCOME_SCHEMA = "sros2-firewall-local-defense-outcomes/v1"
OBSERVATION_SCHEMA = "sros2-firewall-local-outcome-observation/v1"
LIVE_ACK = "I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE"
SESSION_RE = re.compile(
    r"[0-9]{8}T[0-9]{12}Z_[a-z][a-z0-9_]{0,63}_[0-9a-f]{8}"
)
HEX64_RE = re.compile(r"[0-9a-f]{64}")
MAX_FACTS = 24
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


REQUIRED_STAGES: dict[str, tuple[str, ...]] = {
    "normal_traffic_preserved": ("baseline",),
    "unauthorized_participant_denied": ("trigger", "protected", "recovery"),
    "hmac_forgery_dropped": ("trigger", "protected", "recovery"),
    "replay_dropped": ("trigger", "protected", "recovery"),
    "oversized_input_dropped": ("trigger", "protected", "recovery"),
    "parameter_unchanged": ("baseline", "trigger", "protected", "recovery"),
    "velocity_guard_zeroed": ("trigger", "protected"),
    "velocity_guard_recovered": ("baseline", "trigger", "recovery"),
    "graph_failure_fail_safe": ("trigger", "protected", "recovery"),
}


REQUIRED_FACT_KEYS: dict[tuple[str, str], frozenset[str]] = {
    ("normal_traffic_preserved", "baseline"): frozenset(
        {
            "required_topics_live",
            "authenticated_heartbeat_live",
            "final_cmd_vel_observed",
            "unauthorized_publishers",
        }
    ),
    ("unauthorized_participant_denied", "trigger"): frozenset(
        {"sros_deny_count", "sros_deny_evaluable", "unauthorized_delivery_count"}
    ),
    ("unauthorized_participant_denied", "protected"): frozenset(
        {"protected_state_unchanged"}
    ),
    ("unauthorized_participant_denied", "recovery"): frozenset(
        {"authorized_participant_healthy"}
    ),
    ("hmac_forgery_dropped", "trigger"): frozenset(
        {"bad_hmac_reject_count", "forged_accept_count"}
    ),
    ("hmac_forgery_dropped", "protected"): frozenset({"state_unchanged"}),
    ("hmac_forgery_dropped", "recovery"): frozenset({"next_valid_accepted"}),
    ("replay_dropped", "trigger"): frozenset(
        {"replay_reject_count", "replay_accept_count"}
    ),
    ("replay_dropped", "protected"): frozenset({"state_unchanged"}),
    ("replay_dropped", "recovery"): frozenset({"next_fresh_nonce_accepted"}),
    ("oversized_input_dropped", "trigger"): frozenset(
        {"oversized_reject_count", "oversized_accept_count"}
    ),
    ("oversized_input_dropped", "protected"): frozenset(
        {"process_alive", "state_unchanged"}
    ),
    ("oversized_input_dropped", "recovery"): frozenset({"next_valid_accepted"}),
    ("parameter_unchanged", "baseline"): frozenset({"parameter_sha256"}),
    ("parameter_unchanged", "trigger"): frozenset(
        {
            "set_rejected",
            "application_veto_observed",
            "rcl_read_only_veto_observed",
            "sros_deny_evaluable",
        }
    ),
    ("parameter_unchanged", "protected"): frozenset({"parameter_sha256"}),
    ("parameter_unchanged", "recovery"): frozenset({"node_healthy"}),
    ("velocity_guard_zeroed", "trigger"): frozenset(
        {"authenticated_trigger", "stop_latency_sec"}
    ),
    ("velocity_guard_zeroed", "protected"): frozenset(
        {"linear_abs_max", "angular_abs_max"}
    ),
    ("velocity_guard_recovered", "baseline"): frozenset({"guard_initially_locked"}),
    ("velocity_guard_recovered", "trigger"): frozenset({"fault_latched"}),
    ("velocity_guard_recovered", "recovery"): frozenset(
        {
            "fresh_authenticated_heartbeat",
            "authenticated_clear",
            "fresh_command",
            "output_resumed",
            "recovery_latency_sec",
        }
    ),
    ("graph_failure_fail_safe", "trigger"): frozenset(
        {"graph_exception_observed", "d4_fault_emitted"}
    ),
    ("graph_failure_fail_safe", "protected"): frozenset(
        {"guard_zeroed", "lock_transition_observed", "detail_bounded"}
    ),
    ("graph_failure_fail_safe", "recovery"): frozenset(
        {"graph_recovery_event", "monitor_healthy"}
    ),
}


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10_000_000


def _is_timestamp(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= 9_223_372_036_854_775_807
    )


def _is_finite(value: Any, minimum: float, maximum: float) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and minimum <= float(value) <= maximum
    )


def _expect(value: Any, predicate: Callable[[Any], bool], name: str) -> None:
    if not predicate(value):
        raise SchemaError(f"local outcome assertion failed: {name}")


def _validate_fact_types(facts: dict[str, Any]) -> None:
    if not isinstance(facts, dict) or len(facts) > MAX_FACTS:
        raise SchemaError("outcome facts must be a bounded object")
    for key, value in facts.items():
        require_identifier(key, "outcome fact")
        if isinstance(value, str):
            if not value or len(value) > 128 or any(ord(char) < 32 for char in value):
                raise SchemaError(f"invalid text outcome fact: {key}")
        elif isinstance(value, (bool, int, float)):
            if isinstance(value, float) and not math.isfinite(value):
                raise SchemaError(f"non-finite outcome fact: {key}")
        else:
            raise SchemaError(f"unsupported outcome fact type: {key}")


def _artifact_path(root: Path, value: Any) -> tuple[Path, str]:
    if not isinstance(value, str) or not value or len(value) > 256 or "\\" in value:
        raise SchemaError("artifact path must be a bounded POSIX relative path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SchemaError("artifact path must stay below evidence root")
    root_resolved = root.resolve(strict=True)
    path = root.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        raise SchemaError(f"artifact is missing or symlinked: {value}")
    resolved = path.resolve(strict=True)
    if resolved.parent != root_resolved and root_resolved not in resolved.parents:
        raise SchemaError("artifact escaped evidence root")
    return path, relative.as_posix()


def validate_observation(value: Any, *, evidence_root: Path) -> dict[str, Any]:
    expected = {
        "schema_version",
        "session_id",
        "check_id",
        "stage",
        "ts_unix_ns",
        "monotonic_ns",
        "producer",
        "facts",
        "artifact",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise SchemaError("local outcome observation has unexpected keys")
    if value["schema_version"] != OBSERVATION_SCHEMA:
        raise SchemaError("unsupported local outcome observation schema")
    session_id = value["session_id"]
    if not isinstance(session_id, str) or not SESSION_RE.fullmatch(session_id):
        raise SchemaError("invalid local outcome session_id")
    check_id = require_identifier(value["check_id"], "local outcome check_id")
    if check_id not in REQUIRED_STAGES:
        raise SchemaError(f"unsupported local outcome: {check_id}")
    stage = require_identifier(value["stage"], "local outcome stage")
    if stage not in REQUIRED_STAGES[check_id]:
        raise SchemaError(f"unexpected stage for {check_id}: {stage}")
    producer = require_identifier(value["producer"], "local outcome producer")
    for name in ("ts_unix_ns", "monotonic_ns"):
        if not _is_timestamp(value[name]):
            raise SchemaError(f"{name} must be a positive bounded integer")
    facts = value["facts"]
    _validate_fact_types(facts)
    expected_facts = REQUIRED_FACT_KEYS[(check_id, stage)]
    if set(facts) != expected_facts:
        raise SchemaError(
            f"unexpected facts for {check_id}/{stage}: expected={sorted(expected_facts)}"
        )
    artifact = value["artifact"]
    if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "bytes", "kind"}:
        raise SchemaError("outcome artifact has unexpected keys")
    path, relative = _artifact_path(evidence_root, artifact["path"])
    size = path.stat().st_size
    if (
        not isinstance(artifact["bytes"], int)
        or isinstance(artifact["bytes"], bool)
        or not 0 <= artifact["bytes"] <= MAX_ARTIFACT_BYTES
        or artifact["bytes"] != size
        or size > MAX_ARTIFACT_BYTES
    ):
        raise SchemaError("outcome artifact size mismatch or exceeds limit")
    digest = artifact["sha256"]
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest) or digest != sha256_file(path):
        raise SchemaError("outcome artifact SHA-256 mismatch")
    kind = require_identifier(artifact["kind"], "outcome artifact kind")
    if kind != "semantic_probe":
        raise SchemaError(
            "local outcome artifacts must use semantic_probe derivation"
        )
    # Import lazily: local_outcome_probe uses this module's stage contract to
    # produce observations.  The verifier re-opens the raw telemetry and
    # recomputes every fact, so a hashed arbitrary log plus caller-supplied
    # ``facts`` can no longer enter the admission report.
    from .local_outcome_probe import verify_probe_artifact

    derived = verify_probe_artifact(path, evidence_root=evidence_root)
    expected_binding = {
        "session_id": session_id,
        "check_id": check_id,
        "stage": stage,
        "ts_unix_ns": value["ts_unix_ns"],
        "monotonic_ns": value["monotonic_ns"],
        "facts": facts,
    }
    derived_binding = {
        name: derived[name]
        for name in expected_binding
    }
    if derived_binding != expected_binding or producer != "semantic_probe":
        raise SchemaError(
            "local outcome observation does not match semantic probe evidence"
        )
    return {
        **value,
        "session_id": session_id,
        "check_id": check_id,
        "stage": stage,
        "producer": producer,
        "facts": dict(facts),
        "artifact": {"path": relative, "sha256": digest, "bytes": size, "kind": kind},
    }


def _controlled_campaign_flag(
    observations: list[dict[str, Any]], *, evidence_root: Path
) -> bool:
    """Re-open semantic artifacts and classify natural vs controlled graph fault.

    A controlled campaign is valid only when both independent graph consumers
    recorded the seam in both the trigger and recovery windows.  Individual
    stage artifacts already reject controlled records in every other window;
    this campaign-level check prevents a half-triggered seam from being
    presented as either a natural or a complete controlled experiment.
    """
    from .local_outcome_probe import verify_probe_artifact

    flags: dict[tuple[str, str], bool] = {}
    for observation in observations:
        artifact_path, _relative = _artifact_path(
            evidence_root, observation["artifact"]["path"]
        )
        derived = verify_probe_artifact(
            artifact_path, evidence_root=evidence_root
        )
        key = (observation["check_id"], observation["stage"])
        flags[key] = derived["controlled_fault_injection"]

    trigger = flags.get(("graph_failure_fail_safe", "trigger"), False)
    protected = flags.get(("graph_failure_fail_safe", "protected"), False)
    recovery = flags.get(("graph_failure_fail_safe", "recovery"), False)
    if protected:
        raise SchemaError("controlled graph fault cannot occur in protected stage")
    if trigger is not recovery:
        raise SchemaError(
            "controlled graph fault trigger/recovery evidence is incomplete"
        )
    return trigger


def _assert_outcome(check_id: str, stages: dict[str, dict[str, Any]]) -> None:
    fact = lambda stage, name: stages[stage]["facts"][name]
    if check_id == "normal_traffic_preserved":
        for name in ("required_topics_live", "authenticated_heartbeat_live", "final_cmd_vel_observed"):
            _expect(fact("baseline", name), lambda value: value is True, name)
        _expect(fact("baseline", "unauthorized_publishers"), lambda value: _is_count(value) and value == 0, "unauthorized_publishers")
    elif check_id == "unauthorized_participant_denied":
        # Delivery is the security property and always binds. The vendor deny
        # count binds only when a security audit sink actually produced records;
        # under rmw_fastrtps it cannot, and absence must not be read as either
        # evidence of denial or evidence of failure.
        evaluable = fact("trigger", "sros_deny_evaluable")
        _expect(evaluable, lambda value: isinstance(value, bool), "sros_deny_evaluable")
        if evaluable:
            _expect(fact("trigger", "sros_deny_count"), lambda value: _is_count(value) and value >= 1, "sros_deny_count")
        _expect(fact("trigger", "unauthorized_delivery_count"), lambda value: _is_count(value) and value == 0, "unauthorized_delivery_count")
        _expect(fact("protected", "protected_state_unchanged"), lambda value: value is True, "protected_state_unchanged")
        _expect(fact("recovery", "authorized_participant_healthy"), lambda value: value is True, "authorized_participant_healthy")
    elif check_id == "hmac_forgery_dropped":
        _expect(fact("trigger", "bad_hmac_reject_count"), lambda value: _is_count(value) and value >= 1, "bad_hmac_reject_count")
        _expect(fact("trigger", "forged_accept_count"), lambda value: _is_count(value) and value == 0, "forged_accept_count")
        _expect(fact("protected", "state_unchanged"), lambda value: value is True, "state_unchanged")
        _expect(fact("recovery", "next_valid_accepted"), lambda value: value is True, "next_valid_accepted")
    elif check_id == "replay_dropped":
        _expect(fact("trigger", "replay_reject_count"), lambda value: _is_count(value) and value >= 1, "replay_reject_count")
        _expect(fact("trigger", "replay_accept_count"), lambda value: _is_count(value) and value == 0, "replay_accept_count")
        _expect(fact("protected", "state_unchanged"), lambda value: value is True, "state_unchanged")
        _expect(fact("recovery", "next_fresh_nonce_accepted"), lambda value: value is True, "next_fresh_nonce_accepted")
    elif check_id == "oversized_input_dropped":
        _expect(fact("trigger", "oversized_reject_count"), lambda value: _is_count(value) and value >= 1, "oversized_reject_count")
        _expect(fact("trigger", "oversized_accept_count"), lambda value: _is_count(value) and value == 0, "oversized_accept_count")
        _expect(fact("protected", "process_alive"), lambda value: value is True, "process_alive")
        _expect(fact("protected", "state_unchanged"), lambda value: value is True, "state_unchanged")
        _expect(fact("recovery", "next_valid_accepted"), lambda value: value is True, "next_valid_accepted")
    elif check_id == "parameter_unchanged":
        before = fact("baseline", "parameter_sha256")
        after = fact("protected", "parameter_sha256")
        _expect(before, lambda value: isinstance(value, str) and HEX64_RE.fullmatch(value) is not None, "parameter_sha256")
        _expect(after, lambda value: value == before, "parameter hash unchanged")
        # The parameter staying unchanged is the security property and always
        # binds. Which layer refused the change is recorded but does not gate
        # the verdict: rcl's read-only rejection and the application veto reach
        # the same outcome by different mechanisms, and demanding a particular
        # one would be demanding a particular implementation rather than the
        # property. The vendor permission deny binds only when a security audit
        # sink produced records, which under rmw_fastrtps it cannot.
        _expect(fact("trigger", "set_rejected"), lambda value: value is True, "set_rejected")
        for name in ("application_veto_observed", "rcl_read_only_veto_observed"):
            _expect(fact("trigger", name), lambda value: isinstance(value, bool), name)
        _expect(fact("trigger", "sros_deny_evaluable"), lambda value: isinstance(value, bool), "sros_deny_evaluable")
        _expect(fact("recovery", "node_healthy"), lambda value: value is True, "node_healthy")
    elif check_id == "velocity_guard_zeroed":
        _expect(fact("trigger", "authenticated_trigger"), lambda value: value is True, "authenticated_trigger")
        _expect(fact("trigger", "stop_latency_sec"), lambda value: _is_finite(value, 0.0, 2.0), "stop_latency_sec")
        _expect(fact("protected", "linear_abs_max"), lambda value: _is_finite(value, 0.0, 1e-6), "linear_abs_max")
        _expect(fact("protected", "angular_abs_max"), lambda value: _is_finite(value, 0.0, 1e-6), "angular_abs_max")
    elif check_id == "velocity_guard_recovered":
        _expect(fact("baseline", "guard_initially_locked"), lambda value: value is True, "guard_initially_locked")
        _expect(fact("trigger", "fault_latched"), lambda value: value is True, "fault_latched")
        for name in ("fresh_authenticated_heartbeat", "authenticated_clear", "fresh_command", "output_resumed"):
            _expect(fact("recovery", name), lambda value: value is True, name)
        _expect(fact("recovery", "recovery_latency_sec"), lambda value: _is_finite(value, 0.0, 5.0), "recovery_latency_sec")
    elif check_id == "graph_failure_fail_safe":
        for stage, name in (
            ("trigger", "graph_exception_observed"),
            ("trigger", "d4_fault_emitted"),
            ("protected", "guard_zeroed"),
            ("protected", "detail_bounded"),
            ("recovery", "graph_recovery_event"),
            ("recovery", "monitor_healthy"),
        ):
            _expect(fact(stage, name), lambda value: value is True, name)
    else:  # pragma: no cover - guarded by schema
        raise SchemaError(f"unsupported local outcome: {check_id}")


def assemble_local_outcomes(
    *,
    observations_path: Path,
    evidence_root: Path,
    output_path: Path,
    live_ack: str,
) -> dict[str, Any]:
    if live_ack != LIVE_ACK:
        raise SchemaError("explicit live same-host loopback acknowledgement required")
    if observations_path.is_symlink() or not observations_path.is_file():
        raise SchemaError("observations must be a regular non-symlink file")
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise SchemaError("evidence root must be a real directory")
    root_resolved = evidence_root.resolve(strict=True)
    if output_path.parent.resolve(strict=True) != root_resolved:
        raise SchemaError("local outcome report must be written inside evidence root")
    observation_file, observation_relative = _artifact_path(
        evidence_root, observations_path.resolve(strict=True).relative_to(root_resolved).as_posix()
    )
    observations: list[dict[str, Any]] = []
    for line_number, line in enumerate(observations_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SchemaError(f"invalid observation JSON at line {line_number}") from exc
        observations.append(validate_observation(raw, evidence_root=evidence_root))
    if not observations:
        raise SchemaError("no local outcome observations supplied")
    session_ids = {item["session_id"] for item in observations}
    if len(session_ids) != 1:
        raise SchemaError("all local outcomes must belong to one session")
    session_id = next(iter(session_ids))
    grouped: dict[str, dict[str, dict[str, Any]]] = {
        check_id: {} for check_id in REQUIRED_STAGES
    }
    for observation in observations:
        stages = grouped[observation["check_id"]]
        stage = observation["stage"]
        if stage in stages:
            raise SchemaError(f"duplicate local outcome stage: {observation['check_id']}/{stage}")
        stages[stage] = observation
    controlled_fault_injection = _controlled_campaign_flag(
        observations, evidence_root=evidence_root
    )
    checks: list[dict[str, Any]] = []
    previous_monotonic = 0
    for check_id, required_stages in REQUIRED_STAGES.items():
        stages = grouped[check_id]
        if set(stages) != set(required_stages):
            raise SchemaError(
                f"incomplete stages for {check_id}: expected={list(required_stages)} actual={sorted(stages)}"
            )
        stage_times = [stages[stage]["monotonic_ns"] for stage in required_stages]
        if stage_times != sorted(stage_times) or len(set(stage_times)) != len(stage_times):
            raise SchemaError(f"non-monotonic stages for {check_id}")
        if stage_times[0] <= previous_monotonic:
            raise SchemaError("local outcome checks must form one ordered evidence timeline")
        previous_monotonic = stage_times[-1]
        _assert_outcome(check_id, stages)
        checks.append(
            {
                "id": check_id,
                "passed": True,
                "evidence": ";".join(
                    f"{stage}:{stages[stage]['artifact']['path']}#{stages[stage]['artifact']['sha256']}"
                    for stage in required_stages
                ),
                "stages": [stages[stage] for stage in required_stages],
            }
        )
    report = {
        "schema_version": OUTCOME_SCHEMA,
        "created_utc": utc_now(),
        "session_id": session_id,
        "topology": "same_host_loopback",
        "evidence_origin": "live_loopback_probes",
        "network_activity": "same_host_loopback_only",
        "host_firewall_modified": False,
        "controlled_fault_injection": controlled_fault_injection,
        "observations_path": observation_relative,
        "observations_sha256": sha256_file(observation_file),
        "checks": checks,
    }
    atomic_write_json(output_path, report)
    return report


def verify_local_outcome_report(report_path: Path) -> tuple[bool, str]:
    """Re-derive every pass result from raw observations and hashed artifacts."""
    if report_path.is_symlink() or not report_path.is_file():
        raise SchemaError("local outcome report must be a regular non-symlink file")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError("invalid local outcome report JSON") from exc
    expected_root = {
        "schema_version",
        "created_utc",
        "session_id",
        "topology",
        "evidence_origin",
        "network_activity",
        "host_firewall_modified",
        "controlled_fault_injection",
        "observations_path",
        "observations_sha256",
        "checks",
    }
    if not isinstance(report, dict) or set(report) != expected_root:
        raise SchemaError("local outcome report has unexpected keys")
    if report["schema_version"] != OUTCOME_SCHEMA:
        raise SchemaError("unsupported local outcome report schema")
    if report["topology"] != "same_host_loopback":
        raise SchemaError("local outcomes must use same_host_loopback")
    if report["evidence_origin"] != "live_loopback_probes":
        raise SchemaError("local outcomes require live loopback probes")
    if report["network_activity"] != "same_host_loopback_only":
        raise SchemaError("local outcomes must be scoped to same-host loopback")
    if report["host_firewall_modified"] is not False:
        raise SchemaError("local outcome phase may not modify host firewall")
    if not isinstance(report["controlled_fault_injection"], bool):
        raise SchemaError("controlled fault injection report marker must be boolean")
    if not isinstance(report["created_utc"], str):
        raise SchemaError("invalid local outcome created_utc")
    try:
        created = datetime.fromisoformat(report["created_utc"])
    except ValueError as exc:
        raise SchemaError("invalid local outcome created_utc") from exc
    if created.utcoffset() != timedelta(0):
        raise SchemaError("local outcome created_utc must include UTC offset")
    session_id = report["session_id"]
    if not isinstance(session_id, str) or not SESSION_RE.fullmatch(session_id):
        raise SchemaError("invalid local outcome report session_id")
    digest = report["observations_sha256"]
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise SchemaError("invalid observations SHA-256")
    root = report_path.parent
    observations_path, _relative = _artifact_path(root, report["observations_path"])
    if sha256_file(observations_path) != digest:
        raise SchemaError("observations SHA-256 mismatch")
    raw_observations: list[dict[str, Any]] = []
    for line_number, line in enumerate(observations_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SchemaError(f"invalid observation JSON at line {line_number}") from exc
        raw_observations.append(validate_observation(raw, evidence_root=root))
    if any(item["session_id"] != session_id for item in raw_observations):
        raise SchemaError("observation session does not match report")
    controlled_fault_injection = _controlled_campaign_flag(
        raw_observations, evidence_root=root
    )
    if report["controlled_fault_injection"] is not controlled_fault_injection:
        raise SchemaError("controlled fault injection report marker mismatch")
    checks = report["checks"]
    if not isinstance(checks, list) or len(checks) != len(REQUIRED_STAGES):
        raise SchemaError("local outcome report must contain exactly nine checks")
    expected_ids = list(REQUIRED_STAGES)
    if [item.get("id") for item in checks if isinstance(item, dict)] != expected_ids:
        raise SchemaError("local outcome checks are missing, duplicated, or reordered")
    flattened: list[dict[str, Any]] = []
    previous_monotonic = 0
    for check, check_id in zip(checks, expected_ids, strict=True):
        if set(check) != {"id", "passed", "evidence", "stages"} or check["passed"] is not True:
            raise SchemaError(f"invalid check record: {check_id}")
        stages_list = check["stages"]
        required = REQUIRED_STAGES[check_id]
        if not isinstance(stages_list, list) or [item.get("stage") for item in stages_list if isinstance(item, dict)] != list(required):
            raise SchemaError(f"incomplete or reordered stages for {check_id}")
        canonical_stages = [validate_observation(item, evidence_root=root) for item in stages_list]
        if any(item["check_id"] != check_id or item["session_id"] != session_id for item in canonical_stages):
            raise SchemaError(f"stage binding mismatch for {check_id}")
        stage_map = {item["stage"]: item for item in canonical_stages}
        times = [item["monotonic_ns"] for item in canonical_stages]
        if times != sorted(times) or len(times) != len(set(times)) or times[0] <= previous_monotonic:
            raise SchemaError("local outcome report timeline is not strictly ordered")
        previous_monotonic = times[-1]
        _assert_outcome(check_id, stage_map)
        expected_evidence = ";".join(
            f"{stage}:{stage_map[stage]['artifact']['path']}#{stage_map[stage]['artifact']['sha256']}"
            for stage in required
        )
        if check["evidence"] != expected_evidence:
            raise SchemaError(f"evidence summary mismatch for {check_id}")
        flattened.extend(canonical_stages)
    if flattened != raw_observations:
        raise SchemaError("embedded stages do not match raw observation stream")
    return True, f"{len(checks)} hashed live loopback outcomes proven"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--live-loopback-ack", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = assemble_local_outcomes(
        observations_path=args.observations,
        evidence_root=args.evidence_root,
        output_path=args.report,
        live_ack=args.live_loopback_ack,
    )
    print(f"local_outcomes={len(report['checks'])} report={args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
