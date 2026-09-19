"""Strict RTPS/DDS identity evidence for future source-attribution features.

The current campaign has packet captures and Zeek five-tuples, but no decoded
GUID/endpoint/topic stream and no authenticated DDS identity-to-IP binding.
This module defines the missing evidence boundary without treating a caller
supplied boolean as proof.  Its feature rows are development inputs only and
can never authorize a network action.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from .schema import SchemaError, utc_now


IDENTITY_OBSERVATION_SCHEMA = "sros2-firewall-rtps-identity-observation/v1"
IDENTITY_FEATURE_SCHEMA = "sros2-firewall-rtps-identity-features/v1"
IDENTITY_READINESS_SCHEMA = "sros2-firewall-identity-attribution-readiness/v1"

EVIDENCE_KINDS = frozenset(
    {"spdp_locator", "sedp_endpoint", "authenticated_identity"}
)
PERMISSION_STATES = frozenset({"unknown", "allow", "deny"})
IDENTITY_FEATURES = (
    "rtps_participant_rate",
    "rtps_guid_churn_rate",
    "rtps_guid_multi_ip_ratio",
    "rtps_ip_multi_guid_ratio",
    "rtps_endpoint_rate",
    "rtps_topic_diversity_ratio",
    "rtps_acl_deny_ratio",
    "rtps_authenticated_binding_ratio",
    "rtps_complete_evidence_ratio",
)
REQUIRED_IDENTITY_ARTIFACTS = (
    "rtps_identity.jsonl",
    "identity_attestation.json",
    "dds_security_audit.jsonl",
)
REQUIRED_ZEEK_IDENTITY_FIELDS = frozenset(
    {
        "rtps_guid_prefix",
        "rtps_entity_id",
        "dds_topic",
        "dds_identity_subject_sha256",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GUID_PREFIX_RE = re.compile(r"^[0-9a-f]{24}$")
_ENTITY_ID_RE = re.compile(r"^[0-9a-f]{8}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")

_OBSERVATION_KEYS = frozenset(
    {
        "schema_version",
        "session_id",
        "sequence",
        "ts_unix_ns",
        "window",
        "collector_id",
        "capture_sha256",
        "decoder_sha256",
        "policy_sha256",
        "security_mode",
        "source_ip",
        "interface",
        "guid_prefix",
        "entity_id",
        "topic",
        "evidence_kind",
        "identity_subject_sha256",
        "permission_state",
    }
)


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise SchemaError(
            f"{label} fields must be exact; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise SchemaError(f"{field} is invalid")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise SchemaError(f"{field} must be lowercase SHA-256")
    return value


def _optional_text(value: Any, field: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(not character.isprintable() for character in value)
    ):
        raise SchemaError(f"{field} is invalid")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SchemaError(f"{field} must be a non-negative integer")
    return value


def validate_identity_observation(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one decoded identity observation and return canonical values."""

    if not isinstance(value, Mapping):
        raise SchemaError("identity observation must be an object")
    _exact_keys(value, _OBSERVATION_KEYS, "identity observation")
    if value["schema_version"] != IDENTITY_OBSERVATION_SCHEMA:
        raise SchemaError("unsupported identity observation schema")
    session_id = _identifier(value["session_id"], "session_id")
    collector_id = _identifier(value["collector_id"], "collector_id")
    sequence = _nonnegative_int(value["sequence"], "sequence")
    ts_unix_ns = _nonnegative_int(value["ts_unix_ns"], "ts_unix_ns")
    if ts_unix_ns == 0:
        raise SchemaError("ts_unix_ns must be positive")
    window = _nonnegative_int(value["window"], "window")
    capture_sha256 = _sha256(value["capture_sha256"], "capture_sha256")
    decoder_sha256 = _sha256(value["decoder_sha256"], "decoder_sha256")
    policy_sha256 = _sha256(value["policy_sha256"], "policy_sha256")
    if value["security_mode"] not in {"permissive", "enforce"}:
        raise SchemaError("security_mode must be permissive or enforce")
    try:
        source_ip = ipaddress.ip_address(value["source_ip"])
    except (TypeError, ValueError) as exc:
        raise SchemaError("source_ip must be a canonical IPv4 address") from exc
    if source_ip.version != 4 or str(source_ip) != value["source_ip"]:
        raise SchemaError("source_ip must be a canonical IPv4 address")
    if source_ip.is_multicast or source_ip.is_unspecified:
        raise SchemaError("source_ip may not be multicast or unspecified")
    interface = value["interface"]
    if not isinstance(interface, str) or not _INTERFACE_RE.fullmatch(interface):
        raise SchemaError("interface is invalid")
    guid_prefix = value["guid_prefix"]
    if not isinstance(guid_prefix, str) or not _GUID_PREFIX_RE.fullmatch(guid_prefix):
        raise SchemaError("guid_prefix must be 12 lowercase hexadecimal bytes")
    entity_id = value["entity_id"]
    if entity_id is not None and (
        not isinstance(entity_id, str) or not _ENTITY_ID_RE.fullmatch(entity_id)
    ):
        raise SchemaError("entity_id must be 4 lowercase hexadecimal bytes or null")
    topic = _optional_text(value["topic"], "topic")
    evidence_kind = value["evidence_kind"]
    if evidence_kind not in EVIDENCE_KINDS:
        raise SchemaError("evidence_kind is invalid")
    subject = value["identity_subject_sha256"]
    if subject is not None:
        subject = _sha256(subject, "identity_subject_sha256")
    permission_state = value["permission_state"]
    if permission_state not in PERMISSION_STATES:
        raise SchemaError("permission_state is invalid")

    if evidence_kind == "spdp_locator":
        if entity_id is not None or topic is not None or subject is not None:
            raise SchemaError("spdp_locator cannot assert endpoint, topic, or identity")
        if permission_state != "unknown":
            raise SchemaError("spdp_locator permission_state must be unknown")
    elif evidence_kind == "sedp_endpoint":
        if entity_id is None or topic is None or subject is not None:
            raise SchemaError("sedp_endpoint requires entity_id/topic and no identity")
    else:
        if entity_id is not None or topic is not None or subject is None:
            raise SchemaError(
                "authenticated_identity requires subject and no endpoint/topic"
            )

    return {
        "schema_version": IDENTITY_OBSERVATION_SCHEMA,
        "session_id": session_id,
        "sequence": sequence,
        "ts_unix_ns": ts_unix_ns,
        "window": window,
        "collector_id": collector_id,
        "capture_sha256": capture_sha256,
        "decoder_sha256": decoder_sha256,
        "policy_sha256": policy_sha256,
        "security_mode": value["security_mode"],
        "source_ip": str(source_ip),
        "interface": interface,
        "guid_prefix": guid_prefix,
        "entity_id": entity_id,
        "topic": topic,
        "evidence_kind": evidence_kind,
        "identity_subject_sha256": subject,
        "permission_state": permission_state,
    }


def read_identity_observations(
    path: str | Path,
    *,
    expected_session_id: str,
    expected_capture_sha256: str,
    expected_policy_sha256: str,
) -> list[dict[str, Any]]:
    """Read a sealed JSONL stream with sequence and lineage checks."""

    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size <= 0:
        raise SchemaError("identity observation archive is missing, empty, or symlinked")
    _identifier(expected_session_id, "expected_session_id")
    _sha256(expected_capture_sha256, "expected_capture_sha256")
    _sha256(expected_policy_sha256, "expected_policy_sha256")
    rows: list[dict[str, Any]] = []
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SchemaError(f"invalid identity JSONL at line {line_number}") from exc
            rows.append(validate_identity_observation(decoded))
    if not rows:
        raise SchemaError("identity observation archive has no rows")
    if [row["sequence"] for row in rows] != list(range(len(rows))):
        raise SchemaError("identity observation sequence has a gap or reorder")
    timestamps = [row["ts_unix_ns"] for row in rows]
    if timestamps != sorted(timestamps):
        raise SchemaError("identity observation timestamps are not monotonic")
    if {row["session_id"] for row in rows} != {expected_session_id}:
        raise SchemaError("identity observation session binding mismatch")
    if {row["capture_sha256"] for row in rows} != {expected_capture_sha256}:
        raise SchemaError("identity observation capture binding mismatch")
    if {row["policy_sha256"] for row in rows} != {expected_policy_sha256}:
        raise SchemaError("identity observation policy binding mismatch")
    if len({row["decoder_sha256"] for row in rows}) != 1:
        raise SchemaError("identity observations use multiple decoder revisions")
    if len({row["collector_id"] for row in rows}) != 1:
        raise SchemaError("identity observations use multiple collectors")
    return rows


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return min(1.0, max(0.0, numerator / denominator))


def build_identity_window_features(
    observations: Iterable[Mapping[str, Any]], *, window_sec: float
) -> list[dict[str, Any]]:
    """Build development-only RTPS identity features by bounded window."""

    if isinstance(window_sec, bool) or not isinstance(window_sec, (int, float)):
        raise SchemaError("window_sec must be numeric")
    window_sec = float(window_sec)
    if not math.isfinite(window_sec) or not 0.1 <= window_sec <= 3600.0:
        raise SchemaError("window_sec must be in 0.1..3600")
    rows = [validate_identity_observation(row) for row in observations]
    if not rows:
        raise SchemaError("identity features require observations")
    if len({row["session_id"] for row in rows}) != 1:
        raise SchemaError("identity feature rows must belong to one session")
    if len({row["security_mode"] for row in rows}) != 1:
        raise SchemaError("identity feature rows must use one security mode")
    if len({row["capture_sha256"] for row in rows}) != 1:
        raise SchemaError("identity feature rows must use one capture")
    if len({row["policy_sha256"] for row in rows}) != 1:
        raise SchemaError("identity feature rows must use one policy")
    if [row["sequence"] for row in rows] != list(range(len(rows))):
        raise SchemaError("identity feature sequence has a gap or reorder")

    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["window"]].append(row)
    seen_guids: set[str] = set()
    result: list[dict[str, Any]] = []
    for window in sorted(grouped):
        current = grouped[window]
        guids = {row["guid_prefix"] for row in current}
        new_guids = guids - seen_guids
        seen_guids.update(guids)
        guid_to_ips: dict[str, set[str]] = defaultdict(set)
        ip_to_guids: dict[str, set[str]] = defaultdict(set)
        kinds_by_guid: dict[str, set[str]] = defaultdict(set)
        endpoints = set()
        topics = set()
        endpoint_rows = 0
        denied_endpoints = 0
        authenticated_guids = set()
        for row in current:
            guid = row["guid_prefix"]
            guid_to_ips[guid].add(row["source_ip"])
            ip_to_guids[row["source_ip"]].add(guid)
            kinds_by_guid[guid].add(row["evidence_kind"])
            if row["evidence_kind"] == "sedp_endpoint":
                endpoint_rows += 1
                endpoints.add((guid, row["entity_id"]))
                topics.add(row["topic"])
                denied_endpoints += int(row["permission_state"] == "deny")
            elif row["evidence_kind"] == "authenticated_identity":
                authenticated_guids.add(guid)
        complete = {
            guid
            for guid, kinds in kinds_by_guid.items()
            if EVIDENCE_KINDS <= kinds
        }
        feature_values = {
            "rtps_participant_rate": round(len(guids) / window_sec, 6),
            "rtps_guid_churn_rate": round(len(new_guids) / window_sec, 6),
            "rtps_guid_multi_ip_ratio": round(
                _safe_ratio(sum(len(ips) > 1 for ips in guid_to_ips.values()), len(guids)),
                6,
            ),
            "rtps_ip_multi_guid_ratio": round(
                _safe_ratio(
                    sum(len(values) > 1 for values in ip_to_guids.values()),
                    len(ip_to_guids),
                ),
                6,
            ),
            "rtps_endpoint_rate": round(len(endpoints) / window_sec, 6),
            "rtps_topic_diversity_ratio": round(
                _safe_ratio(len(topics), len(endpoints)), 6
            ),
            "rtps_acl_deny_ratio": round(
                _safe_ratio(denied_endpoints, endpoint_rows), 6
            ),
            "rtps_authenticated_binding_ratio": round(
                _safe_ratio(len(authenticated_guids), len(guids)), 6
            ),
            "rtps_complete_evidence_ratio": round(
                _safe_ratio(len(complete), len(guids)), 6
            ),
        }
        result.append(
            {
                "schema_version": IDENTITY_FEATURE_SCHEMA,
                "session_id": current[0]["session_id"],
                "security_mode": current[0]["security_mode"],
                "window": window,
                **feature_values,
                "source_available": True,
                "source_ip_attribution_verified": False,
                "deployment_eligible": False,
                "automatic_ip_block_authorized": False,
            }
        )
    return result


def _zeek_fields(path: Path) -> set[str]:
    if path.is_symlink() or not path.is_file():
        return set()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("#fields"):
                return set(line.rstrip("\r\n").split("\t")[1:])
            if not line.startswith("#"):
                break
    return set()


def audit_identity_attribution_readiness(dataset_root: str | Path) -> dict[str, Any]:
    """Inventory existing archives without parsing PCAP or sending traffic."""

    root = Path(dataset_root)
    if root.is_symlink() or not root.is_dir():
        raise SchemaError("dataset root is missing or symlinked")
    manifests = sorted(root.glob("*/manifest.json"))
    if not manifests:
        raise SchemaError("dataset has no session manifests")
    counts = defaultdict(int)
    union_fields: set[str] = set()
    for manifest_path in manifests:
        if manifest_path.is_symlink():
            raise SchemaError("session manifest may not be symlinked")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SchemaError(f"invalid manifest: {manifest_path}") from exc
        if not isinstance(manifest, dict):
            raise SchemaError(f"manifest is not an object: {manifest_path}")
        counts["sessions"] += 1
        counts["training_eligible_sessions"] += int(
            manifest.get("training_eligible") is True
        )
        evidence = manifest.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        counts["pcap_sessions"] += int("traffic.pcapng" in evidence)
        counts["zeek_conn_sessions"] += int("zeek/conn.log" in evidence)
        for name in REQUIRED_IDENTITY_ARTIFACTS:
            counts[f"{name}_sessions"] += int(name in evidence)
        fields = _zeek_fields(manifest_path.parent / "zeek" / "conn.log")
        union_fields.update(fields)
        counts["zeek_identity_field_sessions"] += int(
            REQUIRED_ZEEK_IDENTITY_FIELDS <= fields
        )

    required_available = all(
        counts[f"{name}_sessions"] == counts["sessions"]
        for name in REQUIRED_IDENTITY_ARTIFACTS
    )
    zeek_available = counts["zeek_identity_field_sessions"] == counts["sessions"]
    blockers = []
    if not required_available:
        blockers.append(
            "no complete decoded RTPS identity plus independent attestation archive"
        )
    if not zeek_available:
        blockers.append(
            "Zeek conn.log exposes five-tuples but not GUID, endpoint, topic, or identity subject"
        )
    blockers.extend(
        [
            "same-UID telemetry source validation is not DDS identity-to-IP attribution",
            "same-host WSL mirrored addresses cannot establish a unique external attacker IP",
            "no independent trusted collector has attested GUID-to-IP-to-subject bindings",
        ]
    )
    dataset_digest = hashlib.sha256(
        "\n".join(path.parent.name for path in manifests).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": IDENTITY_READINESS_SCHEMA,
        "created_utc": utc_now(),
        "dataset": {
            "path": str(root),
            "session_name_list_sha256": dataset_digest,
        },
        "counts": dict(sorted(counts.items())),
        "required_identity_artifacts": list(REQUIRED_IDENTITY_ARTIFACTS),
        "required_zeek_identity_fields": sorted(REQUIRED_ZEEK_IDENTITY_FIELDS),
        "observed_zeek_fields": sorted(union_fields),
        "blockers": blockers,
        "status": "blocked",
        "source_ip_attribution_verified": False,
        "cross_host_test_ready": False,
        "autonomous_ip_block_ready": False,
        "deployment_eligible": False,
        "runtime_authorization": False,
        "network_activity_performed": False,
    }


__all__ = [
    "EVIDENCE_KINDS",
    "IDENTITY_FEATURES",
    "IDENTITY_FEATURE_SCHEMA",
    "IDENTITY_OBSERVATION_SCHEMA",
    "IDENTITY_READINESS_SCHEMA",
    "REQUIRED_IDENTITY_ARTIFACTS",
    "REQUIRED_ZEEK_IDENTITY_FIELDS",
    "audit_identity_attribution_readiness",
    "build_identity_window_features",
    "read_identity_observations",
    "validate_identity_observation",
]
