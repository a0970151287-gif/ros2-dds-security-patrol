import json
from pathlib import Path

import pytest

from firewall_lab.identity_attribution import (
    IDENTITY_FEATURES,
    IDENTITY_OBSERVATION_SCHEMA,
    audit_identity_attribution_readiness,
    build_identity_window_features,
    read_identity_observations,
    validate_identity_observation,
)
from firewall_lab.schema import SchemaError


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
GUID_A = "01" * 12
GUID_B = "02" * 12


def _observation(sequence=0, **changes):
    value = {
        "schema_version": IDENTITY_OBSERVATION_SCHEMA,
        "session_id": "session_001",
        "sequence": sequence,
        "ts_unix_ns": 1_000_000_000 + sequence,
        "window": 0,
        "collector_id": "trusted_collector",
        "capture_sha256": SHA_A,
        "decoder_sha256": SHA_B,
        "policy_sha256": SHA_C,
        "security_mode": "enforce",
        "source_ip": "10.0.0.2",
        "interface": "eth0",
        "guid_prefix": GUID_A,
        "entity_id": None,
        "topic": None,
        "evidence_kind": "spdp_locator",
        "identity_subject_sha256": None,
        "permission_state": "unknown",
    }
    value.update(changes)
    return value


def test_observation_kinds_are_strict_and_canonical():
    assert validate_identity_observation(_observation())["source_ip"] == "10.0.0.2"
    endpoint = _observation(
        evidence_kind="sedp_endpoint",
        entity_id="000003c2",
        topic="rt/chatter",
        permission_state="allow",
    )
    assert validate_identity_observation(endpoint)["topic"] == "rt/chatter"
    identity = _observation(
        evidence_kind="authenticated_identity",
        identity_subject_sha256="d" * 64,
        permission_state="allow",
    )
    assert validate_identity_observation(identity)["identity_subject_sha256"] == "d" * 64


@pytest.mark.parametrize(
    "changes,match",
    [
        ({"source_ip": "010.0.0.2"}, "canonical IPv4"),
        ({"source_ip": "224.0.0.1"}, "multicast"),
        ({"guid_prefix": "A" * 24}, "guid_prefix"),
        ({"sequence": True}, "sequence"),
        ({"entity_id": "000003c2"}, "spdp_locator"),
        ({"permission_state": "allow"}, "spdp_locator"),
        ({"evidence_kind": "authenticated_identity"}, "requires subject"),
    ],
)
def test_observation_rejects_ambiguous_or_contradictory_fields(changes, match):
    with pytest.raises(SchemaError, match=match):
        validate_identity_observation(_observation(**changes))


def test_observation_rejects_extra_fields():
    value = _observation()
    value["source_ip_attribution_verified"] = True
    with pytest.raises(SchemaError, match="extra"):
        validate_identity_observation(value)


def test_archive_binds_sequence_time_session_capture_policy_and_collector(tmp_path):
    rows = [_observation(0), _observation(1, ts_unix_ns=1_000_000_002)]
    path = tmp_path / "identity.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    loaded = read_identity_observations(
        path,
        expected_session_id="session_001",
        expected_capture_sha256=SHA_A,
        expected_policy_sha256=SHA_C,
    )
    assert [row["sequence"] for row in loaded] == [0, 1]

    rows[1]["sequence"] = 2
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    with pytest.raises(SchemaError, match="gap or reorder"):
        read_identity_observations(
            path,
            expected_session_id="session_001",
            expected_capture_sha256=SHA_A,
            expected_policy_sha256=SHA_C,
        )


def test_identity_features_measure_signals_but_never_authorize_action():
    rows = [
        _observation(0),
        _observation(
            1,
            evidence_kind="sedp_endpoint",
            entity_id="000003c2",
            topic="rt/chatter",
            permission_state="deny",
        ),
        _observation(
            2,
            evidence_kind="authenticated_identity",
            identity_subject_sha256="d" * 64,
            permission_state="deny",
        ),
        _observation(3, guid_prefix=GUID_B, source_ip="10.0.0.2"),
        _observation(4, source_ip="10.0.0.3"),
    ]
    feature = build_identity_window_features(rows, window_sec=5.0)[0]
    assert set(IDENTITY_FEATURES) <= set(feature)
    assert feature["rtps_participant_rate"] == 0.4
    assert feature["rtps_guid_churn_rate"] == 0.4
    assert feature["rtps_guid_multi_ip_ratio"] == 0.5
    assert feature["rtps_ip_multi_guid_ratio"] == 0.5
    assert feature["rtps_acl_deny_ratio"] == 1.0
    assert feature["rtps_authenticated_binding_ratio"] == 0.5
    assert feature["rtps_complete_evidence_ratio"] == 0.5
    assert feature["source_ip_attribution_verified"] is False
    assert feature["deployment_eligible"] is False
    assert feature["automatic_ip_block_authorized"] is False


def _session(root: Path, name: str, *, with_identity=False, identity_fields=False):
    directory = root / name
    (directory / "zeek").mkdir(parents=True)
    evidence = {"traffic.pcapng": {}, "zeek/conn.log": {}}
    if with_identity:
        evidence.update(
            {
                "rtps_identity.jsonl": {},
                "identity_attestation.json": {},
                "dds_security_audit.jsonl": {},
            }
        )
    (directory / "manifest.json").write_text(
        json.dumps({"training_eligible": True, "evidence": evidence}), encoding="utf-8"
    )
    fields = ["ts", "uid", "id.orig_h", "id.resp_h"]
    if identity_fields:
        fields += [
            "rtps_guid_prefix",
            "rtps_entity_id",
            "dds_topic",
            "dds_identity_subject_sha256",
        ]
    (directory / "zeek" / "conn.log").write_text(
        "#fields\t" + "\t".join(fields) + "\n", encoding="utf-8"
    )


def test_dataset_audit_distinguishes_five_tuple_from_identity_attribution(tmp_path):
    _session(tmp_path, "session_a")
    _session(tmp_path, "session_b", with_identity=True, identity_fields=True)
    report = audit_identity_attribution_readiness(tmp_path)
    assert report["counts"]["sessions"] == 2
    assert report["counts"]["pcap_sessions"] == 2
    assert report["counts"]["rtps_identity.jsonl_sessions"] == 1
    assert report["counts"]["zeek_identity_field_sessions"] == 1
    assert report["status"] == "blocked"
    assert report["source_ip_attribution_verified"] is False
    assert report["autonomous_ip_block_ready"] is False
    assert any("same-UID" in item for item in report["blockers"])


def test_versioned_contract_matches_code_and_remains_blocked():
    root = Path(__file__).resolve().parents[1]
    contract = json.loads(
        (root / "firewall_lab" / "identity_attribution_contract.v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert tuple(contract["feature_names"]) == IDENTITY_FEATURES
    assert contract["observation_schema"] == IDENTITY_OBSERVATION_SCHEMA
    assert contract["source_ip_attribution_verified"] is False
    assert contract["autonomous_ip_block_ready"] is False
    assert contract["runtime_authorization"] is False
