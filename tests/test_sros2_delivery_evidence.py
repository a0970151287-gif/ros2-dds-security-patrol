"""Offline tests for bounded, direct application delivery evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from firewall_lab.schema import SchemaError, sha256_file
from firewall_lab.sros2_delivery_evidence import (
    AGGREGATE_SCHEMA,
    ARCHIVE_RECORD_SCHEMA,
    CONTRACT_SCHEMA,
    REPORT_SCHEMA,
    aggregate_delivery_evidence,
    main,
    verify_delivery_evidence,
)


BASE = datetime(2026, 8, 17, tzinfo=timezone.utc)


def _ts(seconds: float) -> str:
    return (BASE + timedelta(seconds=seconds)).isoformat(timespec="milliseconds")


def _payload(trial_id: str, sequence: int) -> str:
    return hashlib.sha256(f"{trial_id}:{sequence}".encode()).hexdigest()


def _binding(
    *,
    mode: str,
    trial_id: str,
    session_id: str,
    authorization_case: str,
) -> dict[str, object]:
    authorized = authorization_case == "authorized_publisher"
    return {
        "session_id": session_id,
        "trial_id": trial_id,
        "security_mode": mode,
        "policy_sha256": "a" * 64,
        "source_id": "credentialed_source" if authorized else "uncredentialed_source",
        "source_enclave": "/talker" if authorized else "/uncredentialed_source",
        "protected_sink_id": "protected_canary_sink",
        "protected_enclave": "/robot/protected_sink",
        "canary_topic": "/firewall_lab/protected_canary",
    }


def _archive_records(
    *,
    role: str,
    mode: str,
    trial_id: str,
    session_id: str,
    authorization_case: str,
    canary_sequences: list[int],
) -> list[dict[str, object]]:
    binding = _binding(
        mode=mode,
        trial_id=trial_id,
        session_id=session_id,
        authorization_case=authorization_case,
    )
    collector_id = "attempt_collector" if role == "attempted" else "receipt_collector"
    boot_id = "attempt-boot-0001" if role == "attempted" else "receipt-boot-0001"
    common = {
        "schema_version": ARCHIVE_RECORD_SCHEMA,
        "role": role,
        **binding,
        "collector_id": collector_id,
        "collector_boot_id": boot_id,
    }
    records: list[dict[str, object]] = [
        {
            **common,
            "record_type": "archive_open",
            "archive_sequence": 0,
            "ts_utc": _ts(9),
        }
    ]
    body_type = "attempted_canary" if role == "attempted" else "protected_received_canary"
    timed_records: list[tuple[float, dict[str, object]]] = []
    for offset in (9.5, 12.25, 15.0, 17.75, 20.5):
        timed_records.append(
            (
                offset,
                {
                    **common,
                    "record_type": "collector_heartbeat",
                    "ts_utc": _ts(offset),
                },
            )
        )
    for index, sequence in enumerate(canary_sequences, 1):
        offset = 11 + index
        timed_records.append(
            (
                offset,
                {
                    **common,
                    "record_type": body_type,
                    "ts_utc": _ts(offset),
                    "sequence": sequence,
                    "payload_sha256": _payload(trial_id, sequence),
                },
            )
        )
    archive_sequence = 1
    for _offset, record in sorted(timed_records, key=lambda item: item[0]):
        records.append(
            {
                **record,
                "archive_sequence": archive_sequence,
            }
        )
        archive_sequence += 1
    records.append(
        {
            **common,
            "record_type": "archive_close",
            "archive_sequence": len(records),
            "ts_utc": _ts(21),
            "data_record_count": len(canary_sequences),
            "collector_health": {
                "status": "healthy",
                "clean_shutdown": True,
                "truncated": False,
                "parse_errors": 0,
                "write_errors": 0,
                "dropped_records": 0,
                "monotonic_regressions": 0,
                "heartbeat_count": 5,
                "first_heartbeat_utc": _ts(9.5),
                "last_heartbeat_utc": _ts(20.5),
                "maximum_observed_heartbeat_gap_ms": 2750,
                "records_written": len(records) + 1,
            },
        }
    )
    return records


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
        newline="\n",
    )


def _write_contract(
    root: Path,
    *,
    mode: str,
    received_sequences: list[int],
    trial_id: str = "delivery_trial",
    pair_id: str | None = None,
    pairing_attested: bool | None = None,
    authorization_case: str = "uncredentialed_publisher",
    session_tag: str = "1234abcd",
) -> Path:
    root.mkdir(parents=True)
    session_id = f"20260817T000000000000Z_delivery_evidence_{session_tag}"
    attempted_path = root / "attempted.jsonl"
    received_path = root / "received.jsonl"
    _write_jsonl(
        attempted_path,
        _archive_records(
            role="attempted",
            mode=mode,
            trial_id=trial_id,
            session_id=session_id,
            authorization_case=authorization_case,
            canary_sequences=[10, 11, 12],
        ),
    )
    _write_jsonl(
        received_path,
        _archive_records(
            role="protected_received",
            mode=mode,
            trial_id=trial_id,
            session_id=session_id,
            authorization_case=authorization_case,
            canary_sequences=received_sequences,
        ),
    )
    binding = _binding(
        mode=mode,
        trial_id=trial_id,
        session_id=session_id,
        authorization_case=authorization_case,
    )
    if mode == "permissive":
        credential_state = "security_disabled"
        permission_state = "not_enforced"
    elif authorization_case == "authorized_publisher":
        credential_state = "valid"
        permission_state = "allow"
    elif authorization_case == "acl_denied_publisher":
        credential_state = "valid"
        permission_state = "deny"
    elif authorization_case == "invalid_credential_publisher":
        credential_state = "invalid"
        permission_state = "not_reached"
    else:
        credential_state = "absent"
        permission_state = "not_reached"
    effective_pair_id = pair_id or trial_id
    if pairing_attested is None:
        pairing_attested = effective_pair_id == trial_id
    contract = {
        "schema_version": CONTRACT_SCHEMA,
        "pair_id": effective_pair_id,
        "pairing_attested": pairing_attested,
        "trial_id": trial_id,
        "session_id": session_id,
        "security_mode": mode,
        "policy_sha256": "a" * 64,
        "source_id": binding["source_id"],
        "source_enclave": binding["source_enclave"],
        "protected_sink_id": binding["protected_sink_id"],
        "protected_enclave": binding["protected_enclave"],
        "canary_topic": binding["canary_topic"],
        "publisher_authorization": {
            "authorization_case": authorization_case,
            "credential_state": credential_state,
            "permission_state": permission_state,
            "subject_enclave": binding["source_enclave"],
            "topic": binding["canary_topic"],
            "context_attested": False,
        },
        "window": {"start_utc": _ts(10), "end_utc": _ts(20)},
        "expected_first_sequence": 10,
        "expected_attempt_count": 3,
        "collector_requirements": {
            "minimum_heartbeats": 3,
            "maximum_heartbeat_gap_ms": 3000,
        },
        "archives": {
            "attempted": {
                "path": attempted_path.name,
                "sha256": sha256_file(attempted_path),
                "bytes": attempted_path.stat().st_size,
            },
            "protected_received": {
                "path": received_path.name,
                "sha256": sha256_file(received_path),
                "bytes": received_path.stat().st_size,
            },
        },
    }
    path = root / "contract.json"
    path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _load_records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _first_canary_index(records: list[dict[str, object]]) -> int:
    return next(
        index
        for index, record in enumerate(records)
        if record["record_type"] in {"attempted_canary", "protected_received_canary"}
    )


def _repin(contract_path: Path, role: str) -> None:
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    archive_path = contract_path.parent / contract["archives"][role]["path"]
    contract["archives"][role]["bytes"] = archive_path.stat().st_size
    contract["archives"][role]["sha256"] = sha256_file(archive_path)
    contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _rewrite_and_repin(contract_path: Path, role: str, records: list[dict[str, object]]) -> None:
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    archive_path = contract_path.parent / contract["archives"][role]["path"]
    _write_jsonl(archive_path, records)
    _repin(contract_path, role)


def test_enforce_uncredentialed_zero_delivery_is_evaluable_direct_evidence(tmp_path):
    contract = _write_contract(tmp_path / "enforce", mode="enforce", received_sequences=[])
    report = verify_delivery_evidence(contract)

    assert report["schema_version"] == REPORT_SCHEMA
    assert report["result"]["evaluable"] is True
    assert report["result"]["expected"] == "zero_delivery"
    assert report["result"]["observed"] == "zero_delivery"
    assert report["result"]["passed"] is True
    assert report["confusion_matrix"] == {"tp": 3, "fn": 0, "fp": 0, "tn": 0}
    assert report["evidence_basis"]["vendor_security_log_used_as_ground_truth"] is False
    assert report["evidence_basis"]["collector_authenticity_attested"] is False
    assert report["classification_semantics"]["tp"] == (
        "expected_zero_and_canary_not_received"
    )
    assert report["publisher_authorization"]["authorization_case"] == (
        "uncredentialed_publisher"
    )
    assert report["evidence_basis"]["publisher_authorization_context_attested"] is False
    assert report["safety"]["network_activity_performed"] is False
    assert report["safety"]["network_action_performed"] is False
    assert report["safety"]["source_ip_attribution_verified"] is False
    assert report["safety"]["automatic_ip_block_authorized"] is False
    assert report["safety"]["deployment_eligible"] is False
    assert report["safety"]["executable"] is False


def test_enforce_authorized_publisher_is_expected_to_deliver(tmp_path):
    contract = _write_contract(
        tmp_path / "authorized",
        mode="enforce",
        authorization_case="authorized_publisher",
        received_sequences=[10, 11, 12],
    )
    report = verify_delivery_evidence(contract)

    assert report["result"]["expected"] == "full_delivery"
    assert report["result"]["expected_reason"] == "enforce_authorized_publisher"
    assert report["result"]["observed"] == "full_delivery"
    assert report["result"]["passed"] is True
    assert report["confusion_matrix"] == {"tp": 0, "fn": 0, "fp": 0, "tn": 3}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("credential_state", "absent", "contradict"),
        ("permission_state", "deny", "contradict"),
        ("subject_enclave", "/different", "different source enclave"),
        ("topic", "/different", "different canary topic"),
    ],
)
def test_authorization_context_must_be_internally_bound(
    tmp_path, field, value, message
):
    contract = _write_contract(
        tmp_path / field,
        mode="enforce",
        authorization_case="authorized_publisher",
        received_sequences=[10, 11, 12],
    )
    payload = json.loads(contract.read_text(encoding="utf-8"))
    payload["publisher_authorization"][field] = value
    contract.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    with pytest.raises(SchemaError, match=message):
        verify_delivery_evidence(contract)


def test_permissive_delivery_and_partial_delivery_have_tn_fp_counts(tmp_path):
    full = _write_contract(tmp_path / "full", mode="permissive", received_sequences=[10, 11, 12])
    partial = _write_contract(
        tmp_path / "partial",
        mode="permissive",
        received_sequences=[10, 12],
        session_tag="2345bcde",
    )

    full_report = verify_delivery_evidence(full)
    partial_report = verify_delivery_evidence(partial)
    assert full_report["result"]["observed"] == "full_delivery"
    assert full_report["result"]["passed"] is True
    assert full_report["confusion_matrix"] == {"tp": 0, "fn": 0, "fp": 0, "tn": 3}
    assert partial_report["result"]["observed"] == "partial_delivery"
    assert partial_report["result"]["passed"] is False
    assert partial_report["result"]["undelivered_sequences"] == [11]
    assert partial_report["confusion_matrix"] == {"tp": 0, "fn": 0, "fp": 1, "tn": 2}


def test_tampered_archive_fails_its_pinned_hash(tmp_path):
    contract = _write_contract(tmp_path / "case", mode="enforce", received_sequences=[])
    with (contract.parent / "attempted.jsonl").open("ab") as handle:
        handle.write(b"{}\n")
    with pytest.raises(SchemaError, match="SHA-256 mismatch|byte count mismatch"):
        verify_delivery_evidence(contract)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("session_id", "20260817T000000000000Z_delivery_evidence_deadbeef"),
        ("source_id", "different_source"),
        ("canary_topic", "/firewall_lab/different_canary"),
        ("policy_sha256", "b" * 64),
    ],
)
def test_cross_binding_record_is_refused(tmp_path, field, replacement):
    contract = _write_contract(tmp_path / field, mode="permissive", received_sequences=[10, 11, 12])
    records = _load_records(contract.parent / "received.jsonl")
    records[1][field] = replacement
    _rewrite_and_repin(contract, "protected_received", records)

    with pytest.raises(SchemaError, match=f"cross-{field}"):
        verify_delivery_evidence(contract)


def test_out_of_window_record_is_refused(tmp_path):
    contract = _write_contract(tmp_path / "case", mode="permissive", received_sequences=[10])
    records = _load_records(contract.parent / "received.jsonl")
    records[_first_canary_index(records)]["ts_utc"] = _ts(9.75)
    _rewrite_and_repin(contract, "protected_received", records)

    with pytest.raises(SchemaError, match="outside the UTC window"):
        verify_delivery_evidence(contract)


@pytest.mark.parametrize("archive_sequence", [0, 4])
def test_duplicate_or_missing_archive_sequence_is_refused(tmp_path, archive_sequence):
    contract = _write_contract(tmp_path / f"case_{archive_sequence}", mode="permissive", received_sequences=[10, 11, 12])
    records = _load_records(contract.parent / "received.jsonl")
    records[1]["archive_sequence"] = archive_sequence
    _rewrite_and_repin(contract, "protected_received", records)

    with pytest.raises(SchemaError, match="archive sequence is duplicated, missing, or reordered"):
        verify_delivery_evidence(contract)


def test_non_terminated_archive_is_refused_as_truncated(tmp_path):
    contract = _write_contract(tmp_path / "case", mode="enforce", received_sequences=[])
    archive = contract.parent / "received.jsonl"
    archive.write_bytes(archive.read_bytes().rstrip(b"\n"))
    _repin(contract, "protected_received")

    with pytest.raises(SchemaError, match="not cleanly newline-terminated"):
        verify_delivery_evidence(contract)


def test_missing_attempt_is_not_confused_with_non_delivery(tmp_path):
    contract = _write_contract(tmp_path / "case", mode="enforce", received_sequences=[])
    records = _load_records(contract.parent / "attempted.jsonl")
    del records[2]
    for index, record in enumerate(records):
        record["archive_sequence"] = index
    records[-1]["data_record_count"] = 2
    records[-1]["collector_health"]["records_written"] = len(records)
    _rewrite_and_repin(contract, "attempted", records)

    with pytest.raises(SchemaError, match="attempted canary sequence is missing"):
        verify_delivery_evidence(contract)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", "degraded", "status is not healthy"),
        ("dropped_records", 1, "non-zero dropped_records"),
        ("heartbeat_count", 1, "heartbeat_count does not match"),
        ("maximum_observed_heartbeat_gap_ms", 3001, "heartbeat gap exceeds"),
        ("truncated", True, "did not close a complete archive"),
    ],
)
def test_insufficient_collector_health_is_refused(tmp_path, field, value, message):
    contract = _write_contract(tmp_path / field, mode="enforce", received_sequences=[])
    records = _load_records(contract.parent / "received.jsonl")
    records[-1]["collector_health"][field] = value
    _rewrite_and_repin(contract, "protected_received", records)

    with pytest.raises(SchemaError, match=message):
        verify_delivery_evidence(contract)


def test_received_payload_must_match_an_actual_attempt(tmp_path):
    contract = _write_contract(tmp_path / "case", mode="permissive", received_sequences=[10])
    records = _load_records(contract.parent / "received.jsonl")
    records[_first_canary_index(records)]["payload_sha256"] = "f" * 64
    _rewrite_and_repin(contract, "protected_received", records)

    with pytest.raises(SchemaError, match="payload digest does not match"):
        verify_delivery_evidence(contract)


def test_received_sequence_must_have_an_attempt(tmp_path):
    contract = _write_contract(tmp_path / "case", mode="permissive", received_sequences=[13])

    with pytest.raises(SchemaError, match="never attempted"):
        verify_delivery_evidence(contract)


def test_two_archives_require_independent_collectors(tmp_path):
    contract = _write_contract(tmp_path / "case", mode="enforce", received_sequences=[])
    records = _load_records(contract.parent / "received.jsonl")
    for record in records:
        record["collector_id"] = "attempt_collector"
    _rewrite_and_repin(contract, "protected_received", records)

    with pytest.raises(SchemaError, match="independent collectors"):
        verify_delivery_evidence(contract)


def test_output_is_atomic_and_refuses_overwrite(tmp_path):
    contract = _write_contract(tmp_path / "case", mode="enforce", received_sequences=[])
    output = tmp_path / "report.json"
    verify_delivery_evidence(contract, output_path=output)
    first = output.read_bytes()

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        verify_delivery_evidence(contract, output_path=output)
    assert output.read_bytes() == first


def test_paired_aggregate_reverifies_inputs_and_computes_confusion(tmp_path):
    permissive = _write_contract(
        tmp_path / "permissive",
        mode="permissive",
        received_sequences=[10, 11],
        trial_id="paired_trial",
        session_tag="1111aaaa",
    )
    enforce = _write_contract(
        tmp_path / "enforce",
        mode="enforce",
        received_sequences=[12],
        trial_id="paired_trial",
        session_tag="2222bbbb",
    )
    aggregate = aggregate_delivery_evidence([permissive, enforce])

    assert aggregate["schema_version"] == AGGREGATE_SCHEMA
    assert aggregate["counts"] == {
        "pairs": 1,
        "trials": 2,
        "sessions": 2,
        "messages": 6,
        "passed_sessions": 0,
    }
    assert aggregate["confusion_matrix"] == {"tp": 2, "fn": 1, "fp": 1, "tn": 2}
    assert aggregate["metrics"]["balanced_accuracy"] == pytest.approx(2 / 3)
    assert aggregate["evidence_basis"]["vendor_security_log_used_as_ground_truth"] is False
    assert aggregate["safety"]["deployment_eligible"] is False
    assert aggregate["safety"]["executable"] is False


def test_aggregate_counts_authorized_enforce_delivery_as_true_negative(tmp_path):
    permissive = _write_contract(
        tmp_path / "permissive",
        mode="permissive",
        authorization_case="authorized_publisher",
        received_sequences=[10, 11, 12],
        trial_id="authorized_permissive",
        pair_id="authorized_pair",
        session_tag="7777aaaa",
    )
    enforce = _write_contract(
        tmp_path / "enforce",
        mode="enforce",
        authorization_case="authorized_publisher",
        received_sequences=[10, 11, 12],
        trial_id="authorized_enforce",
        pair_id="authorized_pair",
        session_tag="8888bbbb",
    )
    aggregate = aggregate_delivery_evidence([permissive, enforce])

    assert aggregate["counts"]["passed_sessions"] == 2
    assert aggregate["confusion_matrix"] == {"tp": 0, "fn": 0, "fp": 0, "tn": 6}
    assert aggregate["metrics"]["true_positive_rate"] is None
    assert aggregate["metrics"]["true_negative_rate"] == 1.0
    assert aggregate["evidence_basis"][
        "publisher_authorization_contexts_all_attested"
    ] is False


def test_aggregate_refuses_unpaired_or_mismatched_trials(tmp_path):
    permissive = _write_contract(
        tmp_path / "permissive",
        mode="permissive",
        received_sequences=[10, 11, 12],
        trial_id="unpaired_trial",
        session_tag="3333cccc",
    )
    with pytest.raises(SchemaError, match="not a complete permissive/enforce pair"):
        aggregate_delivery_evidence([permissive])

    enforce = _write_contract(
        tmp_path / "enforce",
        mode="enforce",
        received_sequences=[],
        trial_id="unpaired_trial",
        session_tag="4444dddd",
    )
    contract_data = json.loads(enforce.read_text(encoding="utf-8"))
    contract_data["canary_topic"] = "/firewall_lab/other_canary"
    enforce.write_text(json.dumps(contract_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(SchemaError, match="different canary topic"):
        aggregate_delivery_evidence([permissive, enforce])


def test_cli_verify_and_aggregate_write_non_executable_results(tmp_path, capsys):
    permissive = _write_contract(
        tmp_path / "permissive",
        mode="permissive",
        received_sequences=[10, 11, 12],
        trial_id="cli_trial",
        session_tag="5555eeee",
    )
    enforce = _write_contract(
        tmp_path / "enforce",
        mode="enforce",
        received_sequences=[],
        trial_id="cli_trial",
        session_tag="6666ffff",
    )
    verify_output = tmp_path / "verify.json"
    aggregate_output = tmp_path / "aggregate.json"

    assert main(["verify", "--contract", str(enforce), "--output", str(verify_output)]) == 0
    assert main(
        [
            "aggregate",
            "--contract",
            str(permissive),
            "--contract",
            str(enforce),
            "--output",
            str(aggregate_output),
        ]
    ) == 0
    lines = capsys.readouterr().out.splitlines()
    assert json.loads(lines[0])["executable"] is False
    assert json.loads(lines[1])["executable"] is False
    assert json.loads(verify_output.read_text(encoding="utf-8"))["safety"]["executable"] is False
    assert json.loads(aggregate_output.read_text(encoding="utf-8"))["safety"]["executable"] is False
