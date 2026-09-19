#!/usr/bin/env python3
"""Migrate sealed canary archives into v2 contracts and verify them offline.

The source directory is read-only. Contracts, copied archives, reports and the
aggregate are published into a new output directory that must not already
exist. Old v1 archives do not contain a trustworthy pair identifier, so a
mapping file is mandatory whenever trial_id is not already shared by both
security modes; directory order is never used to invent a pair.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall_lab.schema import SchemaError, require_identifier, sha256_file  # noqa: E402
from firewall_lab.sros2_delivery_evidence import (  # noqa: E402
    CONTRACT_SCHEMA,
    aggregate_delivery_evidence,
    verify_delivery_evidence,
)

PAIR_MAP_SCHEMA = "sros2-firewall-direct-delivery-pair-map/v1"


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _pair_map(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "pairs"}:
        raise SchemaError("pair map has unexpected keys")
    if raw["schema_version"] != PAIR_MAP_SCHEMA or not isinstance(raw["pairs"], dict):
        raise SchemaError("unsupported pair map")
    result: dict[str, str] = {}
    for trial_id, pair_id in raw["pairs"].items():
        result[require_identifier(trial_id, "pair map trial_id")] = require_identifier(
            pair_id, "pair map pair_id"
        )
    return result


def _authorization(binding: dict) -> tuple[str, str, str]:
    source_id = binding.get("source_id")
    mode = binding.get("security_mode")
    if source_id == "credentialed_source":
        case = "authorized_publisher"
    elif source_id in {"uncredentialed_source", "unauthorized_canary_source"}:
        case = "uncredentialed_publisher"
    else:
        raise SchemaError(f"unmapped canary source_id: {source_id!r}")
    if mode == "permissive":
        return case, "security_disabled", "not_enforced"
    if mode != "enforce":
        raise SchemaError(f"invalid canary security_mode: {mode!r}")
    if case == "authorized_publisher":
        return case, "valid", "allow"
    return case, "absent", "not_reached"


def _build_contract(
    source_dir: Path,
    destination: Path,
    *,
    pair_ids: dict[str, str],
    current_policy_sha256: str,
) -> Path:
    attempted_source = source_dir / "attempted.jsonl"
    received_source = source_dir / "protected_received.jsonl"
    if not attempted_source.is_file() or not received_source.is_file():
        raise SchemaError(f"archive pair missing below {source_dir}")
    attempted_rows = _records(attempted_source)
    received_rows = _records(received_source)
    if not attempted_rows or not received_rows:
        raise SchemaError(f"empty archive below {source_dir}")
    binding = attempted_rows[0]
    trial_id = require_identifier(binding.get("trial_id"), "trial_id")
    pair_id = pair_ids.get(trial_id, trial_id)
    if binding.get("policy_sha256") != current_policy_sha256:
        raise SchemaError(f"archive policy drift for {trial_id}")
    authorization_case, credential_state, permission_state = _authorization(binding)

    attempted_canaries = [
        row for row in attempted_rows if row.get("record_type") == "attempted_canary"
    ]
    if not attempted_canaries:
        raise SchemaError(f"no attempted canary records for {trial_id}")
    attempted_sequences = [int(row["sequence"]) for row in attempted_canaries]
    heartbeats = {
        "attempted": [
            row["ts_utc"]
            for row in attempted_rows
            if row.get("record_type") == "collector_heartbeat"
        ],
        "protected_received": [
            row["ts_utc"]
            for row in received_rows
            if row.get("record_type") == "collector_heartbeat"
        ],
    }
    if any(len(values) < 2 for values in heartbeats.values()):
        raise SchemaError(f"insufficient heartbeat evidence for {trial_id}")

    destination.mkdir(parents=True, exist_ok=False)
    attempted = destination / attempted_source.name
    received = destination / received_source.name
    shutil.copyfile(attempted_source, attempted)
    shutil.copyfile(received_source, received)
    contract = {
        "schema_version": CONTRACT_SCHEMA,
        "pair_id": pair_id,
        "pairing_attested": trial_id not in pair_ids,
        "trial_id": trial_id,
        "session_id": binding["session_id"],
        "security_mode": binding["security_mode"],
        "policy_sha256": binding["policy_sha256"],
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
        "window": {
            "start_utc": max(
                heartbeats["attempted"][0], heartbeats["protected_received"][0]
            ),
            "end_utc": min(
                heartbeats["attempted"][-1], heartbeats["protected_received"][-1]
            ),
        },
        "expected_first_sequence": min(attempted_sequences),
        "expected_attempt_count": len(attempted_sequences),
        "collector_requirements": {
            "minimum_heartbeats": 2,
            "maximum_heartbeat_gap_ms": 60_000,
        },
        "archives": {
            "attempted": {
                "path": attempted.name,
                "sha256": sha256_file(attempted),
                "bytes": attempted.stat().st_size,
            },
            "protected_received": {
                "path": received.name,
                "sha256": sha256_file(received),
                "bytes": received.stat().st_size,
            },
        },
    }
    contract_path = destination / "contract_v2.json"
    contract_path.write_text(
        json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    verify_delivery_evidence(contract_path, output_path=destination / "report_v2.json")
    return contract_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--pair-map", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.output_dir.exists() or args.output_dir.is_symlink():
        raise FileExistsError(f"refusing to reuse output directory: {args.output_dir}")
    source_dirs = sorted(path for path in args.source_root.iterdir() if path.is_dir())
    if not source_dirs:
        raise SchemaError("source root contains no canary archive directories")
    pair_ids = _pair_map(args.pair_map)
    current_policy_sha256 = sha256_file(
        args.workspace / "firewall_lab/action_policy.json"
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    contracts: list[Path] = []
    for source_dir in source_dirs:
        contracts.append(
            _build_contract(
                source_dir,
                args.output_dir / source_dir.name,
                pair_ids=pair_ids,
                current_policy_sha256=current_policy_sha256,
            )
        )
    aggregate = aggregate_delivery_evidence(
        contracts, output_path=args.output_dir / "aggregate_v2.json"
    )
    print(
        json.dumps(
            {
                "output": str(args.output_dir),
                "pairs": aggregate["counts"]["pairs"],
                "sessions": aggregate["counts"]["sessions"],
                "passed_sessions": aggregate["counts"]["passed_sessions"],
                "authorization_contexts_all_attested": aggregate["evidence_basis"][
                    "publisher_authorization_contexts_all_attested"
                ],
                "all_pairings_attested": aggregate["evidence_basis"][
                    "all_pairings_attested"
                ],
                "deployment_eligible": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
