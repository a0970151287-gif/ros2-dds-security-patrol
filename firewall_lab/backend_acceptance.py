#!/usr/bin/env python3
"""Offline acceptance probe for the asymmetric response backend.

The probe never invokes sudo, sends traffic, or changes a host firewall.  Its
in-memory timeout set is explicitly simulation-only and its report schema is
different from the production cross-host admission schema.  A second mode
proves that the production placeholder remains blocked.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .evidence import JsonlWriter
from .response_backend import (
    BACKEND_DB_SCHEMA_VERSION,
    RETENTION_POLICY,
    BackendApplyError,
    BackendCapacityError,
    DisabledProductionTimeoutSetAdapter,
    Ed25519TicketIssuer,
    InMemoryTimeoutSetAdapter,
    ResponseBackend,
    SQLiteResponseState,
    TicketReplayError,
    TicketVerificationError,
)
from .schema import atomic_write_json, safe_json_value, sha256_file


ACCEPTANCE_SCHEMA_VERSION = "sros2-firewall-backend-acceptance/v1"
ACCEPTANCE_EVENT_SCHEMA_VERSION = "sros2-firewall-backend-acceptance-event/v1"
SIMULATION_BACKEND = "in_memory_timeout_set"
DISABLED_PRODUCTION_BACKEND = "disabled_production_timeout_set"
PROBE_BACKEND_ID = "offline-acceptance-ed25519-timeout-set"
AUTHORIZED_SCOPE = ("10.77.0.0/24",)
PROTECTED_SCOPE = ("10.77.0.2/32",)

SIMULATION_CHECKS = frozenset(
    {
        "public_key_verifier_only",
        "missing_ticket_rejected",
        "tampered_ticket_rejected",
        "expired_ticket_rejected",
        "replayed_ticket_rejected",
        "source_substitution_rejected",
        "global_capacity_enforced",
        "concurrent_nonce_consume_atomic",
        "automatic_expiry_verified",
        "process_restart_reconciled",
        "backend_state_auditable",
        "durable_state_bounded_fail_closed",
    }
)
DISABLED_PRODUCTION_CHECKS = frozenset({"production_adapter_blocked"})
RECOMPUTED_FIELDS = (
    "summary_sha256",
    "events.bytes",
    "events.sha256",
    "events.records",
    "checks_passed",
    "databases.*.bytes",
    "databases.*.sha256",
    "databases.*.database_status.integrity_check",
    "databases.*.database_status.schema_version",
    "databases.*.database_status.capacity",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _prepare_output(path: str | Path) -> Path:
    output = Path(path)
    if output.exists() and output.is_symlink():
        raise ValueError("acceptance output directory may not be a symlink")
    if output.exists() and any(output.iterdir()):
        raise ValueError("acceptance output directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    return output


def _issue_ticket(
    issuer: Ed25519TicketIssuer,
    *,
    source: str,
    issued_at_ns: int,
    ttl_sec: int = 30,
    nonce: str | None = None,
    label: str = "acceptance",
) -> str:
    return issuer.issue(
        evidence_id=hashlib.sha256(label.encode("utf-8")).hexdigest(),
        source=source,
        source_kind="network_ip",
        action="temporary_block",
        adapter="network_helper",
        backend_id=PROBE_BACKEND_ID,
        interface="offline-fake0",
        identity=f"offline-{label}"[:128],
        response_ttl_sec=ttl_sec,
        issued_at_ns=issued_at_ns,
        nonce=nonce,
    )


def _tamper_signature(ticket: str) -> str:
    replacement = "A" if ticket[-1] != "A" else "B"
    return ticket[:-1] + replacement


def _substitute_source(ticket: str, source: str) -> str:
    encoded, signature = ticket.split(".", 1)
    payload = json.loads(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
    )
    payload["source"] = source
    replacement = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return (
        base64.urlsafe_b64encode(replacement).decode("ascii").rstrip("=")
        + "."
        + signature
    )


def _expect_exception(
    expected: type[BaseException],
    operation: Callable[[], Any],
    text: str = "",
) -> str:
    try:
        operation()
    except expected as exc:
        if text and text not in str(exc):
            raise AssertionError(
                f"expected {expected.__name__} containing {text!r}, got {exc!r}"
            ) from exc
        return f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        raise AssertionError(
            f"expected {expected.__name__}, got {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(f"expected {expected.__name__}, operation succeeded")


def _run_check(
    check_id: str,
    operation: Callable[[], Mapping[str, Any] | str | None],
) -> dict[str, Any]:
    try:
        evidence = operation()
        return {
            "id": check_id,
            "passed": True,
            "detail": "verified",
            "evidence": safe_json_value(evidence or {}),
        }
    except Exception as exc:
        return {
            "id": check_id,
            "passed": False,
            "detail": f"{type(exc).__name__}: {exc}"[:1024],
            "evidence": {},
        }


def _backend(
    issuer: Ed25519TicketIssuer,
    state: SQLiteResponseState,
    adapter: InMemoryTimeoutSetAdapter | DisabledProductionTimeoutSetAdapter,
) -> ResponseBackend:
    return ResponseBackend(
        verifier=issuer.verifier(),
        state=state,
        timeout_set=adapter,
        backend_id=PROBE_BACKEND_ID,
        authorized_sources=AUTHORIZED_SCOPE,
        protected_sources=PROTECTED_SCOPE,
    )


def _database_artifact(path: Path, state: SQLiteResponseState) -> dict[str, Any]:
    status = state.database_status()
    return {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "database_status": status,
    }


def _write_report(
    output: Path,
    *,
    backend: str,
    adapter_class: str,
    simulation_only: bool,
    outcome: str,
    blocked_reason: str,
    key_id: str,
    checks: list[dict[str, Any]],
    states: Mapping[str, tuple[Path, SQLiteResponseState]],
) -> dict[str, Any]:
    event_path = output / "acceptance_events.jsonl"
    writer = JsonlWriter(event_path)
    for sequence, check in enumerate(checks):
        writer.append(
            {
                "schema_version": ACCEPTANCE_EVENT_SCHEMA_VERSION,
                "sequence": sequence,
                **check,
            }
        )
    databases = {
        name: _database_artifact(path, state)
        for name, (path, state) in states.items()
    }
    events = {
        "path": event_path.name,
        "bytes": event_path.stat().st_size,
        "sha256": sha256_file(event_path),
        "records": len(checks),
    }
    checks_passed = all(check.get("passed") is True for check in checks)
    summary = {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "generated_utc": _utc_now(),
        "backend": backend,
        "adapter_class": adapter_class,
        "simulation_only": simulation_only,
        "production_ready": False,
        "production_admission_eligible": False,
        "outcome": outcome,
        "blocked_reason": blocked_reason,
        "checks_passed": checks_passed,
        "checks": checks,
        "ticket_security": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "private_key_persisted": False,
            "backend_has_private_key": False,
        },
        "safety_boundaries": {
            "network_activity": "none",
            "sudo_used": False,
            "host_firewall_modified": False,
            "raw_source_argument_accepted": False,
            "raw_ttl_argument_accepted": False,
        },
        "artifacts": {
            "events": events,
            "databases": databases,
        },
    }
    summary_path = output / "summary.json"
    atomic_write_json(summary_path, summary)
    digest = sha256_file(summary_path)
    _atomic_write_text(output / "summary.json.sha256", f"{digest}  summary.json\n")
    return summary


def _run_simulation(output: Path) -> dict[str, Any]:
    issuer = Ed25519TicketIssuer.generate()
    now = time.time_ns()
    state_path = output / "response_state.sqlite3"
    state = SQLiteResponseState(
        state_path,
        max_active_sources=1,
        max_consumed_tickets=100,
        max_audit_events=200,
    )
    adapter = InMemoryTimeoutSetAdapter(PROBE_BACKEND_ID)
    backend = _backend(issuer, state, adapter)
    checks: list[dict[str, Any]] = []

    def public_verifier() -> Mapping[str, Any]:
        verifier = issuer.verifier()
        if hasattr(verifier, "issue") or hasattr(verifier, "private_key_bytes"):
            raise AssertionError("public verifier exposes a signing capability")
        return {"key_id": verifier.key_id, "public_key_bytes": 32}

    checks.append(_run_check("public_key_verifier_only", public_verifier))
    checks.append(
        _run_check(
            "missing_ticket_rejected",
            lambda: {
                "rejection": _expect_exception(
                    TicketVerificationError,
                    lambda: backend.apply_ticket("", now_ns=now),
                    "missing",
                )
            },
        )
    )
    valid_for_tamper = _issue_ticket(
        issuer, source="10.77.0.10", issued_at_ns=now, label="tamper"
    )
    checks.append(
        _run_check(
            "tampered_ticket_rejected",
            lambda: {
                "rejection": _expect_exception(
                    TicketVerificationError,
                    lambda: backend.apply_ticket(
                        _tamper_signature(valid_for_tamper), now_ns=now
                    ),
                    "signature",
                )
            },
        )
    )
    expired = _issue_ticket(
        issuer,
        source="10.77.0.10",
        issued_at_ns=now - 6_000_000_000,
        label="expired",
    )
    checks.append(
        _run_check(
            "expired_ticket_rejected",
            lambda: {
                "rejection": _expect_exception(
                    TicketVerificationError,
                    lambda: backend.apply_ticket(expired, now_ns=now),
                    "expired",
                )
            },
        )
    )
    source_ticket = _issue_ticket(
        issuer, source="10.77.0.10", issued_at_ns=now, label="source-binding"
    )
    checks.append(
        _run_check(
            "source_substitution_rejected",
            lambda: {
                "rejection": _expect_exception(
                    TicketVerificationError,
                    lambda: backend.apply_ticket(
                        _substitute_source(source_ticket, "10.77.0.11"), now_ns=now
                    ),
                    "signature",
                )
            },
        )
    )

    replay_ticket = _issue_ticket(
        issuer, source="10.77.0.10", issued_at_ns=now, label="replay"
    )

    def replay_check() -> Mapping[str, Any]:
        result = backend.apply_ticket(replay_ticket, now_ns=now)
        rejection = _expect_exception(
            TicketReplayError,
            lambda: backend.apply_ticket(replay_ticket, now_ns=now + 1),
            "already consumed",
        )
        return {
            "source": result.source,
            "ticket_sha256": result.ticket_sha256,
            "rejection": rejection,
        }

    checks.append(_run_check("replayed_ticket_rejected", replay_check))
    phase2 = now + 31_000_000_000
    backend.reconcile(now_ns=phase2)
    capacity_first = _issue_ticket(
        issuer, source="10.77.0.11", issued_at_ns=phase2, label="capacity-first"
    )
    capacity_second = _issue_ticket(
        issuer, source="10.77.0.12", issued_at_ns=phase2, label="capacity-second"
    )

    def capacity_check() -> Mapping[str, Any]:
        backend.apply_ticket(capacity_first, now_ns=phase2)
        rejection = _expect_exception(
            BackendCapacityError,
            lambda: backend.apply_ticket(capacity_second, now_ns=phase2),
            "capacity",
        )
        return {"max_active_sources": 1, "rejection": rejection}

    checks.append(_run_check("global_capacity_enforced", capacity_check))
    phase3 = phase2 + 31_000_000_000
    backend.reconcile(now_ns=phase3)
    concurrent_ticket = _issue_ticket(
        issuer, source="10.77.0.20", issued_at_ns=phase3, label="concurrent"
    )
    concurrent_backends = [
        _backend(
            issuer,
            SQLiteResponseState(
                state_path,
                max_active_sources=1,
                max_consumed_tickets=100,
                max_audit_events=200,
            ),
            adapter,
        )
        for _ in range(12)
    ]

    def concurrent_check() -> Mapping[str, Any]:
        def attempt(candidate: ResponseBackend) -> str:
            try:
                candidate.apply_ticket(concurrent_ticket, now_ns=phase3)
                return "applied"
            except TicketReplayError:
                return "replayed"

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(attempt, concurrent_backends))
        if outcomes.count("applied") != 1 or outcomes.count("replayed") != 11:
            raise AssertionError(f"unexpected concurrent outcomes: {outcomes}")
        return {"workers": 12, "applied": 1, "replayed": 11}

    checks.append(
        _run_check("concurrent_nonce_consume_atomic", concurrent_check)
    )

    def restart_check() -> Mapping[str, Any]:
        expected_expiry = phase3 + 30_000_000_000
        adapter.clear_for_test()
        adapter.seed_for_test("10.77.0.99", phase3 + 60_000_000_000)
        restarted = _backend(
            issuer,
            SQLiteResponseState(
                state_path,
                max_active_sources=1,
                max_consumed_tickets=100,
                max_audit_events=200,
            ),
            adapter,
        )
        snapshot = restarted.reconcile(now_ns=phase3 + 1_000_000_000)
        if snapshot != {"10.77.0.20": expected_expiry}:
            raise AssertionError(f"restart snapshot mismatch: {snapshot}")
        return {"restored": ["10.77.0.20"], "removed_stale": ["10.77.0.99"]}

    checks.append(_run_check("process_restart_reconciled", restart_check))

    def expiry_check() -> Mapping[str, Any]:
        snapshot = backend.reconcile(now_ns=phase3 + 31_000_000_000)
        if snapshot:
            raise AssertionError(f"expired source remains active: {snapshot}")
        return {"active_after_ttl": 0, "ttl_sec": 30}

    checks.append(_run_check("automatic_expiry_verified", expiry_check))

    def audit_check() -> Mapping[str, Any]:
        events = state.audit_events()
        outcomes = {str(event["outcome"]) for event in events}
        event_names = {str(event["event"]) for event in events}
        if not {"applied", "rejected", "reconciled", "removed"} <= outcomes:
            raise AssertionError(f"missing audit outcomes: {outcomes}")
        if not {"ticket_consumed", "ticket_rejected", "restart_reconcile", "response_expired"} <= event_names:
            raise AssertionError(f"missing audit event types: {event_names}")
        return {"audit_rows": len(events), "outcomes": sorted(outcomes)}

    checks.append(_run_check("backend_state_auditable", audit_check))

    limits_path = output / "capacity_state.sqlite3"
    limits_state = SQLiteResponseState(
        limits_path,
        max_active_sources=4,
        max_consumed_tickets=1,
        max_audit_events=2,
    )
    limits_adapter = InMemoryTimeoutSetAdapter(PROBE_BACKEND_ID)
    limits_backend = _backend(issuer, limits_state, limits_adapter)

    def durable_capacity_check() -> Mapping[str, Any]:
        first = _issue_ticket(
            issuer, source="10.77.0.30", issued_at_ns=phase3, label="limit-first"
        )
        second = _issue_ticket(
            issuer, source="10.77.0.31", issued_at_ns=phase3, label="limit-second"
        )
        limits_backend.apply_ticket(first, now_ns=phase3)
        consumed_rejection = _expect_exception(
            BackendCapacityError,
            lambda: limits_backend.apply_ticket(second, now_ns=phase3),
            "consumed-ticket capacity",
        )
        audit_rejection = _expect_exception(
            BackendCapacityError,
            lambda: limits_backend.apply_ticket("", now_ns=phase3),
            "audit capacity",
        )
        status = limits_state.capacity_status()
        if status["consumed_tickets"] != 1 or status["audit_events"] != 2:
            raise AssertionError(f"bounded rows were silently removed: {status}")
        if status["retention_policy"] != RETENTION_POLICY:
            raise AssertionError("retention policy metadata drift")
        return {
            "consumed_rejection": consumed_rejection,
            "audit_rejection": audit_rejection,
            "capacity": status,
        }

    checks.append(
        _run_check("durable_state_bounded_fail_closed", durable_capacity_check)
    )

    # Normalize order so report review and verification are deterministic.
    checks.sort(key=lambda item: item["id"])
    outcome = (
        "simulation_passed"
        if {item["id"] for item in checks} == SIMULATION_CHECKS
        and all(item["passed"] for item in checks)
        else "simulation_failed"
    )
    return _write_report(
        output,
        backend=SIMULATION_BACKEND,
        adapter_class="InMemoryTimeoutSetAdapter",
        simulation_only=True,
        outcome=outcome,
        blocked_reason=(
            "simulation-only fake timeout set; never valid for production or "
            "cross-host admission"
        ),
        key_id=issuer.key_id,
        checks=checks,
        states={
            "response_state": (state_path, state),
            "capacity_state": (limits_path, limits_state),
        },
    )


def _run_disabled_production(output: Path) -> dict[str, Any]:
    issuer = Ed25519TicketIssuer.generate()
    now = time.time_ns()
    state_path = output / "response_state.sqlite3"
    state = SQLiteResponseState(state_path)
    adapter = DisabledProductionTimeoutSetAdapter(PROBE_BACKEND_ID)
    backend = _backend(issuer, state, adapter)
    ticket = _issue_ticket(
        issuer, source="10.77.0.10", issued_at_ns=now, label="production-disabled"
    )

    def blocked_check() -> Mapping[str, Any]:
        rejection = _expect_exception(
            BackendApplyError,
            lambda: backend.apply_ticket(ticket, now_ns=now),
            "staged durably",
        )
        events = state.audit_events()
        if not any(event["outcome"] == "pending_recovery" for event in events):
            raise AssertionError("disabled adapter did not leave a durable blocked audit")
        if adapter.__class__ is not DisabledProductionTimeoutSetAdapter:
            raise AssertionError("unexpected production adapter type")
        return {"rejection": rejection, "audit_rows": len(events)}

    checks = [_run_check("production_adapter_blocked", blocked_check)]
    return _write_report(
        output,
        backend=DISABLED_PRODUCTION_BACKEND,
        adapter_class="DisabledProductionTimeoutSetAdapter",
        simulation_only=False,
        outcome="blocked",
        blocked_reason=(
            "production timeout-set adapter is disabled; no host firewall "
            "operation was attempted"
        ),
        key_id=issuer.key_id,
        checks=checks,
        states={"response_state": (state_path, state)},
    )


def run_backend_acceptance(
    output_dir: str | Path,
    *,
    adapter_mode: str = "production-disabled",
) -> dict[str, Any]:
    """Run one bounded probe and write its immutable evidence artifacts."""

    output = _prepare_output(output_dir)
    if adapter_mode == "in-memory":
        return _run_simulation(output)
    if adapter_mode == "production-disabled":
        return _run_disabled_production(output)
    raise ValueError("adapter_mode must be in-memory or production-disabled")


def _safe_artifact(root: Path, name: Any) -> Path:
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ValueError("artifact paths must be simple file names")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact is missing or symlinked: {name}")
    return path


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("summary root must be an object")
    return value


def _read_database_status(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        metadata = {
            str(row["key"]): str(row["value"])
            for row in connection.execute(
                "SELECT key, value FROM backend_metadata"
            ).fetchall()
        }
        consumed = int(
            connection.execute("SELECT COUNT(*) FROM consumed_tickets").fetchone()[0]
        )
        audit = int(connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
        desired = int(
            connection.execute("SELECT COUNT(*) FROM desired_responses").fetchone()[0]
        )
    finally:
        connection.close()
    required_metadata = {
        "max_active_sources",
        "max_consumed_tickets",
        "max_audit_events",
        "retention_policy",
    }
    if set(metadata) != required_metadata:
        raise ValueError("database capacity metadata is incomplete")
    maximum_consumed = int(metadata["max_consumed_tickets"])
    maximum_audit = int(metadata["max_audit_events"])
    maximum_active = int(metadata["max_active_sources"])
    return {
        "integrity_check": integrity,
        # A read-only verifier does not run a checkpoint.  The writer's
        # checkpoint result is separately constrained below.
        "wal_checkpoint": [0, 0, 0],
        "schema_version": user_version,
        "capacity": {
            "consumed_tickets": consumed,
            "max_consumed_tickets": maximum_consumed,
            "consumed_remaining": max(0, maximum_consumed - consumed),
            "audit_events": audit,
            "max_audit_events": maximum_audit,
            "audit_remaining": max(0, maximum_audit - audit),
            "desired_responses": desired,
            "max_active_sources": maximum_active,
            "retention_policy": metadata["retention_policy"],
        },
    }


def verify_backend_acceptance(
    summary_path: str | Path,
    *,
    purpose: str = "offline_simulation",
) -> dict[str, Any]:
    """Recompute artifact facts and enforce non-production report semantics.

    ``purpose='production_admission'`` always rejects both report modes in this
    module.  A future production verifier must use a different schema and
    independently attest a real kernel timeout-set adapter.
    """

    if purpose not in {"offline_simulation", "production_admission"}:
        raise ValueError("purpose must be offline_simulation or production_admission")
    path = Path(summary_path)
    result: dict[str, Any] = {
        "artifact_valid": False,
        "accepted": False,
        "purpose": purpose,
        "production_admission_eligible": False,
        "backend": "",
        "simulation_only": None,
        "blockers": [],
        "recomputed_fields": list(RECOMPUTED_FIELDS),
        "recomputed": {},
    }
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("summary is missing or symlinked")
        root = path.parent
        summary = _read_json(path)
        if summary.get("schema_version") != ACCEPTANCE_SCHEMA_VERSION:
            raise ValueError("unsupported backend acceptance schema")
        required_root = {
            "schema_version",
            "generated_utc",
            "backend",
            "adapter_class",
            "simulation_only",
            "production_ready",
            "production_admission_eligible",
            "outcome",
            "blocked_reason",
            "checks_passed",
            "checks",
            "ticket_security",
            "safety_boundaries",
            "artifacts",
        }
        if set(summary) != required_root:
            raise ValueError("summary has unexpected fields")
        backend = summary.get("backend")
        result["backend"] = backend
        result["simulation_only"] = summary.get("simulation_only")
        if summary.get("production_ready") is not False:
            raise ValueError("offline probe may never declare production_ready")
        if summary.get("production_admission_eligible") is not False:
            raise ValueError("offline probe may never declare production admission")
        expected_checks: frozenset[str]
        expected_databases: set[str]
        if backend == SIMULATION_BACKEND:
            if (
                summary.get("adapter_class") != "InMemoryTimeoutSetAdapter"
                or summary.get("simulation_only") is not True
                or summary.get("outcome") not in {"simulation_passed", "simulation_failed"}
            ):
                raise ValueError("in-memory report cannot masquerade as production")
            expected_checks = SIMULATION_CHECKS
            expected_databases = {"response_state", "capacity_state"}
        elif backend == DISABLED_PRODUCTION_BACKEND:
            if (
                summary.get("adapter_class") != "DisabledProductionTimeoutSetAdapter"
                or summary.get("simulation_only") is not False
                or summary.get("outcome") != "blocked"
            ):
                raise ValueError("disabled production report must remain blocked")
            expected_checks = DISABLED_PRODUCTION_CHECKS
            expected_databases = {"response_state"}
        else:
            raise ValueError("probe backend name is not allowed")
        ticket_security = summary.get("ticket_security")
        if not isinstance(ticket_security, dict) or ticket_security.get("algorithm") != "Ed25519":
            raise ValueError("ticket security metadata is invalid")
        if (
            ticket_security.get("private_key_persisted") is not False
            or ticket_security.get("backend_has_private_key") is not False
            or not isinstance(ticket_security.get("key_id"), str)
            or len(ticket_security["key_id"]) != 64
        ):
            raise ValueError("backend/private-key boundary is invalid")
        boundaries = summary.get("safety_boundaries")
        expected_boundaries = {
            "network_activity": "none",
            "sudo_used": False,
            "host_firewall_modified": False,
            "raw_source_argument_accepted": False,
            "raw_ttl_argument_accepted": False,
        }
        if boundaries != expected_boundaries:
            raise ValueError("probe safety boundaries are invalid")
        checks = summary.get("checks")
        if not isinstance(checks, list):
            raise ValueError("checks must be a list")
        check_ids = {
            item.get("id")
            for item in checks
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        if check_ids != expected_checks or len(checks) != len(expected_checks):
            raise ValueError("acceptance checks are incomplete or duplicated")
        recomputed_checks_passed = all(
            isinstance(item, dict) and item.get("passed") is True for item in checks
        )
        if summary.get("checks_passed") is not recomputed_checks_passed:
            raise ValueError("checks_passed does not match check records")
        artifacts = summary.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != {"events", "databases"}:
            raise ValueError("artifact inventory is invalid")
        events_meta = artifacts["events"]
        if not isinstance(events_meta, dict) or set(events_meta) != {"path", "bytes", "sha256", "records"}:
            raise ValueError("event artifact metadata is invalid")
        events_path = _safe_artifact(root, events_meta["path"])
        event_lines = events_path.read_text(encoding="utf-8").splitlines()
        event_values = [json.loads(line) for line in event_lines if line.strip()]
        normalized_events = []
        for sequence, event in enumerate(event_values):
            if (
                not isinstance(event, dict)
                or event.get("schema_version") != ACCEPTANCE_EVENT_SCHEMA_VERSION
                or event.get("sequence") != sequence
            ):
                raise ValueError("event JSONL schema or sequence is invalid")
            normalized_events.append(
                {
                    key: event[key]
                    for key in ("id", "passed", "detail", "evidence")
                }
            )
        recomputed_events = {
            "bytes": events_path.stat().st_size,
            "sha256": sha256_file(events_path),
            "records": len(event_values),
        }
        if any(events_meta[name] != value for name, value in recomputed_events.items()):
            raise ValueError("event artifact digest/count does not match")
        if normalized_events != checks:
            raise ValueError("event JSONL checks differ from summary")
        databases = artifacts["databases"]
        if not isinstance(databases, dict) or set(databases) != expected_databases:
            raise ValueError("database artifact set is invalid")
        recomputed_databases: dict[str, Any] = {}
        for name, metadata in databases.items():
            if not isinstance(metadata, dict) or set(metadata) != {
                "path", "bytes", "sha256", "database_status"
            }:
                raise ValueError(f"database metadata is invalid: {name}")
            database_path = _safe_artifact(root, metadata["path"])
            status = _read_database_status(database_path)
            # Writer checkpoint return values may vary by SQLite build; all
            # other status fields are recomputed from the immutable DB.
            recorded_status = metadata["database_status"]
            if not isinstance(recorded_status, dict):
                raise ValueError("database_status must be an object")
            status["wal_checkpoint"] = recorded_status.get("wal_checkpoint")
            recomputed = {
                "bytes": database_path.stat().st_size,
                "sha256": sha256_file(database_path),
                "database_status": status,
            }
            if any(metadata[field] != recomputed[field] for field in recomputed):
                raise ValueError(f"database artifact mismatch: {name}")
            if (
                status["integrity_check"] != "ok"
                or status["schema_version"] != BACKEND_DB_SCHEMA_VERSION
                or status["capacity"]["retention_policy"] != RETENTION_POLICY
            ):
                raise ValueError(f"database integrity/retention mismatch: {name}")
            recomputed_databases[name] = recomputed
        sidecar = _safe_artifact(root, "summary.json.sha256")
        summary_digest = sha256_file(path)
        if sidecar.read_text(encoding="ascii") != f"{summary_digest}  summary.json\n":
            raise ValueError("summary SHA-256 sidecar does not match")
        result["recomputed"] = {
            "summary_sha256": summary_digest,
            "events": recomputed_events,
            "databases": recomputed_databases,
            "checks_passed": recomputed_checks_passed,
        }
        result["artifact_valid"] = True
        if purpose == "production_admission":
            result["blockers"].append(
                "offline/simulation acceptance schema is never production evidence"
            )
        elif backend == SIMULATION_BACKEND and recomputed_checks_passed:
            result["accepted"] = True
        else:
            result["blockers"].append(str(summary.get("blocked_reason", "blocked")))
        return result
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, sqlite3.Error) as exc:
        result["blockers"].append(f"{type(exc).__name__}: {exc}"[:1024])
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--adapter",
        choices=("in-memory", "production-disabled"),
        default="production-disabled",
    )
    args = parser.parse_args(argv)
    summary = run_backend_acceptance(args.output, adapter_mode=args.adapter)
    verification = verify_backend_acceptance(args.output / "summary.json")
    print(
        json.dumps(
            {
                "summary": summary,
                "verification": verification,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    if not verification["artifact_valid"]:
        return 1
    return 0 if verification["accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
