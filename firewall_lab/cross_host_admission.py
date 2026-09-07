#!/usr/bin/env python3
"""Fail-closed admission gate before isolated cross-host defense testing.

The gate is passive: it reads local artifacts and evidence reports, never
starts ROS, sends packets, or changes a firewall.  Missing evidence is a
blocker, not an invitation to infer a successful defense outcome.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .backend_acceptance import (
    ACCEPTANCE_SCHEMA_VERSION,
    verify_backend_acceptance,
)
from .catalog import load_catalog
from .decision import DecisionPolicy
from .evidence import EvidenceAuthority, feature_sha256
from .formal_preflight import _live_multimodal_contract_check
from .inference import FirewallModel
from .isolated_topology import TOPOLOGY_SCHEMA, verify_isolated_topology_report
from .local_outcomes import (
    OUTCOME_SCHEMA,
    REQUIRED_STAGES as LOCAL_OUTCOME_STAGES,
    verify_local_outcome_report,
)
from .response_authorizer import ResponseAuthorizer, ResponseContext
from .schema import SchemaError, atomic_write_json, sha256_file, utc_now
from .synthetic_dataset import ATTACK_PROFILES, load_synthetic_scenarios


REPORT_SCHEMA = "sros2-firewall-cross-host-admission/v1"
BACKEND_SCHEMA = "sros2-firewall-response-backend-recovery/v1"
WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = WORKSPACE_ROOT / "展示指令" / "sros2_policy_least_privilege.xml"
DEFENSE_COVERAGE_PATH = Path(__file__).with_name("defense_coverage.json")
DEFENSE_COVERAGE_SCHEMA = "sros2-firewall-defense-coverage/v1"

REQUIRED_LOCAL_OUTCOMES = frozenset(LOCAL_OUTCOME_STAGES)
REQUIRED_BACKEND_CHECKS = frozenset(
    {
        "protected_source_rejected",
        "shared_ip_rejected",
        "global_capacity_enforced",
        "concurrent_update_idempotent",
        "automatic_expiry_verified",
        "process_restart_reconciled",
        "backend_state_auditable",
        "missing_ticket_rejected",
        "ticket_source_substitution_rejected",
        "expired_ticket_rejected",
        "replayed_ticket_rejected",
        "backend_uses_ticket_source",
    }
)
MIN_BALANCED_ACCURACY = 0.80
MIN_MACRO_F1 = 0.80
MIN_ANOMALY_RECALL = 0.70
MAX_ANOMALY_FPR = 0.05


def _result(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": str(detail)[:2048]}


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("evidence file is missing or is a symlink")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("evidence root must be an object")
    return value


def _check_outcome_report(path: Path | None) -> tuple[bool, str]:
    if path is None:
        return False, "local defense outcome report not supplied"
    try:
        return verify_local_outcome_report(path)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_backend_report(path: Path | None) -> tuple[bool, str]:
    if path is None:
        return False, "response backend recovery report not supplied"
    try:
        value = _read_json(path)
        schema = value.get("schema_version")
        if schema == ACCEPTANCE_SCHEMA_VERSION:
            verification = verify_backend_acceptance(
                path,
                purpose="production_admission",
            )
            return False, "; ".join(verification["blockers"])
        if schema == BACKEND_SCHEMA:
            return False, (
                "legacy backend recovery reports are self-asserted and are no "
                "longer accepted; a privileged kernel-state production "
                "attestation verifier is required"
            )
        raise ValueError("unsupported response backend schema")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_topology(path: Path | None) -> tuple[bool, str]:
    if path is None:
        return False, "owned isolated topology declaration not supplied"
    try:
        return verify_isolated_topology_report(path)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_policy_alignment() -> tuple[bool, str]:
    try:
        policy = DecisionPolicy.load()
        expected = {
            scenario.attack_class: scenario.expected_action
            for scenario in load_catalog().values()
        }
        expected.update(
            {
                scenario["attack_class"]: scenario["expected_action"]
                for scenario in load_synthetic_scenarios().values()
            }
        )
        actual = {
            attack_class: rule["action"]
            for attack_class, rule in policy.rules.items()
        }
        required_classes = {"normal", *ATTACK_PROFILES}
        passed = set(actual) == required_classes and actual == expected
        return passed, f"policy_classes={len(actual)}; expected={len(required_classes)}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_defense_coverage() -> tuple[bool, str]:
    try:
        value = _read_json(DEFENSE_COVERAGE_PATH)
        if value.get("schema_version") != DEFENSE_COVERAGE_SCHEMA:
            raise ValueError("unsupported defense coverage schema")
        classes = value.get("classes")
        if not isinstance(classes, dict):
            raise ValueError("coverage classes must be an object")
        expected = {"normal", *ATTACK_PROFILES}
        if set(classes) != expected:
            raise ValueError("coverage must contain exactly all model classes")
        policy = DecisionPolicy.load()
        required_fields = {
            "prevention",
            "detection",
            "action",
            "adapter",
            "recovery",
            "evidence",
            "residual_risk",
        }
        for attack_class, item in classes.items():
            if not isinstance(item, dict) or set(item) != required_fields:
                raise ValueError(f"invalid coverage fields for {attack_class}")
            if not all(
                isinstance(item[name], list)
                and item[name]
                and all(isinstance(entry, str) and entry for entry in item[name])
                for name in ("prevention", "detection")
            ):
                raise ValueError(f"empty controls for {attack_class}")
            if any(
                not isinstance(item[name], str) or not item[name]
                for name in ("recovery", "evidence", "residual_risk")
            ):
                raise ValueError(f"missing recovery/evidence/risk for {attack_class}")
            rule = policy.rules[attack_class]
            if (item["action"], item["adapter"]) != (
                rule["action"],
                rule["adapter"],
            ):
                raise ValueError(f"coverage policy drift for {attack_class}")
        return True, f"{len(classes)} classes have prevention/detection/response/recovery/risk"
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_sros2_policy(path: Path = DEFAULT_POLICY) -> tuple[bool, str]:
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("canonical policy missing or symlinked")
        root = ET.parse(path).getroot()
        serialized = ET.tostring(root, encoding="unicode")
        if "*" in serialized:
            raise ValueError("wildcard is forbidden")
        guard = root.find(".//enclave[@path='/velocity_guard_node']")
        if guard is None:
            raise ValueError("velocity guard enclave missing")
        subscribed = {
            (topic.text or "").strip()
            for topic in guard.findall(".//topics[@subscribe='ALLOW']/topic")
        }
        if "security/heartbeat" not in subscribed:
            raise ValueError("velocity guard heartbeat lease permission missing")
        final_publishers = []
        for enclave in root.findall(".//enclave"):
            for profile in enclave.findall("./profiles/profile"):
                published = {
                    (topic.text or "").strip()
                    for topic in profile.findall("./topics[@publish='ALLOW']/topic")
                }
                if "cmd_vel" in published:
                    final_publishers.append(enclave.get("path"))
        if final_publishers != ["/velocity_guard_node"]:
            raise ValueError(f"unexpected final cmd_vel publishers: {final_publishers}")
        return True, "wildcard-free policy; heartbeat lease; one final velocity writer"
    except (OSError, ValueError, ET.ParseError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_response_authorizer() -> tuple[bool, str]:
    try:
        authority = EvidenceAuthority(
            b"cross-host-gate-self-test-secret!!",
            collector_id="cross-host-gate-self-test",
        )
        verifier = authority.verifier()
        model_hash = "1" * 64
        policy_hash = sha256_file(Path(__file__).with_name("action_policy.json"))
        backend_id = "cross-host-gate-nft-timeout-set"
        authorizer = ResponseAuthorizer(
            protected_sources={"10.10.10.2/32"},
            authorized_sources={"10.10.10.0/24"},
            evidence_verifier=verifier,
            model_deployment_eligible=True,
            model_artifact_sha256=model_hash,
            policy_verified=True,
            policy_sha256=policy_hash,
            network_backend_kind="nftables_timeout_set",
            network_backend_id=backend_id,
            network_backend_capacity_ready=True,
            network_backend_recovery_verified=True,
        )

        def request(
            source: str = "10.10.10.1",
            *,
            signals: dict[str, float] | None = None,
            source_shared: bool = False,
        ) -> tuple[Any, ResponseContext]:
            # This gate proves the authorizer refuses/permits correctly, so it
            # needs a decision that is allowed to execute.  The shipped policy
            # authorises nothing, so ask for that authority explicitly here
            # rather than depending on the operational policy being permissive.
            decision = DecisionPolicy.authorising(["service_dos"]).decide(
                predicted_class="service_dos", confidence=0.99, anomaly=True
            )
            evidence = authority.issue(
                source=source,
                source_kind="network_ip",
                interface="gate0",
                identity=f"dds:{source}",
                feature_digest=feature_sha256({"gate_probe": 1.0}),
                session_id="gate-self-test",
                window_id=f"window:{source}:{source_shared}:{signals}",
                model_sha256=model_hash,
                policy_sha256=policy_hash,
                backend_id=backend_id,
                attribution_confidence=0.99,
                signals=signals or {"network": 0.99, "host": 0.90},
                source_shared=source_shared,
                confirmation_windows=2,
                decision=decision,
            )
            decision = replace(decision, evidence_id=evidence.evidence_id)
            return decision, ResponseContext(
                requested_mode="live",
                source=source,
                source_kind="network_ip",
                evidence=evidence,
            )

        decision, context = request()
        accepted = authorizer.authorize(decision, context)
        one_signal_decision, one_signal = request(signals={"network": 0.99})
        shared_decision, shared = request(source_shared=True)
        protected_decision, protected = request(source="10.10.10.2")
        substituted = replace(context, source="10.10.10.99")
        unknown_id = replace(decision, evidence_id="b" * 64)
        verifier.verify_ticket(
            accepted.authorization_ticket,
            source=accepted.source,
            action=accepted.action,
            adapter=accepted.adapter,
            evidence_id=accepted.evidence_id,
            backend_id=backend_id,
            interface=context.evidence.interface,
            identity=context.evidence.identity,
            ttl_sec=accepted.ttl_sec,
        )
        try:
            verifier.verify_ticket(
                accepted.authorization_ticket,
                source="10.10.10.99",
                action=accepted.action,
                adapter=accepted.adapter,
                evidence_id=accepted.evidence_id,
                backend_id=backend_id,
                interface=context.evidence.interface,
                identity=context.evidence.identity,
                ttl_sec=accepted.ttl_sec,
            )
            ticket_substitution_rejected = False
        except SchemaError:
            ticket_substitution_rejected = True
        passed = (
            accepted.execute
            and not hasattr(verifier, "issue")
            and ticket_substitution_rejected
            and not authorizer.authorize(
                one_signal_decision, one_signal
            ).execute
            and not authorizer.authorize(
                shared_decision, shared
            ).execute
            and not authorizer.authorize(
                protected_decision, protected
            ).execute
            and not authorizer.authorize(decision, substituted).execute
            and not authorizer.authorize(unknown_id, context).execute
        )
        return passed, (
            "signed source-bound evidence, logical verifier API, short-lived "
            "ticket, A-to-B substitution, unknown-ID, two-signal, shared-IP, "
            "scope and rollback gates"
        )
    except (SchemaError, ValueError, TypeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_model(path: Path | None) -> tuple[bool, str]:
    if path is None:
        return False, "signed deployment model not supplied"
    try:
        model = FirewallModel(path)
        metrics = model.bundle.get("metrics")
        if not isinstance(metrics, dict):
            raise ValueError("model metrics missing")
        values = {
            "balanced_accuracy": float(metrics.get("balanced_accuracy")),
            "macro_f1": float(metrics.get("macro_f1")),
            "anomaly_recall": float(metrics.get("anomaly_recall")),
            "anomaly_fpr": float(metrics.get("anomaly_fpr")),
        }
        passed = (
            model.deployment_eligible
            and values["balanced_accuracy"] >= MIN_BALANCED_ACCURACY
            and values["macro_f1"] >= MIN_MACRO_F1
            and values["anomaly_recall"] >= MIN_ANOMALY_RECALL
            and values["anomaly_fpr"] <= MAX_ANOMALY_FPR
        )
        return passed, json.dumps(values, sort_keys=True)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def evaluate_admission(
    *,
    model_path: Path | None = None,
    local_outcomes_path: Path | None = None,
    backend_report_path: Path | None = None,
    topology_path: Path | None = None,
    report_path: Path | None = None,
) -> dict[str, Any]:
    multimodal_ok, multimodal_detail = _live_multimodal_contract_check()
    checks = [
        _result("policy_alignment", *_check_policy_alignment()),
        _result("defense_coverage", *_check_defense_coverage()),
        _result("sros2_policy", *_check_sros2_policy()),
        _result("response_authorizer", *_check_response_authorizer()),
        _result("live_multimodal", multimodal_ok, multimodal_detail),
        _result("local_defense_outcomes", *_check_outcome_report(local_outcomes_path)),
        _result("response_backend_recovery", *_check_backend_report(backend_report_path)),
        _result("isolated_cross_host_topology", *_check_topology(topology_path)),
        _result("deployment_model", *_check_model(model_path)),
    ]
    by_name = {item["name"]: item["passed"] for item in checks}
    static_ready = all(
        by_name[name]
        for name in (
            "policy_alignment",
            "defense_coverage",
            "sros2_policy",
            "response_authorizer",
        )
    )
    cross_host_test_ready = static_ready and all(
        by_name[name]
        for name in (
            "live_multimodal",
            "local_defense_outcomes",
            "response_backend_recovery",
            "isolated_cross_host_topology",
        )
    )
    autonomous_ip_block_ready = cross_host_test_ready and by_name["deployment_model"]
    blockers = [item["name"] for item in checks if not item["passed"]]
    report = {
        "schema_version": REPORT_SCHEMA,
        "created_utc": utc_now(),
        "network_activity": "none_passive_checks_only",
        "host_firewall_modified": False,
        "static_defense_ready": static_ready,
        "cross_host_test_ready": cross_host_test_ready,
        "autonomous_ip_block_ready": autonomous_ip_block_ready,
        "effective_mode": (
            "live" if autonomous_ip_block_ready else "observe_or_dry_run_only"
        ),
        "checks": checks,
        "blockers": blockers,
    }
    if report_path is not None:
        atomic_write_json(report_path, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--local-outcomes", type=Path)
    parser.add_argument("--backend-report", type=Path)
    parser.add_argument("--topology", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    report = evaluate_admission(
        model_path=args.model,
        local_outcomes_path=args.local_outcomes,
        backend_report_path=args.backend_report,
        topology_path=args.topology,
        report_path=args.report,
    )
    state = "READY" if report["autonomous_ip_block_ready"] else "BLOCKED"
    print(f"{state} blockers={','.join(report['blockers']) or 'none'}")
    return 0 if report["autonomous_ip_block_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
