"""Fail-closed authorization between model intent and a live adapter.

The classifier is never trusted as the sole authority for a firewall change.
Every dynamic response requires an authenticated evidence envelope, trusted
runtime attestations, protected-source checks, and a bounded recovery path.
"""

from __future__ import annotations

import ipaddress
import hashlib
import math
import time
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .decision import FirewallDecision
from .evidence import EvidenceEnvelope, EvidenceVerifier, SOURCE_KINDS
from .schema import SchemaError, safe_json_value


AUTHORIZATION_SCHEMA_VERSION = "sros2-firewall-response-authorization/v1"
REQUEST_MODES = frozenset({"observe", "dry_run", "live"})
NETWORK_BACKENDS = frozenset({"nftables_timeout_set", "ipset_timeout"})
LIVE_SIGNAL_MIN = 0.75
NETWORK_SIGNAL_MIN = 0.80
ATTRIBUTION_MIN = 0.95
MAX_NETWORK_TTL_SEC = 300
MAX_SAFETY_HOLD_SEC = 30
MAX_DYNAMIC_EVIDENCE_AGE_SEC = 10.0
MAX_FUTURE_CLOCK_SKEW_SEC = 1.0
MIN_NETWORK_CONFIRMATION_WINDOWS = 2
UPSTREAM_PREVENTION_ADAPTERS = frozenset(
    {"sros2_identity", "sros2_acl", "application_hmac", "input_validator"}
)


@dataclass(frozen=True)
class ResponseContext:
    requested_mode: str
    source: str
    source_kind: str
    evidence: EvidenceEnvelope | None = None
    requested_ttl_sec: int = MAX_NETWORK_TTL_SEC


@dataclass(frozen=True)
class AuthorizedResponse:
    requested_mode: str
    effective_mode: str
    action: str
    adapter: str
    source: str
    evidence_id: str
    authorization_ticket: str
    execute: bool
    live_eligible: bool
    rollback_required: bool
    ttl_sec: int
    blockers: tuple[str, ...]
    reason: str
    schema_version: str = AUTHORIZATION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        ticket = value.get("authorization_ticket", "")
        value["authorization_ticket"] = "<redacted>" if ticket else ""
        value["authorization_ticket_sha256"] = (
            hashlib.sha256(ticket.encode("utf-8")).hexdigest() if ticket else ""
        )
        return safe_json_value(value)


def _finite_probability(value: Any, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise SchemaError(f"{name} must be finite and in 0..1")
    return float(value)


class ResponseAuthorizer:
    """Turn a signed response intent into a narrowly scoped authorization.

    Runtime readiness is constructor-owned configuration, not caller-provided
    booleans.  This prevents a Detection object from self-declaring that its
    model, policy, backend, attribution, and rollback path are trustworthy.
    """

    def __init__(
        self,
        *,
        protected_sources: Iterable[str] = (),
        allowlisted_sources: Iterable[str] = (),
        authorized_sources: Iterable[str] = (),
        evidence_verifier: EvidenceVerifier | None = None,
        model_deployment_eligible: bool = False,
        model_artifact_sha256: str = "",
        policy_verified: bool = False,
        policy_sha256: str = "",
        network_backend_kind: str = "none",
        network_backend_id: str = "",
        network_backend_capacity_ready: bool = False,
        network_backend_recovery_verified: bool = False,
        velocity_guard_recovery_verified: bool = False,
    ):
        for name, value in (
            ("model_deployment_eligible", model_deployment_eligible),
            ("policy_verified", policy_verified),
            ("network_backend_capacity_ready", network_backend_capacity_ready),
            ("network_backend_recovery_verified", network_backend_recovery_verified),
            ("velocity_guard_recovery_verified", velocity_guard_recovery_verified),
        ):
            if not isinstance(value, bool):
                raise SchemaError(f"{name} must be bool")
        if evidence_verifier is not None and type(evidence_verifier) is not EvidenceVerifier:
            raise SchemaError("evidence_verifier has the wrong type")
        for name, value in (
            ("network_backend_kind", network_backend_kind),
            ("network_backend_id", network_backend_id),
        ):
            if not isinstance(value, str):
                raise SchemaError(f"{name} must be text")
        for name, value in (
            ("model_artifact_sha256", model_artifact_sha256),
            ("policy_sha256", policy_sha256),
        ):
            if (
                not isinstance(value, str)
                or (value and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value)))
            ):
                raise SchemaError(f"{name} must be empty or lowercase SHA-256")
        self.protected_networks = self._parse_networks(protected_sources)
        self.allowlisted_networks = self._parse_networks(allowlisted_sources)
        self.authorized_networks = self._parse_networks(authorized_sources)
        self.evidence_verifier = evidence_verifier
        self.model_deployment_eligible = model_deployment_eligible
        self.model_artifact_sha256 = model_artifact_sha256
        self.policy_verified = policy_verified
        self.policy_sha256 = policy_sha256
        self.network_backend_kind = network_backend_kind
        self.network_backend_id = network_backend_id
        self.network_backend_capacity_ready = network_backend_capacity_ready
        self.network_backend_recovery_verified = network_backend_recovery_verified
        self.velocity_guard_recovery_verified = velocity_guard_recovery_verified

    @staticmethod
    def _parse_networks(values: Iterable[str]) -> tuple[Any, ...]:
        result = []
        for value in values:
            try:
                result.append(ipaddress.ip_network(str(value), strict=False))
            except ValueError as exc:
                raise SchemaError(f"invalid configured source network: {value}") from exc
        return tuple(result)

    @staticmethod
    def _special_ip_blocker(source: str) -> tuple[Any | None, str | None]:
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            return None, "source is not a single IP address"
        if address.version != 4:
            return None, "only a single IPv4 source may be blocked"
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            return None, "special, loopback, or reserved source may not be blocked"
        return address, None

    @staticmethod
    def _in_networks(address: Any, networks: tuple[Any, ...]) -> bool:
        return any(
            address.version == network.version and address in network
            for network in networks
        )

    @staticmethod
    def _base_response(
        decision: FirewallDecision,
        context: ResponseContext,
        *,
        effective_mode: str,
        execute: bool,
        live_eligible: bool,
        rollback_required: bool,
        ttl_sec: int,
        blockers: list[str],
        reason: str,
        source: str | None = None,
        evidence_id: str = "",
        authorization_ticket: str = "",
    ) -> AuthorizedResponse:
        return AuthorizedResponse(
            requested_mode=context.requested_mode,
            effective_mode=effective_mode,
            action=decision.action,
            adapter=decision.adapter,
            source=str(context.source if source is None else source)[:128],
            evidence_id=evidence_id,
            authorization_ticket=authorization_ticket,
            execute=execute,
            live_eligible=live_eligible,
            rollback_required=rollback_required,
            ttl_sec=ttl_sec,
            blockers=tuple(blockers),
            reason=reason,
        )

    def _verified_evidence(
        self,
        decision: FirewallDecision,
        context: ResponseContext,
        blockers: list[str],
    ) -> EvidenceEnvelope | None:
        if self.evidence_verifier is None:
            blockers.append("trusted evidence verifier is not configured")
            return None
        try:
            evidence = self.evidence_verifier.verify(context.evidence)
        except SchemaError:
            blockers.append("authenticated evidence verification failed")
            return None
        if context.source_kind != evidence.source_kind:
            blockers.append("response source kind does not match signed evidence")
        try:
            context_source = (
                str(ipaddress.ip_address(context.source))
                if context.source_kind == "network_ip"
                else str(context.source).strip()
            )
        except ValueError:
            context_source = ""
        if context_source != evidence.source:
            blockers.append("response source does not match signed evidence")
        if decision.evidence_id != evidence.evidence_id:
            blockers.append("decision does not reference the signed evidence")
        if (
            decision.predicted_class != evidence.predicted_class
            or float(decision.confidence) != evidence.decision_confidence
            or decision.anomaly is not evidence.anomaly
            or decision.action != evidence.action
            or decision.adapter != evidence.adapter
            or decision.executable is not evidence.executable
        ):
            blockers.append("decision fields do not match signed evidence")
        now_ns = time.time_ns()
        age_sec = (now_ns - evidence.observed_at_ns) / 1_000_000_000
        if age_sec < -MAX_FUTURE_CLOCK_SKEW_SEC:
            blockers.append("signed evidence timestamp is in the future")
        elif age_sec > MAX_DYNAMIC_EVIDENCE_AGE_SEC:
            blockers.append("signed evidence is stale")
        return evidence

    def _claim_ticket(
        self,
        evidence: EvidenceEnvelope | None,
        decision: FirewallDecision,
        ttl_sec: int,
        blockers: list[str],
    ) -> str:
        if evidence is None or self.evidence_verifier is None:
            return ""
        try:
            ticket = self.evidence_verifier.claim(
                evidence,
                action=decision.action,
                adapter=decision.adapter,
                ttl_sec=ttl_sec,
            )
            self.evidence_verifier.verify_ticket(
                ticket,
                source=evidence.source,
                action=decision.action,
                adapter=decision.adapter,
                evidence_id=evidence.evidence_id,
                backend_id=evidence.backend_id,
                interface=evidence.interface,
                identity=evidence.identity,
                ttl_sec=ttl_sec,
            )
            return ticket
        except SchemaError:
            blockers.append("signed evidence was already claimed for another response")
            return ""

    def authorize(
        self,
        decision: FirewallDecision,
        context: ResponseContext,
    ) -> AuthorizedResponse:
        if context.requested_mode not in REQUEST_MODES:
            raise SchemaError("requested_mode must be observe, dry_run, or live")
        if context.source_kind not in SOURCE_KINDS:
            raise SchemaError("unsupported source_kind")
        _finite_probability(decision.confidence, "decision.confidence")
        if not isinstance(decision.anomaly, bool) or not isinstance(
            decision.executable, bool
        ):
            raise SchemaError("decision booleans have invalid types")
        if (
            isinstance(context.requested_ttl_sec, bool)
            or not isinstance(context.requested_ttl_sec, int)
            or not 1 <= context.requested_ttl_sec <= MAX_NETWORK_TTL_SEC
        ):
            raise SchemaError("requested_ttl_sec must be an integer in 1..300")

        if decision.adapter in UPSTREAM_PREVENTION_ADAPTERS:
            return self._base_response(
                decision,
                context,
                effective_mode="prevention_only",
                execute=False,
                live_eligible=True,
                rollback_required=False,
                ttl_sec=0,
                blockers=[],
                reason="message or DDS policy is enforced upstream; no dynamic command",
            )
        if not decision.executable or decision.adapter == "none":
            return self._base_response(
                decision,
                context,
                effective_mode="observe",
                execute=False,
                live_eligible=False,
                rollback_required=False,
                ttl_sec=0,
                blockers=["decision has no fixed executable adapter"],
                reason="observe and preserve evidence",
            )

        blockers: list[str] = []
        if context.requested_mode == "observe":
            blockers.append("operator requested observe-only mode")
        evidence = self._verified_evidence(decision, context, blockers)
        signals = dict(evidence.signals) if evidence is not None else {}
        attribution = (
            evidence.attribution_confidence if evidence is not None else 0.0
        )
        normalized_source = evidence.source if evidence is not None else str(context.source)

        if decision.adapter == "network_helper":
            if decision.action != "temporary_block":
                blockers.append("network helper only accepts temporary_block")
            if context.source_kind != "network_ip":
                blockers.append("network response requires network_ip attribution")
                address = None
            else:
                address, blocker = self._special_ip_blocker(normalized_source)
                if blocker:
                    blockers.append(blocker)
            if address is not None and (
                not self.authorized_networks
                or not self._in_networks(address, self.authorized_networks)
            ):
                blockers.append("source is outside authorizer-owned scope")
            if evidence is None or evidence.source_shared:
                blockers.append(
                    "source IP is shared by multiple identities or attribution is ambiguous"
                )
            if evidence is None or evidence.confirmation_windows < MIN_NETWORK_CONFIRMATION_WINDOWS:
                blockers.append("network response needs two signed consecutive windows")
            if not self.model_deployment_eligible:
                blockers.append("model is not approved for live deployment")
            if (
                not self.model_artifact_sha256
                or evidence is None
                or evidence.model_sha256 != self.model_artifact_sha256
            ):
                blockers.append("signed evidence is not bound to the active model hash")
            if not self.policy_verified:
                blockers.append("action policy integrity is not verified")
            if (
                not self.policy_sha256
                or evidence is None
                or evidence.policy_sha256 != self.policy_sha256
            ):
                blockers.append("signed evidence is not bound to the active policy hash")
            if self.network_backend_kind not in NETWORK_BACKENDS:
                blockers.append("network backend lacks kernel-managed bounded expiry")
            if (
                not self.network_backend_id
                or evidence is None
                or evidence.backend_id != self.network_backend_id
            ):
                blockers.append("signed evidence is not bound to the active backend")
            if not self.network_backend_capacity_ready:
                blockers.append("network backend capacity guard is not ready")
            if not self.network_backend_recovery_verified:
                blockers.append("network backend recovery is not verified")
            if address is not None and self._in_networks(address, self.protected_networks):
                blockers.append("source belongs to protected target range")
            if address is not None and self._in_networks(address, self.allowlisted_networks):
                blockers.append("source belongs to explicit allowlist")
            if attribution < ATTRIBUTION_MIN:
                blockers.append("source attribution confidence below 0.95")
            if signals.get("network", 0.0) < NETWORK_SIGNAL_MIN:
                blockers.append("network signal below 0.80")
            corroborating = max(
                signals.get("telemetry", 0.0),
                signals.get("sros2", 0.0),
                signals.get("host", 0.0),
                signals.get("ros_behavior", 0.0),
            )
            if corroborating < LIVE_SIGNAL_MIN:
                blockers.append("no independent corroborating signal at 0.75")
            live_eligible = not blockers
            effective_mode = (
                "live"
                if context.requested_mode == "live" and live_eligible
                else "dry_run"
                if context.requested_mode == "dry_run"
                else "observe"
            )
            ticket = ""
            if effective_mode == "live":
                ticket = self._claim_ticket(
                    evidence, decision, context.requested_ttl_sec, blockers
                )
                if not ticket:
                    effective_mode = "observe"
                    live_eligible = False
            return self._base_response(
                decision,
                context,
                effective_mode=effective_mode,
                execute=effective_mode == "live",
                live_eligible=live_eligible,
                rollback_required=True,
                ttl_sec=context.requested_ttl_sec,
                blockers=blockers,
                reason=(
                    "signed two-signal attributed temporary network response"
                    if live_eligible
                    else "live response denied; retain dry-run evidence"
                ),
                source=normalized_source,
                evidence_id=evidence.evidence_id if evidence is not None else "",
                authorization_ticket=ticket,
            )

        if decision.adapter == "velocity_guard":
            behavior_signal = max(
                signals.get("ros_behavior", 0.0),
                signals.get("telemetry", 0.0),
            )
            if behavior_signal < LIVE_SIGNAL_MIN:
                blockers.append("velocity guard needs signed ROS behavior/telemetry at 0.75")
            if not self.policy_verified:
                blockers.append("action policy integrity is not verified")
            if (
                not self.policy_sha256
                or evidence is None
                or evidence.policy_sha256 != self.policy_sha256
            ):
                blockers.append("signed evidence is not bound to the active policy hash")
            if not self.velocity_guard_recovery_verified:
                blockers.append("authenticated clear/recovery path is not verified")
            live_eligible = not blockers
            effective_mode = (
                "live"
                if context.requested_mode == "live" and live_eligible
                else "dry_run"
                if context.requested_mode == "dry_run"
                else "observe"
            )
            ttl_sec = min(context.requested_ttl_sec, MAX_SAFETY_HOLD_SEC)
            ticket = ""
            if effective_mode == "live":
                ticket = self._claim_ticket(evidence, decision, ttl_sec, blockers)
                if not ticket:
                    effective_mode = "observe"
                    live_eligible = False
            return self._base_response(
                decision,
                context,
                effective_mode=effective_mode,
                execute=effective_mode == "live",
                live_eligible=live_eligible,
                rollback_required=True,
                ttl_sec=ttl_sec,
                blockers=blockers,
                reason=(
                    "signed bounded safety hold with authenticated recovery"
                    if live_eligible
                    else "safety hold denied; observe only"
                ),
                source=normalized_source,
                evidence_id=evidence.evidence_id if evidence is not None else "",
                authorization_ticket=ticket,
            )

        return self._base_response(
            decision,
            context,
            effective_mode="observe",
            execute=False,
            live_eligible=False,
            rollback_required=False,
            ttl_sec=0,
            blockers=["adapter is not authorized by the response layer"],
            reason="fail closed on unsupported adapter",
        )
