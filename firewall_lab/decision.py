"""Constrained policy mapping from model output to firewall intent."""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .catalog import ALLOWED_ACTIONS
from .schema import SchemaError, require_identifier, safe_json_value


POLICY_SCHEMA_VERSION = "sros2-firewall-action-policy/v1"
ALLOWED_ADAPTERS = frozenset(
    {
        "none",
        "sros2_identity",
        "sros2_acl",
        "velocity_guard",
        "application_hmac",
        "input_validator",
        "network_helper",
    }
)
ACTION_ADAPTERS = {
    "allow": frozenset({"none"}),
    "alert": frozenset({"none"}),
    "quarantine": frozenset({"none"}),
    "deny_participant": frozenset({"sros2_identity", "sros2_acl"}),
    "lock_velocity": frozenset({"velocity_guard"}),
    "drop_message": frozenset({"application_hmac", "input_validator"}),
    "temporary_block": frozenset({"network_helper"}),
}


@dataclass(frozen=True)
class FirewallDecision:
    predicted_class: str
    confidence: float
    anomaly: bool
    action: str
    adapter: str
    executable: bool
    reason: str
    evidence_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return safe_json_value(asdict(self))


class DecisionPolicy:
    def __init__(self, value: dict[str, Any]):
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "default_action",
            "unknown_anomaly_action",
            "rules",
        }:
            raise SchemaError("action policy has unexpected keys")
        if value["schema_version"] != POLICY_SCHEMA_VERSION:
            raise SchemaError("unsupported action policy schema")
        self.default_action = require_identifier(
            value["default_action"], "default_action"
        )
        self.unknown_anomaly_action = require_identifier(
            value["unknown_anomaly_action"], "unknown_anomaly_action"
        )
        if (
            self.default_action not in ALLOWED_ACTIONS
            or self.unknown_anomaly_action not in ALLOWED_ACTIONS
        ):
            raise SchemaError("action policy references unknown action")
        if self.default_action not in {"alert", "quarantine"}:
            raise SchemaError("default_action must be non-executable")
        if self.unknown_anomaly_action not in {"alert", "quarantine"}:
            raise SchemaError("unknown_anomaly_action must be non-executable")
        if not isinstance(value["rules"], dict) or not value["rules"]:
            raise SchemaError("action policy rules must be non-empty")
        self.rules = {}
        for attack_class, rule in value["rules"].items():
            require_identifier(attack_class, "rules class")
            if not isinstance(rule, dict) or set(rule) != {
                "action",
                "min_confidence",
                "adapter",
            }:
                raise SchemaError(f"invalid rule keys for {attack_class}")
            action = require_identifier(rule["action"], "rule.action")
            adapter = require_identifier(rule["adapter"], "rule.adapter")
            threshold = rule["min_confidence"]
            if (
                action not in ALLOWED_ACTIONS
                or action not in ACTION_ADAPTERS
                or adapter not in ALLOWED_ADAPTERS
                or isinstance(threshold, bool)
                or not isinstance(threshold, (int, float))
                or not math.isfinite(float(threshold))
                or not 0.0 <= float(threshold) <= 1.0
            ):
                raise SchemaError(f"unsafe action rule for {attack_class}")
            if adapter not in ACTION_ADAPTERS[action]:
                raise SchemaError(
                    f"action/adapter mismatch for {attack_class}: "
                    f"{action}/{adapter}"
                )
            if attack_class == "normal" and (
                action != "allow" or adapter != "none"
            ):
                raise SchemaError("normal rule must be allow/none")
            self.rules[attack_class] = {
                "action": action,
                "adapter": adapter,
                "min_confidence": float(threshold),
            }

    @classmethod
    def load(cls, path: str | Path | None = None) -> "DecisionPolicy":
        policy_path = (
            Path(path)
            if path is not None
            else Path(__file__).with_name("action_policy.json")
        )
        return cls(json.loads(policy_path.read_text(encoding="utf-8")))

    def decide(
        self,
        *,
        predicted_class: str,
        confidence: float,
        anomaly: bool,
    ) -> FirewallDecision:
        require_identifier(predicted_class, "predicted_class")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            return FirewallDecision(
                predicted_class=predicted_class,
                confidence=0.0,
                anomaly=bool(anomaly),
                action="alert",
                adapter="none",
                executable=False,
                reason="invalid confidence failed closed to alert only",
            )
        confidence = float(confidence)
        rule = self.rules.get(predicted_class)
        if rule is None:
            action = (
                self.unknown_anomaly_action
                if anomaly
                else self.default_action
            )
            return FirewallDecision(
                predicted_class=predicted_class,
                confidence=confidence,
                anomaly=bool(anomaly),
                action=action,
                adapter="none",
                executable=False,
                reason="unknown class requires operator-approved adapter",
            )
        if confidence < rule["min_confidence"]:
            return FirewallDecision(
                predicted_class=predicted_class,
                confidence=confidence,
                anomaly=bool(anomaly),
                action="alert",
                adapter="none",
                executable=False,
                reason=(
                    f"confidence below {rule['min_confidence']:.2f}; "
                    "observe only"
                ),
            )
        if predicted_class == "normal" and anomaly:
            return FirewallDecision(
                predicted_class=predicted_class,
                confidence=confidence,
                anomaly=True,
                action=self.unknown_anomaly_action,
                adapter="none",
                executable=False,
                reason="known classifier says normal but anomaly model disagrees",
            )
        action = rule["action"]
        adapter = rule["adapter"]
        return FirewallDecision(
            predicted_class=predicted_class,
            confidence=confidence,
            anomaly=bool(anomaly),
            action=action,
            adapter=adapter,
            executable=action != "allow" and adapter != "none",
            reason="matched constrained action policy",
        )
