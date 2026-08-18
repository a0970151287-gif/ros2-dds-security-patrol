"""Constrained policy mapping from model output to firewall intent."""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

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
        if not isinstance(value, dict) or not {
            "schema_version",
            "default_action",
            "unknown_anomaly_action",
            "rules",
        } <= set(value) <= {
            "schema_version",
            "default_action",
            "unknown_anomaly_action",
            "rules",
            "executable_classes",
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
        # Which classes may ever reach an adapter. A closed-set classifier
        # answers every input with one of the classes it was trained on, so an
        # attack type absent from training does not fall through to
        # unknown_anomaly_action -- it is reported as the nearest known class
        # and would otherwise inherit that class's executable adapter. This
        # list is the operator's separate statement of which classes have been
        # validated well enough to act on. Absent means none of them.
        raw_executable = value.get("executable_classes", [])
        if not isinstance(raw_executable, list) or not all(
            isinstance(name, str) for name in raw_executable
        ):
            raise SchemaError("executable_classes must be a list of strings")
        self.executable_classes = frozenset(
            require_identifier(name, "executable_classes entry")
            for name in raw_executable
        )
        unknown_executable = self.executable_classes - set(value["rules"])
        if unknown_executable:
            raise SchemaError(
                f"executable_classes has no rule: {sorted(unknown_executable)}"
            )
        if "normal" in self.executable_classes:
            raise SchemaError("normal may never be executable")
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
    def authorising(
        cls,
        classes: Iterable[str],
        *,
        path: str | Path | None = None,
    ) -> "DecisionPolicy":
        """The shipped policy, with the named classes authorised to execute.

        ``executable_classes`` ships empty: no model has passed a deployment
        gate, so nothing is authorised to act. Code that has to exercise the
        enforcement path anyway -- the cross-host admission self-test, and the
        authorizer/backend tests -- must ask for that authority explicitly here
        instead of depending on the operational policy staying permissive.
        Nothing in this constructor grants an adapter a rule does not already
        have; it only lifts the authorisation gate for the named classes.
        """

        policy_path = (
            Path(path)
            if path is not None
            else Path(__file__).with_name("action_policy.json")
        )
        value = json.loads(policy_path.read_text(encoding="utf-8"))
        value["executable_classes"] = sorted({str(name) for name in classes})
        return cls(value)

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
        if (
            action != "allow"
            and adapter != "none"
            and predicted_class not in self.executable_classes
        ):
            return FirewallDecision(
                predicted_class=predicted_class,
                confidence=confidence,
                anomaly=bool(anomaly),
                action="alert",
                adapter="none",
                executable=False,
                reason=(
                    f"{predicted_class} is not in the policy's "
                    "executable_classes; observe only"
                ),
            )
        return FirewallDecision(
            predicted_class=predicted_class,
            confidence=confidence,
            anomaly=bool(anomaly),
            action=action,
            adapter=adapter,
            executable=action != "allow" and adapter != "none",
            reason="matched constrained action policy",
        )
