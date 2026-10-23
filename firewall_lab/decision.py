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
        "dds_guard",
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
    # 一個 action 對一個 adapter：可撤銷的 participant 阻斷只能由第二層守衛
    # 執行，不可以退回去用 SROS2 的靜態 ACL（那不可撤銷，也不在 runtime 生效）。
    "revocable_participant_block": frozenset({"dds_guard"}),
}

# 未知攻擊路徑**只准**走可撤銷的動作。
#
# 這條清單本來只有 alert 與 quarantine，也就是完全不可執行。放寬它的理由不是
# 「讓未知攻擊也能反應」，而是這一層的動作性質變了：處女 holdout 上的
# open-set recall 只有 0.0273，異常判定經常是錯的，所以它配得上的只有
# **可撤銷、有 TTL、範圍只有一個 participant** 的動作。
#
# `temporary_block`（網路層、要 root、影響整個 IP）與 `deny_participant`
# （SROS2 靜態 ACL、不可撤銷）刻意不在這裡：不確定的判定不該觸發
# 收不回來或波及第三方的動作。
REVOCABLE_ANOMALY_ACTION = "revocable_participant_block"
ANOMALY_ALLOWED_ACTIONS = frozenset(
    {"alert", "quarantine", REVOCABLE_ANOMALY_ACTION}
)


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
            "anomaly_response_authorized",
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
            # default_action 走的是「有未知類別、但**異常偵測器沒有說話**」
            # 的情況。連異常訊號都沒有，就沒有任何動作的正當性，所以這一條
            # 維持完全不可執行。
            raise SchemaError("default_action must be non-executable")
        if self.unknown_anomaly_action not in ANOMALY_ALLOWED_ACTIONS:
            raise SchemaError(
                "unknown_anomaly_action must be alert, quarantine, or "
                f"{REVOCABLE_ANOMALY_ACTION}")
        # 未知攻擊路徑要執行，必須由操作者**另外**明確開啟。
        # 不讓它搭 executable_classes 的便車：那份清單是逐類的判斷，
        # 而未知攻擊按定義不屬於任何一類，兩者是不同的授權決定。
        raw_anomaly_authorized = value.get("anomaly_response_authorized", False)
        if not isinstance(raw_anomaly_authorized, bool):
            raise SchemaError("anomaly_response_authorized must be bool")
        self.anomaly_response_authorized = raw_anomaly_authorized
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
        anomaly_action: str | None = None,
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
        if anomaly_action is not None:
            # 未知攻擊路徑要在測試或演練裡走通，同樣必須明確要求，
            # 不能因為某些類別被授權就順便獲得。
            value["unknown_anomaly_action"] = anomaly_action
            value["anomaly_response_authorized"] = (
                anomaly_action == REVOCABLE_ANOMALY_ACTION)
        return cls(value)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "DecisionPolicy":
        policy_path = (
            Path(path)
            if path is not None
            else Path(__file__).with_name("action_policy.json")
        )
        return cls(json.loads(policy_path.read_text(encoding="utf-8")))

    def _anomaly_response(self) -> tuple[str, bool]:
        """未知攻擊路徑要用哪個 adapter，以及能不能執行。

        **兩件事都成立才可執行**：policy 指定的動作是可撤銷的那一個，
        而且操作者另外開了 `anomaly_response_authorized`。任何一項不成立
        就退回 observe——包括「動作寫成可撤銷但沒開開關」這一種。

        兩道而不是一道，是因為它們回答不同的問題：動作本身配不配得上
        不確定的證據（policy 設計），以及這一套部署有沒有被授權對未知攻擊
        動手（操作者決定）。
        """
        if (
            self.unknown_anomaly_action == REVOCABLE_ANOMALY_ACTION
            and self.anomaly_response_authorized
        ):
            return sorted(ACTION_ADAPTERS[REVOCABLE_ANOMALY_ACTION])[0], True
        return "none", False

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
            if anomaly:
                action = self.unknown_anomaly_action
                adapter, executable = self._anomaly_response()
                reason = (
                    "unknown class with anomaly agreement; revocable response"
                    if executable
                    else "unknown class requires operator-approved adapter"
                )
            else:
                action = self.default_action
                adapter, executable, reason = (
                    "none", False,
                    "unknown class requires operator-approved adapter")
            return FirewallDecision(
                predicted_class=predicted_class,
                confidence=confidence,
                anomaly=bool(anomaly),
                action=action,
                adapter=adapter,
                executable=executable,
                reason=reason,
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
            adapter, executable = self._anomaly_response()
            return FirewallDecision(
                predicted_class=predicted_class,
                confidence=confidence,
                anomaly=True,
                action=self.unknown_anomaly_action,
                adapter=adapter,
                executable=executable,
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
