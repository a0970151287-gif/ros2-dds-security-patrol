from __future__ import annotations

import copy

import pytest

from firewall_lab.decision import DecisionPolicy
from firewall_lab.inference import FirewallModel
from firewall_lab.schema import SchemaError
from firewall_lab.train import FEATURES


class _Classifier:
    classes_ = ["normal", "service_dos"]

    def __init__(self, probabilities):
        self.probabilities = probabilities

    def predict_proba(self, _rows):
        return [self.probabilities]


class _Anomaly:
    def __init__(self, value=1):
        self.value = value

    def predict(self, _rows):
        return [self.value]


def _model(probabilities, *, anomaly=1):
    model = FirewallModel.__new__(FirewallModel)
    model.classifier = _Classifier(probabilities)
    model.anomaly_detector = _Anomaly(anomaly)
    model.features = list(FEATURES)
    model.classes = ["normal", "service_dos"]
    model.policy = DecisionPolicy.load()
    model.deployment_eligible = True
    model.reject_threshold = 0.0
    model.policy_verified = True
    return model


def _features():
    return {name: 0.0 for name in FEATURES}


@pytest.mark.parametrize(
    "probabilities",
    ([0.8, 0.8], [-0.1, 1.1], [float("nan"), 1.0], [1.0]),
)
def test_inference_rejects_invalid_probability_vectors(probabilities):
    with pytest.raises(RuntimeError, match="probabilit"):
        _model(probabilities).predict(_features())


def test_inference_rejects_invalid_anomaly_output():
    with pytest.raises(RuntimeError, match="anomaly detector"):
        _model([0.1, 0.9], anomaly=0).predict(_features())


def test_inference_rejects_out_of_range_feature():
    values = _features()
    values["spdp_ratio"] = 1.01
    with pytest.raises(ValueError, match="admitted range"):
        _model([0.1, 0.9]).predict(values)


def test_non_deployable_model_can_only_emit_observation():
    model = _model([0.1, 0.9], anomaly=-1)
    model.deployment_eligible = False
    result = model.predict(_features())
    assert result["predicted_class"] == "service_dos"
    assert result["decision"]["action"] == "alert"
    assert result["decision"]["adapter"] == "none"
    assert result["decision"]["executable"] is False


def test_validation_reject_threshold_forces_observation_only():
    model = _model([0.31, 0.69], anomaly=1)
    model.reject_threshold = 0.70
    result = model.predict(_features())
    assert result["predicted_class"] == "service_dos"
    assert result["decision"]["action"] == "alert"
    assert result["decision"]["adapter"] == "none"
    assert result["decision"]["executable"] is False
    assert "reject threshold" in result["decision"]["reason"]


def test_decision_policy_rejects_normal_rule_that_can_execute():
    value = {
        "schema_version": "sros2-firewall-action-policy/v1",
        "default_action": "alert",
        "unknown_anomaly_action": "quarantine",
        "rules": {
            "normal": {
                "action": "temporary_block",
                "min_confidence": 0.6,
                "adapter": "network_helper",
            }
        },
    }
    with pytest.raises(SchemaError, match="normal rule"):
        DecisionPolicy(copy.deepcopy(value))


def test_decision_policy_rejects_legacy_rate_limit_semantics():
    value = {
        "schema_version": "sros2-firewall-action-policy/v1",
        "default_action": "alert",
        "unknown_anomaly_action": "quarantine",
        "rules": {
            "service_dos": {
                "action": "rate_limit",
                "min_confidence": 0.8,
                "adapter": "network_helper",
            }
        },
    }
    with pytest.raises(SchemaError, match="unsafe action rule"):
        DecisionPolicy(copy.deepcopy(value))


def test_decision_policy_rejects_mismatched_action_adapter():
    value = {
        "schema_version": "sros2-firewall-action-policy/v1",
        "default_action": "alert",
        "unknown_anomaly_action": "quarantine",
        "rules": {
            "normal": {
                "action": "allow",
                "min_confidence": 0.6,
                "adapter": "none",
            },
            "bad": {
                "action": "lock_velocity",
                "min_confidence": 0.8,
                "adapter": "network_helper",
            },
        },
    }
    with pytest.raises(SchemaError, match="action/adapter mismatch"):
        DecisionPolicy(copy.deepcopy(value))
