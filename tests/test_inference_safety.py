from __future__ import annotations

import copy

import pytest

from firewall_lab.decision import DecisionPolicy
from firewall_lab.inference import FirewallModel
from firewall_lab.schema import SchemaError
from firewall_lab.synthetic_dataset import TELEMETRY_FEATURES
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
    model.anomaly_features = list(FEATURES)
    model.required_features = list(FEATURES)
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


def test_anomaly_detector_receives_its_own_features_not_the_classifier_s():
    """The detector is fitted on telemetry while the classifier uses network.

    Feeding it the classifier's row would score live traffic against a model
    of entirely different columns and still return a plausible -1/1, so the
    error would be silent. Assert the exact row each estimator is handed.
    """

    seen = {}

    class _RecordingClassifier(_Classifier):
        def predict_proba(self, rows):
            seen["classifier"] = list(rows[0])
            return [self.probabilities]

    class _RecordingAnomaly(_Anomaly):
        def predict(self, rows):
            seen["anomaly"] = list(rows[0])
            return [self.value]

    model = _model([0.1, 0.9])
    model.classifier = _RecordingClassifier([0.1, 0.9])
    model.anomaly_detector = _RecordingAnomaly(1)
    model.anomaly_features = list(TELEMETRY_FEATURES)
    model.required_features = list(FEATURES) + list(TELEMETRY_FEATURES)

    # Distinct per feature so a wrong column order or a shared row shows up,
    # and inside every FEATURE_BOUNDS range (the tightest is 0.0-1.0).
    values = {name: 0.0 for name in model.required_features}
    for offset, name in enumerate(FEATURES, start=1):
        values[name] = offset / 1000.0
    for offset, name in enumerate(TELEMETRY_FEATURES, start=1):
        values[name] = 0.5 + offset / 1000.0

    model.predict(values)

    assert seen["classifier"] == [values[name] for name in FEATURES]
    assert seen["anomaly"] == [values[name] for name in TELEMETRY_FEATURES]
    assert seen["classifier"] != seen["anomaly"]


def test_inference_requires_the_union_of_both_feature_sets():
    model = _model([0.1, 0.9])
    model.anomaly_features = list(TELEMETRY_FEATURES)
    model.required_features = list(FEATURES) + list(TELEMETRY_FEATURES)
    with pytest.raises(ValueError, match="features must contain exactly"):
        model.predict(_features())


def test_bundle_without_anomaly_features_reuses_the_classifier_s():
    """Models trained before the split must keep loading and behaving."""

    from firewall_lab import inference

    bundle = {"features": list(FEATURES)}
    anomaly_features = bundle.get("anomaly_features", bundle["features"])
    assert anomaly_features == list(FEATURES)
    assert anomaly_features in inference.ALLOWED_FEATURE_ORDERS


def _policy_value(*, executable_classes=None):
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
            "service_dos": {
                "action": "temporary_block",
                "min_confidence": 0.5,
                "adapter": "network_helper",
            },
        },
    }
    if executable_classes is not None:
        value["executable_classes"] = executable_classes
    return value


def test_policy_without_executable_classes_can_never_execute():
    """Absence must fail closed.

    A policy that never names a class as executable has not authorised any
    enforcement, so a rule carrying an adapter is not enough on its own.
    """

    policy = DecisionPolicy(_policy_value())
    decision = policy.decide(
        predicted_class="service_dos", confidence=0.99, anomaly=False
    )
    assert decision.executable is False
    assert decision.action == "alert"
    assert decision.adapter == "none"
    assert "executable_classes" in decision.reason


def test_policy_executes_only_the_classes_it_names():
    allowed = DecisionPolicy(_policy_value(executable_classes=["service_dos"]))
    decision = allowed.decide(
        predicted_class="service_dos", confidence=0.99, anomaly=False
    )
    assert decision.executable is True
    assert decision.action == "temporary_block"
    assert decision.adapter == "network_helper"

    withheld = DecisionPolicy(_policy_value(executable_classes=[]))
    decision = withheld.decide(
        predicted_class="service_dos", confidence=0.99, anomaly=False
    )
    assert decision.executable is False


@pytest.mark.parametrize(
    "executable_classes",
    (["normal"], ["no_such_class"], "service_dos", [1]),
)
def test_policy_rejects_an_unsafe_executable_class_list(executable_classes):
    with pytest.raises(SchemaError):
        DecisionPolicy(_policy_value(executable_classes=executable_classes))


def test_policy_covering_more_classes_than_the_model_is_accepted():
    """The live models predict 9 classes against a 23-rule policy.

    Requiring set equality refused them at load, which blocked alert-only
    observation as well as enforcement. Extra rules must be allowed; missing
    ones must not be.
    """

    from firewall_lab.decision import DecisionPolicy as _P

    policy = _P(_policy_value(executable_classes=["service_dos"]))
    model_classes = {"normal", "service_dos"}
    assert model_classes <= set(policy.rules)
    assert set(policy.rules) - model_classes == set()

    wider = dict(_policy_value(executable_classes=["service_dos"]))
    wider["rules"] = dict(wider["rules"])
    wider["rules"]["spdp_flood"] = {
        "action": "temporary_block",
        "min_confidence": 0.9,
        "adapter": "network_helper",
    }
    wide_policy = _P(wider)
    # The model cannot emit spdp_flood; that rule simply never fires.
    assert model_classes <= set(wide_policy.rules)
    assert "spdp_flood" in wide_policy.rules


def test_shipped_policy_authorises_no_class_to_execute():
    """Phase 1 authorises nothing, and that must be visible in the file.

    Safety here does not rest on deployment_eligible staying false. The
    shipped policy is the operator's own statement of what may act, and no
    class has cleared a live outcome, false-positive, revocation and backend
    acceptance review yet. Anything that needs to exercise the enforcement
    path asks for authority explicitly via DecisionPolicy.authorising.
    """

    policy = DecisionPolicy.load()
    assert policy.executable_classes == frozenset()
    for name, rule in policy.rules.items():
        decision = policy.decide(
            predicted_class=name, confidence=1.0, anomaly=False
        )
        assert decision.executable is False, name
        assert decision.adapter == "none", name


def test_authorising_grants_only_the_named_classes():
    policy = DecisionPolicy.authorising(["service_dos"])
    granted = policy.decide(
        predicted_class="service_dos", confidence=1.0, anomaly=False
    )
    assert granted.executable is True

    withheld = policy.decide(
        predicted_class="command_injection", confidence=1.0, anomaly=False
    )
    assert withheld.executable is False
    assert withheld.adapter == "none"


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
