"""Authenticated model inference for the SROS2 firewall control plane."""

from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Any

from .decision import DecisionPolicy, FirewallDecision
from .features import TELEMETRY_FEATURES
from .schema import sha256_file
from .train import FEATURES, MODEL_SCHEMA_VERSION


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
ML_DIR = WORKSPACE_ROOT / "ML防禦"
FEATURE_BOUNDS = {
    "conn_count": (0.0, 1_000_000.0),
    "conn_rate": (0.0, 1_000_000.0),
    "uniq_dst_ports": (0.0, 65_536.0),
    "uniq_dst_hosts": (0.0, 65_536.0),
    "spdp_ratio": (0.0, 1.0),
    "meta_ratio": (0.0, 1.0),
    "userdata_ratio": (0.0, 1.0),
    "mcast_ratio": (0.0, 1.0),
    "dst_port_entropy": (0.0, 16.0),
    "interarrival_cv": (0.0, 1_000_000.0),
    "burstiness": (-1.0, 1.0),
    "dominant_port_ratio": (0.0, 1.0),
    "dominant_host_ratio": (0.0, 1.0),
    "tuple_repeat_ratio": (0.0, 1.0),
    "sros_auth_fail_rate": (0.0, 1_000_000.0),
    "sros_permission_deny_rate": (0.0, 1_000_000.0),
    "participant_churn_rate": (0.0, 1_000_000.0),
    "unknown_node_rate": (0.0, 1_000_000.0),
    "hmac_failure_rate": (0.0, 1_000_000.0),
    "nonce_reuse_ratio": (0.0, 1.0),
    "channel_mismatch_ratio": (0.0, 1.0),
    "timestamp_violation_ratio": (0.0, 1.0),
    "publisher_violation_ratio": (0.0, 1.0),
    "parameter_call_rate": (0.0, 1_000_000.0),
    "oversized_message_ratio": (0.0, 1.0),
    "qos_drop_ratio": (0.0, 1.0),
    "heartbeat_gap_sec": (0.0, 1_000_000.0),
    "control_conflict_ratio": (0.0, 1.0),
    "scan_static_ratio": (0.0, 1.0),
    "odom_cmd_mismatch_ratio": (0.0, 1.0),
    "alert_reflection_ratio": (0.0, 1.0),
    "log_reject_rate": (0.0, 1_000_000.0),
}
ALLOWED_FEATURE_ORDERS = (
    list(FEATURES),
    list(TELEMETRY_FEATURES),
    list(FEATURES + TELEMETRY_FEATURES),
)


class FirewallModel:
    def __init__(
        self,
        model_path: str | Path,
        *,
        action_policy_path: str | Path | None = None,
    ):
        sys.path.insert(0, str(ML_DIR))
        try:
            from ml_utils import verified_joblib_load
        finally:
            sys.path.remove(str(ML_DIR))
        bundle = verified_joblib_load(model_path)
        if not isinstance(bundle, dict):
            raise ValueError("firewall model bundle must be a dict")
        if bundle.get("schema_version") != MODEL_SCHEMA_VERSION:
            raise ValueError("unsupported firewall model schema")
        model_features = bundle.get("features")
        if model_features not in ALLOWED_FEATURE_ORDERS:
            raise ValueError("firewall model feature order mismatch")
        if not isinstance(bundle.get("classes"), list) or not bundle["classes"]:
            raise ValueError("firewall model classes are missing")
        classifier = bundle.get("classifier")
        anomaly = bundle.get("anomaly_detector")
        if not callable(getattr(classifier, "predict_proba", None)):
            raise ValueError("firewall classifier is invalid")
        if not callable(getattr(anomaly, "predict", None)):
            raise ValueError("firewall anomaly detector is invalid")
        classifier_classes = getattr(classifier, "classes_", None)
        try:
            normalized_classifier_classes = [
                str(value) for value in classifier_classes
            ]
        except TypeError as exc:
            raise ValueError("firewall classifier classes are invalid") from exc
        bundle_classes = [str(value) for value in bundle["classes"]]
        if (
            not normalized_classifier_classes
            or len(set(normalized_classifier_classes))
            != len(normalized_classifier_classes)
            or normalized_classifier_classes != bundle_classes
        ):
            raise ValueError("firewall classifier classes do not match bundle")
        training = bundle.get("training")
        if not isinstance(training, dict):
            raise ValueError("firewall model training metadata is missing")
        deployment_eligible = training.get("deployment_eligible")
        if not isinstance(deployment_eligible, bool):
            raise ValueError("model deployment eligibility is invalid")
        reject_threshold = training.get("reject_threshold", 0.0)
        if (
            isinstance(reject_threshold, bool)
            or not isinstance(reject_threshold, (int, float))
            or not math.isfinite(float(reject_threshold))
            or not 0.0 <= float(reject_threshold) <= 1.0
        ):
            raise ValueError("model reject threshold is invalid")
        policy_path = (
            Path(action_policy_path)
            if action_policy_path is not None
            else Path(__file__).with_name("action_policy.json")
        )
        expected_policy_sha256 = training.get("action_policy_sha256")
        if (
            not isinstance(expected_policy_sha256, str)
            or len(expected_policy_sha256) != 64
            or expected_policy_sha256 != sha256_file(policy_path)
        ):
            raise ValueError("action policy integrity does not match model")
        policy = DecisionPolicy.load(policy_path)
        if set(bundle_classes) != set(policy.rules):
            raise ValueError("model classes are not exactly covered by action policy")

        self.bundle = bundle
        self.classifier = classifier
        self.anomaly_detector = anomaly
        self.features = list(model_features)
        self.classes = bundle_classes
        self.policy = policy
        self.deployment_eligible = deployment_eligible
        self.reject_threshold = float(reject_threshold)
        self.policy_verified = True

    def predict(self, features: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(features, dict) or set(features) != set(self.features):
            raise ValueError(
                f"features must contain exactly {self.features}"
            )
        row = []
        for name in self.features:
            value = features[name]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                raise ValueError(f"feature {name} must be finite")
            numeric = float(value)
            minimum, maximum = FEATURE_BOUNDS[name]
            if not minimum <= numeric <= maximum:
                raise ValueError(
                    f"feature {name} is outside the admitted range"
                )
            row.append(numeric)
        try:
            probability = [
                float(value)
                for value in self.classifier.predict_proba([row])[0]
            ]
        except (IndexError, TypeError, ValueError) as exc:
            raise RuntimeError("classifier emitted invalid probability") from exc
        if len(probability) != len(self.classes):
            raise RuntimeError("classifier probability shape mismatch")
        if any(
            not math.isfinite(value) or not 0.0 <= value <= 1.0
            for value in probability
        ):
            raise RuntimeError("classifier emitted invalid probability")
        if not math.isclose(math.fsum(probability), 1.0, abs_tol=1e-6):
            raise RuntimeError("classifier probabilities must sum to 1")
        best_index = max(range(len(probability)), key=probability.__getitem__)
        predicted_class = self.classes[best_index]
        confidence = probability[best_index]
        try:
            anomaly_value = int(self.anomaly_detector.predict([row])[0])
        except (IndexError, TypeError, ValueError, OverflowError) as exc:
            raise RuntimeError("anomaly detector emitted invalid prediction") from exc
        if anomaly_value not in {-1, 1}:
            raise RuntimeError("anomaly detector prediction must be -1 or 1")
        anomaly = anomaly_value == -1
        decision = self.policy.decide(
            predicted_class=predicted_class,
            confidence=confidence,
            anomaly=anomaly,
        )
        if confidence < self.reject_threshold:
            decision = FirewallDecision(
                predicted_class=predicted_class,
                confidence=confidence,
                anomaly=anomaly,
                action="alert",
                adapter="none",
                executable=False,
                reason=(
                    "model confidence is below the validation-only reject "
                    "threshold"
                ),
                evidence_id="",
            )
        if not self.deployment_eligible and decision.executable:
            decision = FirewallDecision(
                predicted_class=predicted_class,
                confidence=confidence,
                anomaly=anomaly,
                action="alert",
                adapter="none",
                executable=False,
                reason="model is not deployment eligible; offline observation only",
                evidence_id="",
            )
        return {
            "schema_version": "sros2-firewall-inference/v1",
            "predicted_class": predicted_class,
            "confidence": confidence,
            "anomaly": anomaly,
            "probabilities": {
                str(label): float(value)
                for label, value in zip(
                    self.classes, probability
                )
            },
            "decision": decision.to_dict(),
        }
