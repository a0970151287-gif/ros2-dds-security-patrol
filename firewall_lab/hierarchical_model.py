"""Fail-closed hierarchical inference for the SROS2 firewall research model.

This module deliberately does not call the response policy or a network
backend.  A hierarchical candidate must first earn independent final-test,
local-outcome and kernel-backend evidence.  Until then every prediction is an
observe-only alert, even if a serialized estimator or caller asks otherwise.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Mapping, Sequence

from .features import TELEMETRY_FEATURES
from .inference import FEATURE_BOUNDS
from .schema import SECURITY_MODES
from .train import FEATURES, ML_DIR


HIERARCHICAL_MODEL_SCHEMA = "sros2-firewall-hierarchical-model/v2"
HIERARCHICAL_INFERENCE_SCHEMA = "sros2-firewall-hierarchical-inference/v2"
ARCHITECTURE_NAME = "mode_aware_binary_family_ood_v2"
MASK_PREFIX = "source_available__"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_MAX_STREAMS = 4096

RAW_FEATURES = tuple(FEATURES + TELEMETRY_FEATURES)
SOURCE_MASK_FEATURES = tuple(
    f"{MASK_PREFIX}{name}" for name in TELEMETRY_FEATURES
)
DELTA_FEATURES = tuple(f"delta1__{name}" for name in RAW_FEATURES)
ROLLING_MEAN_FEATURES = tuple(f"mean3__{name}" for name in RAW_FEATURES)
ROLLING_MAX_FEATURES = tuple(f"max3__{name}" for name in RAW_FEATURES)
HISTORY_MASK_FEATURES = ("history_available_1", "history_available_2")
EXPANDED_FEATURES = (
    RAW_FEATURES
    + DELTA_FEATURES
    + ROLLING_MEAN_FEATURES
    + ROLLING_MAX_FEATURES
    + SOURCE_MASK_FEATURES
    + HISTORY_MASK_FEATURES
)

# The family layer answers the response-relevant question without forcing a
# weak flat classifier to distinguish every closely related subtype.  The map
# covers every checked-in action-policy class, including classes not present in
# the first live campaign, so future data cannot silently fall through.
FAMILY_BY_LABEL = {
    "normal": "normal",
    "identity_abuse": "participant_deny",
    "node_name_evasion": "participant_deny",
    "parameter_tamper": "participant_deny",
    "cmd_vel_race": "control_lock",
    "command_injection": "control_lock",
    "odom_spoof": "control_lock",
    "scan_drift": "control_lock",
    "cross_channel_relay": "application_drop",
    "health_spoof": "application_drop",
    "hmac_forgery": "application_drop",
    "message_dos": "application_drop",
    "mission_spoof": "application_drop",
    "replay": "application_drop",
    "replay_dos": "application_drop",
    "sensor_spoof": "application_drop",
    "node_churn": "network_block",
    "service_dos": "network_block",
    "spdp_flood": "network_block",
    "verify_flood": "network_block",
    "confused_deputy": "alert_only",
    "discovery_recon": "alert_only",
    "baseline_poisoning": "quarantine",
}
ATTACK_FAMILIES = tuple(sorted(set(FAMILY_BY_LABEL.values()) - {"normal"}))

# Status is specific to the 2026-08-13/14 campaign.  A false value means the
# dataset cannot distinguish "zero events" from "no trustworthy source".  The
# raw value is therefore forced to zero and a separate mask is supplied to the
# estimator.  When a source becomes trustworthy the model must be retrained;
# inference refuses a profile different from the signed bundle.
DEFAULT_LIVE_SOURCE_AVAILABILITY = {
    name: name
    not in {
        "sros_auth_fail_rate",
        "sros_permission_deny_rate",
        "parameter_call_rate",
        "heartbeat_gap_sec",
        "scan_static_ratio",
    }
    for name in TELEMETRY_FEATURES
}


def family_map_sha256() -> str:
    payload = json.dumps(
        FAMILY_BY_LABEL,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def family_for_label(label: str) -> str:
    if not isinstance(label, str) or label not in FAMILY_BY_LABEL:
        raise ValueError(f"unmapped attack label: {label!r}")
    return FAMILY_BY_LABEL[label]


def normalize_policy_sha256(value: object) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("policy_sha256 must be 64 lowercase hexadecimal characters")
    return value


def conditional_leaf_candidate(
    predicted_family: str,
    leaf_classes: Sequence[str],
    leaf_probability: Sequence[float],
) -> tuple[str, float, bool]:
    """Return the runtime leaf candidate conditioned on the family head.

    Training threshold selection imports this exact helper so validation and
    runtime cannot silently use different probability semantics.
    """

    classes = [str(value) for value in leaf_classes]
    probability = [float(value) for value in leaf_probability]
    if len(classes) != len(probability) or len(classes) != len(set(classes)):
        raise ValueError("leaf classes/probabilities are invalid")
    if any(
        not math.isfinite(value) or not 0.0 <= value <= 1.0
        for value in probability
    ):
        raise ValueError("leaf probabilities are invalid")
    by_class = dict(zip(classes, probability))
    family_classes = [
        label for label in classes if family_for_label(label) == predicted_family
    ]
    family_mass = math.fsum(by_class[label] for label in family_classes)
    if not family_classes or family_mass <= 0.0:
        return "unknown_attack", 0.0, False
    conditional = {
        label: by_class[label] / family_mass for label in family_classes
    }
    predicted = max(conditional, key=conditional.get)
    return predicted, float(conditional[predicted]), True


def normalize_source_availability(
    value: Mapping[str, Any],
) -> dict[str, bool]:
    if not isinstance(value, Mapping):
        raise ValueError("source_availability must be a mapping")
    expected = set(TELEMETRY_FEATURES)
    actual = set(value)
    if actual != expected:
        raise ValueError(
            "source_availability must contain exactly the telemetry features; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    normalized: dict[str, bool] = {}
    for name in TELEMETRY_FEATURES:
        available = value[name]
        if not isinstance(available, bool):
            raise ValueError(f"source availability for {name} must be bool")
        normalized[name] = available
    return normalized


def build_expanded_row(
    features: Mapping[str, Any],
    source_availability: Mapping[str, Any],
) -> list[float]:
    """Validate one raw observation and append explicit source masks."""

    if not isinstance(features, Mapping) or set(features) != set(RAW_FEATURES):
        missing = set(RAW_FEATURES) - set(features) if isinstance(features, Mapping) else set(RAW_FEATURES)
        extra = set(features) - set(RAW_FEATURES) if isinstance(features, Mapping) else set()
        raise ValueError(
            "features must contain exactly the 32 raw features; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    availability = normalize_source_availability(source_availability)
    admitted: dict[str, float] = {}
    for name in RAW_FEATURES:
        value = features[name]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError(f"feature {name} must be a finite number")
        numeric = float(value)
        minimum, maximum = FEATURE_BOUNDS[name]
        if not minimum <= numeric <= maximum:
            raise ValueError(f"feature {name} is outside the admitted range")
        if name in availability and not availability[name]:
            if numeric != 0.0:
                raise ValueError(
                    f"feature {name} is non-zero while its source is unavailable"
                )
            numeric = 0.0
        admitted[name] = numeric
    return [admitted[name] for name in RAW_FEATURES] + [
        1.0 if availability[name] else 0.0 for name in TELEMETRY_FEATURES
    ]


def build_temporal_row(
    features: Mapping[str, Any],
    source_availability: Mapping[str, Any],
    *,
    history: Sequence[Mapping[str, Any]] | None = None,
) -> list[float]:
    """Create causal current/delta/rolling features from at most two past rows.

    ``history`` is ordered oldest to newest.  No timestamp or window index is
    used, so a model cannot learn the fixed campaign schedule as a shortcut.
    """

    if history is None:
        history = ()
    if not isinstance(history, Sequence) or isinstance(history, (str, bytes)):
        raise ValueError("history must be a sequence of prior feature mappings")
    if len(history) > 2:
        raise ValueError("history may contain at most the two previous rows")
    current = build_expanded_row(features, source_availability)
    width = len(RAW_FEATURES)
    current_values = current[:width]
    source_masks = current[width:]
    prior_values = [
        build_expanded_row(item, source_availability)[:width]
        for item in history
    ]
    previous = prior_values[-1] if prior_values else None
    delta = [
        value - previous[index] if previous is not None else 0.0
        for index, value in enumerate(current_values)
    ]
    rolling = prior_values[-2:] + [current_values]
    rolling_mean = [
        math.fsum(row[index] for row in rolling) / len(rolling)
        for index in range(width)
    ]
    rolling_max = [
        max(row[index] for row in rolling) for index in range(width)
    ]
    history_masks = [
        1.0 if len(prior_values) >= 1 else 0.0,
        1.0 if len(prior_values) >= 2 else 0.0,
    ]
    result = (
        current_values
        + delta
        + rolling_mean
        + rolling_max
        + source_masks
        + history_masks
    )
    if len(result) != len(EXPANDED_FEATURES):
        raise RuntimeError("temporal feature width mismatch")
    if not all(math.isfinite(value) for value in result):
        raise RuntimeError("temporal feature row contains a non-finite value")
    return result


def _probabilities(estimator: Any, row: list[float], *, name: str) -> tuple[list[str], list[float]]:
    predict_proba = getattr(estimator, "predict_proba", None)
    if not callable(predict_proba):
        raise ValueError(f"{name} must implement predict_proba")
    try:
        classes = [str(value) for value in estimator.classes_]
        probability = [float(value) for value in predict_proba([row])[0]]
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} emitted invalid probabilities") from exc
    if not classes or len(classes) != len(set(classes)):
        raise RuntimeError(f"{name} classes are invalid")
    if len(probability) != len(classes):
        raise RuntimeError(f"{name} probability shape mismatch")
    if any(
        not math.isfinite(value) or not 0.0 <= value <= 1.0
        for value in probability
    ):
        raise RuntimeError(f"{name} probabilities are invalid")
    if not math.isclose(math.fsum(probability), 1.0, abs_tol=1e-6):
        raise RuntimeError(f"{name} probabilities must sum to one")
    return classes, probability


def validate_hierarchical_bundle(bundle: Any) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        raise ValueError("hierarchical model bundle must be a dictionary")
    if bundle.get("schema_version") != HIERARCHICAL_MODEL_SCHEMA:
        raise ValueError("unsupported hierarchical model schema")
    if bundle.get("architecture") != ARCHITECTURE_NAME:
        raise ValueError("unsupported hierarchical architecture")
    if bundle.get("raw_features") != list(RAW_FEATURES):
        raise ValueError("hierarchical raw feature order mismatch")
    if bundle.get("expanded_features") != list(EXPANDED_FEATURES):
        raise ValueError("hierarchical expanded feature order mismatch")
    if bundle.get("family_map_sha256") != family_map_sha256():
        raise ValueError("attack-family taxonomy does not match runtime")
    data_policy_sha256 = normalize_policy_sha256(bundle.get("data_policy_sha256"))
    action_policy_sha256 = normalize_policy_sha256(
        bundle.get("action_policy_sha256")
    )
    if bundle.get("security_mode") not in SECURITY_MODES:
        raise ValueError("hierarchical model security_mode is invalid")
    availability = normalize_source_availability(
        bundle.get("source_availability", {})
    )
    for estimator_name in (
        "binary_classifier",
        "family_classifier",
        "leaf_classifier",
        "normality_detector",
        "attack_ood_detector",
    ):
        if bundle.get(estimator_name) is None:
            raise ValueError(f"hierarchical bundle is missing {estimator_name}")
    binary_classes = {
        str(value) for value in getattr(bundle["binary_classifier"], "classes_", [])
    }
    if binary_classes != {"normal", "attack"}:
        raise ValueError("binary classifier must contain normal and attack")
    family_classes = [
        str(value) for value in getattr(bundle["family_classifier"], "classes_", [])
    ]
    if (
        len(family_classes) < 2
        or len(family_classes) != len(set(family_classes))
        or not set(family_classes) <= set(ATTACK_FAMILIES)
    ):
        raise ValueError("family classifier classes are invalid")
    leaf_classes = [
        str(value) for value in getattr(bundle["leaf_classifier"], "classes_", [])
    ]
    if (
        len(leaf_classes) < 2
        or len(leaf_classes) != len(set(leaf_classes))
        or "normal" in leaf_classes
        or not set(leaf_classes) <= set(FAMILY_BY_LABEL)
    ):
        raise ValueError("leaf classifier classes are invalid")
    for field in ("binary_threshold", "family_threshold", "leaf_threshold"):
        value = bundle.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not 0.0 <= float(value) <= 1.0
        ):
            raise ValueError(f"{field} must be finite and in 0..1")
    for field in ("normality_threshold", "attack_ood_threshold"):
        threshold = bundle.get(field)
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(float(threshold))
        ):
            raise ValueError(f"{field} must be finite")
    training = bundle.get("training")
    if not isinstance(training, dict):
        raise ValueError("hierarchical training metadata is missing")
    # V1 is intentionally an observe-only candidate.  Refuse metadata that
    # tries to turn this loader into an enforcement bypass.
    if training.get("deployment_eligible") is not False:
        raise ValueError("hierarchical candidate must not be deployment eligible")
    if training.get("independent_final_test") is not False:
        raise ValueError("hierarchical candidate has no independent final test")
    if training.get("executable") is not False:
        raise ValueError("hierarchical candidate must be non-executable")
    holdout = training.get("novelty_holdout_labels")
    supervised = training.get("supervised_train_labels")
    if not isinstance(holdout, list) or not all(isinstance(v, str) for v in holdout):
        raise ValueError("novelty holdout labels are invalid")
    if not isinstance(supervised, list) or not all(
        isinstance(v, str) for v in supervised
    ):
        raise ValueError("supervised train labels are invalid")
    if set(holdout) & set(supervised):
        raise ValueError("novelty holdout leaked into supervised training")
    bundle = dict(bundle)
    bundle["source_availability"] = availability
    bundle["data_policy_sha256"] = data_policy_sha256
    bundle["action_policy_sha256"] = action_policy_sha256
    return bundle


class HierarchicalFirewallModel:
    """Authenticated, observe-only runtime for a hierarchical candidate."""

    def __init__(
        self,
        model_path: str | Path,
        *,
        data_policy_sha256: str,
        action_policy_sha256: str,
        secret: bytes | None = None,
        max_streams: int = DEFAULT_MAX_STREAMS,
    ) -> None:
        sys.path.insert(0, str(ML_DIR))
        try:
            from ml_utils import verified_joblib_load
        finally:
            sys.path.remove(str(ML_DIR))
        bundle = verified_joblib_load(model_path, secret=secret)
        self._load_bundle(
            bundle,
            data_policy_sha256=data_policy_sha256,
            action_policy_sha256=action_policy_sha256,
            max_streams=max_streams,
        )

    @classmethod
    def _from_bundle_for_testing(
        cls,
        bundle: dict[str, Any],
        *,
        data_policy_sha256: str,
        action_policy_sha256: str,
        max_streams: int = DEFAULT_MAX_STREAMS,
    ) -> "HierarchicalFirewallModel":
        """Construct from an in-memory bundle only for unit tests.

        Production callers must use ``__init__`` so HMAC verification happens
        before joblib deserialization.
        """

        instance = cls.__new__(cls)
        instance._load_bundle(
            bundle,
            data_policy_sha256=data_policy_sha256,
            action_policy_sha256=action_policy_sha256,
            max_streams=max_streams,
        )
        return instance

    def _load_bundle(
        self,
        bundle: dict[str, Any],
        *,
        data_policy_sha256: str,
        action_policy_sha256: str,
        max_streams: int,
    ) -> None:
        value = validate_hierarchical_bundle(bundle)
        current_data_policy = normalize_policy_sha256(data_policy_sha256)
        current_action_policy = normalize_policy_sha256(action_policy_sha256)
        if value["data_policy_sha256"] != current_data_policy:
            raise ValueError("current data/SROS2 policy does not match signed model")
        if value["action_policy_sha256"] != current_action_policy:
            raise ValueError("current action policy does not match signed model")
        if isinstance(max_streams, bool) or not isinstance(max_streams, int):
            raise ValueError("max_streams must be an integer")
        if not 1 <= max_streams <= 65536:
            raise ValueError("max_streams must be in 1..65536")
        self.bundle = value
        self.binary_classifier = value["binary_classifier"]
        self.family_classifier = value["family_classifier"]
        self.leaf_classifier = value["leaf_classifier"]
        self.normality_detector = value["normality_detector"]
        self.attack_ood_detector = value["attack_ood_detector"]
        self.binary_threshold = float(value["binary_threshold"])
        self.family_threshold = float(value["family_threshold"])
        self.leaf_threshold = float(value["leaf_threshold"])
        self.normality_threshold = float(value["normality_threshold"])
        self.attack_ood_threshold = float(value["attack_ood_threshold"])
        self.security_mode = str(value["security_mode"])
        self.source_availability = dict(value["source_availability"])
        self.data_policy_sha256 = current_data_policy
        self.action_policy_sha256 = current_action_policy
        self.max_streams = max_streams
        self._streams: OrderedDict[
            tuple[str, str], tuple[int, list[dict[str, float]]]
        ] = OrderedDict()

    def predict(
        self,
        features: Mapping[str, Any],
        *,
        security_mode: str,
        source_availability: Mapping[str, Any],
        session_id: str,
        source: str,
        window: int,
    ) -> dict[str, Any]:
        """Predict one causally ordered stream observation.

        History is owned by the runtime and keyed by ``(session_id, source)``;
        callers cannot inject naked prior rows from a different identity.
        """

        if (
            not isinstance(session_id, str)
            or not session_id
            or session_id in {".", ".."}
            or Path(session_id).name != session_id
        ):
            raise ValueError("session_id must be a safe basename")
        if (
            not isinstance(source, str)
            or not source
            or len(source) > 255
            or any(ord(character) < 32 for character in source)
        ):
            raise ValueError("source identity is invalid")
        if isinstance(window, bool) or not isinstance(window, int) or window < 0:
            raise ValueError("window must be a non-negative integer")
        key = (session_id, source)
        state = self._streams.get(key)
        if state is None:
            if len(self._streams) >= self.max_streams:
                raise RuntimeError("stream capacity reached; prediction refused")
            history: list[dict[str, float]] = []
        else:
            last_window, history = state
            if window != last_window + 1:
                self._streams.pop(key, None)
                if window > last_window + 1:
                    # Treat the current row as a new cold-start anchor, but do
                    # not emit a model decision for a discontinuous sequence.
                    build_expanded_row(features, source_availability)
                    self._streams[key] = (window, [dict(features)])
                raise ValueError("stream window is not contiguous; history reset")

        result = self._predict_with_history(
            features,
            security_mode=security_mode,
            source_availability=source_availability,
            history=history,
        )
        next_history = (history + [dict(features)])[-2:]
        self._streams[key] = (window, next_history)
        self._streams.move_to_end(key)
        result["stream"] = {
            "session_id": session_id,
            "source": source,
            "window": window,
            "history_depth": len(history),
            "contiguous": True,
        }
        return result

    def reset_stream(self, *, session_id: str, source: str) -> bool:
        """Remove one stream history at an explicit lifecycle boundary."""

        return self._streams.pop((session_id, source), None) is not None

    def _predict_with_history(
        self,
        features: Mapping[str, Any],
        *,
        security_mode: str,
        source_availability: Mapping[str, Any],
        history: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        if security_mode != self.security_mode:
            raise ValueError(
                "security_mode does not match this mode-specific model"
            )
        availability = normalize_source_availability(source_availability)
        if availability != self.source_availability:
            raise ValueError(
                "source availability differs from the signed training profile; "
                "retraining is required"
            )
        row = build_temporal_row(
            features,
            availability,
            history=history,
        )
        binary_classes, binary_probability = _probabilities(
            self.binary_classifier, row, name="binary classifier"
        )
        binary_by_class = dict(zip(binary_classes, binary_probability))
        attack_probability = binary_by_class["attack"]

        family_classes, family_probability = _probabilities(
            self.family_classifier, row, name="family classifier"
        )
        family_by_class = dict(zip(family_classes, family_probability))
        family_index = max(
            range(len(family_probability)), key=family_probability.__getitem__
        )
        predicted_family = family_classes[family_index]
        family_confidence = family_probability[family_index]

        leaf_classes, leaf_probability = _probabilities(
            self.leaf_classifier, row, name="leaf classifier"
        )
        leaf_by_class = dict(zip(leaf_classes, leaf_probability))
        predicted_leaf, leaf_confidence, hierarchy_consistent = (
            conditional_leaf_candidate(
                predicted_family,
                leaf_classes,
                leaf_probability,
            )
        )

        scores: dict[str, float] = {}
        for name, detector in (
            ("normality", self.normality_detector),
            ("attack_ood", self.attack_ood_detector),
        ):
            score_samples = getattr(detector, "score_samples", None)
            if not callable(score_samples):
                raise ValueError(f"{name} detector must implement score_samples")
            try:
                score = float(score_samples([row])[0])
            except (IndexError, TypeError, ValueError, OverflowError) as exc:
                raise RuntimeError(f"{name} detector emitted an invalid score") from exc
            if not math.isfinite(score):
                raise RuntimeError(f"{name} detector score must be finite")
            scores[name] = score
        abnormal_vs_normal = scores["normality"] < self.normality_threshold
        unknown_vs_known_attack = scores["attack_ood"] < self.attack_ood_threshold
        binary_attack = attack_probability >= self.binary_threshold

        if binary_attack and unknown_vs_known_attack:
            status = "unknown_attack"
            output_family = "unknown"
            output_leaf = "unknown_attack"
            reason = "known-attack OOD head rejected the observation"
        elif (
            binary_attack
            and family_confidence >= self.family_threshold
            and leaf_confidence >= self.leaf_threshold
            and hierarchy_consistent
        ):
            status = "known_attack"
            output_family = predicted_family
            output_leaf = predicted_leaf
            reason = "binary, family and conditional leaf heads agreed"
        elif binary_attack:
            status = "abstained_attack"
            output_family = "unknown"
            output_leaf = "unknown_attack"
            reason = "binary gate detected attack but the hierarchy abstained"
        elif abnormal_vs_normal:
            status = "abstained_anomaly"
            output_family = "unknown"
            output_leaf = "unknown_attack"
            reason = "normality detector disagreed with the binary gate"
        else:
            status = "normal"
            output_family = "normal"
            output_leaf = "normal"
            reason = "binary gate remained below its validation-only threshold"

        return {
            "schema_version": HIERARCHICAL_INFERENCE_SCHEMA,
            "architecture": ARCHITECTURE_NAME,
            "security_mode": self.security_mode,
            "status": status,
            "attack_probability": attack_probability,
            "binary_threshold": self.binary_threshold,
            "predicted_family": output_family,
            "family_candidate": predicted_family,
            "family_confidence": family_confidence,
            "family_threshold": self.family_threshold,
            "predicted_class": output_leaf,
            "leaf_candidate": predicted_leaf,
            "leaf_conditional_confidence": leaf_confidence,
            "leaf_threshold": self.leaf_threshold,
            "hierarchy_consistent": hierarchy_consistent,
            "abnormal_vs_normal": abnormal_vs_normal,
            "normality_score": scores["normality"],
            "normality_threshold": self.normality_threshold,
            "unknown_vs_known_attack": unknown_vs_known_attack,
            "attack_ood_score": scores["attack_ood"],
            "attack_ood_threshold": self.attack_ood_threshold,
            "binary_probabilities": binary_by_class,
            "family_probabilities": family_by_class,
            "leaf_probabilities": leaf_by_class,
            "decision": {
                "action": "alert",
                "adapter": "none",
                "executable": False,
                "reason": (
                    f"{reason}; hierarchical v1 is observe-only until an "
                    "independent final test and live acceptance pass"
                ),
            },
        }
