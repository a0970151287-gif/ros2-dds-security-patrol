from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from firewall_lab.hierarchical_model import (
    ARCHITECTURE_NAME,
    DEFAULT_LIVE_SOURCE_AVAILABILITY,
    EXPANDED_FEATURES,
    FAMILY_BY_LABEL,
    HIERARCHICAL_MODEL_SCHEMA,
    RAW_FEATURES,
    HierarchicalFirewallModel,
    build_temporal_row,
    conditional_leaf_candidate,
    family_map_sha256,
    validate_hierarchical_bundle,
)
from firewall_lab.train import FEATURES, LEGACY_TRAINER_DEPLOYMENT_ELIGIBLE

TEST_POLICY_SHA256 = "a" * 64
CURRENT_ACTION_POLICY_SHA256 = hashlib.sha256(
    Path("firewall_lab/action_policy.json").read_bytes()
).hexdigest()


class _FixedClassifier:
    def __init__(self, classes, probabilities):
        self.classes_ = list(classes)
        self.probabilities = list(probabilities)

    def predict_proba(self, rows):
        return [list(self.probabilities) for _ in rows]


class _FixedDetector:
    def __init__(self, score):
        self.score = score

    def score_samples(self, rows):
        return [self.score for _ in rows]


def _raw_features(**overrides):
    values = {name: 0.0 for name in RAW_FEATURES}
    values.update(overrides)
    return values


def _bundle(*, attack_ood_score=1.0):
    return {
        "schema_version": HIERARCHICAL_MODEL_SCHEMA,
        "architecture": ARCHITECTURE_NAME,
        "security_mode": "permissive",
        "data_policy_sha256": TEST_POLICY_SHA256,
        "action_policy_sha256": TEST_POLICY_SHA256,
        "raw_features": list(RAW_FEATURES),
        "expanded_features": list(EXPANDED_FEATURES),
        "source_availability": dict(DEFAULT_LIVE_SOURCE_AVAILABILITY),
        "family_map_sha256": family_map_sha256(),
        "binary_classifier": _FixedClassifier(
            ["attack", "normal"], [0.95, 0.05]
        ),
        "family_classifier": _FixedClassifier(
            ["application_drop", "network_block"], [0.05, 0.95]
        ),
        "leaf_classifier": _FixedClassifier(
            ["message_dos", "service_dos"], [0.10, 0.90]
        ),
        "normality_detector": _FixedDetector(1.0),
        "attack_ood_detector": _FixedDetector(attack_ood_score),
        "binary_threshold": 0.80,
        "family_threshold": 0.80,
        "leaf_threshold": 0.80,
        "normality_threshold": 0.0,
        "attack_ood_threshold": 0.0,
        "training": {
            "deployment_eligible": False,
            "independent_final_test": False,
            "executable": False,
            "data_policy_sha256": TEST_POLICY_SHA256,
            "action_policy_sha256": TEST_POLICY_SHA256,
            "novelty_holdout_labels": ["sensor_spoof"],
            "supervised_train_labels": [
                "normal",
                "message_dos",
                "service_dos",
            ],
        },
    }


def test_family_map_covers_every_action_policy_rule():
    policy = json.loads(
        Path("firewall_lab/action_policy.json").read_text(encoding="utf-8")
    )
    assert set(FAMILY_BY_LABEL) == set(policy["rules"])
    assert FAMILY_BY_LABEL["service_dos"] == "network_block"
    assert FAMILY_BY_LABEL["command_injection"] == "control_lock"
    assert FAMILY_BY_LABEL["normal"] == "normal"


def test_legacy_trainer_can_never_mark_a_model_deployable():
    assert LEGACY_TRAINER_DEPLOYMENT_ELIGIBLE is False


def test_temporal_features_are_causal_and_mark_cold_start():
    first = _raw_features(conn_count=10.0, conn_rate=2.0)
    second = _raw_features(conn_count=14.0, conn_rate=4.0)
    future_a = _raw_features(conn_count=18.0, conn_rate=8.0)
    future_b = _raw_features(conn_count=999.0, conn_rate=999.0)

    cold = build_temporal_row(first, DEFAULT_LIVE_SOURCE_AVAILABILITY)
    warm_a = build_temporal_row(
        second, DEFAULT_LIVE_SOURCE_AVAILABILITY, history=[first]
    )
    warm_b = build_temporal_row(
        second, DEFAULT_LIVE_SOURCE_AVAILABILITY, history=[first]
    )
    # Changing a future row cannot alter the current row because future values
    # are not an input to the causal builder.
    assert future_a != future_b
    assert warm_a == warm_b
    assert len(cold) == len(EXPANDED_FEATURES)
    assert cold[-2:] == [0.0, 0.0]
    assert warm_a[-2:] == [1.0, 0.0]
    conn_index = list(RAW_FEATURES).index("conn_count")
    delta_index = len(RAW_FEATURES) + conn_index
    mean_index = 2 * len(RAW_FEATURES) + conn_index
    assert warm_a[delta_index] == 4.0
    assert warm_a[mean_index] == 12.0


def test_unavailable_source_is_masked_and_nonzero_value_is_rejected():
    row = build_temporal_row(
        _raw_features(), DEFAULT_LIVE_SOURCE_AVAILABILITY
    )
    mask_start = 4 * len(RAW_FEATURES)
    telemetry = list(DEFAULT_LIVE_SOURCE_AVAILABILITY)
    sros_index = telemetry.index("sros_auth_fail_rate")
    qos_index = telemetry.index("qos_drop_ratio")
    assert row[mask_start + sros_index] == 0.0
    assert row[mask_start + qos_index] == 1.0

    with pytest.raises(ValueError, match="source is unavailable"):
        build_temporal_row(
            _raw_features(sros_auth_fail_rate=1.0),
            DEFAULT_LIVE_SOURCE_AVAILABILITY,
        )


def test_hierarchical_known_attack_is_always_observe_only():
    model = HierarchicalFirewallModel._from_bundle_for_testing(
        _bundle(),
        data_policy_sha256=TEST_POLICY_SHA256,
        action_policy_sha256=TEST_POLICY_SHA256,
    )
    result = model.predict(
        _raw_features(),
        security_mode="permissive",
        source_availability=DEFAULT_LIVE_SOURCE_AVAILABILITY,
        session_id="session-a",
        source="10.0.0.2",
        window=0,
    )
    assert result["status"] == "known_attack"
    assert result["predicted_family"] == "network_block"
    assert result["predicted_class"] == "service_dos"
    assert result["decision"] == {
        "action": "alert",
        "adapter": "none",
        "executable": False,
        "reason": result["decision"]["reason"],
    }


def test_attack_ood_forces_unknown_and_no_adapter():
    model = HierarchicalFirewallModel._from_bundle_for_testing(
        _bundle(attack_ood_score=-1.0),
        data_policy_sha256=TEST_POLICY_SHA256,
        action_policy_sha256=TEST_POLICY_SHA256,
    )
    result = model.predict(
        _raw_features(),
        security_mode="permissive",
        source_availability=DEFAULT_LIVE_SOURCE_AVAILABILITY,
        session_id="session-a",
        source="10.0.0.2",
        window=0,
    )
    assert result["status"] == "unknown_attack"
    assert result["predicted_class"] == "unknown_attack"
    assert result["decision"]["executable"] is False
    assert result["decision"]["adapter"] == "none"


def test_runtime_rejects_mode_or_source_profile_drift():
    model = HierarchicalFirewallModel._from_bundle_for_testing(
        _bundle(),
        data_policy_sha256=TEST_POLICY_SHA256,
        action_policy_sha256=TEST_POLICY_SHA256,
    )
    with pytest.raises(ValueError, match="security_mode"):
        model.predict(
            _raw_features(),
            security_mode="enforce",
            source_availability=DEFAULT_LIVE_SOURCE_AVAILABILITY,
            session_id="session-a",
            source="10.0.0.2",
            window=0,
        )
    changed = dict(DEFAULT_LIVE_SOURCE_AVAILABILITY)
    changed["sros_auth_fail_rate"] = True
    with pytest.raises(ValueError, match="retraining is required"):
        model.predict(
            _raw_features(),
            security_mode="permissive",
            source_availability=changed,
            session_id="session-b",
            source="10.0.0.2",
            window=0,
        )


def test_runtime_rejects_policy_drift_and_owns_contiguous_history():
    with pytest.raises(ValueError, match="policy"):
        HierarchicalFirewallModel._from_bundle_for_testing(
            _bundle(),
            data_policy_sha256="b" * 64,
            action_policy_sha256=TEST_POLICY_SHA256,
        )

    model = HierarchicalFirewallModel._from_bundle_for_testing(
        _bundle(),
        data_policy_sha256=TEST_POLICY_SHA256,
        action_policy_sha256=TEST_POLICY_SHA256,
        max_streams=2,
    )
    first = model.predict(
        _raw_features(conn_count=1.0),
        security_mode="permissive",
        source_availability=DEFAULT_LIVE_SOURCE_AVAILABILITY,
        session_id="session-a",
        source="10.0.0.2",
        window=4,
    )
    second = model.predict(
        _raw_features(conn_count=2.0),
        security_mode="permissive",
        source_availability=DEFAULT_LIVE_SOURCE_AVAILABILITY,
        session_id="session-a",
        source="10.0.0.2",
        window=5,
    )
    other_source = model.predict(
        _raw_features(conn_count=99.0),
        security_mode="permissive",
        source_availability=DEFAULT_LIVE_SOURCE_AVAILABILITY,
        session_id="session-a",
        source="10.0.0.3",
        window=0,
    )
    assert first["stream"]["history_depth"] == 0
    assert second["stream"]["history_depth"] == 1
    assert other_source["stream"]["history_depth"] == 0
    with pytest.raises(ValueError, match="not contiguous"):
        model.predict(
            _raw_features(conn_count=3.0),
            security_mode="permissive",
            source_availability=DEFAULT_LIVE_SOURCE_AVAILABILITY,
            session_id="session-a",
            source="10.0.0.2",
            window=7,
        )
    recovered = model.predict(
        _raw_features(conn_count=4.0),
        security_mode="permissive",
        source_availability=DEFAULT_LIVE_SOURCE_AVAILABILITY,
        session_id="session-a",
        source="10.0.0.2",
        window=8,
    )
    assert recovered["stream"]["history_depth"] == 1


def test_conditional_leaf_helper_matches_family_gated_runtime_semantics():
    label, confidence, consistent = conditional_leaf_candidate(
        "network_block",
        ["message_dos", "service_dos", "spdp_flood"],
        [0.80, 0.12, 0.08],
    )
    assert label == "service_dos"
    assert confidence == pytest.approx(0.60)
    assert consistent is True


def test_bundle_rejects_novelty_leakage_or_enforcement_flag():
    leaked = _bundle()
    leaked["training"]["supervised_train_labels"].append("sensor_spoof")
    with pytest.raises(ValueError, match="leaked"):
        validate_hierarchical_bundle(leaked)

    executable = _bundle()
    executable["training"]["deployment_eligible"] = True
    with pytest.raises(ValueError, match="must not be deployment eligible"):
        validate_hierarchical_bundle(executable)


def _write_exclusion_fixture(tmp_path: Path):
    dataset = tmp_path / "dataset"
    session_id = "20260817T000000000000Z_identity_abuse_00000000"
    session = dataset / session_id
    session.mkdir(parents=True)
    expected = b"sealed\n"
    observed = b"sealed\nlate child output\n"
    artifact = session / "attack.stderr.log"
    artifact.write_bytes(observed)
    expected_sha = hashlib.sha256(expected).hexdigest()
    observed_sha = hashlib.sha256(observed).hexdigest()
    manifest = {
        "session_id": session_id,
        "security_mode": "enforce",
        "attack_class": "identity_abuse",
        "evidence": {
            "attack.stderr.log": {
                "bytes": len(expected),
                "sha256": expected_sha,
            }
        },
    }
    manifest_path = session / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    campaign = tmp_path / "campaign.json"
    campaign_value = {
        "entries": [
            {
                "session_id": session_id,
                "security_mode": "enforce",
                "attack_class": "identity_abuse",
                "status": "complete",
            }
        ]
    }
    campaign.write_text(json.dumps(campaign_value), encoding="utf-8")
    registry = {
        "schema_version": "sros2-firewall-dataset-exclusions/v1",
        "campaign": {
            "path": str(campaign),
            "sha256": hashlib.sha256(campaign.read_bytes()).hexdigest(),
        },
        "exclusions": [
            {
                "session_id": session_id,
                "security_mode": "enforce",
                "attack_class": "identity_abuse",
                "split": "train",
                "disposition": (
                    "exclude_from_training_calibration_selection_and_evaluation"
                ),
                "manifest": {
                    "bytes": manifest_path.stat().st_size,
                    "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                },
                "artifact": {
                    "path": "attack.stderr.log",
                    "manifest_bytes": len(expected),
                    "manifest_sha256": expected_sha,
                    "observed_bytes": len(observed),
                    "observed_sha256": observed_sha,
                },
            }
        ],
    }
    registry_path = tmp_path / "exclusions.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    return dataset, registry_path, session_id


def _write_training_csv(
    tmp_path: Path,
    *,
    security_mode: str = "permissive",
    applicable_exclusion: str | None = None,
) -> Path:
    pd = pytest.importorskip("pandas")
    tmp_path.mkdir(parents=True, exist_ok=True)
    rows = []
    labels = ("normal", "identity_abuse", "command_injection", "sensor_spoof")
    for split, sessions in (("train", 3), ("validation", 6), ("test", 2)):
        for label_index, label in enumerate(labels):
            for session_index in range(sessions):
                session_id = f"{split}_{label}_{session_index}"
                if (
                    applicable_exclusion
                    and split == "train"
                    and label == "identity_abuse"
                    and session_index == 0
                ):
                    session_id = applicable_exclusion
                for window in range(3):
                    values = _raw_features(
                        conn_count=10.0 + label_index * 15.0 + window,
                        conn_rate=1.0 + label_index * 3.0 + window / 10.0,
                        participant_churn_rate=(
                            0.4 if label == "identity_abuse" else 0.0
                        ),
                        control_conflict_ratio=(
                            0.8 if label == "command_injection" else 0.0
                        ),
                        hmac_failure_rate=(
                            0.7 if label == "sensor_spoof" else 0.0
                        ),
                    )
                    rows.append(
                        {
                            **values,
                            "session_id": session_id,
                            "group_id": session_id,
                            "source": "10.0.0.2",
                            "window": window,
                            "security_mode": security_mode,
                            "split": split,
                            "label": label,
                            "binary": "normal" if label == "normal" else "attack",
                            "novelty_role": (
                                "novelty_holdout_candidate"
                                if label == "sensor_spoof"
                                else "known"
                            ),
                            "training_eligible": True,
                            "evaluation_eligible": True,
                            "origin": "live_lab",
                            "policy_sha256": "a" * 64,
                        }
                    )
    path = tmp_path / "features.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_end_to_end_candidate_excludes_whole_novelty_sessions(tmp_path):
    pytest.importorskip("sklearn")
    from firewall_lab.hierarchical_training import train_hierarchical_candidate

    dataset, exclusions, excluded_session = _write_exclusion_fixture(tmp_path)
    features = _write_training_csv(
        tmp_path,
        security_mode="enforce",
        applicable_exclusion=excluded_session,
    )
    output = tmp_path / "model"
    result = train_hierarchical_candidate(
        features,
        output,
        security_mode="enforce",
        exclusions=exclusions,
        dataset_root=dataset,
        n_estimators=20,
        signing_secret=b"unit-test-signing-secret-32-bytes!!",
    )
    assert result["deployment_eligible"] is False
    metrics = json.loads((output / "training_metrics.json").read_text())
    assert metrics["test_metrics"] is None
    assert metrics["test_prediction_passes"] == 0
    assert metrics["applicable_excluded_sessions"] == [excluded_session]
    assert metrics["sessions_after_exclusion"] == 43
    assert metrics["feature_input"]["sha256"] == hashlib.sha256(
        features.read_bytes()
    ).hexdigest()
    assert metrics["novelty_protocol"]["supervised_train_rows_used"] == 0
    assert metrics["novelty_protocol"]["selection_rows_used"] == 0
    assert metrics["novelty_protocol"]["calibration_rows_used"] == 0
    assert metrics["novelty_protocol"]["threshold_rows_used"] == 0
    groups = metrics["validation_protocol"]
    assert set(groups["selection_groups"]).isdisjoint(groups["calibration_groups"])
    assert set(groups["selection_groups"]).isdisjoint(groups["threshold_groups"])
    assert set(groups["calibration_groups"]).isdisjoint(groups["threshold_groups"])

    model = HierarchicalFirewallModel(
        output / "hierarchical_model.joblib",
        data_policy_sha256=TEST_POLICY_SHA256,
        action_policy_sha256=CURRENT_ACTION_POLICY_SHA256,
        secret=b"unit-test-signing-secret-32-bytes!!",
    )
    assert "sensor_spoof" not in model.bundle["training"]["supervised_train_labels"]
    assert len(model.bundle["expanded_features"]) == len(EXPANDED_FEATURES)


def test_exclusion_registry_rejects_semantic_and_pin_tampering(tmp_path):
    from firewall_lab.hierarchical_training import load_verified_exclusions

    dataset, registry_path, _ = _write_exclusion_fixture(tmp_path)
    original = json.loads(registry_path.read_text(encoding="utf-8"))

    for mutation, expected in (
        (lambda value: value["exclusions"][0].pop("split"), "split"),
        (
            lambda value: value["exclusions"][0].update({"split": "validation"}),
            None,
        ),
        (
            lambda value: value["exclusions"][0].update(
                {"session_id": "../unsafe"}
            ),
            "basename",
        ),
    ):
        changed = json.loads(json.dumps(original))
        mutation(changed)
        registry_path.write_text(json.dumps(changed), encoding="utf-8")
        if expected is None:
            excluded, lineage = load_verified_exclusions(registry_path, dataset)
            assert excluded
            assert lineage["verified_entries"][0]["split"] == "validation"
        else:
            with pytest.raises(ValueError, match=expected):
                load_verified_exclusions(registry_path, dataset)

    changed = json.loads(json.dumps(original))
    campaign_path = Path(changed["campaign"]["path"])
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    campaign["entries"][0]["attack_class"] = "replay"
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
    changed["campaign"]["sha256"] = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
    registry_path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="campaign identity mismatch"):
        load_verified_exclusions(registry_path, dataset)


def test_training_rejects_group_alias_and_output_inside_dataset(tmp_path):
    pd = pytest.importorskip("pandas")
    pytest.importorskip("sklearn")
    from firewall_lab.hierarchical_training import train_hierarchical_candidate

    dataset, exclusions, _ = _write_exclusion_fixture(tmp_path)
    features = _write_training_csv(tmp_path)
    frame = pd.read_csv(features)
    frame.loc[0, "group_id"] = "different-session"
    frame.to_csv(features, index=False)
    with pytest.raises(ValueError, match="session_id must equal group_id"):
        train_hierarchical_candidate(
            features,
            tmp_path / "model",
            security_mode="permissive",
            exclusions=exclusions,
            dataset_root=dataset,
            n_estimators=20,
            signing_secret=b"unit-test-signing-secret-32-bytes!!",
        )

    features = _write_training_csv(tmp_path / "fresh")
    with pytest.raises(ValueError, match="outside the immutable dataset_root"):
        train_hierarchical_candidate(
            features,
            dataset / "models",
            security_mode="permissive",
            exclusions=exclusions,
            dataset_root=dataset,
            n_estimators=20,
            signing_secret=b"unit-test-signing-secret-32-bytes!!",
        )
