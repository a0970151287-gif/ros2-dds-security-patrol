from __future__ import annotations

import pytest

try:
    import numpy as np
    import pandas as pd
except ModuleNotFoundError:
    np = None
    pd = None

pytestmark = pytest.mark.skipif(
    np is None or pd is None,
    reason="grouped ML tests require numpy and pandas",
)

if np is not None and pd is not None:
    from firewall_lab.grouped_training import (
        DEFAULT_ANOMALY_FEATURE_SET,
        DEFAULT_ANOMALY_NORMAL_FPR,
        FEATURE_SETS,
        MAX_DEPLOYMENT_ANOMALY_FPR,
        choose_reject_threshold,
        split_validation_for_calibration,
        train_grouped_model,
        validate_preassigned_split,
    )


def _split_frame():
    rows = []
    for split in ("train", "validation", "test"):
        sessions = 4 if split == "validation" else 2
        for label in ("normal", "service_dos"):
            for session in range(sessions):
                group = f"{split}_{label}_{session}"
                for window in range(2):
                    rows.append(
                        {
                            "group_id": group,
                            "label": label,
                            "split": split,
                            "window": window,
                        }
                    )
    return pd.DataFrame(rows)


def test_preassigned_split_is_session_disjoint():
    frame = _split_frame()
    split = validate_preassigned_split(frame)
    groups = {
        name: set(frame.iloc[index]["group_id"])
        for name, index in split.items()
    }
    assert groups["train"].isdisjoint(groups["validation"])
    assert groups["train"].isdisjoint(groups["test"])
    assert groups["validation"].isdisjoint(groups["test"])


def test_preassigned_split_rejects_same_session_in_two_splits():
    frame = _split_frame()
    frame.loc[frame.index[-1], "group_id"] = frame.iloc[0]["group_id"]
    with pytest.raises(ValueError, match="session leakage"):
        validate_preassigned_split(frame)


def test_preassigned_split_allows_normal_and_attack_windows_in_one_session():
    frame = _split_frame()
    attack_row = frame[
        (frame["split"] == "train") & (frame["label"] == "service_dos")
    ].index[0]
    normal_group = frame[
        (frame["split"] == "train") & (frame["label"] == "normal")
    ].iloc[0]["group_id"]
    frame.loc[attack_row, "group_id"] = normal_group
    split = validate_preassigned_split(frame)
    assert len(split["train"]) > 0


def test_calibration_and_threshold_subsets_are_session_disjoint():
    frame = _split_frame()
    split = validate_preassigned_split(frame)
    calibration, threshold = split_validation_for_calibration(
        frame,
        split["validation"],
        seed=42,
    )
    calibration_groups = set(frame.iloc[calibration]["group_id"])
    threshold_groups = set(frame.iloc[threshold]["group_id"])
    assert calibration_groups
    assert threshold_groups
    assert calibration_groups.isdisjoint(threshold_groups)
    assert set(frame.iloc[calibration]["label"]) == {"normal", "service_dos"}
    assert set(frame.iloc[threshold]["label"]) == {"normal", "service_dos"}


def test_reject_threshold_uses_precision_and_normal_fpr_constraints():
    classes = ["normal", "service_dos"]
    y = np.array(["normal", "normal", "service_dos", "service_dos"])
    probability = np.array(
        [
            [0.99, 0.01],
            [0.49, 0.51],
            [0.01, 0.99],
            [0.20, 0.80],
        ]
    )
    selected = choose_reject_threshold(
        y,
        probability,
        classes,
        minimum_attack_precision=1.0,
        maximum_normal_fpr=0.0,
    )
    assert selected["constraints_satisfied"] is True
    assert selected["threshold"] > 0.51
    assert selected["attack_precision"] == 1.0
    assert selected["normal_fpr"] == 0.0


def test_anomaly_defaults_are_telemetry_and_inside_the_deployment_gate():
    """Pin the two defaults the live unknown-attack result depends on.

    Network features gave 0.055 unknown recall on live Permissive data and
    telemetry gave 0.616; the second number also needs most of the false-
    positive allowance, so a silent revert to a small budget would quietly
    undo the fix while every test still passed.
    """

    assert DEFAULT_ANOMALY_FEATURE_SET == "telemetry"
    assert DEFAULT_ANOMALY_FEATURE_SET in FEATURE_SETS
    assert 0.0 < DEFAULT_ANOMALY_NORMAL_FPR <= MAX_DEPLOYMENT_ANOMALY_FPR


@pytest.mark.parametrize(
    "kwargs",
    (
        {"anomaly_feature_set": "not_a_feature_set"},
        {"anomaly_normal_fpr": 0.0},
        {"anomaly_normal_fpr": MAX_DEPLOYMENT_ANOMALY_FPR + 0.001},
    ),
)
def test_training_refuses_an_anomaly_budget_beyond_the_gate(tmp_path, kwargs):
    """A budget above the gate would produce a model that cannot ever pass."""

    with pytest.raises(ValueError):
        train_grouped_model(
            feature_csv=tmp_path / "missing.csv",
            output_dir=tmp_path / "out",
            data_tier="live",
            **kwargs,
        )
