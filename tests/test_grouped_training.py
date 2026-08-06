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
        choose_reject_threshold,
        split_validation_for_calibration,
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
