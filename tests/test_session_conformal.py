import math

import pytest

from firewall_lab.session_conformal import (
    SESSION_CONFORMAL_SCHEMA,
    SessionMaxConformalCalibrator,
    conformal_resolution,
    grouped_rejection_metrics,
)


def _fit(alpha=0.05, sessions=19):
    scores = []
    groups = []
    for index in range(sessions):
        scores.extend([index / 100.0, index / 100.0 + 0.001])
        groups.extend([f"session_{index:03d}"] * 2)
    return SessionMaxConformalCalibrator.fit(
        scores,
        groups,
        alpha=alpha,
        reference_kind="normality",
    )


def test_session_max_prevents_long_sessions_from_dominating_reference():
    calibrator = SessionMaxConformalCalibrator.fit(
        [0.1] * 100 + [0.9],
        ["long"] * 100 + ["short"],
        alpha=0.5,
        reference_kind="normality",
    )
    assert calibrator.session_maxima == (0.1, 0.9)
    assert calibrator.calibration_sessions == 2


def test_alpha_resolution_requires_enough_sessions():
    with pytest.raises(ValueError, match="at least 19 sessions"):
        _fit(sessions=18)
    calibrator = _fit(sessions=19)
    assert math.isclose(calibrator.minimum_p_value, 0.05)
    assert calibrator.reject([999.0]) == [True]


def test_ties_are_conservative():
    calibrator = _fit(sessions=19)
    maximum = max(calibrator.session_maxima)
    assert calibrator.p_values([maximum])[0] > calibrator.minimum_p_value
    assert calibrator.reject([maximum]) == [False]


def test_holdout_overlap_is_rejected_without_storing_plain_group_ids():
    calibrator = _fit()
    calibrator.assert_holdout_disjoint(["new_session"])
    with pytest.raises(ValueError, match="overlap"):
        calibrator.assert_holdout_disjoint(["session_003"])
    contract = calibrator.to_contract()
    assert contract["schema_version"] == SESSION_CONFORMAL_SCHEMA
    assert contract["calibration_sessions"] == 19
    assert "session_003" not in str(contract)
    assert contract["development_only"] is True
    assert contract["deployment_eligible"] is False
    assert contract["automatic_ip_block_authorized"] is False


@pytest.mark.parametrize(
    "scores,groups,alpha,match",
    [
        ([True], ["a"], 0.5, "numbers"),
        ([float("nan")], ["a"], 0.5, "finite"),
        ([0.1], [""], 0.5, "group_ids"),
        ([0.1], ["a"], True, "alpha"),
        ([0.1], ["a"], 0.0, "alpha"),
    ],
)
def test_invalid_inputs_fail_closed(scores, groups, alpha, match):
    with pytest.raises(ValueError, match=match):
        SessionMaxConformalCalibrator.fit(
            scores,
            groups,
            alpha=alpha,
            reference_kind="normality",
        )


def test_grouped_metrics_report_window_and_any_window_units():
    metrics = grouped_rejection_metrics(
        [False, True, False, False], ["a", "a", "b", "b"]
    )
    assert metrics["rows"] == 4
    assert metrics["sessions"] == 2
    assert metrics["session_equal_window_rejection_rate"] == 0.25
    assert metrics["any_window_session_rejection_rate"] == 0.5


def test_grouped_metrics_refuse_non_boolean_flags():
    with pytest.raises(ValueError, match="booleans"):
        grouped_rejection_metrics([0, 1], ["a", "b"])


def test_finite_sample_resolution_reports_exact_deficit():
    report = conformal_resolution(0.02, 22)
    assert report["required_sessions"] == 49
    assert report["additional_sessions_required"] == 27
    assert math.isclose(report["minimum_p_value"], 1 / 23)
    assert report["finite_sample_resolution_sufficient"] is False
    assert conformal_resolution(0.05, 19)[
        "finite_sample_resolution_sufficient"
    ] is True


@pytest.mark.parametrize("alpha,sessions", [(True, 10), (0.0, 10), (0.5, True), (0.5, -1)])
def test_finite_sample_resolution_rejects_invalid_inputs(alpha, sessions):
    with pytest.raises(ValueError):
        conformal_resolution(alpha, sessions)
