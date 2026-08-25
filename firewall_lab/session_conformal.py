"""Session-grouped conformal calibration for development-only OOD decisions."""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Sequence


SESSION_CONFORMAL_SCHEMA = "sros2-firewall-session-max-conformal/v1"
REFERENCE_KINDS = frozenset({"normality", "known_attack"})


def conformal_resolution(alpha: float, calibration_sessions: int) -> dict[str, Any]:
    """Return the exact finite-sample resolution and session deficit."""

    if isinstance(alpha, bool) or not isinstance(alpha, (int, float)):
        raise ValueError("alpha must be numeric")
    alpha = float(alpha)
    if not math.isfinite(alpha) or not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")
    if (
        isinstance(calibration_sessions, bool)
        or not isinstance(calibration_sessions, int)
        or calibration_sessions < 0
    ):
        raise ValueError("calibration_sessions must be a non-negative integer")
    required = max(1, math.ceil(1.0 / alpha) - 1)
    minimum_p = 1.0 / (calibration_sessions + 1)
    return {
        "alpha": alpha,
        "calibration_sessions": calibration_sessions,
        "minimum_p_value": minimum_p,
        "required_sessions": required,
        "additional_sessions_required": max(0, required - calibration_sessions),
        "finite_sample_resolution_sufficient": calibration_sessions >= required,
    }


def _finite_scores(values: Iterable[Any], field: str) -> list[float]:
    result: list[float] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{field} must contain only numbers")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ValueError(f"{field} must contain only finite numbers")
        result.append(numeric)
    if not result:
        raise ValueError(f"{field} must be non-empty")
    return result


def _groups(values: Iterable[Any], expected: int) -> list[str]:
    result = []
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError("group_ids must contain bounded non-empty strings")
        result.append(value)
    if len(result) != expected:
        raise ValueError("scores and group_ids must align")
    return result


@dataclass(frozen=True)
class SessionMaxConformalCalibrator:
    """Conservative conformal p-values using one maximum per calibration session.

    Inputs are nonconformity scores where larger means more anomalous.  Taking
    each session's maximum prevents a long session with many windows from
    dominating the empirical reference and controls the any-window alarm unit.
    Ties use ``>=`` in the numerator, producing conservative p-values.
    """

    alpha: float
    reference_kind: str
    session_maxima: tuple[float, ...]
    calibration_group_hashes: frozenset[str]
    calibration_group_set_sha256: str

    @classmethod
    def fit(
        cls,
        nonconformity_scores: Sequence[Any],
        group_ids: Sequence[Any],
        *,
        alpha: float,
        reference_kind: str,
        minimum_sessions: int | None = None,
    ) -> "SessionMaxConformalCalibrator":
        if isinstance(alpha, bool) or not isinstance(alpha, (int, float)):
            raise ValueError("alpha must be numeric")
        alpha = float(alpha)
        if not math.isfinite(alpha) or not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        if reference_kind not in REFERENCE_KINDS:
            raise ValueError("reference_kind must be normality or known_attack")
        scores = _finite_scores(nonconformity_scores, "nonconformity_scores")
        groups = _groups(group_ids, len(scores))
        by_group: dict[str, list[float]] = defaultdict(list)
        for group, score in zip(groups, scores):
            by_group[group].append(score)
        resolution_minimum = max(1, math.ceil(1.0 / alpha) - 1)
        if minimum_sessions is None:
            minimum_sessions = resolution_minimum
        if (
            isinstance(minimum_sessions, bool)
            or not isinstance(minimum_sessions, int)
            or minimum_sessions < resolution_minimum
        ):
            raise ValueError(
                "minimum_sessions cannot be below conformal alpha resolution"
            )
        if len(by_group) < minimum_sessions:
            raise ValueError(
                f"conformal calibration needs at least {minimum_sessions} sessions; "
                f"got {len(by_group)}"
            )
        maxima = tuple(sorted(max(values) for values in by_group.values()))
        group_hashes = frozenset(
            hashlib.sha256(group.encode("utf-8")).hexdigest() for group in by_group
        )
        digest = hashlib.sha256(
            json.dumps(sorted(group_hashes), separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return cls(
            alpha=alpha,
            reference_kind=reference_kind,
            session_maxima=maxima,
            calibration_group_hashes=group_hashes,
            calibration_group_set_sha256=digest,
        )

    @property
    def calibration_sessions(self) -> int:
        return len(self.session_maxima)

    @property
    def minimum_p_value(self) -> float:
        return 1.0 / (self.calibration_sessions + 1)

    def p_values(self, nonconformity_scores: Sequence[Any]) -> list[float]:
        scores = _finite_scores(nonconformity_scores, "nonconformity_scores")
        denominator = self.calibration_sessions + 1
        return [
            (1 + sum(reference >= score for reference in self.session_maxima))
            / denominator
            for score in scores
        ]

    def reject(self, nonconformity_scores: Sequence[Any]) -> list[bool]:
        return [value <= self.alpha for value in self.p_values(nonconformity_scores)]

    def assert_holdout_disjoint(self, group_ids: Sequence[Any]) -> None:
        groups = _groups(group_ids, len(group_ids))
        overlap = {
            hashlib.sha256(group.encode("utf-8")).hexdigest() for group in groups
        } & set(self.calibration_group_hashes)
        if overlap:
            raise ValueError("holdout groups overlap conformal calibration sessions")

    def to_contract(self) -> dict[str, Any]:
        return {
            "schema_version": SESSION_CONFORMAL_SCHEMA,
            "method": "session_max_split_conformal",
            "reference_kind": self.reference_kind,
            "score_direction": "larger_is_more_anomalous",
            "tie_rule": "greater_or_equal_conservative",
            "alpha": self.alpha,
            "calibration_sessions": self.calibration_sessions,
            "minimum_p_value": self.minimum_p_value,
            "calibration_group_set_sha256": self.calibration_group_set_sha256,
            "session_maxima": list(self.session_maxima),
            "development_only": True,
            "independent_final_test": False,
            "deployment_eligible": False,
            "automatic_ip_block_authorized": False,
            "executable": False,
        }


def grouped_rejection_metrics(
    rejected: Sequence[Any], group_ids: Sequence[Any]
) -> dict[str, float | int]:
    if not rejected:
        raise ValueError("rejected must be non-empty")
    flags = []
    for value in rejected:
        if not isinstance(value, bool):
            raise ValueError("rejected must contain booleans")
        flags.append(value)
    groups = _groups(group_ids, len(flags))
    by_group: dict[str, list[bool]] = defaultdict(list)
    for group, flag in zip(groups, flags):
        by_group[group].append(flag)
    session_rates = [sum(values) / len(values) for values in by_group.values()]
    return {
        "rows": len(flags),
        "sessions": len(by_group),
        "session_equal_window_rejection_rate": sum(session_rates) / len(session_rates),
        "any_window_session_rejection_rate": (
            sum(any(values) for values in by_group.values()) / len(by_group)
        ),
    }


__all__ = [
    "REFERENCE_KINDS",
    "SESSION_CONFORMAL_SCHEMA",
    "SessionMaxConformalCalibrator",
    "conformal_resolution",
    "grouped_rejection_metrics",
]
