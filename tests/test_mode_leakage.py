"""The mode-leakage gate must catch an arm that is identifiable from features.

Twice the lab shipped a dataset where the security mode was recoverable without
looking at any attack: first because Permissive ran on shared memory while
Enforce was forced onto UDP, then because Enforce contributed a source address
Permissive never produced.  Both were caught by hand.  These tests pin the
automated replacement, including the case that matters most -- a planted leak
must fail, or the gate is decoration.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from firewall_lab.mode_leakage import (
    DEFAULT_MAX_AUC,
    LeakageError,
    measure,
)
from firewall_lab.train import FEATURES

pytest.importorskip("pandas")
pytest.importorskip("sklearn")


def _write(path: Path, rows: list[dict]) -> Path:
    columns = [
        "session_id",
        "scenario_id",
        "security_mode",
        "window",
        *FEATURES,
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _rows(*, mode: str, scenarios: list[str], sessions_per_scenario: int,
          windows: int, offset: float, rng) -> list[dict]:
    """Feature rows whose distribution depends on the scenario, never the mode.

    Each feature is drawn independently with its own scenario-specific mean, so
    the columns are not collinear; a generator where every column is the same
    value plus a constant lets a forest find spurious structure in a handful of
    rows and the gate then fires on data that has no leak in it.

    `offset` is the planted leak: a shift applied to one arm only.
    """
    out = []
    for scenario in scenarios:
        for s in range(sessions_per_scenario):
            session_id = f"{mode}_{scenario}_{s}"
            for w in range(windows):
                row = {
                    "session_id": session_id,
                    "scenario_id": scenario,
                    "security_mode": mode,
                    "window": w,
                }
                for i, name in enumerate(FEATURES):
                    # Scenario- and feature-specific mean, identical per arm.
                    mean = 1.0 + scenarios.index(scenario) * 0.8 + i * 0.3
                    row[name] = rng.gauss(mean, 1.0) + offset
                out.append(row)
    return out


def _dataset(tmp_path: Path, *, leak: float) -> Path:
    import random

    rng = random.Random(7)
    scenarios = ["normal_patrol", "cmd_vel_injection", "parameter_tamper"]
    # Enough independent sessions that a coin-flip AUC is actually resolvable;
    # at a handful of sessions the estimate is too noisy to assert on.
    rows = _rows(
        mode="permissive", scenarios=scenarios, sessions_per_scenario=6,
        windows=5, offset=0.0, rng=rng,
    ) + _rows(
        mode="enforce", scenarios=scenarios, sessions_per_scenario=6,
        windows=5, offset=leak, rng=rng,
    )
    return _write(tmp_path / f"features_leak_{leak}.csv", rows)


def test_indistinguishable_arms_pass():
    """Same distribution in both arms -> separability near a coin flip."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        report = measure(_dataset(Path(tmp), leak=0.0))
    assert report["passed"] is True
    assert report["separability"] < DEFAULT_MAX_AUC


def test_planted_offset_between_arms_is_caught():
    """A constant shift applied only to Enforce must fail the gate.

    This is the shape of both real incidents: the arms differed in something
    that had nothing to do with the attacks.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        report = measure(_dataset(Path(tmp), leak=4.0))
    assert report["passed"] is False
    assert report["separability"] > 0.9


def test_unpaired_scenarios_are_refused_rather_than_scored(tmp_path):
    """Scenario differences would be scored as mode signal, so refuse instead."""
    import random

    rng = random.Random(3)
    rows = _rows(
        mode="permissive", scenarios=["normal_patrol", "cmd_vel_injection"],
        sessions_per_scenario=3, windows=5, offset=0.0, rng=rng,
    ) + _rows(
        mode="enforce", scenarios=["normal_patrol"],
        sessions_per_scenario=3, windows=5, offset=0.0, rng=rng,
    )
    path = _write(tmp_path / "unpaired.csv", rows)
    with pytest.raises(LeakageError, match="not paired"):
        measure(path)


def test_single_mode_dataset_is_refused(tmp_path):
    import random

    rng = random.Random(5)
    rows = _rows(
        mode="enforce", scenarios=["normal_patrol", "cmd_vel_injection"],
        sessions_per_scenario=3, windows=5, offset=0.0, rng=rng,
    )
    path = _write(tmp_path / "one_mode.csv", rows)
    with pytest.raises(LeakageError, match="both security modes"):
        measure(path)


def test_too_few_sessions_is_refused_not_passed(tmp_path):
    """A small sample must not be able to earn a pass by accident."""
    import random

    rng = random.Random(11)
    rows = _rows(
        mode="permissive", scenarios=["normal_patrol"],
        sessions_per_scenario=1, windows=5, offset=0.0, rng=rng,
    ) + _rows(
        mode="enforce", scenarios=["normal_patrol"],
        sessions_per_scenario=1, windows=5, offset=0.0, rng=rng,
    )
    path = _write(tmp_path / "tiny.csv", rows)
    with pytest.raises(LeakageError, match="sessions"):
        measure(path)


def test_windows_of_one_session_never_span_the_split(tmp_path):
    """Without grouping, the classifier scores session identity, not mode."""
    import inspect

    from firewall_lab import mode_leakage

    source = inspect.getsource(mode_leakage.measure)
    assert "StratifiedGroupKFold" in source
    assert "groups" in source
