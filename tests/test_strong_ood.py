"""Tests for the strong-OOD diagnosis arithmetic.

The headline claim -- that a strong known-attack OOD rejection points at normal
traffic rather than at an unseen attack -- rests on these two functions, so they
are tested without sklearn or a feature table.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "工具腳本" / "diagnose_strong_ood.py"
    spec = importlib.util.spec_from_file_location("diagnose_strong_ood", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


strong = _load()


def test_precision_is_reweighted_not_a_raw_count():
    """Group sizes must not leak into the answer.

    Ten times as many normal rows at the same rate must not change it; a raw
    share would report the population, not the separation.
    """
    assert strong.balanced_precision(0.8, 0.2) == pytest.approx(0.8)
    assert strong.balanced_precision(0.4, 0.4) == pytest.approx(0.5)


def test_precision_over_nothing_is_undefined_not_zero():
    """No rejections at all is not the same as rejecting only normal rows."""
    assert strong.balanced_precision(0.0, 0.0) is None
    assert strong.balanced_precision(0.0, 0.3) == pytest.approx(0.0)


def _fold(name, unknown, normal, known=0.0):
    return {
        "held_family": name,
        "strong_threshold_sweep": [
            {
                "known_attack_budget": 0.05,
                "unknown_below_rate": unknown,
                "normal_below_rate": normal,
                "known_below_rate": known,
                "balanced_precision_vs_normal": strong.balanced_precision(
                    unknown, normal
                ),
            }
        ],
    }


def test_every_family_counts_once_regardless_of_row_count():
    macro = strong.aggregate_macro(
        [_fold("a", 0.9, 0.1), _fold("b", 0.1, 0.9)], (0.05,)
    )
    assert macro[0]["macro_unknown_below_rate"] == pytest.approx(0.5)
    assert macro[0]["macro_normal_below_rate"] == pytest.approx(0.5)


def test_folds_where_unknown_beats_normal_is_counted_not_averaged():
    """An average can hide that the rule inverts in some folds.

    Enforce is the case this exists for: the mean looks merely bad, while the
    per-fold count shows the ordering is wrong in every single fold.
    """
    macro = strong.aggregate_macro(
        [_fold("a", 0.9, 0.1), _fold("b", 0.1, 0.9), _fold("c", 0.1, 0.9)],
        (0.05,),
    )
    assert macro[0]["folds_where_unknown_beats_normal"] == 1


def test_a_fold_with_no_rejections_does_not_drag_precision_to_zero():
    macro = strong.aggregate_macro(
        [_fold("a", 0.8, 0.2), _fold("b", 0.0, 0.0)], (0.05,)
    )
    # Only the fold that actually fired contributes.
    assert macro[0]["macro_balanced_precision_vs_normal"] == pytest.approx(0.8)
