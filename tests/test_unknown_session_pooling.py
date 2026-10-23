"""未知攻擊場次池化掃描的契約。

這支工具**重建了 Codex 的 family-LOO 折**，而重建就有分岔的風險。所以最重要
的測試不是「k-of-n 算得對」，是「等價檢查真的會擋」——分岔了卻照樣輸出新數字，
比不做這件事更糟。
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "sweep", ROOT / "工具腳本" / "sweep_unknown_session_pooling.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sweep = _load()


# ------------------------------------------------------------ 池化規則

def test_k_equals_one_is_exactly_any():
    """k=1 必須等於 Codex 現在用的 `any()`，否則兩邊的數字不可比。"""
    groups = ["s1", "s1", "s1", "s2", "s2", "s2"]
    flagged = [False, True, False, False, False, False]
    assert sweep.k_of_n_rate(groups, flagged, 1) == pytest.approx(0.5)


def test_higher_k_requires_persistence():
    """零星單一視窗不算；連續多個才算——這正是本工具的假設。"""
    groups = ["s1"] * 4 + ["s2"] * 4
    flagged = [True, False, False, False,      # s1：只有一個
               True, True, True, False]        # s2：三個
    assert sweep.k_of_n_rate(groups, flagged, 1) == pytest.approx(1.0)
    assert sweep.k_of_n_rate(groups, flagged, 3) == pytest.approx(0.5)
    assert sweep.k_of_n_rate(groups, flagged, 4) == pytest.approx(0.0)


def test_fraction_rule_scales_with_session_length():
    """比例規則對長短不一的場次要公平——k-of-n 不會。"""
    groups = ["short", "short"] + ["long"] * 8
    flagged = [True, True] + [True, True] + [False] * 6   # 兩場各 2 個命中
    assert sweep.fraction_rate(groups, flagged, 0.5) == pytest.approx(0.5)
    # 同樣的資料用 k=2 會判兩場都成立
    assert sweep.k_of_n_rate(groups, flagged, 2) == pytest.approx(1.0)


def test_empty_input_is_refused():
    with pytest.raises(sweep.SweepError):
        sweep.k_of_n_rate([], [], 1)
    with pytest.raises(sweep.SweepError):
        sweep.fraction_rate([], [], 0.5)


# ------------------------------------------------------------ 等價檢查

def _reference(tmp_path, metrics):
    p = tmp_path / "ref.json"
    p.write_text(json.dumps({"folds": [{"held_family": "fam_a", "metrics": metrics}]}),
                 encoding="utf-8")
    return p


def _fold(row_recall, row_fpr, any_recall, any_fpr):
    return [{
        "held_family": "fam_a",
        "row": {"unknown_recall": row_recall, "normal_false_unknown_rate": row_fpr},
        "any": {"unknown_recall": any_recall, "normal_false_unknown_rate": any_fpr},
    }]


def test_matching_reconstruction_passes(tmp_path):
    ref = _reference(tmp_path, {
        "parallel_unknown_recall": 0.5,
        "normal_false_unknown_rate": 0.02,
        "parallel_unknown_session_recall": 0.7,
        "normal_false_unknown_session_rate": 0.18,
    })
    assert sweep.check_equivalence(_fold(0.5, 0.02, 0.7, 0.18), ref) == []


def test_a_diverged_reconstruction_is_caught(tmp_path):
    """折構造只要有一點不同，數字就會飄——必須被擋下。"""
    ref = _reference(tmp_path, {
        "parallel_unknown_recall": 0.5,
        "normal_false_unknown_rate": 0.02,
        "parallel_unknown_session_recall": 0.7,
        "normal_false_unknown_session_rate": 0.18,
    })
    problems = sweep.check_equivalence(_fold(0.51, 0.02, 0.7, 0.18), ref)
    assert problems and "parallel_unknown_recall" in problems[0]


def test_tolerance_is_tight_enough_to_catch_a_real_divergence(tmp_path):
    """容差必須小到抓得住真實分岔，但容得下浮點誤差。"""
    ref = _reference(tmp_path, {
        "parallel_unknown_recall": 0.5,
        "normal_false_unknown_rate": 0.02,
        "parallel_unknown_session_recall": 0.7,
        "normal_false_unknown_session_rate": 0.18,
    })
    assert sweep.check_equivalence(_fold(0.5 + 1e-12, 0.02, 0.7, 0.18), ref) == []
    assert sweep.check_equivalence(_fold(0.5 + 1e-6, 0.02, 0.7, 0.18), ref)


def test_missing_fold_in_reference_is_reported(tmp_path):
    ref = _reference(tmp_path, {"parallel_unknown_recall": 0.5})
    folds = _fold(0.5, 0.02, 0.7, 0.18)
    folds[0]["held_family"] = "fam_b"
    problems = sweep.check_equivalence(folds, ref)
    assert problems and "fam_b" in problems[0]


def test_reference_missing_a_metric_is_reported(tmp_path):
    """參照少一個欄位不可當成通過——那是介面漂移。"""
    ref = _reference(tmp_path, {"parallel_unknown_recall": 0.5})
    problems = sweep.check_equivalence(_fold(0.5, 0.02, 0.7, 0.18), ref)
    assert any("normal_false_unknown_rate" in p for p in problems)


# ------------------------------------------------------------ 介面對齊

def test_codex_helpers_are_still_present():
    """本工具重用 Codex 的 helper；他改了介面就必須先對齊，不可安靜跑下去。"""
    module = sweep.load_codex_module()
    for need in ("_fit_attack_ood", "_probability", "_weighted_rate",
                 "_event_rate", "family_for_label", "RAW_FEATURES"):
        assert hasattr(module, need), need


def test_reference_is_a_required_argument():
    """沒有參照就沒有等價檢查——不可選。"""
    with pytest.raises(SystemExit):
        sweep.build_parser().parse_args(
            ["--features", "f.csv", "--metrics", "m.json"])


def test_defaults_match_the_shipping_gate():
    args = sweep.build_parser().parse_args(
        ["--features", "f.csv", "--metrics", "m.json", "--reference", "r.json"])
    assert args.maximum_normal_fpr == 0.02
    assert args.attack_ood_scorer == "mahalanobis"
    assert 1 in args.k, "k=1 必須在掃描範圍內，它是 Codex 現行的 any()"
