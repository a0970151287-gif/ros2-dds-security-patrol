"""`工具腳本/measure_prediction_confidence.py` 的回歸測試。

這一支回答的是「**它說有把握的時候是不是真的對**」，而那個答案會被拿去決定
「哪些判定可以自動採取行動、哪些退回 alert」。所以算錯的代價是直接的。

測試集中在三件事：

1. **ECE／Brier／過度自信的定義要對**——用手算得出來的輸入逐項比。
2. **風險－覆蓋曲線要真的按信心排序**，而且覆蓋 100% 的正確率必須等於整體
   正確率（不然就是排序或切片錯了）。
3. **等價檢查要會咬人**——這一支自己跑折,與選型工具分岔的話,兩邊的數字就
   不可比,而那正是 C2C-060 記過的風險。
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_MODULE_PATH = _ROOT / "工具腳本" / "measure_prediction_confidence.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "measure_prediction_confidence", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


conf = _load()
np = pytest.importorskip("numpy")


def _bundle(confidence, correct, proba=None, truth=None):
    confidence = np.asarray(confidence, dtype=float)
    correct = np.asarray(correct, dtype=bool)
    if proba is None:
        # 二類:把信心放在被選中的那一欄。
        proba = np.column_stack([confidence, 1.0 - confidence])
        truth = np.where(correct, 0, 1)
    return {"confidence": confidence, "correct": correct,
            "proba": np.asarray(proba, dtype=float),
            "truth_index": np.asarray(truth, dtype=int),
            "per_repeat_ba": [float(correct.mean())] if len(correct) else [],
            "seconds_per_prediction": 0.0}


# ── 校準 ──────────────────────────────────────────────────────


def test_perfect_calibration_has_zero_ece():
    """說 1.0 就全對、說 0.0 就全錯 ⇒ ECE = 0。"""
    bundle = _bundle([1.0, 1.0, 1.0, 1.0], [True, True, True, True])
    out = conf.calibration_metrics(bundle)
    assert out["ece"] == pytest.approx(0.0, abs=1e-9)
    assert out["overconfidence"] == pytest.approx(0.0, abs=1e-9)


def test_overconfidence_is_confidence_minus_accuracy():
    """說 0.9 但只有一半對 ⇒ 高估自己 0.4。"""
    bundle = _bundle([0.9, 0.9, 0.9, 0.9], [True, False, True, False])
    out = conf.calibration_metrics(bundle)
    assert out["mean_confidence"] == pytest.approx(0.9)
    assert out["accuracy"] == pytest.approx(0.5)
    assert out["overconfidence"] == pytest.approx(0.4)
    # 同一個箱子裡 |0.9 - 0.5| = 0.4，權重 1.0
    assert out["ece"] == pytest.approx(0.4)


def test_underconfidence_is_negative():
    bundle = _bundle([0.4, 0.4], [True, True])
    out = conf.calibration_metrics(bundle)
    assert out["overconfidence"] < 0


def test_brier_matches_the_hand_computed_value():
    """三類、兩筆。Brier = 平均的 sum_k (p_k - y_k)^2。"""
    proba = np.array([[0.7, 0.2, 0.1],
                      [0.1, 0.1, 0.8]])
    truth = np.array([0, 1])          # 第二筆猜錯
    confidence = proba.max(axis=1)
    correct = np.array([True, False])
    out = conf.calibration_metrics(
        _bundle(confidence, correct, proba=proba, truth=truth))
    first = (0.3 ** 2) + (0.2 ** 2) + (0.1 ** 2)
    second = (0.1 ** 2) + (0.9 ** 2) + (0.8 ** 2)
    assert out["brier"] == pytest.approx((first + second) / 2)


def test_truth_outside_the_class_list_is_refused():
    """真值不在 classes_ 裡的話 Brier 會靜默算錯,必須拒絕。"""
    bundle = _bundle([0.5], [True])
    bundle["truth_index"] = np.array([-1])
    with pytest.raises(conf.ConfidenceError):
        conf.calibration_metrics(bundle)


def test_empty_input_is_refused():
    with pytest.raises(conf.ConfidenceError):
        conf.calibration_metrics(_bundle([], []))


# ── 風險－覆蓋 ────────────────────────────────────────────────


def test_full_coverage_accuracy_equals_overall_accuracy():
    bundle = _bundle([0.9, 0.8, 0.7, 0.6], [True, True, False, False])
    out = conf.risk_coverage(bundle)
    assert out["curve"]["1.0"]["accuracy"] == pytest.approx(0.5)
    assert out["curve"]["1.0"]["n"] == 4


def test_coverage_really_sorts_by_confidence():
    """最有把握的兩筆是對的 ⇒ 覆蓋 50% 時正確率 1.0。

    若實作沒有排序（或排反了）,這裡會拿到 0.0。
    """
    bundle = _bundle([0.1, 0.95, 0.2, 0.9], [False, True, False, True])
    out = conf.risk_coverage(bundle)
    assert out["curve"]["0.5"]["accuracy"] == pytest.approx(1.0)
    assert out["curve"]["1.0"]["accuracy"] == pytest.approx(0.5)


def test_a_model_that_knows_nothing_has_a_flat_curve():
    """信心與對錯無關 ⇒ 任何覆蓋率的正確率都差不多,AURC 接近錯誤率。"""
    rng = np.random.default_rng(0)
    n = 400
    confidence = rng.uniform(0.3, 0.9, size=n)
    correct = rng.random(n) < 0.6
    out = conf.risk_coverage(_bundle(confidence, correct))
    assert out["aurc"] == pytest.approx(1 - correct.mean(), abs=0.08)


def test_aurc_is_lower_when_confidence_is_informative():
    n = 400
    rng = np.random.default_rng(1)
    correct = rng.random(n) < 0.6
    informative = np.where(correct, 0.9, 0.4)
    useless = np.full(n, 0.65)
    good = conf.risk_coverage(_bundle(informative, correct))["aurc"]
    bad = conf.risk_coverage(_bundle(useless, correct))["aurc"]
    assert good < bad


def test_coverage_grid_is_declared_and_descending():
    assert conf.COVERAGE_GRID[0] == 1.0
    assert list(conf.COVERAGE_GRID) == sorted(conf.COVERAGE_GRID, reverse=True)


# ── fail-closed ───────────────────────────────────────────────


def test_eval_split_only_accepts_train_validation():
    parser = conf.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--features", "f.csv", "--arms", "rf",
                           "--reference", "rf", "--eval-split", "test"])


def test_loader_requires_the_selector_interface(monkeypatch, tmp_path):
    """折與聚合一律沿用選型工具。介面變了就必須拒絕,不要自己重建一份。"""
    (tmp_path / "select_identification_model.py").write_text(
        "def repeated_cv(*a, **k): pass\n", encoding="utf-8")
    monkeypatch.setattr(conf, "_HERE", tmp_path)
    with pytest.raises(conf.ConfidenceError, match="缺少"):
        conf._load_selector()
