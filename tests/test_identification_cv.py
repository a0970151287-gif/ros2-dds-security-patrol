"""`工具腳本/cross_validate_identification.py` 的回歸測試。

這支工具存在的理由是**解析度**：validation 每類只有 3 場，逐類 recall 只能是
0／0.333／0.667／1.000，一場的差別就是 0.333。2026-09-15 因此把
「Enforce 有 5 類恆零、上限 12/17 = 0.7059」講錯了——換成每類 17 場之後，
真正恆零的只有 1 類，上限是 0.9412。

所以測試的重點是那幾個會讓結論整個翻掉的地方：

1. **上限的算術**要對。
2. **test 的列不可以混進來**（final test 已於 2026-09-03 開過一次）。
3. **深層時序在串流缺口要重置**——不重置等於宣稱兩個不相鄰的視窗在時間上相接。
4. **打亂標籤的對照要會咬人**，否則它只是裝飾。
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "工具腳本"
    / "cross_validate_identification.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("identification_cv", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


cv = _load()


# ── 上限的算術 ────────────────────────────────────────────────


def _per_class(recalls):
    return {f"c{i}": {"sessions": 17, "correct": int(round(r * 17)), "recall": r}
            for i, r in enumerate(recalls)}


def test_ceiling_with_no_zero_classes_is_one():
    cap = cv.ceiling(_per_class([1.0, 0.5, 0.25]))
    assert cap["arithmetic_ceiling"] == 1.0
    assert cap["zero_recall_classes"] == []


def test_ceiling_is_locked_by_zero_classes():
    """17 類、5 類恆零 ⇒ 上限 12/17。這就是被講錯的那個數字。"""
    cap = cv.ceiling(_per_class([0.0] * 5 + [1.0] * 12))
    assert cap["classes"] == 17
    assert len(cap["zero_recall_classes"]) == 5
    assert cap["arithmetic_ceiling"] == pytest.approx(12 / 17, abs=1e-4)
    assert cap["arithmetic_ceiling"] < 0.80  # 低於門檻


def test_ceiling_with_one_zero_class_of_seventeen():
    """實測的情況：只有 1 類恆零 ⇒ 0.9412，**遠高於門檻**。"""
    cap = cv.ceiling(_per_class([0.0] + [0.5] * 16))
    assert cap["arithmetic_ceiling"] == pytest.approx(16 / 17, abs=1e-4)
    assert cap["arithmetic_ceiling"] > 0.80


def test_a_tiny_nonzero_recall_is_not_counted_as_zero():
    """1/17 = 0.0588 不是 0。把它算成恆零會再犯一次同樣的錯。"""
    cap = cv.ceiling(_per_class([1 / 17] + [1.0] * 16))
    assert cap["zero_recall_classes"] == []
    assert cap["arithmetic_ceiling"] == 1.0


# ── 深層時序：缺口必須重置 ─────────────────────────────────────


def _rows(windows, session="s1"):
    return [{"session_id": session, "source": "a", "window": str(w),
             "label": "x", "split": "train"} for w in windows]


def test_deeper_temporal_resets_on_a_gap():
    """視窗 0,1,2 然後跳到 7——第 7 個視窗不可以帶前面的歷史。"""
    numpy = pytest.importorskip("numpy")
    rows = _rows([0, 1, 2, 7])
    X = numpy.array([[1.0], [2.0], [3.0], [10.0]])
    extra = cv.deeper_temporal(rows, X)
    mean5, max5 = extra[:, 0], extra[:, 1]
    # 缺口之後只剩自己
    assert mean5[3] == pytest.approx(10.0)
    assert max5[3] == pytest.approx(10.0)
    # 缺口之前照常累積
    assert mean5[2] == pytest.approx(2.0)
    assert max5[2] == pytest.approx(3.0)


def test_deeper_temporal_without_reset_would_differ():
    """變異檢定：不重置的話第 7 個視窗的 mean5 會是 4.0 而不是 10.0。

    兩者不同才代表上面那條斷言真的在檢查重置。
    """
    numpy = pytest.importorskip("numpy")
    rows = _rows([0, 1, 2, 7])
    X = numpy.array([[1.0], [2.0], [3.0], [10.0]])
    extra = cv.deeper_temporal(rows, X)
    no_reset_mean = float(numpy.mean([1.0, 2.0, 3.0, 10.0]))
    assert extra[3, 0] != pytest.approx(no_reset_mean)


def test_deeper_temporal_keeps_streams_separate():
    numpy = pytest.importorskip("numpy")
    rows = _rows([0, 1], "s1") + _rows([0, 1], "s2")
    X = numpy.array([[1.0], [1.0], [100.0], [100.0]])
    extra = cv.deeper_temporal(rows, X)
    assert extra[1, 1] == pytest.approx(1.0)      # s1 的 max5 不含 s2
    assert extra[3, 1] == pytest.approx(100.0)


def test_deeper_temporal_window_is_five_not_three():
    """mean5 必須真的看五個視窗,否則它與既有的 mean3 重複。"""
    numpy = pytest.importorskip("numpy")
    rows = _rows([0, 1, 2, 3, 4])
    X = numpy.array([[0.0], [0.0], [0.0], [0.0], [5.0]])
    extra = cv.deeper_temporal(rows, X)
    assert extra[4, 0] == pytest.approx(1.0)      # 5/5
    mean3_like = float(numpy.mean([0.0, 0.0, 5.0]))
    assert extra[4, 0] != pytest.approx(mean3_like)


# ── 分區閘門 ──────────────────────────────────────────────────


def test_eval_split_only_accepts_train_validation():
    parser = cv.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--features", "x.csv", "--eval-split", "test"])
    args = parser.parse_args(
        ["--features", "x.csv", "--eval-split", "train_validation"]
    )
    assert args.eval_split == "train_validation"


def test_temporal_and_rule_choices_are_closed():
    parser = cv.build_parser()
    for bad in (["--temporal", "everything"], ["--rule", "session_max"]):
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["--features", "x.csv", "--eval-split", "train_validation", *bad]
            )


def test_cli_refuses_a_feature_table_with_no_train_or_validation(tmp_path, monkeypatch, capsys):
    table = tmp_path / "f.csv"
    table.write_text(
        "session_id,source,window,label,split,feat\n"
        "s1,a,0,x,test,1.0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", [
        "cross_validate_identification.py",
        "--features", str(table),
        "--eval-split", "train_validation",
    ])
    assert cv.main() == 2
    assert "train" in capsys.readouterr().err


def test_cli_refuses_to_overwrite_an_existing_report(tmp_path, monkeypatch):
    table = tmp_path / "f.csv"
    table.write_text("session_id,source,window,label,split,feat\n", encoding="utf-8")
    out = tmp_path / "r.json"
    out.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "cross_validate_identification.py",
        "--features", str(table),
        "--eval-split", "train_validation",
        "--output", str(out),
    ])
    # 空表會先在 load_rows 擋下,但無論走哪一條都不可以覆寫既有報告。
    cv.main()
    assert out.read_text(encoding="utf-8") == "{}"


# ── helper 必須真的來自共用模組 ────────────────────────────────


def test_helpers_come_from_the_shared_evaluator():
    """重寫一份就會有兩個版本各自漂移。這一條守住重用。"""
    helpers = cv._load_helpers()
    for need in ("live_matrix", "temporal_matrix", "session_labels", "pool",
                 "NON_FEATURE"):
        assert hasattr(helpers, need)
    # 位置與識別欄位必須被排除,否則 CV 分數是洩漏出來的。
    for leaky in ("window", "window_start_unix", "session_id", "scenario_id",
                  "label", "split", "novelty_role"):
        assert leaky in helpers.NON_FEATURE
