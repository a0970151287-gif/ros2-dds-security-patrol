"""池化與時序特徵評估器的契約。

這支工具報的是**提升**，而提升最容易來自洩漏或 harness 產物。所以測試釘住的
主要是那些會讓它安靜地給出漂亮數字的路徑，而不是「算得對不對」。
"""

from __future__ import annotations

import csv
import importlib.util
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "pooling", ROOT / "工具腳本" / "evaluate_pooling_and_temporal.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pooling = _load()


def _rows(spec):
    """spec: [(session, source, window, label, split, feat_a, feat_b), …]"""
    return [{"session_id": s, "source": src, "window": str(w), "label": lab,
             "split": sp, "feat_a": str(a), "feat_b": str(b)}
            for s, src, w, lab, sp, a, b in spec]


def _csv(tmp_path, rows):
    p = tmp_path / "f.csv"
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return p


# ------------------------------------------------------------ 時序特徵

def test_delta_is_zero_on_the_first_window_of_a_stream():
    rows = _rows([("s1", "a", 0, "normal", "train", 1.0, 0.0),
                  ("s1", "a", 1, "normal", "train", 3.0, 0.0)])
    X, _ = pooling.live_matrix(rows)
    Xt, resets = pooling.temporal_matrix(rows, X)
    n = X.shape[1]
    assert Xt[0, n] == 0.0            # 第一列沒有前一個視窗
    assert Xt[1, n] == pytest.approx(2.0)
    assert resets == 0


def test_a_gap_resets_the_stream_instead_of_bridging_it():
    """C2C-026 記過：把兩個不相鄰的視窗當成接續是錯的。"""
    rows = _rows([("s1", "a", 0, "normal", "train", 1.0, 0.0),
                  ("s1", "a", 5, "normal", "train", 9.0, 0.0)])
    X, _ = pooling.live_matrix(rows)
    Xt, resets = pooling.temporal_matrix(rows, X)
    n = X.shape[1]
    assert resets == 1
    assert Xt[1, n] == 0.0, "跨越缺口不得算差分"


def test_streams_are_keyed_by_session_and_source(tmp_path):
    """同一場的兩個來源是兩條串流；混在一起會算出跨來源的假差分。"""
    rows = _rows([("s1", "a", 0, "normal", "train", 1.0, 0.0),
                  ("s1", "b", 1, "normal", "train", 9.0, 0.0)])
    X, _ = pooling.live_matrix(rows)
    Xt, _ = pooling.temporal_matrix(rows, X)
    n = X.shape[1]
    assert Xt[1, n] == 0.0, "不同 source 不是同一條串流"


def test_constant_columns_are_dropped():
    rows = _rows([("s1", "a", 0, "normal", "train", 1.0, 7.0),
                  ("s1", "a", 1, "normal", "train", 2.0, 7.0)])
    X, names = pooling.live_matrix(rows)
    assert names == ["feat_a"]


# ------------------------------------------------------------ 池化

def _proba(rows_of_pairs):
    return np.array(rows_of_pairs, dtype=float)


def test_attack_only_ignores_windows_the_model_calls_normal():
    classes = ["attack", "normal"]
    # 兩個 normal 視窗（機率壓倒性）＋ 一個 attack 視窗
    proba = _proba([[0.1, 0.9], [0.1, 0.9], [0.8, 0.2]])
    sids = np.array(["s1", "s1", "s1"])
    out = pooling.pool("session_attack_only", classes, proba, sids, ["s1"])
    assert out[0] == "attack"
    # 單純平均會被兩個 normal 稀釋
    mean = pooling.pool("session_mean", classes, proba, sids, ["s1"])
    assert mean[0] == "normal"


def test_attack_only_falls_back_when_every_window_looks_normal():
    classes = ["attack", "normal"]
    proba = _proba([[0.2, 0.8], [0.3, 0.7]])
    sids = np.array(["s1", "s1"])
    assert pooling.pool("session_attack_only", classes, proba, sids, ["s1"])[0] == "normal"


def test_vote_and_mean_can_disagree():
    classes = ["a", "b"]
    # 兩票給 a（勉強），一票給 b（壓倒性）
    proba = _proba([[0.55, 0.45], [0.55, 0.45], [0.05, 0.95]])
    sids = np.array(["s1", "s1", "s1"])
    assert pooling.pool("session_vote", classes, proba, sids, ["s1"])[0] == "a"
    assert pooling.pool("session_mean", classes, proba, sids, ["s1"])[0] == "b"


def test_unknown_pooling_rule_is_refused():
    with pytest.raises(pooling.EvalError, match="unknown pooling rule"):
        pooling.pool("nope", ["a"], _proba([[1.0]]), np.array(["s1"]), ["s1"])


# ------------------------------------------------------------ 場次標籤

def test_session_label_is_the_attack_class_not_the_majority_window():
    """一場 6 個視窗只有 2 個是攻擊，場次標籤仍是那個攻擊類別。"""
    rows = _rows([("s1", "a", w, "normal" if w in (0, 4, 5) else "replay",
                   "train", 1.0, 0.0) for w in range(6)])
    assert pooling.session_labels(rows, ["s1"])["s1"] == "replay"


def test_pure_normal_session_is_labelled_normal():
    rows = _rows([("s1", "a", w, "normal", "train", 1.0, 0.0) for w in range(3)])
    assert pooling.session_labels(rows, ["s1"])["s1"] == "normal"


def test_two_attack_labels_in_one_session_is_refused():
    rows = _rows([("s1", "a", 0, "replay", "train", 1.0, 0.0),
                  ("s1", "a", 1, "sensor_spoof", "train", 1.0, 0.0)])
    with pytest.raises(pooling.EvalError, match="多個攻擊標籤"):
        pooling.session_labels(rows, ["s1"])


# ------------------------------------------------------------ fail-closed

def test_test_split_cannot_be_selected_for_evaluation():
    """final test 已於 2026-09-03 開過一次，再開就不是獨立評估。"""
    parser = pooling.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--features", "f.csv", "--eval-split", "test"])


def test_session_overlap_between_splits_is_refused(tmp_path):
    rows = _rows([("s1", "a", 0, "normal", "train", 1.0, 0.0),
                  ("s1", "a", 1, "normal", "validation", 2.0, 0.0),
                  ("s2", "a", 0, "replay", "train", 5.0, 0.0)])
    code = pooling.main(["--features", str(_csv(tmp_path, rows))])
    assert code == 2


def test_empty_split_is_refused(tmp_path):
    rows = _rows([("s1", "a", 0, "normal", "train", 1.0, 0.0),
                  ("s1", "a", 1, "normal", "train", 2.0, 0.0)])
    code = pooling.main(["--features", str(_csv(tmp_path, rows))])
    assert code == 2


def test_missing_required_column_is_refused(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text("session_id,window,label\ns1,0,normal\n", encoding="utf-8")
    assert pooling.main(["--features", str(p)]) == 2


def test_existing_output_is_never_overwritten(tmp_path):
    rows = []
    for si, (lab, sp) in enumerate([("normal", "train"), ("replay", "train"),
                                    ("normal", "validation"), ("replay", "validation")]):
        for w in range(3):
            rows.append(("s%d" % si, "a", w, lab if w == 1 else "normal", sp,
                         float(w + si), float(si)))
    out = tmp_path / "r.json"
    out.write_text("{}", encoding="utf-8")
    code = pooling.main(["--features", str(_csv(tmp_path, _rows(rows))),
                         "--no-controls", "--output", str(out)])
    assert code == 2
    assert out.read_text(encoding="utf-8") == "{}"


def test_controls_are_on_by_default():
    """對照必須是預設開啟——關掉要刻意。"""
    args = pooling.build_parser().parse_args(["--features", "f.csv"])
    assert args.no_controls is False
    assert args.eval_split == "validation"
