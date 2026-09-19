"""`工具腳本/compare_session_models.py` 的回歸測試。

這支比較三種問題表述。**比較要成立，前提是三者吃到的是同一批折與同一份真值**
——任何一邊算錯，勝負就是假的。所以測試集中在會讓比較失效的地方：

1. **聚合統計量**要與宣告的定義一致（`mean/std/min/max/max_abs_delta/trend`）。
2. **缺口要跳過**：不相鄰的視窗之間不可以算 delta。
3. **序列的遮罩**要對：padding 不可以被當成觀測值。
4. **有效性檢查要會咬人**：基準重現不了就必須拒絕輸出，否則這支可能整個
   與既有流程分岔而我們拿它的數字去比較。

⚠️ 這支工具跑在平行的 `~/.venvs/sros2-seqmodel`（有 torch／xgboost／lightgbm）。
測試在專案的 `~/.venvs/sros2-firewall` 下跑，所以需要那些套件的測試會自動跳過
——但**純函式的部分不依賴它們**，那才是這裡要守的東西。
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "工具腳本"
    / "compare_session_models.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("compare_session_models",
                                                  _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


cmp = _load()
numpy = pytest.importorskip("numpy")


def _rows(spec):
    """spec: [(session, source, window), ...]"""
    return [{"session_id": s, "source": src, "window": str(w),
             "label": "x", "split": "train"} for s, src, w in spec]


# ── 宣告的空間 ────────────────────────────────────────────────


def test_declared_space_is_explicit():
    assert cmp.FORMULATIONS == ("per_window_pooled", "session_aggregate",
                                "window_sequence")
    assert "random_forest" in cmp.MODELS          # 現行基準必須在裡面
    assert {"xgboost", "lightgbm"} <= set(cmp.MODELS)
    assert cmp.SEQUENCE_MODELS == ("tcn", "gru")
    assert cmp.AGGREGATE_STATS == ("mean", "std", "min", "max",
                                   "max_abs_delta", "trend")


def test_aggregate_width_matches_the_declared_statistics():
    rows = _rows([("s1", "a", 0), ("s1", "a", 1)])
    X = numpy.array([[1.0, 10.0], [3.0, 20.0]])
    out = cmp.aggregate_sessions(rows, X, ["s1"])
    assert out.shape == (1, X.shape[1] * len(cmp.AGGREGATE_STATS))


# ── 聚合統計量 ────────────────────────────────────────────────


def test_aggregate_computes_the_declared_statistics():
    rows = _rows([("s1", "a", 0), ("s1", "a", 1), ("s1", "a", 2)])
    X = numpy.array([[1.0], [3.0], [2.0]])
    out = cmp.aggregate_sessions(rows, X, ["s1"])[0]
    mean, std, low, high, max_delta, trend = out
    assert mean == pytest.approx(2.0)
    assert std == pytest.approx(numpy.std([1.0, 3.0, 2.0]))
    assert low == pytest.approx(1.0)
    assert high == pytest.approx(3.0)
    assert max_delta == pytest.approx(2.0)      # |3-1| 比 |2-3| 大
    assert trend == pytest.approx(1.0)          # 最後 2.0 − 最初 1.0


def test_aggregate_skips_deltas_across_a_gap():
    """視窗 0,1 然後跳到 9——1 與 9 之間不是相鄰，不可以算 delta。"""
    rows = _rows([("s1", "a", 0), ("s1", "a", 1), ("s1", "a", 9)])
    X = numpy.array([[1.0], [2.0], [100.0]])
    max_delta = cmp.aggregate_sessions(rows, X, ["s1"])[0][4]
    assert max_delta == pytest.approx(1.0)      # 只有 |2-1|
    assert max_delta != pytest.approx(98.0)     # 不是 |100-2|


def test_aggregate_keeps_streams_separate():
    """兩個 source 是兩條 stream；delta 不可以跨 stream。"""
    rows = _rows([("s1", "a", 0), ("s1", "b", 0)])
    X = numpy.array([[1.0], [100.0]])
    max_delta = cmp.aggregate_sessions(rows, X, ["s1"])[0][4]
    assert max_delta == pytest.approx(0.0)      # 每條 stream 只有一個視窗


def test_aggregate_single_window_session_has_zero_delta_and_trend():
    rows = _rows([("s1", "a", 0)])
    X = numpy.array([[5.0]])
    out = cmp.aggregate_sessions(rows, X, ["s1"])[0]
    assert out[4] == pytest.approx(0.0)         # max_abs_delta
    assert out[5] == pytest.approx(0.0)         # trend


def test_aggregate_does_not_encode_session_length():
    """場次長度是位置資訊，與視窗編號同一類——不可以偷偷進到特徵裡。

    兩場數值完全相同但長度不同，聚合向量必須一致。
    """
    short = cmp.aggregate_sessions(
        _rows([("s1", "a", 0), ("s1", "a", 1)]),
        numpy.array([[2.0], [2.0]]), ["s1"])[0]
    long = cmp.aggregate_sessions(
        _rows([("s2", "a", 0), ("s2", "a", 1), ("s2", "a", 2), ("s2", "a", 3)]),
        numpy.array([[2.0], [2.0], [2.0], [2.0]]), ["s2"])[0]
    assert numpy.allclose(short, long)


# ── 序列表示 ──────────────────────────────────────────────────


def test_sequences_are_padded_with_a_mask():
    rows = _rows([("s1", "a", 0), ("s1", "a", 1), ("s2", "a", 0)])
    X = numpy.array([[1.0], [2.0], [7.0]])
    seq, mask, max_len = cmp.build_sequences(rows, X, ["s1", "s2"])
    assert max_len == 2
    assert seq.shape == (2, 2, 1)
    assert mask.tolist() == [[1.0, 1.0], [1.0, 0.0]]
    assert seq[1, 1, 0] == pytest.approx(0.0)   # padding 是零
    assert seq[1, 0, 0] == pytest.approx(7.0)


def test_sequences_average_sources_within_a_window():
    """序列的軸是時間。同一個視窗的多個 source 先平均，不可以變成兩個時間步。"""
    rows = _rows([("s1", "a", 0), ("s1", "b", 0), ("s1", "a", 1)])
    X = numpy.array([[0.0], [10.0], [4.0]])
    seq, mask, max_len = cmp.build_sequences(rows, X, ["s1"])
    assert max_len == 2                          # 兩個視窗，不是三列
    assert seq[0, 0, 0] == pytest.approx(5.0)    # (0+10)/2
    assert seq[0, 1, 0] == pytest.approx(4.0)
    assert mask[0].tolist() == [1.0, 1.0]


def test_sequences_are_ordered_by_window_not_row_order():
    rows = _rows([("s1", "a", 5), ("s1", "a", 1)])
    X = numpy.array([[50.0], [10.0]])
    seq, _mask, _n = cmp.build_sequences(rows, X, ["s1"])
    assert seq[0, 0, 0] == pytest.approx(10.0)   # window 1 在前
    assert seq[0, 1, 0] == pytest.approx(50.0)


# ── 有效性檢查與閘門 ──────────────────────────────────────────


def test_eval_split_only_accepts_train_validation():
    parser = cmp.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--features", "x.csv", "--eval-split", "test"])


def test_cli_refuses_to_overwrite_before_doing_any_work(tmp_path, monkeypatch, capsys):
    out = tmp_path / "r.json"
    out.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "compare_session_models.py",
        "--features", str(tmp_path / "missing.csv"),
        "--eval-split", "train_validation",
        "--output", str(out),
    ])
    assert cmp.main() == 2
    assert "不覆寫" in capsys.readouterr().err
    assert out.read_text(encoding="utf-8") == "{}"


def test_baseline_artifact_has_the_field_the_validity_check_reads(tmp_path):
    """有效性檢查讀的是 `session_balanced_accuracy`。欄位改名它會靜默失效。"""
    repo = pathlib.Path(__file__).resolve().parents[1]
    artifact = repo / "文件" / "識別交叉驗證_enforce_deep_2026-09-15.json"
    if not artifact.is_file():
        pytest.skip("基準 artifact 不在")
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert "session_balanced_accuracy" in payload
    assert 0.0 <= float(payload["session_balanced_accuracy"]) <= 1.0
    # 這一輪的比較就是拿它當基準，值改了下面的斷言要跟著改。
    assert payload["session_balanced_accuracy"] == pytest.approx(0.5571, abs=1e-4)


def test_unknown_model_and_formulation_are_rejected():
    with pytest.raises(cmp.CompareError):
        cmp.make_model("magic", 0)


# ── 2026-09-16 擴充的學習法清單 ────────────────────────────────


def test_every_declared_model_can_be_constructed():
    """清單裡有建不起來的名字,那一格會在跑到一半才炸,而前面的結果已經算完。

    ⚠️ 需要 xgboost／lightgbm／catboost,那些只裝在 ~/.venvs/sros2-seqmodel。
    在專案的 venv 下缺哪一個就跳過哪一個——但**純 sklearn 的那些不准跳**。
    """
    optional = {"xgboost", "lightgbm", "catboost"}
    missing = []
    for name in cmp.MODELS:
        try:
            cmp.make_model(name, 0)
        except ModuleNotFoundError:
            if name in optional:
                continue
            missing.append((name, "ModuleNotFoundError"))
        except Exception as exc:  # noqa: BLE001
            missing.append((name, f"{type(exc).__name__}: {exc}"))
    assert not missing, f"這些宣告的模型建不起來：{missing}"


def test_the_list_covers_every_inductive_bias_family():
    """清單的價值在於涵蓋不同的歸納偏置,不是數量。少掉一整族就要察覺。"""
    families = {
        "樹／集成": {"random_forest", "extra_trees", "hist_gradient_boosting",
                     "xgboost", "lightgbm", "catboost", "adaboost",
                     "gradient_boosting"},
        "核方法": {"svm_rbf", "svm_linear", "pca_svm"},
        "生成式": {"lda_shrinkage", "qda", "gaussian_nb"},
        "原型／實例": {"nearest_centroid", "knn", "lda_project_knn"},
        "正則化線性": {"logistic", "ridge", "sgd_hinge"},
        "機率式": {"gaussian_process"},
        "神經網路": {"mlp"},
        "組合": {"stacking", "voting_soft"},
    }
    declared = set(cmp.MODELS)
    for family, members in families.items():
        assert members & declared, f"「{family}」這一族在清單裡一個都沒有"
    uncovered = declared - set().union(*families.values())
    assert not uncovered, f"這些模型沒有被歸到任何一族：{sorted(uncovered)}"


def test_random_forest_is_not_the_only_option():
    """Jesse 2026-09-16 要求不要只用隨機森林。清單必須真的有替代品。"""
    assert len(cmp.MODELS) >= 20
    assert len(set(cmp.MODELS) - {"random_forest"}) >= 19


def test_formulation_and_model_filters_exist():
    """只跑勝出的表述時要能過濾,否則每次都要重跑 per_window_pooled。"""
    parser = cmp.build_parser()
    args = parser.parse_args([
        "--features", "x.csv", "--eval-split", "train_validation",
        "--formulations", "session_aggregate",
        "--models", "svm_rbf", "lda_shrinkage",
    ])
    assert args.formulations == ["session_aggregate"]
    assert args.models == ["svm_rbf", "lda_shrinkage"]
    with pytest.raises(SystemExit):
        parser.parse_args([
            "--features", "x.csv", "--eval-split", "train_validation",
            "--formulations", "not_a_formulation",
        ])
