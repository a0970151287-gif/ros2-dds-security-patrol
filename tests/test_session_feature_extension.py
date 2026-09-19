"""`工具腳本/extend_session_features.py` 的回歸測試。

這一支在**加資訊**，所以它算錯的方式會直接偽裝成「加料有效」或「加料無效」。
測試守四件事：

1. **分位數／端點／波動度的定義要對**，逐項與手算值比。
2. **缺口不可以被當成相鄰**。跨缺口算差等於宣稱兩個不相鄰的視窗在時間上
   相接（C2C-026 記過）；`aggregate_sessions` 的 `max_abs_delta` 就是跳過
   缺口的，加料的波動度必須一致。
3. **多來源要逐 stream 算完再平均**，與既有的 `trend` 同一個作法。
4. **加料只能接在基礎區塊後面、不可以蓋掉它**——否則量到的不是「加料」，
   是「換料」。
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_MODULE_PATH = _ROOT / "工具腳本" / "extend_session_features.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "extend_session_features", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ext = _load()
np = pytest.importorskip("numpy")


def _rows(spec):
    """spec: [(session, source, window)]"""
    return [{"session_id": s, "source": src, "window": str(w),
             "label": "x", "split": "train"} for s, src, w in spec]


# ── 宣告的空間 ────────────────────────────────────────────────


def test_declared_blocks_are_explicit_and_plus_all_is_their_union():
    assert ext.ARMS[0] == "base"
    union = (ext.EXTRA_BLOCKS["plus_quantiles"]
             + ext.EXTRA_BLOCKS["plus_endpoints"]
             + ext.EXTRA_BLOCKS["plus_volatility"])
    assert ext.EXTRA_BLOCKS["plus_all"] == union


def test_no_positional_statistic_is_declared():
    """視窗數／編號／argmax 位置一律不可以進來（2026-09-15 位置混淆檢定）。"""
    banned = {"n_windows", "window", "argmax", "index", "position", "length"}
    for names in ext.EXTRA_BLOCKS.values():
        for name in names:
            assert not (banned & set(name.split("_"))), name


# ── 統計量的定義 ──────────────────────────────────────────────


def test_quantiles_match_hand_computed_values():
    rows = _rows([("s", "a", 0), ("s", "a", 1), ("s", "a", 2), ("s", "a", 3)])
    X = np.array([[0.0], [10.0], [20.0], [30.0]])
    out = ext.extra_matrix(rows, X, ["s"], ("p25", "median", "p75"))
    assert out.shape == (1, 3)
    assert out[0].tolist() == pytest.approx([7.5, 15.0, 22.5])


def test_endpoints_are_the_first_and_last_observed_window():
    rows = _rows([("s", "a", 5), ("s", "a", 0), ("s", "a", 2)])
    X = np.array([[50.0], [1.0], [20.0]])       # 故意不照視窗順序排列
    out = ext.extra_matrix(rows, X, ["s"], ("first", "last"))
    assert out[0].tolist() == pytest.approx([1.0, 50.0])


def test_volatility_skips_gaps():
    """視窗 0,1,5。只有 (0,1) 是相鄰的,(1,5) 跨缺口必須被跳過。"""
    rows = _rows([("s", "a", 0), ("s", "a", 1), ("s", "a", 5)])
    X = np.array([[0.0], [3.0], [100.0]])
    out = ext.extra_matrix(rows, X, ["s"], ("mean_abs_delta", "std_abs_delta"))
    # 只有一對相鄰 ⇒ 平均 3.0、標準差 0.0。
    # 若跨缺口也算,平均會是 (3+97)/2 = 50.0。
    assert out[0].tolist() == pytest.approx([3.0, 0.0])


def test_volatility_of_a_single_window_stream_is_zero_not_nan():
    rows = _rows([("s", "a", 0)])
    X = np.array([[42.0]])
    out = ext.extra_matrix(rows, X, ["s"], ("mean_abs_delta", "std_abs_delta"))
    assert np.isfinite(out).all()
    assert out[0].tolist() == [0.0, 0.0]


def test_volatility_of_an_all_gap_stream_is_zero():
    rows = _rows([("s", "a", 0), ("s", "a", 4), ("s", "a", 9)])
    X = np.array([[0.0], [7.0], [70.0]])
    out = ext.extra_matrix(rows, X, ["s"], ("mean_abs_delta",))
    assert out[0].tolist() == [0.0]


def test_streams_are_averaged_not_concatenated():
    """兩個來源各自一條串流。端點要逐 stream 取完再平均。"""
    rows = _rows([("s", "a", 0), ("s", "a", 1), ("s", "b", 0), ("s", "b", 1)])
    X = np.array([[0.0], [10.0], [100.0], [200.0]])
    out = ext.extra_matrix(rows, X, ["s"], ("first", "last"))
    assert out[0].tolist() == pytest.approx([50.0, 105.0])


def test_quantiles_pool_every_row_of_the_session():
    """分位數與 mean/std/min/max 同一個母體——整場所有列,跨來源。"""
    rows = _rows([("s", "a", 0), ("s", "b", 0)])
    X = np.array([[0.0], [100.0]])
    out = ext.extra_matrix(rows, X, ["s"], ("median",))
    assert out[0].tolist() == pytest.approx([50.0])


def test_block_order_follows_the_requested_names():
    rows = _rows([("s", "a", 0), ("s", "a", 1)])
    X = np.array([[0.0, 1.0], [10.0, 1.0]])
    first_last = ext.extra_matrix(rows, X, ["s"], ("first", "last"))
    last_first = ext.extra_matrix(rows, X, ["s"], ("last", "first"))
    assert first_last[0].tolist() == pytest.approx([0.0, 1.0, 10.0, 1.0])
    assert last_first[0].tolist() == pytest.approx([10.0, 1.0, 0.0, 1.0])


def test_unknown_block_is_refused():
    rows = _rows([("s", "a", 0)])
    with pytest.raises(ext.ExtendError):
        ext.extra_matrix(rows, np.array([[1.0]]), ["s"], ("mystery",))


def test_sessions_keep_the_requested_order():
    rows = _rows([("a", "x", 0), ("b", "x", 0)])
    X = np.array([[1.0], [2.0]])
    forward = ext.extra_matrix(rows, X, ["a", "b"], ("median",))
    backward = ext.extra_matrix(rows, X, ["b", "a"], ("median",))
    assert forward[:, 0].tolist() == [1.0, 2.0]
    assert backward[:, 0].tolist() == [2.0, 1.0]


# ── 加料是「接上去」不是「換掉」 ─────────────────────────────


def test_extension_is_appended_after_the_base_block(tmp_path):
    """`plus_*` 的前段必須逐位等於 base,否則量到的是換料不是加料。"""
    sel_path = _ROOT / "工具腳本" / "select_identification_model.py"
    spec = importlib.util.spec_from_file_location("_sel_for_ext", sel_path)
    sel = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sel)

    path = tmp_path / "features.csv"
    lines = ["session_id,source,window,label,split,f0,f1"]
    rng = np.random.default_rng(3)
    for i in range(8):
        label = "normal" if i < 4 else "attack"
        for w in range(3):
            lines.append(f"s{i:02d},127.0.0.1,{w},{label},train,"
                         f"{rng.normal():.5f},{rng.normal():.5f}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    cmp = sel._load_compare()
    cv = cmp._load_cv()
    helpers = cv._load_helpers()
    rows = cv.load_rows(path)
    Xs, _ys, sessions, width = sel.session_matrix(cmp, cv, helpers, rows,
                                                  "none")
    extra = ext.extra_matrix(rows, cv.build_matrix(helpers, rows, "none")[0],
                             sessions, ext.EXTRA_BLOCKS["plus_all"])
    combined = np.hstack([Xs, extra])
    assert combined[:, :Xs.shape[1]].tolist() == Xs.tolist()
    assert combined.shape[1] == Xs.shape[1] + width * 7


def test_eval_split_only_accepts_train_validation():
    parser = ext.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--features", "f.csv", "--model", "m",
                           "--eval-split", "test"])
