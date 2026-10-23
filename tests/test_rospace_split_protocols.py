"""ROSPaCe 切分協定工具（C2C-133）。

這些測試在**拿到 ROSPaCe 之前**就要過。重點是兩個答案已知的合成資料：

* **正對照**：類別資訊只藏在一個隨時間單調上升的計數器裡。按列打亂時，
  測試列的時間鄰居在訓練集裡，所以分數很高；按區塊切時，那個時間範圍整段
  沒見過，分數應該掉到亂猜附近。工具**必須**量到這個差距。
* **負對照**：類別資訊在一個真的特徵裡、沒有時間代理。兩種切法都應該很高，
  工具**不可以**量出差距。

一個量不到已知洩漏的儀器，在真資料上回報「沒有洩漏」時沒有資訊量
（C2C-061 的教訓：一個連已知可分的類別都分不出來的方法，說不可分時沒有資訊量）。

⚠️ 用到模型的測試需要 xgboost，而它只裝在 `~/.venvs/sros2-seqmodel`
（與 `test_session_model_comparison.py` 同一個慣例）。
"""
from __future__ import annotations

import ast
import importlib.util
import json
import pathlib
import re
import sys

import pytest

np = pytest.importorskip("numpy")
pd = pytest.importorskip("pandas")
pytest.importorskip("sklearn")
pytest.importorskip("scipy")

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_MODULE_PATH = _ROOT / "工具腳本" / "rospace_split_protocols.py"
_REGISTRATION = _ROOT / "文件" / "預測_ROSPaCe的切分協定_2026-10-23.md"


def _load():
    spec = importlib.util.spec_from_file_location("rospace_split_protocols", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclass 解析型別時要從 sys.modules 找到自己的模組
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rsp = _load()

_ATTACKS = ("ros2 reconnaissance", "nmap discovery", "metasploit SYN flood")


def _synthetic(*, leak_only: bool, runs: int = 4, blocks_per_run: int = 6,
               rows_per_seq: int = 200, seed: int = 0) -> pd.DataFrame:
    """Runs of (observe, attack) blocks, 10 ms per row, 5 s between blocks,
    1 h between runs."""
    rng = np.random.default_rng(seed)
    t0 = pd.Timestamp("2023-03-16 14:00:00")
    rows, clock, counter, k = [], 0.0, 0, 0
    for r in range(runs):
        for b in range(blocks_per_run):
            attack = _ATTACKS[k % len(_ATTACKS)]
            k += 1
            for label in ("observe", attack):
                for _ in range(rows_per_seq):
                    rows.append((clock, label, counter))
                    clock += 0.01
                    counter += 1
            clock += 5.0
        clock += 3600.0
    df = pd.DataFrame(rows, columns=["sec", "attack", "counter"])
    n = len(df)
    df["timestamp"] = (t0 + pd.to_timedelta(df["sec"], unit="s")).astype(str)
    if leak_only:
        df["f_signal"] = rng.normal(0, 1, n)
        df["f_counter"] = df["counter"] + rng.normal(0, 0.1, n)
    else:
        means = {"observe": 0.0, **{a: 4.0 * (i + 1) for i, a in enumerate(_ATTACKS)}}
        df["f_signal"] = df["attack"].map(means) + rng.normal(0, 0.5, n)
        df["f_counter"] = rng.normal(0, 1, n)
    df["f_hex"] = [f"0x{v:04x}" for v in rng.integers(0, 4096, n)]
    df["f_str"] = rng.choice(["alpha", "beta", "gamma"], n)
    df["f_const"] = 7
    df.insert(0, "Unnamed: 0", np.arange(n))
    # 檔案順序刻意打亂:作者的 complete 檔也不是按時間排的
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df[["Unnamed: 0", "timestamp", "f_signal", "f_counter", "f_hex",
               "f_str", "f_const", "attack"]]


def _csv(tmp_path, df, name="data.csv"):
    p = tmp_path / name
    df.to_csv(p, index=False)
    return p


# ── 註冊與程式必須一致 ──────────────────────────────────────────


def _registered_constants() -> dict:
    text = _REGISTRATION.read_text(encoding="utf-8")
    block = re.search(r"<!-- constants:begin -->\s*```text\n(.*?)```\s*<!-- constants:end -->",
                      text, re.S)
    assert block, "註冊裡找不到常數區塊"
    out = {}
    for line in block.group(1).splitlines():
        m = re.fullmatch(r"([A-Z][A-Z0-9_]*) = (.+)", line.strip())
        if m:
            out[m.group(1)] = ast.literal_eval(m.group(2))
    return out


def test_every_registered_constant_is_the_one_the_tool_uses():
    """測了機制不等於測了接線（C2C-099）:常數只能有一個出處。"""
    registered = _registered_constants()
    assert len(registered) >= 15
    for name, value in registered.items():
        assert getattr(rsp, name) == value, f"{name}: 註冊 {value!r} ≠ 工具 {getattr(rsp, name)!r}"


def test_reproduction_target_is_derived_from_the_authors_confusion_matrix():
    tn, fp, fn, tp = 2_085_218, 434_632, 403_798, 7_309_544
    ba = (tn / (tn + fp) + tp / (tp + fn)) / 2
    assert round(ba, 6) == rsp.AUTHOR_BLOCK_BA
    assert sum(rsp.AUTHOR_LABEL_COUNTS.values()) == 30_247_050
    assert set(rsp.AUTHOR_LABEL_COUNTS) == set(rsp.KNOWN_LABELS)


# ── 欄位與標籤 ────────────────────────────────────────────────


def test_time_label_and_index_never_become_features():
    header = ["Unnamed: 0", "Unnamed: 0.1", "timestamp", "x", "attack", "y"]
    assert rsp.feature_columns(header) == ["x", "y"]
    assert rsp.feature_columns(header, ["timestamp", "x", "attack"]) == ["x"]
    with pytest.raises(ValueError):
        rsp.feature_columns(header, ["not_there"])


def test_an_unknown_label_stops_the_scan(tmp_path):
    df = _synthetic(leak_only=False, runs=1, blocks_per_run=1, rows_per_seq=5)
    df.loc[0, "attack"] = "mystery"
    with pytest.raises(ValueError, match="unknown labels"):
        rsp.scan_labels_and_time([_csv(tmp_path, df)])


def test_a_file_without_timestamp_is_refused_not_ordered_by_file(tmp_path, capsys):
    df = _synthetic(leak_only=False, runs=1, blocks_per_run=1, rows_per_seq=5)
    p = _csv(tmp_path, df.drop(columns=["timestamp"]))
    assert rsp.main(["--csv", str(p), "--output", str(tmp_path / "o.json")]) == 2
    assert "timestamp" in capsys.readouterr().out
    assert not (tmp_path / "o.json").exists()


def test_the_output_is_never_overwritten(tmp_path):
    out = tmp_path / "o.json"
    out.write_text("{}")
    p = _csv(tmp_path, _synthetic(leak_only=False, runs=1, blocks_per_run=1, rows_per_seq=5))
    assert rsp.main(["--csv", str(p), "--output", str(out)]) == 2
    assert out.read_text() == "{}"


# ── 結構:run、sequence、block ─────────────────────────────────


def test_runs_and_blocks_follow_the_registered_definitions(tmp_path):
    scan = rsp.scan_labels_and_time([_csv(tmp_path, _synthetic(leak_only=False))])
    st = rsp.build_structure(scan.ts_ns, scan.code)
    assert st.run_start_ns.size == 4
    assert len(st.block_key) == 24
    assert all(k in _ATTACKS for k in st.block_key)
    assert sorted(st.block_key.count(a) for a in _ATTACKS) == [8, 8, 8]
    # 每個 block 只屬於一個 run
    for b in range(len(st.block_key)):
        assert np.unique(st.run[st.block == b]).size == 1


def test_an_attack_at_the_start_of_a_run_is_its_own_block():
    n, a = rsp.KNOWN_LABELS.index("observe"), rsp.KNOWN_LABELS.index("nmap discovery")
    code = np.array([a, a, n, n, a, a], dtype=np.int8)
    ts = (np.arange(6) * 10**9).astype(np.int64)
    st = rsp.build_structure(ts, code)
    assert st.block_key == ["nmap discovery", "nmap discovery"]
    assert st.block.tolist() == [0, 0, 1, 1, 1, 1]


def test_a_long_gap_starts_a_new_run_and_a_new_block():
    n, a = rsp.KNOWN_LABELS.index("observe"), rsp.KNOWN_LABELS.index("nmap discovery")
    code = np.array([n, a, a, a], dtype=np.int8)
    ts = np.array([0, 1, 2, 2 + 601], dtype=np.int64) * 10**9
    st = rsp.build_structure(ts, code)
    assert st.run.tolist() == [0, 0, 0, 1]
    assert st.block.tolist() == [0, 0, 0, 1]


# ── 抽樣 ─────────────────────────────────────────────────────


def test_sampling_is_deterministic_and_a_forced_shrink_is_recorded(tmp_path):
    scan = rsp.scan_labels_and_time([_csv(tmp_path, _synthetic(leak_only=False))])
    st = rsp.build_structure(scan.ts_ns, scan.code)
    a = rsp.sample_rows(st, rows_per_block=100)
    b = rsp.sample_rows(st, rows_per_block=100)
    assert np.array_equal(a.rows, b.rows) and a.deviation is None
    assert a.rows.size == 24 * 100
    c = rsp.sample_rows(st, rows_per_block=100, max_rows=1000)
    assert c.rows.size <= 1000 and c.rows_per_block < 100
    assert "reduced" in c.deviation


# ── 編碼 ─────────────────────────────────────────────────────


def test_numbers_hex_strings_and_missing_are_encoded_without_labels(tmp_path):
    df = pd.DataFrame({
        "timestamp": ["2023-01-01 00:00:00"] * 5,
        "v": ["1.5", "0x0010", "abc", None, "abc"],
        "attack": ["observe"] * 5,
    })
    p = _csv(tmp_path, df)
    X, enc = rsp.load_features([p], ["v"], np.arange(5))
    col = X[:, 0].tolist()
    assert col[0] == 1.5 and col[1] == 16.0 and col[3] == -1.0
    assert col[2] == col[4] and col[2] <= -2.0
    assert enc["string_coded_columns"] == ["v"]


# ── 時間代理 ──────────────────────────────────────────────────


def test_the_counter_is_a_time_proxy_and_the_signal_is_not(tmp_path):
    p = _csv(tmp_path, _synthetic(leak_only=True))
    scan = rsp.scan_labels_and_time([p])
    st = rsp.build_structure(scan.ts_ns, scan.code)
    sm = rsp.sample_rows(st)
    cols = ["f_signal", "f_counter", "f_hex", "f_str", "f_const"]
    X, _ = rsp.load_features([p], cols, sm.rows)
    found = rsp.detect_time_proxies(X, scan.ts_ns[sm.rows], sm.run, cols)
    assert found["proxies"] == ["f_counter"]
    assert found["runs_used"] == 4


# ── 切分 ─────────────────────────────────────────────────────


def test_block_split_never_shares_a_block_and_keeps_every_kind_on_both_sides(tmp_path):
    scan = rsp.scan_labels_and_time([_csv(tmp_path, _synthetic(leak_only=False))])
    st = rsp.build_structure(scan.ts_ns, scan.code)
    sm = rsp.sample_rows(st)
    for seed in rsp.SEEDS:
        tr, te, singles = rsp.split_blocks(sm.block, st.block_key, seed)
        assert not set(sm.block[tr]) & set(sm.block[te])
        assert singles == []
        for side in (tr, te):
            kinds = {st.block_key[b] for b in np.unique(sm.block[side])}
            assert kinds == set(_ATTACKS)


def test_chrono_split_trains_on_earlier_runs_and_needs_three():
    run = np.repeat([0, 1, 2, 3], 10)
    start = np.array([0, 10, 20, 30], dtype=np.int64)
    tr, te = rsp.split_chrono(run, start)
    assert set(run[tr]) == {0, 1, 2} and set(run[te]) == {3}
    assert rsp.split_chrono(np.repeat([0, 1], 10), start[:2]) is None


# ── 判定規則本身 ──────────────────────────────────────────────


def _res(row, block, chrono=None, row_np=None, block_np=None, mc=(None, None), k=7):
    def node(v, n_classes=2):
        return {"mean_ba": v, "per_seed": [{"n_classes": n_classes}]}

    protocols = {
        "row": {"all": {"binary": node(row)}},
        "block": {"all": {"binary": node(block)}},
    }
    if row_np is not None:
        protocols["row"]["no_time_proxy"] = {"binary": node(row_np)}
        protocols["block"]["no_time_proxy"] = {"binary": node(block_np)}
    if chrono is not None:
        protocols["chrono"] = {"all": {"binary": node(chrono)}}
    if mc[0] is not None:
        protocols["row"]["all"]["multiclass"] = node(mc[0], k)
        protocols["block"]["all"]["multiclass"] = node(mc[1], k)
    return {"protocols": protocols, "controls": {}}


@pytest.mark.parametrize("row,block,expected", [
    (0.99, 0.89, "supported"),    # gap 0.10
    (0.95, 0.90, "supported"),    # gap 0.05,邊界算成立
    (0.92, 0.90, "undecided"),    # gap 0.02
    (0.905, 0.90, "refuted"),     # gap 0.005
])
def test_r1_uses_the_registered_three_way_rule(row, block, expected):
    assert rsp.judge(_res(row, block))["R1"] == expected


def test_r2_measures_how_much_of_the_gap_the_proxies_explain():
    v = rsp.judge(_res(0.99, 0.89, row_np=0.91, block_np=0.89))
    assert v["R2"] == "supported" and abs(v["R2_shrink"] - 0.8) < 1e-9
    v = rsp.judge(_res(0.99, 0.89, row_np=0.985, block_np=0.89))
    assert v["R2"] == "refuted"
    # 沒有差距可解釋時不可評估,而不是「成立」
    assert rsp.judge(_res(0.90, 0.90, row_np=0.90, block_np=0.90))["R2"] == "not_evaluable"


def test_r3_and_r4_and_c1():
    v = rsp.judge(_res(0.99, 0.89, chrono=0.70))
    assert v["R3"] == "supported" and v["C1"] == "pass"
    assert rsp.judge(_res(0.99, 0.89, chrono=0.885))["R3"] == "refuted"
    assert rsp.judge(_res(0.99, 0.70))["C1"] == "fail"
    # 二元差 0.10 → 正規化 0.20;多類 7 類差 0.30 → 0.35 ⇒ 成立
    v = rsp.judge(_res(0.99, 0.89, mc=(0.90, 0.60)))
    assert v["R4"] == "supported"
    v = rsp.judge(_res(0.99, 0.89, mc=(0.90, 0.88)))
    assert v["R4"] == "refuted"


def test_r4_is_not_evaluable_when_nothing_was_inflated():
    """兩個差距都是雜訊時,「識別被灌得比偵測多」是空洞為真(C2C-127 的 G4)。"""
    v = rsp.judge(_res(0.9989, 0.9997, mc=(0.9954, 0.9959)))
    assert v["R4"] == "not_evaluable"
    # 只要其中一個任務真的被灌高,就可以比
    assert rsp.judge(_res(0.90, 0.90, mc=(0.90, 0.60)))["R4"] == "supported"


# ── 儀器驗證:答案已知的兩份合成資料 ──────────────────────────


def _run(tmp_path, df):
    pytest.importorskip("xgboost")
    return rsp.run([_csv(tmp_path, df)], None, hash_inputs=False)


def test_positive_control_the_tool_sees_a_leak_that_is_known_to_be_there(tmp_path):
    res = _run(tmp_path, _synthetic(leak_only=True))
    row = res["protocols"]["row"]["all"]["binary"]["mean_ba"]
    block = res["protocols"]["block"]["all"]["binary"]["mean_ba"]
    # 註冊 C5 的判準:R1 成立,而且 BA(block) ≤ 0.70
    assert block <= 0.70, block
    assert row - block >= 0.20, (row, block)
    v = res["verdicts"]
    assert v["R1"] == "supported"
    assert res["time_proxies"]["proxies"] == ["f_counter"]
    assert v["R2"] == "supported"
    assert v["C2"] == "pass"


def test_negative_control_the_tool_sees_no_leak_when_there_is_none(tmp_path):
    res = _run(tmp_path, _synthetic(leak_only=False))
    row = res["protocols"]["row"]["all"]["binary"]["mean_ba"]
    block = res["protocols"]["block"]["all"]["binary"]["mean_ba"]
    assert row >= 0.95 and block >= 0.95
    assert res["verdicts"]["R1"] == "refuted"
    assert res["time_proxies"]["proxies"] == []
    assert res["verdicts"]["R2"] == "not_evaluable"
    assert res["verdicts"]["R4"] == "not_evaluable"
    assert res["protocols"]["block"]["all"]["multiclass"]["mean_ba"] >= 0.95


def test_the_artifact_records_what_a_rerun_needs(tmp_path):
    res = _run(tmp_path, _synthetic(leak_only=False, runs=3, blocks_per_run=3))
    assert res["schema"] == rsp.SCHEMA and res["holdout_reads"] == 0
    c = res["constants"]
    assert c["seeds"] == list(rsp.SEEDS) and c["xgb"] == rsp.XGB_PARAMS
    assert "Unnamed: 0" not in res["data"]["feature_columns"]
    assert "timestamp" not in res["data"]["feature_columns"]
    json.dumps(res)  # 必須可以序列化
