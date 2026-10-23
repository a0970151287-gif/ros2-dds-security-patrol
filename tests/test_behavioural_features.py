"""行為特徵建構器的契約。

這支工具的結論是**負面的**——2026-09-04 量到它建出來的 `guard_input_rate`
其實不是行為特徵，而是「守衛已經鎖定一段時間」的代理。測試因此不保證那些
特徵有用，只保證：

1. 視窗幾何**取自既有特徵表**，不自己重新定義（不然兩張表接不起來）
2. 讀不到就中止，不安靜補零（「沒有訊號」與「沒有讀到」必須分得開）
3. 零速度與非零速度分得開——那正是推翻結論的那個量測
"""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "behav", ROOT / "工具腳本" / "build_behavioural_features.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


behav = _load()


def _dataset(tmp_path: Path, sid: str, events: list[dict], *,
             mode: str = "enforce") -> Path:
    root = tmp_path / "dataset"
    d = root / sid
    d.mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps({
        "session_id": sid, "scenario_id": "normal_patrol",
        "attack_class": "normal", "security_mode": mode, "status": "complete",
    }), encoding="utf-8")
    (d / "telemetry_events.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return root


def _features(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "f.csv"
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return p


def _ev(kind, ts_ns, **details):
    return {"event_type": kind, "ts_unix_ns": ts_ns, "details": details}


BASE_NS = 1_000_000_000_000_000_000
BASE_S = BASE_NS / 1e9


# ------------------------------------------------------------ 視窗幾何

def test_windows_come_from_the_feature_table_not_from_the_events(tmp_path):
    """視窗必須跟既有特徵表對齊，否則兩張表接不起來。

    事件橫跨 24 秒，但特徵表只宣告兩個視窗——輸出就只能有兩列。
    """
    events = [_ev("guard_input", BASE_NS + i * 1_000_000_000,
                  linear_x=0.2, angular_z=0.0) for i in range(24)]
    ds = _dataset(tmp_path, "s1", events)
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)},
        {"session_id": "s1", "window": "1", "window_start_unix": str(BASE_S + 8)},
    ])
    rows = behav.build(ds, feats, "enforce")
    assert [r["window"] for r in rows] == [0, 1]
    # 每個 8 秒視窗 8 個事件 -> 每秒 1 個
    assert rows[0]["guard_input_rate"] == pytest.approx(1.0)
    assert rows[1]["guard_input_rate"] == pytest.approx(1.0)


def test_events_outside_the_declared_windows_are_dropped(tmp_path):
    events = [_ev("guard_input", BASE_NS + 100 * 1_000_000_000,
                  linear_x=0.2, angular_z=0.0)]
    ds = _dataset(tmp_path, "s1", events)
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    rows = behav.build(ds, feats, "enforce")
    assert rows[0]["guard_input_rate"] == 0.0


# ------------------------------------------------------------ 零速度

def test_zero_velocity_inputs_are_separated_from_moving_ones(tmp_path):
    """零速度佔比是推翻整個結論的那個量測。

    內鬼 92-97% 的 guard_input 是零速度，正常只有 2.8%——那證明它量的是
    「守衛鎖定後系統噴零」，不是攻擊者送命令。
    """
    events = [_ev("guard_input", BASE_NS + i * 100_000_000,
                  linear_x=0.0, angular_z=0.0) for i in range(9)]
    events.append(_ev("guard_input", BASE_NS + 900_000_000,
                      linear_x=0.25, angular_z=0.1))
    ds = _dataset(tmp_path, "s1", events)
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    rows = behav.build(ds, feats, "enforce")
    assert rows[0]["guard_input_nonzero_ratio"] == pytest.approx(0.1)
    assert rows[0]["guard_input_linear_abs_mean"] == pytest.approx(0.025)


def test_missing_velocity_fields_do_not_crash(tmp_path):
    ds = _dataset(tmp_path, "s1", [_ev("guard_input", BASE_NS)])
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    rows = behav.build(ds, feats, "enforce")
    assert rows[0]["guard_input_rate"] == pytest.approx(0.125)
    assert rows[0]["guard_input_nonzero_ratio"] == 0.0


# ------------------------------------------------------------ 兩類分開

def test_behavioural_and_defence_reaction_stay_disjoint():
    """兩類必須互斥且窮盡——整個實驗的問法就建立在這個分類上。

    ⚠️ 2026-09-04 的結論是這個**分類本身是錯的**（guard_input_rate 其實是
    防禦反應）。分類錯不代表可以不分類；分類是可否證的前提。
    """
    assert not set(behav.BEHAVIOURAL) & set(behav.DEFENCE_REACTION)
    assert set(behav.ALL_FEATURES) == set(behav.BEHAVIOURAL) | set(
        behav.DEFENCE_REACTION)


# ------------------------------------------------------------ fail-closed

def test_dataset_with_no_matching_session_is_refused(tmp_path):
    """接不上就中止。安靜輸出零列會被讀成「沒有訊號」。"""
    ds = _dataset(tmp_path, "s1", [_ev("guard_input", BASE_NS)])
    feats = _features(tmp_path, [
        {"session_id": "OTHER", "window": "0", "window_start_unix": str(BASE_S)}])
    with pytest.raises(behav.BuildError, match="no session"):
        behav.build(ds, feats, "enforce")


def test_wrong_security_mode_is_refused(tmp_path):
    ds = _dataset(tmp_path, "s1", [_ev("guard_input", BASE_NS)], mode="enforce")
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    with pytest.raises(behav.BuildError, match="no session"):
        behav.build(ds, feats, "permissive")


def test_feature_table_without_window_geometry_is_refused(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text("session_id,window\ns1,0\n", encoding="utf-8")
    with pytest.raises(behav.BuildError, match="window geometry"):
        behav.session_windows(p)


def test_existing_output_is_never_overwritten(tmp_path):
    ds = _dataset(tmp_path, "s1", [_ev("guard_input", BASE_NS)])
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    out = tmp_path / "o.csv"
    out.write_text("keep", encoding="utf-8")
    code = behav.main(["--dataset", str(ds), "--features", str(feats),
                       "--output", str(out)])
    assert code == 2
    assert out.read_text(encoding="utf-8") == "keep"


def test_meta_records_that_shipping_features_are_untouched(tmp_path):
    ds = _dataset(tmp_path, "s1", [_ev("guard_input", BASE_NS)])
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    out = tmp_path / "o.csv"
    assert behav.main(["--dataset", str(ds), "--features", str(feats),
                       "--output", str(out)]) == 0
    meta = json.loads(out.with_suffix(".meta.json").read_text(encoding="utf-8"))
    assert meta["changes_shipped_features"] is False
    assert meta["window_sec"] == behav.WINDOW_SEC
    assert meta["behavioural"] and meta["defence_reaction"]
