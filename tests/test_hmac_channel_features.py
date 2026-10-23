"""`build_hmac_channel_features.py` 與 `join_side_features.py` 的契約。

這一輪的結論是**負面的**（頻道特徵安全但冗餘），所以測試不保證那些特徵有用。
它守的是「量測不要自己出錯」——而這一輪真的踩到兩個：

1. **事件鍵是 `event_type` 不是 `event`。** 第一版探針用錯，量到「所有頻道
   都是零」，差一步就寫成「這個欄位沒有資料」。
2. **基表是 (session, window, **source**) 粒度**，一個視窗有 2–3 列；側表是
   視窗層級。第一版的接表用 `(session, window)` 當唯一鍵，直接拒絕；而如果
   當初改成「只留交集」，兩臂的列數就會不同而分數不可比。

所以這裡的重點是：**詞彙要與發送端一致、未知值不吞、接不齊就拒絕、
一對多要廣播。**
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "工具腳本" / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


chan = _load("hmac_chan", "build_hmac_channel_features.py")
join = _load("side_join", "join_side_features.py")

BASE_NS = 1_000_000_000_000_000_000
BASE_S = BASE_NS / 1e9


def _ev(ts_ns: int, channel: str, outcome: str = "accepted"):
    return {"event_type": "hmac_result", "ts_unix_ns": ts_ns,
            "details": {"channel": channel, "outcome": outcome,
                        "reason": outcome if outcome == "accepted" else "bad"}}


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


def _csv(path: Path, rows: list[dict]) -> Path:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path


def _features(tmp_path: Path, rows: list[dict]) -> Path:
    return _csv(tmp_path / "f.csv", rows)


# ── 詞彙必須與發送端一致 ──────────────────────────────────────


def test_channel_vocabulary_matches_the_emitter():
    """詞彙在兩個地方各寫一份。分岔的話這張表會安靜地少算一整個頻道，
    而 `share` 的分母會跟著錯——沒有任何徵兆。"""
    sys.path.insert(0, str(ROOT / "src" / "dds_security_monitor"))
    from dds_security_monitor import runtime_telemetry

    assert set(chan.HMAC_CHANNELS) == set(runtime_telemetry.HMAC_CHANNELS)


def test_feature_names_cover_every_channel_in_both_halves():
    assert len(chan.BEHAVIOURAL) == 2 * len(chan.HMAC_CHANNELS)
    assert len(chan.DEFENCE_REACTION) == len(chan.HMAC_CHANNELS)
    # 兩半不可以重疊——整個實驗就是要分開測它們
    assert not set(chan.BEHAVIOURAL) & set(chan.DEFENCE_REACTION)
    assert chan.column("sensor/status", "rate") == "hmac_ch_sensor_status_rate"


def test_unknown_channel_is_rejected_not_silently_dropped(tmp_path):
    """吞掉未知頻道會讓 `share` 的分母偏小,而每一欄看起來都還很合理。"""
    ds = _dataset(tmp_path, "s1", [_ev(BASE_NS, "telepathy")])
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    with pytest.raises(chan.BuildError, match="unknown HMAC channel"):
        chan.build(ds, feats, "enforce")


# ── 三個統計量的定義 ──────────────────────────────────────────


def test_rate_share_and_reject_ratio(tmp_path):
    events = [
        _ev(BASE_NS + 0, "alerts", "rejected"),
        _ev(BASE_NS + 1, "alerts", "rejected"),
        _ev(BASE_NS + 2, "alerts", "accepted"),
        _ev(BASE_NS + 3, "heartbeat", "accepted"),
    ]
    ds = _dataset(tmp_path, "s1", events)
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    row = chan.build(ds, feats, "enforce")[0]
    assert row["hmac_ch_alerts_rate"] == pytest.approx(3 / 8.0)
    assert row["hmac_ch_alerts_share"] == pytest.approx(0.75)      # 3/4
    assert row["hmac_ch_alerts_reject_ratio"] == pytest.approx(2 / 3)
    assert row["hmac_ch_heartbeat_share"] == pytest.approx(0.25)
    assert row["hmac_ch_heartbeat_reject_ratio"] == pytest.approx(0.0)


def test_absent_channel_still_gets_a_zero_column(tmp_path):
    """詞彙取自發送端而不是資料——否則換一批資料欄位就變,兩批不可比。

    實測 `patrol/goto` 在 640 場裡一次都沒出現。
    """
    ds = _dataset(tmp_path, "s1", [_ev(BASE_NS, "alerts")])
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    row = chan.build(ds, feats, "enforce")[0]
    assert row["hmac_ch_patrol_goto_rate"] == 0.0
    assert row["hmac_ch_patrol_goto_share"] == 0.0


def test_window_with_no_hmac_traffic_is_all_zero_not_missing(tmp_path):
    ds = _dataset(tmp_path, "s1", [_ev(BASE_NS, "alerts")])
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)},
        {"session_id": "s1", "window": "1", "window_start_unix": str(BASE_S + 8)}])
    rows = chan.build(ds, feats, "enforce")
    assert [r["window"] for r in rows] == [0, 1]
    assert all(rows[1][n] == 0.0 for n in chan.ALL_FEATURES)


def test_windows_come_from_the_feature_table(tmp_path):
    """事件跨 24 秒但特徵表只宣告一個視窗——多的必須丟掉,不可以自己補視窗。"""
    events = [_ev(BASE_NS + i * 1_000_000_000, "alerts") for i in range(24)]
    ds = _dataset(tmp_path, "s1", events)
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    rows = chan.build(ds, feats, "enforce")
    assert len(rows) == 1
    assert rows[0]["hmac_ch_alerts_rate"] == pytest.approx(1.0)  # 8 則 / 8 秒


def test_mode_mismatch_is_fail_closed(tmp_path):
    """接錯模式會安靜地產生空表。這一輪真的踩到:permissive 的特徵表對應的是
    `permissive_v3/`,不是 `permissive/`——這道檢查擋下了那次。"""
    ds = _dataset(tmp_path, "s1", [_ev(BASE_NS, "alerts")], mode="permissive")
    feats = _features(tmp_path, [
        {"session_id": "s1", "window": "0", "window_start_unix": str(BASE_S)}])
    with pytest.raises(chan.BuildError, match="no session"):
        chan.build(ds, feats, "enforce")


# ── 接表 ──────────────────────────────────────────────────────


def _base_side(tmp_path, base_rows, side_rows):
    return (_csv(tmp_path / "base.csv", base_rows),
            _csv(tmp_path / "side.csv", side_rows))


def test_join_broadcasts_one_window_to_every_source_row(tmp_path):
    """基表是 (session, window, source) 粒度,側表是視窗層級。

    遙測特徵在同一個視窗的各 source 列上本來就是相同的（實測 enforce 2,076
    個多來源視窗,遙測欄位變異的有 0 個）,所以廣播才是與 `features.py`
    一致的語意。
    """
    base, side = _base_side(
        tmp_path,
        [{"session_id": "s1", "window": "0", "source": "127.0.0.1", "x": "1"},
         {"session_id": "s1", "window": "0", "source": "10.0.0.1", "x": "2"}],
        [{"session_id": "s1", "window": "0", "newcol": "9"}])
    rows, names = join.join(base, [side], None, allow_partial=False)
    assert len(rows) == 2                      # 兩列都留著,不可以塌成一列
    assert [r["newcol"] for r in rows] == ["9", "9"]
    assert [r["x"] for r in rows] == ["1", "2"]   # 原本的值沒被動到
    assert names[-1] == "newcol"


def test_join_refuses_when_the_key_sets_differ(tmp_path):
    """補零會讓「沒有訊號」與「沒有算到」同值；只留交集會讓兩臂列數不同。"""
    base, side = _base_side(
        tmp_path,
        [{"session_id": "s1", "window": "0", "x": "1"},
         {"session_id": "s1", "window": "1", "x": "1"}],
        [{"session_id": "s1", "window": "0", "newcol": "9"}])
    with pytest.raises(join.JoinError, match="key sets differ"):
        join.join(base, [side], None, allow_partial=False)


def test_allow_partial_drops_rows_and_says_so(tmp_path, capsys):
    base, side = _base_side(
        tmp_path,
        [{"session_id": "s1", "window": "0", "x": "1"},
         {"session_id": "s1", "window": "1", "x": "1"}],
        [{"session_id": "s1", "window": "0", "newcol": "9"}])
    rows, _ = join.join(base, [side], None, allow_partial=True)
    assert len(rows) == 1
    assert "丟掉" in capsys.readouterr().err


def test_join_rejects_a_duplicated_side_key(tmp_path):
    """側表必須是視窗層級的唯一鍵,否則廣播哪一列是隨機的。"""
    base, side = _base_side(
        tmp_path,
        [{"session_id": "s1", "window": "0", "x": "1"}],
        [{"session_id": "s1", "window": "0", "newcol": "9"},
         {"session_id": "s1", "window": "0", "newcol": "8"}])
    with pytest.raises(join.JoinError, match="duplicate key"):
        join.join(base, [side], None, allow_partial=False)


def test_join_refuses_to_overwrite_an_existing_column(tmp_path):
    base, side = _base_side(
        tmp_path,
        [{"session_id": "s1", "window": "0", "x": "1"}],
        [{"session_id": "s1", "window": "0", "x": "9"}])
    with pytest.raises(join.JoinError, match="overwrite"):
        join.join(base, [side], None, allow_partial=False)


def test_join_can_select_a_subset_of_columns(tmp_path):
    base, side = _base_side(
        tmp_path,
        [{"session_id": "s1", "window": "0", "x": "1"}],
        [{"session_id": "s1", "window": "0", "a": "1", "b": "2"}])
    _rows, names = join.join(base, [side], ["a"], allow_partial=False)
    assert "a" in names and "b" not in names


def test_join_reports_a_requested_column_that_does_not_exist(tmp_path):
    base, side = _base_side(
        tmp_path,
        [{"session_id": "s1", "window": "0", "x": "1"}],
        [{"session_id": "s1", "window": "0", "a": "1"}])
    with pytest.raises(join.JoinError, match="lacks requested columns"):
        join.join(base, [side], ["nope"], allow_partial=False)


def test_join_keeps_base_row_order(tmp_path):
    base, side = _base_side(
        tmp_path,
        [{"session_id": "s2", "window": "0", "x": "b"},
         {"session_id": "s1", "window": "0", "x": "a"}],
        [{"session_id": "s1", "window": "0", "newcol": "1"},
         {"session_id": "s2", "window": "0", "newcol": "2"}])
    rows, _ = join.join(base, [side], None, allow_partial=False)
    assert [r["session_id"] for r in rows] == ["s2", "s1"]
    assert [r["newcol"] for r in rows] == ["2", "1"]
