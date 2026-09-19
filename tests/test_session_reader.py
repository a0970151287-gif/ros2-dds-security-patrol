"""共用 session 讀取器的契約。

這個模組存在的理由是 2026-09-03 的稽核：**21 個檔案各自實作「讀 manifest ＋
掃 telemetry」**，而同一天的三個錯誤全部出在那裡（用錯資料集、讀錯欄位、
兩處走訪 details 的方式不同）。

所以測試要釘住的不只是「能讀」，還有那三個錯誤各自對應的不變量。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall_lab.session_reader import (
    SessionReadError,
    count_events,
    detail_tokens,
    iter_sessions,
    signal_counts,
)


def _session(root: Path, sid: str, **kw) -> Path:
    d = root / sid
    d.mkdir(parents=True)
    manifest = {
        "session_id": sid,
        "scenario_id": kw.get("scenario_id", "normal_patrol"),
        "attack_class": kw.get("attack_class", "normal"),
        "security_mode": kw.get("security_mode", "enforce"),
        "status": kw.get("status", "complete"),
    }
    if "return_code" in kw:
        manifest["result"] = {"attack_process": {"return_code": kw["return_code"]}}
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    events = kw.get("events")
    if events is not None:
        (d / "telemetry_events.jsonl").write_text(
            "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events),
            encoding="utf-8",
        )
    return d


# ------------------------------------------------------------ 走訪

def test_incomplete_sessions_are_skipped_by_default(tmp_path):
    """跑到一半的場次證據還沒寫完，算進統計會低估。"""
    _session(tmp_path, "a", events=[])
    _session(tmp_path, "b", status="running", events=[])
    assert [s.session_id for s in iter_sessions(tmp_path)] == ["a"]
    assert len(list(iter_sessions(tmp_path, complete_only=False))) == 2


def test_filters_compose(tmp_path):
    _session(tmp_path, "a", security_mode="enforce", attack_class="replay", events=[])
    _session(tmp_path, "b", security_mode="permissive", attack_class="replay", events=[])
    _session(tmp_path, "c", security_mode="enforce", attack_class="normal", events=[])
    got = [s.session_id for s in iter_sessions(
        tmp_path, security_mode="enforce", attack_class="replay")]
    assert got == ["a"]


def test_missing_root_raises_rather_than_returning_nothing(tmp_path):
    """讀不到與「沒有東西」是兩件事——安靜回傳空的會被讀成後者。"""
    with pytest.raises(SessionReadError, match="not a directory"):
        list(iter_sessions(tmp_path / "nope"))


def test_missing_telemetry_raises(tmp_path):
    d = _session(tmp_path, "a")           # 不寫 telemetry
    session = next(iter_sessions(tmp_path))
    with pytest.raises(SessionReadError, match="telemetry file missing"):
        list(session.telemetry())


def test_truncated_last_line_is_skipped_not_fatal(tmp_path):
    """行程被砍時 JSONL 最後一行可能截斷，那不該讓整場證據讀不出來。"""
    d = _session(tmp_path, "a", events=[{"event_type": "x", "details": {}}])
    with (d / "telemetry_events.jsonl").open("a", encoding="utf-8") as fh:
        fh.write('{"event_type": "y", "detai')
    session = next(iter_sessions(tmp_path))
    assert [e["event_type"] for e in session.telemetry()] == ["x"]


def test_attack_return_code_is_read_from_the_nested_result(tmp_path):
    _session(tmp_path, "a", return_code=2, events=[])
    _session(tmp_path, "b", events=[])
    got = {s.session_id: s.attack_return_code for s in iter_sessions(tmp_path)}
    assert got == {"a": 2, "b": None}


# ------------------------------------------------------------ 訊號編碼

def test_numeric_fields_use_zero_versus_nonzero(tmp_path):
    """`count=7` 與 `count=8` 是同一件事；重要的是計數器有沒有離開零。"""
    a = detail_tokens({"count": 7})
    b = detail_tokens({"count": 8})
    z = detail_tokens({"count": 0})
    assert a == b == ["count>0"]
    assert z == ["count=0"]


def test_bool_is_not_treated_as_a_number():
    """bool 是 int 的子型別——混進數值分支會變成 `flag>0`，語意就沒了。"""
    assert detail_tokens({"flag": True}) == ["flag=True"]
    assert detail_tokens({"flag": False}) == ["flag=False"]


def test_empty_string_is_not_a_signal():
    assert detail_tokens({"reason": ""}) == []


def test_pairs_are_recorded_and_do_not_explode(tmp_path):
    """配對是 2026-09-02 加的：正常流量也在那些頻道驗章，單一欄位不排他。"""
    _session(tmp_path, "a", events=[
        {"event_type": "hmac_result",
         "details": {"outcome": "rejected", "reason": "malformed_envelope",
                     "channel": "system/health"}},
    ])
    counts = signal_counts(next(iter_sessions(tmp_path)))
    pairs = [k for k in counts if "&" in k]
    assert len(pairs) == 3                      # C(3,2)
    assert not any(k.count("&") > 1 for k in counts)
    assert any("channel=system/health" in k and "reason=malformed_envelope" in k
               for k in pairs)


def test_signal_encoding_matches_the_exclusivity_gate(tmp_path):
    """兩處對同一份證據必須算出相同的訊號——分岔過一次就會得到不同結論。"""
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "gate", root / "工具腳本" / "check_evidence_exclusivity.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)

    events = [
        {"event_type": "hmac_result",
         "details": {"outcome": "rejected", "reason": "invalid_signature",
                     "channel": "alerts"}},
        {"event_type": "message_validation",
         "details": {"count": 5, "oversized_count": 0}},
        {"event_type": "guard_output",
         "details": {"linear_x": 0.0, "angular_z": 0.0, "blocked": True}},
    ]
    d = _session(tmp_path, "a", events=events)
    mine = signal_counts(next(iter_sessions(tmp_path)))
    theirs = gate.telemetry_signals(d)
    assert dict(mine) == dict(theirs)


# ------------------------------------------------------------ 計數

def test_count_events_prefers_the_count_field(tmp_path):
    _session(tmp_path, "a", events=[
        {"event_type": "sros2_deny", "details": {"count": 18, "kind": "authentication"}},
        {"event_type": "sros2_deny", "details": {"count": 2, "kind": "authentication"}},
    ])
    assert count_events(next(iter_sessions(tmp_path)), "sros2_deny") == 20


def test_count_events_falls_back_to_one_per_event(tmp_path):
    """缺 count 欄位時算一次——寧可高估，不可低估。

    低估會把「有反應」讀成「沉默」，而那正是 2026-09-01 內鬼量測要防的誤讀。
    """
    _session(tmp_path, "a", events=[
        {"event_type": "sros2_deny", "details": {"kind": "authentication"}},
        {"event_type": "sros2_deny", "details": {"count": True}},   # bool 不算數值
    ])
    assert count_events(next(iter_sessions(tmp_path)), "sros2_deny") == 2
