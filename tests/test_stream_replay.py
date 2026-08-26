"""串流歷史完整性：先過濾再餵模型必須大聲失敗。

2026-08-25 的 open-set 評估就是這樣量錯的——過濾之後 485/550 條串流從
window 1 開始，該有歷史的列拿到 cold-start 特徵，數字整批偏掉而且完全沒有
報錯。

⚠️ 本檔第一版**抓不到那個 bug**：它明文寫著「串流從 window 1 開始本身是
允許的」，而那正是 bug 的症狀。依 C2C-037 更正為強制 `window 0` 起始。
"""

from __future__ import annotations

import pytest

from firewall_lab.stream_replay import StreamHistoryError, replay_in_order, tally


def _rows(*specs):
    return [
        {"session_id": session, "source": "127.0.0.1", "window": window, "label": label}
        for session, window, label in specs
    ]


def _run(rows):
    resets: list[tuple[str, str]] = []
    pairs = list(
        replay_in_order(
            rows,
            predict=lambda row, window: f"{row['session_id']}:{window}",
            reset=lambda session, source: resets.append((session, source)),
        )
    )
    return pairs, resets


def test_full_session_replays_with_one_reset_per_stream():
    rows = _rows(
        ("a", 0, "normal"), ("a", 1, "replay"), ("a", 2, "replay"),
        ("b", 0, "normal"), ("b", 1, "normal"),
    )
    pairs, resets = _run(rows)
    assert len(pairs) == 5
    assert resets == [("a", "127.0.0.1"), ("b", "127.0.0.1")]


def test_stream_that_does_not_start_at_window_zero_is_rejected():
    """這就是原本那個 bug 的症狀：過濾掉 normal 之後串流從 window 1 開始。

    只檢查「不跳號」是抓不到它的——第一列沒有前一列可以比。
    """
    rows = _rows(("a", 0, "normal"), ("a", 1, "replay"), ("a", 2, "replay"))
    attack_only = [row for row in rows if row["label"] != "normal"]
    with pytest.raises(StreamHistoryError, match="starts at window 1"):
        _run(attack_only)


def test_gap_in_the_middle_is_rejected():
    rows = _rows(("a", 0, "attack"), ("a", 1, "normal"), ("a", 2, "attack"))
    holed = [row for row in rows if row["label"] != "normal"]
    with pytest.raises(StreamHistoryError, match="jumped from window 0 to 2"):
        _run(holed)


def test_repeated_window_is_rejected():
    with pytest.raises(StreamHistoryError, match="repeats window 1"):
        _run(_rows(("a", 0, "normal"), ("a", 1, "normal"), ("a", 1, "normal")))


def test_interleaved_streams_keep_independent_history():
    rows = [
        {"session_id": "a", "source": "s1", "window": 0, "label": "normal"},
        {"session_id": "a", "source": "s2", "window": 0, "label": "normal"},
        {"session_id": "a", "source": "s1", "window": 1, "label": "normal"},
        {"session_id": "a", "source": "s2", "window": 1, "label": "normal"},
    ]
    pairs, resets = _run(rows)
    assert len(pairs) == 4
    assert sorted(resets) == [("a", "s1"), ("a", "s2")]


def test_tally_counts_only_the_wanted_rows():
    """統計子集，但模型仍看過每一列——這個分離就是修正的核心。"""
    rows = _rows(("a", 0, "normal"), ("a", 1, "replay"), ("a", 2, "replay"))
    pairs, _ = _run(rows)
    attack, normal = tally(
        pairs,
        [lambda row: row["label"] == "replay", lambda row: row["label"] == "normal"],
        label_of=lambda verdict: verdict.split(":")[0],
    )
    assert sum(attack.values()) == 2
    assert sum(normal.values()) == 1
