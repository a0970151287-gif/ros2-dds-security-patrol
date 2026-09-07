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


def _run(rows, **kw):
    resets: list[tuple[str, str]] = []
    pairs = list(
        replay_in_order(
            rows,
            predict=lambda row, window: f"{row['session_id']}:{window}",
            reset=lambda session, source: resets.append((session, source)),
            **kw,
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


def test_filtering_before_feeding_is_rejected():
    """這就是原本那個 bug：先過濾掉 normal 再餵，串流因此失去歷史。

    ⚠️ 2026-09-03 換了抓法。原本靠「串流必須從 window 0 開始」，但那對
    **稀疏來源**是錯的——正式資料裡 `192.168.0.129` 只有 4 列，分散在
    window 1 與 2，那個位址本來就只在那些視窗有流量。絕對規則會把真實資料
    判成錯誤。

    改用**完整性**：餵進來的 (串流, window) 必須與輸入表一模一樣。
    過濾必然讓集合變小，所以照樣抓得到，而且不會誤傷稀疏來源。
    """
    rows = _rows(("a", 0, "normal"), ("a", 1, "replay"), ("a", 2, "replay"))
    attack_only = [row for row in rows if row["label"] != "normal"]
    # 呼叫端必須把「檔案裡有幾列」傳進來，守衛才有得比。
    with pytest.raises(StreamHistoryError, match="must be fed unfiltered"):
        _run(attack_only, expected_row_count=len(rows))


def test_completeness_cannot_be_self_derived():
    """守衛**無法**從 rows 自己推導完整性——這是它的已知限制，寫成測試。

    不傳 `expected_row_count` 的話，過濾後的資料自我比對永遠成立。
    我第一版就是這樣寫的，所以把它釘住，避免有人以為那樣就夠了。
    """
    rows = _rows(("a", 0, "normal"), ("a", 1, "replay"), ("a", 2, "replay"))
    attack_only = [row for row in rows if row["label"] != "normal"]
    pairs, _ = _run(attack_only)          # 不給期望列數 → 不會拋
    assert len(pairs) == 2


def test_sparse_stream_that_starts_late_is_accepted():
    """稀疏來源的串流本來就不從 0 開始，不可判為錯誤。

    正式資料的實例：`192.168.0.129` 全表 4 列，在 window 1 與 2。
    """
    rows = _rows(("a", 1, "attack"), ("a", 2, "attack"))
    pairs, resets = _run(rows)
    assert len(pairs) == 2
    assert resets == [("a", "127.0.0.1")]


def test_caller_can_still_require_a_first_window():
    """呼叫端若確知資料應該從某個 window 起，仍然可以明示要求。"""
    rows = _rows(("a", 1, "attack"))
    with pytest.raises(StreamHistoryError, match="starts at window 1"):
        _run(rows, first_window=0)


def test_gap_triggers_a_reset_not_an_error():
    """缺口 → 重置，不是錯誤。

    ⚠️ 2026-09-03 改的。稀疏來源的缺口是真的：正式資料裡 `192.168.0.129`
    有一條串流是 window [1, 5]，那個位址只在那兩個視窗有流量。

    但缺口不能忽略——把 window 1 與 5 當成相鄰，等於宣稱兩個不相鄰的視窗
    在時間上接續（C2C-026 記過同一件事）。所以在缺口處讓那一段各自
    cold start。過濾造成的缺口改由 `expected_row_count` 抓。
    """
    rows = _rows(("a", 0, "attack"), ("a", 1, "normal"), ("a", 2, "attack"))
    holed = [row for row in rows if row["label"] != "normal"]
    pairs, resets = _run(holed)
    assert len(pairs) == 2
    # 兩段各自 cold start
    assert resets == [("a", "127.0.0.1"), ("a", "127.0.0.1")]


def test_backwards_window_is_still_rejected():
    """倒退是真正的排序錯誤，不是稀疏。"""
    rows = _rows(("a", 0, "attack"), ("a", 2, "attack"), ("a", 1, "attack"))
    with pytest.raises(StreamHistoryError, match="went backwards"):
        _run(rows)

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
