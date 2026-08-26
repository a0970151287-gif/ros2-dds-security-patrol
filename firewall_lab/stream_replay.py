"""把特徵表的列依因果順序餵進模型，並守住串流歷史的完整性。

**為什麼需要這個。** 2026-08-25 的 open-set 評估量錯過一次：評估腳本先依標籤
把列過濾出來、再餵進模型。但 550 場裡有 393 場同時含 `normal` 與攻擊列，
過濾之後 485 條串流從 `window 1` 開始，該有歷史的列全部拿到 cold-start 特徵——
而訓練端 `_expanded_matrix` 用的是完整 session。兩邊語意不一致，數字整批偏掉
（open-set recall 0.5499 實際應為 0.5789；已知攻擊誤否決 0.2652 實際應為 0.0281）。

`HierarchicalFirewallModel.predict` 本來就會拒絕不連續的 window，但評估腳本
用 `reset_stream` 繞過了那道守衛。所以正確的作法是：**整份表逐列餵，只在統計
時挑要算的列**。

失效是靜默的——過濾器一旦溜回來，數字只會偏掉，不會報錯。這裡把它變成
大聲失敗，而且**每條串流必須從 `window 0` 起、逐一遞增**：原本那個 bug 的
症狀正是串流從 `window 1` 開始，所以只檢查「不跳號」是抓不到它的。
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

__all__ = ["StreamHistoryError", "replay_in_order", "tally"]


class StreamHistoryError(RuntimeError):
    """串流歷史被切斷——通常是有人在餵模型之前先過濾了列。"""


def _default_key(row: Mapping[str, Any]) -> tuple[str, str]:
    return (str(row["session_id"]), str(row["source"]))


def _default_window(row: Mapping[str, Any]) -> int:
    return int(row["window"])


def replay_in_order(
    rows: Sequence[Mapping[str, Any]],
    *,
    predict: Callable[[Mapping[str, Any], int], Any],
    reset: Callable[[str, str], Any],
    key: Callable[[Mapping[str, Any]], tuple[str, str]] = _default_key,
    window_of: Callable[[Mapping[str, Any]], int] = _default_window,
    first_window: int = 0,
) -> Iterator[tuple[Mapping[str, Any], Any]]:
    """依 (串流, window) 順序逐列預測，產出 `(row, verdict)`。

    `rows` 必須是**未經過濾**的完整表，且已依 (session_id, source, window)
    排序。契約有三條，任何一條被破壞都直接拋 `StreamHistoryError`：

    1. 每條串流的第一列必須是 `first_window`（預設 0）。
       ——先過濾掉 `normal` 列會讓串流從 1 開始，這條專門抓那個。
    2. 之後的 window 必須逐一遞增，不得跳號。
    3. 同一個 (串流, window) 不得重複出現。
    """

    last: dict[tuple[str, str], int] = {}
    for row in rows:
        stream = key(row)
        window = window_of(row)
        if stream not in last:
            if window != first_window:
                raise StreamHistoryError(
                    f"stream {stream} starts at window {window}, expected "
                    f"{first_window}; rows must be fed unfiltered in window order"
                )
            reset(*stream)
        elif window == last[stream]:
            raise StreamHistoryError(
                f"stream {stream} repeats window {window}"
            )
        elif window != last[stream] + 1:
            raise StreamHistoryError(
                f"stream {stream} jumped from window {last[stream]} to {window}; "
                "rows must be fed unfiltered in window order"
            )
        last[stream] = window
        yield row, predict(row, window)


def tally(
    pairs: Iterable[tuple[Mapping[str, Any], Any]],
    predicates: Sequence[Callable[[Mapping[str, Any]], bool]],
    label_of: Callable[[Any], str],
) -> list[Any]:
    """統計每個 predicate 選中的列的判定分佈。

    預測與統計刻意分開：預測必須看完整串流，統計只看有興趣的子集。
    這個分離就是修正的核心——先前的版本把兩者綁在一起，所以「只想統計
    holdout」變成了「只餵 holdout」。
    """

    import collections

    counters = [collections.Counter() for _ in predicates]
    for row, verdict in pairs:
        for slot, predicate in enumerate(predicates):
            if predicate(row):
                counters[slot][label_of(verdict)] += 1
    return counters
