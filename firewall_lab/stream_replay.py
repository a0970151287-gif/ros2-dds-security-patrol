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
    first_window: int | None = None,
    expected_row_count: int | None = None,
) -> Iterator[tuple[Mapping[str, Any], Any]]:
    """依 (串流, window) 順序逐列預測，產出 `(row, verdict)`。

    `rows` 必須是**未經過濾**的完整表，且已依 (session_id, source, window)
    排序。契約有三條，任何一條被破壞都直接拋 `StreamHistoryError`：

    1. **餵進來的列必須與輸入表逐列相同**——不可先過濾。
       這是原本要擋的東西：先挑出 holdout 列再餵，會讓串流失去歷史。
    2. window 不得倒退，同一個 (串流, window) 不得重複出現。
    3. **缺口會觸發重置，不是錯誤**——稀疏來源的缺口是真的，而把不相鄰的
       視窗當成接續會讓模型拿到錯的歷史。

    ⚠️ **2026-09-03 放寬了一條，理由如下。** 原本第 1 條寫的是「每條串流的
    第一列必須是 window 0」。那對**稀疏來源**是錯的：新資料裡
    `192.168.0.129` 這個區網位址全表只有 4 列，分散在 3 場的 window 1 與 2
    ——那個位址只在那些視窗有流量，串流本來就不從 0 開始。

    絕對的「從 0 開始」會把真實資料判成錯誤。

    改成 `expected_row_count`：**呼叫端**把「檔案裡有幾列」傳進來，這裡比對。
    ⚠️ 完整性**無法**從 `rows` 自己推導——若呼叫端在傳進來之前就過濾了，
    這裡看到的已經是過濾後的集合，自我比對永遠成立。我第一版就是這樣寫的，
    測試當場抓到它不會咬人。

    `first_window` 保留為選用參數：呼叫端若確知資料應該從某個 window 起，
    可以自己要求；預設 `None` 表示由資料決定（稀疏來源就是這種情況）。
    """

    # 完整性只能靠**呼叫端**提供的期望列數。從 `rows` 自己算沒有意義——
    # 若呼叫端在傳進來之前就過濾了，這裡看到的已經是過濾後的集合。
    if expected_row_count is not None and len(rows) != expected_row_count:
        raise StreamHistoryError(
            f"got {len(rows)} rows but the table has {expected_row_count}; "
            "rows must be fed unfiltered"
        )

    last: dict[tuple[str, str], int] = {}
    for row in rows:
        stream = key(row)
        window = window_of(row)
        if stream not in last:
            if first_window is not None and window != first_window:
                raise StreamHistoryError(
                    f"stream {stream} starts at window {window}, expected "
                    f"{first_window}; rows must be fed unfiltered in window order"
                )
            reset(*stream)
        elif window == last[stream]:
            raise StreamHistoryError(
                f"stream {stream} repeats window {window}"
            )
        elif window < last[stream]:
            raise StreamHistoryError(
                f"stream {stream} went backwards from {last[stream]} to {window}; "
                "rows must be sorted by window"
            )
        elif window != last[stream] + 1:
            # 缺口 → **重置**，不是報錯。
            #
            # 稀疏來源的缺口是真的：正式資料裡 `192.168.0.129` 全表只有 4 列，
            # 其中一條串流是 window [1, 5]——那個位址只在那兩個視窗有流量。
            #
            # 而缺口確實不能忽略：把 window 1 與 5 當成相鄰，等於宣稱兩個不
            # 相鄰的視窗在時間上接續（C2C-026 記過同一件事）。所以在缺口處
            # 讓那一段各自 cold start，語意才對。
            #
            # 過濾造成的缺口因此不再由這裡抓——那由 `expected_row_count` 抓，
            # 而且抓得更準（它比對的是呼叫端讀進來的總列數）。
            reset(*stream)
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
