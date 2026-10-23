"""自動重啟監看器的靜態檢查。

2026-10-09：campaign 會在約 3.5 小時後因攻擊端孤兒累積而被步調熔斷器停下，
而 pending 還有 1,154 場（約 40–50 小時）⇒ 需要多次重啟。這一支監看器把那
件事自動化，而自動化一個「會產生 live 攻擊流量的迴圈」有四個必須守住的性質。

與 `test_mega_supervisor.py` 同一個理由：bash 的失敗是安靜的，而這個專案已經
被「安靜的失敗偽裝成系統性質」咬過二十幾次。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

WATCHER = (
    Path(__file__).resolve().parents[1] / "工具腳本" / "relaunch_mega_campaign.sh"
)


@pytest.fixture(scope="module")
def source() -> str:
    return WATCHER.read_text(encoding="utf-8")


def test_the_watcher_parses() -> None:
    """`bash -n`。一個連 parse 都過不了的腳本在無人值守時會安靜地什麼都不做。"""
    result = subprocess.run(
        ["bash", "-n", str(WATCHER)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_the_loop_is_bounded(source: str) -> None:
    """無人值守的迴圈必須會停。

    C2C-049 對跨主機批次寫過這條，而 C2C-069 記過監督器當初漏掉它的代價：
    連續 19 輪、80 分鐘零產出。
    """
    assert "MAX_RELAUNCH" in source
    match = re.search(r'MAX_RELAUNCH="\$\{MAX_RELAUNCH:-(\d+)\}"', source)
    assert match, "MAX_RELAUNCH 必須有預設值"
    assert 1 <= int(match.group(1)) <= 100, "上限要存在而且不荒謬"
    assert re.search(r'for attempt in \$\(seq 1 "\$MAX_RELAUNCH"\)', source), (
        "迴圈必須真的用那個上限，而不是只宣告它"
    )


def test_it_only_relaunches_after_a_circuit_breaker_stop(source: str) -> None:
    """只有 exit 3（零產出）與 exit 4（步調過慢）才重啟。

    其他退出碼代表未預期的失敗。繼續拉起來只會重複同一個錯誤，而那正是
    「重啟看起來有效」最危險的形態——它會把一個真的壞掉的系統藏起來。
    """
    assert re.search(r'EXPECTED_STOPS="?3 4"?', source), (
        "必須明確列出哪些退出碼算熔斷器自停"
    )
    assert 'exit "$rc"' in source, "未預期的退出碼必須原樣傳出去，不可以吞掉"


def test_zero_output_stops_the_loop(source: str) -> None:
    """一輪一場都沒產出就停——那時重啟不是解法。

    C2C-105 記過：「任何一次重啟都會看起來有效，然後數小時後再次失效。」
    所以這一支不可以在零產出時繼續轉。
    """
    assert re.search(r'if \[ "\$after" -le "\$before" \]', source), (
        "必須比較重啟前後的場次數"
    )
    assert "exit 5" in source


def test_it_refuses_to_run_beside_another_supervisor(source: str) -> None:
    """已經有 campaign 在跑就拒絕。

    C2C-069 §5 記過兩個 campaign 同時把記憶體裡的計畫寫回同一個檔案的事故。
    """
    assert 'pgrep -f "[r]un_mega_campaign.sh"' in source
    assert "不重複啟動" in source


def test_it_sweeps_the_attack_side_orphans(source: str) -> None:
    """清理必須涵蓋 talker ——那是 2026-10-09 量到的那個累積。

    ⚠️ 用 `-x`（精確名字）而不是 `-f`：裸 `talker` 餵給 `pkill -f` 會配到
    使用者任何含那個字的指令。
    """
    assert "pkill -TERM -x talker" in source
    assert "pkill -KILL -x talker" in source
    assert "pkill -f talker" not in source, "不可以用 -f，會誤殺"


def test_every_round_leaves_a_measurable_record(source: str) -> None:
    """每一輪都要記下停止原因、耗時與場次增量。

    否則「重啟節奏 vs 產能」只能靠印象，而這個專案的結論被印象推翻過很多次。
    """
    for needed in ("監督器結束 rc=", "場次 $before → $after", "這一輪速率"):
        assert needed in source, f"缺少可量測的紀錄：{needed}"
