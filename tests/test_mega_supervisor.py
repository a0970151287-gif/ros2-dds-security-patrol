"""大型 campaign 監督器的靜態檢查。

2026-09-20 這支腳本連續 19 輪、80 分鐘完全零產出，而日誌每輪只寫一句
「stack 起不來」。三個缺陷疊在一起：

1. `stack_up` 把 `live_stack.sh start` 的輸出整個 `>/dev/null`，所以真正的
   原因（`RTPS_TRANSPORT_SHM Error: open_and_lock_file failed`，幾百行）
   躺在另一個檔案裡沒有人看。
2. `stack_down` 只靠 `live_stack.sh stop`，而它殺的是 **pid 檔記錄的行程
   群組**。上一輪失敗、這一輪覆蓋 pid 檔之後，舊的孤兒結構上再也殺不到，
   於是 36→42→48→54→60→66 一路長。
3. 迴圈**沒有任何停止條件**。無人值守的批次必須會大聲失敗。

這一支把三件事都釘住。與 `test_outcome_driver.py` 同一個理由：bash 的失敗
是安靜的，而安靜的失敗在這個專案已經偽裝成「防禦沒反應」很多次。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

SUPERVISOR = (
    Path(__file__).resolve().parents[1] / "工具腳本" / "run_mega_campaign.sh"
)

DEFINITION = re.compile(r"^([a-z_][a-z0-9_]*)\(\)\s*\{", re.M)
REQUIRED = (
    "stack_up",
    "stack_down",
    "clear_stale_lock",
    "assert_no_other_campaign",
    "clear_stale_dds_shm",
    "count_stack_processes",
    "quarantine_empty_sessions",
    "session_count",
)


@pytest.fixture(scope="module")
def source() -> str:
    return SUPERVISOR.read_text(encoding="utf-8")


def _code_only(text: str) -> str:
    """把註解拿掉。

    斷言要看的是程式碼,不是文件。第一版 `test_stack_up_reports_why_it_failed`
    被它自己的根因說明咬到——那段註解裡就寫著 `>/dev/null`。與
    `test_adaptive_attacker.py` 的 `_body()` 同一個坑,同一天踩第二次。
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_the_script_parses(source: str) -> None:
    """`bash -n`。語法錯誤會讓整夜的 campaign 一行都不跑。"""
    result = subprocess.run(
        ["bash", "-n", str(SUPERVISOR)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_every_called_helper_is_defined(source: str) -> None:
    """未定義的函式在 bash 只回 127 然後**繼續跑**（C2C-047 記過）。"""
    defined = set(DEFINITION.findall(source))
    missing = [name for name in REQUIRED if name not in defined]
    assert not missing, f"監督器少了這些函式：{missing}"
    for name in sorted(defined):
        assert f"{name} " in source or f"{name}(" in source


def test_the_loop_stops_after_barren_batches(source: str) -> None:
    """沒有停止條件的重試迴圈會安靜地空轉一整夜。"""
    assert "MAX_BARREN_BATCHES" in source
    assert "barren=$((barren + 1))" in source
    assert "barren=0" in source, "成功之後必須把計數歸零，否則早晚會誤停"
    assert source.count("exit 3") >= 2, (
        "stack 起不來與『跑了但沒新增場次』是兩條不同的路徑，都要能停"
    )


def test_teardown_escalates_beyond_live_stack(source: str) -> None:
    """`live_stack.sh stop` 殺不到被覆蓋 pid 檔的孤兒，必須有名字兜底。"""
    assert "pkill" in source and "-KILL" in source and "-TERM" in source
    term = source.index("-TERM")
    kill = source.index("-KILL")
    assert term < kill, "要先 TERM 再 KILL，不能直接硬殺"


def test_the_kill_patterns_are_specific_enough(source: str) -> None:
    """按名字殺是危險動作。通用字會誤殺使用者自己的行程。

    `create`、`python`、`node`、`ros2` 這類名字必須不在清單裡——
    `ros_gz_sim create` 要寫成 `ros_gz_sim`。
    """
    match = re.search(r"STACK_PATTERNS='([^']*)'", source, re.S)
    assert match, "找不到 STACK_PATTERNS 宣告"
    patterns = [p for p in match.group(1).replace("\n", "").split("|") if p]
    assert len(patterns) >= 8
    banned = {"create", "python", "python3", "node", "ros2", "bash", "sh",
              "launch", "container", "bridge"}
    for pattern in patterns:
        assert pattern.strip() not in banned, (
            f"{pattern!r} 太通用，會誤殺不相關的行程")
        assert len(pattern.strip()) >= 6, f"{pattern!r} 太短"
    # 而且必須用同一份清單去數與去殺，否則「還剩幾個」與「殺了誰」會分岔。
    assert source.count('"$STACK_PATTERNS"') >= 3


def test_shm_cleanup_never_runs_while_the_stack_is_alive(source: str) -> None:
    """清掉正在用的 Fast DDS 段 = 把一個還能救的 stack 弄死。"""
    start = source.index("clear_stale_dds_shm()")
    body = source[start:source.index("\n}", start)]
    guard = body.index("count_stack_processes")
    removal = body.index("rm -f /dev/shm/fastrtps_")
    assert guard < removal, "必須先確認沒有 stack 行程才准刪"
    assert "-ne 0 ]; then return 0" in body


def test_stack_up_reports_why_it_failed(source: str) -> None:
    """原本整個 `>/dev/null`，所以日誌永遠只寫『起不來』。"""
    start = source.index("stack_up()")
    body = _code_only(source[start:source.index("\n}", start)])
    # ⚠️ 不要只搜 `>/dev/null`——`2>/dev/null` 含有同一個子字串,那是合法的
    # （讀不到日誌檔不該讓收尾爆掉）。要判的是**啟動指令本身**有沒有被丟掉。
    launch = next(line for line in body.splitlines()
                  if "live_stack.sh start" in line)
    assert "/dev/null" not in launch, f"啟動輸出被丟掉了：{launch.strip()}"
    assert '> "$out"' in launch, "啟動輸出要留檔，失敗時才報得出原因"
    assert "sros2_live_runtime" in body, "失敗時要把 stack 日誌的尾巴印出來"
    assert "fastrtps" in body, "SHM 段數是這次的根因，要一起報"


def test_empty_sessions_are_moved_not_deleted(source: str) -> None:
    """raw 證據不刪，這是專案的規矩。"""
    start = source.index("quarantine_empty_sessions()")
    body = source[start:source.index("\n}", start)]
    assert "mv " in body
    assert "rm -rf" not in body and "rm -r " not in body


def test_a_second_campaign_is_refused_even_without_the_lock(source: str) -> None:
    """鎖只防得住遵守它的人。

    2026-09-20：我自己在重啟腳本裡 `rm -f` 掉 `<plan>.lock`，註解寫著
    「前面已確認沒有 campaign 行程」——而那一步只查了監督器的名字，沒查
    `firewall_lab.campaign`。舊監督器的孤兒 campaign 還活著，新的又起一個，
    同一秒有**兩場 session 都是 status=running**，兩邊各自把記憶體裡的計畫
    寫回同一個檔案。

    所以除了鎖之外，還要直接數行程。
    """
    assert "assert_no_other_campaign" in source
    start = source.index("assert_no_other_campaign()")
    body = _code_only(source[start:source.index("\n}", start)])
    assert "firewall_lab.campaign run" in body, "要數的是 campaign 行程本身"
    assert "return 1" in body, "偵測到就要讓這一批不要開始"
    # 而且必須真的被呼叫，不能只是定義了放著（C2C-038 記過：helper 沒被 import）。
    loop = source[source.index("while :; do"):]
    assert "assert_no_other_campaign" in loop
    assert loop.index("assert_no_other_campaign") < loop.index(
        "firewall_lab.campaign run"), "檢查必須在啟動 campaign 之前"
