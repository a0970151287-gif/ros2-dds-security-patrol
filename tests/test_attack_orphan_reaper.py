"""攻擊孤兒 reaper 的行為檢查。

這一支刻意用**真實行程**而不是 mock：它要守的性質是「不殺不該殺的」，
而那在 mock 上成立不代表在 `/proc` 上成立。2026-10-09 記過一次同形態的教訓
——「測了機制不等於測了接線」。

行程名用 monkeypatch 注入，避免與執行中的 reaper（--loop）互相干擾。
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

TOOL = (
    Path(__file__).resolve().parents[1] / "工具腳本" / "reap_attack_orphans.py"
)
# ⚠️ 必須 ≤15 字元：`/proc/<pid>/comm` 的上限是 TASK_COMM_LEN-1。第一版用
# `t_reaper_fixture`（16 字元）被截成 `t_reaper_fixtur`，於是工具一個都找不到
# ——而**三個「不該殺」的測試照樣通過**，因為它們斷言的是「找不到」。
# 是下面那個正向對照抓到的。真正的 `talker` 是 6 字元，所以出貨路徑沒事。
FIXTURE_COMM = "t_reap_fix"


def _load():
    spec = importlib.util.spec_from_file_location("reap_attack_orphans", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def reaper():
    return _load()


@pytest.fixture
def fake_attack(tmp_path):
    """起一個名字在 ATTACK_COMMS 裡、但什麼都不做的行程。"""
    binary = tmp_path / FIXTURE_COMM
    shutil.copy2("/bin/sleep", binary)
    started: list[subprocess.Popen] = []

    def spawn(env_extra: dict[str, str] | None) -> subprocess.Popen:
        env = dict(os.environ)
        env.pop("SROS2_ATTACK_DEADLINE_MONOTONIC", None)
        if env_extra:
            env.update(env_extra)
        proc = subprocess.Popen([str(binary), "120"], env=env)
        started.append(proc)
        time.sleep(0.4)  # 讓 /proc 項目穩定
        return proc

    yield spawn
    for proc in started:
        try:
            proc.send_signal(signal.SIGKILL)
            proc.wait(timeout=5)
        except Exception:
            pass


def test_the_tool_parses() -> None:
    result = subprocess.run(
        ["python3", "-c", f"import ast,pathlib;ast.parse(pathlib.Path({str(TOOL)!r}).read_text())"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_a_process_without_the_deadline_is_never_touched(
    reaper, fake_attack, monkeypatch
) -> None:
    """fail-closed：讀不到期限的行程一律不殺。

    那包含使用者自己起的同名行程。寧可漏殺也不要誤殺——與監督器
    `STACK_PATTERNS` 的註解是同一條原則。
    """
    monkeypatch.setattr(reaper, "ATTACK_COMMS", frozenset({FIXTURE_COMM}))
    proc = fake_attack(None)
    found = reaper.find_orphans(grace_sec=30.0)
    assert proc.pid not in [f["pid"] for f in found], (
        "沒有 SROS2_ATTACK_DEADLINE_MONOTONIC 的行程不可以被當成孤兒"
    )


def test_a_deadline_in_the_future_is_never_touched(
    reaper, fake_attack, monkeypatch
) -> None:
    """期限在未來 ⇒ 那一場還在跑 ⇒ 殺它會破壞那一場的攻擊。"""
    monkeypatch.setattr(reaper, "ATTACK_COMMS", frozenset({FIXTURE_COMM}))
    future = time.clock_gettime(time.CLOCK_MONOTONIC) + 600.0
    proc = fake_attack({reaper.DEADLINE_ENV: repr(future)})
    found = reaper.find_orphans(grace_sec=30.0)
    assert proc.pid not in [f["pid"] for f in found], (
        "進行中的攻擊（期限在未來）不可以被收掉"
    )


def test_an_expired_deadline_past_the_grace_is_an_orphan(
    reaper, fake_attack, monkeypatch
) -> None:
    """期限過了寬限期 ⇒ 場次結束 ⇒ 孤兒。這一條確認它真的找得到東西。"""
    monkeypatch.setattr(reaper, "ATTACK_COMMS", frozenset({FIXTURE_COMM}))
    expired = time.clock_gettime(time.CLOCK_MONOTONIC) - 900.0
    proc = fake_attack({reaper.DEADLINE_ENV: repr(expired)})
    found = reaper.find_orphans(grace_sec=120.0)
    hit = [f for f in found if f["pid"] == proc.pid]
    assert hit, "過期超過寬限期的行程必須被認出來"
    assert hit[0]["overdue_sec"] > 120.0


def test_the_grace_window_still_protects_a_just_finished_session(
    reaper, fake_attack, monkeypatch
) -> None:
    """剛過期的不算孤兒——場次自己的收尾需要時間。"""
    monkeypatch.setattr(reaper, "ATTACK_COMMS", frozenset({FIXTURE_COMM}))
    just_expired = time.clock_gettime(time.CLOCK_MONOTONIC) - 10.0
    proc = fake_attack({reaper.DEADLINE_ENV: repr(just_expired)})
    found = reaper.find_orphans(grace_sec=120.0)
    assert proc.pid not in [f["pid"] for f in found]


def test_the_grace_window_has_a_floor() -> None:
    """寬限期不可以被設成 0 ——那會殺到正在收尾的場次。"""
    result = subprocess.run(
        ["python3", str(TOOL), "--grace-sec", "0", "--dry-run"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "寬限期" in result.stderr


def test_the_loop_survives_a_failing_round() -> None:
    """清理失敗不可以讓迴圈停掉——無人值守的清理必須比它的錯誤活得久。"""
    source = TOOL.read_text(encoding="utf-8")
    assert "except Exception as exc:" in source
    assert "繼續" in source
    assert "while True:" in source


def test_the_fixture_name_fits_in_proc_comm() -> None:
    """fixture 的名字必須塞得進 `/proc/<pid>/comm`。

    否則三個 fail-closed 測試會變成「工具找不到任何東西」的假通過——
    那是這一支測試檔第一版的實際狀況。
    """
    assert len(FIXTURE_COMM) <= 15, (
        f"{FIXTURE_COMM!r} 有 {len(FIXTURE_COMM)} 字元，而 comm 上限是 15"
    )
