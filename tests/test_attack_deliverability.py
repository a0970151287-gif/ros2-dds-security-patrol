"""攻擊的 QoS 必須讓訊息真的送得到。

這個專案最貴的一類缺陷不是防禦有洞，是**攻擊根本沒送達，而資料上看起來
跟「防禦擋下了」一模一樣**。已經咬過兩次，兩次都是同一個機制：

- 2026-08-18（C2C-014）：N1 心跳重放是 BEST_EFFORT publisher 對 RELIABLE
  subscriber，1,100 場正式資料裡 100 場 `replay` **從未送達**。
- 2026-09-02：`verify_flood` 同樣的錯，回報送出 12,231,436 筆，封包層只多
  15 個。而那一場的資料被拿去判定「三支候選彼此不可分」。

DDS 的規則是單向的：**BEST_EFFORT writer 配不上 RELIABLE reader**
（reader 要求的可靠性比 writer 提供的強），反過來可以。所以只要防守端是
RELIABLE，攻擊端就必須也是 RELIABLE，否則一則都不會離開行程。

⚠️ **相容性有兩個軸，兩個都要對。** 2026-09-15 第一次重跑只修了 reliability，
攻擊仍然 rc=2——防守端的 `/security/heartbeat` 是 RELIABLE **＋
TRANSIENT_LOCAL**，而 VOLATILE writer 一樣配不上 TRANSIENT_LOCAL reader。
只驗一個軸的測試會給出「已經修好」的假象。

這裡把兩個軸都釘成回歸測試。
"""
from __future__ import annotations

import pathlib
import re

import pytest

from firewall_lab.catalog import load_catalog
from firewall_lab.runners import build_attack_argv

_REPO = pathlib.Path(__file__).resolve().parents[1]
_MONITOR = (
    _REPO
    / "src"
    / "dds_security_monitor"
    / "dds_security_monitor"
    / "intelligent_defense_node.py"
)

# 防守端以 RELIABLE 訂閱的安全通道。攻擊端對這些 topic 不可用 BEST_EFFORT。
RELIABLE_DEFENDER_TOPICS = ("/security/heartbeat",)

_CANDIDATE_CATALOG = _REPO / "firewall_lab" / "scenarios_smoke_candidates.json"


def _argv_for(catalog_path: pathlib.Path, runner: str) -> list[str] | None:
    catalog = load_catalog(catalog_path)
    for scenario in catalog.values():
        if scenario.runner == runner:
            return build_attack_argv(
                scenario,
                workspace_root=_REPO,
                duration_sec=25.0,
                intensity=0.5,
            )
    return None


def test_defender_heartbeat_is_actually_reliable():
    """前提查核：如果防守端哪天改成 BEST_EFFORT，這個測試的理由就不成立了。

    直接讀防守端的程式，不是憑記憶——這正是 2026-09-02 那次沒做的事。
    """
    source = _MONITOR.read_text(encoding="utf-8")
    assert "/security/heartbeat" in source, "防守端不再訂閱 /security/heartbeat？"
    # `qos_hb` 是心跳用的 profile；它必須是 RELIABLE。
    match = re.search(r"qos_hb\s*=.*?(?=\n\s*\n|\n\S)", source, re.S)
    assert match, "找不到 qos_hb 的定義"
    assert "RELIABLE" in match.group(0), (
        "防守端心跳不再是 RELIABLE，本檔的前提要重新評估：\n" + match.group(0)[:400]
    )


def test_verify_flood_does_not_declare_best_effort():
    """N20 打 /security/heartbeat，防守端是 RELIABLE。

    宣告 `be` 的話 DDS 直接不投遞，而腳本只數自己呼叫了幾次 publish()。
    """
    argv = _argv_for(_CANDIDATE_CATALOG, "verify_flood")
    assert argv is not None, "候選 catalog 裡找不到 verify_flood"
    assert "/security/heartbeat" in argv
    assert "be" not in argv, (
        "verify_flood 又宣告成 BEST_EFFORT 了——對 RELIABLE 訂閱者一則都不會送達。"
        f" argv={argv}"
    )
    assert "reliable" in argv, f"argv={argv}"
    # 第二個軸。只修 reliability 的話 2026-09-15 那一輪已經證明還是送不到。
    assert "transient_local" in argv, (
        "verify_flood 沒有宣告 transient_local——防守端是 TRANSIENT_LOCAL，"
        f"VOLATILE writer 配不上它。argv={argv}"
    )


@pytest.mark.parametrize("catalog_path", [
    _REPO / "firewall_lab" / "scenarios.json",
    _CANDIDATE_CATALOG,
])
def test_no_runner_targets_a_reliable_topic_with_best_effort(catalog_path):
    """全 catalog 掃描，不只 verify_flood 一支。"""
    if not catalog_path.is_file():
        pytest.skip(f"{catalog_path} 不存在")
    catalog = load_catalog(catalog_path)
    offenders = []
    for scenario in catalog.values():
        argv = build_attack_argv(
            scenario,
            workspace_root=_REPO,
            duration_sec=25.0,
            intensity=0.5,
        )
        if not argv:
            continue
        tokens = [str(item) for item in argv]
        if "be" not in tokens:
            continue
        if any(topic in tokens for topic in RELIABLE_DEFENDER_TOPICS):
            offenders.append((scenario.id, tokens))
    assert not offenders, (
        "以下 runner 對 RELIABLE 通道宣告 BEST_EFFORT，訊息不會送達：\n"
        + "\n".join(f"  {sid}: {tok}" for sid, tok in offenders)
    )


def test_the_check_would_have_caught_the_first_incomplete_fix():
    """變異測試之二：只修了 reliability 的那一版必須被抓到。

    2026-09-15 第一次重跑就是這一版,攻擊仍然 rc=2。
    """
    half_fixed = [
        "python3",
        "紅隊測試/PoC腳本/N20_verify_flood.py",
        "/security/heartbeat",
        "25.000",
        "reliable",
    ]
    assert "transient_local" not in half_fixed, (
        "判準對「只修一半」的 argv 不會咬人,那它抓不到 2026-09-15 那次"
    )


def test_the_check_would_have_caught_the_2026_09_02_defect():
    """變異測試：把 argv 還原成當時的樣子，上面那道掃描必須失敗。

    不驗這一條的話，這個測試可能只是恰好通過而抓不到真正的缺陷。
    """
    historical_argv = [
        "python3",
        "紅隊測試/PoC腳本/N20_verify_flood.py",
        "/security/heartbeat",
        "25.000",
        "be",
    ]
    hits = [
        topic for topic in RELIABLE_DEFENDER_TOPICS if topic in historical_argv
    ]
    assert "be" in historical_argv and hits, (
        "判準對 2026-09-02 的實際 argv 不會咬人，那它就沒有用"
    )


# ── 2026-09-19 補上的缺口：這一整組測試都是「讀字串」 ──────────


def test_every_poc_script_actually_parses():
    """上面每一個測試都用 regex 讀原始碼,所以**一個連 parse 都過不了的檔案
    照樣全部通過**。

    2026-09-19 實測到的後果：`N20_verify_flood.py` 有一個
    `SyntaxError: unterminated f-string literal`（某次修補把 `\n` 寫成了真正的
    換行字元,把字串截斷成三段）。它在 2026-09-02、09-15、09-19 三輪 smoke 裡
    都是「攻擊沒有執行」,而這一組測試每一輪都是綠的。

    修補本身正確、測試也正確,只是兩者之間沒有人問過「這個檔案跑得起來嗎」。
    """
    import py_compile

    root = pathlib.Path(__file__).resolve().parents[1]
    scripts = sorted((root / "紅隊測試" / "PoC腳本").glob("*.py"))
    assert scripts, "找不到任何 PoC 腳本——路徑變了?"
    broken = []
    for script in scripts:
        try:
            py_compile.compile(str(script), cfile=None, doraise=True)
        except py_compile.PyCompileError as exc:
            broken.append(f"{script.name}: {exc.msg.strip().splitlines()[-1]}")
    assert not broken, "PoC 腳本語法錯誤：\n" + "\n".join(broken)
