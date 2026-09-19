"""`N36_graph_overflow` 候選的回歸測試。

這一支攻擊打的是 `monitor_node._check_graph()` 的一道 fail-safe：

    if graph_nodes is None or len(graph_nodes) > _GRAPH_NODE_MAX:   # 256
        _record_graph_transition(self, "overflow", ...)
        ... 冷卻 30 秒才發一次告警 ... 緊急停止 ...
        return                       # ← 白名單比對整段不執行

**那個 `return` 就是攻擊面**：溢位期間 monitor 停止偵測未授權節點。
所以這裡釘的是**控制流本身**——誰把 `return` 改成繼續往下走、或把上限拿掉，
這些測試就會紅，而那正是修補的位置。

⚠️ 這一支原本的假說是「心跳餓死」（monitor 單執行緒、守衛租約 5s < IDS 門檻
10s）。跑 live 之前的微基準推翻了它：400 個 node 時
`get_node_names_and_namespaces()` 只要 0.05 ms，離餓死 2 秒的計時器差三個
數量級。那個不等式仍然存在，只是這條路到不了它。
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_POC = _ROOT / "紅隊測試" / "PoC腳本" / "N36_graph_overflow.py"
_MONITOR = (_ROOT / "src" / "dds_security_monitor" / "dds_security_monitor"
            / "monitor_node.py")


def _constant(path: pathlib.Path, name: str) -> float:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"^{re.escape(name)}\s*(?::\s*[A-Za-z_][A-Za-z0-9_]*)?\s*=\s*"
        r"([0-9]+\.?[0-9]*)", text, re.MULTILINE)
    assert match, f"{path.name} 找不到常數 {name}"
    return float(match.group(1))


# ── 攻擊面：溢位時提早 return ────────────────────────────────


def test_graph_node_cap_exists_and_is_what_the_poc_targets():
    cap = _constant(_MONITOR, "_GRAPH_NODE_MAX")
    assert cap == pytest.approx(256)
    poc = _POC.read_text(encoding="utf-8")
    assert "DEFENDER_GRAPH_NODE_MAX = 256" in poc, (
        "防守端的門檻改了而 PoC 的參考值沒跟上")


def test_overflow_path_returns_before_the_whitelist_comparison():
    """溢位分支必須在白名單比對**之前** return——那就是偵測空窗。

    這個測試不是在說那個 return 是錯的（fail-closed 有它的理由），
    而是把「它存在」這件事釘起來，因為 N36 的整個論點建立在它上面。
    """
    text = _MONITOR.read_text(encoding="utf-8")
    start = text.index("def _check_graph")
    body = text[start:start + 4000]
    overflow_at = body.index("_GRAPH_NODE_MAX")
    return_at = body.index("\n            return\n", overflow_at)
    whitelist_at = body.index("current: set[str] = set()")
    assert overflow_at < return_at < whitelist_at, (
        "溢位分支不再於白名單比對前 return——N36 的偵測空窗沒了")


def test_overflow_triggers_the_emergency_stop():
    text = _MONITOR.read_text(encoding="utf-8")
    start = text.index("def _check_graph")
    body = text[start:start + 4000]
    assert "_trigger_emergency_stop" in body


def test_evidence_is_scarce_by_design():
    """兩個機制讓溢位幾乎不留痕跡，而特徵視窗只有 8 秒。"""
    cooldown = _constant(_MONITOR, "_GRAPH_OVERFLOW_ALERT_COOLDOWN_SEC")
    assert cooldown == pytest.approx(30.0)
    assert cooldown > 8.0, "告警冷卻短於特徵視窗的話，證據就不稀缺了"
    # 狀態轉換才發：持續溢位只留下一筆 graph_state。
    text = _MONITOR.read_text(encoding="utf-8")
    start = text.index("def _record_graph_transition")
    body = text[start:start + 700]
    assert "if previous == normalized:" in body and "return" in body


def test_graph_state_is_a_declared_telemetry_event():
    vocab = (_ROOT / "src" / "dds_security_monitor" / "dds_security_monitor"
             / "runtime_telemetry.py").read_text(encoding="utf-8")
    assert "def emit_graph_state" in vocab
    assert '"graph_state"' in vocab


# ── PoC 本身 ──────────────────────────────────────────────────


def test_poc_records_the_falsified_hypothesis():
    """被推翻的假說要留在檔案裡。不留的話，下一個人會再想一次同一條路。"""
    text = _POC.read_text(encoding="utf-8")
    assert "被推翻" in text
    assert "0.05 ms" in text, "要留下推翻它的那個量測值"


def test_poc_declares_its_predictions():
    text = _POC.read_text(encoding="utf-8")
    for marker in ("P1", "P2", "P3", "P4"):
        assert f"**{marker}**" in text, f"缺少事前預測 {marker}"


def test_poc_never_touches_the_hmac_secret_or_telemetry_socket():
    text = _POC.read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("#"))
    for banned in ("DDS_ALERT_SECRET", "SROS2_FIREWALL_TELEMETRY",
                   "alert_secret", "sign_alert"):
        assert banned not in body, f"PoC 不可以碰 {banned}"


def test_poc_has_hard_caps():
    text = _POC.read_text(encoding="utf-8")
    assert "MAX_NODES_HARD" in text and "MAX_DURATION_SEC" in text


# ── 接線 ──────────────────────────────────────────────────────


def _scenario():
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import catalog

    scenarios = catalog.load_catalog(
        str(_ROOT / "firewall_lab" / "scenarios_smoke_candidates.json"))
    return scenarios["graph_overflow"]


def test_runner_is_allowed_and_wired():
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import catalog, runners

    assert "graph_overflow" in catalog.ALLOWED_RUNNERS
    argv = runners.build_attack_argv(
        _scenario(), workspace_root=_ROOT, duration_sec=45.0, intensity=1.0)
    assert argv is not None
    assert argv[1].endswith("N36_graph_overflow.py")


def test_every_intensity_crosses_the_defender_cap():
    """上限沒有跨過 256 的話，這一場什麼都不會發生——而 rc 仍然是 0，
    看起來像「攻擊跑了但防禦沒反應」。那是最糟的一種空跑。"""
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import runners

    scenario = _scenario()
    for intensity in (0.0, 0.1, 0.5, 1.0):
        argv = runners.build_attack_argv(
            scenario, workspace_root=_ROOT, duration_sec=45.0,
            intensity=intensity)
        ceiling = int(argv[argv.index("--max-nodes") + 1])
        assert ceiling > 256, f"intensity={intensity} 的上限 {ceiling} 跨不過門檻"


def test_intensity_only_moves_the_ceiling_not_the_ramp():
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import runners

    scenario = _scenario()

    def argv_for(intensity):
        return runners.build_attack_argv(
            scenario, workspace_root=_ROOT, duration_sec=45.0,
            intensity=intensity)

    low, high = argv_for(0.1), argv_for(1.0)

    def value(argv, flag):
        return argv[argv.index(flag) + 1]

    for flag in ("--start", "--step", "--step-sec"):
        assert value(low, flag) == value(high, flag)
    assert int(value(low, "--max-nodes")) < int(value(high, "--max-nodes"))


def test_the_candidate_is_not_in_the_shipping_catalog():
    shipping = json.loads(
        (_ROOT / "firewall_lab" / "scenarios.json").read_text(encoding="utf-8"))
    ids = {s["id"] for s in shipping["scenarios"]}
    assert "graph_overflow" not in ids
    # 2026-09-20 verify_flood 升級之後是 20 支。
    assert len(ids) == 20


def test_it_is_not_a_credentialed_runner():
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import runners

    assert "graph_overflow" not in runners.CREDENTIALED_RUNNERS


def test_teardown_must_not_destroy_nodes_one_by_one():
    """收尾太慢會讓整場證據作廢,而且看起來像「攻擊沒有執行」。

    2026-09-19 第一次 live：340 個 node 逐一 destroy_node() 要 11.92 秒,
    超過 orchestrator 的寬限期 → SIGKILL → manifest return_code=-9 →
    證據排他性 gate 判 `void_attack_did_not_run`。
    攻擊其實完整跑完了（遙測有 graph_state overflow node_count=339）。
    實測同樣 340 個:只呼叫一次 rclpy.shutdown() 是 1.92 秒。
    """
    text = _POC.read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("#"))
    assert "destroy_node()" not in body, (
        "逐一銷毀會讓行程被 SIGKILL,整場證據作廢")
    assert "rclpy.shutdown()" in body


def test_terminate_signals_break_the_loop_promptly():
    """收到 SIGTERM 要立刻跳出去收尾,不能撐到自己的 deadline。"""
    text = _POC.read_text(encoding="utf-8")
    assert "signal.SIGTERM" in text and "signal.SIGINT" in text
    assert "while not _STOP" in text


def test_the_main_loop_stops_before_the_duration_to_leave_room_for_teardown():
    """收尾預算必須從**主迴圈**扣,不是只讓它停止建立。

    2026-09-19 第四輪:build_until 有扣,但主迴圈仍跑滿 deadline,收尾一開始
    就超時(74.1s vs 70s)→ SIGKILL → return_code=-9 → 整場作廢。
    """
    text = _POC.read_text(encoding="utf-8")
    assert "hard_deadline = t0 + duration" in text
    assert "deadline = hard_deadline - TEARDOWN_RESERVE_SEC" in text
    assert "build_until = deadline - " in text


def test_process_exits_hard_after_flushing():
    """332 個 participant 的 DDS 清理會讓直譯器在退出時卡住。

    2026-09-19 第五輪:主迴圈與收尾都在時限內(57.1s / 70s)、訊息也印出來了,
    行程仍然拿到 return_code=-9。對攻擊端沒有需要保留的狀態,硬退即可;
    但必須先 flush,否則 stdout 會掉,而那是與防守端遙測對齊的唯一依據。
    """
    text = _POC.read_text(encoding="utf-8")
    exit_at = text.index("os._exit(0)")
    assert "sys.stdout.flush()" in text[:exit_at]
    assert "sys.stderr.flush()" in text[:exit_at]
