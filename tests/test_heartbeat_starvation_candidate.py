"""`N36_heartbeat_starvation` 候選的回歸測試。

這一支攻擊打的是 monitor 的**執行緒預算**，不是某個 topic。它成立的前提是三個
常數之間的關係，而那三個常數散在三個檔案裡：

    monitor_node._HEARTBEAT_PERIOD_SEC              2.0   心跳多久發一次
    velocity_guard_node.HEARTBEAT_LEASE_TIMEOUT_SEC 5.0   守衛多久沒收到就鎖定
    intelligent_defense_node.HEARTBEAT_TIMEOUT_SEC 10.0   IDS 多久沒收到才告警

**只要有人把 5.0 調到 ≥ 10.0，這個攻擊的「隱形」那一半就消失了**（守衛鎖定的
同時 IDS 也會告警）。反過來把 10.0 調到 ≤ 5.0 也一樣。所以這裡把那個**不等式**
釘起來——它是攻擊存在的理由，也是修補它的位置。

其餘測試守的是安全界線：攻擊行程不可以拿到 HMAC 金鑰或遙測 socket，
否則它可以自己偽造「防禦有反應」的證據，整批資料就作廢（C2C-053）。
"""
from __future__ import annotations

import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_POC = _ROOT / "紅隊測試" / "PoC腳本" / "N36_heartbeat_starvation.py"
_SRC = _ROOT / "src" / "dds_security_monitor" / "dds_security_monitor"


def _constant(path: pathlib.Path, name: str) -> float:
    text = path.read_text(encoding="utf-8")
    # 三個常數的寫法不一致：有的帶型別註解（`X: float = 2.0`），有的沒有。
    match = re.search(
        rf"^{re.escape(name)}\s*(?::\s*[A-Za-z_][A-Za-z0-9_]*)?\s*=\s*"
        r"([0-9]+\.?[0-9]*)", text, re.MULTILINE)
    assert match, f"{path.name} 找不到常數 {name}"
    return float(match.group(1))


# ── 攻擊存在的理由：三個常數之間的不等式 ──────────────────────


def test_the_guard_locks_strictly_before_the_ids_alerts():
    """守衛租約 < IDS 門檻 ⇒ 存在「已停住但沒告警」的窗。

    這個不等式就是 N36 的攻擊面。誰把它改掉，這個測試就會紅——那是提醒，
    不是錯誤：攻擊沒了，候選也該跟著重新評估。
    """
    lease = _constant(_SRC / "velocity_guard_node.py",
                      "HEARTBEAT_LEASE_TIMEOUT_SEC")
    alert = _constant(_SRC / "intelligent_defense_node.py",
                      "HEARTBEAT_TIMEOUT_SEC")
    assert lease == pytest.approx(5.0)
    assert alert == pytest.approx(10.0)
    assert lease < alert, (
        "守衛租約已經不早於 IDS 門檻——N36 賴以存在的靜默窗消失了")


def test_the_heartbeat_period_is_short_enough_that_a_gap_means_starvation():
    """心跳 2 秒一次，所以 >5 秒的間隔代表至少漏發兩次，不是抖動。"""
    period = _constant(_SRC / "monitor_node.py", "_HEARTBEAT_PERIOD_SEC")
    lease = _constant(_SRC / "velocity_guard_node.py",
                      "HEARTBEAT_LEASE_TIMEOUT_SEC")
    assert period == pytest.approx(2.0)
    assert lease >= 2 * period, "租約不到兩個心跳週期，會被正常抖動誤觸發"


def test_the_monitor_still_runs_on_a_single_threaded_executor():
    """攻擊的機制是「graph 檢查與心跳搶同一條執行緒」。

    改成 MultiThreadedExecutor 或給心跳自己的 callback group，攻擊就不成立。
    """
    text = (_SRC / "monitor_node.py").read_text(encoding="utf-8")
    assert "rclpy.spin(node)" in text
    assert "MultiThreadedExecutor" not in text
    assert "ReentrantCallbackGroup" not in text


def test_the_graph_check_cost_scales_with_graph_size():
    text = (_SRC / "monitor_node.py").read_text(encoding="utf-8")
    assert "get_node_names_and_namespaces()" in text


# ── PoC 本身 ──────────────────────────────────────────────────


def test_poc_exists_and_declares_its_predictions():
    text = _POC.read_text(encoding="utf-8")
    # 事前預測必須寫在腳本裡,跑完才不能改口。
    for marker in ("P1", "P2", "P3"):
        assert f"**{marker}**" in text, f"缺少事前預測 {marker}"


def test_poc_never_touches_the_hmac_secret_or_telemetry_socket():
    """攻擊端拿到任何一個,就能自己偽造「防禦有反應」的證據。"""
    text = _POC.read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("#"))
    for banned in ("DDS_ALERT_SECRET", "SROS2_FIREWALL_TELEMETRY",
                   "alert_secret", "sign_alert"):
        assert banned not in body, f"PoC 不可以碰 {banned}"


def test_poc_has_a_hard_cap_on_nodes():
    """DDS discovery 是 O(n²)。沒有上限的話攻擊者會先打死自己,
    而「攻擊者自己掛掉」與「防禦擋下了」在遙測上分不出來（C2C-020）。"""
    text = _POC.read_text(encoding="utf-8")
    assert "MAX_NODES_HARD" in text
    assert "MAX_DURATION_SEC" in text


# ── 接線 ──────────────────────────────────────────────────────


def test_runner_is_allowed_and_wired():
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import catalog, runners

    assert "heartbeat_starvation" in catalog.ALLOWED_RUNNERS
    scenarios = catalog.load_catalog(
        str(_ROOT / "firewall_lab" / "scenarios_smoke_candidates.json"))
    assert "heartbeat_starvation" in scenarios
    scenario = scenarios["heartbeat_starvation"]
    argv = runners.build_attack_argv(
        scenario, workspace_root=_ROOT, duration_sec=45.0, intensity=1.0)
    assert argv is not None
    assert argv[1].endswith("N36_heartbeat_starvation.py")
    assert "--max-nodes" in argv


def test_intensity_only_moves_the_ceiling_not_the_ramp():
    """爬升節奏固定,只有上限隨 intensity 走。

    節奏也跟著變的話,就分不出門檻是被「node 數」還是「爬升速度」推過去的。
    """
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import catalog, runners

    scenarios = catalog.load_catalog(
        str(_ROOT / "firewall_lab" / "scenarios_smoke_candidates.json"))
    scenario = scenarios["heartbeat_starvation"]

    def argv_for(intensity):
        return runners.build_attack_argv(
            scenario, workspace_root=_ROOT, duration_sec=45.0,
            intensity=intensity)

    low, high = argv_for(0.1), argv_for(1.0)
    def value(argv, flag):
        return argv[argv.index(flag) + 1]

    assert value(low, "--step-sec") == value(high, "--step-sec")
    assert value(low, "--step") == value(high, "--step")
    assert value(low, "--start") == value(high, "--start")
    assert int(value(low, "--max-nodes")) < int(value(high, "--max-nodes"))


def test_the_candidate_is_not_in_the_shipping_catalog():
    """沒通過證據排他性 gate 之前不可以進出貨 catalog——改它的 SHA-256
    會讓既有 campaign 的來源憑證失效（2026-09-01 發生過一次）。"""
    import json

    shipping = json.loads(
        (_ROOT / "firewall_lab" / "scenarios.json").read_text(encoding="utf-8"))
    ids = {s["id"] for s in shipping["scenarios"]}
    assert "heartbeat_starvation" not in ids
    assert len(ids) == 19


def test_it_is_not_a_credentialed_runner():
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import runners

    assert "heartbeat_starvation" not in runners.CREDENTIALED_RUNNERS
