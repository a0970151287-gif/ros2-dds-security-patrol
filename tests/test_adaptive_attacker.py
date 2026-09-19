"""N37 自適應攻擊者的回歸測試。

這一支讓攻擊者**看得到防禦的反應並據此改變行為**，所以它踩在兩條界線上：

1. **證據完整性**：攻擊者不可以拿到 HMAC 金鑰或遙測 socket。拿到任何一個，
   它就能自己偽造「防禦有反應」的證據，整批資料作廢（C2C-053）。
   它只能**數** `/security/alerts` 的訊息，不能驗也不能發。
2. **不重寫攻擊**：驅動器必須 import `build_attack_argv`，不可以自己維護
   第二份參數對應表——重寫就會有兩個版本各自漂移（C2C-054 的程式碼稽核）。

另外守一條結構性的：**一場只打一個類別**。換類別會讓場次變成多標籤，而
`session_labels()` 對多標籤直接拋例外。
"""
from __future__ import annotations

import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_POC = _ROOT / "紅隊測試" / "PoC腳本" / "N37_adaptive_attacker.py"


def _source() -> str:
    return _POC.read_text(encoding="utf-8")


def _body() -> str:
    """只留**程式碼**：模組 docstring 與註解都拿掉。

    第一版只濾 `#` 開頭的行，於是 docstring 裡引用的
    `points = 5000 + intensity*45000`（那是在**描述別人**的寫法）被當成
    驅動器自己在算參數。斷言要看的是程式碼，不是文件。
    """
    import ast

    lines = _source().splitlines()
    tree = ast.parse("\n".join(lines))
    first = tree.body[0] if tree.body else None
    if (isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)):
        # 用**行號**切，不要用字串比對：docstring 裡有 `\\`（用法範例的續行），
        # `ast.get_docstring()` 回傳的值與原始文字不同，replace 會找不到。
        lines = lines[first.end_lineno:]
    return "\n".join(line for line in lines
                     if not line.lstrip().startswith("#"))


# ── 證據完整性 ────────────────────────────────────────────────


def test_attacker_never_touches_the_secret_or_the_telemetry_socket():
    body = _body()
    for banned in ("DDS_ALERT_SECRET", "SROS2_FIREWALL_TELEMETRY_SOCKET",
                   "sign_alert", "verify_alert", "alert_secret"):
        assert banned not in body, f"自適應攻擊者不可以碰 {banned}"


def test_it_only_counts_alerts_and_never_parses_them():
    """沒有金鑰就驗不了簽章。解析內容會讓它看起來比真實攻擊者更強。"""
    source = _source()
    start = source.index("def _on_alert")
    handler = source[start:source.index("def _on_cmd")]
    assert "+= 1" in handler
    for banned in ("json.loads", "msg.data", "decode", "split"):
        assert banned not in handler, f"alert 處理器不該做 {banned}"


def test_observation_channels_are_public_topics_only():
    body = _body()
    subscribed = set(re.findall(r'create_subscription\(\s*\w+,\s*"([^"]+)"',
                                body))
    assert subscribed == {"/security/alerts", "/cmd_vel"}, (
        f"訂閱了預期以外的 topic：{sorted(subscribed)}")


# ── 不重寫攻擊 ────────────────────────────────────────────────


def test_it_reuses_build_attack_argv_instead_of_its_own_parameter_table():
    body = _body()
    assert "from firewall_lab.runners import build_attack_argv" in body
    assert "build_attack_argv(" in body
    # 自己寫 intensity → 參數的對應就是第二份表。
    assert not re.search(r"intensity\s*\*\s*\d", body), (
        "驅動器自己在算參數了——那會變成第二份會漂移的對應表")


def test_the_wrapper_does_not_recurse():
    """`build_adaptive_argv` 不可以呼叫 `build_attack_argv`：N37 內部已經會
    呼叫它，兩邊都叫就會無限遞迴。"""
    import sys
    sys.path.insert(0, str(_ROOT))
    import inspect

    from firewall_lab import runners

    src = inspect.getsource(runners.build_adaptive_argv)
    assert "build_attack_argv(" not in src


# ── 一場一個類別 ──────────────────────────────────────────────


def test_one_vector_per_session():
    """`--scenario` 是單數而且必填；驅動器不得在場次內換類別。"""
    body = _body()
    assert '"--scenario", required=True' in body
    assert "load_catalog(args.catalog)[args.scenario]" in body
    # 沒有任何地方重新挑 scenario。
    assert body.count("[args.scenario]") == 1


# ── 決策規則要是宣告的，而且方向要對 ────────────────────────


def test_decision_thresholds_are_declared_constants():
    import importlib.util

    spec = importlib.util.spec_from_file_location("_n37", _POC)
    mod = importlib.util.module_from_spec(spec)
    # rclpy 不一定裝在測試環境,只取常數就好——用 exec 會跑 import,
    # 所以改成從原始碼讀。
    source = _source()
    values = {}
    for name in ("NOTICE_ALERT_FACTOR", "CONTAINED_ZERO_FRACTION",
                 "ESCALATE", "BACK_OFF", "RECON_SEC",
                 "BURST_MIN_SEC", "BURST_MAX_SEC"):
        m = re.search(rf"^{name}\s*=\s*([0-9.]+)", source, re.MULTILINE)
        assert m, f"找不到宣告的常數 {name}"
        values[name] = float(m.group(1))
    del spec, mod
    # 方向必須合理:升級 > 1 > 退避。
    assert values["ESCALATE"] > 1.0 > values["BACK_OFF"] > 0.0
    assert 0.0 < values["CONTAINED_ZERO_FRACTION"] < 1.0
    assert values["NOTICE_ALERT_FACTOR"] > 1.0
    assert values["BURST_MIN_SEC"] < values["BURST_MAX_SEC"]


def test_a_session_can_fit_several_decision_rounds():
    """一回合 ≈ burst ＋ 間隔。場次太短就只有一個決策點,看不出適應——
    2026-09-20 第一次測就是這樣（29 秒的場次只跑了 1 個 burst）。"""
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import orchestrator as orch

    source = _source()
    recon = float(re.search(r"^RECON_SEC\s*=\s*([0-9.]+)", source,
                            re.MULTILINE).group(1))
    burst_max = float(re.search(r"^BURST_MAX_SEC\s*=\s*([0-9.]+)", source,
                                re.MULTILINE).group(1))
    # 自適應模式的場次長度下限:catalog 最短的攻擊 × 縮放下限。
    shortest_catalog = 30.0
    low = shortest_catalog * orch.JITTER_DURATION_SCALE_ADAPTIVE[0]
    rounds = (low - recon) / (burst_max + 4.0)
    assert rounds >= 3.0, (
        f"最短的自適應場次只塞得下 {rounds:.1f} 個回合，看不出適應")


def test_adaptive_sessions_are_longer_than_plain_ones():
    import sys
    sys.path.insert(0, str(_ROOT))
    from firewall_lab import orchestrator as orch

    assert (orch.JITTER_DURATION_SCALE_ADAPTIVE[0]
            > orch.JITTER_DURATION_SCALE[1]), (
        "自適應場次必須明顯比一般場次長，否則決策回合不夠")


# ── 收尾與軌跡 ────────────────────────────────────────────────


def test_it_exits_hard_after_flushing_and_emits_a_trace():
    source = _source()
    assert "DECISION_TRACE " in source, "沒有輸出可機讀的決策軌跡"
    exit_at = source.index("os._exit(0)")
    assert "sys.stdout.flush()" in source[:exit_at]
    assert 'print("DECISION_TRACE ' in source[:exit_at]


def test_terminate_signals_are_handled():
    source = _source()
    assert "signal.SIGTERM" in source and "signal.SIGINT" in source
    assert "while not _STOP" in source


def test_blind_mode_is_recorded_not_silently_ignored():
    """Enforce 下未認證攻擊者訂閱不到東西。那不是缺陷,是這個威脅模型的
    真實樣子——但必須寫進軌跡,否則事後分不出「沒反應」與「看不到」。"""
    source = _source()
    assert '"blind": not observer.ok' in source
    assert "盲打" in source
