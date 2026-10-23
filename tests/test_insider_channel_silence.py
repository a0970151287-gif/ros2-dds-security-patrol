"""`measure_insider_channel_silence.py` 的判定條件。

這支工具存在的理由是：「內鬼場次身份層 deny = 0」有兩種完全不同的成因，
而它們在資料上長得一模一樣——

    (a) 攻擊在身份層是合法的，所以沒有認證拒絕     ← 要證明的
    (b) 攻擊根本沒跑起來，所以什麼都沒有           ← 毫無意義

所以工具把三件事寫成硬條件。這個檔案確認那三條**真的會拒絕**，而不是
只有在快樂路徑上跑得動。
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

WORKSPACE = Path(__file__).resolve().parents[1]
TOOL = WORKSPACE / "工具腳本" / "measure_insider_channel_silence.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("insider_silence", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


def _session(
    root: Path,
    session_id: str,
    attack_class: str,
    *,
    deny: int = 0,
    hmac_rejects: int = 0,
    veto_rejects: int = 0,
    status: str = "complete",
) -> None:
    session = root / session_id
    session.mkdir(parents=True)
    (session / "manifest.json").write_text(
        json.dumps(
            {
                "session_id": session_id,
                "attack_class": attack_class,
                "security_mode": "enforce",
                "status": status,
            }
        ),
        encoding="utf-8",
    )
    lines = []
    if deny:
        lines.append(
            {"event_type": "sros2_deny",
             "details": {"count": deny, "kind": "authentication"}}
        )
    for _ in range(hmac_rejects):
        lines.append(
            {"event_type": "hmac_result",
             "details": {"outcome": "rejected", "reason": "invalid_signature"}}
        )
    for _ in range(veto_rejects):
        lines.append(
            {"event_type": "parameter_veto", "details": {"layer": "rcl_read_only"}}
        )
    (session / "telemetry_events.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in lines),
        encoding="utf-8",
    )


def _healthy(root: Path) -> None:
    """一批會通過的資料：對照組正常，兩個內鬼沉默且有第二層證據。"""
    for i in range(3):
        _session(root, f"pos{i}", "identity_abuse", deny=18)
        _session(root, f"neg{i}", "normal")
        _session(root, f"hmac{i}", "hmac_forgery", hmac_rejects=40)
        _session(root, f"cd{i}", "confused_deputy", veto_rejects=14)


def _run(root: Path) -> dict:
    return tool.evaluate(
        tool.collect(root),
        insider=["hmac_forgery", "confused_deputy"],
        positive_control="identity_abuse",
        negative_control="normal",
    )


def test_healthy_run_reports_silence(tmp_path):
    _healthy(tmp_path)
    report = _run(tmp_path)
    assert report["verdict"] == "identity_channel_silent_for_insiders"
    findings = report["insider_findings"]
    assert findings["hmac_forgery"]["second_layer_rejections"] == 120
    assert findings["confused_deputy"]["second_layer_rejections"] == 42


def test_missing_positive_control_voids_the_run(tmp_path):
    """沒有正向對照，「內鬼沉默」與「觀測者壞掉」分不開。"""
    for i in range(3):
        _session(tmp_path, f"neg{i}", "normal")
        _session(tmp_path, f"hmac{i}", "hmac_forgery", hmac_rejects=40)
        _session(tmp_path, f"cd{i}", "confused_deputy", veto_rejects=14)
    report = _run(tmp_path)
    assert report["verdict"] == "void_no_positive_control"


def test_positive_control_that_does_not_fire_voids_the_run(tmp_path):
    """觀測者靜默失效是真實會發生的事（C2C-041 的 FastCDR 不一致）。"""
    _healthy(tmp_path)
    _session(tmp_path, "pos_dead", "identity_abuse", deny=0)
    report = _run(tmp_path)
    assert report["verdict"] == "void_positive_control_did_not_fire"
    assert "3/4" in report["verdict_reason"]


def test_negative_control_that_fires_voids_the_run(tmp_path):
    """正常流量也有訊號時，內鬼的沉默無法歸因。"""
    _healthy(tmp_path)
    _session(tmp_path, "neg_dirty", "normal", deny=5)
    report = _run(tmp_path)
    assert report["verdict"] == "void_negative_control_fired"


def test_insider_without_second_layer_evidence_is_void_not_pass(tmp_path):
    """這是整支工具存在的理由：沒跑起來的攻擊也會是零。"""
    for i in range(3):
        _session(tmp_path, f"pos{i}", "identity_abuse", deny=18)
        _session(tmp_path, f"neg{i}", "normal")
        _session(tmp_path, f"hmac{i}", "hmac_forgery", hmac_rejects=40)
        # confused_deputy 完全沒有 veto —— 攻擊可能根本沒抵達節點
        _session(tmp_path, f"cd{i}", "confused_deputy")
    report = _run(tmp_path)
    assert report["verdict"] == "void_insufficient_second_layer_evidence"
    assert report["insider_findings"]["confused_deputy"]["verdict"] == (
        "void_attack_may_not_have_run"
    )
    # hmac_forgery 有證據，不該被連坐成「沒跑」
    assert report["insider_findings"]["hmac_forgery"]["verdict"] == (
        "silent_and_blocked_downstream"
    )


def test_insider_that_does_fire_is_reported_not_hidden(tmp_path):
    """如果內鬼真的觸發身份層，結論要改而不是被吞掉。"""
    _healthy(tmp_path)
    _session(tmp_path, "hmac_loud", "hmac_forgery", deny=7, hmac_rejects=40)
    report = _run(tmp_path)
    assert report["verdict"] == "identity_channel_not_silent_for_insiders"
    assert "hmac_forgery" in report["verdict_reason"]


def test_incomplete_sessions_are_ignored(tmp_path):
    """跑到一半的場次不得計入——它的證據還沒寫完。"""
    _healthy(tmp_path)
    _session(tmp_path, "pos_running", "identity_abuse", deny=0, status="running")
    report = _run(tmp_path)
    assert report["verdict"] == "identity_channel_silent_for_insiders"
    assert report["classes"]["identity_abuse"]["sessions"] == 3


def test_deny_without_count_field_still_counts_as_signal(tmp_path):
    """寧可高估身份層訊號，不可低估——低估會把「有反應」讀成「沉默」。"""
    _healthy(tmp_path)
    session = tmp_path / "hmac_odd"
    session.mkdir()
    (session / "manifest.json").write_text(
        json.dumps({"session_id": "hmac_odd", "attack_class": "hmac_forgery",
                    "status": "complete"}),
        encoding="utf-8",
    )
    (session / "telemetry_events.jsonl").write_text(
        json.dumps({"event_type": "sros2_deny", "details": {"kind": "authentication"}})
        + "\n",
        encoding="utf-8",
    )
    report = _run(tmp_path)
    assert report["classes"]["hmac_forgery"]["sessions_with_identity_signal"] == 1
    assert report["verdict"] == "identity_channel_not_silent_for_insiders"


def test_output_refuses_to_overwrite(tmp_path, monkeypatch, capsys):
    """量測是一次性的，覆寫會抹掉原始數字。"""
    _healthy(tmp_path)
    out = tmp_path / "report.json"
    out.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        ["tool", "--dataset", str(tmp_path), "--output", str(out)],
    )
    assert tool.main() == 2
    assert "拒絕覆寫" in capsys.readouterr().out
    assert out.read_text(encoding="utf-8") == "{}"


def test_second_layer_signature_is_class_specific(tmp_path):
    """用錯類別的證據不算數：HMAC 拒絕不能拿來證明 parameter veto 發生過。"""
    for i in range(3):
        _session(tmp_path, f"pos{i}", "identity_abuse", deny=18)
        _session(tmp_path, f"neg{i}", "normal")
        _session(tmp_path, f"hmac{i}", "hmac_forgery", hmac_rejects=40)
        # confused_deputy 只有 HMAC 拒絕，沒有它自己那一種
        _session(tmp_path, f"cd{i}", "confused_deputy", hmac_rejects=40)
    report = _run(tmp_path)
    assert report["verdict"] == "void_insufficient_second_layer_evidence"
