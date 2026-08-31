"""擴充攻擊面之前的證據排他性 gate。

判準來自 C2C-013 量到的規律：**識別率由證據排他性決定**。`parameter_tamper`
與 `replay` 認不出來，不是模型不好，是它們觸發的是同一組五個通用特徵——
模型手上沒有任何資訊可以分開它們。

這個 gate 已用既有真實資料雙向驗證過（2026-09-01）：

| Scenario | 原始資料 | 300 場重跑後 |
|---|---|---|
| `oversized_scan`（recall 1.000） | ✅ 通過 | — |
| `heartbeat_replay`（recall 0.375） | ❌ 拒絕 | ✅ 通過 |
| `parameter_tamper`（recall 0.429） | ❌ 拒絕 | ✅ 通過 |

而且它指出的專屬訊號正是 8/21 那兩個修正補上的通道
（`nonce_reuse_or_capacity` 與 `parameter_call`）——與 C2C-024 記錄的
可否證預測相符。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "工具腳本" / "check_evidence_exclusivity.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_evidence_exclusivity", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


gate = _load()


def _session(tmp_path: Path, name: str, events: list[dict],
             *, attack: dict | None = None,
             attack_class: str = "message_dos") -> Path:
    d = tmp_path / name
    d.mkdir(parents=True)
    manifest = {
        "session_id": name,
        "scenario_id": name,
        "attack_class": attack_class,
        "security_mode": "permissive",
        "result": {} if attack is None else {"attack_process": attack},
    }
    (d / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (d / "telemetry_events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    return d


OK_ATTACK = {"return_code": 0, "duration_sec": 40.0}


def test_the_discriminating_field_lives_inside_details(tmp_path):
    """第一版讀頂層欄位，於是完全看不到專屬訊號。

    實測 `oversized_scan` 的訊號是 `message_validation` 的
    `oversized_count>0`（候選 56 次、基線 0 次），它在 `details` 裡面。
    讀錯層會讓 gate 拒絕一個已知 recall 1.000 的類別。
    """
    events = [
        {"event_type": "message_validation",
         "details": {"count": 7, "oversized_count": 3}}
        for _ in range(5)
    ]
    signals = gate.telemetry_signals(
        _session(tmp_path, "cand", events, attack=OK_ATTACK)
    )

    assert signals["message_validation.oversized_count>0"] == 5


def test_numeric_fields_are_compared_as_zero_versus_nonzero(tmp_path):
    """`count=7` 與 `count=8` 是同一件事。

    直接拿值當鍵會讓每個不同的計數變成一個獨立「訊號」，於是任何攻擊都會
    看起來有一堆專屬訊號——gate 就失去意義了。
    """
    events = [
        {"event_type": "message_validation", "details": {"count": n}}
        for n in (7, 8, 9, 10)
    ]
    signals = gate.telemetry_signals(
        _session(tmp_path, "cand", events, attack=OK_ATTACK)
    )

    assert signals["message_validation.count>0"] == 4
    assert not any(k.startswith("message_validation.count=")
                   for k in signals if k.endswith(("7", "8", "9")))


def test_a_counter_that_stays_zero_is_not_an_exclusive_signal(tmp_path):
    """恆零的計數器在候選與基線都是 `=0`，不該被當成專屬。"""
    same = [
        {"event_type": "message_validation",
         "details": {"count": 3, "oversized_count": 0}}
        for _ in range(5)
    ]
    candidate = gate.telemetry_signals(
        _session(tmp_path, "cand", same, attack=OK_ATTACK)
    )
    baseline = gate.telemetry_signals(
        _session(tmp_path, "base", same, attack_class="normal")
    )

    exclusive = {
        k: v for k, v in candidate.items()
        if v >= 3 and baseline.get(k, 0) == 0
    }
    assert exclusive == {}


def test_an_attack_that_did_not_run_is_void_not_rejected():
    """兩者在資料上長得一樣，意義完全不同。

    「攻擊沒執行」與「攻擊執行了但沒有專屬證據」都會得到零訊號。把前者記成
    後者，等於把一個沒跑的實驗寫成「這個類別沒有證據通道」——這個專案被
    「兩種原因產生同一個觀測」咬過七次。
    """
    ran, why = gate.attack_actually_ran(
        {"attack_class": "message_dos", "result": {}}
    )
    assert ran is False
    assert "沒有執行" in why

    ran, why = gate.attack_actually_ran({
        "attack_class": "message_dos",
        "result": {"attack_process": {"return_code": 1, "duration_sec": 40.0}},
    })
    assert ran is False
    assert "return_code=1" in why


def test_an_attack_that_exits_instantly_counts_as_not_run():
    """跑 0.02 秒就結束的攻擊不該被當成「執行過」。"""
    ran, why = gate.attack_actually_ran({
        "attack_class": "message_dos",
        "result": {"attack_process": {"return_code": 0, "duration_sec": 0.02}},
    })
    assert ran is False
    assert "太短" in why


def test_a_normal_session_needs_no_attack_process():
    """基線場次本來就沒有攻擊行程，不該被判成作廢。"""
    ran, _ = gate.attack_actually_ran(
        {"attack_class": "normal", "result": {}}
    )
    assert ran is True
