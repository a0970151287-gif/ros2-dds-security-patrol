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


# --------------------------------------------------------------------------
# 兩兩可分性（2026-09-01 實跑發現 gate 有缺口）
# --------------------------------------------------------------------------
#
# 九支候選跑完，五支通過個別判定——但其中三支彼此分不開：
#
#     mission_spoof 的訊號 ⊂ confused_deputy 的 ⊂ health_spoof 的
#     三者共用 hmac_result.reason=malformed_envelope
#
# 它們對 normal 排他，卻對彼此不排他。**那正是這道 gate 本來要防的失效**
# （C2C-013 的 parameter_tamper / replay）。只比「候選 vs normal」不夠。


def _report(scenario: str, signals: dict, verdict: str = "pass") -> dict:
    return {
        "scenario_id": scenario,
        "verdict": verdict,
        "exclusive_signals": signals,
    }


def test_two_classes_with_identical_signals_are_not_separable():
    """對 normal 排他不代表對彼此排他。"""
    result = gate.pairwise_separability([
        _report("health_spoof", {"hmac_result.reason=malformed_envelope": 113}),
        _report("mission_spoof", {"hmac_result.reason=malformed_envelope": 246}),
    ])

    assert result["all_separable"] is False
    assert ["health_spoof", "mission_spoof"] in result["inseparable_pairs"]


def test_a_strict_subset_is_not_separable_either():
    """實測就是這一種：一方的訊號完全包含另一方。

    mission_spoof ⊂ confused_deputy。被包含的那一個沒有任何自己獨有的訊號，
    所以分不開——即使包含它的那一個有。
    """
    result = gate.pairwise_separability([
        _report("confused_deputy", {
            "hmac_result.reason=malformed_envelope": 7,
            "alert_observation.reflection_count>0": 7,
        }),
        _report("mission_spoof", {
            "hmac_result.reason=malformed_envelope": 246,
        }),
    ])

    assert result["all_separable"] is False


def test_classes_each_holding_a_unique_signal_are_separable():
    """共用一部分沒關係，只要每一邊都有別人沒有的。"""
    result = gate.pairwise_separability([
        _report("cross_channel_relay", {
            "hmac_result.outcome=rejected": 51,
            "hmac_result.reason=channel_mismatch": 51,
        }),
        _report("scan_drift", {
            "log_reject": 15,
            "authenticated_action.action=guard_lock": 4,
        }),
    ])

    assert result["all_separable"] is True
    assert result["inseparable_pairs"] == []


def test_rejected_candidates_are_left_out_of_the_comparison():
    """沒通過個別判定的不該進兩兩比對——它們根本沒有訊號可比。"""
    result = gate.pairwise_separability([
        _report("cross_channel_relay", {"a": 1}),
        _report("verify_flood", {}, verdict="reject_no_exclusive_evidence"),
    ])

    assert result["candidates_compared"] == ["cross_channel_relay"]
    assert result["pairs"] == []

# ---------------------------------------------------- 欄位組合（2026-09-02）

def _ev(kind: str, **details):
    return {"event_type": kind, "details": details}


def test_field_pairs_are_counted_as_their_own_signal(tmp_path):
    """逐欄位編碼會丟掉配對資訊，而判別力正好在配對上。"""
    d = _session(tmp_path, "s", [
        _ev("hmac_result", outcome="rejected", reason="malformed_envelope",
            channel="system/health"),
    ], attack=OK_ATTACK)
    counts = gate.telemetry_signals(d)
    assert counts["hmac_result.channel=system/health"] == 1
    assert counts["hmac_result.outcome=rejected"] == 1
    pairs = {k for k in counts if "&" in k}
    assert any("channel=system/health" in k and "reason=malformed_envelope" in k
               for k in pairs), sorted(pairs)


def test_a_pair_can_be_exclusive_while_neither_field_is(tmp_path):
    """這是加入配對編碼的**唯一理由**，直接寫成測試。

    實測：正常流量本來就在 `system/health` 上驗章（基線 22 次），所以
    `channel=X` 單獨不排他；有判別力的是「在那個頻道上被拒絕」。
    """
    base = _session(tmp_path, "base", [
        _ev("hmac_result", outcome="accepted", reason="accepted",
            channel="system/health"),
        _ev("hmac_result", outcome="rejected", reason="invalid_signature",
            channel="alerts"),
    ])
    cand = _session(tmp_path, "cand", [
        _ev("hmac_result", outcome="rejected", reason="malformed_envelope",
            channel="system/health"),
    ], attack=OK_ATTACK)
    b, c = gate.telemetry_signals(base), gate.telemetry_signals(cand)
    assert b["hmac_result.channel=system/health"] > 0
    assert b["hmac_result.outcome=rejected"] > 0
    pair = next(k for k in c if "&" in k and "channel=system/health" in k
                and "outcome=rejected" in k)
    assert b[pair] == 0


def test_pairs_do_not_explode(tmp_path):
    """details 只有 2–4 個欄位，配對數必須是 O(n²) 而不是子集數 O(2ⁿ)。"""
    d = _session(tmp_path, "s", [_ev("x", a="1", b="2", c="3", d="4")],
                 attack=OK_ATTACK)
    counts = gate.telemetry_signals(d)
    singles = [k for k in counts if "&" not in k]
    pairs = [k for k in counts if "&" in k]
    # 事件種類本身也算一個訊號（"x"），所以是 1 + 4 個欄位
    assert sorted(singles) == ["x", "x.a=1", "x.b=2", "x.c=3", "x.d=4"]
    assert len(pairs) == 6          # C(4,2)，不是 2⁴
    assert not any(k.count("&") > 1 for k in counts)


def test_numeric_pairs_keep_the_zero_nonzero_encoding(tmp_path):
    """配對必須沿用單欄位的語意，不可退回比較原始數值。"""
    a = gate.telemetry_signals(
        _session(tmp_path, "a", [_ev("m", count=7, oversized_count=3)],
                 attack=OK_ATTACK))
    b = gate.telemetry_signals(
        _session(tmp_path, "b", [_ev("m", count=99, oversized_count=1)],
                 attack=OK_ATTACK))
    assert set(a) == set(b), "不同的非零值不該產生不同的訊號"
