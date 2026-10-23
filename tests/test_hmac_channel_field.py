"""`hmac_result` 的 `channel` 欄位：生產端必填、驗證端選填。

## 為什麼需要這個欄位

`malformed_envelope` 這個理由本身不足以分辨攻擊。實測 N7（mission_spoof）與
N8（health_spoof）都是「對受保護 topic publish 未簽章字串」，撞的是驗證器裡
**同一個分支**；真正不同的是**打哪一個頻道**。沒有這個欄位，兩者在遙測上
完全相同，證據排他性 gate 判它們兩兩不可分。

## 為什麼是不對稱的

| 端 | 必填？ | 理由 |
|---|---|---|
| 生產端 `emit_hmac_result` | **必填** | 選填會讓它悄悄消失——C2C-047 那次就是發送端字彙表缺一項，接縫正常運作卻一個事件都沒有 |
| 收集端 `validate_telemetry_event` | **選填** | 1,100 場既有證據沒有這個欄位，而那些檔案不可變；`features.py` 會重新驗證它們，必填會讓整批讀不出來 |

少任何一邊都不行，所以兩邊各有一個測試釘住。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from firewall_lab import live_telemetry_collector as collector

pytest.importorskip("rclpy", reason="需要 ROS 環境才能載入 monitor_node")

from dds_security_monitor import monitor_node  # noqa: E402
from dds_security_monitor import runtime_telemetry  # noqa: E402


# ------------------------------------------------------ 兩邊詞彙表必須相等

def test_channel_vocabularies_are_identical_on_both_sides():
    """發送端與收集端的字彙表分岔過一次，代價是七輪 live 被記成防禦失效。"""
    assert runtime_telemetry.HMAC_CHANNELS == collector.HMAC_CHANNELS


def test_vocabulary_matches_the_monitor_channel_constants():
    """詞彙表若與 CH_* 常數漂移，真實的拒絕會被字彙表擋在門外。"""
    declared = {
        monitor_node.CH_ALERTS,
        monitor_node.CH_HEARTBEAT,
        monitor_node.CH_GOTO,
        monitor_node.CH_SENSOR,
        monitor_node.CH_MISSION,
        monitor_node.CH_HEALTH,
    }
    assert declared == runtime_telemetry.HMAC_CHANNELS


# ------------------------------------------------------ 生產端：必填

def test_producer_requires_channel():
    observed: list[dict] = []
    producer = SimpleNamespace(emit_hmac_result=lambda **kw: observed.append(kw))
    with pytest.raises(TypeError):
        runtime_telemetry.RuntimeTelemetryProducer.emit_hmac_result(
            producer, accepted=False, reason="invalid_signature"
        )


def test_producer_rejects_a_channel_outside_the_vocabulary():
    with pytest.raises(ValueError):
        runtime_telemetry.RuntimeTelemetryProducer.emit_hmac_result(
            SimpleNamespace(_emit=lambda *a, **k: True),
            accepted=False,
            reason="invalid_signature",
            channel="/system/health",   # 多了斜線開頭，不是 CH_HEALTH 的值
        )


# ------------------------------------------------------ 收集端：選填但驗值

def _event(details: dict) -> dict:
    return {
        "schema_version": collector.TELEMETRY_EVENT_SCHEMA_VERSION,
        "session_id": "20260902T000000000000Z_test_00000000",
        "sequence": 0,
        "ts_unix_ns": 1_770_000_000_000_000_000,
        "monotonic_ns": 1_000_000,
        "source": "telemetry_collector",
        "event_type": "hmac_result",
        "details": details,
    }


def test_collector_still_accepts_historical_events_without_channel():
    """1,100 場既有證據沒有這個欄位，而 features.py 會重新驗證它們。"""
    out = collector.validate_telemetry_event(
        _event({"outcome": "rejected", "reason": "malformed_envelope"})
    )
    assert out["details"] == {"outcome": "rejected", "reason": "malformed_envelope"}


def test_collector_keeps_the_channel_when_present():
    out = collector.validate_telemetry_event(
        _event({
            "outcome": "rejected",
            "reason": "malformed_envelope",
            "channel": "system/health",
        })
    )
    assert out["details"]["channel"] == "system/health"


def test_collector_rejects_an_unknown_channel():
    with pytest.raises(collector.SchemaError):
        collector.validate_telemetry_event(
            _event({
                "outcome": "rejected",
                "reason": "malformed_envelope",
                "channel": "attacker_chosen",
            })
        )


# ------------------------------------------------------ 端到端：N7 對 N8

def test_the_field_separates_two_attacks_that_share_a_reason():
    """這是整個欄位存在的理由，用真實的驗證路徑走一次。

    兩則都是未簽章的原始字串，只是送到不同頻道。沒有 channel 的話，
    兩筆遙測逐字相同。
    """
    secret = b"runtime_telemetry_test_secret_32_bytes_minimum"
    observed: list[dict] = []
    telemetry = SimpleNamespace(emit_hmac_result=lambda **item: observed.append(item))

    for channel in (monitor_node.CH_HEALTH, monitor_node.CH_MISSION):
        assert monitor_node.verify_alert(
            "not even json",           # N7 與 N8 都送這種東西
            secret,
            expected_channel=channel,
            telemetry=telemetry,
        ) is None

    assert [o["reason"] for o in observed] == ["malformed_envelope"] * 2
    # 理由相同——分開它們的只有 channel
    assert [o["channel"] for o in observed] == ["system/health", "mission/cmd"]


def test_emitted_record_survives_a_round_trip_through_the_collector():
    """發送端產生的東西，收集端必須收得下——這一對過去分岔過。"""
    secret = b"runtime_telemetry_test_secret_32_bytes_minimum"
    observed: list[dict] = []
    telemetry = SimpleNamespace(emit_hmac_result=lambda **item: observed.append(item))
    monitor_node.verify_alert(
        "not even json", secret,
        expected_channel=monitor_node.CH_HEALTH, telemetry=telemetry,
    )
    item = observed[0]
    out = collector.validate_telemetry_event(
        _event({
            "outcome": "accepted" if item["accepted"] else "rejected",
            "reason": item["reason"],
            "channel": item["channel"],
        })
    )
    assert out["details"]["channel"] == monitor_node.CH_HEALTH
