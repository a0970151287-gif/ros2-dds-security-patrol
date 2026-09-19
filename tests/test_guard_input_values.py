"""`guard_input` 記下守衛**收到**的速度指令。

## 為什麼

`guard_output` 一直記著守衛**輸出**什麼（`linear_x`、`angular_z`），
`guard_input` 卻只記 `accepted_count`。那個不對稱讓證據無法診斷偵測器：

| 偵測器 | 用的量值 | 先前記在證據裡嗎 |
|---|---|---|
| d1 physics | cmd_vel 的線／角速度上限 | **沒有** |
| d6 case (b) | `avg_cmd > 0.05 且 avg_lin < 0.005` | **沒有** |

2026-09-02 因此無法判斷 N34（odom 偽造）為什麼沒有觸發 d6——它需要
`avg_cmd > 0.05`，而錄下來的遙測裡沒有任何 cmd 的量值。
**證據不足以診斷證據本身。**

## 不對稱的必要性

| 端 | 必填？ | 理由 |
|---|---|---|
| 生產端 | **必填** | 選填會讓它悄悄消失（C2C-047 的形狀） |
| 收集端 | **選填** | 既有 1,100 場只有 `accepted_count`，而 `features.py` 會重新驗證那些不可變的檔案 |
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from firewall_lab import live_telemetry_collector as collector

pytest.importorskip("rclpy", reason="需要 ROS 環境")

from dds_security_monitor import runtime_telemetry  # noqa: E402


def _producer():
    seen: list[tuple] = []
    obj = SimpleNamespace(_emit=lambda k, d: (seen.append((k, d)), True)[1])
    return obj, seen


# ------------------------------------------------------------ 生產端

def test_producer_requires_the_values():
    obj, _ = _producer()
    with pytest.raises(TypeError):
        runtime_telemetry.RuntimeTelemetryProducer.emit_guard_input(
            obj, accepted_count=1
        )


def test_producer_records_what_the_guard_received():
    obj, seen = _producer()
    assert runtime_telemetry.RuntimeTelemetryProducer.emit_guard_input(
        obj, 0.18, -0.42, accepted_count=1
    )
    kind, details = seen[0]
    assert kind == "guard_input"
    assert details["linear_x"] == pytest.approx(0.18)
    assert details["angular_z"] == pytest.approx(-0.42)
    assert details["accepted_count"] == 1


@pytest.mark.parametrize(
    "linear_x, angular_z",
    [
        (float("nan"), 0.0),
        (float("inf"), 0.0),
        (0.0, float("-inf")),
        (2_000.0, 0.0),          # 超出界線
        (True, 0.0),             # bool 是 int 的子型別，必須擋掉
    ],
)
def test_producer_rejects_unbounded_or_non_finite(linear_x, angular_z):
    obj, _ = _producer()
    with pytest.raises(ValueError):
        runtime_telemetry.RuntimeTelemetryProducer.emit_guard_input(
            obj, linear_x, angular_z
        )


def test_bounds_match_guard_output():
    """兩端用同一組界線，否則同一個值一邊過一邊不過。"""
    obj, _ = _producer()
    for emit in ("emit_guard_input", "emit_guard_output"):
        fn = getattr(runtime_telemetry.RuntimeTelemetryProducer, emit)
        kwargs = {"blocked": False} if emit == "emit_guard_output" else {}
        with pytest.raises(ValueError):
            fn(obj, 1_000.5, 0.0, **kwargs)
        # 界線內必須通過
        assert fn(obj, 999.0, 0.0, **kwargs)


# ------------------------------------------------------------ 收集端

def _event(details: dict) -> dict:
    return {
        "schema_version": collector.TELEMETRY_EVENT_SCHEMA_VERSION,
        "session_id": "20260902T000000000000Z_test_00000000",
        "sequence": 0,
        "ts_unix_ns": 1_770_000_000_000_000_000,
        "monotonic_ns": 1_000_000,
        "source": "velocity_guard_node",
        "event_type": "guard_input",
        "details": details,
    }


def test_collector_still_accepts_historical_events_without_values():
    """既有 1,100 場只有 accepted_count，而 features.py 會重新驗證它們。"""
    out = collector.validate_telemetry_event(_event({"accepted_count": 1}))
    assert out["details"] == {"accepted_count": 1}


def test_collector_keeps_the_values_when_present():
    out = collector.validate_telemetry_event(
        _event({"accepted_count": 1, "linear_x": 0.2, "angular_z": -0.1})
    )
    assert out["details"]["linear_x"] == pytest.approx(0.2)
    assert out["details"]["angular_z"] == pytest.approx(-0.1)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 5_000.0, True, "0.2"])
def test_collector_rejects_bad_values(bad):
    with pytest.raises(collector.SchemaError):
        collector.validate_telemetry_event(
            _event({"accepted_count": 1, "linear_x": bad, "angular_z": 0.0})
        )


def test_the_recorded_value_can_answer_the_detector_question():
    """整個欄位存在的理由：能不能從證據判斷 d6 case (b) 的前提成立與否。

    d6 case (b) 需要 `avg_cmd > 0.05`。有了這個欄位，答案直接讀得出來；
    沒有它，就只能猜。
    """
    fast = collector.validate_telemetry_event(
        _event({"accepted_count": 1, "linear_x": 0.18, "angular_z": 0.0})
    )
    idle = collector.validate_telemetry_event(
        _event({"accepted_count": 1, "linear_x": 0.0, "angular_z": 0.0})
    )
    assert fast["details"]["linear_x"] > 0.05      # d6 (b) 的前提成立
    assert idle["details"]["linear_x"] <= 0.05     # 不成立——而這是可讀的
