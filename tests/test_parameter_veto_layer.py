"""參數拒絕發生在哪一層，必須看得出來。

`whitelist` 宣告時帶 `read_only=True`，rcl 在 `_apply_descriptors` 就拒絕，
application 層的 `on_set_parameters` 從來沒被呼叫過。所以攻擊在 1,100 場資料裡
被拒絕了 18 次，遙測卻一筆都沒有——`parameter_unchanged` 因此永遠拿不到證據。

修法是**修遙測**（讓服務層記錄回應裡的拒絕），不是放寬判定。這些測試守的是：
拒絕真的被記下來、兩層分得開，而且舊資料仍然合法。
"""

from __future__ import annotations

import pytest

from firewall_lab.live_telemetry_collector import (
    TELEMETRY_EVENT_SCHEMA_VERSION,
    PARAMETER_VETO_LAYERS,
    validate_telemetry_event,
)
from firewall_lab.schema import SchemaError


def _event(details):
    return {
        "schema_version": TELEMETRY_EVENT_SCHEMA_VERSION,
        "session_id": "20260827T120000000000Z_probe_0a1b2c3d",
        "sequence": 0,
        "ts_unix_ns": 1_787_800_000_000_000_000,
        "monotonic_ns": 1_000_000_000,
        "source": "dds_security_monitor",
        "event_type": "parameter_veto",
        "details": details,
    }


# ── 收集器 schema ───────────────────────────────────────────────────────────

def test_the_layer_is_recorded_when_present():
    for layer in sorted(PARAMETER_VETO_LAYERS):
        event = validate_telemetry_event(_event({"count": 1, "layer": layer}))
        assert event["details"]["layer"] == layer


def test_events_without_a_layer_stay_valid():
    # 1,100 場正式資料裡的 veto 事件沒有這個欄位，而那些檔案是不可變的證據。
    # 讓它們失效等於讓既有資料集無法重新處理。
    event = validate_telemetry_event(_event({"count": 2}))
    assert "layer" not in event["details"]
    assert event["details"]["count"] == 2


def test_an_unrecognised_layer_is_refused():
    with pytest.raises(SchemaError, match="details.layer"):
        validate_telemetry_event(_event({"count": 1, "layer": "somewhere_else"}))


def test_unrelated_extra_keys_are_still_refused():
    # 放寬只針對這一個具名欄位，不是把 schema 變成寬鬆比對。
    with pytest.raises(SchemaError, match="unexpected detail keys"):
        validate_telemetry_event(_event({"count": 1, "smuggled": "value"}))


def test_a_required_key_is_still_required():
    with pytest.raises(SchemaError, match="unexpected detail keys"):
        validate_telemetry_event(_event({"layer": "application"}))


# ── 服務層的拒絕記錄 ────────────────────────────────────────────────────────

class _Result:
    def __init__(self, successful):
        self.successful = successful


class _Response:
    def __init__(self, results):
        self.results = results


class _Telemetry:
    def __init__(self):
        self.vetoes = []

    def emit_parameter_veto(self, *, count=1, layer="application"):
        self.vetoes.append((count, layer))
        return True


class _Node:
    def __init__(self):
        self._telemetry = _Telemetry()


def _emit_refusals():
    """從 runtime_telemetry 取得記錄器。

    這個函式刻意住在 runtime_telemetry 而不是 monitor_node：它是純邏輯，
    放在需要 rclpy 的模組裡會讓它在測試環境永遠被 skip——而被 skip 的測試
    等於沒有測試。
    """
    import importlib.util
    from pathlib import Path

    path = (Path(__file__).resolve().parents[1] / "src" / "dds_security_monitor"
            / "dds_security_monitor" / "runtime_telemetry.py")
    spec = importlib.util.spec_from_file_location("runtime_telemetry_for_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.record_parameter_refusals


def test_a_read_only_rejection_is_recorded_as_its_own_layer():
    emit_refusals = _emit_refusals()
    node = _Node()
    refused = emit_refusals(node, _Response([_Result(False), _Result(True)]))
    assert refused == 1
    assert node._telemetry.vetoes == [(1, "rcl_read_only")]


def test_a_successful_change_records_nothing():
    # 只記拒絕。把成功也記成 veto 會讓「參數沒被改」這個性質失去意義。
    emit_refusals = _emit_refusals()
    node = _Node()
    assert emit_refusals(node, _Response([_Result(True)])) == 0
    assert node._telemetry.vetoes == []


def test_responses_without_results_contribute_nothing():
    # get_parameters 之類沒有東西可以拒絕，不該產生一筆 count=0 的空事件。
    emit_refusals = _emit_refusals()
    node = _Node()

    class _Bare:
        pass

    assert emit_refusals(node, _Bare()) == 0
    assert node._telemetry.vetoes == []


def test_telemetry_failure_never_propagates():
    # 證據是盡力而為，絕不可以拖慢或弄壞節點自己的回應。
    emit_refusals = _emit_refusals()

    class _Broken:
        def emit_parameter_veto(self, **_):
            raise RuntimeError("socket is gone")

    node = _Node()
    node._telemetry = _Broken()
    assert emit_refusals(node, _Response([_Result(False)])) == 1
