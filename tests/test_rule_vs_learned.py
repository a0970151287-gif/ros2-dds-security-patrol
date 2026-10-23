"""`工具腳本/compare_rule_vs_learned.py` 的回歸測試。

整份對照表建立在兩件事上：規則式對照組是**公平**的（不是稻草人），
以及信賴區間是在**場次層級**重抽的。任何一個壞掉，整張表就不能引用。
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pandas as pd
import pytest

_TOOL = (Path(__file__).resolve().parents[1]
         / "工具腳本" / "compare_rule_vs_learned.py")


def _load():
    spec = importlib.util.spec_from_file_location("compare_rule_vs_learned", _TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules["compare_rule_vs_learned"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool():
    return _load()


def _frame(**columns):
    length = len(next(iter(columns.values())))
    base = {name: [0.0] * length for _, name in
            [(0, c) for c in ("hmac_failure_rate", "oversized_message_ratio",
                              "alert_reflection_ratio", "nonce_reuse_ratio",
                              "parameter_call_rate", "sros_auth_fail_rate",
                              "sros_permission_deny_rate")]}
    base.update(columns)
    return pd.DataFrame(base)


def test_no_indicator_means_normal(tool):
    predicted, fired = tool.rule_predict(_frame(hmac_failure_rate=[0.0, 0.0]))
    assert list(predicted) == ["normal", "normal"]
    assert sum(fired.values()) == 0


def test_each_exclusive_channel_maps_to_its_class(tool):
    for column, label in (("hmac_failure_rate", "sensor_spoof"),
                          ("oversized_message_ratio", "message_dos"),
                          ("alert_reflection_ratio", "replay_dos"),
                          ("nonce_reuse_ratio", "replay"),
                          ("parameter_call_rate", "parameter_tamper")):
        predicted, _ = tool.rule_predict(_frame(**{column: [0.5]}))
        assert list(predicted) == [label], column


def test_priority_order_is_stable_when_several_fire(tool):
    # 多條同時命中時必須有確定的結果，否則同一份資料會給出不同的表。
    predicted, fired = tool.rule_predict(_frame(
        hmac_failure_rate=[1.0], parameter_call_rate=[1.0]))
    assert list(predicted) == ["sensor_spoof"]
    # 已經被判定的列不可以再被後面的規則計入命中，否則命中數會超過列數。
    assert fired["parameter_call_rate"] == 0


def test_fired_counts_never_exceed_the_number_of_rows(tool):
    frame = _frame(hmac_failure_rate=[1.0, 1.0, 0.0],
                   oversized_message_ratio=[1.0, 0.0, 1.0],
                   parameter_call_rate=[1.0, 1.0, 1.0])
    _, fired = tool.rule_predict(frame)
    assert sum(fired.values()) <= len(frame)


def test_unavailable_sources_are_kept_as_rules_that_never_fire(tool):
    # 保留這兩條是刻意的誠實：規則寫得出來，證據拿不到。
    columns = [column for column, _ in tool.RULES]
    assert "sros_auth_fail_rate" in columns
    assert "sros_permission_deny_rate" in columns


def test_bootstrap_resamples_sessions_not_rows(tool):
    # 建一份資料：同一場內全對或全錯。若重抽的是列，區間會很窄；
    # 若重抽的是場次，區間必然橫跨 0 到 1 附近。
    truth = ["normal"] * 20 + ["message_dos"] * 20
    predicted = ["normal"] * 20 + ["normal"] * 20
    groups = ["s1"] * 20 + ["s2"] * 20
    result = tool._bootstrap(truth, predicted, groups, iterations=200, seed=1)
    recall = result["binary_recall"]
    # 只有兩場，所以重抽必然出現「兩場都是 s1」或「都是 s2」之類的極端組合。
    assert recall["ci95_low"] == pytest.approx(0.0, abs=1e-9)
    assert recall["bootstrap_samples"] > 0


def test_bootstrap_skips_draws_with_a_single_class(tool):
    # 全部同一類的重抽沒有定義指標。跳過而不是補 0——補 0 是憑空的悲觀。
    truth = ["normal"] * 10
    predicted = ["normal"] * 10
    groups = ["s1"] * 5 + ["s2"] * 5
    result = tool._bootstrap(truth, predicted, groups, iterations=50, seed=2)
    assert result == {}


def test_existing_output_is_never_overwritten(tool, tmp_path, monkeypatch):
    existing = tmp_path / "report.json"
    existing.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "compare_rule_vs_learned.py",
        "--features", str(tmp_path / "f.csv"),
        "--output", str(existing),
    ])
    assert tool.main() == 1
