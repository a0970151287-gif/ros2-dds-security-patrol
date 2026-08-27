"""`工具腳本/diagnose_gate_veto.py` 的回歸測試。

整份否決分析建立在一個不變量上：OOD 頭認對的每一列，恰好落進
via_binary／via_normality／vetoed 三者之一。分解錯了，「59% 被否決」
這個數字就沒有意義，而它正是要拿去寫報告的那一個。
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

_TOOL = (Path(__file__).resolve().parents[1]
         / "工具腳本" / "diagnose_gate_veto.py")


def _load():
    spec = importlib.util.spec_from_file_location("diagnose_gate_veto", _TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules["diagnose_gate_veto"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool():
    return _load()


def test_paths_are_mutually_exclusive_and_exhaustive(tool):
    rng = np.random.default_rng(20260827)
    for _ in range(50):
        size = int(rng.integers(1, 200))
        binary = rng.random(size) < 0.4
        abnormal = rng.random(size) < 0.3
        rejected = rng.random(size) < 0.6
        paths = tool.decompose_paths(binary, abnormal, rejected)
        assert (paths["via_binary"] + paths["via_normality"] + paths["vetoed"]
                == paths["ood_rejected"])
        assert paths["via_binary"] + paths["via_normality"] == paths["unknown"]


def test_gate_rule_matches_the_model(tool):
    # 與 hierarchical_model.parallel_gate_membership 的語意必須一致：
    # OOD 頭單獨不能把一列判成未知。
    paths = tool.decompose_paths([False], [False], [True])
    assert paths["ood_rejected"] == 1
    assert paths["unknown"] == 0
    assert paths["vetoed"] == 1


def test_binary_hit_is_not_counted_as_normality_recovery(tool):
    # 兩個訊號都成立時只能算進 via_binary，否則救回來的功勞會被重複計算。
    paths = tool.decompose_paths([True], [True], [True])
    assert paths["via_binary"] == 1
    assert paths["via_normality"] == 0
    assert paths["vetoed"] == 0


def test_rows_the_ood_head_missed_are_never_counted(tool):
    paths = tool.decompose_paths([True, True], [True, True], [False, False])
    assert paths == {
        "ood_rejected": 0, "via_binary": 0, "via_normality": 0,
        "vetoed": 0, "unknown": 0,
    }


def test_mismatched_mask_lengths_are_rejected(tool):
    with pytest.raises(ValueError, match="equal-length"):
        tool.decompose_paths([True, False], [True], [True, True])


def test_empty_denominator_is_refused_not_reported_as_zero(tool):
    # 這個專案的核心紀律：「沒有樣本」不可以印成「量到零」。
    with pytest.raises(ValueError, match="empty denominator"):
        tool._rate(0, 0)


def test_existing_output_is_never_overwritten(tool, tmp_path):
    existing = tmp_path / "report.json"
    existing.write_text("{}", encoding="utf-8")
    with pytest.raises(FileExistsError):
        tool.main([
            "--features", str(tmp_path / "f.csv"),
            "--metrics", str(tmp_path / "m.json"),
            "--output", str(existing),
        ])


def test_sweep_values_outside_the_open_unit_interval_are_rejected(tool, tmp_path):
    for bad in ("0", "1", "1.5"):
        with pytest.raises(ValueError, match="sweep value"):
            tool.main([
                "--features", str(tmp_path / "f.csv"),
                "--metrics", str(tmp_path / "m.json"),
                "--output", str(tmp_path / f"out_{bad}.json"),
                "--normality-sweep", bad,
            ])
