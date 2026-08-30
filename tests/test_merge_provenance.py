"""合併特徵表時的建表方式一致性檢查。

欄位比對擋不到這件事：conn 分窗與封包分窗、校驗和損壞與 `-C` 重建，產生的
**欄位完全一樣**，只有數值意義不同。兩張表併在一起，模型可以學到「這一列
出自哪一次建表」——與 2026-08-30 觀測者覆蓋不均等是同一種假象，而且更難發現，
因為沒有任何欄位長得可疑。
"""
from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MERGE_SCRIPT = ROOT / "工具腳本" / "merge_rerun_features.py"

COLUMNS = ["session_id", "scenario_id", "conn_count", "label"]


def _load_merger():
    spec = importlib.util.spec_from_file_location(
        "merge_rerun_features", MERGE_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _table(
    directory: Path,
    rows: list[dict[str, str]],
    provenance: dict | None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    csv_path = directory / "fusion_features.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    if provenance is not None:
        (directory / "feature_build.json").write_text(
            json.dumps(provenance), encoding="utf-8"
        )
    return csv_path


def _old_rows() -> list[dict[str, str]]:
    return [
        {"session_id": "s1", "scenario_id": "normal_patrol",
         "conn_count": "5", "label": "normal"},
        {"session_id": "s2", "scenario_id": "parameter_tamper",
         "conn_count": "9", "label": "parameter_tamper"},
    ]


def _new_rows() -> list[dict[str, str]]:
    return [
        {"session_id": "s9", "scenario_id": "parameter_tamper",
         "conn_count": "3", "label": "parameter_tamper"},
    ]


CONN_BUILD = {
    "network_source": "conn",
    "zeek_conn_sources": {"checksum_rebuilt": 2},
    "window_sec": 8.0,
}
PACKET_BUILD = {
    "network_source": "packet",
    "zeek_conn_sources": {"checksum_rebuilt": 1},
    "window_sec": 8.0,
}


def _run(module, old: Path, new: Path, out: Path, extra=()) -> int:
    import sys

    argv = ["--old", str(old), "--new", str(new), "--output", str(out), *extra]
    saved = sys.argv
    sys.argv = ["merge_rerun_features.py", *argv]
    try:
        return module.main()
    finally:
        sys.argv = saved


def test_mixing_conn_and_packet_windowing_is_refused(tmp_path, capsys):
    module = _load_merger()
    old = _table(tmp_path / "old", _old_rows(), CONN_BUILD)
    new = _table(tmp_path / "new", _new_rows(), PACKET_BUILD)

    code = _run(module, old, new, tmp_path / "out" / "merged.csv")

    assert code == 1
    assert "network_source" in capsys.readouterr().err
    assert not (tmp_path / "out" / "merged.csv").exists()


def test_mixing_rebuilt_and_corrupt_zeek_output_is_refused(tmp_path, capsys):
    """校驗和損壞與重建的欄位一模一樣，只有數值不同。"""
    module = _load_merger()
    old = _table(tmp_path / "old", _old_rows(),
                 {**CONN_BUILD, "zeek_conn_sources": {"original": 2}})
    new = _table(tmp_path / "new", _new_rows(), CONN_BUILD)

    code = _run(module, old, new, tmp_path / "out" / "merged.csv")

    assert code == 1
    assert "zeek_conn_sources" in capsys.readouterr().err


def test_a_missing_build_manifest_is_not_treated_as_agreement(
    tmp_path, capsys
):
    """「不知道」不等於「一樣」。"""
    module = _load_merger()
    old = _table(tmp_path / "old", _old_rows(), None)
    new = _table(tmp_path / "new", _new_rows(), CONN_BUILD)

    code = _run(module, old, new, tmp_path / "out" / "merged.csv")

    assert code == 1
    assert "feature_build.json" in capsys.readouterr().err


def test_a_missing_key_in_an_older_manifest_is_not_treated_as_agreement(
    tmp_path, capsys
):
    """舊 schema 沒有 network_source 欄位時，不可以默認它是 conn。"""
    module = _load_merger()
    old = _table(tmp_path / "old", _old_rows(),
                 {"zeek_conn_sources": {"checksum_rebuilt": 2},
                  "window_sec": 8.0})
    new = _table(tmp_path / "new", _new_rows(), CONN_BUILD)

    code = _run(module, old, new, tmp_path / "out" / "merged.csv")

    assert code == 1
    assert "network_source" in capsys.readouterr().err


def test_matching_provenance_is_merged(tmp_path):
    module = _load_merger()
    old = _table(tmp_path / "old", _old_rows(), CONN_BUILD)
    new = _table(tmp_path / "new", _new_rows(), CONN_BUILD)
    out = tmp_path / "out" / "merged.csv"

    code = _run(module, old, new, out)

    assert code == 0
    merged = list(csv.DictReader(out.open(encoding="utf-8")))
    # 受影響 scenario 的舊列被剔除，新列接上。
    assert [r["session_id"] for r in merged] == ["s1", "s9"]


def test_the_override_exists_but_must_be_asked_for_explicitly(tmp_path):
    """有逃生門，但不能是預設。"""
    module = _load_merger()
    old = _table(tmp_path / "old", _old_rows(), CONN_BUILD)
    new = _table(tmp_path / "new", _new_rows(), PACKET_BUILD)
    out = tmp_path / "out" / "merged.csv"

    assert _run(module, old, new, out) == 1
    assert _run(module, old, new, out, ["--allow-mixed-provenance"]) == 0
