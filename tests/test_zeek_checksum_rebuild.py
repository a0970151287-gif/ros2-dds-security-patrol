"""Zeek 校驗和重建的回歸測試。

兩個性質必須守住：

1. **原始證據不能被覆寫。** `zeek/conn.log` 的大小與 SHA-256 記在 manifest 裡，
   重建一旦寫回原處，整個資料集的完整性檢查就會失敗。
2. **一張特徵表只能有一種 conn.log 來源。** 一半場次用重建後的位元組、一半用
   校驗和丟包後的殘骸，模型學到的會是「哪些場次被重建過」——與 2026-08-30
   觀測者覆蓋不均等是同一種假象。
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

from firewall_lab.features import (
    SchemaError,
    build_features,
    resolve_conn_log,
)

from tests.test_live_multimodal import _write_live_session


ROOT = Path(__file__).resolve().parents[1]
REBUILD_SCRIPT = ROOT / "工具腳本" / "rebuild_zeek_checksum.py"


def _load_rebuilder():
    spec = importlib.util.spec_from_file_location(
        "rebuild_zeek_checksum", REBUILD_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _conn_log(orig_bytes: str = "12840") -> str:
    return (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\torig_bytes\n"
        f"1800000001.000000\t127.0.0.1\t239.255.0.1\t14900\tudp\t{orig_bytes}\n"
    )


def _fake_zeek(tmp_path: Path, *, warn: bool = False, rc: int = 0,
               conn: str | None = None) -> Path:
    """一個假的 zeek：把 conn.log 寫進 cwd，可選擇噴校驗和警告。"""
    body = ["#!/bin/sh"]
    if conn is None:
        conn = _conn_log()
    if conn:
        body.append("cat > conn.log <<'ZEEKEOF'")
        body.append(conn.rstrip("\n"))
        body.append("ZEEKEOF")
    if warn:
        body.append(
            'echo "warning: Your trace file likely has '
            'invalid UDP checksums" >&2'
        )
    body.append(f"exit {rc}")
    script = tmp_path / "fake_zeek.sh"
    script.write_text("\n".join(body) + "\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def _rebuildable_session(tmp_path: Path) -> Path:
    session, _ = _write_live_session(tmp_path)
    (session / "traffic.pcapng").write_bytes(b"\xd4\xc3\xb2\xa1")
    (session / "zeek_process.json").write_text(
        json.dumps(
            {
                "argv": [
                    "/usr/local/bin/zeek",
                    "-r",
                    str(session / "traffic.pcapng"),
                    "-e",
                    "redef udp_inactivity_timeout = 5sec;",
                ]
            }
        ),
        encoding="utf-8",
    )
    return session


# --------------------------------------------------------------------------
# resolve_conn_log
# --------------------------------------------------------------------------


def test_rebuilt_conn_log_is_preferred_over_the_original(tmp_path):
    session, _ = _write_live_session(tmp_path)
    (session / "zeek_checksum_fixed").mkdir()
    (session / "zeek_checksum_fixed" / "conn.log").write_text(
        _conn_log(), encoding="utf-8"
    )

    path, source = resolve_conn_log(session)

    assert source == "checksum_rebuilt"
    assert path == session / "zeek_checksum_fixed" / "conn.log"


def test_original_conn_log_is_used_when_there_is_no_rebuild(tmp_path):
    session, _ = _write_live_session(tmp_path)

    path, source = resolve_conn_log(session)

    assert source == "original"
    assert path == session / "zeek" / "conn.log"


def test_missing_conn_log_is_reported_rather_than_guessed(tmp_path):
    session, _ = _write_live_session(tmp_path)
    (session / "zeek" / "conn.log").unlink()

    path, source = resolve_conn_log(session)

    assert path is None
    assert source == "missing"


# --------------------------------------------------------------------------
# 混用即拒絕
# --------------------------------------------------------------------------


def test_feature_build_refuses_a_mixture_of_conn_log_sources(tmp_path):
    """一半重建一半沒有，等於把「被重建過」偷渡成一個特徵。"""
    rebuilt, _ = _write_live_session(tmp_path)
    _write_live_session(tmp_path)  # 第二場故意不重建
    (rebuilt / "zeek_checksum_fixed").mkdir()
    (rebuilt / "zeek_checksum_fixed" / "conn.log").write_text(
        _conn_log(), encoding="utf-8"
    )

    with pytest.raises(SchemaError, match="來源不一致"):
        build_features(dataset_root=tmp_path, output_dir=tmp_path / "features")


def test_feature_build_accepts_a_dataset_rebuilt_in_full(tmp_path):
    for _ in range(2):
        session, _ = _write_live_session(tmp_path)
        (session / "zeek_checksum_fixed").mkdir()
        (session / "zeek_checksum_fixed" / "conn.log").write_text(
            _conn_log(), encoding="utf-8"
        )

    build_features(dataset_root=tmp_path, output_dir=tmp_path / "features")

    summary = json.loads(
        (tmp_path / "features" / "feature_build.json").read_text(
            encoding="utf-8"
        )
    )
    assert summary["zeek_conn_sources"] == {"checksum_rebuilt": 2}


def test_feature_build_records_that_the_original_source_was_used(tmp_path):
    """來源要寫進 build manifest，否則兩張表事後分不出誰是誰。"""
    _write_live_session(tmp_path)

    build_features(dataset_root=tmp_path, output_dir=tmp_path / "features")

    summary = json.loads(
        (tmp_path / "features" / "feature_build.json").read_text(
            encoding="utf-8"
        )
    )
    assert summary["zeek_conn_sources"] == {"original": 1}


# --------------------------------------------------------------------------
# 重建腳本本身
# --------------------------------------------------------------------------


def test_rebuild_never_touches_the_original_conn_log(tmp_path):
    module = _load_rebuilder()
    session = _rebuildable_session(tmp_path)
    original = session / "zeek" / "conn.log"
    before = original.read_bytes()

    result = module.rebuild_one(
        session, str(_fake_zeek(tmp_path)), timeout=30
    )

    assert result["status"] == "ok"
    assert original.read_bytes() == before
    assert (session / "zeek_checksum_fixed" / "conn.log").is_file()


def test_rebuild_passes_the_checksum_flag_and_keeps_the_original_timeout(
    tmp_path,
):
    module = _load_rebuilder()
    session = _rebuildable_session(tmp_path)

    module.rebuild_one(session, str(_fake_zeek(tmp_path)), timeout=30)

    record = json.loads(
        (session / "zeek_checksum_fixed" / "rebuild.json").read_text(
            encoding="utf-8"
        )
    )
    assert "-C" in record["argv"]
    # 重建必須沿用當初那一場的 inactivity timeout，否則流的切法會不一樣，
    # 新舊 conn 列數就不能拿來比較了。
    assert "redef udp_inactivity_timeout = 5sec;" in record["argv"]


def test_rebuild_refuses_a_run_where_the_flag_did_not_take_effect(tmp_path):
    """`-C` 生效時警告會消失；警告還在就代表旗標沒吃到。"""
    module = _load_rebuilder()
    session = _rebuildable_session(tmp_path)

    result = module.rebuild_one(
        session, str(_fake_zeek(tmp_path, warn=True)), timeout=30
    )

    assert result["status"] == "flag_ineffective"
    assert not (session / "zeek_checksum_fixed").exists()


def test_rebuild_refuses_a_result_that_still_has_no_bytes(tmp_path):
    """位元組欄位仍是 `-` 代表什麼都沒修好，不可以當成成功收下。"""
    module = _load_rebuilder()
    session = _rebuildable_session(tmp_path)

    result = module.rebuild_one(
        session,
        str(_fake_zeek(tmp_path, conn=_conn_log(orig_bytes="-"))),
        timeout=30,
    )

    assert result["status"] == "still_no_bytes"
    assert not (session / "zeek_checksum_fixed").exists()


def test_rebuild_refuses_an_empty_conn_log(tmp_path):
    module = _load_rebuilder()
    session = _rebuildable_session(tmp_path)

    result = module.rebuild_one(
        session,
        str(_fake_zeek(tmp_path, conn="#fields\tts\torig_bytes\n")),
        timeout=30,
    )

    assert result["status"] == "empty_conn_log"
    assert not (session / "zeek_checksum_fixed").exists()


def test_rebuild_reports_a_nonzero_exit_instead_of_writing_output(tmp_path):
    module = _load_rebuilder()
    session = _rebuildable_session(tmp_path)

    result = module.rebuild_one(
        session, str(_fake_zeek(tmp_path, rc=1)), timeout=30
    )

    assert result["status"] == "zeek_failed"
    assert result["return_code"] == 1
    assert not (session / "zeek_checksum_fixed").exists()


def test_rebuild_skips_a_session_that_already_used_the_flag(tmp_path):
    """已經加過 `-C` 的場次沒有東西要修，重跑只會浪費時間。"""
    module = _load_rebuilder()
    session = _rebuildable_session(tmp_path)
    record = json.loads(
        (session / "zeek_process.json").read_text(encoding="utf-8")
    )
    record["argv"].insert(1, "-C")
    (session / "zeek_process.json").write_text(
        json.dumps(record), encoding="utf-8"
    )

    result = module.rebuild_one(
        session, str(_fake_zeek(tmp_path)), timeout=30
    )

    assert result["status"] == "already_had_flag"


def test_rebuild_reports_a_session_with_no_capture(tmp_path):
    module = _load_rebuilder()
    session = _rebuildable_session(tmp_path)
    os.unlink(session / "traffic.pcapng")

    result = module.rebuild_one(
        session, str(_fake_zeek(tmp_path)), timeout=30
    )

    assert result["status"] == "no_pcap"
