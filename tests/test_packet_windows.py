"""逐封包分窗的回歸測試。

要守住的核心性質只有一個，但它是整個修正的理由：**視窗歸屬要用封包自己的
時間，不是流的起點。** Zeek 的 conn 紀錄一筆代表整條流、時間戳是起點，所以
一條 50 秒的 DDS 流只會落進一個 8 秒視窗——量到的是「這個視窗裡開始了幾條
流」，不是「這個視窗裡有多少流量」。

舊特徵表每場有 7 個視窗，那個時間解析度是校驗和 bug 的副產物：被丟棄的封包
把一條長流碎成幾千筆短紀錄，剛好散佈在整場上。修好校驗和之後真實流數只剩
462 筆而且幾乎同時開始，每場只剩約 3 個視窗——**修好資料反而暴露了分窗方式
本身是錯的。**
"""
from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path

import pytest

from firewall_lab.features import (
    PACKET_WINDOW_DIR,
    SchemaError,
    build_features,
    build_network_rows,
    build_network_rows_from_packets,
    load_label_intervals,
    load_manifest,
    load_packet_records,
)

from tests.test_live_multimodal import _write_live_session


ROOT = Path(__file__).resolve().parents[1]
EXTRACT_SCRIPT = ROOT / "工具腳本" / "extract_packet_windows.py"

HEADER = "frame.time_epoch\tip.src\tip.dst\tudp.srcport\tudp.dstport\tframe.len"
BASE = 1_800_000_000.0
# domain 30 -> 7400 + 250*30 = 14900；14913 落在 userdata 範圍內。
USERDATA_PORT = 14913


def _write_packets(session: Path, rows: list[tuple]) -> None:
    out = session / PACKET_WINDOW_DIR
    out.mkdir(exist_ok=True)
    with gzip.open(out / "packets.tsv.gz", "wt", encoding="utf-8",
                   newline="\n") as handle:
        handle.write(HEADER + "\n")
        for ts, src, dst, sport, dport, length in rows:
            handle.write(
                f"{ts:.6f}\t{src}\t{dst}\t{sport}\t{dport}\t{length}\n"
            )


def _long_flow(seconds: int, *, length: int = 100) -> list[tuple]:
    """一條每秒一個封包、持續 `seconds` 秒的單向流。"""
    return [
        (BASE + offset, "10.0.0.1", "10.0.0.2", 40000, USERDATA_PORT, length)
        for offset in range(seconds)
    ]


def _rows_for(session: Path, packets: list[tuple]) -> list[dict]:
    _write_packets(session, packets)
    return build_network_rows_from_packets(
        session,
        load_manifest(session),
        load_label_intervals(session),
        window_sec=8.0,
    )


# --------------------------------------------------------------------------
# 分窗語意
# --------------------------------------------------------------------------


def test_a_long_flow_appears_in_every_window_it_spans(tmp_path):
    """24 秒的流在 8 秒視窗下必須產生 3 個視窗，不是 1 個。"""
    session, _ = _write_live_session(tmp_path)

    rows = _rows_for(session, _long_flow(24))

    assert [int(row["window"]) for row in rows] == [0, 1, 2]


def test_conn_windowing_collapses_the_same_flow_into_one_window(tmp_path):
    """對照組：同一條流走 conn.log 只會落進一個視窗——這就是缺陷本身。"""
    session, _ = _write_live_session(tmp_path)
    (session / "zeek" / "conn.log").write_text(
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto"
        "\tduration\torig_bytes\torig_pkts\n"
        f"{BASE:.6f}\t10.0.0.1\t10.0.0.2\t{USERDATA_PORT}\tudp"
        "\t24.0\t2400\t24\n",
        encoding="utf-8",
    )

    rows = build_network_rows(
        session,
        load_manifest(session),
        load_label_intervals(session),
        window_sec=8.0,
    )

    assert [int(row["window"]) for row in rows] == [0]


def test_bytes_land_in_the_window_the_packets_were_sent_in(tmp_path):
    """流量歸屬要跟著封包走。前 8 秒大封包、後 8 秒小封包必須分得開。"""
    session, _ = _write_live_session(tmp_path)
    packets = (
        [(BASE + i, "10.0.0.1", "10.0.0.2", 40000, USERDATA_PORT, 1000)
         for i in range(8)]
        + [(BASE + 8 + i, "10.0.0.1", "10.0.0.2", 40000, USERDATA_PORT, 10)
           for i in range(8)]
    )

    rows = _rows_for(session, packets)

    by_window = {int(row["window"]): row for row in rows}
    assert float(by_window[0]["orig_bytes_rate"]) == 8000 / 8.0
    assert float(by_window[1]["orig_bytes_rate"]) == 80 / 8.0
    assert float(by_window[0]["mean_bytes_per_packet"]) == 1000
    assert float(by_window[1]["mean_bytes_per_packet"]) == 10


def test_amplification_uses_traffic_returned_to_the_source(tmp_path):
    """放大比要看回送給該來源的量，這是反射攻擊唯一的痕跡。"""
    session, _ = _write_live_session(tmp_path)
    packets = [
        (BASE + 0.0, "10.0.0.1", "10.0.0.2", 40000, USERDATA_PORT, 100),
        (BASE + 0.1, "10.0.0.2", "10.0.0.1", USERDATA_PORT, 40000, 900),
    ]

    rows = _rows_for(session, packets)

    sender = next(r for r in rows if r["source"] == "10.0.0.1")
    assert float(sender["amplification_ratio"]) == 9.0


def test_conn_count_is_active_five_tuples_not_flow_starts(tmp_path):
    """兩條並行的流在每個視窗都算兩個活躍單位。"""
    session, _ = _write_live_session(tmp_path)
    packets = _long_flow(16) + [
        (BASE + i, "10.0.0.1", "10.0.0.3", 40001, USERDATA_PORT, 50)
        for i in range(16)
    ]

    rows = _rows_for(session, packets)

    counts = {int(r["window"]): int(r["conn_count"]) for r in rows}
    assert counts == {0: 2, 1: 2}


def test_burstiness_is_computed_from_packet_times_not_flow_starts(tmp_path):
    """均勻與爆發的同一條流必須算出不同的形狀。"""
    session, _ = _write_live_session(tmp_path)
    even = [(BASE + i * 0.5, "10.0.0.1", "10.0.0.2", 40000, USERDATA_PORT, 10)
            for i in range(16)]
    bursty = [(BASE + (0.01 * i if i < 15 else 7.0), "10.0.0.1", "10.0.0.2",
               40000, USERDATA_PORT, 10) for i in range(16)]

    even_rows = _rows_for(session, even)
    bursty_rows = _rows_for(session, bursty)

    assert float(even_rows[0]["interarrival_cv"]) != float(
        bursty_rows[0]["interarrival_cv"]
    )


def test_label_still_follows_the_window_midpoint(tmp_path):
    """攻擊區間是 8–16 秒，所以視窗 1 是攻擊、視窗 0 與 2 不是。"""
    session, _ = _write_live_session(tmp_path)

    rows = _rows_for(session, _long_flow(24))

    labels = {int(r["window"]): r["label"] for r in rows}
    assert labels[0] == "normal"
    assert labels[1] == "command_injection"
    assert labels[2] == "normal"


# --------------------------------------------------------------------------
# fail-closed
# --------------------------------------------------------------------------


def test_missing_packet_artifact_is_refused_rather_than_silently_empty(
    tmp_path,
):
    """靜靜回傳空清單會讓這場從表裡消失，看起來像「這場沒有流量」。"""
    session, _ = _write_live_session(tmp_path)
    (session / "traffic.pcapng").write_bytes(b"\xd4\xc3\xb2\xa1")

    with pytest.raises(SchemaError, match="packets.tsv.gz"):
        build_features(
            dataset_root=tmp_path,
            output_dir=tmp_path / "features",
            network_source="packet",
        )


def test_an_unknown_network_source_is_refused(tmp_path):
    _write_live_session(tmp_path)

    with pytest.raises(SchemaError, match="network_source"):
        build_features(
            dataset_root=tmp_path,
            output_dir=tmp_path / "features",
            network_source="pcap",
        )


def test_a_packet_file_with_the_wrong_header_is_refused(tmp_path):
    session, _ = _write_live_session(tmp_path)
    out = session / PACKET_WINDOW_DIR
    out.mkdir()
    with gzip.open(out / "packets.tsv.gz", "wt", encoding="utf-8") as handle:
        handle.write("ts\tsrc\tdst\n1800000000.0\t10.0.0.1\t10.0.0.2\n")

    with pytest.raises(SchemaError, match="逐封包格式"):
        load_packet_records(session)


def test_the_build_manifest_records_which_windowing_was_used(tmp_path):
    """兩張表欄位一樣，來源不記下來事後就分不出誰是誰。"""
    session, _ = _write_live_session(tmp_path)
    _write_packets(session, _long_flow(24))

    build_features(
        dataset_root=tmp_path,
        output_dir=tmp_path / "features",
        network_source="packet",
    )

    summary = json.loads(
        (tmp_path / "features" / "feature_build.json").read_text(
            encoding="utf-8"
        )
    )
    assert summary["network_source"] == "packet"


def test_conn_remains_the_default_so_shipping_behaviour_is_unchanged(tmp_path):
    _write_live_session(tmp_path)

    build_features(dataset_root=tmp_path, output_dir=tmp_path / "features")

    summary = json.loads(
        (tmp_path / "features" / "feature_build.json").read_text(
            encoding="utf-8"
        )
    )
    assert summary["network_source"] == "conn"


# --------------------------------------------------------------------------
# 抽取器
# --------------------------------------------------------------------------


def test_extractor_asks_tshark_for_the_fields_the_windowing_needs():
    """欄位少一個，下游就得改用猜的。把清單釘住。"""
    spec = importlib.util.spec_from_file_location(
        "extract_packet_windows", EXTRACT_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    assert module.FIELDS == (
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "frame.len",
    )


def test_amplification_works_when_ports_are_not_mirrored(tmp_path):
    """真實 RTPS 的回應來自對方的臨時埠，不是鏡像埠。

    實測一場  的 462 個五元組裡，存在嚴格反轉配對的是 **0**
    個。用五元組反轉去配對回流，在這個協定上恆為零——
    在修正前於 conn 版與封包版都是 0.00% 非零，量到的是配對方式不成立，
    不是沒有回流。
    """
    session, _ = _write_live_session(tmp_path)
    packets = [
        # A:49402 -> B:14910（B 的監聽埠）
        (BASE + 0.0, "10.0.0.1", "10.0.0.2", 49402, 14910, 100),
        # B 的回應來自它自己的臨時埠，送到 A 的監聽埠。五元組完全不對稱。
        (BASE + 0.1, "10.0.0.2", "10.0.0.1", 51777, 14911, 900),
    ]

    rows = _rows_for(session, packets)

    sender = next(r for r in rows if r["source"] == "10.0.0.1")
    assert float(sender["amplification_ratio"]) == 9.0
