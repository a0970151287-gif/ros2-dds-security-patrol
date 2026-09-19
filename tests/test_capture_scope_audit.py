"""`工具腳本/audit_capture_scope.py` 的回歸測試。

這支工具存在的理由是「一份只擷到多播的空擷取，看起來跟一份正常的擷取一樣忙」。
所以測試的重點不是它會不會跑，是**它會不會咬人**：把已知壞的那一批餵進去
必須判 void，把已知好的餵進去必須判 ok。
"""
from __future__ import annotations

import gzip
import importlib.util
import json
import pathlib
import sys

import pytest

_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "工具腳本"
    / "audit_capture_scope.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("audit_capture_scope", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


audit = _load()


# ── 多播分類器 ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "address, expected",
    [
        ("239.255.0.1", True),    # RTPS SPDP
        ("239.255.0.7", True),    # Gazebo gz-transport
        ("224.0.0.1", True),
        ("239.255.255.255", True),
        ("223.255.255.255", False),
        ("240.0.0.1", False),
        ("127.0.0.1", False),
        ("192.168.0.129", False),
        ("", False),
        ("not-an-ip", False),
        ("fe80::1", False),       # IPv6 一律當單播，保守
    ],
)
def test_multicast_classification(address, expected):
    assert audit.is_multicast_ipv4(address) is expected


def test_sanity_check_passes_on_correct_classifier():
    assert audit.check_multicast_classifier() == []


def test_sanity_check_catches_a_broken_classifier(monkeypatch):
    """自我檢查必須真的會咬人，否則它只是裝飾。"""
    monkeypatch.setattr(audit, "is_multicast_ipv4", lambda _address: False)
    wrong = audit.check_multicast_classifier()
    assert wrong, "分類器全部回 False 時自我檢查竟然通過"
    assert any("239.255.0.1" in item for item in wrong)


# ── 從 manifest 取擷取介面 ─────────────────────────────────────


def test_capture_interface_from_argv_list():
    manifest = {
        "result": {
            "capture_process": {
                "argv": [
                    "/usr/bin/dumpcap", "-q", "-i", "eth1",
                    "-f", "udp portrange 7400-15200", "-w", "traffic.pcapng",
                ]
            }
        }
    }
    assert audit.capture_interface_from_manifest(manifest) == "eth1"


def test_capture_interface_from_argv_string():
    manifest = {
        "result": {"capture_process": {"argv": "/usr/bin/dumpcap -q -i lo -w x"}}
    }
    assert audit.capture_interface_from_manifest(manifest) == "lo"


def test_capture_interface_joined_form():
    manifest = {"result": {"capture_process": {"argv": ["dumpcap", "-ilo"]}}}
    assert audit.capture_interface_from_manifest(manifest) == "lo"


@pytest.mark.parametrize(
    "manifest",
    [
        {},
        {"result": None},
        {"result": {}},
        {"result": {"capture_process": None}},      # rerun300 真的有這一種
        {"result": {"capture_process": {}}},
        {"result": {"capture_process": {"argv": None}}},
        {"result": "not-a-dict"},
        {"result": {"capture_process": {"argv": ["dumpcap", "-i"]}}},  # -i 在結尾
    ],
)
def test_capture_interface_absent_is_none_not_a_crash(manifest):
    """稽核工具自己爆掉，會讓一整批安靜地沒有被檢查。"""
    assert audit.capture_interface_from_manifest(manifest) is None


# ── verdict ──────────────────────────────────────────────────


def test_all_multicast_is_void():
    assert audit.classify(3320, 0, min_unicast_ratio=0.5) == "void_no_unicast"


def test_empty_capture_is_void():
    assert audit.classify(0, 0, min_unicast_ratio=0.5) == "void_no_packets"


def test_mostly_multicast_is_degraded():
    assert audit.classify(1000, 100, min_unicast_ratio=0.5) == "degraded_low_unicast"


def test_loopback_capture_is_ok():
    assert audit.classify(9748, 9748, min_unicast_ratio=0.5) == "ok"
    # dataset_rerun300 實測約 93% 單播
    assert audit.classify(5148, 4814, min_unicast_ratio=0.5) == "ok"


def test_busy_multicast_capture_is_not_rescued_by_packet_count():
    """判準必須是佔比。3,320 個封包很多，但一個單播都沒有。"""
    assert audit.classify(3320, 0, min_unicast_ratio=0.5) == "void_no_unicast"
    assert audit.classify(10, 10, min_unicast_ratio=0.5) == "ok"


# ── 端到端：用合成的 session 目錄 ───────────────────────────────


def _make_session(root: pathlib.Path, name: str, destinations, interface="lo"):
    session = root / name
    (session / "packet_windows").mkdir(parents=True)
    with gzip.open(
        session / "packet_windows" / "packets.tsv.gz", "wt", encoding="utf-8"
    ) as handle:
        handle.write(
            "frame.time_epoch\tip.src\tip.dst\tudp.srcport\tudp.dstport\tframe.len\n"
        )
        for index, destination in enumerate(destinations):
            handle.write(
                "%.3f\t192.168.0.129\t%s\t40000\t14900\t100\n"
                % (1000.0 + index, destination)
            )
    (session / "manifest.json").write_text(
        json.dumps(
            {
                "attack_class": "normal",
                "security_mode": "permissive",
                "ros_domain_id": 30,
                "status": "complete",
                "training_eligible": True,
                "result": {
                    "capture_process": {
                        "argv": ["/usr/bin/dumpcap", "-q", "-i", interface]
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return session


def test_end_to_end_multicast_only_batch_is_void(tmp_path):
    """重現 2026-09-02 那一批：全部多播，介面是 eth1。"""
    session = _make_session(
        tmp_path, "s1", ["239.255.0.7"] * 90 + ["239.255.0.1"] * 10, interface="eth1"
    )
    row = audit.audit_session(session, min_unicast_ratio=0.5)
    assert row["verdict"] == "void_no_unicast"
    assert row["capture_interface"] == "eth1"
    assert row["packets_unicast"] == 0
    assert row["packets_total"] == 100


def test_end_to_end_loopback_batch_is_ok(tmp_path):
    session = _make_session(
        tmp_path, "s1", ["127.0.0.1"] * 95 + ["239.255.0.1"] * 5, interface="lo"
    )
    row = audit.audit_session(session, min_unicast_ratio=0.5)
    assert row["verdict"] == "ok"
    assert row["capture_interface"] == "lo"
    assert row["unicast_ratio"] == pytest.approx(0.95)


def test_completed_session_without_capture_is_void_not_silently_skipped(tmp_path):
    session = tmp_path / "s1"
    session.mkdir()
    (session / "manifest.json").write_text(
        json.dumps(
            {
                "attack_class": "normal",
                "status": "complete",
                "training_eligible": True,
            }
        ),
        encoding="utf-8",
    )
    row = audit.audit_session(session, min_unicast_ratio=0.5)
    assert row["verdict"] == "void_no_capture"


@pytest.mark.parametrize(
    "manifest",
    [
        {"attack_class": "replay", "status": "failed", "training_eligible": False},
        {"attack_class": "replay", "status": "complete", "training_eligible": False},
        {"attack_class": "replay"},
    ],
)
def test_ineligible_session_is_skipped_not_counted_as_void(tmp_path, manifest):
    """rerun300 真的有一場 status=failed、完全沒有擷取檔。

    那是 fail-closed 正確中止的場次，也沒有進特徵表——算成 void 會製造假警報，
    而假警報會讓真警報被忽略。
    """
    session = tmp_path / "s1"
    session.mkdir()
    (session / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    row = audit.audit_session(session, min_unicast_ratio=0.5)
    assert row["verdict"] == "skipped_not_eligible"


def test_a_batch_of_only_ineligible_sessions_does_not_pass_silently(
    tmp_path, monkeypatch
):
    """全部被跳過時不該回報「一切正常」——那等於什麼都沒檢查。"""
    batch = tmp_path / "batch"
    batch.mkdir()
    session = batch / "s1"
    session.mkdir()
    (session / "manifest.json").write_text(
        json.dumps({"attack_class": "replay", "status": "failed"}), encoding="utf-8"
    )
    monkeypatch.setattr(
        sys, "argv", ["audit_capture_scope.py", "--batch", str(batch)]
    )
    assert audit.main() == 2


def test_directory_without_manifest_is_skipped(tmp_path):
    (tmp_path / "junk").mkdir()
    assert audit.audit_session(tmp_path / "junk", min_unicast_ratio=0.5) is None


def test_cli_exits_nonzero_on_a_void_batch(tmp_path, monkeypatch, capsys):
    batch = tmp_path / "batch"
    batch.mkdir()
    _make_session(batch, "s1", ["239.255.0.7"] * 50, interface="eth1")
    monkeypatch.setattr(
        sys, "argv", ["audit_capture_scope.py", "--batch", str(batch)]
    )
    assert audit.main() == 1
    captured = capsys.readouterr()
    assert "void_no_unicast" in captured.out
    # 訊息必須說清楚「無效」不等於「陰性」——這正是先前被誤讀的地方
    assert "無效" in captured.err and "陰性" in captured.err


def test_cli_exits_zero_on_a_good_batch(tmp_path, monkeypatch):
    batch = tmp_path / "batch"
    batch.mkdir()
    _make_session(batch, "s1", ["127.0.0.1"] * 50, interface="lo")
    monkeypatch.setattr(
        sys, "argv", ["audit_capture_scope.py", "--batch", str(batch)]
    )
    assert audit.main() == 0


def test_cli_refuses_to_overwrite_an_existing_report(tmp_path, monkeypatch):
    batch = tmp_path / "batch"
    batch.mkdir()
    _make_session(batch, "s1", ["127.0.0.1"] * 50, interface="lo")
    out = tmp_path / "report.json"
    out.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["audit_capture_scope.py", "--batch", str(batch), "--output", str(out)],
    )
    assert audit.main() == 2
    assert out.read_text(encoding="utf-8") == "{}"


def test_nested_layout_is_walked(tmp_path):
    batch = tmp_path / "batch"
    dataset = batch / "enforce" / "dataset"
    dataset.mkdir(parents=True)
    _make_session(dataset, "s1", ["127.0.0.1"] * 20, interface="lo")
    found = list(audit.iter_sessions(batch, nested=True))
    assert [item.name for item in found] == ["s1"]
