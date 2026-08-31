"""N32 被動 discovery 偵察：把「真的不說話」這件事釘住。

這支攻擊的整個前提是**不送任何東西**。而 `rclpy.Node()` 預設會偷偷替你建
六個參數服務、一個 `~/get_type_description` 服務、以及 rosout publisher——
那些都會送流量，前提就沒了。

三個開關缺一不可，而 type description service **只能在建構當下**用
`parameter_overrides` 關掉。這個專案已經被同一個陷阱咬過三次
（delivery canary、outcome observer、N29），而且失敗訊息一個字都不提你少關了
什麼——N29 那次是「Failed to initialize type description service:
create_service() failed to create request DataReader」。

所以這裡不測「跑得動」，測的是**建構參數**。用假的 rclpy 攔下來看，
不啟動任何 ROS runtime。
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "紅隊測試" / "PoC腳本" / "N32_discovery_recon.py"


def _load():
    spec = importlib.util.spec_from_file_location("n32_discovery_recon", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _FakeParameter:
    BOOL = "bool"

    class Type:
        BOOL = "bool"

    def __init__(self, name, kind, value):
        self.name = name
        self.kind = kind
        self.value = value


class _FakeNode:
    """記下建構參數，並提供 discovery 查詢的最小回應。"""

    constructed: list[dict] = []

    def __init__(self, name, **kwargs):
        _FakeNode.constructed.append({"name": name, **kwargs})

    def get_node_names_and_namespaces(self):
        return [("dds_security_monitor", "/"), ("gazebo", "/")]

    def get_topic_names_and_types(self):
        return [("/scan", ["sensor_msgs/msg/LaserScan"])]

    def get_publishers_info_by_topic(self, topic):
        info = types.SimpleNamespace(node_name="gazebo", node_namespace="/")
        return [info]

    def get_subscriptions_info_by_topic(self, topic):
        info = types.SimpleNamespace(
            node_name="dds_security_monitor", node_namespace="/"
        )
        return [info]

    def destroy_node(self):
        pass


@pytest.fixture
def stubbed_rclpy(monkeypatch):
    """裝一套假的 rclpy，讓腳本可以在沒有 ROS 的情況下被檢查。"""
    _FakeNode.constructed = []

    rclpy = types.ModuleType("rclpy")
    rclpy.init = lambda *a, **k: None
    rclpy.shutdown = lambda *a, **k: None
    rclpy.spin_once = lambda *a, **k: None

    node_mod = types.ModuleType("rclpy.node")
    node_mod.Node = _FakeNode

    param_mod = types.ModuleType("rclpy.parameter")
    param_mod.Parameter = _FakeParameter

    monkeypatch.setitem(sys.modules, "rclpy", rclpy)
    monkeypatch.setitem(sys.modules, "rclpy.node", node_mod)
    monkeypatch.setitem(sys.modules, "rclpy.parameter", param_mod)
    yield


def test_all_three_silencing_switches_are_set(stubbed_rclpy, capsys):
    """漏掉任何一個，rclpy 就會替它建會送流量的東西——前提就沒了。"""
    module = _load()

    module._run_silent_participant(1.0, interval=0.0)

    assert len(_FakeNode.constructed) == 1
    kwargs = _FakeNode.constructed[0]
    assert kwargs["start_parameter_services"] is False, "六個參數服務沒關"
    assert kwargs["enable_rosout"] is False, "rosout publisher 沒關"

    overrides = kwargs["parameter_overrides"]
    names = {p.name: p.value for p in overrides}
    assert names.get("start_type_description_service") is False, (
        "type description service 沒關——它是 Node.__init__ 裡直接建的，"
        "只能用 parameter_overrides 在建構當下關掉"
    )


def test_it_creates_no_publisher_or_subscriber(stubbed_rclpy):
    """假 Node 沒有 create_publisher／create_subscription。

    腳本若呼叫了它們就會 AttributeError——這比讀程式碼可靠，
    因為它擋的是**未來**有人加回去。
    """
    module = _load()

    assert not hasattr(_FakeNode, "create_publisher")
    assert not hasattr(_FakeNode, "create_subscription")
    # 跑得完就代表它一次都沒呼叫。
    assert module._run_silent_participant(1.0, interval=0.0) == 0


def test_the_recon_product_is_the_topology(stubbed_rclpy, capsys):
    """偵察的產物要是拓撲本身，否則這支就沒有攻擊價值。"""
    module = _load()

    module._run_silent_participant(1.0, interval=0.0)

    import json

    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "silent-participant"
    assert "/dds_security_monitor" in report["nodes"]
    assert "/scan" in report["topics"]
    # 誰在發、誰在收——DDS 主動公告給每個加入者的東西。
    assert "pub:/gazebo" in report["endpoints"]["/scan"]
    assert "sub:/dds_security_monitor" in report["endpoints"]["/scan"]


def test_duration_is_bounded_like_every_other_runner():
    """runner 契約要求有界；無界的攻擊會讓整個視窗的標記失去意義。"""
    module = _load()

    for bad in ("0.5", "301"):
        assert module.main.__doc__ is None or True  # main 用 argv
        sys.argv = ["n32", bad]
        assert module.main() == 2

    sys.argv = ["n32"]


def test_sniff_mode_reports_zero_packets_sent():
    """`sniff` 模式的重點就是攻擊者送出 0 個封包。

    這一類在任何以速率／比例／連線數為基礎的特徵上都不可見。腳本必須把這件事
    寫進產物，否則之後讀資料的人會以為是模型沒抓到。
    """
    text = SCRIPT.read_text(encoding="utf-8")
    assert '"packets_sent_by_attacker": 0' in text
