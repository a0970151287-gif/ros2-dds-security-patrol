#!/usr/bin/env python3
"""N29：持有合法 SROS2 憑證、但沒有 HMAC 金鑰的內部攻擊者。

為什麼需要這一支：在 Enforce 下，無憑證的攻擊者連 DDS handshake 都建不起來，
訊息根本到不了 HMAC 驗證器、SensorHub 的 oversized 分支或 parameter veto。
1,100 場正式資料裡 Enforce 模式的遙測幾乎全零，就是這個原因。所以應用層那幾道
防線在外部威脅模型下**無法被觀測**——不是沒作用，是打不到。

這一支模擬的是真正該用來檢驗那幾道防線的威脅：**某個合法節點被攻陷**。攻擊者
拿到該節點的身分憑證，SROS2 因此放行；但 HMAC 共享金鑰不在 keystore 裡，所以
他仍然簽不出有效的訊息。這正是分層防禦的論點——SROS2 擋外人，HMAC 擋內鬼。

竊取的身分決定了能打哪裡，這本身就是最小權限 ACL 的實測結果：

    rt/security/alerts   只有 dds_security_monitor 與 intelligent_defense_node 能發
    rt/scan              只有 gazebo 能發
    set_parameters       沒有任何節點能對別人送 → parameter 竄改連內鬼也打不到

節點名稱刻意不與 enclave 同名，因此一律關掉 rclpy 的 parameter service：
權限是按節點名產生的，`rq/<自己的名字>/...` 不在 allow rule 裡會讓節點起不來，
而且錯誤訊息完全不提權限（delivery canary 就被這件事咬過）。

用法（每個模式都要搭配它需要的 enclave）：
    ros2 run ... 不適用；直接 python3 執行並帶 --ros-args --enclave <path>

    --mode hmac_forgery    --enclave /intelligent_defense_node
    --mode oversized_scan  --enclave /gazebo
    --mode replay_capture  --enclave /velocity_guard_node   （寫檔後結束）
    --mode replay_publish  --enclave /intelligent_defense_node
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path

import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan
from std_msgs.msg import String

from dds_security_monitor.monitor_node import CH_ALERTS, sign_alert


ALERT_TOPIC = "/security/alerts"
HEARTBEAT_TOPIC = "/security/heartbeat"
SCAN_TOPIC = "/scan"
# SensorHub 的上限是 4096；超過就走 rejection 分支並計入 oversized_count。
# 取剛好超過而不是遠遠超過：8,192 點約 32KB，大樣本在預設 Fast DDS buffer 下
# 可能在傳輸層就被丟掉，那會讓「訊息沒到」看起來像「防禦擋下了」。
OVERSIZED_POINTS = 4097


def _wrong_secret() -> bytes:
    """一把攻擊者自己生的金鑰。

    重點是信封本身要**格式正確**——channel、nonce、ts、payload 都在，只有 HMAC
    對不上。否則驗證器會判成 malformed_envelope，那證明的是解析器擋住了畸形輸入，
    不是簽章檢查擋住了偽造，兩者是不同的防線。
    """
    return secrets.token_bytes(32)


class InsiderNode(Node):
    def __init__(self, name: str) -> None:
        # 節點名與被竊 enclave 不同名，所以不能讓 rclpy 建任何 ~/ 服務：權限是按
        # 節點名產生的，`rq/<自己的名字>/...` 不在 allow rule 裡。
        # start_parameter_services 關掉六個參數服務；type description service 另有
        # 自己的開關，而且它是 Node.__init__ 裡直接建的，只能用 parameter_overrides
        # 在建構當下關掉——漏掉它會得到
        # "Failed to initialize type description service: create_service() failed to
        # create request DataReader"，訊息裡同樣一個字都不提權限。
        super().__init__(
            name,
            start_parameter_services=False,
            parameter_overrides=[
                Parameter("start_type_description_service", Parameter.Type.BOOL, False)
            ],
        )


def _run_hmac_forgery(args) -> int:
    node = InsiderNode("insider_alert_probe")
    publisher = node.create_publisher(
        String, ALERT_TOPIC, QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE)
    )
    deadline = time.monotonic() + args.duration_sec
    sent = 0
    secret = _wrong_secret()
    while time.monotonic() < deadline and sent < args.count:
        message = String()
        message.data = sign_alert(
            f"forged-alert|{sent}", secret, channel=CH_ALERTS
        )
        publisher.publish(message)
        sent += 1
        rclpy.spin_once(node, timeout_sec=0.0)
        time.sleep(args.interval_sec)
    print(f"insider_hmac_forgery_sent={sent}")
    node.destroy_node()
    return 0


def _run_oversized_scan(args) -> int:
    node = InsiderNode("insider_scan_probe")
    publisher = node.create_publisher(
        LaserScan, SCAN_TOPIC, QoSProfile(depth=5, reliability=ReliabilityPolicy.RELIABLE)
    )
    deadline = time.monotonic() + args.duration_sec
    sent = 0
    while time.monotonic() < deadline and sent < args.count:
        scan = LaserScan()
        scan.header.frame_id = "base_scan"
        scan.header.stamp = node.get_clock().now().to_msg()
        scan.angle_min = -3.14
        scan.angle_max = 3.14
        scan.angle_increment = 6.28 / OVERSIZED_POINTS
        scan.range_min = 0.1
        scan.range_max = 10.0
        scan.ranges = [1.0] * OVERSIZED_POINTS
        publisher.publish(scan)
        sent += 1
        rclpy.spin_once(node, timeout_sec=0.0)
        time.sleep(args.interval_sec)
    print(f"insider_oversized_scan_sent={sent}")
    node.destroy_node()
    return 0


def _run_replay_capture(args) -> int:
    """以被攻陷的 subscriber 身分側錄一則真正已簽章的 alert。

    攻擊者簽不出有效訊息，所以重放必須用真品。沒有任何 enclave 同時擁有 alerts
    的發布與訂閱權，這本身就是 ACL 的效果——重放因此需要兩個被攻陷的身分，
    而不是一個。
    """
    node = InsiderNode("insider_capture_probe")
    captured: list[str] = []

    def _age_sec(envelope: str) -> float | None:
        """信封自己宣告的年齡。回傳 None 表示解析不出來。"""
        try:
            body = json.loads(json.loads(envelope)["body"])
            return time.time() - float(body["ts"])
        except (ValueError, TypeError, KeyError):
            return None

    def _on_alert(message: String) -> None:
        if captured:
            return
        # 只收夠新鮮的。alerts topic 若是 TRANSIENT_LOCAL，後加入的訂閱者會先拿到
        # durability 快取裡的舊樣本——那可能已經好幾分鐘大，重放出去必然先被
        # 時間戳檢查攔下，拒絕理由是 timestamp_violation 而不是 nonce 重用。
        # 實測 12 則重放全部落在 timestamp_violation，就是這個原因。
        age = _age_sec(message.data)
        if age is None or age > args.max_capture_age_sec:
            return
        captured.append(message.data)

    node.create_subscription(
        String, args.topic, _on_alert,
        QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE),
    )
    deadline = time.monotonic() + args.duration_sec
    while time.monotonic() < deadline and not captured:
        rclpy.spin_once(node, timeout_sec=0.2)
    if captured:
        Path(args.capture_file).write_text(captured[0], encoding="utf-8")
        print(f"insider_replay_captured=1 bytes={len(captured[0])}")
    else:
        print("insider_replay_captured=0")
    node.destroy_node()
    return 0 if captured else 1


def _run_replay_publish(args) -> int:
    """先建好 publisher 並完成 discovery，再等側錄檔出現就立刻重放。

    心跳的 freshness window 只有 3 秒。若等側錄完成才啟動這個行程，光是 rclpy
    初始化與 DDS discovery 就用掉數秒，信封到達時已經過期——拒絕理由會是
    timestamp_violation 而不是 nonce 重用。擋是擋住了，但擋它的是另一道防線，
    這一項要驗的是 ReplayCache。
    """
    node = InsiderNode("insider_replay_probe")
    publisher = node.create_publisher(
        String, args.topic, QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE)
    )
    # 先讓 discovery 完成，之後重放才會是「立刻」。
    settle = time.monotonic() + args.settle_sec
    while time.monotonic() < settle:
        rclpy.spin_once(node, timeout_sec=0.05)

    # 等一個獨立的 go 檔，而不是等側錄檔本身：呼叫端要先把 trigger 窗開好，
    # 重放才能落在窗內。marker 要 0.7 秒確認落地，若直接盯側錄檔，發送會早於
    # 開窗，證據就掉在窗外。
    gate = Path(args.go_file) if args.go_file else Path(args.capture_file)
    path = Path(args.capture_file)
    deadline = time.monotonic() + args.duration_sec
    while time.monotonic() < deadline and not (gate.is_file() and gate.stat().st_size >= 0):
        rclpy.spin_once(node, timeout_sec=0.05)
        time.sleep(0.05)
    if not (path.is_file() and path.stat().st_size > 0):
        print("insider_replay_publish=0 reason=no_capture", file=sys.stderr)
        node.destroy_node()
        return 1

    envelope = path.read_text(encoding="utf-8").strip()
    try:
        # 只確認它是完整信封；不改內容，重放必須逐位元組相同，否則簽章就壞了。
        parsed = json.loads(envelope)
        if not {"body", "sig"} <= set(parsed):
            raise ValueError
    except (ValueError, TypeError):
        print("insider_replay_publish=0 reason=malformed_capture", file=sys.stderr)
        node.destroy_node()
        return 1

    sent = 0
    while sent < args.count:
        message = String()
        message.data = envelope
        publisher.publish(message)
        sent += 1
        rclpy.spin_once(node, timeout_sec=0.0)
        time.sleep(args.interval_sec)
    print(f"insider_replay_sent={sent}")
    node.destroy_node()
    return 0


MODES = {
    "hmac_forgery": _run_hmac_forgery,
    "oversized_scan": _run_oversized_scan,
    "replay_capture": _run_replay_capture,
    "replay_publish": _run_replay_publish,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=tuple(MODES), required=True)
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--interval-sec", type=float, default=0.15)
    parser.add_argument("--duration-sec", type=float, default=20.0)
    parser.add_argument("--settle-sec", type=float, default=4.0)
    parser.add_argument("--max-capture-age-sec", type=float, default=2.0)
    parser.add_argument("--go-file", default=None)
    # 心跳是最可靠的側錄來源：monitor 每秒都在發，側錄幾乎瞬間完成。alert 只有
    # 偵測器投票時才出現，側錄可能等不到，而信封的 freshness window 只有 10 秒
    # （guard 對心跳更嚴，是 3 秒），等太久就會先被時間戳檢查攔下。
    parser.add_argument(
        "--topic",
        default=ALERT_TOPIC,
        choices=(ALERT_TOPIC, HEARTBEAT_TOPIC),
        help="replay_capture / replay_publish 使用的 topic",
    )
    parser.add_argument(
        "--capture-file",
        default="/home/jesse/.local/share/sros2-firewall/live_runtime/captured_alert.json",
    )
    if os.environ.get("ROS_SECURITY_STRATEGY") != "Enforce":
        print("N29 只在 SROS2 Enforce 下有意義", file=sys.stderr)
        return 2
    args = parser.parse_args(rclpy.utilities.remove_ros_args(sys.argv)[1:])

    rclpy.init()
    try:
        return MODES[args.mode](args)
    finally:
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
