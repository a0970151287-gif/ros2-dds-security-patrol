"""訂閱端到底拿不拿得到發送者的 GUID？

這決定 IDS↔SROS2 第二層（可撤銷的應用層黑名單）做不做得成：有黑名單卻不知道
訊息來自誰，就無法丟棄。

`rmw_message_info_t` 有 `publisher_gid`（16 bytes），而 DDS GUID 剛好是
16 bytes（12 byte prefix ＋ 4 byte entity）。rclpy 的訂閱支援兩參數回呼
`(msg, message_info)`。這支就是去看那個結構裡實際有什麼。

最小測試：同一個行程內一個 publisher 一個 subscriber，用未使用的 domain，
不啟用安全、不產生攻擊流量。
"""

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

seen = []


class Probe(Node):
    def __init__(self):
        super().__init__("gid_probe")
        self.pub = self.create_publisher(String, "gid_probe_topic", 10)
        # 兩個參數 → rclpy 會用 WithMessageInfo 模式
        self.create_subscription(String, "gid_probe_topic", self.on_msg, 10)
        self.create_timer(0.5, self.tick)
        self.count = 0

    def tick(self):
        message = String()
        message.data = f"probe {self.count}"
        self.count += 1
        self.pub.publish(message)

    def on_msg(self, message, info):
        if seen:
            return
        seen.append(info)
        print("message_info 型別:", type(info).__name__)
        if isinstance(info, dict):
            print("鍵:", sorted(info))
            gid = info.get("publisher_gid")
        else:
            print("屬性:", [a for a in dir(info) if not a.startswith("_")])
            gid = getattr(info, "publisher_gid", None)
        print("publisher_gid 原始:", gid)
        if gid is not None:
            data = getattr(gid, "data", gid)
            try:
                as_bytes = bytes(data)
            except TypeError:
                as_bytes = None
            if as_bytes is not None:
                print("長度:", len(as_bytes))
                print("十六進位:", as_bytes.hex())
                print("前 12 bytes（GUID prefix 候選）:", as_bytes[:12].hex())


def main():
    rclpy.init()
    node = Probe()
    for _ in range(40):
        rclpy.spin_once(node, timeout_sec=0.2)
        if seen:
            break
    node.destroy_node()
    rclpy.shutdown()
    print("結果:", "拿到 message_info" if seen else "❌ 沒收到任何訊息")


if __name__ == "__main__":
    main()
