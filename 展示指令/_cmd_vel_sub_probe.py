#!/usr/bin/env python3
"""最小 /cmd_vel 訂閱探針 — 收到 TwistStamped 就即時寫檔(flush)。
用於 SROS2 Enforce vs Permissive 的 /cmd_vel 注入對照驗證。
用法: python3 _cmd_vel_sub_probe.py <秒數> <輸出檔>
"""
import sys, time
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped

OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/cmd_recv.txt"
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 10


class Probe(Node):
    def __init__(self):
        super().__init__("cmd_vel_probe")
        self.n = 0
        self.create_subscription(TwistStamped, "/cmd_vel", self.cb, 10)
        with open(OUT, "w") as f:
            f.write("probe-started\n")

    def cb(self, m):
        self.n += 1
        with open(OUT, "a") as f:
            f.write(f"recv {self.n} linear.x={m.twist.linear.x} angular.z={m.twist.angular.z}\n")


def main():
    rclpy.init()
    node = Probe()
    end = time.time() + DUR
    while time.time() < end and rclpy.ok():
        rclpy.spin_once(node, timeout_sec=0.3)
    node.destroy_node()
    rclpy.shutdown()


if __name__ == "__main__":
    main()
