#!/usr/bin/env python3
"""目標機側 /odom 角速度記錄器 — 量「機器人物理上聽誰的」。
SROS2 對照證據：before(Permissive 被劫持→ang 飆到攻擊值) vs after(Enforce→ang≈0)。

用法（目標機，跟系統同 domain/enclave）:
  # Permissive(before)：
  ROS_DOMAIN_ID=30 python3 _odom_angular_probe.py 30 /tmp/odom_before.csv
  # Enforce(after)：掛 enclave 才訂得到加密的 /odom
  ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce ROS_SECURITY_KEYSTORE=... \
    ROS_SECURITY_ENCLAVE_OVERRIDE=/dds_security_monitor \
    python3 _odom_angular_probe.py 30 /tmp/odom_after.csv
"""
import sys, time
import rclpy
from rclpy.node import Node
from nav_msgs.msg import Odometry

DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 30
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/odom_probe.csv"


class OdomProbe(Node):
    def __init__(self):
        super().__init__("odom_angular_probe")
        self.n = 0
        self.create_subscription(Odometry, "/odom", self.cb, 10)
        with open(OUT, "w") as f:
            f.write("t,linear_x,angular_z\n")
        self._t0 = time.time()
        self.create_timer(2.0, self._tick)   # 每 2s 印目前峰值

    def cb(self, m):
        self.n += 1
        lx = m.twist.twist.linear.x
        az = m.twist.twist.angular.z
        with open(OUT, "a") as f:
            f.write(f"{time.time()-self._t0:.2f},{lx:.4f},{az:.4f}\n")

    def _tick(self):
        self.get_logger().info(f"已收 {self.n} 筆 /odom（寫入 {OUT}）")


def main():
    rclpy.init()
    node = OdomProbe()
    end = time.time() + DUR
    while time.time() < end and rclpy.ok():
        rclpy.spin_once(node, timeout_sec=0.3)
    # 收尾統計：最大 |angular_z|
    try:
        import csv
        rows = list(csv.DictReader(open(OUT)))
        az = [abs(float(r["angular_z"])) for r in rows] or [0.0]
        print(f"\n=== /odom 統計（{len(rows)} 筆）===")
        print(f"  max |angular_z| = {max(az):.3f} rad/s")
        print(f"  → {'⚠️ 機器人被外力旋轉（疑似劫持）' if max(az) > 0.3 else '✅ 角速度≈0，未被劫持'}")
    except Exception as e:
        print("統計失敗:", e)
    node.destroy_node()
    rclpy.shutdown()


if __name__ == "__main__":
    main()
