#!/usr/bin/env python3
"""智能防禦節點 — 最後一道防線（行為層異常偵測）。

設計理念：
    身份/輸入驗證 (HMAC, whitelist) 擋 application-layer 假冒
    SROS2 Enforce 擋 DDS-layer 越權
    本節點擋「合法身份做異常行為」— 攻擊者繞過前兩層、用看似合法的訊息攻擊時的最後防線

4 個 detector (任 2 個觸發 → 發 alert):
    D1 cmd vs physics      : cmd_vel 超出 burger 物理上限      → 擋攻擊 C
    D2 cmd oscillation    : cmd_vel 方向高頻翻轉              → 擋攻擊 J (namesake race)
    D3 scan repetition    : scan 連續幀差異趨近 0              → 擋攻擊 K (poisoning)
    D4 publisher count    : /cmd_vel /scan publisher 多於 1   → 擋 hijack/spoofing

不直接停車（避免誤判），只發 alert → 讓 patrol/burger_env 自行決定如何反應。
"""
import time
from collections import deque

import numpy as np
import rclpy
from geometry_msgs.msg import TwistStamped
from nav_msgs.msg import Odometry
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan
from std_msgs.msg import String

from dds_security_monitor.monitor_node import (
    CH_ALERTS,
    CH_HEARTBEAT,
    ReplayCache,
    _load_alert_secret,
    secret_fingerprint,
    sign_alert,
    verify_alert,
)


# ── 偵測門檻（保守值，避免誤判）─────────────────────────────────────
# Burger 規格：max linear 0.22 m/s, max angular 2.84 rad/s
# G5 修補：原本 0.50 留 50% buffer 過鬆，攻擊者灌 0.4 完全不會被抓
# G5→N9 修補：收緊到 0.23（剛好 burger spec 0.22 + 5% buffer），把 attacker safe zone
# 從 0.12-0.25 (13cm/s 範圍) 縮到 0.12-0.23 (11cm/s 範圍)
# 真要救命還是要靠 D4 + N9 cmd_vel race-mitigation
PHYSICS_LIN_MAX        = 0.23    # m/s, 超過視為非物理可行
PHYSICS_ANG_MAX        = 3.00    # rad/s, burger 規格 2.84 + 5% buffer
CMD_OSCILLATION_RATIO  = 0.7     # 最近 20 幀中 70%+ 方向翻轉 → 攻擊 J 徵兆
SCAN_REPEAT_MAX_DIFF   = 0.005   # 連續幀最大 |Δ| < 此值 → 攻擊 K 重複送
HISTORY_LEN            = 20      # 滑動窗口長度
EVAL_PERIOD_SEC        = 0.5     # 評估頻率
ALERT_COOLDOWN_SEC     = 10.0    # 兩次 alert 之間最少間隔（防止洗版）
VOTE_THRESHOLD         = 2       # 多少個 detector 同時觸發才 emit alert
HEARTBEAT_TIMEOUT_SEC  = 10.0    # G6: monitor 心跳 >10s 沒收到 → alert（monitor 被打掛）


class IntelligentDefenseNode(Node):
    """行為層 IDS — 系統的最後一道防線（防護堆疊 Layer 3）。

    六個偵測器（投票 ≥2 fire，D4 為 strong signal 可單獨 fire）：
      D1 cmd_vel 物理門檻：linear.x > 0.23 m/s（Burger 上限 0.22）
      D2 cmd 方向衝突：前進 ≥15% + 後退 ≥15% 同窗
      D3 scan 重複：max_diff < 0.005（攻擊者用固定假 scan）
      D4 unauthorized publisher：白名單外 publisher + 重複 publisher 計數
      D5 heartbeat watchdog：10s 內無 monitor 心跳 → 偵測層失能告警
      D6 cmd-vs-odom 一致性：cmd 推進但 odom 不動 / odom 移動但 scan 靜止

    Cascade DoS 緩解（ROSEC-2026-011 N21/N23）：
      偵測 → 自動 emergency stop 鏈本身是介面。為防攻擊者反覆觸發
      偵測達成 永久 pause，加入「90s 內 ≥2 次 pause → 進入 120s
      quiet window，alert 不再觸發自動 pause」斷路器，升級到外部介入。
    """

    def __init__(self):
        super().__init__('intelligent_defense_node')

        # 滑動視窗
        self._cmd_history:  deque = deque(maxlen=HISTORY_LEN)
        self._scan_history: deque = deque(maxlen=HISTORY_LEN)
        self._odom_twist_history: deque = deque(maxlen=HISTORY_LEN)

        # 最後一次 alert 時間（cooldown）
        self._last_alert_time = 0.0

        # 各 detector 累計觸發次數（telemetry）
        self._detector_hits = {"D1": 0, "D2": 0, "D3": 0, "D4": 0, "D5": 0, "D6": 0}

        # G6: monitor 心跳 watchdog
        self._last_heartbeat_wall = 0.0
        self._heartbeat_alerted = False   # 一次性 alert，避免每 0.5s 洗版

        # 訂閱
        qos_be = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        self.create_subscription(LaserScan,    '/scan',    self._scan_cb, qos_be)
        self.create_subscription(Odometry,     '/odom',    self._odom_cb, qos_be)
        self.create_subscription(TwistStamped, '/cmd_vel', self._cmd_cb,  10)
        # G6 + N1 修補：心跳改用 RELIABLE + TRANSIENT_LOCAL（對齊 monitor 端）
        # 確保 IDS 能拿到最後一筆心跳 → 攻擊者後續 replay 就會在 nonce cache 命中
        qos_hb = QoSProfile(
            depth=1,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self.create_subscription(String, '/security/heartbeat', self._hb_cb, qos_hb)

        # 發布 alert（簽章後跟 monitor_node 共用 /security/alerts）
        qos_alert = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._alert_pub = self.create_publisher(String, '/security/alerts', qos_alert)
        self._secret = _load_alert_secret()
        # N1 修補：心跳專用 ReplayCache，攻擊者錄一筆 replay 會在 nonce LRU 命中
        self._hb_replay_cache = ReplayCache()

        # 定時評估
        self.create_timer(EVAL_PERIOD_SEC, self._evaluate)

        # 5 秒印一次統計
        self.create_timer(5.0, self._print_stats)

        self.get_logger().info(
            f'🛡️ 智能防禦啟動 — voting threshold={VOTE_THRESHOLD}/4, '
            f'cooldown={ALERT_COOLDOWN_SEC:.0f}s, '
            f'monitor 心跳 timeout={HEARTBEAT_TIMEOUT_SEC:.0f}s'
        )

    # ── 訊息收集 ────────────────────────────────────────────────────

    def _scan_cb(self, msg: LaserScan):
        ranges = list(msg.ranges)
        if len(ranges) > 50:
            self._scan_history.append(ranges)

    def _odom_cb(self, msg: Odometry):
        # 取實際線速度跟角速度（Gazebo diff_drive 受物理上限）
        self._odom_twist_history.append((msg.twist.twist.linear.x,
                                         msg.twist.twist.angular.z))

    def _cmd_cb(self, msg: TwistStamped):
        self._cmd_history.append((msg.twist.linear.x, msg.twist.angular.z))

    def _hb_cb(self, msg: String):
        # G6 + N1 修補：驗章 + freshness(3s) + nonce-LRU 三重檢查。
        # max_age 故意比 alert 短：心跳每 2s 一筆，3s 視為過期。攻擊者頂多 replay 3s 後
        # 訊息變過期 → watchdog 不再被刷新 → D5 在 timeout 後 fire。
        payload = verify_alert(
            msg.data, self._secret,
            expected_channel=CH_HEARTBEAT,
            cache=self._hb_replay_cache,
            max_age=3.0,
        )
        if payload is None:
            self.get_logger().warn(
                f'⛔ 心跳驗證失敗（簽錯/重放/過期）— 拒絕',
                throttle_duration_sec=5.0)
            return
        self._last_heartbeat_wall = time.monotonic()
        if self._heartbeat_alerted:
            self._heartbeat_alerted = False
            self.get_logger().info('💓 monitor 心跳恢復')

    # ── 4 個 detector ────────────────────────────────────────────────

    def _detect_d1_physics(self) -> tuple[bool, str]:
        """D1: cmd_vel 超出物理上限 → 攻擊 C 注入 100 m/s 必中"""
        if not self._cmd_history:
            return False, ""
        recent = list(self._cmd_history)[-5:]
        max_lin = max(abs(c[0]) for c in recent)
        max_ang = max(abs(c[1]) for c in recent)
        if max_lin > PHYSICS_LIN_MAX:
            return True, f"cmd_lin={max_lin:.2f}>={PHYSICS_LIN_MAX}"
        if max_ang > PHYSICS_ANG_MAX:
            return True, f"cmd_ang={max_ang:.2f}>={PHYSICS_ANG_MAX}"
        return False, ""

    def _detect_d2_oscillation(self) -> tuple[bool, str]:
        """D2: cmd_vel 方向衝突 → 攻擊 J namesake race（真假 patrol 競爭）

        改進版：不用「翻轉率」（會因不同頻率比例失效），改用「forward/backward 共存」
        正常 patrol 同一段時間內方向一致；攻擊者塞反向 → 兩個方向同時存在。
        """
        if len(self._cmd_history) < 10:
            return False, ""
        hist = list(self._cmd_history)
        fwd = sum(1 for c in hist if c[0] > 0.01)
        bwd = sum(1 for c in hist if c[0] < -0.01)
        n   = len(hist)
        # 兩個方向各佔 ≥ 15% → 行為衝突
        if fwd / n >= 0.15 and bwd / n >= 0.15:
            return True, f"fwd={fwd}/{n} + bwd={bwd}/{n}（方向衝突）"
        return False, ""

    def _detect_d3_scan_repeat(self) -> tuple[bool, str]:
        """D3: scan 連續幀差異趨近 0 → 攻擊 K 偽造（重複 pattern）"""
        if len(self._scan_history) < 5:
            return False, ""
        hist = list(self._scan_history)[-5:]
        max_diff = 0.0
        for i in range(1, len(hist)):
            a = np.asarray(hist[i],   dtype=np.float32)
            b = np.asarray(hist[i-1], dtype=np.float32)
            # 過濾 inf/nan
            mask = np.isfinite(a) & np.isfinite(b)
            if mask.sum() > 0:
                d = float(np.mean(np.abs(a[mask] - b[mask])))
                if d > max_diff:
                    max_diff = d
        # 真實 lidar 即使靜止也有 0.005~0.05 的雜訊
        if max_diff < SCAN_REPEAT_MAX_DIFF:
            return True, f"max_diff={max_diff:.4f}<{SCAN_REPEAT_MAX_DIFF}"
        return False, ""

    def _detect_d4_publishers(self) -> tuple[bool, str]:
        """D4: /cmd_vel /scan 上 publisher 計數異常 → hijack/spoofing

        G2 修補：原版完全信任 node_name 白名單，攻擊者把自己命名為
        `patrol_node` 或 `teleop_keyboard` 即可通過。改為「同時 publisher 數量」檢測：
            - /cmd_vel 同時 ≥ 2 個（扣掉 dds_security_monitor emergency stop 用的）→ hijack
            - /scan 同時 ≥ 2 個 → spoof
        合法狀況下 robot 只能有 1 個 cmd 來源（patrol_node OR burger_env_top OR teleop，三選一）
        2 個同時存在 = 雙重控制 = 攻擊。
        Name 白名單仍保留為次要檢查（catch 攻擊者用了未列名的 process）。
        """
        CMD_ALLOWED  = {"burger_env_top", "teleop_keyboard", "patrol_node",
                        "dds_security_monitor", "intelligent_defense_node"}
        SCAN_ALLOWED = {"ros_gz_bridge", "parameter_bridge",
                        "hokuyo_driver", "rplidar_node", "ldlidar_node", "urg_node"}
        # N11 修補：/odom 也納入監控
        ODOM_ALLOWED = {"ros_gz_bridge", "parameter_bridge", "turtlebot3_node",
                        "diff_drive_controller", "gazebo"}
        # N22 修補：/imu 也納入監控（雖然目前 sensor_hub 不用 IMU 做決策，
        # 但防「哪天有人開始相信」場景；同源 publisher 計數攔截 spoof）
        IMU_ALLOWED  = {"ros_gz_bridge", "parameter_bridge", "turtlebot3_node",
                        "gazebo"}
        def is_benign(name: str) -> bool:
            return name == "_NODE_NAME_UNKNOWN_"
        try:
            cmd_pubs  = self.get_publishers_info_by_topic('/cmd_vel')
            scan_pubs = self.get_publishers_info_by_topic('/scan')
            odom_pubs = self.get_publishers_info_by_topic('/odom')
            imu_pubs  = self.get_publishers_info_by_topic('/imu')
        except Exception:
            return False, ""

        # ── (a) 名字檢查（次要）─────────
        cmd_bad  = [p.node_name for p in cmd_pubs
                    if p.node_name not in CMD_ALLOWED  and not is_benign(p.node_name)]
        scan_bad = [p.node_name for p in scan_pubs
                    if p.node_name not in SCAN_ALLOWED and not is_benign(p.node_name)]
        odom_bad = [p.node_name for p in odom_pubs
                    if p.node_name not in ODOM_ALLOWED and not is_benign(p.node_name)]
        imu_bad  = [p.node_name for p in imu_pubs
                    if p.node_name not in IMU_ALLOWED  and not is_benign(p.node_name)]
        if cmd_bad:
            return True, f"cmd unauthorized pub: {cmd_bad}"
        if scan_bad:
            return True, f"scan unauthorized pub: {scan_bad}"
        if odom_bad:
            return True, f"odom unauthorized pub: {odom_bad}"
        if imu_bad:
            return True, f"imu unauthorized pub: {imu_bad}"

        # ── (b) 計數檢查（主要 — 防同名冒充 G2 + N11 odom spoof + N22 imu spoof）─────────
        # dds_security_monitor / patrol_node 偶爾發 emergency stop / pause cmd_vel，扣掉
        real_cmd  = [p.node_name for p in cmd_pubs
                     if not is_benign(p.node_name)
                     and p.node_name != "dds_security_monitor"
                     and p.node_name != "intelligent_defense_node"]
        if len(real_cmd) >= 2:
            return True, f"cmd 同時 {len(real_cmd)} 個 publisher: {real_cmd}（hijack/同名冒充）"
        real_scan = [p.node_name for p in scan_pubs if not is_benign(p.node_name)]
        if len(real_scan) >= 2:
            return True, f"scan 同時 {len(real_scan)} 個 publisher: {real_scan}（spoof）"
        real_odom = [p.node_name for p in odom_pubs if not is_benign(p.node_name)]
        if len(real_odom) >= 2:
            return True, f"odom 同時 {len(real_odom)} 個 publisher: {real_odom}（spoof）"
        real_imu = [p.node_name for p in imu_pubs if not is_benign(p.node_name)]
        if len(real_imu) >= 2:
            return True, f"imu 同時 {len(real_imu)} 個 publisher: {real_imu}（N22 spoof）"
        return False, ""

    def _detect_d6_scan_odom_consistency(self) -> tuple[bool, str]:
        """D6 (N10/N11 部分修補): scan-vs-odom 行為一致性檢查。

        應用層無法直接擋 /scan /odom 偽造（message type 不是 String 無法包 envelope；
        真正修補需要 SROS2 Enforce）。但可以用「資料間的物理一致性」抓邏輯破綻：

          (a) 若 odom 顯示 robot 在動（|v| > 0.05 m/s）但 scan 連續幀完全一樣
              → 攻擊者可能在 odom 偽造速度（讓 SAC 學錯）或 scan 偽造靜態畫面
          (b) 若 cmd_vel 持續正向 > 0.05 m/s 1 秒以上但 odom 完全沒位移
              → odom 被凍結（攻擊者篡改位置認知，讓 patrol 在原地跳 waypoint）

        這只能補強，無法替代 SROS2 — 行為一致性的攻擊（精心配合的假 scan+假 odom）仍可繞過。
        """
        # 需要足夠歷史
        if len(self._odom_twist_history) < 10 or len(self._scan_history) < 5:
            return False, ""
        # (a) odom 顯示有移動 + scan 完全靜止 → 不一致
        recent_twist = list(self._odom_twist_history)[-10:]
        avg_lin = float(np.mean([abs(t[0]) for t in recent_twist]))
        if avg_lin > 0.05:
            hist = list(self._scan_history)[-3:]
            max_diff = 0.0
            for i in range(1, len(hist)):
                a = np.asarray(hist[i],   dtype=np.float32)
                b = np.asarray(hist[i-1], dtype=np.float32)
                mask = np.isfinite(a) & np.isfinite(b)
                if mask.sum() > 0:
                    max_diff = max(max_diff, float(np.mean(np.abs(a[mask] - b[mask]))))
            if max_diff < 0.002:    # scan 比 D3 更嚴格的「靜止度」
                return True, f"odom v={avg_lin:.2f}m/s 移動中但 scan 完全靜止 ({max_diff:.4f})"
        # (b) cmd 持續正向但 odom 沒動
        if len(self._cmd_history) >= 5:
            recent_cmd = list(self._cmd_history)[-5:]
            avg_cmd = float(np.mean([c[0] for c in recent_cmd]))
            if avg_cmd > 0.05 and avg_lin < 0.005:
                return True, f"cmd v={avg_cmd:.2f}m/s 持續正向但 odom 靜止 ({avg_lin:.4f})"
        return False, ""

    # ── 投票評估 ────────────────────────────────────────────────────

    def _check_heartbeat(self) -> tuple[bool, str]:
        """G6: monitor 心跳 watchdog — 超時表示 monitor 被打掛或被隔離"""
        # 啟動初期還沒收到第一次心跳，給 grace period
        if self._last_heartbeat_wall == 0.0:
            return False, ""
        gap = time.monotonic() - self._last_heartbeat_wall
        if gap > HEARTBEAT_TIMEOUT_SEC:
            return True, f"monitor 心跳已 {gap:.1f}s 未到達 (>{HEARTBEAT_TIMEOUT_SEC:.0f}s)"
        return False, ""

    def _evaluate(self):
        votes = []
        details = []
        strong = False    # D4/D5 訊號強，獨立可觸發
        for did, fn in [
            ("D1", self._detect_d1_physics),
            ("D2", self._detect_d2_oscillation),
            ("D3", self._detect_d3_scan_repeat),
            ("D4", self._detect_d4_publishers),
            ("D5", self._check_heartbeat),
            ("D6", self._detect_d6_scan_odom_consistency),
        ]:
            triggered, info = fn()
            if triggered:
                votes.append(did)
                details.append(f"{did}[{info}]")
                self._detector_hits[did] += 1
                if did in ("D4", "D5"):
                    strong = True

        # G6: heartbeat 失效只發一次 alert，避免重複洗版
        if "D5" in votes and self._heartbeat_alerted:
            # 已 alert 過，不再 emit；但仍累計 D5 計數
            votes.remove("D5")
            details = [d for d in details if not d.startswith("D5[")]
            strong = any(v == "D4" for v in votes)
        elif "D5" in votes:
            self._heartbeat_alerted = True

        if len(votes) >= VOTE_THRESHOLD or strong:
            now = time.monotonic()
            if now - self._last_alert_time < ALERT_COOLDOWN_SEC:
                self.get_logger().warn(
                    f'⏳ 異常持續 ({", ".join(votes)})，cooldown 中（剩 '
                    f'{ALERT_COOLDOWN_SEC - (now - self._last_alert_time):.1f}s）'
                )
                return
            self._last_alert_time = now
            reason = "vote" if len(votes) >= VOTE_THRESHOLD else "strong-D4"
            self._emit_alert(votes, details, reason)
        elif len(votes) == 1:
            self.get_logger().warn(
                f"⚠️ 單一 detector 警告: {details[0]}（未達投票門檻 {VOTE_THRESHOLD}，繼續觀察）"
            )

    def _emit_alert(self, votes, details, reason="vote"):
        header = (f"vote={len(votes)}/6 >= {VOTE_THRESHOLD}" if reason == "vote"
                  else "strong signal (D4 publisher hijack / D5 monitor 心跳失效)")
        text = (
            f"🛡️ [智能防禦警報]\n"
            f"行為層異常偵測 ({header}):\n"
            + "\n".join(f"  • {d}" for d in details)
        )
        signed = sign_alert(text, self._secret, channel=CH_ALERTS)
        msg = String()
        msg.data = signed
        self._alert_pub.publish(msg)
        self.get_logger().error(text)

    def _print_stats(self):
        # 永遠 print 資料流狀態（debug 用）
        self.get_logger().info(
            f"📊 status: cmd_hist={len(self._cmd_history)}, "
            f"odom_hist={len(self._odom_twist_history)}, "
            f"scan_hist={len(self._scan_history)}  |  "
            f"hits D1={self._detector_hits['D1']}, "
            f"D2={self._detector_hits['D2']}, "
            f"D3={self._detector_hits['D3']}, "
            f"D4={self._detector_hits['D4']}, "
            f"D5={self._detector_hits['D5']} (hb), "
            f"D6={self._detector_hits['D6']} (consistency)"
        )


def main(args=None):
    rclpy.init(args=args)
    node = IntelligentDefenseNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
