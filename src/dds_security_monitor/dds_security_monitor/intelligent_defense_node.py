#!/usr/bin/env python3
"""智能防禦節點 — 最後一道防線（行為層異常偵測）。

設計理念：
    身份/輸入驗證 (HMAC, whitelist) 擋 application-layer 假冒
    SROS2 Enforce 擋 DDS-layer 越權
    本節點擋「合法身份做異常行為」— 攻擊者繞過前兩層、用看似合法的訊息攻擊時的最後防線

D1–D6 六個 detector（任 2 個觸發；D1/D4/D5 強訊號可單獨發 alert）:
    D1 cmd vs physics      : cmd_vel 超出 burger 物理上限      → 擋攻擊 C
    D2 cmd oscillation    : cmd_vel 方向高頻翻轉              → 擋攻擊 J (namesake race)
    D3 scan repetition    : scan 連續幀差異趨近 0              → 擋攻擊 K (poisoning)
    D4 publisher count    : /cmd_vel /scan publisher 多於 1   → 擋 hijack/spoofing
    D5 heartbeat watchdog : monitor 心跳逾時／從未出現          → 擋監控失能
    D6 sensor consistency : cmd、odom、scan 行為不一致          → 擋感測偽造

不直接發布 /cmd_vel；只發簽章 alert，由 velocity_guard 鎖住唯一 final
/cmd_vel 出口，其他 consumer 同步進入安全狀態。
"""
import math
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

from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer
from dds_security_monitor.test_fault_seam import ControlledGraphFaultSeam

from dds_security_monitor.constants import (
    CMD_VEL_ALLOWED_PUBS,
    IDS_ALERT_COOLDOWN_SEC,
    IDS_OSCILLATION_RATIO,
    IDS_PHYSICS_ANG_MAX,
    IDS_PHYSICS_LIN_MAX,
    IDS_SCAN_REPEAT_DIFF,
    IDS_VOTE_THRESHOLD,
    IMU_ALLOWED_PUBS,
    ODOM_ALLOWED_PUBS,
    SCAN_ALLOWED_PUBS,
)
from dds_security_monitor.monitor_node import (
    CH_ALERTS,
    CH_HEARTBEAT,
    ReplayCache,
    SECURITY_STATE_MONITOR_HEARTBEAT,
    _load_alert_secret,
    encode_security_state,
    hms,
    lock_sensitive_params,
    secret_fingerprint,
    sign_alert,
    verify_alert,
)


# ── 偵測門檻（保守值，避免誤判）─────────────────────────────────────
# Burger 規格：max linear 0.22 m/s, max angular 2.84 rad/s
# G5 修補：原本 0.50 留 50% buffer 過鬆，攻擊者灌 0.4 完全不會被抓
# G5→N9 修補：收緊到 0.23（剛好 burger spec 0.22 + 5% buffer），把 attacker safe zone
# 從 0.12-0.25 (13cm/s 範圍) 縮到 0.12-0.23 (11cm/s 範圍)
# 最終控制安全由 velocity guard 單一 writer + SROS2 ACL 負責；D1 是縱深偵測。
PHYSICS_LIN_MAX        = IDS_PHYSICS_LIN_MAX
PHYSICS_ANG_MAX        = IDS_PHYSICS_ANG_MAX
CMD_OSCILLATION_RATIO  = IDS_OSCILLATION_RATIO
SCAN_REPEAT_MAX_DIFF   = IDS_SCAN_REPEAT_DIFF
SCAN_MAX_POINTS        = 4096    # N24 修補：burger lidar=360；超過此數截斷，防超大 scan 記憶體/CPU 爆
HISTORY_LEN            = 20      # 滑動窗口長度
EVAL_PERIOD_SEC        = 0.5     # 評估頻率
ALERT_COOLDOWN_SEC     = IDS_ALERT_COOLDOWN_SEC
VOTE_THRESHOLD         = IDS_VOTE_THRESHOLD
HEARTBEAT_TIMEOUT_SEC  = 10.0    # G6: monitor 心跳 >10s 沒收到 → alert（monitor 被打掛）
HEARTBEAT_FAULT_REPEAT_SEC = 5.0 # 故障期間重送，讓晚啟動/重啟的 consumer 也會 fail-safe
DATA_FRESHNESS_SEC     = 2.0     # 不拿停止更新的舊 deque 反覆判定新事件
PUBLISHER_DETAIL_MAX   = 8       # endpoint flood 時只列前 N 個，避免 alert 膨脹
PUBLISHER_NAME_MAX     = 96


def _summarize_publishers(names) -> str:
    """Bound untrusted ROS graph names before putting them in signed alerts."""
    bounded = []
    for name in names[:PUBLISHER_DETAIL_MAX]:
        try:
            text = str(name)
        except Exception:
            text = f"<{type(name).__name__}>"
        text = "".join(ch if ch.isprintable() else "�" for ch in text)
        bounded.append(text[:PUBLISHER_NAME_MAX])
    extra = max(0, len(names) - len(bounded))
    suffix = f" (+{extra} more)" if extra else ""
    return f"{bounded}{suffix}"


class IntelligentDefenseNode(Node):
    """行為層 IDS — 系統的最後一道防線（防護堆疊 Layer 3）。

    六個偵測器（投票 ≥2 fire，D1/D4/D5 可作 strong signal 單獨 fire）：
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
        self._telemetry = RuntimeTelemetryProducer.from_environment(
            "intelligent_defense_node"
        )
        self._graph_fault_test_seam = ControlledGraphFaultSeam.from_environment(
            "ids", self._telemetry
        )
        self._detector_runtime_state = {
            detector: False
            for detector in ("D1", "D2", "D3", "D4", "D5", "D6")
        }

        # 滑動視窗
        self._cmd_history:  deque = deque(maxlen=HISTORY_LEN)
        self._scan_history: deque = deque(maxlen=HISTORY_LEN)
        self._odom_twist_history: deque = deque(maxlen=HISTORY_LEN)
        self._last_cmd_wall = -math.inf
        self._last_scan_wall = -math.inf
        self._last_odom_wall = -math.inf

        # 最後一次 alert 時間（cooldown）
        # 第一個高可信異常不能因主機剛開機、monotonic 尚小於 cooldown 而被吃掉。
        self._last_alert_time = -math.inf

        # 各 detector 累計觸發次數（telemetry）
        self._detector_hits = {"D1": 0, "D2": 0, "D3": 0, "D4": 0, "D5": 0, "D6": 0}

        # G6: monitor 心跳 watchdog
        self._startup_wall = time.monotonic()
        self._last_heartbeat_wall = 0.0
        self._heartbeat_alerted = False
        self._last_heartbeat_fault_emit = -math.inf

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

        # F1-b 修補：鎖 use_sim_time 等敏感參數，runtime 拒絕未授權竄改
        lock_sensitive_params(self)

        # 定時評估
        self.create_timer(EVAL_PERIOD_SEC, self._evaluate)

        # 5 秒印一次統計
        self.create_timer(5.0, self._print_stats)

        self.get_logger().info(
            f'🛡️ 智能防禦啟動 — voting threshold={VOTE_THRESHOLD}/6, '
            f'cooldown={ALERT_COOLDOWN_SEC:.0f}s, '
            f'monitor 心跳 timeout={HEARTBEAT_TIMEOUT_SEC:.0f}s'
        )

    # ── 訊息收集 ────────────────────────────────────────────────────

    def _scan_cb(self, msg: LaserScan):
        point_count = len(msg.ranges)
        # 先看長度再 slice，避免 list(msg.ranges) 在超大輸入上先複製整幀。
        ranges = list(msg.ranges[:SCAN_MAX_POINTS])
        # N24 修補：超大 scan（攻擊者灌數十萬點）截斷到 SCAN_MAX_POINTS，
        # 防 deque 累積巨量 list + D3/D6 numpy 在百萬點上爆記憶體/CPU。
        if point_count > SCAN_MAX_POINTS:
            self.get_logger().warn(
                f'⚠️ /scan 點數異常 {point_count}（>{SCAN_MAX_POINTS}）'
                f'→ 截斷（疑似 N24 超大 scan 攻擊）',
                throttle_duration_sec=5.0)
        if len(ranges) > 50:
            self._scan_history.append(ranges)
            self._last_scan_wall = time.monotonic()

    def _odom_cb(self, msg: Odometry):
        # 取實際線速度跟角速度（Gazebo diff_drive 受物理上限）
        self._odom_twist_history.append((msg.twist.twist.linear.x,
                                         msg.twist.twist.angular.z))
        self._last_odom_wall = time.monotonic()

    def _cmd_cb(self, msg: TwistStamped):
        self._cmd_history.append((msg.twist.linear.x, msg.twist.angular.z))
        self._last_cmd_wall = time.monotonic()

    def _hb_cb(self, msg: String):
        # G6 + N1 修補：驗章 + freshness(3s) + nonce-LRU 三重檢查。
        # max_age 故意比 alert 短：心跳每 2s 一筆，3s 視為過期。攻擊者頂多 replay 3s 後
        # 訊息變過期 → watchdog 不再被刷新 → D5 在 timeout 後 fire。
        payload = verify_alert(
            msg.data, self._secret,
            expected_channel=CH_HEARTBEAT,
            cache=self._hb_replay_cache,
            max_age=3.0,
            telemetry=getattr(self, "_telemetry", None),
        )
        if payload is None:
            self.get_logger().warn(
                f'⛔ 心跳驗證失敗（簽錯/重放/過期）— 拒絕',
                throttle_duration_sec=5.0)
            return
        self._last_heartbeat_wall = time.monotonic()
        if self._heartbeat_alerted:
            if self._emit_heartbeat_state(
                "clear", "收到新鮮且驗章成功的 monitor 心跳"
            ):
                self._heartbeat_alerted = False
                self.get_logger().info('💓 monitor 心跳恢復，已發布 authenticated clear')

    # ── D1–D6 detector ───────────────────────────────────────────────

    def _detect_d1_physics(self) -> tuple[bool, str]:
        """D1: cmd_vel 超出物理上限 → 攻擊 C 注入 100 m/s 必中"""
        if not self._cmd_history:
            return False, ""
        now = time.monotonic()
        if now - getattr(self, "_last_cmd_wall", now) > DATA_FRESHNESS_SEC:
            return False, ""
        recent = list(self._cmd_history)[-5:]
        if any(not math.isfinite(v) for sample in recent for v in sample):
            return True, "cmd_vel 含 NaN/Infinity（非有限控制值）"
        max_lin = max(abs(c[0]) for c in recent)
        max_ang = max(abs(c[1]) for c in recent)
        if max_lin > PHYSICS_LIN_MAX:
            return True, f"cmd_lin={max_lin:.2f}>{PHYSICS_LIN_MAX}"
        if max_ang > PHYSICS_ANG_MAX:
            return True, f"cmd_ang={max_ang:.2f}>{PHYSICS_ANG_MAX}"
        return False, ""

    def _detect_d2_oscillation(self) -> tuple[bool, str]:
        """D2: cmd_vel 方向衝突 → 攻擊 J namesake race（真假 patrol 競爭）

        改進版：不用「翻轉率」（會因不同頻率比例失效），改用「forward/backward 共存」
        正常 patrol 同一段時間內方向一致；攻擊者塞反向 → 兩個方向同時存在。
        """
        if len(self._cmd_history) < 10:
            return False, ""
        now = time.monotonic()
        if now - getattr(self, "_last_cmd_wall", now) > DATA_FRESHNESS_SEC:
            return False, ""
        hist = list(self._cmd_history)
        fwd = sum(1 for c in hist if c[0] > 0.01)
        bwd = sum(1 for c in hist if c[0] < -0.01)
        n   = len(hist)
        # 兩個方向各達門檻 → 行為衝突
        if (fwd / n >= CMD_OSCILLATION_RATIO
                and bwd / n >= CMD_OSCILLATION_RATIO):
            return True, f"fwd={fwd}/{n} + bwd={bwd}/{n}（方向衝突）"
        return False, ""

    @staticmethod
    def _safe_frame_diff(prev, cur) -> float:
        """兩幀 scan 的平均 |Δ|。N24b 修補：相鄰幀長度不同時取最短長度比較，
        避免 (len_a,) & (len_b,) 的 numpy broadcast ValueError 打掛 executor。"""
        a = np.asarray(cur,  dtype=np.float32)
        b = np.asarray(prev, dtype=np.float32)
        n = min(a.shape[0], b.shape[0])
        if n == 0:
            return 0.0
        a, b = a[:n], b[:n]
        mask = np.isfinite(a) & np.isfinite(b)
        if not mask.any():
            return 0.0
        return float(np.mean(np.abs(a[mask] - b[mask])))

    def _detect_d3_scan_repeat(self) -> tuple[bool, str]:
        """D3: scan 連續幀差異趨近 0 → 攻擊 K 偽造（重複 pattern）"""
        if len(self._scan_history) < 5:
            return False, ""
        now = time.monotonic()
        if now - getattr(self, "_last_scan_wall", now) > DATA_FRESHNESS_SEC:
            return False, ""
        hist = list(self._scan_history)[-5:]
        max_diff = 0.0
        for i in range(1, len(hist)):
            d = self._safe_frame_diff(hist[i-1], hist[i])
            if d > max_diff:
                max_diff = d
        # 真實 lidar 即使靜止也有 0.005~0.05 的雜訊
        if max_diff < SCAN_REPEAT_MAX_DIFF:
            return True, f"max_diff={max_diff:.4f}<{SCAN_REPEAT_MAX_DIFF}"
        return False, ""

    def _detect_d4_publishers(self) -> tuple[bool, str]:
        """D4: final /cmd_vel 必須只有 velocity_guard_node 一個 publisher。

        G2 修補：原版完全信任 node_name 白名單，攻擊者把自己命名為
        `patrol_node` 或 `teleop_keyboard` 即可通過。改為「同時 publisher 數量」檢測：
            - /cmd_vel 缺少、同時 ≥ 2 個或名稱不是 velocity_guard_node → hijack/fail
            - /scan 同時 ≥ 2 個 → spoof
        合法控制器只寫 /cmd_vel/{patrol,nav2,tqc}，guard 仲裁後才寫 final topic。
        Name 白名單仍保留為次要檢查（catch 攻擊者用了未列名的 process）。
        """
        # N11/N22：/odom、/imu 也納入監控；白名單集中在 constants.py。
        def is_unknown(name: str) -> bool:
            return name == "_NODE_NAME_UNKNOWN_"
        try:
            seam = getattr(self, "_graph_fault_test_seam", None)
            if seam is not None and seam.consume_if_armed():
                raise RuntimeError("controlled one-shot D4 graph inspection fault")
            cmd_pubs  = self.get_publishers_info_by_topic('/cmd_vel')
            scan_pubs = self.get_publishers_info_by_topic('/scan')
            odom_pubs = self.get_publishers_info_by_topic('/odom')
            imu_pubs  = self.get_publishers_info_by_topic('/imu')
        except Exception:
            # Graph inspection is a strong safety detector.  Treat loss of the
            # detector itself as a bounded fault instead of silently declaring
            # the publisher topology healthy.
            return True, "ROS graph inspection unavailable"
        seam = getattr(self, "_graph_fault_test_seam", None)
        if seam is not None:
            seam.record_normal_graph()

        # 非 ROS DDS participant 常以 _NODE_NAME_UNKNOWN_ 出現；這正是 raw DDS
        # injector 的典型形態，不能當作 benign 後直接從名稱與數量檢查排除。
        unknown_topics = [
            topic for topic, pubs in (
                ("/cmd_vel", cmd_pubs),
                ("/scan", scan_pubs),
                ("/odom", odom_pubs),
                ("/imu", imu_pubs),
            )
            if any(is_unknown(p.node_name) for p in pubs)
        ]
        if unknown_topics:
            return True, f"unknown DDS publisher on {unknown_topics}"

        # ── (a) 名字檢查（次要）─────────
        cmd_bad  = [p.node_name for p in cmd_pubs
                    if p.node_name not in CMD_VEL_ALLOWED_PUBS]
        scan_bad = [p.node_name for p in scan_pubs
                    if p.node_name not in SCAN_ALLOWED_PUBS]
        odom_bad = [p.node_name for p in odom_pubs
                    if p.node_name not in ODOM_ALLOWED_PUBS]
        imu_bad  = [p.node_name for p in imu_pubs
                    if p.node_name not in IMU_ALLOWED_PUBS]
        if cmd_bad:
            return True, f"cmd unauthorized pub: {_summarize_publishers(cmd_bad)}"
        if scan_bad:
            return True, f"scan unauthorized pub: {_summarize_publishers(scan_bad)}"
        if odom_bad:
            return True, f"odom unauthorized pub: {_summarize_publishers(odom_bad)}"
        if imu_bad:
            return True, f"imu unauthorized pub: {_summarize_publishers(imu_bad)}"

        # ── (b) 計數檢查（主要 — 防同名冒充 G2 + N11 odom spoof + N22 imu spoof）─────────
        if (
            len(cmd_pubs) == 0
            and time.monotonic() - getattr(self, "_startup_wall", 0.0) > 5.0
        ):
            return True, "final cmd_vel 缺少 velocity_guard_node publisher"
        if len(cmd_pubs) >= 2:
            return True, (
                f"final cmd 同時 {len(cmd_pubs)} 個 publisher: "
                f"{_summarize_publishers([p.node_name for p in cmd_pubs])}"
                "（hijack/同名冒充）")
        real_scan = [p.node_name for p in scan_pubs]
        if len(real_scan) >= 2:
            return True, (
                f"scan 同時 {len(real_scan)} 個 publisher: "
                f"{_summarize_publishers(real_scan)}（spoof）")
        real_odom = [p.node_name for p in odom_pubs]
        if len(real_odom) >= 2:
            return True, (
                f"odom 同時 {len(real_odom)} 個 publisher: "
                f"{_summarize_publishers(real_odom)}（spoof）")
        real_imu = [p.node_name for p in imu_pubs]
        if len(real_imu) >= 2:
            return True, (
                f"imu 同時 {len(real_imu)} 個 publisher: "
                f"{_summarize_publishers(real_imu)}（N22 spoof）")
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
        now = time.monotonic()
        stream_ages = {
            "odom": now - getattr(self, "_last_odom_wall", now),
            "scan": now - getattr(self, "_last_scan_wall", now),
        }
        if self._cmd_history:
            stream_ages["cmd_vel"] = (
                now - getattr(self, "_last_cmd_wall", now)
            )
        stale = sorted(
            name for name, age in stream_ages.items()
            if age > DATA_FRESHNESS_SEC
        )
        if stale:
            return True, (
                f"資料流超過 {DATA_FRESHNESS_SEC:.1f}s 未更新: {stale}"
            )
        # (a) odom 顯示有移動 + scan 完全靜止 → 不一致
        recent_twist = list(self._odom_twist_history)[-10:]
        if any(not math.isfinite(v) for sample in recent_twist for v in sample):
            return True, "odom twist 含 NaN/Infinity（感測資料無效）"
        avg_lin = float(np.mean([abs(t[0]) for t in recent_twist]))
        if avg_lin > 0.05:
            hist = list(self._scan_history)[-3:]
            max_diff = 0.0
            for i in range(1, len(hist)):
                max_diff = max(max_diff, self._safe_frame_diff(hist[i-1], hist[i]))
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

    def _heartbeat_gap_sec(self) -> float:
        now = time.monotonic()
        if getattr(self, "_last_heartbeat_wall", 0.0) <= 0.0:
            gap = now - getattr(self, "_startup_wall", now)
        else:
            gap = now - self._last_heartbeat_wall
        return min(300.0, max(0.0, float(gap)))

    def _record_detector_transition(self, detector: str, active: bool) -> None:
        states = getattr(self, "_detector_runtime_state", None)
        if states is None:
            states = {
                name: False
                for name in ("D1", "D2", "D3", "D4", "D5", "D6")
            }
            self._detector_runtime_state = states
        if states.get(detector, False) == active:
            return
        states[detector] = active
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is None:
            return
        try:
            telemetry.emit_detector_state(
                detector.lower(), "incident" if active else "recovery"
            )
            if detector == "D5":
                telemetry.emit_heartbeat_state(
                    "gap" if active else "recovery",
                    IntelligentDefenseNode._heartbeat_gap_sec(self),
                )
        except Exception:
            pass

    def _detector_recovery_observable(self, detector: str) -> bool:
        """Do not call missing/stale data a recovery from an incident."""
        now = time.monotonic()
        if detector == "D1":
            return bool(getattr(self, "_cmd_history", ())) and (
                now - getattr(self, "_last_cmd_wall", -math.inf)
                <= DATA_FRESHNESS_SEC
            )
        if detector == "D2":
            return len(getattr(self, "_cmd_history", ())) >= 10 and (
                now - getattr(self, "_last_cmd_wall", -math.inf)
                <= DATA_FRESHNESS_SEC
            )
        if detector == "D3":
            return len(getattr(self, "_scan_history", ())) >= 5 and (
                now - getattr(self, "_last_scan_wall", -math.inf)
                <= DATA_FRESHNESS_SEC
            )
        if detector == "D6":
            return (
                len(getattr(self, "_odom_twist_history", ())) >= 10
                and len(getattr(self, "_scan_history", ())) >= 5
            )
        return True

    def _check_heartbeat(self) -> tuple[bool, str]:
        """G6: monitor 心跳 watchdog — 超時表示 monitor 被打掛或被隔離"""
        # 啟動初期還沒收到第一次心跳，只給固定 grace；不能永遠略過，
        # 否則 monitor 比 IDS 早已死亡／根本未啟動時 D5 永遠不會 fire。
        if self._last_heartbeat_wall == 0.0:
            gap = time.monotonic() - self._startup_wall
            if gap > HEARTBEAT_TIMEOUT_SEC:
                return True, (
                    f"啟動後 {gap:.1f}s 從未收到 monitor 心跳 "
                    f"(>{HEARTBEAT_TIMEOUT_SEC:.0f}s)")
            return False, ""
        gap = time.monotonic() - self._last_heartbeat_wall
        if gap > HEARTBEAT_TIMEOUT_SEC:
            return True, f"monitor 心跳已 {gap:.1f}s 未到達 (>{HEARTBEAT_TIMEOUT_SEC:.0f}s)"
        return False, ""

    def _evaluate(self):
        votes = []
        details = []
        strong = False    # D1/D4/D5 為策略上允許單獨觸發的訊號
        for did, fn in [
            ("D1", self._detect_d1_physics),
            ("D2", self._detect_d2_oscillation),
            ("D3", self._detect_d3_scan_repeat),
            ("D4", self._detect_d4_publishers),
            ("D5", self._check_heartbeat),
            ("D6", self._detect_d6_scan_odom_consistency),
        ]:
            try:
                triggered, info = fn()
            except Exception as e:
                # N24b 防禦：單一 detector 的例外不能打死整條行為層防線——
                # 隔離後本輪跳過該 detector，其餘 detector 照常投票。
                self.get_logger().error(f"⚠️ {did} detector 例外，本輪跳過（未影響其他偵測器）: {e!r}")
                continue
            was_active = getattr(
                self, "_detector_runtime_state", {}
            ).get(did, False)
            if (
                triggered
                or not was_active
                or IntelligentDefenseNode._detector_recovery_observable(
                    self, did
                )
            ):
                IntelligentDefenseNode._record_detector_transition(
                    self, did, triggered
                )
            if triggered:
                votes.append(did)
                details.append(f"{did}[{info}]")
                self._detector_hits[did] += 1
                if did in ("D1", "D4", "D5"):
                    strong = True

        # D5 使用 machine-readable fault/clear 狀態，故障期間低頻重送。
        # 不能只發一次：consumer 若在 outage 中重啟，VOLATILE topic 會漏掉舊警報。
        if "D5" in votes:
            now = time.monotonic()
            d5_detail = next(
                (d[3:-1] for d in details if d.startswith("D5[")),
                "monitor heartbeat unavailable",
            )
            if now - self._last_heartbeat_fault_emit >= HEARTBEAT_FAULT_REPEAT_SEC:
                if self._emit_heartbeat_state("fault", d5_detail):
                    self._heartbeat_alerted = True
                    self._last_heartbeat_fault_emit = now
            votes.remove("D5")
            details = [d for d in details if not d.startswith("D5[")]
            strong = any(v in ("D1", "D4") for v in votes)

        if len(votes) >= VOTE_THRESHOLD or strong:
            now = time.monotonic()
            if now - self._last_alert_time < ALERT_COOLDOWN_SEC:
                self.get_logger().warn(
                    f'⏳ 異常持續 ({", ".join(votes)})，cooldown 中（剩 '
                    f'{ALERT_COOLDOWN_SEC - (now - self._last_alert_time):.1f}s）'
                )
                return
            reason = "vote" if len(votes) >= VOTE_THRESHOLD else "strong"
            if not self._emit_alert(votes, details, reason):
                return
            # 只有 publish 成功才消耗一般 detector cooldown；否則下輪重試。
            self._last_alert_time = now
        elif len(votes) == 1:
            self.get_logger().warn(
                f"⚠️ 單一 detector 警告: {details[0]}（未達投票門檻 {VOTE_THRESHOLD}，繼續觀察）"
            )

    def _emit_heartbeat_state(self, state: str, detail: str) -> bool:
        """Publish D5 fault/clear as a signed, strict state-machine event."""
        try:
            payload = encode_security_state(
                SECURITY_STATE_MONITOR_HEARTBEAT,
                state,
                detail,
            )
            msg = String()
            msg.data = sign_alert(payload, self._secret, channel=CH_ALERTS)
            self._alert_pub.publish(msg)
        except Exception as exc:
            self.get_logger().error(
                f"⛔ D5 {state} 狀態發布失敗，稍後重試：{exc!r}"
            )
            return False
        self.get_logger().error(
            f"🛡️ D5 monitor heartbeat state={state}: {detail}"
        )
        return True

    def _emit_alert(self, votes, details, reason="vote"):
        header = (f"vote={len(votes)}/6 >= {VOTE_THRESHOLD}" if reason == "vote"
                  else "single-trigger policy signal (D1 physics / D4 publisher)")
        text = (
            f"🛡️ [智能防禦警報] [{hms()}]\n"
            f"行為層異常偵測 ({header}):\n"
            + "\n".join(f"  • {d}" for d in details)
        )
        try:
            signed = sign_alert(text, self._secret, channel=CH_ALERTS)
            msg = String()
            msg.data = signed
            self._alert_pub.publish(msg)
        except Exception as exc:
            # Graph/endpoint flood must not turn a diagnostic string into an
            # exception that kills the timer callback and disables all IDS rules.
            self.get_logger().error(
                f"⛔ IDS alert serialization/publish failed; will retry: {exc!r}")
            return False
        self.get_logger().error(text)
        return True

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

    def destroy_node(self):
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is not None:
            telemetry.close()
        return super().destroy_node()


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
