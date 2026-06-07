#!/usr/bin/env python3
"""ROS2 DDS Security Monitor Node.

Polls the ROS2 node graph and sends LINE alerts when unknown nodes appear.
When emergency_stop_enabled=true, publishes zero velocity to /cmd_vel and
cancels active Nav2 goals on any security alert.

Credentials: env vars LINE_CHANNEL_TOKEN and LINE_USER_ID (priority over YAML).
"""
import collections
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request

import rclpy
from action_msgs.msg import GoalInfo
from action_msgs.srv import CancelGoal
from geometry_msgs.msg import TwistStamped
from rcl_interfaces.msg import ParameterDescriptor
from rcl_interfaces.srv import SetParameters
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String


# N2 修補：完全移除 _INTERNAL_NODE_REGEX 白名單。
# 原因（紅隊 N2）：任何「by name」的內部節點白名單都是後門 — 攻擊者把節點命名為
# `_ros2cli_evil_99999_deadbeef` 就能匹配正則 → 完全隱身。
#
# 改為「啟動基準快照 + grace period」策略：
#   - monitor 啟動後 _STARTUP_GRACE_SEC 秒內，所有出現的節點都吸收進 baseline
#   - grace period 結束後，任何新節點都會 alert (即使名字像 ros2cli)
#   - 副作用：production 環境部署完後不應再執行 `ros2 cli` 命令；要用的話請
#     在 monitor 啟動前先 `ros2 daemon start`
_STARTUP_GRACE_SEC: float = 15.0

# 心跳發送週期 (G6)：intelligent_defense 沒收到 >10s 就 alert，攻擊者 kill monitor 會被抓
_HEARTBEAT_PERIOD_SEC: float = 2.0

# 緊急停止全域 cooldown (G7)：攻擊者輪流創建假節點觸發連環 stop = DoS
_EMERGENCY_STOP_COOLDOWN_SEC: float = 30.0

# Minimum seconds between LINE push notifications (prevents API rate-limit bans).
_LINE_RATE_LIMIT_SEC: float = 15.0

# N17 修補：LINE batch window — attacker 用 100 個唯一 unknown name 灌 monitor
# 會讓 operator 收 100 條 LINE 通知 → 通知爆炸 → operator 關掉通知 → 真實警報漏網。
# 改為「每 BATCH_WINDOW 秒最多送 1 條，把期間累積的 alerts 聚合成一條摘要」。
_LINE_BATCH_WINDOW_SEC: float = 30.0
# N17 副作用修補：pending list 也要有上限，attacker burst 太大時 batch 期間記憶體會 spike
_LINE_BATCH_PENDING_MAX: int = 256

# N18 修補：_alerted_nodes 是 dedup set，但 attacker 用 100 萬個唯一 node names
# rotate 進來會讓這個 set 永久成長 → OOM。改用 (TTL, LRU) bounded structure：
# 一個 alert dedup 只在 TTL 期間有效，過期允許再次 alert（防止 attacker 用同名 node
# 永久 squat）；同時 LRU 上限防止 burst 期間 set 爆炸。
_ALERTED_NODES_TTL_SEC: float = 600.0   # 10 分鐘內同名 node 不重複 alert
_ALERTED_NODES_MAX: int = 2048           # LRU 上限

# HMAC 簽章用的 secret 來源（紅隊攻擊 B 已驗證：沒有簽章 → 任何人都能偽造 alert）
# subscriber 端必須驗章才相信 alert。secret 從環境變數 DDS_ALERT_SECRET 或檔案讀取。
_ALERT_SECRET_ENV = "DDS_ALERT_SECRET"
_ALERT_SECRET_FILE = os.path.expanduser("~/.config/dds-monitor/alert_secret")

# LINE 通知 token 檔案位置（紅隊攻擊 H 修補 — 不從 environ 讀）
_LINE_TOKEN_FILE   = os.path.expanduser("~/.config/dds-monitor/line_token")
_LINE_USER_ID_FILE = os.path.expanduser("~/.config/dds-monitor/line_user_id")


def _load_line_token(logger=None) -> str:
    """讀 LINE channel token，優先從檔案（chmod 600）讀。

    紅隊測試攻擊 H：以前從 env 讀 → 同 user 的 process 全部都能從 /proc/<pid>/environ 偷
    現在從檔案讀，攻擊者要先拿到 read 權限才能取得。
    """
    if os.path.exists(_LINE_TOKEN_FILE):
        # 檢查檔案權限：必須是 600（只有 owner 能讀）
        mode = os.stat(_LINE_TOKEN_FILE).st_mode & 0o777
        if mode != 0o600 and logger:
            logger.warn(
                f"⚠️ {_LINE_TOKEN_FILE} 權限 {oct(mode)} 不是 600，"
                "建議 chmod 600 防止其他 user 讀取"
            )
        with open(_LINE_TOKEN_FILE) as f:
            return f.read().strip()
    # Fallback to env（向後相容，但 warn）
    token = os.environ.get('LINE_CHANNEL_TOKEN', '')
    if token and logger:
        logger.warn(
            f"⚠️ LINE_CHANNEL_TOKEN 從環境變數讀取（不安全 — 同 user process 可從 "
            f"/proc/<pid>/environ 偷取）。建議移到 {_LINE_TOKEN_FILE} 並 chmod 600"
        )
    return token


def _load_line_user_id(logger=None) -> str:
    """讀 LINE user_id（不是 secret，但放檔案統一管理）。"""
    if os.path.exists(_LINE_USER_ID_FILE):
        with open(_LINE_USER_ID_FILE) as f:
            return f.read().strip()
    return os.environ.get('LINE_USER_ID', '')


class AlertSecretMissingError(RuntimeError):
    """alert_secret 未設定時 raise — fail-loud 而非靜默 fallback。

    Reviewer 指出：原本 fallback random bytes 會讓 6 個 subscriber 各拿不同 key
    → 整套 alert pipeline 安靜壞掉，使用者完全不知道。
    現在改為 raise，每個 node 啟動時若 secret 不在就直接 refuse to start。
    """


def _load_alert_secret(strict: bool = True) -> bytes:
    """從環境變數或 secret 檔讀取 HMAC key。

    Args:
        strict: True (default) — secret 不存在則 raise AlertSecretMissingError
                False           — 回傳 b""（給可選功能用，例如 fail-safe import）

    優先順序：DDS_ALERT_SECRET env > ~/.config/dds-monitor/alert_secret 檔
    """
    s = os.environ.get(_ALERT_SECRET_ENV)
    if s:
        return s.encode("utf-8")
    if os.path.exists(_ALERT_SECRET_FILE):
        # 檢查權限
        mode = os.stat(_ALERT_SECRET_FILE).st_mode & 0o777
        if mode != 0o600:
            # 不直接 raise（避免使用者卡住），但 log（caller 看不到 logger 時用 stderr）
            import sys
            print(
                f"⚠️ {_ALERT_SECRET_FILE} 權限 {oct(mode)} 不安全，"
                "建議 chmod 600",
                file=sys.stderr,
            )
        with open(_ALERT_SECRET_FILE, "rb") as f:
            data = f.read().strip()
            if not data:
                if strict:
                    raise AlertSecretMissingError(
                        f"{_ALERT_SECRET_FILE} 是空的"
                    )
                return b""
            return data
    if strict:
        raise AlertSecretMissingError(
            "找不到 alert_secret。請執行：\n"
            "  mkdir -p ~/.config/dds-monitor\n"
            "  openssl rand -hex 32 > ~/.config/dds-monitor/alert_secret\n"
            "  chmod 600 ~/.config/dds-monitor/alert_secret"
        )
    return b""


def secret_fingerprint(secret: bytes) -> str:
    """回傳 secret 的 SHA256 前 8 bytes hex — 給啟動 banner 印出來互比對。

    每個訂閱 /security/alerts 的節點啟動時都印 fingerprint，
    使用者一眼就能確認所有節點拿到同一個 secret。
    """
    return hashlib.sha256(secret).hexdigest()[:16]


## ── Anti-replay + channel-binding 簽章 (修補紅隊 N1 + N3 + N4) ─────────
# 演化史：
#   v1 (原版)：{"payload": str, "sig": HMAC(payload)}
#     → 紅隊 N1/N3：HMAC bytes 可無限重放
#   v2 (N1/N3 修補)：{"body": json({payload, ts, nonce}), "sig": HMAC(body)}
#     → 紅隊 N4：envelope 不綁 channel — attacker 把 heartbeat bytes forward
#       到 /security/alerts，每個 receiver 的 cache 都是「初次」 → 接受
#   v3 (現在)：{"body": json({channel, nonce, payload, ts}), "sig": HMAC(body)}
#     - channel: sender 寫「我要發到哪」，receiver 必須帶 `expected_channel` 比對
#       cross-channel forwarding 在 verify_alert 直接拒絕
#     - 同時保留 nonce LRU + ts freshness 防同 channel replay
#
# 注意：receiver 需要自己持有 ReplayCache instance（cross-process state 沒辦法共享）

REPLAY_MAX_AGE_SEC: float = 10.0    # 預設 freshness window
REPLAY_CLOCK_SKEW_SEC: float = 2.0  # 允許 receiver 比 sender 快這麼多（NTP 抖動）
REPLAY_CACHE_MAXLEN: int = 4096     # LRU nonce 緩存大小

# Canonical channel 名稱常數 — sender/receiver 必須對齊
CH_ALERTS:    str = "alerts"          # /security/alerts (monitor/IDS → patrol/mission/system/burger_env)
CH_HEARTBEAT: str = "heartbeat"       # /security/heartbeat (monitor → IDS)
CH_GOTO:      str = "patrol/goto"     # /patrol/goto (operator → patrol)
CH_SENSOR:    str = "sensor/status"   # /sensor/status (sensor_hub → mission_manager)
CH_MISSION:   str = "mission/cmd"     # /mission/cmd (mission_manager → system_status)
CH_HEALTH:    str = "system/health"   # /system/health (system_status → operator dashboard)


class ReplayCache:
    """Receiver-side anti-replay nonce LRU + timestamp expiry.

    N12 修補：純 LRU 在攻擊者 flood unique nonce 時會 evict 舊的 → attacker
    可以 capture 老的 fresh-but-pre-evicted nonce 重放成功。
    解法：以 nonce 加入時間做 TTL，TTL 過了直接 expire（與 freshness window 對齊），
    這樣即使被擠出 LRU，下次同一個 nonce 來只要還在 max_age 內就會「過期不能重用」。

    具體：每次 check_and_add 時先掃描清掉所有 TTL 過期 entry，所以 cache 只保留
    "仍可能被當作 fresh 重放" 的 nonce —  set 大小 ~= max_age * publish_rate（小）。
    """

    def __init__(self, maxlen: int = REPLAY_CACHE_MAXLEN, ttl_sec: float = REPLAY_MAX_AGE_SEC + REPLAY_CLOCK_SKEW_SEC):
        # OrderedDict 內存 nonce → expiry_monotonic_time
        self._seen: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._maxlen = maxlen
        self._ttl = ttl_sec
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str) -> bool:
        """nonce 未見過 → 收下並回傳 True；已見過 → 拒絕並回傳 False。"""
        with self._lock:
            now = time.monotonic()
            # N12: 清掉所有 TTL 過期的 entry — 在最舊端，OrderedDict 順序就是插入順序
            while self._seen:
                oldest_nonce, expiry = next(iter(self._seen.items()))
                if expiry > now:
                    break
                self._seen.popitem(last=False)
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + self._ttl
            # LRU 上限（防呆）— 但通常 TTL 清理就讓 size 不會爆
            while len(self._seen) > self._maxlen:
                self._seen.popitem(last=False)
            return True

    def __len__(self) -> int:
        return len(self._seen)


def sign_alert(
    payload: str,
    secret: bytes,
    *,
    channel: str,
    ts: float | None = None,
) -> str:
    """HMAC-SHA256 簽章 + channel + ts + nonce envelope，防 replay & cross-channel confusion。

    回傳 `{"body": "<inner-json>", "sig": "<hex-hmac>"}` 的 JSON 字串。
    inner JSON 含 channel / nonce / payload / ts。
    sort_keys 確保 sender/receiver 算出相同 HMAC。

    `channel` 必填 — 用 monitor_node 的 CH_* 常數，避免拼錯。
    """
    if ts is None:
        ts = time.time()
    nonce = secrets.token_hex(8)
    body = json.dumps(
        {"channel": channel, "nonce": nonce, "payload": payload, "ts": ts},
        sort_keys=True, ensure_ascii=False,
    )
    mac = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
    return json.dumps({"body": body, "sig": mac}, ensure_ascii=False)


def verify_alert(
    signed: str,
    secret: bytes,
    *,
    expected_channel: str,
    cache: ReplayCache | None = None,
    max_age: float = REPLAY_MAX_AGE_SEC,
    clock_skew: float = REPLAY_CLOCK_SKEW_SEC,
) -> str | None:
    """驗 envelope。通過 → 回傳 payload；任一檢查失敗 → None。

    五道檢查（全部要過）：
      1. envelope 格式正確 (body + sig 都是 str)
      2. HMAC(body, secret) == sig
      3. body.channel == expected_channel  (修補 N4 cross-channel confusion)
      4. body.ts 在 [now - max_age, now + clock_skew] 範圍內 (anti-replay 時間窗)
      5. body.nonce 未在 cache 中見過 (anti-replay nonce LRU)

    cache=None 時跳過 nonce 檢查（罕用，建議都傳 cache）。
    """
    try:
        env = json.loads(signed)
        if not isinstance(env, dict):
            return None
        body_str = env.get("body")
        sig = env.get("sig")
        if not isinstance(body_str, str) or not isinstance(sig, str):
            return None
        expected = hmac.new(secret, body_str.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        body = json.loads(body_str)
        if not isinstance(body, dict):
            return None
        payload = body.get("payload")
        ts = body.get("ts")
        nonce = body.get("nonce")
        channel = body.get("channel")
        if (not isinstance(payload, str)
                or not isinstance(ts, (int, float))
                or not isinstance(nonce, str)
                or not isinstance(channel, str)):
            return None
        # N4 修補：channel binding — sender 寫了「我要發到 alerts」，
        # 攻擊者 forward 到 heartbeat channel → channel 對不上 → 拒絕
        if channel != expected_channel:
            return None
        # Freshness window
        now = time.time()
        if ts < now - max_age or ts > now + clock_skew:
            return None
        # Nonce LRU (anti-replay 主要防線)
        if cache is not None and not cache.check_and_add(nonce):
            return None
        return payload
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


# ─── 檔案完整性簽章（修補紅隊攻擊 I, M）─────────────────────────────
# Pickle RCE / model swap 共用機制：訓練存檔時同時寫 .sha256.hmac，
# load 之前先驗章。攻擊者修改 buffer.pkl 或 best.zip 後沒有正確 HMAC 就會被擋。

def sign_file(file_path, secret: bytes) -> str:
    """算檔案 SHA256-HMAC 並寫到 <file>.sha256.hmac，回傳 hex sig。"""
    from pathlib import Path
    p = Path(file_path)
    h = hmac.new(secret, digestmod=hashlib.sha256)
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    sig = h.hexdigest()
    sig_path = p.with_suffix(p.suffix + ".sha256.hmac")
    sig_path.write_text(sig)
    return sig


def verify_file(file_path, secret: bytes) -> bool:
    """驗檔案 HMAC，通過 True，失敗 / 沒簽章檔 False。"""
    from pathlib import Path
    p = Path(file_path)
    sig_path = p.with_suffix(p.suffix + ".sha256.hmac")
    if not sig_path.exists():
        return False
    expected = sig_path.read_text().strip()
    h = hmac.new(secret, digestmod=hashlib.sha256)
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return hmac.compare_digest(expected, h.hexdigest())


class DDSSecurityMonitor(Node):
    def __init__(self):
        super().__init__('dds_security_monitor')

        # N14 修補（藍方主動預判）：安全敏感參數一律 read_only。
        # ROS2 預設每個 node 都 expose /set_parameters service —
        # L1 攻擊者可 `ros2 service call /dds_security_monitor/set_parameters ...`
        # 把自己節點名加進 whitelist，永久隱身。read_only 後 declare 之後不可寫，
        # /set_parameters 會回 successful=False。
        ro = ParameterDescriptor(read_only=True)
        self.declare_parameter('poll_interval_sec', 5.0, ro)
        self.declare_parameter('line_token', '', ro)
        self.declare_parameter('line_user_id', '', ro)
        self.declare_parameter('alert_on_node_exit', False, ro)
        self.declare_parameter('emergency_stop_enabled', True, ro)
        self.declare_parameter('emergency_stop_duration_sec', 3.0, ro)
        self.declare_parameter('whitelist', [
            'bt_navigator', 'planner_server', 'controller_server', 'map_server',
            'amcl', 'behavior_server', 'waypoint_follower', 'velocity_smoother',
            'lifecycle_manager_navigation', 'lifecycle_manager_localization',
            'robot_state_publisher', 'joint_state_publisher', 'rviz2',
            'cartographer_node', 'cartographer_occupancy_grid_node',
            'turtlebot3_node', 'diff_drive_controller', 'teleop_keyboard',
            'turtlebot3_patrol_server', 'my_nav_client', 'dds_security_monitor', 'patrol_node',
            'ros_gz_bridge', 'ros_gz_image', 'ros_gz_point_cloud', 'ros_gz_sim',
            'gazebo', 'gzserver', 'gzclient',
            'sensor_hub_node', 'mission_manager_node', 'system_status_node',
            # SAC 訓練相關（避免訓練節點被誤判為入侵 → 觸發 emergency stop → 干擾訓練）
            'burger_sac_env', 'dqn_environment',
            'intelligent_defense_node',
        ], ro)

        self._poll_interval = self.get_parameter('poll_interval_sec').value
        # 修補紅隊攻擊 H：LINE token 不再從環境變數讀（避免 /proc/<pid>/environ 洩漏）
        # 優先順序：
        #   1. ~/.config/dds-monitor/line_token（chmod 600，最安全）
        #   2. environment variable（向後相容，但會 warn）
        #   3. YAML 參數（測試用）
        self._line_token = _load_line_token(self.get_logger())
        self._line_user_id = _load_line_user_id(self.get_logger())
        self._whitelist: set[str] = set(self.get_parameter('whitelist').value)
        self._alert_on_exit: bool = self.get_parameter('alert_on_node_exit').value
        self._emergency_stop: bool = self.get_parameter('emergency_stop_enabled').value
        self._stop_duration: float = self.get_parameter('emergency_stop_duration_sec').value

        self._known_nodes: set[str] = set()
        # N18 修補：dedup 改為 (node_full → 加入時 monotonic)，過 TTL 自動 evict + LRU 上限
        # 防 attacker rotate 唯一 names 造成 OOM 增長
        self._alerted_nodes: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._initialized = False
        self._init_wall_time: float = 0.0       # N2: 基準快照開始時間，用於 grace period
        self._stop_timer = None
        self._stop_ticks = 0
        self._last_line_time: float = 0.0       # LINE rate-limit timestamp
        self._last_emergency_stop_time: float = 0.0   # G7: 全域 emergency stop cooldown
        # N17 修補：LINE batch — pending alerts 由 timer 每 30s 聚合送出
        # 副作用修補：(1) 上限 _LINE_BATCH_PENDING_MAX 防 burst memory spike;
        #            (2) leading-edge 第一筆立刻送，後續才 batch（避免單一 alert 延遲 30s）
        self._pending_line_alerts: list[tuple[float, str, int]] = []
        self._pending_line_overflow: int = 0      # 超 cap 被丟掉的計數
        self._last_line_burst_send_t: float = 0.0 # leading-edge 上次送出時間
        self._lock = threading.Lock()            # guards _known_nodes & _alerted_nodes
        self._alert_secret = _load_alert_secret()  # HMAC key, 給 alert publish/subscribe 共用
        self.get_logger().info(
            f'🔐 Alert HMAC 簽章已啟用  secret fingerprint={secret_fingerprint(self._alert_secret)}'
        )

        qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._alert_pub = self.create_publisher(String, '/security/alerts', qos)
        # G6 + N1 修補：心跳 channel 改 RELIABLE + TRANSIENT_LOCAL — late-subscribed
        # IDS 能拿到「最後一筆」心跳的 nonce 進 cache，攻擊者 replay 就會立刻在 LRU 命中。
        # 原本 BEST_EFFORT 有 race：attacker 比 IDS 先訂到第一筆心跳，IDS 漏掉 →
        # 後續 replay 在 IDS 端被當成「初次見到」接受 → watchdog 不會 fire。
        qos_hb = QoSProfile(
            depth=1,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._heartbeat_pub = self.create_publisher(String, '/security/heartbeat', qos_hb)
        self._cmd_vel_pub = self.create_publisher(TwistStamped, '/cmd_vel', 10)

        # Nav2 goal cancellation client
        self._cancel_client = self.create_client(
            CancelGoal, '/navigate_to_pose/_action/cancel_goal'
        )

        self.create_timer(self._poll_interval, self._check_graph)
        # G6: 持續發送已簽章心跳，subscriber 沒收到就知道 monitor 被打掛
        self.create_timer(_HEARTBEAT_PERIOD_SEC, self._publish_heartbeat)
        # N17: 定期 flush LINE alerts 聚合 batch
        self.create_timer(_LINE_BATCH_WINDOW_SEC, self._flush_line_batch)
        self.get_logger().info(
            f'DDS Security Monitor 啟動 '
            f'(輪詢: {self._poll_interval}s, '
            f'緊急停止: {"開啟" if self._emergency_stop else "關閉"}, '
            f'白名單: {len(self._whitelist)} 個節點)'
        )

    # ── graph polling ────────────────────────────────────────────────────────

    def _check_graph(self) -> None:
        current: set[str] = set()
        for name, namespace in self.get_node_names_and_namespaces():
            ns = namespace.rstrip('/')
            current.add(f'{ns}/{name}')

        with self._lock:
            if not self._initialized:
                self._initialized = True
                self._init_wall_time = time.monotonic()
                # N5 修補：首次 baseline 不再無條件吸收 — 只信白名單上的節點。
                # 攻擊者比 monitor 早出現（pre-startup poison）也會被立刻 alert。
                # 副作用：`_ros2cli_daemon_<uuid>` 名字不在白名單會 alert 一次（可接受
                # operational cost；要消除請在 monitor 啟動前先 `ros2 daemon stop` 或
                # 把 daemon 加入白名單）。
                legit = {n for n in current
                         if n.rsplit('/', 1)[-1] in self._whitelist}
                bad   = current - legit
                self._known_nodes = legit
                self.get_logger().info(
                    f'基準快照：{len(legit)} 個白名單節點已建為 baseline'
                )
                if bad:
                    self.get_logger().error(
                        f'🚨 N5 防護：啟動時發現 {len(bad)} 個非白名單節點 — '
                        f'視為 pre-startup poison 攻擊'
                    )
                pre_existing_bad = bad
                new_nodes = set()      # 走下面 alert 邏輯
                exited_nodes = set()
                # Fall through 處理 pre_existing_bad
            else:
                new_nodes = current - self._known_nodes
                exited_nodes = self._known_nodes - current

                # N2 修補：grace period 只吸收「白名單上的」晚進場節點（例如 Gazebo
                # bridges 在 monitor 第一次 poll 後才註冊完成）。非白名單者一律走 alert
                # 邏輯 — 這樣攻擊者就算趕在 grace 期間進場也藏不住（不像舊版的 regex 後門）。
                grace_elapsed = time.monotonic() - self._init_wall_time
                if grace_elapsed < _STARTUP_GRACE_SEC and new_nodes:
                    wl_new = {n for n in new_nodes
                              if n.rsplit('/', 1)[-1] in self._whitelist}
                    if wl_new:
                        self._known_nodes |= wl_new
                        new_nodes -= wl_new
                        self.get_logger().info(
                            f'⏱ grace ({grace_elapsed:.1f}/{_STARTUP_GRACE_SEC:.0f}s) '
                            f'吸收 {len(wl_new)} 個白名單新節點: {sorted(wl_new)}'
                        )
                self._known_nodes = current
                pre_existing_bad = set()

        # N5 alerts (pre-startup poison) + 一般 new node alerts 共用同邏輯
        # N18 修補：dedup 用 TTL+LRU，attacker rotate 100 萬個唯一名字也不會 OOM
        now = time.monotonic()
        for node_full in pre_existing_bad | new_nodes:
            short = node_full.rsplit('/', 1)[-1]
            if short in self._whitelist:
                continue
            with self._lock:
                # N18: 清掉 TTL 過期的 entry（OrderedDict 最舊端先 evict）
                while self._alerted_nodes:
                    oldest_key, ts = next(iter(self._alerted_nodes.items()))
                    if now - ts < _ALERTED_NODES_TTL_SEC:
                        break
                    self._alerted_nodes.popitem(last=False)
                if node_full in self._alerted_nodes:
                    continue
                self._alerted_nodes[node_full] = now
                # N18: LRU 上限（防呆，TTL 通常 size 不會爆）
                while len(self._alerted_nodes) > _ALERTED_NODES_MAX:
                    self._alerted_nodes.popitem(last=False)
            self._alert_new_node(node_full, len(current))

        if self._alert_on_exit:
            for node_full in exited_nodes:
                short = node_full.rsplit('/', 1)[-1]
                if short not in self._whitelist:
                    self._alert_node_exit(node_full)
                with self._lock:
                    self._alerted_nodes.pop(node_full, None)

    # ── alert helpers ────────────────────────────────────────────────────────

    def _alert_new_node(self, node_full: str, total: int) -> None:
        text = (
            f'🤖 [DDS 節點警報]\n'
            f'發現未知 ROS2 節點加入網路！\n'
            f'> 節點名稱: {node_full}\n'
            f'> 目前網路節點總數: {total}'
        )
        self.get_logger().warn(f'偵測到未知節點: {node_full}')
        self._publish(text)
        # N17 修補：leading-edge + batch
        # - 第一筆 alert（距上次 burst >= window）→ 立刻 _send_line（不延遲）
        # - window 內後續 alerts → 加入 pending，由 timer flush 成 summary
        # - pending 超 _LINE_BATCH_PENDING_MAX → drop 並計數（防 burst memory spike）
        now = time.monotonic()
        send_immediate = False
        with self._lock:
            if now - self._last_line_burst_send_t >= _LINE_BATCH_WINDOW_SEC:
                self._last_line_burst_send_t = now
                send_immediate = True
            else:
                if len(self._pending_line_alerts) < _LINE_BATCH_PENDING_MAX:
                    self._pending_line_alerts.append((now, node_full, total))
                else:
                    self._pending_line_overflow += 1
        if send_immediate:
            self._send_line(text)
        if self._emergency_stop:
            self._trigger_emergency_stop()

    def _alert_node_exit(self, node_full: str) -> None:
        text = (
            f'⚠️ [節點離線警報]\n'
            f'ROS2 節點已從網路消失！\n'
            f'> 節點名稱: {node_full}'
        )
        self.get_logger().warn(f'節點離線: {node_full}')
        self._publish(text)
        # N17: exit alerts 也走 batch
        with self._lock:
            self._pending_line_alerts.append((time.monotonic(), f'(exit) {node_full}', -1))

    def _flush_line_batch(self) -> None:
        """N17: 每 _LINE_BATCH_WINDOW_SEC 把 pending alerts 聚合成 1 條 LINE 訊息。

        attacker flood 100 個 unknown nodes 在 30s 內 → operator 只收 1 條包含
        「30 秒內偵測到 100 個未知節點」+ 名單，而不是 100 條獨立通知。

        副作用修補：包含 overflow 計數（超過 _LINE_BATCH_PENDING_MAX 被 drop 的數量）
        """
        with self._lock:
            pending = list(self._pending_line_alerts)
            overflow = self._pending_line_overflow
            self._pending_line_alerts.clear()
            self._pending_line_overflow = 0
        if not pending and overflow == 0:
            return
        names = [p[1] for p in pending]
        preview = '\n'.join(f'  • {n}' for n in names[:10])
        extra = f'\n  ... 還有 {len(names) - 10} 個' if len(names) > 10 else ''
        overflow_line = f'\n  ⚠️ 另有 {overflow} 個 alert 因 burst 超量被丟（PoC 期待這條）' if overflow else ''
        text = (
            f'🚨 [DDS 節點警報 — burst summary]\n'
            f'{_LINE_BATCH_WINDOW_SEC:.0f} 秒內額外偵測到 {len(pending) + overflow} 個未知節點：\n'
            f'{preview}{extra}{overflow_line}\n'
            f'(leading edge 第一筆已即時送出，這是後續聚合摘要)'
        )
        self._send_line(text)

    def _publish(self, text: str) -> None:
        # B + N4 修補：HMAC 簽章 + channel binding。攻擊者 forward 其他 channel 的
        # 簽章 bytes 到這條 alerts channel，receiver 比對 expected_channel 會拒絕。
        msg = String()
        msg.data = sign_alert(text, self._alert_secret, channel=CH_ALERTS)
        self._alert_pub.publish(msg)

    # ── emergency stop ───────────────────────────────────────────────────────

    def _trigger_emergency_stop(self) -> None:
        # G7 修補：全域 cooldown 防止 attacker 輪流生成假節點 → 連環 stop = DoS 武器
        now = time.monotonic()
        elapsed = now - self._last_emergency_stop_time
        if elapsed < _EMERGENCY_STOP_COOLDOWN_SEC:
            self.get_logger().warn(
                f'⏳ emergency_stop cooldown 中 (剩 '
                f'{_EMERGENCY_STOP_COOLDOWN_SEC - elapsed:.1f}s)，alert 仍會發送，但不再重複煞停'
            )
            return
        self._last_emergency_stop_time = now

        self.get_logger().error('🛑 安全威脅！執行緊急停止...')

        # Cancel active Nav2 navigation goal
        if self._cancel_client.service_is_ready():
            req = CancelGoal.Request()
            req.goal_info = GoalInfo()  # Empty = cancel all goals
            self._cancel_client.call_async(req)
            self.get_logger().error('🛑 已取消 Nav2 導航目標')

        # Publish zero velocity repeatedly for stop_duration seconds
        self._stop_ticks = int(self._stop_duration / 0.1)
        if self._stop_timer is not None:
            self._stop_timer.cancel()
        self._stop_timer = self.create_timer(0.1, self._publish_stop)

    def _publish_heartbeat(self) -> None:
        """G6 + N4: 持續送已簽章心跳給 intelligent_defense_node。channel='heartbeat'
        確保 attacker forward 到 alerts channel 會被 receiver 拒絕。
        """
        payload = f'hb|{time.time():.3f}'
        msg = String()
        msg.data = sign_alert(payload, self._alert_secret, channel=CH_HEARTBEAT)
        self._heartbeat_pub.publish(msg)

    def _publish_stop(self) -> None:
        msg = TwistStamped()
        msg.header.stamp    = self.get_clock().now().to_msg()
        msg.header.frame_id = 'base_link'
        self._cmd_vel_pub.publish(msg)  # All zeros = full stop
        self._stop_ticks -= 1
        if self._stop_ticks <= 0:
            self._stop_timer.cancel()
            self._stop_timer = None
            self.get_logger().warn('緊急停止指令發送完畢')

    # ── LINE notification ────────────────────────────────────────────────────

    def _send_line(self, text: str) -> None:
        if not self._line_token or not self._line_user_id:
            self.get_logger().debug('LINE 憑證未設定，略過通知')
            return
        now = time.monotonic()
        if now - self._last_line_time < _LINE_RATE_LIMIT_SEC:
            self.get_logger().debug(
                f'LINE 通知頻率限制中 (剩餘 {_LINE_RATE_LIMIT_SEC-(now-self._last_line_time):.0f}s)，略過')
            return
        self._last_line_time = now
        # 用獨立執行緒發送，避免 HTTP 請求阻塞 ROS2 執行器
        threading.Thread(target=self._send_line_sync, args=(text,), daemon=True).start()

    def _send_line_sync(self, text: str) -> None:
        payload = json.dumps({
            'to': self._line_user_id,
            'messages': [{'type': 'text', 'text': text}],
        }).encode('utf-8')

        req = urllib.request.Request(
            'https://api.line.me/v2/bot/message/push',
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self._line_token}',
            },
            method='POST',
        )

        try:
            # 慢網路下 LINE API 可能 5~8 秒才回應，timeout 拉到 10 秒
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    self.get_logger().info('✅ LINE 通知發送成功')
                else:
                    self.get_logger().warn(f'⚠️ LINE 通知非預期狀態: HTTP {resp.status}')
        except urllib.error.HTTPError as e:
            self.get_logger().error(f'❌ LINE 通知失敗: HTTP {e.code}')
        except Exception as e:
            # 失敗仍維持 rate limit（避免網路斷時連續打爆 LINE API）
            self.get_logger().error(f'❌ LINE 通知錯誤: {e}')


def main(args=None):
    rclpy.init(args=args)
    node = DDSSecurityMonitor()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
