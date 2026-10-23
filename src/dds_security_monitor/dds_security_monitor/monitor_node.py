#!/usr/bin/env python3
"""ROS2 DDS Security Monitor Node.

Polls the ROS2 node graph and sends LINE alerts when unknown nodes appear.
When emergency_stop_enabled=true, publishes a signed security alert and
cancels active Nav2 goals.  ``velocity_guard_node`` consumes the alert and is
the sole publisher allowed to drive the final /cmd_vel.

Credentials: LINE channel token is read only from
~/.config/dds-monitor/line_token (mode 0600). LINE user ID may also come from
LINE_USER_ID for backwards compatibility because it is not a secret.
"""
import collections
import hashlib
import hmac
import json
import math
import os
import secrets
import threading
import time
import urllib.error
import urllib.request

import rclpy
from action_msgs.msg import GoalInfo
from action_msgs.srv import CancelGoal
from rcl_interfaces.msg import ParameterDescriptor, SetParametersResult
from rcl_interfaces.srv import SetParameters
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

from dds_security_monitor.runtime_telemetry import (
    RuntimeTelemetryProducer,
    record_parameter_refusals,
)
from dds_security_monitor.test_fault_seam import (
    ControlledGraphFaultSeam,
    ControlledHeartbeatSuppressSeam,
)


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
_GRAPH_NODE_MAX: int = 256
_GRAPH_OVERFLOW_ALERT_COOLDOWN_SEC: float = 30.0

# HMAC 簽章用的 secret 來源（紅隊攻擊 B 已驗證：沒有簽章 → 任何人都能偽造 alert）
# subscriber 端必須驗章才相信 alert。secret 只從權限受控檔案讀取，
# 避免繼承到 child process 或出現在 /proc/<pid>/environ。
_ALERT_SECRET_FILE = os.path.expanduser("~/.config/dds-monitor/alert_secret")
HMAC_SECRET_MIN_BYTES: int = 32

# LINE 通知 token 檔案位置（紅隊攻擊 H 修補 — 不從 environ 讀）
_LINE_TOKEN_FILE   = os.path.expanduser("~/.config/dds-monitor/line_token")
_LINE_USER_ID_FILE = os.path.expanduser("~/.config/dds-monitor/line_user_id")


def _load_line_token(logger=None) -> str:
    """讀 LINE channel token，只接受權限受控的檔案（chmod 600）。

    紅隊測試攻擊 H：以前從 env 讀 → 同 user 的 process 全部都能從 /proc/<pid>/environ 偷
    現在從檔案讀，避免 token 被動繼承到所有 child process。注意：chmod 600
    只隔離其他 Unix 帳號；已取得同一 UID 任意讀檔能力的程式仍可讀取 token，
    根治需獨立 service account／OS secret service 等行程隔離。
    """
    if os.path.exists(_LINE_TOKEN_FILE):
        # 檢查檔案權限：必須是 600（只有 owner 能讀）
        mode = os.stat(_LINE_TOKEN_FILE).st_mode & 0o777
        if mode != 0o600:
            if logger:
                logger.error(
                    f"⛔ {_LINE_TOKEN_FILE} 權限 {oct(mode)} 不是 600，"
                    "拒絕載入；請 chmod 600"
                )
            return ""
        with open(_LINE_TOKEN_FILE) as f:
            return f.read().strip()
    # 不再把 environment 當成「向後相容」的 secret 儲存位置；這修補
    # /proc environ 被動曝露，但不宣稱能抵抗同 UID 任意檔案讀取。
    if os.environ.get('LINE_CHANNEL_TOKEN') and logger:
        logger.warn(
            f"⚠️ 已忽略 LINE_CHANNEL_TOKEN 環境變數（同 user process 可從 "
            f"/proc/<pid>/environ 讀取）。請移到 {_LINE_TOKEN_FILE} 並 chmod 600"
        )
    return ""


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
    """從權限受控的 secret 檔讀取 HMAC key。

    Args:
        strict: True (default) — secret 不存在則 raise AlertSecretMissingError
                False           — 回傳 b""（給可選功能用，例如 fail-safe import）

    DDS_ALERT_SECRET environment fallback 已移除：環境變數會被 child process
    繼承，也可能出現在 /proc/<pid>/environ。測試應直接傳入測試 key。
    """
    if os.path.exists(_ALERT_SECRET_FILE):
        # 檢查權限
        mode = os.stat(_ALERT_SECRET_FILE).st_mode & 0o777
        if mode != 0o600:
            if strict:
                raise AlertSecretMissingError(
                    f"{_ALERT_SECRET_FILE} 權限 {oct(mode)} 不安全；請 chmod 600")
            return b""
        with open(_ALERT_SECRET_FILE, "rb") as f:
            data = f.read().strip()
            if len(data) < HMAC_SECRET_MIN_BYTES:
                if strict:
                    raise AlertSecretMissingError(
                        f"{_ALERT_SECRET_FILE} 必須至少有 "
                        f"{HMAC_SECRET_MIN_BYTES} bytes（目前 {len(data)}）"
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


def hms() -> str:
    """本地牆鐘時間字串 HH:MM:SS — 嵌進 log/告警讓使用者一眼看到事件發生時間。

    用於：任務切換、攻擊觸發急停、攻擊解除恢復巡邏等關鍵事件，
    使用者看 console/LINE 時能直接對到「幾點幾分發生」，方便對驗紅隊時間軸。
    """
    return time.strftime("%H:%M:%S")


# F1-b 修補：runtime 一律拒絕竄改的安全敏感/系統參數。
# use_sim_time 是 rclpy 內建參數（Node.__init__ 自動 declare），無法用
# declare_parameter(read_only=True) 鎖；紅隊 F1-b 實測在 Permissive 下把
# monitor 的 use_sim_time False→True 竄改成功（翻 true 又無 /clock → 節點所有
# wall-clock timer 凍結 = 對該節點 DoS：心跳停、巡邏停）。
SECURITY_LOCKED_PARAMS: frozenset = frozenset({"use_sim_time"})


def _emit_graph_telemetry(node, *, churn: int, unknown: int) -> None:
    """Best-effort ROS-graph evidence; never allowed to disturb detection."""
    telemetry = getattr(node, "_telemetry", None)
    if telemetry is None:
        return
    for method_name, amount in (
        ("emit_participant_change", churn),
        ("emit_unknown_node", unknown),
    ):
        if amount <= 0:
            continue
        emit = getattr(telemetry, method_name, None)
        if not callable(emit):
            continue
        try:
            emit(count=amount)
        except Exception:
            pass


def lock_sensitive_params(node, extra=frozenset()):
    """掛 on_set_parameters callback，runtime 拒絕竄改 SECURITY_LOCKED_PARAMS。

    - Permissive：擋住 use_sim_time（及 extra 指定的敏感參數）被未授權翻改。
    - Enforce：攻擊者根本呼叫不到 set_parameters 服務（無 CA 憑證）→ 根治；
      本 callback 是 app 層縱深，與 SROS2 存取控制互補。
    必須在所有 declare_parameter 之後呼叫（read_only 參數由 rcl 在 callback 前先擋，
    declare 本身不觸發 callback，故不影響初始化）。

    遙測不要掛在這個 callback 裡：read_only 參數被 rcl 先擋掉時它不會執行，
    1,100 場正式資料的 parameter_call_rate 因此全為 0。計數改由
    count_parameter_service_calls 包在服務層。
    """
    locked = SECURITY_LOCKED_PARAMS | set(extra)

    def _veto(params):
        for p in params:
            if p.name in locked:
                telemetry = getattr(node, "_telemetry", None)
                emit_veto = getattr(telemetry, "emit_parameter_veto", None)
                if callable(emit_veto):
                    try:
                        emit_veto(count=1)
                    except Exception:
                        # Evidence is best-effort and must never weaken or
                        # prevent the parameter veto itself.
                        pass
                node.get_logger().warn(
                    f"[{hms()}] ⛔ 拒絕竄改安全敏感參數 {p.name}={p.value}（F1-b 防護）")
                return SetParametersResult(
                    successful=False,
                    reason=f"{p.name} is security-locked (F1-b)")
        return SetParametersResult(successful=True)

    node.add_on_set_parameters_callback(_veto)
    count_parameter_service_calls(node)


# The parameter services rclpy starts for every node.  Counting all of them,
# not just set_parameters, is the point: the service-flood scenario hammers
# get_parameters, which never reaches a set callback at all.
_PARAMETER_SERVICE_SUFFIXES = (
    "/describe_parameters",
    "/get_parameters",
    "/get_parameter_types",
    "/list_parameters",
    "/set_parameters",
    "/set_parameters_atomically",
)


def count_parameter_service_calls(node):
    """Feed parameter_call_rate from every parameter-service request.

    The previous hook was the on_set_parameters callback, which rcl never
    reaches for a read-only parameter: it rejects those in _apply_descriptors
    first, with "Trying to set a read-only parameter". So the whitelist-hijack
    attack was refused 18 times per session and emitted no telemetry at all,
    and the service flood emitted none either because it calls get_parameters.
    Wrapping the service handlers counts the attempt itself, whatever the node
    decides to do with it.

    Wrapping is idempotent and never alters the response.
    """

    def wrap(service):
        original = service.callback
        if getattr(original, "_counts_parameter_calls", False):
            return

        def counted(request, response):
            telemetry = getattr(node, "_telemetry", None)
            emit_call = getattr(telemetry, "emit_parameter_call", None)
            if callable(emit_call):
                try:
                    emit_call(count=1)
                except Exception:
                    # Evidence is best-effort and must never break or delay
                    # the node's own answer to the request.
                    pass
            answer = original(request, response)
            # Counting the attempt says a parameter change was tried; it does
            # not say whether it was refused. rcl rejects a read-only parameter
            # in _apply_descriptors, before on_set_parameters runs, so the
            # application veto never fires for the whitelist and the refusal
            # was invisible -- which is why parameter_unchanged could never be
            # evidenced. The refusal is right here in the response.
            record_parameter_refusals(node, answer)
            return answer

        counted._counts_parameter_calls = True
        service.callback = counted

    for service in list(node.services):
        name = getattr(service, "srv_name", "") or ""
        if name.endswith(_PARAMETER_SERVICE_SUFFIXES):
            wrap(service)


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
REPLAY_CACHE_MAXLEN: int = 4096     # nonce 緩存大小
ENVELOPE_MAX_CHARS: int = 65536     # 未驗章輸入解析上限，避免巨型 JSON CPU/RAM DoS
BODY_MAX_CHARS: int = 32768
PAYLOAD_MAX_CHARS: int = 24576
NONCE_MAX_CHARS: int = 128
CHANNEL_MAX_CHARS: int = 128

# Canonical channel 名稱常數 — sender/receiver 必須對齊
CH_ALERTS:    str = "alerts"          # /security/alerts (monitor/IDS → patrol/mission/system/burger_env)
CH_HEARTBEAT: str = "heartbeat"       # /security/heartbeat (monitor → IDS)
CH_GOTO:      str = "patrol/goto"     # /patrol/goto (operator → patrol)
CH_SENSOR:    str = "sensor/status"   # /sensor/status (sensor_hub → mission_manager)
CH_MISSION:   str = "mission/cmd"     # /mission/cmd (mission_manager → system_status)
CH_HEALTH:    str = "system/health"   # /system/health (system_status → operator dashboard)

SECURITY_STATE_SCHEMA: str = "dds-security-state/v1"
SECURITY_STATE_MONITOR_HEARTBEAT: str = "monitor_heartbeat"
_SECURITY_STATE_MAX_CHARS: int = 1024
_SECURITY_STATE_DETAIL_MAX_CHARS: int = 512
SENSOR_STATUS_SCHEMA: str = "dds-sensor-status/v1"
_SENSOR_STATUS_MAX_CHARS: int = 2048
_SENSOR_STATUS_DETAIL_MAX_CHARS: int = 1024


def encode_security_state(kind: str, state: str, detail: str = "") -> str:
    """Encode a strict machine-readable fault/clear event for CH_ALERTS."""
    if kind != SECURITY_STATE_MONITOR_HEARTBEAT:
        raise ValueError("unsupported security state kind")
    if state not in {"fault", "clear"}:
        raise ValueError("security state must be fault or clear")
    if not isinstance(detail, str):
        raise TypeError("security state detail must be text")
    clean = "".join(
        ch if ch >= " " else " "
        for ch in detail[:_SECURITY_STATE_DETAIL_MAX_CHARS]
    )
    return json.dumps(
        {
            "detail": clean,
            "kind": kind,
            "schema": SECURITY_STATE_SCHEMA,
            "state": state,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def decode_security_state(payload: str) -> tuple[str, str, str] | None:
    """Decode only the exact versioned schema; unknown input is not a clear."""
    if not isinstance(payload, str) or len(payload) > _SECURITY_STATE_MAX_CHARS:
        return None
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, RecursionError):
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"detail", "kind", "schema", "state"}
        or value.get("schema") != SECURITY_STATE_SCHEMA
        or value.get("kind") != SECURITY_STATE_MONITOR_HEARTBEAT
        or value.get("state") not in {"fault", "clear"}
        or not isinstance(value.get("detail"), str)
        or len(value["detail"]) > _SECURITY_STATE_DETAIL_MAX_CHARS
    ):
        return None
    return value["kind"], value["state"], value["detail"]


def encode_sensor_status(state: str, detail: str) -> str:
    """Encode the sensor hub result without relying on display-string matching."""
    if state not in {"safe", "danger"}:
        raise ValueError("sensor state must be safe or danger")
    if not isinstance(detail, str):
        raise TypeError("sensor detail must be text")
    clean = "".join(
        ch if ch >= " " else " "
        for ch in detail[:_SENSOR_STATUS_DETAIL_MAX_CHARS]
    )
    return json.dumps(
        {
            "detail": clean,
            "schema": SENSOR_STATUS_SCHEMA,
            "state": state,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def decode_sensor_status(payload: str) -> tuple[str, str] | None:
    """Strictly decode v1 sensor state; malformed/unknown schemas fail closed."""
    if not isinstance(payload, str) or len(payload) > _SENSOR_STATUS_MAX_CHARS:
        return None
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, RecursionError):
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"detail", "schema", "state"}
        or value.get("schema") != SENSOR_STATUS_SCHEMA
        or value.get("state") not in {"safe", "danger"}
        or not isinstance(value.get("detail"), str)
        or len(value["detail"]) > _SENSOR_STATUS_DETAIL_MAX_CHARS
    ):
        return None
    return value["state"], value["detail"]


class ReplayCache:
    """Receiver-side anti-replay nonce cache + timestamp expiry.

    N12 修補：純 LRU 在攻擊者 flood unique nonce 時會 evict 舊的 → attacker
    可以 capture 老的 fresh-but-pre-evicted nonce 重放成功。
    解法：以 nonce 加入時間做 TTL，TTL 過了才 expire（與 freshness window 對齊）。
    容量若被尚未過期的 nonce 填滿，採 fail-closed 拒絕新 nonce；絕不驅逐 fresh
    nonce，否則被驅逐的訊息仍能在 freshness window 內重放。

    具體：每次 check_and_add 時先掃描清掉所有 TTL 過期 entry，所以 cache 只保留
    "仍可能被當作 fresh 重放" 的 nonce —  set 大小 ~= max_age * publish_rate（小）。
    """

    def __init__(self, maxlen: int = REPLAY_CACHE_MAXLEN, ttl_sec: float = REPLAY_MAX_AGE_SEC + REPLAY_CLOCK_SKEW_SEC):
        if isinstance(maxlen, bool) or not isinstance(maxlen, int) or maxlen <= 0:
            raise ValueError("ReplayCache maxlen must be a positive integer")
        if (isinstance(ttl_sec, bool)
                or not isinstance(ttl_sec, (int, float))
                or not math.isfinite(ttl_sec)
                or ttl_sec <= 0):
            raise ValueError("ReplayCache ttl_sec must be finite and positive")
        # OrderedDict 內存 nonce → expiry_monotonic_time
        self._seen: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._maxlen = maxlen
        self._ttl = float(ttl_sec)
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str) -> bool:
        """nonce 未見過 → 收下；已見過、無效或容量已滿 → 拒絕。"""
        if not isinstance(nonce, str) or not nonce or len(nonce) > NONCE_MAX_CHARS:
            return False
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
            # N12: fail closed。不能為 bounded memory 淘汰尚在 freshness window
            # 內的 nonce，否則 attacker 可立刻重放被淘汰的舊 envelope。
            if len(self._seen) >= self._maxlen:
                return False
            self._seen[nonce] = now + self._ttl
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)

    @property
    def ttl_sec(self) -> float:
        return self._ttl


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
    if not isinstance(secret, bytes) or len(secret) < HMAC_SECRET_MIN_BYTES:
        raise ValueError(f"secret must contain at least {HMAC_SECRET_MIN_BYTES} bytes")
    if not isinstance(payload, str) or len(payload) > PAYLOAD_MAX_CHARS:
        raise ValueError(
            f"payload must be a string of at most {PAYLOAD_MAX_CHARS} characters")
    if (not isinstance(channel, str) or not channel
            or len(channel) > CHANNEL_MAX_CHARS):
        raise ValueError(f"channel must be 1..{CHANNEL_MAX_CHARS} characters")
    if ts is None:
        ts = time.time()
    if (isinstance(ts, bool)
            or not isinstance(ts, (int, float))
            or not math.isfinite(ts)):
        raise ValueError("ts must be a finite Unix timestamp")
    nonce = secrets.token_hex(8)
    body = json.dumps(
        {"channel": channel, "nonce": nonce, "payload": payload, "ts": ts},
        sort_keys=True, ensure_ascii=False, allow_nan=False,
    )
    # 字元數通過不代表 JSON 跳脫後仍在 wire limit 內（例如大量 `"` 或
    # `\` 會膨脹）。Sender 必須保證自己產生的 envelope 能被 receiver 接受。
    if len(body) > BODY_MAX_CHARS:
        raise ValueError(
            f"serialized body exceeds {BODY_MAX_CHARS} characters")
    mac = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
    envelope = json.dumps({"body": body, "sig": mac}, ensure_ascii=False)
    if len(envelope) > ENVELOPE_MAX_CHARS:
        raise ValueError(
            f"serialized envelope exceeds {ENVELOPE_MAX_CHARS} characters")
    return envelope


def verify_alert_detailed(
    signed: str,
    secret: bytes,
    *,
    expected_channel: str,
    cache: ReplayCache | None = None,
    max_age: float = REPLAY_MAX_AGE_SEC,
    clock_skew: float = REPLAY_CLOCK_SKEW_SEC,
) -> tuple[str | None, str]:
    """Verify an envelope and return ``(payload, stable_reason_code)``.

    五道檢查（全部要過）：
      1. envelope 格式正確 (body + sig 都是 str)
      2. HMAC(body, secret) == sig
      3. body.channel == expected_channel  (修補 N4 cross-channel confusion)
      4. body.ts 在 [now - max_age, now + clock_skew] 範圍內 (anti-replay 時間窗)
      5. body.nonce 未在 cache 中見過 (anti-replay nonce LRU)

    cache=None 時跳過 nonce 檢查（罕用，建議都傳 cache）。
    """
    try:
        if not isinstance(signed, str) or len(signed) > ENVELOPE_MAX_CHARS:
            return None, "invalid_input"
        if (
            not isinstance(secret, bytes)
            or len(secret) < HMAC_SECRET_MIN_BYTES
            or not isinstance(expected_channel, str)
            or not expected_channel
            or len(expected_channel) > CHANNEL_MAX_CHARS
        ):
            return None, "invalid_configuration"
        if (isinstance(max_age, bool)
                or not isinstance(max_age, (int, float))
                or not math.isfinite(max_age)
                or max_age < 0
                or isinstance(clock_skew, bool)
                or not isinstance(clock_skew, (int, float))
                or not math.isfinite(clock_skew)
                or clock_skew < 0):
            return None, "invalid_configuration"
        env = json.loads(signed)
        if not isinstance(env, dict) or set(env) != {"body", "sig"}:
            return None, "malformed_envelope"
        body_str = env.get("body")
        sig = env.get("sig")
        if (not isinstance(body_str, str)
                or len(body_str) > BODY_MAX_CHARS
                or not isinstance(sig, str)
                or len(sig) != hashlib.sha256().digest_size * 2):
            return None, "malformed_envelope"
        expected = hmac.new(secret, body_str.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None, "invalid_signature"
        try:
            body = json.loads(body_str)
        except (json.JSONDecodeError, RecursionError):
            return None, "malformed_body"
        if (not isinstance(body, dict)
                or set(body) != {"channel", "nonce", "payload", "ts"}):
            return None, "malformed_body"
        payload = body.get("payload")
        ts = body.get("ts")
        nonce = body.get("nonce")
        channel = body.get("channel")
        if (not isinstance(payload, str)
                or len(payload) > PAYLOAD_MAX_CHARS
                or isinstance(ts, bool)
                or not isinstance(ts, (int, float))
                or not math.isfinite(ts)
                or not isinstance(nonce, str)
                or not nonce
                or len(nonce) > NONCE_MAX_CHARS
                or not isinstance(channel, str)
                or not channel
                or len(channel) > CHANNEL_MAX_CHARS):
            return None, "malformed_body"
        # N4 修補：channel binding — sender 寫了「我要發到 alerts」，
        # 攻擊者 forward 到 heartbeat channel → channel 對不上 → 拒絕
        if channel != expected_channel:
            return None, "channel_mismatch"
        # Freshness window
        now = time.time()
        if ts < now - max_age or ts > now + clock_skew:
            return None, "timestamp_violation"
        # Nonce LRU (anti-replay 主要防線)
        if cache is not None:
            # Cache TTL must cover the entire accepted wall-clock interval.
            # Otherwise a caller increasing max_age could let a still-fresh
            # nonce expire from the cache and become replayable.
            if cache.ttl_sec < float(max_age) + float(clock_skew):
                return None, "invalid_configuration"
            if not cache.check_and_add(nonce):
                return None, "nonce_reuse_or_capacity"
        return payload, "accepted"
    except json.JSONDecodeError:
        return None, "malformed_envelope"
    except (KeyError, TypeError, ValueError, RecursionError):
        return None, "invalid_input"


def verify_alert(
    signed: str,
    secret: bytes,
    *,
    expected_channel: str,
    cache: ReplayCache | None = None,
    max_age: float = REPLAY_MAX_AGE_SEC,
    clock_skew: float = REPLAY_CLOCK_SKEW_SEC,
    telemetry=None,
) -> str | None:
    """Compatibility wrapper with optional non-blocking reason telemetry."""
    payload, reason = verify_alert_detailed(
        signed,
        secret,
        expected_channel=expected_channel,
        cache=cache,
        max_age=max_age,
        clock_skew=clock_skew,
    )
    if telemetry is not None:
        try:
            telemetry.emit_hmac_result(
                accepted=payload is not None,
                reason=reason,
                channel=expected_channel,
            )
        except Exception:
            # Evidence must never become a denial-of-service path inside a ROS
            # callback.  The producer tracks local drops when it is available.
            pass
    return payload


# ─── 檔案完整性簽章（修補紅隊攻擊 I, M）─────────────────────────────
# Pickle RCE / model swap 共用機制：訓練存檔時同時寫 .sha256.hmac，
# load 之前先驗章。攻擊者修改 buffer.pkl 或 best.zip 後沒有正確 HMAC 就會被擋。

def sign_file(file_path, secret: bytes) -> str:
    """算檔案 SHA256-HMAC 並寫到 <file>.sha256.hmac，回傳 hex sig。"""
    from pathlib import Path
    if not isinstance(secret, bytes) or len(secret) < HMAC_SECRET_MIN_BYTES:
        raise ValueError(f"secret must contain at least {HMAC_SECRET_MIN_BYTES} bytes")
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
    if not isinstance(secret, bytes) or len(secret) < HMAC_SECRET_MIN_BYTES:
        return False
    p = Path(file_path)
    sig_path = p.with_suffix(p.suffix + ".sha256.hmac")
    if not p.is_file() or not sig_path.is_file():
        return False
    try:
        expected = sig_path.read_text().strip()
        if len(expected) != hashlib.sha256().digest_size * 2:
            return False
        h = hmac.new(secret, digestmod=hashlib.sha256)
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return hmac.compare_digest(expected, h.hexdigest())
    except (OSError, UnicodeError, TypeError):
        return False


class DDSSecurityMonitor(Node):
    """應用層資安監控節點（系統的第一道防線）。

    職責：
      1. 定期 poll ROS graph 比對白名單，發現未授權節點 → 簽章發 /security/alerts
      2. 發布 /security/heartbeat 作為偵測層 liveness probe
         （供 intelligent_defense_node 的 D5 watchdog 用）
      3. LINE 通知聚合（30s batch，防 alert flood 洗版 — 對應 ROSEC-2026-018）

    所有對外簽章皆透過 sign_alert() 帶 channel binding，接收端用
    verify_alert(expected_channel=...) 驗章，防 cross-channel confusion
    （ROSEC-2026-001 N4 攻擊已修補）。

    敏感參數（whitelist / poll_interval / emergency_stop_* / line_*）
    以 ParameterDescriptor(read_only=True) 宣告，擋 ROSEC-2026-004 N14
    /set_parameters whitelist hijack。
    """

    def __init__(self):
        super().__init__('dds_security_monitor')
        self._telemetry = RuntimeTelemetryProducer.from_environment(
            "dds_security_monitor"
        )
        self._graph_fault_test_seam = ControlledGraphFaultSeam.from_environment(
            "monitor", self._telemetry
        )
        self._heartbeat_suppress_seam = (
            ControlledHeartbeatSuppressSeam.from_environment(
                "monitor", self._telemetry
            )
        )
        self._graph_runtime_state = "healthy"

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
            # TQC 訓練相關（避免訓練節點被誤判為入侵 → 觸發 emergency stop → 干擾訓練）
            'burger_env_top',
            'intelligent_defense_node',
        ], ro)

        # F1-b 修補：鎖 use_sim_time 等內建敏感參數，runtime 拒絕未授權竄改
        lock_sensitive_params(self)

        self._poll_interval = self.get_parameter('poll_interval_sec').value
        # 修補紅隊攻擊 H：LINE token 只從 mode 0600 檔案讀，
        # 不接受 environment/YAML（避免 /proc 與參數服務洩漏）。
        self._line_token = _load_line_token(self.get_logger())
        if self.get_parameter('line_token').value:
            self.get_logger().warn(
                '⚠️ 已忽略 line_token ROS parameter；secret 必須放在 mode 0600 檔案')
        self._line_user_id = (
            _load_line_user_id(self.get_logger())
            or self.get_parameter('line_user_id').value
        )
        self._whitelist: set[str] = set(self.get_parameter('whitelist').value)
        self._alert_on_exit: bool = self.get_parameter('alert_on_node_exit').value
        self._emergency_stop: bool = self.get_parameter('emergency_stop_enabled').value

        self._known_nodes: set[str] = set()
        # N18 修補：dedup 改為 (node_full → 加入時 monotonic)，過 TTL 自動 evict + LRU 上限
        # 防 attacker rotate 唯一 names 造成 OOM 增長
        self._alerted_nodes: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._initialized = False
        self._init_wall_time: float = 0.0       # N2: 基準快照開始時間，用於 grace period
        # -inf ensures the first incident is never suppressed on a host that
        # booted less than one cooldown window ago.
        self._last_line_time: float = -math.inf
        self._last_emergency_stop_time: float = -math.inf
        self._last_graph_overflow_alert: float = -math.inf
        # N17 修補：LINE batch — pending alerts 由 timer 每 30s 聚合送出
        # 副作用修補：(1) 上限 _LINE_BATCH_PENDING_MAX 防 burst memory spike;
        #            (2) leading-edge 第一筆立刻送，後續才 batch（避免單一 alert 延遲 30s）
        self._pending_line_alerts: list[tuple[float, str, int]] = []
        self._pending_line_overflow: int = 0      # 超 cap 被丟掉的計數
        self._last_line_burst_send_t: float = -math.inf
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

    def _record_graph_transition(self, state: str, node_count: int) -> None:
        previous = getattr(self, "_graph_runtime_state", "healthy")
        normalized = "healthy" if state == "recovery" else state
        if previous == normalized:
            return
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is not None:
            try:
                telemetry.emit_graph_state(state, node_count)
            except Exception:
                pass
        self._graph_runtime_state = normalized

    def _check_graph(self) -> None:
        try:
            seam = getattr(self, "_graph_fault_test_seam", None)
            if seam is not None and seam.consume_if_armed():
                raise RuntimeError("controlled one-shot graph inspection fault")
            graph_nodes = self.get_node_names_and_namespaces()
        except Exception:
            graph_nodes = None
        if graph_nodes is None or len(graph_nodes) > _GRAPH_NODE_MAX:
            graph_state = "fault" if graph_nodes is None else "overflow"
            DDSSecurityMonitor._record_graph_transition(
                self,
                graph_state,
                -1 if graph_nodes is None else len(graph_nodes),
            )
            now = time.monotonic()
            count_text = (
                "unavailable" if graph_nodes is None else str(len(graph_nodes))
            )
            self.get_logger().error(
                "ROS graph inspection fault: "
                f"nodes={count_text}, admitted_max={_GRAPH_NODE_MAX}"
            )
            if (
                now - getattr(self, "_last_graph_overflow_alert", -math.inf)
                >= _GRAPH_OVERFLOW_ALERT_COOLDOWN_SEC
            ):
                self._last_graph_overflow_alert = now
                self._publish(
                    "ROS graph inspection unavailable or over capacity; "
                    "baseline preserved and safety stop requested"
                )
                if self._emergency_stop:
                    self._trigger_emergency_stop()
            return
        seam = getattr(self, "_graph_fault_test_seam", None)
        if seam is not None:
            seam.record_normal_graph()
        if getattr(self, "_graph_runtime_state", "healthy") != "healthy":
            DDSSecurityMonitor._record_graph_transition(
                self, "recovery", len(graph_nodes)
            )
        current: set[str] = set()
        for name, namespace in graph_nodes:
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

        # Graph telemetry: churn and non-whitelisted membership.  Emitted every
        # poll so participant_churn_rate / unknown_node_rate have a live source;
        # both features were structurally zero before 2026-08-06 because no node
        # produced these events.  Evidence is best-effort and must never affect
        # the alert path below.
        _emit_graph_telemetry(
            self,
            churn=len(new_nodes) + len(exited_nodes),
            unknown=sum(
                1
                for node_full in (pre_existing_bad | new_nodes)
                if node_full.rsplit('/', 1)[-1] not in self._whitelist
            ),
        )

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
            if len(self._pending_line_alerts) < _LINE_BATCH_PENDING_MAX:
                self._pending_line_alerts.append(
                    (time.monotonic(), f'(exit) {node_full}', -1))
            else:
                self._pending_line_overflow += 1

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

        # The signed alert was published before this method is called.
        # velocity_guard_node latches that alert and is the only /cmd_vel writer.
        self.get_logger().error(
            '🛑 已要求 velocity guard 鎖零速（signed /security/alerts）')

    def _publish_heartbeat(self) -> None:
        """G6 + N4: 持續送已簽章心跳給 intelligent_defense_node。channel='heartbeat'
        確保 attacker forward 到 alerts channel 會被 receiver 拒絕。
        """
        # Test-only seam, inert unless five independent gates plus its own
        # acknowledgement are present and a short-lived mode-0600 arm file is
        # atomically consumed.  It skips only this publish: the process, its
        # DDS participant and every other duty keep running, which is the whole
        # point -- SIGSTOP on the process makes D5 fire but also lets the
        # liveliness lease kill the participant, so the heartbeat never returns
        # and velocity_guard_recovered can never show fault and recovery in one
        # session.
        seam = getattr(self, "_heartbeat_suppress_seam", None)
        if seam is not None and seam.suppress_if_armed():
            return
        if seam is not None:
            # An arm that is written but never consumed looks exactly like a
            # defence that did not react, and that ambiguity is what made five
            # velocity_guard_recovered attempts inconclusive.  take_refusal
            # reports only the causes that mean an arm was thrown away, and
            # only on the edge where the cause changes, so this cannot become
            # a per-heartbeat log flood.
            refusal = seam.take_refusal()
            if refusal is not None:
                self.get_logger().warning(
                    f"controlled heartbeat suppression refused an arm: {refusal}"
                )
            # A seam that consumed its arm but could not report it looks, to
            # every downstream reader, exactly like a seam that was never
            # consumed.  That is the actual history of this check.
            emit_error = seam.take_emit_error()
            if emit_error is not None:
                self.get_logger().error(
                    f"controlled heartbeat suppression telemetry failed: {emit_error}"
                )
            seam.record_normal_heartbeat()
        payload = f'hb|{time.time():.3f}'
        msg = String()
        msg.data = sign_alert(payload, self._alert_secret, channel=CH_HEARTBEAT)
        self._heartbeat_pub.publish(msg)

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

    def destroy_node(self):
        telemetry = getattr(self, "_telemetry", None)
        if telemetry is not None:
            telemetry.close()
        return super().destroy_node()


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
