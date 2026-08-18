"""核心資安機制的單元測試。

涵蓋（reviewer 指名要有的）：
    1. HMAC 簽章/驗章正確性
    2. 偽造、改檔、無簽 → 一律 reject
    3. /patrol/goto 座標範圍檢查
    4. /scan 異常偵測（std、95% near-max）
    5. 檔案完整性簽章對「替換攻擊」生效

執行：
    source ~/dqn_env/bin/activate
    source ~/ros2_ws/install/setup.bash
    pytest tests/test_security.py -v
"""
from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

import dds_security_monitor.monitor_node as monitor_node
import dds_security_monitor.intelligent_defense_node as defense_node
import dds_security_monitor.mission_manager_node as mission_manager
import dds_security_monitor.patrol_node as patrol_node
import dds_security_monitor.sensor_hub_node as sensor_hub
import dds_security_monitor.velocity_guard_node as velocity_guard
from dds_security_monitor.monitor_node import (
    sign_alert, verify_alert,
    sign_file, verify_file,
    secret_fingerprint,
    _load_alert_secret,
    _load_line_token,
    AlertSecretMissingError,
    ReplayCache,
    SECURITY_STATE_MONITOR_HEARTBEAT,
    CH_ALERTS, CH_HEARTBEAT, CH_MISSION, CH_SENSOR,
    decode_security_state,
    decode_sensor_status,
    encode_security_state,
    encode_sensor_status,
)
from dds_security_monitor.patrol_node import (
    LIDAR_MAX_RANGE,
    REQUIRED_FRONT_HALF_ANGLE_DEG,
    SCAN_MIN_POINTS,
    WAYPOINT_NAME_MAX_CHARS,
    _load_yaml,
    _prepare_odom_pose,
    _prepare_scan,
    _validate_waypoint,
)
from dds_security_monitor.sensor_hub_node import (
    _format_sensor_status,
    _horizontal_acceleration,
    _minimum_scan_range,
)


class TestVelocityGuard:
    @pytest.mark.parametrize(
        "linear,angular",
        [
            (float("nan"), 0.0),
            (0.0, float("inf")),
            (True, 0.0),
            (0.24, 0.0),
            (0.0, 2.86),
        ],
    )
    def test_invalid_or_out_of_envelope_velocity_is_rejected(
        self, linear, angular
    ):
        with pytest.raises(ValueError):
            velocity_guard.validate_velocity(linear, angular)

    def test_only_fresh_selected_command_reaches_final_topic(self, monkeypatch):
        now = [100.0]
        monkeypatch.setattr(
            velocity_guard.time, "monotonic", lambda: now[0]
        )
        published = []
        fake = SimpleNamespace(
            _monitor_down=False,
            _generic_stop_until=0.0,
            _last_monitor_hb_wall=100.0,
            _heartbeat_timeout=5.0,
            _active_source="patrol",
            _latest=velocity_guard.SafeVelocity(0.1, 0.2),
            _latest_wall=100.0,
            _input_timeout=0.5,
            _publish=published.append,
        )
        fake._blocking_reasons = lambda current: (
            velocity_guard.VelocityGuardNode._blocking_reasons(fake, current)
        )

        velocity_guard.VelocityGuardNode._publish_selected(fake)
        assert published[-1] == velocity_guard.SafeVelocity(0.1, 0.2)

        now[0] = 100.6
        velocity_guard.VelocityGuardNode._publish_selected(fake)
        assert published[-1] == velocity_guard.SafeVelocity(0.0, 0.0)

        now[0] = 100.1
        fake._monitor_down = True
        velocity_guard.VelocityGuardNode._publish_selected(fake)
        assert published[-1] == velocity_guard.SafeVelocity(0.0, 0.0)

    def test_guard_boots_locked_before_authenticated_heartbeat(self, monkeypatch):
        monkeypatch.setattr(velocity_guard.time, "monotonic", lambda: 100.0)
        published = []
        fake = SimpleNamespace(
            _monitor_down=False,
            _generic_stop_until=0.0,
            _last_monitor_hb_wall=0.0,
            _heartbeat_timeout=5.0,
            _active_source="patrol",
            _latest=velocity_guard.SafeVelocity(0.1, 0.2),
            _latest_wall=100.0,
            _input_timeout=0.5,
            _publish=published.append,
        )
        fake._blocking_reasons = lambda current: (
            velocity_guard.VelocityGuardNode._blocking_reasons(fake, current)
        )
        velocity_guard.VelocityGuardNode._publish_selected(fake)
        assert published[-1] == velocity_guard.SafeVelocity(0.0, 0.0)
        assert "monitor_lease_missing" in fake._blocking_reasons(100.0)

    def test_valid_heartbeat_opens_and_timeout_relocks_guard(self, monkeypatch):
        now = [100.0]
        monkeypatch.setattr(velocity_guard.time, "monotonic", lambda: now[0])

        class Logger:
            def warn(self, *_args, **_kwargs):
                pass

        fake = SimpleNamespace(
            _secret=SECRET,
            _heartbeat_cache=ReplayCache(),
            _last_monitor_hb_wall=0.0,
            _heartbeat_timeout=5.0,
            _monitor_down=False,
            _generic_stop_until=0.0,
            _active_source="patrol",
            _latest=velocity_guard.SafeVelocity(0.1, 0.2),
            _latest_wall=100.0,
            _input_timeout=0.5,
            get_logger=lambda: Logger(),
        )
        heartbeat = SimpleNamespace(
            data=sign_alert("alive", SECRET, channel=CH_HEARTBEAT)
        )
        velocity_guard.VelocityGuardNode._on_heartbeat(fake, heartbeat)
        assert fake._last_monitor_hb_wall == 100.0
        assert not velocity_guard.VelocityGuardNode._blocking_reasons(
            fake, 100.0
        )

        # Replaying the same heartbeat cannot refresh the lease.
        now[0] = 104.0
        velocity_guard.VelocityGuardNode._on_heartbeat(fake, heartbeat)
        assert fake._last_monitor_hb_wall == 100.0
        now[0] = 105.1
        assert "monitor_lease_missing" in (
            velocity_guard.VelocityGuardNode._blocking_reasons(fake, now[0])
        )

    def test_guard_stop_reasons_do_not_clear_each_other(self):
        fake = SimpleNamespace(
            _monitor_down=False,
            _generic_stop_until=120.0,
            _last_monitor_hb_wall=100.0,
            _heartbeat_timeout=5.0,
            _active_source="patrol",
            _latest=velocity_guard.SafeVelocity(0.1, 0.2),
            _latest_wall=100.0,
            _input_timeout=0.5,
        )
        assert velocity_guard.VelocityGuardNode._blocking_reasons(
            fake, 100.0
        ) == {"generic_alert"}
        fake._monitor_down = True
        assert velocity_guard.VelocityGuardNode._blocking_reasons(
            fake, 100.0
        ) == {"generic_alert", "monitor_fault"}
        fake._monitor_down = False
        assert velocity_guard.VelocityGuardNode._blocking_reasons(
            fake, 100.0
        ) == {"generic_alert"}


SECRET = b"test_secret_for_unit_tests_32_bytes_minimum"


# ════════════════════════════════════════════════════════════════
# 1. HMAC 簽章基本性質 (envelope v3: body{channel,nonce,payload,ts} + sig)
# ════════════════════════════════════════════════════════════════

class TestHmacSign:
    def test_sign_then_verify_roundtrip(self):
        """正常 case：簽完應該驗得過。"""
        signed = sign_alert("hello", SECRET, channel=CH_ALERTS)
        assert verify_alert(signed, SECRET, expected_channel=CH_ALERTS) == "hello"

    def test_verify_plain_string_rejected(self):
        """攻擊 B 修補：純字串（無簽章）必須拒絕。"""
        assert verify_alert("not signed", SECRET, expected_channel=CH_ALERTS) is None

    def test_verify_tampered_payload_rejected(self):
        """攻擊者修改 body 但保留 sig → 驗章失敗。"""
        signed = sign_alert("legit msg", SECRET, channel=CH_ALERTS)
        bad = signed.replace("legit msg", "EVIL")
        assert verify_alert(bad, SECRET, expected_channel=CH_ALERTS) is None

    def test_verify_wrong_secret_rejected(self):
        """用錯誤 secret 驗章必失敗。"""
        signed = sign_alert("hello", SECRET, channel=CH_ALERTS)
        wrong_secret = b"different_secret_key" * 4
        assert verify_alert(signed, wrong_secret, expected_channel=CH_ALERTS) is None

    def test_verify_garbage_input(self):
        """各種垃圾輸入都要回 None，不能 raise。"""
        for bad in ["", "{}", "{not json}", "[]", '{"only_payload": "x"}',
                    '{"payload": "x"}', '\x00\x01\x02']:
            assert verify_alert(bad, SECRET, expected_channel=CH_ALERTS) is None, \
                f"failed on: {bad!r}"

    def test_cross_channel_rejected(self):
        """N4 修補：簽 channel=ALERTS 的訊息不能被 channel=HEARTBEAT 接受。"""
        signed = sign_alert("payload", SECRET, channel=CH_ALERTS)
        assert verify_alert(signed, SECRET, expected_channel=CH_HEARTBEAT) is None
        # 但用正確 channel 仍應通過
        assert verify_alert(signed, SECRET, expected_channel=CH_ALERTS) == "payload"

    def test_old_envelope_replay_rejected(self):
        """N1/N3 修補：太老的 ts 應該被拒絕（超出 max_age 視窗）。"""
        old_signed = sign_alert("stale", SECRET, channel=CH_ALERTS, ts=0.0)
        # max_age 預設應該很短，ts=0 (1970) 必過期
        assert verify_alert(old_signed, SECRET, expected_channel=CH_ALERTS) is None

    def test_nonce_replay_rejected_with_cache(self):
        """N1/N3: 同一 nonce 二次來訪應被 ReplayCache 擋。"""
        cache = ReplayCache()
        signed = sign_alert("once", SECRET, channel=CH_ALERTS)
        # 第一次：通過
        assert verify_alert(signed, SECRET, expected_channel=CH_ALERTS, cache=cache) == "once"
        # 第二次：重放，必須被擋
        assert verify_alert(signed, SECRET, expected_channel=CH_ALERTS, cache=cache) is None

    @staticmethod
    def _signed_custom_body(body: dict) -> str:
        """模擬其他 sender 產生的有效 HMAC，驗 receiver 邊界檢查。"""
        body_str = json.dumps(
            body, sort_keys=True, ensure_ascii=False, allow_nan=True)
        sig = hmac.new(SECRET, body_str.encode(), hashlib.sha256).hexdigest()
        return json.dumps({"body": body_str, "sig": sig}, ensure_ascii=False)

    @pytest.mark.parametrize("bad_ts", [float("nan"), float("inf"), True])
    def test_nonfinite_or_boolean_timestamp_rejected(self, bad_ts):
        """NaN 比較永遠為 False，若不先 isfinite 會繞過 freshness window。"""
        signed = self._signed_custom_body({
            "channel": CH_ALERTS,
            "nonce": "0123456789abcdef",
            "payload": "bad timestamp",
            "ts": bad_ts,
        })
        assert verify_alert(
            signed, SECRET, expected_channel=CH_ALERTS) is None

    @pytest.mark.parametrize("bad_ts", [float("nan"), float("inf"), True])
    def test_sign_rejects_invalid_timestamp(self, bad_ts):
        with pytest.raises(ValueError):
            sign_alert("payload", SECRET, channel=CH_ALERTS, ts=bad_ts)

    def test_short_hmac_secret_rejected(self):
        with pytest.raises(ValueError):
            sign_alert("payload", b"too-short", channel=CH_ALERTS)
        signed = sign_alert("payload", SECRET, channel=CH_ALERTS)
        assert verify_alert(
            signed, b"too-short", expected_channel=CH_ALERTS) is None

    def test_protocol_rejects_extra_fields(self):
        """欄位集合固定，避免不同 parser 對 ambiguous envelope 解讀不一。"""
        signed = self._signed_custom_body({
            "channel": CH_ALERTS,
            "nonce": "0123456789abcdef",
            "payload": "payload",
            "ts": monitor_node.time.time(),
            "unexpected": "field",
        })
        assert verify_alert(
            signed, SECRET, expected_channel=CH_ALERTS) is None

    def test_oversized_untrusted_envelope_rejected(self):
        assert verify_alert(
            "x" * (monitor_node.ENVELOPE_MAX_CHARS + 1),
            SECRET,
            expected_channel=CH_ALERTS,
        ) is None

    def test_deeply_nested_json_cannot_escape_as_recursion_error(self):
        nested = "[" * 1100 + "]" * 1100
        assert verify_alert(
            nested, SECRET, expected_channel=CH_ALERTS) is None

    def test_sender_rejects_payload_that_json_escaping_makes_too_large(self):
        """字元數未超限，但大量引號跳脫後 body 超限時不可產生必拒封包。"""
        payload = '"' * (monitor_node.PAYLOAD_MAX_CHARS - 1)
        with pytest.raises(ValueError, match="serialized body"):
            sign_alert(payload, SECRET, channel=CH_ALERTS)


class TestReplayCache:
    def test_capacity_is_fail_closed_without_evicting_fresh_nonce(self, monkeypatch):
        """N12 regression：容量滿時不可淘汰 fresh nonce，否則舊包可立刻重放。"""
        now = [100.0]
        monkeypatch.setattr(monitor_node.time, "monotonic", lambda: now[0])
        cache = ReplayCache(maxlen=2, ttl_sec=12.0)

        assert cache.check_and_add("nonce-a") is True
        assert cache.check_and_add("nonce-b") is True
        assert cache.check_and_add("nonce-c") is False
        assert cache.check_and_add("nonce-a") is False
        assert len(cache) == 2

        # TTL 到期後才可清除舊 nonce 並接收新值。
        now[0] = 112.1
        assert cache.check_and_add("nonce-c") is True
        assert len(cache) == 1

    @pytest.mark.parametrize(
        ("maxlen", "ttl"),
        [(0, 1.0), (-1, 1.0), (True, 1.0), (1, 0.0), (1, float("nan"))],
    )
    def test_invalid_configuration_rejected(self, maxlen, ttl):
        with pytest.raises(ValueError):
            ReplayCache(maxlen=maxlen, ttl_sec=ttl)

    def test_invalid_nonce_rejected(self):
        cache = ReplayCache(maxlen=2)
        assert cache.check_and_add("") is False
        assert cache.check_and_add(
            "x" * (monitor_node.NONCE_MAX_CHARS + 1)) is False
        assert len(cache) == 0

    def test_cache_ttl_must_cover_custom_freshness_window(self):
        signed = sign_alert(
            "payload",
            SECRET,
            channel=CH_ALERTS,
            ts=monitor_node.time.time(),
        )
        too_short = ReplayCache(maxlen=10, ttl_sec=2.0)
        assert verify_alert(
            signed,
            SECRET,
            expected_channel=CH_ALERTS,
            cache=too_short,
            max_age=10.0,
            clock_skew=2.0,
        ) is None


class TestSecretLoading:
    def test_alert_secret_environment_is_ignored(self, monkeypatch, tmp_path):
        missing = tmp_path / "missing_alert_secret"
        monkeypatch.setattr(monitor_node, "_ALERT_SECRET_FILE", str(missing))
        monkeypatch.setenv("DDS_ALERT_SECRET", "x" * 64)
        assert _load_alert_secret(strict=False) == b""
        with pytest.raises(AlertSecretMissingError):
            _load_alert_secret()

    def test_alert_secret_too_short_is_rejected(self, monkeypatch, tmp_path):
        secret_file = tmp_path / "alert_secret"
        secret_file.write_bytes(b"short")
        secret_file.chmod(0o600)
        monkeypatch.setattr(monitor_node, "_ALERT_SECRET_FILE", str(secret_file))
        with pytest.raises(AlertSecretMissingError):
            _load_alert_secret()

    def test_line_token_environment_is_ignored(self, monkeypatch, tmp_path):
        missing = tmp_path / "missing_line_token"
        monkeypatch.setattr(monitor_node, "_LINE_TOKEN_FILE", str(missing))
        monkeypatch.setenv("LINE_CHANNEL_TOKEN", "must-not-be-used")
        assert _load_line_token() == ""

    def test_secret_files_are_loaded(self, monkeypatch, tmp_path):
        alert_file = tmp_path / "alert_secret"
        alert_file.write_bytes(b"a" * 32)
        alert_file.chmod(0o600)
        line_file = tmp_path / "line_token"
        line_file.write_text("line-token", encoding="utf-8")
        line_file.chmod(0o600)
        monkeypatch.setattr(monitor_node, "_ALERT_SECRET_FILE", str(alert_file))
        monkeypatch.setattr(monitor_node, "_LINE_TOKEN_FILE", str(line_file))
        assert _load_alert_secret() == b"a" * 32
        assert _load_line_token() == "line-token"


# ════════════════════════════════════════════════════════════════
# 2. 檔案完整性（攻擊 I/M 修補）
# ════════════════════════════════════════════════════════════════

class TestFileIntegrity:
    @pytest.fixture
    def tmpfile(self):
        """建立 tmp 檔案 + 自動清理（含 .sha256.hmac 簽章檔）。"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            f.write(b"legitimate_pickle_data" * 100)
            path = Path(f.name)
        yield path
        path.unlink(missing_ok=True)
        path.with_suffix(".pkl.sha256.hmac").unlink(missing_ok=True)

    def test_sign_creates_sig_file(self, tmpfile):
        sign_file(tmpfile, SECRET)
        sig_path = tmpfile.with_suffix(".pkl.sha256.hmac")
        assert sig_path.exists()

    def test_unmodified_file_verifies(self, tmpfile):
        sign_file(tmpfile, SECRET)
        assert verify_file(tmpfile, SECRET) is True

    def test_modified_file_rejected(self, tmpfile):
        """攻擊 I/M 核心：檔案被改後 verify 必須 False。"""
        sign_file(tmpfile, SECRET)
        # 攻擊者附加 payload
        with open(tmpfile, "ab") as f:
            f.write(b"EVIL_PICKLE_RCE_PAYLOAD")
        assert verify_file(tmpfile, SECRET) is False

    def test_missing_sig_rejected(self, tmpfile):
        """沒 .sha256.hmac 檔 → fail-secure（不通過）。"""
        # 沒呼叫 sign_file → 沒簽章檔
        assert verify_file(tmpfile, SECRET) is False

    def test_forged_sig_with_wrong_secret_rejected(self, tmpfile):
        """攻擊者用錯 secret 簽 → 我們用正確 secret 驗應拒絕。"""
        wrong_secret = b"attacker_guessed_wrong" * 2
        sign_file(tmpfile, wrong_secret)
        assert verify_file(tmpfile, SECRET) is False

    def test_short_secret_cannot_sign_or_verify_file(self, tmpfile):
        """模型/回放檔完整性與 envelope 使用同一最低 key 強度。"""
        with pytest.raises(ValueError):
            sign_file(tmpfile, b"short")
        sign_file(tmpfile, SECRET)
        assert verify_file(tmpfile, b"short") is False


# ════════════════════════════════════════════════════════════════
# 3. /patrol/goto 座標範圍檢查（攻擊 D 修補）
# ════════════════════════════════════════════════════════════════

class TestPatrolGotoBounds:
    def _is_valid(self, x: float, y: float) -> bool:
        try:
            _validate_waypoint(
                {"name": "test", "x": x, "y": y},
                allow_default_name=True,
            )
            return True
        except ValueError:
            return False

    def test_inside_bounds_accepted(self):
        assert self._is_valid(1.5, -1.0) is True
        assert self._is_valid(0.0, 0.0) is True
        assert self._is_valid(2.5, 2.5) is True
        assert self._is_valid(-2.5, -2.5) is True

    def test_outside_bounds_rejected(self):
        """攻擊 D：送機器人到 (100, 100) 牆外 → 拒絕。"""
        assert self._is_valid(100.0, 100.0) is False
        assert self._is_valid(0.0, -10.0) is False
        assert self._is_valid(3.0, 0.0) is False

    def test_boundary_inclusive(self):
        """邊界值 (±2.5) 視為合法。"""
        assert self._is_valid(2.5, 0.0) is True
        assert self._is_valid(2.50001, 0.0) is False

    @pytest.mark.parametrize(
        "value",
        [float("nan"), float("inf"), float("-inf"), True, "1.0", None],
    )
    def test_nonfinite_or_nonnumeric_coordinate_rejected(self, value):
        assert self._is_valid(value, 0.0) is False

    @pytest.mark.parametrize(
        "name",
        [123, "", " ", "x" * (WAYPOINT_NAME_MAX_CHARS + 1), "bad\x1bname"],
    )
    def test_invalid_name_rejected(self, name):
        with pytest.raises(ValueError):
            _validate_waypoint({"name": name, "x": 0.0, "y": 0.0})

    def test_missing_goto_name_uses_bounded_default(self):
        waypoint = _validate_waypoint(
            {"x": 0.0, "y": 0.0}, allow_default_name=True)
        assert waypoint.name == "臨時目標"


class TestWaypointYamlValidation:
    @pytest.mark.parametrize(
        "content",
        [
            "[]",
            "waypoints: not-a-list",
            "waypoints: []",
            "waypoints:\n  - name: ok\n    x: .nan\n    y: 0.0",
            "waypoints:\n  - name: ok\n    x: 99.0\n    y: 0.0",
            "waypoints:\n  - name: 123\n    x: 0.0\n    y: 0.0",
            "waypoints:\n  - [bad, structure]",
            "waypoints:\n  - name: ok\n    x: 0.0\n    y: 0.0\nextra: true",
        ],
    )
    def test_malformed_yaml_rejected(self, tmp_path, content):
        path = tmp_path / "waypoints.yaml"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError):
            _load_yaml(path)

    def test_valid_yaml_is_loaded(self, tmp_path):
        path = tmp_path / "waypoints.yaml"
        path.write_text(
            "waypoints:\n"
            "  - name: A\n"
            "    x: -1.0\n"
            "    y: 1.0\n",
            encoding="utf-8",
        )
        assert _load_yaml(path) == [
            patrol_node.Waypoint(name="A", x=-1.0, y=1.0)]


# ════════════════════════════════════════════════════════════════
# 4. Scan 異常偵測（攻擊 K 修補）
# ════════════════════════════════════════════════════════════════

class TestScanAnomaly:
    """重現 burger_env._scan_cb 的三重偵測邏輯。"""

    LIDAR_MAX = 3.5
    STD_THRESHOLD = 0.01
    NEAR_MAX_RATIO = 0.95

    def _detect(self, scan: list[float], prev: list[float] | None = None) -> str | None:
        """三重偵測，回傳觸發的規則名稱（None 表示通過）。"""
        arr = np.asarray(scan, dtype=np.float32)
        arr = np.where(np.isinf(arr) | np.isnan(arr), self.LIDAR_MAX, arr)
        # 規則 1: std 過低
        if float(np.std(arr)) < self.STD_THRESHOLD:
            return "low_std"
        # 規則 2: 跟上一幀完全相同
        if prev is not None and scan == prev:
            return "frame_repeat"
        # 規則 3: 95% bin 接近 max
        near_max = float(np.sum(arr > 0.9 * self.LIDAR_MAX)) / len(arr)
        if near_max > self.NEAR_MAX_RATIO:
            return "mostly_max"
        return None

    def test_uniform_max_rejected(self):
        """攻擊 K-1：全 3.5m → 觸發 low_std。"""
        assert self._detect([3.5] * 360) == "low_std"

    def test_uniform_short_rejected(self):
        """攻擊 K-2：全 1.0m → low_std。"""
        assert self._detect([1.0] * 360) == "low_std"

    def test_frame_repeat_rejected(self):
        """攻擊 K-3：連續幀完全相同。"""
        import random
        random.seed(42)
        attack = [3.5 + random.uniform(-0.04, 0.04) for _ in range(360)]
        assert self._detect(attack, prev=attack) == "frame_repeat"

    def test_mostly_max_rejected(self):
        """攻擊 K-4：noise 但 95% 接近 max。"""
        import random
        random.seed(99)
        attack = [3.5 + random.uniform(-0.05, 0.05) for _ in range(360)]
        assert self._detect(attack) == "mostly_max"

    def test_real_scan_with_obstacles_passes(self):
        """正常有障礙 scan 應通過。"""
        import random
        random.seed(200)
        real = [3.5 + random.uniform(-0.05, 0.05) for _ in range(360)]
        # 模擬有柱子
        for i in range(20):
            real[100+i] = 0.5 + random.uniform(-0.02, 0.02)
        assert self._detect(real) is None


class TestPatrolScanPreparation:
    def test_downsampling_covers_entire_angular_span(self):
        """359 點舊算法用 n//90，只取到 index 267；尾端障礙會完全漏掉。"""
        ranges = np.linspace(0.1, LIDAR_MAX_RANGE, 359, dtype=np.float32)
        sampled, angle_min, increment = _prepare_scan(
            ranges, -np.pi, np.pi)
        assert len(sampled) == 90
        assert sampled[0] == pytest.approx(0.1)
        assert sampled[-1] == pytest.approx(LIDAR_MAX_RANGE)
        assert angle_min == pytest.approx(-np.pi)
        assert increment == pytest.approx((2 * np.pi) / 89)

    @pytest.mark.parametrize(
        ("ranges", "angle_min", "angle_max"),
        [
            ([], -1.0, 1.0),
            ([1.0] * (SCAN_MIN_POINTS - 1), -1.0, 1.0),
            ([1.0] * SCAN_MIN_POINTS, 0.0, 0.0),
            ([1.0] * SCAN_MIN_POINTS, float("nan"), 1.0),
            ([1.0] * SCAN_MIN_POINTS, -4.0, 4.0),
            ([1.0] * SCAN_MIN_POINTS, -0.5, 0.5),
            ([1.0] * SCAN_MIN_POINTS, np.pi / 2, np.pi),
            ([1.0] * SCAN_MIN_POINTS, 0.0, np.pi),
        ],
    )
    def test_malformed_scan_rejected(self, ranges, angle_min, angle_max):
        with pytest.raises(ValueError):
            _prepare_scan(ranges, angle_min, angle_max)

    def test_nan_and_negative_infinity_are_fail_safe_obstacles(self):
        ranges = [1.0] * 90
        ranges[0] = float("nan")
        ranges[1] = float("-inf")
        ranges[2] = float("inf")
        sampled, _, _ = _prepare_scan(ranges, -1.1, 1.1)
        assert sampled[0] == 0.0
        assert sampled[1] == 0.0
        assert sampled[2] == LIDAR_MAX_RANGE

    def test_exact_required_front_coverage_is_accepted(self):
        half = np.deg2rad(REQUIRED_FRONT_HALF_ANGLE_DEG)
        sampled, _, _ = _prepare_scan(
            [1.0] * SCAN_MIN_POINTS, -half, half)
        assert len(sampled) == SCAN_MIN_POINTS

    def test_full_circle_zero_to_two_pi_has_wrapped_front_coverage(self):
        sampled, angle_min, increment = _prepare_scan(
            [1.0] * 360, 0.0, 2 * np.pi)
        assert len(sampled) == 90
        assert angle_min == 0.0
        assert increment > 0.0

    def test_gazebo_rounded_full_circle_metadata_is_accepted(self):
        """TurtleBot3 Gazebo uses 360 samples over 0..6.28, not exact 2π."""
        sampled, angle_min, increment = _prepare_scan(
            [1.0] * 360, 0.0, 6.28)
        assert len(sampled) == 90
        assert angle_min == 0.0
        assert increment == pytest.approx(6.28 / 89)

    def test_material_front_blind_wedge_is_still_rejected(self):
        """Endpoint tolerance must not turn a real front blind wedge into 360°."""
        with pytest.raises(ValueError, match="未實際覆蓋前方"):
            _prepare_scan(
                [1.0] * 360,
                0.0,
                2 * np.pi - np.deg2rad(3.0),
            )


class TestPatrolOdomPreparation:
    def test_valid_quaternion_is_normalized(self):
        x, y, heading = _prepare_odom_pose(
            1.0, -0.5, 0.0, 0.0, 0.0, 1.02)
        assert (x, y) == (1.0, -0.5)
        assert heading == pytest.approx(0.0)

    @pytest.mark.parametrize(
        "pose",
        [
            (float("nan"), 0.0, 0.0, 0.0, 0.0, 1.0),
            (0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            (0.0, 0.0, 0.0, 0.0, 0.0, 2.0),
            (0.0, 0.0, float("inf"), 0.0, 0.0, 1.0),
        ],
    )
    def test_malformed_pose_is_rejected(self, pose):
        with pytest.raises(ValueError):
            _prepare_odom_pose(*pose)


class TestSensorHubScanValidation:
    def test_all_invalid_scan_is_not_reported_safe(self):
        assert _minimum_scan_range(
            [float("nan"), float("-inf"), -1.0],
            range_min=0.12,
            range_max=3.5,
        ) is None

    def test_positive_infinity_maps_to_sensor_max(self):
        assert _minimum_scan_range(
            [float("inf")],
            range_min=0.12,
            range_max=3.5,
        ) == pytest.approx(3.5)

    def test_nearest_valid_obstacle_is_kept(self):
        assert _minimum_scan_range(
            [float("inf"), 0.7, 0.2],
            range_min=0.12,
            range_max=3.5,
        ) == pytest.approx(0.2)

    def test_finite_out_of_sensor_range_is_not_treated_as_clear(self):
        assert _minimum_scan_range(
            [999.0], range_min=0.12, range_max=3.5) is None

    def test_oversized_scan_is_rejected_before_copying(self):
        assert _minimum_scan_range(
            [1.0] * (sensor_hub.SCAN_MAX_POINTS + 1),
            range_min=0.12,
            range_max=3.5,
        ) is None

    def test_non_numeric_scan_values_are_ignored_fail_safe(self):
        assert _minimum_scan_range(
            ["1.0", True, None],
            range_min=0.12,
            range_max=3.5,
        ) is None

    @pytest.mark.parametrize(
        ("range_min", "range_max"),
        [
            (float("nan"), 3.5),
            (0.12, float("nan")),
            (-0.1, 3.5),
            (3.5, 3.5),
            (4.0, 3.5),
        ],
    )
    def test_invalid_scan_metadata_is_fail_danger(self, range_min, range_max):
        assert _minimum_scan_range(
            [999.0], range_min=range_min, range_max=range_max) is None


class TestSensorHubFreshness:
    class FakeLogger:
        def warn(self, *_args, **_kwargs):
            pass

    @pytest.mark.parametrize(
        "axes",
        [
            (float("nan"), 0.0, 9.8),
            (0.0, float("inf"), 9.8),
            (0.0, 0.0, float("-inf")),
            (0.0, 0.0, "9.8"),
            (0.0, 0.0, True),
        ],
    )
    def test_all_three_imu_axes_must_be_finite(self, axes):
        with pytest.raises(ValueError):
            _horizontal_acceleration(*axes)

    def test_valid_imu_uses_horizontal_magnitude_after_validating_z(self):
        assert _horizontal_acceleration(3.0, 4.0, 9.8) == 5.0

    def test_invalid_scan_does_not_refresh_timestamp(self, monkeypatch):
        monkeypatch.setattr(sensor_hub.time, "monotonic", lambda: 100.0)
        fake = SimpleNamespace(
            _min_range=0.5,
            _scan_last_valid_wall=10.0,
            _scan_invalid=False,
            get_logger=lambda: self.FakeLogger(),
        )
        msg = SimpleNamespace(
            ranges=[float("nan"), float("-inf")],
            range_min=0.12,
            range_max=3.5,
        )
        sensor_hub.SensorHubNode._on_scan(fake, msg)
        assert fake._scan_last_valid_wall == 10.0
        assert fake._min_range == 0.5
        assert fake._scan_invalid is True

    def test_invalid_imu_does_not_refresh_timestamp(self, monkeypatch):
        monkeypatch.setattr(sensor_hub.time, "monotonic", lambda: 100.0)
        fake = SimpleNamespace(
            _linear_acc=0.5,
            _imu_last_valid_wall=10.0,
            _imu_invalid=False,
            get_logger=lambda: self.FakeLogger(),
        )
        msg = SimpleNamespace(
            linear_acceleration=SimpleNamespace(
                x=0.0, y=0.0, z=float("nan")))
        sensor_hub.SensorHubNode._on_imu(fake, msg)
        assert fake._imu_last_valid_wall == 10.0
        assert fake._linear_acc == 0.5
        assert fake._imu_invalid is True

    def test_missing_sensors_are_explicitly_dangerous(self):
        status = _format_sensor_status(
            now=100.0,
            min_range=None,
            linear_acc=0.0,
            scan_last_valid=0.0,
            imu_last_valid=0.0,
            scan_invalid=False,
            imu_invalid=False,
        )
        assert "⚠️ 危險" in status
        assert "LiDAR 尚未收到" in status
        assert "IMU 尚未收到" in status

    def test_stale_sensors_are_explicitly_dangerous(self):
        status = _format_sensor_status(
            now=100.0,
            min_range=1.0,
            linear_acc=0.2,
            scan_last_valid=90.0,
            imu_last_valid=90.0,
            scan_invalid=False,
            imu_invalid=False,
        )
        assert "⚠️ 危險" in status
        assert "LiDAR 已過期" in status
        assert "IMU 已過期" in status

    def test_fresh_valid_sensors_can_report_safe(self):
        status = _format_sensor_status(
            now=100.0,
            min_range=1.0,
            linear_acc=0.2,
            scan_last_valid=99.0,
            imu_last_valid=99.0,
            scan_invalid=False,
            imu_invalid=False,
        )
        assert "✅ 安全" in status


class TestVersionedStateSchemas:
    @pytest.mark.parametrize("state", ["safe", "danger"])
    def test_sensor_status_v1_roundtrip(self, state):
        detail = f"sensor state is {state}"
        payload = encode_sensor_status(state, detail)
        assert decode_sensor_status(payload) == (state, detail)

    @pytest.mark.parametrize(
        "payload",
        [
            "legacy display text: ✅ 安全",
            json.dumps({
                "detail": "ok",
                "schema": "dds-sensor-status/v2",
                "state": "safe",
            }),
            json.dumps({
                "detail": "ok",
                "extra": True,
                "schema": "dds-sensor-status/v1",
                "state": "safe",
            }),
            json.dumps({
                "detail": "ok",
                "schema": "dds-sensor-status/v1",
                "state": "unknown",
            }),
            json.dumps({
                "detail": 123,
                "schema": "dds-sensor-status/v1",
                "state": "safe",
            }),
            '{"schema":',
        ],
    )
    def test_sensor_status_unknown_or_malformed_input_fails_closed(
            self, payload):
        assert decode_sensor_status(payload) is None

    def test_security_state_v1_roundtrip_and_unknown_version_rejected(self):
        payload = encode_security_state(
            SECURITY_STATE_MONITOR_HEARTBEAT,
            "clear",
            "fresh authenticated heartbeat",
        )
        assert decode_security_state(payload) == (
            SECURITY_STATE_MONITOR_HEARTBEAT,
            "clear",
            "fresh authenticated heartbeat",
        )
        assert decode_security_state(json.dumps({
            "detail": "looks like a clear but uses an unknown schema",
            "kind": SECURITY_STATE_MONITOR_HEARTBEAT,
            "schema": "dds-security-state/v2",
            "state": "clear",
        })) is None

    def test_sensor_hub_publishes_signed_machine_state(self, monkeypatch):
        class FakeLogger:
            def info(self, *_args, **_kwargs):
                pass

        published = []
        monkeypatch.setattr(sensor_hub.time, "monotonic", lambda: 100.0)
        fake = SimpleNamespace(
            _min_range=1.0,
            _linear_acc=0.2,
            _scan_last_valid_wall=99.0,
            _imu_last_valid_wall=99.0,
            _scan_invalid=False,
            _imu_invalid=False,
            _secret=SECRET,
            _status_pub=SimpleNamespace(
                publish=lambda msg: published.append(msg)),
            get_logger=lambda: FakeLogger(),
        )

        sensor_hub.SensorHubNode._publish_status(fake)

        assert len(published) == 1
        payload = verify_alert(
            published[0].data,
            SECRET,
            expected_channel=CH_SENSOR,
        )
        assert payload is not None
        state, detail = decode_sensor_status(payload)
        assert state == "safe"
        assert "✅ 安全" in detail


class TestMissionSensorSafety:
    class FakeLogger:
        def info(self, *_args, **_kwargs):
            pass

        def warn(self, *_args, **_kwargs):
            pass

        def error(self, *_args, **_kwargs):
            pass

    @pytest.mark.parametrize(
        "payload",
        [
            "legacy display text: ✅ 安全",
            json.dumps({
                "detail": "claims safe",
                "schema": "dds-sensor-status/v2",
                "state": "safe",
            }),
            json.dumps({
                "detail": "claims safe",
                "extra": "ambiguous",
                "schema": "dds-sensor-status/v1",
                "state": "safe",
            }),
        ],
    )
    def test_authenticated_but_unknown_sensor_format_enters_fault(
            self, monkeypatch, payload):
        monkeypatch.setattr(
            mission_manager.time, "monotonic", lambda: 100.0)
        fake = SimpleNamespace(
            _alert_secret=SECRET,
            _sensor_replay_cache=ReplayCache(),
            _mission="PATROL",
            _last_sensor_status_wall=50.0,
            _last_sensor_state="safe",
            get_logger=lambda: self.FakeLogger(),
        )
        fake._set_mission = (
            lambda value: setattr(fake, "_mission", value))
        msg = SimpleNamespace(
            data=sign_alert(payload, SECRET, channel=CH_SENSOR))

        mission_manager.MissionManagerNode._on_sensor(fake, msg)

        assert fake._mission == "SENSOR_FAULT"
        assert fake._last_sensor_state == "invalid"
        assert fake._last_sensor_status_wall == 50.0

    def test_sensor_watchdog_expires_after_startup_grace(self, monkeypatch):
        now = [100.0 + mission_manager.SENSOR_STATUS_TIMEOUT_SEC - 0.1]
        monkeypatch.setattr(
            mission_manager.time, "monotonic", lambda: now[0])
        fake = SimpleNamespace(
            _mission="PATROL",
            _monitor_down=False,
            _startup_wall=100.0,
            _last_sensor_status_wall=0.0,
            _last_sensor_state="unknown",
            _alert_time=0.0,
            _cascade_quiet_until=0.0,
            _pause_history=[],
            get_logger=lambda: self.FakeLogger(),
        )
        fake._set_mission = (
            lambda value: setattr(fake, "_mission", value))
        fake._sensor_is_fresh = lambda current=None: (
            mission_manager.MissionManagerNode._sensor_is_fresh(
                fake, current))

        mission_manager.MissionManagerNode._check_recovery(fake)
        assert fake._mission == "PATROL"

        now[0] = (
            100.0 + mission_manager.SENSOR_STATUS_TIMEOUT_SEC + 0.1)
        mission_manager.MissionManagerNode._check_recovery(fake)
        assert fake._mission == "SENSOR_FAULT"


class TestIntelligentDefenseBoundaries:
    def test_nonfinite_cmd_is_physics_violation(self):
        fake = SimpleNamespace(
            _cmd_history=deque([(float("nan"), 0.0)], maxlen=20))
        triggered, detail = (
            defense_node.IntelligentDefenseNode._detect_d1_physics(fake))
        assert triggered is True
        assert "NaN/Infinity" in detail

    def test_stale_cmd_history_is_not_replayed_as_new_d1_event(
            self, monkeypatch):
        monkeypatch.setattr(defense_node.time, "monotonic", lambda: 100.0)
        fake = SimpleNamespace(
            _cmd_history=deque([(99.0, 0.0)], maxlen=20),
            _last_cmd_wall=90.0,
        )
        assert (
            defense_node.IntelligentDefenseNode._detect_d1_physics(fake)
            == (False, "")
        )

    def test_d6_reports_stale_stream_instead_of_comparing_old_samples(
            self, monkeypatch):
        monkeypatch.setattr(defense_node.time, "monotonic", lambda: 100.0)
        fake = SimpleNamespace(
            _cmd_history=deque([(0.1, 0.0)] * 5, maxlen=20),
            _scan_history=deque([[1.0] * 100] * 5, maxlen=20),
            _odom_twist_history=deque([(0.0, 0.0)] * 10, maxlen=20),
            _last_cmd_wall=90.0,
            _last_scan_wall=90.0,
            _last_odom_wall=90.0,
        )
        triggered, detail = (
            defense_node.IntelligentDefenseNode
            ._detect_d6_scan_odom_consistency(fake)
        )
        assert triggered is True
        assert "未更新" in detail

    def test_d1_physics_is_high_confidence_single_signal(self, monkeypatch):
        class FakeLogger:
            def warn(self, *_args, **_kwargs):
                pass

            def error(self, *_args, **_kwargs):
                pass

        monkeypatch.setattr(defense_node.time, "monotonic", lambda: 1.0)
        emitted = []
        fake = SimpleNamespace(
            _last_alert_time=-float("inf"),
            _heartbeat_alerted=False,
            _detector_hits={
                "D1": 0, "D2": 0, "D3": 0, "D4": 0, "D5": 0, "D6": 0,
            },
            _detect_d1_physics=lambda: (True, "cmd_lin=99.0"),
            _detect_d2_oscillation=lambda: (False, ""),
            _detect_d3_scan_repeat=lambda: (False, ""),
            _detect_d4_publishers=lambda: (False, ""),
            _check_heartbeat=lambda: (False, ""),
            _detect_d6_scan_odom_consistency=lambda: (False, ""),
            _emit_alert=lambda votes, details, reason: (
                emitted.append((votes, details, reason)) or True),
            get_logger=lambda: FakeLogger(),
        )
        defense_node.IntelligentDefenseNode._evaluate(fake)
        assert emitted == [(["D1"], ["D1[cmd_lin=99.0]"], "strong")]

    def test_never_received_heartbeat_eventually_alerts(self, monkeypatch):
        now = [100.0]
        monkeypatch.setattr(defense_node.time, "monotonic", lambda: now[0])
        fake = SimpleNamespace(
            _startup_wall=100.0,
            _last_heartbeat_wall=0.0,
        )
        assert defense_node.IntelligentDefenseNode._check_heartbeat(fake)[0] is False
        now[0] += defense_node.HEARTBEAT_TIMEOUT_SEC + 0.1
        triggered, detail = (
            defense_node.IntelligentDefenseNode._check_heartbeat(fake))
        assert triggered is True
        assert "從未收到" in detail

    def test_unknown_raw_dds_publisher_is_not_benign(self):
        endpoints = {
            "/cmd_vel": [SimpleNamespace(node_name="_NODE_NAME_UNKNOWN_")],
            "/scan": [],
            "/odom": [],
            "/imu": [],
        }

        class FakeDefense:
            def get_publishers_info_by_topic(self, topic):
                return endpoints[topic]

        triggered, detail = (
            defense_node.IntelligentDefenseNode._detect_d4_publishers(
                FakeDefense()))
        assert triggered is True
        assert "/cmd_vel" in detail

    @pytest.mark.parametrize(
        "failing_topic", ["/cmd_vel", "/scan", "/odom", "/imu"]
    )
    def test_d4_graph_query_failure_is_fail_safe(self, failing_topic):
        class FakeDefense:
            def get_publishers_info_by_topic(self, topic):
                if topic == failing_topic:
                    raise RuntimeError("untrusted graph failure " + "x" * 5000)
                return []

        triggered, detail = (
            defense_node.IntelligentDefenseNode._detect_d4_publishers(
                FakeDefense()
            )
        )
        assert triggered is True
        assert detail == "ROS graph inspection unavailable"
        assert len(detail) < 128

    def test_d5_fault_repeats_at_low_frequency_outside_normal_cooldown(
            self, monkeypatch):
        class FakeLogger:
            def warn(self, *_args, **_kwargs):
                pass

            def error(self, *_args, **_kwargs):
                pass

        now = [100.0]
        monkeypatch.setattr(defense_node.time, "monotonic", lambda: now[0])
        heartbeat_states = []
        normal_alerts = []
        fake = SimpleNamespace(
            _heartbeat_alerted=False,
            _last_heartbeat_fault_emit=-float("inf"),
            _last_alert_time=95.0,
            _detector_hits={
                "D1": 0, "D2": 0, "D3": 0, "D4": 0, "D5": 0, "D6": 0,
            },
            _detect_d1_physics=lambda: (False, ""),
            _detect_d2_oscillation=lambda: (False, ""),
            _detect_d3_scan_repeat=lambda: (False, ""),
            _detect_d4_publishers=lambda: (False, ""),
            _check_heartbeat=lambda: (True, "heartbeat missing"),
            _detect_d6_scan_odom_consistency=lambda: (False, ""),
            _emit_heartbeat_state=lambda state, detail: (
                heartbeat_states.append((state, detail)) or True),
            _emit_alert=lambda votes, details, reason: (
                normal_alerts.append((votes, details, reason)) or True),
            get_logger=lambda: FakeLogger(),
        )

        defense_node.IntelligentDefenseNode._evaluate(fake)
        assert heartbeat_states == [("fault", "heartbeat missing")]
        assert normal_alerts == []
        assert fake._heartbeat_alerted is True
        assert fake._last_heartbeat_fault_emit == 100.0

        now[0] = (
            100.0 + defense_node.HEARTBEAT_FAULT_REPEAT_SEC - 0.1)
        defense_node.IntelligentDefenseNode._evaluate(fake)
        assert heartbeat_states == [("fault", "heartbeat missing")]

        now[0] = (
            100.0 + defense_node.HEARTBEAT_FAULT_REPEAT_SEC + 0.1)
        defense_node.IntelligentDefenseNode._evaluate(fake)
        assert heartbeat_states == [
            ("fault", "heartbeat missing"),
            ("fault", "heartbeat missing"),
        ]
        assert normal_alerts == []

    def test_fresh_heartbeat_publishes_authenticated_clear_schema(
            self, monkeypatch):
        class FakeLogger:
            def info(self, *_args, **_kwargs):
                pass

            def warn(self, *_args, **_kwargs):
                pass

            def error(self, *_args, **_kwargs):
                pass

        published = []
        monkeypatch.setattr(defense_node.time, "monotonic", lambda: 100.0)
        fake = SimpleNamespace(
            _secret=SECRET,
            _hb_replay_cache=ReplayCache(),
            _last_heartbeat_wall=0.0,
            _heartbeat_alerted=True,
            _alert_pub=SimpleNamespace(
                publish=lambda msg: published.append(msg)),
            get_logger=lambda: FakeLogger(),
        )
        fake._emit_heartbeat_state = lambda state, detail: (
            defense_node.IntelligentDefenseNode._emit_heartbeat_state(
                fake, state, detail))
        heartbeat = SimpleNamespace(
            data=sign_alert(
                "monitor alive",
                SECRET,
                channel=CH_HEARTBEAT,
            ))

        defense_node.IntelligentDefenseNode._hb_cb(fake, heartbeat)

        assert fake._last_heartbeat_wall == 100.0
        assert fake._heartbeat_alerted is False
        assert len(published) == 1
        payload = verify_alert(
            published[0].data,
            SECRET,
            expected_channel=CH_ALERTS,
            cache=ReplayCache(),
        )
        assert decode_security_state(payload) == (
            SECURITY_STATE_MONITOR_HEARTBEAT,
            "clear",
            "收到新鮮且驗章成功的 monitor 心跳",
        )

    def test_publisher_flood_detail_is_bounded(self):
        endpoints = {
            "/cmd_vel": [
                SimpleNamespace(node_name=f"evil_{i}_" + "x" * 200)
                for i in range(100)
            ],
            "/scan": [],
            "/odom": [],
            "/imu": [],
        }

        class FakeDefense:
            def get_publishers_info_by_topic(self, topic):
                return endpoints[topic]

        triggered, detail = (
            defense_node.IntelligentDefenseNode._detect_d4_publishers(
                FakeDefense()))
        assert triggered is True
        assert "(+92 more)" in detail
        assert len(detail) < 1200


class TestMonitorGraphBounds:
    class Logger:
        def error(self, *_args, **_kwargs):
            pass

    def test_graph_overflow_preserves_baseline_and_aggregates(self, monkeypatch):
        monkeypatch.setattr(monitor_node.time, "monotonic", lambda: 100.0)
        baseline = {"/known"}
        published = []
        stops = []
        graph = [
            (f"node_{index}", "/")
            for index in range(monitor_node._GRAPH_NODE_MAX + 1)
        ]
        fake = SimpleNamespace(
            _known_nodes=baseline,
            _last_graph_overflow_alert=-float("inf"),
            _emergency_stop=True,
            get_node_names_and_namespaces=lambda: graph,
            get_logger=lambda: self.Logger(),
            _publish=published.append,
            _trigger_emergency_stop=lambda: stops.append(True),
        )

        monitor_node.DDSSecurityMonitor._check_graph(fake)
        assert fake._known_nodes is baseline
        assert len(published) == 1
        assert len(stops) == 1
        assert "node_" not in published[0]

        monitor_node.DDSSecurityMonitor._check_graph(fake)
        assert len(published) == 1
        assert len(stops) == 1


class TestMonitorDownLatch:
    class FakeLogger:
        def info(self, *_args, **_kwargs):
            pass

        def warn(self, *_args, **_kwargs):
            pass

        def error(self, *_args, **_kwargs):
            pass

    def test_mission_stays_stopped_until_authenticated_clear(
            self, monkeypatch):
        now = [100.0]
        monkeypatch.setattr(
            mission_manager.time, "monotonic", lambda: now[0])
        fake = SimpleNamespace(
            _alert_secret=SECRET,
            _alert_replay_cache=ReplayCache(),
            _mission="PATROL",
            _alert_time=0.0,
            _monitor_down=False,
            _startup_wall=90.0,
            _last_sensor_status_wall=100.0,
            _last_sensor_state="safe",
            _pause_history=[],
            _cascade_quiet_until=0.0,
            get_logger=lambda: self.FakeLogger(),
        )
        fake._set_mission = (
            lambda value: setattr(fake, "_mission", value))
        fake._sensor_is_fresh = lambda current=None: (
            mission_manager.MissionManagerNode._sensor_is_fresh(
                fake, current))

        fault = encode_security_state(
            SECURITY_STATE_MONITOR_HEARTBEAT,
            "fault",
            "monitor heartbeat missing",
        )
        mission_manager.MissionManagerNode._on_alert(
            fake,
            SimpleNamespace(
                data=sign_alert(fault, SECRET, channel=CH_ALERTS)),
        )
        assert fake._monitor_down is True
        assert fake._mission == "EMERGENCY_STOP"

        now[0] += mission_manager.EMERGENCY_RECOVERY_SEC + 0.1
        fake._last_sensor_status_wall = now[0]
        mission_manager.MissionManagerNode._check_recovery(fake)
        assert fake._mission == "EMERGENCY_STOP"

        clear = encode_security_state(
            SECURITY_STATE_MONITOR_HEARTBEAT,
            "clear",
            "monitor heartbeat restored",
        )
        mission_manager.MissionManagerNode._on_alert(
            fake,
            SimpleNamespace(data=clear),
        )
        assert fake._monitor_down is True
        assert fake._mission == "EMERGENCY_STOP"

        mission_manager.MissionManagerNode._on_alert(
            fake,
            SimpleNamespace(
                data=sign_alert(clear, SECRET, channel=CH_ALERTS)),
        )
        assert fake._monitor_down is False
        assert fake._mission == "EMERGENCY_STOP"

        mission_manager.MissionManagerNode._check_recovery(fake)
        assert fake._mission == "PATROL"

    def test_patrol_resume_is_blocked_until_authenticated_clear(
            self, monkeypatch):
        class FakeTimer:
            def __init__(self):
                self.cancelled = False

            def cancel(self):
                self.cancelled = True

        now = [100.0]
        monkeypatch.setattr(patrol_node.time, "monotonic", lambda: now[0])
        published = []
        fake = SimpleNamespace(
            _alert_secret=SECRET,
            _alert_replay_cache=ReplayCache(),
            _monitor_down=False,
            _cascade_dos_escalated=False,
            _cascade_dos_quiet_until=0.0,
            _pause_history=[],
            _paused=False,
            _alerts_during_pause=0,
            _resume_timer=None,
            _race_timer=None,
            _pos_x=0.0,
            _pos_y=0.0,
            _last_pos_x=0.0,
            _last_pos_y=0.0,
            _stuck_since=0.0,
            create_timer=lambda _delay, _callback: FakeTimer(),
            _pub=lambda v, w: published.append((v, w)),
            get_logger=lambda: self.FakeLogger(),
        )
        fake._resume = lambda: patrol_node.SmartPatrolNode._resume(fake)
        fake._race_pub_zero = (
            lambda: patrol_node.SmartPatrolNode._race_pub_zero(fake))
        fake._check_cascade_dos = (
            lambda: patrol_node.SmartPatrolNode._check_cascade_dos(fake))

        fault = encode_security_state(
            SECURITY_STATE_MONITOR_HEARTBEAT,
            "fault",
            "monitor heartbeat missing",
        )
        patrol_node.SmartPatrolNode._cb_alert(
            fake,
            SimpleNamespace(
                data=sign_alert(fault, SECRET, channel=CH_ALERTS)),
        )
        assert fake._monitor_down is True
        assert fake._paused is True
        assert published[-1] == (0, 0)

        now[0] = 140.0
        patrol_node.SmartPatrolNode._resume(fake)
        assert fake._paused is True
        assert published[-1] == (0, 0)

        clear = encode_security_state(
            SECURITY_STATE_MONITOR_HEARTBEAT,
            "clear",
            "monitor heartbeat restored",
        )
        patrol_node.SmartPatrolNode._cb_alert(
            fake,
            SimpleNamespace(
                data=sign_alert(clear, SECRET, channel=CH_ALERTS)),
        )
        assert fake._monitor_down is False
        assert fake._paused is False


class TestCascadeDetection:
    def test_second_pause_within_window_triggers(self):
        history, cascade = mission_manager._record_pause([], 100.0)
        assert cascade is False
        history, cascade = mission_manager._record_pause(history, 130.0)
        assert cascade is True
        assert history == [100.0, 130.0]

    def test_old_pause_is_pruned(self):
        history, cascade = mission_manager._record_pause(
            [0.0], mission_manager.CASCADE_WINDOW_SEC)
        assert cascade is False
        assert history == [mission_manager.CASCADE_WINDOW_SEC]

    def test_mission_manager_enters_and_enforces_quiet_window(self, monkeypatch):
        class FakeLogger:
            def info(self, *_args, **_kwargs):
                pass

            def warn(self, *_args, **_kwargs):
                pass

            def error(self, *_args, **_kwargs):
                pass

        now = [100.0]
        monkeypatch.setattr(mission_manager.time, "monotonic", lambda: now[0])
        fake = SimpleNamespace(
            _alert_secret=SECRET,
            _alert_replay_cache=ReplayCache(),
            _mission="PATROL",
            _alert_time=0.0,
            _monitor_down=False,
            _startup_wall=100.0,
            _last_sensor_status_wall=100.0,
            _last_sensor_state="safe",
            _pause_history=[70.0],
            _cascade_quiet_until=0.0,
            get_logger=lambda: FakeLogger(),
        )
        fake._set_mission = lambda value: setattr(fake, "_mission", value)
        fake._sensor_is_fresh = lambda current=None: (
            mission_manager.MissionManagerNode._sensor_is_fresh(
                fake, current))

        first = SimpleNamespace(
            data=sign_alert("cascade-2", SECRET, channel=CH_ALERTS))
        mission_manager.MissionManagerNode._on_alert(fake, first)
        assert fake._mission == "EMERGENCY_STOP"
        assert fake._cascade_quiet_until == pytest.approx(
            100.0 + mission_manager.CASCADE_QUIET_SEC)

        # 超過一般 30 秒 recovery 後，quiet 尚未結束，仍必須保持停車。
        now[0] = 140.0
        mission_manager.MissionManagerNode._check_recovery(fake)
        assert fake._mission == "EMERGENCY_STOP"

        # quiet 期間的合法告警不延長期限，但也絕不能讓任務回 PATROL。
        second = SimpleNamespace(
            data=sign_alert("cascade-3", SECRET, channel=CH_ALERTS))
        mission_manager.MissionManagerNode._on_alert(fake, second)
        assert fake._mission == "EMERGENCY_STOP"
        assert fake._pause_history == [70.0, 100.0]

        # quiet 期滿後才允許既有 recovery 邏輯恢復。
        now[0] = 100.0 + mission_manager.CASCADE_QUIET_SEC + 0.1
        fake._last_sensor_status_wall = now[0]
        mission_manager.MissionManagerNode._check_recovery(fake)
        assert fake._mission == "PATROL"
        assert fake._cascade_quiet_until == 0.0
        assert fake._pause_history == []

    def test_patrol_resume_is_deferred_until_quiet_expires(self, monkeypatch):
        class FakeTimer:
            def __init__(self):
                self.cancelled = False

            def cancel(self):
                self.cancelled = True

        class FakeLogger:
            def info(self, *_args, **_kwargs):
                pass

            def warn(self, *_args, **_kwargs):
                pass

        now = [140.0]
        monkeypatch.setattr(patrol_node.time, "monotonic", lambda: now[0])
        old_resume = FakeTimer()
        race = FakeTimer()
        scheduled = []
        published = []
        fake = SimpleNamespace(
            _monitor_down=False,
            _cascade_dos_escalated=True,
            _cascade_dos_quiet_until=220.0,
            _pause_history=[70.0, 100.0],
            _paused=True,
            _resume_timer=old_resume,
            _race_timer=race,
            _pos_x=0.0,
            _pos_y=0.0,
            _last_pos_x=0.0,
            _last_pos_y=0.0,
            _stuck_since=0.0,
            _resume=lambda: None,
            create_timer=lambda delay, callback: (
                scheduled.append((delay, callback)) or FakeTimer()),
            _pub=lambda v, w: published.append((v, w)),
            get_logger=lambda: FakeLogger(),
        )

        patrol_node.SmartPatrolNode._resume(fake)
        assert fake._paused is True
        assert race.cancelled is False
        assert old_resume.cancelled is True
        assert scheduled[-1][0] == pytest.approx(80.0)
        assert published[-1] == (0, 0)

        now[0] = 220.1
        patrol_node.SmartPatrolNode._resume(fake)
        assert fake._paused is False
        assert race.cancelled is True
        assert fake._cascade_dos_escalated is False
        assert fake._pause_history == []


# ════════════════════════════════════════════════════════════════
# 5. secret fingerprint 一致性
# ════════════════════════════════════════════════════════════════

class TestSecretFingerprint:
    def test_same_secret_same_fingerprint(self):
        """同 secret → 同 fingerprint（讓所有 node 互比對）。"""
        s = b"some_secret_bytes_xxxxxxxxxx"
        assert secret_fingerprint(s) == secret_fingerprint(s)

    def test_different_secret_different_fingerprint(self):
        assert secret_fingerprint(b"a" * 32) != secret_fingerprint(b"b" * 32)

    def test_fingerprint_is_short(self):
        """fingerprint 該短到可印 banner（16 hex chars = 8 bytes）。"""
        assert len(secret_fingerprint(b"x" * 32)) == 16


def test_security_log_profile_parses_and_carries_every_property():
    """Fast DDS falls back to defaults silently when a profile fails to parse.

    A single "--" inside an XML comment once disabled an entire profile in this
    project with no warning, and the loopback pilot recorded that a parseability
    test must be restored if a profile is ever reintroduced. This is that test.

    The property suffixes are checked against the spellings that actually exist
    in the installed build: LogOptions.h declares distribute, log_level and
    log_file, but the property literals in libfastrtps.so are logging_level and
    log_file. Writing log_level or logging_file would be accepted by the XML
    parser and then ignored, which is the same silent failure in a new place.
    """
    import xml.etree.ElementTree as ET
    from pathlib import Path

    profile = Path(__file__).resolve().parents[1] / "firewall_lab" / "fastdds_security_log.xml"
    assert profile.is_file(), "security log profile is missing"

    # Parsing must not raise: that is the failure mode being guarded.
    root = ET.parse(profile).getroot()

    ns = {"dds": "http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles"}
    properties = {
        prop.findtext("dds:name", namespaces=ns): prop.findtext("dds:value", namespaces=ns)
        for prop in root.iterfind(".//dds:property", ns)
    }

    assert properties.get("dds.sec.log.plugin") == "builtin.DDS_LogTopic"
    prefix = "dds.sec.log.builtin.DDS_LogTopic"
    assert properties.get(f"{prefix}.logging_level") == "WARNING_LEVEL"
    assert properties.get(f"{prefix}.distribute") == "false"

    log_file = properties.get(f"{prefix}.log_file")
    assert log_file and log_file.startswith("/"), "log_file must be an absolute path"
    assert not log_file.startswith("/mnt/"), (
        "the audit log may not live on the 9p mount; the telemetry socket "
        "already failed there with Errno 95"
    )

    # Spellings the binary does not contain would be silently ignored.
    for wrong in (f"{prefix}.log_level", f"{prefix}.logging_file"):
        assert wrong not in properties, f"{wrong} is not a property this build reads"


def test_security_log_profile_changes_nothing_but_logging():
    """The previous profile in this repo broke DDS while appearing to work.

    It set useBuiltinTransports=false with an interfaceWhiteList, and the
    resulting zero packets on the wire were mistaken for confinement until a
    positive control showed the talker delivered 0 messages against 22 without
    it. Transport and discovery must stay untouched here.
    """
    from pathlib import Path

    import re

    profile = Path(__file__).resolve().parents[1] / "firewall_lab" / "fastdds_security_log.xml"
    # Strip comments first: the file explains what the earlier broken profile
    # did, and naming a setting in prose is not the same as applying it.
    text = re.sub(r"<!--.*?-->", "", profile.read_text(encoding="utf-8"), flags=re.S)

    for forbidden in (
        "useBuiltinTransports",
        "interfaceWhiteList",
        "<transport_descriptors>",
        "userTransports",
        "<discovery_config>",
        "initialPeersList",
    ):
        assert forbidden not in text, (
            f"{forbidden} changes transport or discovery; this profile may only "
            "add security logging properties"
        )


def test_audit_log_name_matches_the_profile():
    """The orchestrator and the XML must agree on the filename.

    They are set in different files, so a rename in one would silently send the
    adapter back to following generic stack output -- the situation that
    produced 249,670 unclassifiable lines and two features with no source.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    profile = (root / "firewall_lab" / "fastdds_security_log.xml").read_text(
        encoding="utf-8"
    )
    from firewall_lab.orchestrator import SECURITY_AUDIT_LOG_NAME

    match = re.search(r"<value>(/[^<]*?)</value>", profile)
    assert match, "no absolute log_file path in the profile"
    assert match.group(1).endswith("/" + SECURITY_AUDIT_LOG_NAME), (
        f"profile writes {match.group(1)} but the orchestrator follows "
        f"{SECURITY_AUDIT_LOG_NAME}"
    )
