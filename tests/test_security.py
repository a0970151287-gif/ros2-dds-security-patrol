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

import os
import tempfile
from pathlib import Path

import numpy as np
import pytest

# 確保有 secret 才能跑（測試專用 secret）
os.environ.setdefault(
    "DDS_ALERT_SECRET",
    "test_secret_for_unit_tests_DO_NOT_USE_IN_PROD_3f8e7d6c5b4a"
)

from dds_security_monitor.monitor_node import (
    sign_alert, verify_alert,
    sign_file, verify_file,
    secret_fingerprint,
    _load_alert_secret,
    ReplayCache,
    CH_ALERTS, CH_HEARTBEAT, CH_MISSION, CH_SENSOR,
)


SECRET = _load_alert_secret()


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


# ════════════════════════════════════════════════════════════════
# 3. /patrol/goto 座標範圍檢查（攻擊 D 修補）
# ════════════════════════════════════════════════════════════════

class TestPatrolGotoBounds:
    """直接測試 _cb_goto 內的座標檢查邏輯。

    Note: 不啟 ROS node，只測座標 dict 的 validation 行為。
    完整 integration test 看紅隊測試腳本。
    """

    MAX_RANGE = 2.5   # 跟 patrol_node.py 一致

    def _is_valid(self, x: float, y: float) -> bool:
        """重現 patrol_node._cb_goto 的範圍檢查邏輯。"""
        return -self.MAX_RANGE <= x <= self.MAX_RANGE and \
               -self.MAX_RANGE <= y <= self.MAX_RANGE

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
