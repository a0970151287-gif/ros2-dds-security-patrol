"""`dds_identity` 遙測事件：IDS 唯一看得到 DDS 身份的管道。

ROS 把 DDS 身份完全抽象掉了，所以偵測層原本說得出「這像攻擊」卻說不出
「是哪一個 participant」。這個事件類型把 security observer 觀察到的
GUID 與認證判定送進 IDS 已經在讀的同一條遙測串流。

設計見 `文件/IDS與SROS2協作設計_2026-08-26.md`。
"""

from __future__ import annotations

import pytest

from firewall_lab.live_telemetry_collector import (
    EVENT_DETAIL_KEYS,
    _validate_details,
)
from firewall_lab.schema import SchemaError

GUID = "a25a104e1409ff76a1d8572d"
SUBJECT = "b" * 64


def test_event_type_is_registered_with_exact_keys():
    assert EVENT_DETAIL_KEYS["dds_identity"] == frozenset(
        {"guid_prefix", "verdict", "subject_sha256"}
    )


def test_unauthorized_participant_carries_no_subject():
    """認證失敗的 participant 沒有經驗證的 subject——這是實測結果，不是設計選擇。

    2026-08-26：wrong-CA participant 只產生 UNAUTHORIZED 認證事件，
    連一筆帶 claimed_subject 的 discovery 事件都沒有。
    """
    result = _validate_details("dds_identity", {
        "guid_prefix": GUID, "verdict": "unauthorized", "subject_sha256": None,
    })
    assert result["subject_sha256"] is None


def test_authorized_participant_requires_a_subject():
    """通過認證卻說不出身份的記錄沒有意義，必須拒絕。"""
    with pytest.raises(SchemaError, match="requires subject_sha256"):
        _validate_details("dds_identity", {
            "guid_prefix": GUID, "verdict": "authorized", "subject_sha256": None,
        })


def test_unauthorized_participant_may_not_claim_a_subject():
    """認證失敗卻帶著 subject，等於把未經驗證的宣稱當成身份。"""
    with pytest.raises(SchemaError, match="may not carry a subject"):
        _validate_details("dds_identity", {
            "guid_prefix": GUID, "verdict": "unauthorized",
            "subject_sha256": SUBJECT,
        })


@pytest.mark.parametrize("prefix", ["", "XX", "A" * 24, "a" * 23, "a" * 25])
def test_malformed_guid_prefix_is_rejected(prefix):
    with pytest.raises(SchemaError, match="guid_prefix"):
        _validate_details("dds_identity", {
            "guid_prefix": prefix, "verdict": "authorized",
            "subject_sha256": SUBJECT,
        })


def test_unknown_verdict_is_rejected():
    with pytest.raises(SchemaError, match="verdict"):
        _validate_details("dds_identity", {
            "guid_prefix": GUID, "verdict": "maybe", "subject_sha256": None,
        })


def test_extra_detail_keys_are_rejected():
    """詞彙表是固定的；多一個欄位就代表發送端與收集端對不上。"""
    with pytest.raises(SchemaError, match="unexpected detail keys"):
        _validate_details("dds_identity", {
            "guid_prefix": GUID, "verdict": "unauthorized",
            "subject_sha256": None, "source_ip": "127.0.0.1",
        })
