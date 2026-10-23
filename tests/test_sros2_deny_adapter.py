"""Regression tests derived from the real 1,100-session log audit."""

from __future__ import annotations

import pytest

from firewall_lab.sros2_deny_adapter import (
    Sros2DenyLogAdapter,
    classify_sros2_deny,
)


@pytest.mark.parametrize(
    "line",
    [
        (
            "[ERROR] [1785133895.1] [mission_manager]: monitor heartbeat "
            "still failed; only accept IDS authenticated clear"
        ),
        (
            "[WARN] [1785133895.2] [intelligent_defense_node]: "
            "D4[scan unauthorized pub: ['talker']]"
        ),
        "PermissionError: [Errno 13] Permission denied",
        "authentication cache invalid; rebuilding",
        "participant authenticated successfully with 0 errors reported",
        "Failed to publish: publisher's context is invalid",
        "Could not find service /dds_security_monitor/set_parameters",
        (
            "[INFO] [1785133895.3] [rcl]: Found security directory: "
            "/redacted/enclaves/patrol_node"
        ),
    ],
)
def test_real_application_and_attack_logs_do_not_forge_sros2_denials(line):
    assert classify_sros2_deny(line) is None


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        ("Handshake failed: ", "authentication"),
        (
            "Unable to authenticate the message. EVP_DecryptFinal_ex "
            "function returns an error",
            "authentication",
        ),
        ("access permission denied", "permission"),
        ("Topic denied by deny rule.", "permission"),
        ("Error loading Governance XML", "governance"),
    ],
)
def test_precise_fastdds_vendor_fragments_remain_classified(line, kind):
    assert classify_sros2_deny(line) == kind


class _Producer:
    def __init__(self, *, succeeds: bool) -> None:
        self.succeeds = succeeds

    def emit_sros2_deny(self, _kind: str) -> bool:
        return self.succeeds


def test_summary_separates_no_observation_from_a_sent_deny():
    adapter = Sros2DenyLogAdapter(_Producer(succeeds=True))
    adapter.ingest_line("ordinary stack output")
    adapter.ingest_line(
        "[ERROR] [1785133895.1] [mission_manager]: authenticated clear failed"
    )
    assert adapter.summary() == {
        "lines_seen": 2,
        "records_classified": 0,
        "denies_emitted": 0,
        "send_failures": 0,
        "ignored": 2,
        "oversize_lines": 0,
        "ros_application_lines": 1,
        "observability": "no_deny_records_observed",
    }

    adapter.ingest_line("Access control permission denied for topic rt/cmd_vel")
    assert adapter.summary()["records_classified"] == 1
    assert adapter.summary()["denies_emitted"] == 1
    assert adapter.summary()["observability"] == "deny_records_observed"


def test_summary_distinguishes_classification_from_socket_send_failure():
    adapter = Sros2DenyLogAdapter(_Producer(succeeds=False))
    assert adapter.ingest_line("Handshake failed: remote participant") == (
        "authentication"
    )
    summary = adapter.summary()
    assert summary["records_classified"] == 1
    assert summary["denies_emitted"] == 0
    assert summary["send_failures"] == 1


def test_oversize_line_is_counted_and_never_classified():
    adapter = Sros2DenyLogAdapter(_Producer(succeeds=True))
    adapter.ingest_line("Handshake failed: " + "x" * 9000)
    summary = adapter.summary()
    assert summary["lines_seen"] == 1
    assert summary["oversize_lines"] == 1
    assert summary["records_classified"] == 0
    assert summary["ignored"] == 1
