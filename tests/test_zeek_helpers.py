"""Zeek helper safety regression tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SEND_LINE_PATH = ROOT / "Zeek監控" / "send_line.py"
BLOCK_SOURCE_PATH = ROOT / "Zeek監控" / "block_source.sh"
ZEEK_MONITOR_PATH = ROOT / "Zeek監控" / "dds_monitor.zeek"
PCAP_GENERATOR_PATH = ROOT / "Zeek監控" / "test" / "gen_test_pcap.py"
FIREWALL_PATH = ROOT / "跨主機紅隊" / "dos_firewall.sh"
INSTALLER_PATH = ROOT / "工具腳本" / "install_zeek_helpers.sh"
REVOKER_PATH = ROOT / "工具腳本" / "revoke_legacy_zeek_privileges.sh"


def _load_send_line_module():
    spec = importlib.util.spec_from_file_location("zeek_send_line", SEND_LINE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_zeek_fixture(
    tmp_path: Path,
    case: str,
    *,
    redefinitions: tuple[str, ...] = (),
) -> str:
    """Run one deterministic offline pcap without invoking a real notifier."""
    zeek = shutil.which("zeek")
    if zeek is None:
        pytest.skip("zeek is required")
    pcap = tmp_path / f"{case}.pcap"
    generated = subprocess.run(
        [
            sys.executable,
            str(PCAP_GENERATOR_PATH),
            str(pcap),
            "--case",
            case,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generated.returncode == 0, generated.stderr
    assert pcap.is_file() and pcap.stat().st_size > 24

    wrapper = tmp_path / "offline_test.zeek"
    wrapper.write_text(
        "\n".join(
            [
                f"@load {ZEEK_MONITOR_PATH}",
                'redef SEND_LINE_SCRIPT = "/bin/true";',
                *redefinitions,
                "",
            ]
        ),
        encoding="utf-8",
    )
    command = [
        zeek,
        "-Cr",
        str(pcap),
        str(wrapper),
    ]
    result = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_line_token_requires_private_file_permissions(tmp_path, monkeypatch):
    helper = _load_send_line_module()
    config = tmp_path / ".config" / "dds-monitor"
    config.mkdir(parents=True)
    token = config / "line_token"
    token.write_text("secret-token\n", encoding="utf-8")

    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    token.chmod(0o600)
    assert helper.load_file_cred("line_token", secret=True) == "secret-token"

    token.chmod(0o644)
    assert helper.load_file_cred("line_token", secret=True) == ""


def test_line_token_does_not_fall_back_to_environment(tmp_path, monkeypatch):
    helper = _load_send_line_module()
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("LINE_CHANNEL_TOKEN", "environment-secret")

    assert helper.load_file_cred("line_token", secret=True) == ""


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")
@pytest.mark.parametrize(
    "arguments",
    [(), ("10.10.10.1", "300"), ("apply", "--ticket-stdin")],
)
def test_legacy_block_source_is_always_fail_closed(arguments):
    result = subprocess.run(
        ["bash", str(BLOCK_SOURCE_PATH), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "disabled" in result.stderr.lower()


def test_legacy_block_source_contains_no_firewall_action():
    helper = BLOCK_SOURCE_PATH.read_text(encoding="utf-8")

    assert "iptables" not in helper
    assert "nft " not in helper
    assert "sleep " not in helper
    assert "${1" not in helper
    assert "${2" not in helper


def test_privileged_helpers_use_fixed_installed_paths():
    firewall = FIREWALL_PATH.read_text(encoding="utf-8")
    installer = INSTALLER_PATH.read_text(encoding="utf-8")

    assert 'readonly IFACE="eth0"' in firewall
    assert 'readonly PEER="10.10.10.1"' in firewall
    assert 'readonly SELF="10.10.10.2"' in firewall
    assert "${IFACE:-" not in firewall
    assert "${PEER:-" not in firewall
    assert "/usr/local/libexec/dds-monitor" in installer
    assert "install -o root -g root -m 0755" in installer
    assert "block-source *" not in installer
    assert "NOPASSWD:" not in installer
    assert 'install -o root -g root -m 0755 "$LEGACY_BLOCK"' not in installer
    assert 'install -o root -g root -m 0755 "$LEGACY_DOS"' not in installer
    assert "legacy_sudoers=(/etc/sudoers.d/dds-monitor-block-*)" in installer
    assert "revoke_legacy_zeek_privileges.sh" in installer
    assert "exit 3" in installer


def test_legacy_privilege_revocation_is_exact_and_recoverable():
    revoker = REVOKER_PATH.read_text(encoding="utf-8")

    assert 'readonly LEGACY_BLOCK="$DEST_DIR/block-source"' in revoker
    assert 'readonly LEGACY_DOS="$DEST_DIR/dos-firewall"' in revoker
    assert 'readonly LEGACY_SUDOERS="/etc/sudoers.d/dds-monitor-block-${CALLER}"' in revoker
    assert "--confirm-revoke" in revoker
    assert "mktemp -d" in revoker
    assert 'mv -- "$source"' in revoker
    assert "visudo -cf /etc/sudoers" in revoker
    assert 'sudo -n -l -U "$CALLER"' in revoker
    assert "|| true" not in revoker
    assert "stat -c '%u:%g:%a'" in revoker
    assert "mountpoint -q" in revoker
    assert "不得作為 Zeek/ML 服務帳號" in revoker
    assert "rm -" not in revoker


@pytest.mark.skipif(shutil.which("zeek") is None, reason="zeek is required")
def test_zeek_existing_rules_keep_expected_offline_metrics(tmp_path):
    output = _run_zeek_fixture(tmp_path, "baseline")

    assert (
        "DDS_MONITOR_METRICS recon=1 inject=1 dos=1 stealth_dos=0 "
        "param=1 spoof=1 state_capacity_drops=0"
    ) in output
    assert (
        output.count(
            "DDS_MONITOR_EVENT kind=spdp_dos source=10.10.10.1 count=25"
        )
        == 1
    )


@pytest.mark.skipif(shutil.which("zeek") is None, reason="zeek is required")
def test_zeek_spdp_threshold_is_per_source_not_global(tmp_path):
    mixed = _run_zeek_fixture(tmp_path / "mixed", "mixed-sources")
    assert "DDS_MONITOR_EVENT kind=spdp_dos" not in mixed
    assert "dos=0" in mixed

    one_source = _run_zeek_fixture(
        tmp_path / "single",
        "single-source-threshold",
    )
    event = "DDS_MONITOR_EVENT kind=spdp_dos source=10.10.10.1 count=25"
    assert one_source.count(event) == 1
    assert "dos=1" in one_source


@pytest.mark.skipif(shutil.which("zeek") is None, reason="zeek is required")
def test_zeek_spdp_does_not_accumulate_across_windows(tmp_path):
    output = _run_zeek_fixture(tmp_path, "cross-window")

    assert "DDS_MONITOR_EVENT kind=spdp_dos" not in output
    assert "dos=0" in output


@pytest.mark.skipif(shutil.which("zeek") is None, reason="zeek is required")
def test_zeek_tracking_state_has_hard_capacity(tmp_path):
    output = _run_zeek_fixture(
        tmp_path,
        "capacity",
        redefinitions=(
            "redef MAX_TRACKED_DDS_NODES = 2;",
            "redef MAX_SPDP_SOURCES = 2;",
        ),
    )

    assert (
        "DDS_MONITOR_STATE_CAPACITY kind=dds_nodes "
        "action=drop_new_state"
    ) in output
    assert "state_capacity_drops=2" in output
    assert "tracked_dds_nodes=2" in output
    assert "spdp_sources=2" in output


def test_zeek_active_blocking_remains_opt_in_and_state_is_expiring():
    monitor = ZEEK_MONITOR_PATH.read_text(encoding="utf-8")

    assert "const DOS_BLOCK_ENABLED: bool = F &redef;" in monitor
    assert "&create_expire = TRACKING_STATE_TTL" in monitor
    assert "&write_expire = DOS_WINDOW" in monitor
    assert "MAX_SPDP_EVENTS_PER_SOURCE" in monitor


def test_zeek_sensor_cannot_bypass_response_authorizer():
    monitor = ZEEK_MONITOR_PATH.read_text(encoding="utf-8")
    assert "status=suppressed reason=response_authorizer_required" in monitor
    assert "sudo -n %s %s %d" not in monitor
    assert "Exec::run(bcmd)" not in monitor
