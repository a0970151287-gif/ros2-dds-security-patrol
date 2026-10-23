"""Offline bounds tests for the real-kernel nft acceptance executor.

This executor is the one program in the project that deliberately drops packets
on a live host, so the tests here are about **what it refuses to do**, not about
what it proves. Every bound in
``nft_backend_service.live_acceptance_plan()["future_executor_bounds"]`` gets an
assertion, and each refusal path gets a case that would fail if the guard were
removed.

Two hazards drive the anti-lockout tests:

* the host under test is reached over SSH, and blocking the SSH peer would make
  the operator's only remote path disappear mid-run;
* the acceptance preconditions require an isolated link, and a default route is
  the cheapest observable proof that the link is *not* isolated.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from firewall_lab import nft_backend_service as nft_module  # noqa: E402
from firewall_lab.nft_backend_service import (  # noqa: E402
    LIVE_ACCEPTANCE_APPROVAL,
    LIVE_ACCEPTANCE_SCHEMA_VERSION,
    NFT_BINARY,
    REQUIRED_LIVE_CHECKS,
    live_acceptance_plan,
    verify_live_acceptance,
)

_EXECUTOR_PATH = _ROOT / "工具腳本" / "run_nft_live_acceptance.py"


def _load():
    spec = importlib.util.spec_from_file_location("_nft_live_acceptance", _EXECUTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def executor():
    return _load()


@pytest.fixture(scope="module")
def source() -> str:
    return _EXECUTOR_PATH.read_text(encoding="utf-8")


def _code_only(text: str) -> str:
    """Strip comments and the module docstring.

    Assertions must look at code, not at prose describing the code. This bit me
    twice on 2026-09-20 in other test files, where a root-cause note quoting the
    old behaviour matched a substring assertion.
    """
    import ast

    lines = text.splitlines()
    tree = ast.parse(text)
    first = tree.body[0] if tree.body else None
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        lines = lines[first.end_lineno:]
    return "\n".join(l for l in lines if not l.lstrip().startswith("#"))


# ── the executor exists and the plan stops lying about it ────────────────────


def test_the_plan_now_reports_the_executor_as_implemented():
    """`live_executor_implemented` is a statement of fact, not a safety gate.

    Leaving it False once the executor exists would make the plan wrong. The
    real gate is `LIVE_NFT_ACTIVATION_ALLOWED`, asserted separately below.
    """
    plan = live_acceptance_plan()
    assert _EXECUTOR_PATH.is_file()
    assert plan["live_executor_implemented"] is True
    assert plan["human_approval_required"] is True
    assert plan["required_approval_phrase"] == LIVE_ACCEPTANCE_APPROVAL


def test_the_production_source_gate_is_still_closed():
    """Implementing the executor must not open production activation."""
    assert nft_module.LIVE_NFT_ACTIVATION_ALLOWED is False
    assert live_acceptance_plan()["production_source_gate"] is False


# ── bounds are copied from the plan, not invented ────────────────────────────


def test_executor_bounds_match_the_plan(executor):
    bounds = live_acceptance_plan()["future_executor_bounds"]
    assert executor.MAX_TEST_TTL_SEC == bounds["maximum_test_ttl_sec"]
    assert executor.TEST_SOURCES == bounds["test_sources"] == 1
    assert executor.APPLIED_TTL_SEC <= executor.MAX_TEST_TTL_SEC
    assert bounds["nft_binary"] == NFT_BINARY


def test_only_the_fixed_nft_binary_is_ever_invoked(source):
    body = _code_only(source)
    # Every subprocess argv literal must start from a fixed absolute path.
    assert "shell=True" not in body
    assert body.count("subprocess.run") == len(
        [l for l in body.splitlines() if "subprocess.run" in l]
    )
    for token in ('"nft"', "'nft'", "/bin/sh", "os.system", "popen"):
        assert token not in body, f"{token} must not appear in the executor"
    assert "NFT_BINARY" in body


def test_the_executor_never_flushes_or_persists(source):
    body = _code_only(source)
    for forbidden in ("flush ruleset", '"flush"', "'flush'", "nft -f /etc", "systemctl enable"):
        assert forbidden not in body, f"{forbidden!r} violates the declared bounds"


def test_it_neither_imports_nor_assigns_the_production_gate(source):
    """The executor may *mention* the gate when telling the operator what is
    still required; it must never import or assign it.

    The first version of this test searched for the bare name and failed on the
    closing message that says the gate still needs a source review -- an
    assertion about prose, not about behaviour. AST is the right resolution.
    """
    import ast

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                assert alias.name != "LIVE_NFT_ACTIVATION_ALLOWED", "must not import the gate"
        if isinstance(node, ast.Assign):
            for target in ast.walk(node):
                if isinstance(target, ast.Name):
                    assert target.id != "LIVE_NFT_ACTIVATION_ALLOWED", "must not assign the gate"
        if isinstance(node, ast.Attribute):
            assert node.attr != "LIVE_NFT_ACTIVATION_ALLOWED", "must not touch the gate"


# ── refusal paths ────────────────────────────────────────────────────────────


def test_non_root_is_refused_before_anything_else(executor, monkeypatch):
    monkeypatch.setattr(executor.os, "geteuid", lambda: 1000)
    with pytest.raises(executor.AcceptanceError, match="UID 0"):
        executor._require_root()


def test_the_exact_approval_phrase_is_required(executor):
    for wrong in ("", "yes", LIVE_ACCEPTANCE_APPROVAL.lower(), LIVE_ACCEPTANCE_APPROVAL + "X"):
        with pytest.raises(executor.AcceptanceError, match="approval phrase"):
            executor._require_approval(io.StringIO(wrong + "\n"))
    assert executor._require_approval(
        io.StringIO(LIVE_ACCEPTANCE_APPROVAL + "\n")
    ) == LIVE_ACCEPTANCE_APPROVAL


def _no_kernel_sessions(executor, monkeypatch, tmp_path):
    """Point the socket-table reader at paths that do not exist.

    Without this the suite would read the real /proc on a Linux host and the
    result would depend on who happens to be logged in at the time.
    """
    monkeypatch.setattr(executor, "_PROC_TCP", str(tmp_path / "absent-tcp"))
    monkeypatch.setattr(executor, "_PROC_TCP6", str(tmp_path / "absent-tcp6"))


def test_blocking_the_ssh_peer_is_refused(executor, monkeypatch, tmp_path):
    """The anti-lockout guard: never drop the path the operator arrived on."""
    _no_kernel_sessions(executor, monkeypatch, tmp_path)
    monkeypatch.setenv("SSH_CONNECTION", "192.168.137.50 51000 192.168.137.2 22")
    monkeypatch.setattr(executor, "_default_route_present", lambda: (False, ""))
    monkeypatch.setattr(executor, "_link_for", lambda a: "192.168.137.50 dev eth0 src 192.168.137.2")
    with pytest.raises(executor.AcceptanceError, match="SSH session"):
        executor._check_isolation("192.168.137.50")


def test_a_default_route_is_refused(executor, monkeypatch):
    """A default route means NAT/internet is reachable: not an isolated link."""
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(executor, "_default_route_present", lambda: (True, "default via 192.168.137.1"))
    with pytest.raises(executor.AcceptanceError, match="default route"):
        executor._check_isolation("192.168.137.50")


def test_a_routed_source_is_refused(executor, monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(executor, "_default_route_present", lambda: (False, ""))
    monkeypatch.setattr(executor, "_link_for", lambda a: "8.8.8.8 via 192.168.137.1 dev eth0")
    with pytest.raises(executor.AcceptanceError, match="directly connected"):
        executor._check_isolation("192.168.137.50")


def test_public_addresses_are_refused(executor, monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    with pytest.raises(executor.AcceptanceError, match="RFC1918"):
        executor._check_isolation("8.8.8.8")


def test_isolation_passes_only_when_every_condition_holds(executor, monkeypatch, tmp_path):
    _no_kernel_sessions(executor, monkeypatch, tmp_path)
    monkeypatch.setenv("SSH_CONNECTION", "192.168.137.1 51000 192.168.137.2 22")
    monkeypatch.setattr(executor, "_default_route_present", lambda: (False, ""))
    monkeypatch.setattr(executor, "_link_for", lambda a: "192.168.137.50 dev eth0 src 192.168.137.2")
    evidence = executor._check_isolation("192.168.137.50")
    assert "default_route=none" in evidence
    assert "ssh_peers=192.168.137.1" in evidence
    assert "source=SSH_CONNECTION" in evidence


# -- the anti-lockout guard must not depend on the environment ----------------

# A realistic /proc/net/tcp excerpt. Addresses are little-endian hex:
#   0289A8C0 -> 192.168.137.2 (local), 3289A8C0 -> 192.168.137.50 (remote).
# State 01 is ESTABLISHED, 0A is LISTEN; 0016 is port 22 and 1F90 is 8080.
_PROC_TCP_FIXTURE = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0289A8C0:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9001 1 0000000000000000 100 0 0 10 0
   1: 0289A8C0:0016 3289A8C0:C7B8 01 00000000:00000000 02:00000000 00000000  1000        0 9002 1 0000000000000000 20 4 30 10 -1
   2: 0289A8C0:1F90 0189A8C0:D431 01 00000000:00000000 02:00000000 00000000  1000        0 9003 1 0000000000000000 20 4 30 10 -1
"""


def test_the_lockout_guard_still_bites_when_sudo_strips_the_environment(
    executor, monkeypatch, tmp_path
):
    """The defect this replaced: `sudo` runs under `env_reset`.

    Measured on the Pi on 2026-09-21 -- under plain `sudo`, `SSH_CONNECTION` is
    empty while the kernel still lists the session. An env-only guard therefore
    reads None and protects nothing, silently. This test removes the variable
    entirely, so only the socket table can make the guard fire.
    """
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    proc = tmp_path / "tcp"
    proc.write_text(_PROC_TCP_FIXTURE, encoding="ascii")
    monkeypatch.setattr(executor, "_PROC_TCP", str(proc))
    monkeypatch.setattr(executor, "_PROC_TCP6", str(tmp_path / "absent-tcp6"))
    monkeypatch.setattr(executor, "_default_route_present", lambda: (False, ""))
    monkeypatch.setattr(executor, "_link_for", lambda a: "192.168.137.50 dev eth0")

    assert os.environ.get("SSH_CONNECTION") is None, "the variable must really be gone"
    with pytest.raises(executor.AcceptanceError, match="SSH session"):
        executor._check_isolation("192.168.137.50")


def test_only_established_sessions_on_the_ssh_port_count(executor, monkeypatch, tmp_path):
    """A listener and a session on another port must not become peers.

    Line 0 is the sshd listener (state 0A) and line 2 is an established
    connection from 192.168.137.1 to port 8080, not 22. Neither is a path whose
    loss would lock the operator out, so those addresses stay blockable.
    """
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    proc = tmp_path / "tcp"
    proc.write_text(_PROC_TCP_FIXTURE, encoding="ascii")
    monkeypatch.setattr(executor, "_PROC_TCP", str(proc))
    monkeypatch.setattr(executor, "_PROC_TCP6", str(tmp_path / "absent-tcp6"))

    peers, source = executor._ssh_peers()
    assert peers == {"192.168.137.50"}
    assert "proc-net-tcp(1)" in source


def test_no_sessions_is_a_measurement_not_a_missing_variable(executor, monkeypatch, tmp_path):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(executor, "_PROC_TCP", str(tmp_path / "absent-tcp"))
    monkeypatch.setattr(executor, "_PROC_TCP6", str(tmp_path / "absent-tcp6"))
    peers, source = executor._ssh_peers()
    assert peers == set()
    assert source == "none-observed"


def test_the_little_endian_socket_decoders_are_right(executor):
    assert executor._hex_to_ipv4("3289A8C0") == "192.168.137.50"
    assert executor._hex_to_ipv4("0100007F") == "127.0.0.1"
    # ::1 -- four little-endian words, the last holding 0x00000001.
    assert executor._hex_to_ipv6("00000000000000000000000001000000") == "::1"


def test_v4_mapped_peers_are_compared_as_ipv4(executor, monkeypatch, tmp_path):
    """sshd on a dual-stack host reports v4 clients as ::ffff:a.b.c.d.

    Left unmapped, the peer would never equal the dotted-quad test source and
    the guard would silently miss the very case it exists for.
    """
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    header = "  sl  local_address remote_address st"
    entry = (
        "   0: 0000000000000000FFFF00000289A8C0:0016 "
        "0000000000000000FFFF00003289A8C0:C7B8 01 00000000:00000000 "
        "02:00000000 00000000  1000 0 9004 1 0000000000000000 20 4 30 10 -1"
    )
    proc6 = tmp_path / "tcp6"
    proc6.write_text(chr(10).join([header, entry, ""]), encoding="ascii")
    monkeypatch.setattr(executor, "_PROC_TCP", str(tmp_path / "absent-tcp"))
    monkeypatch.setattr(executor, "_PROC_TCP6", str(proc6))
    peers, _ = executor._ssh_peers()
    assert peers == {"192.168.137.50"}


# ── the report contract ──────────────────────────────────────────────────────


def _report(passed: bool = True) -> dict:
    return {
        "schema_version": LIVE_ACCEPTANCE_SCHEMA_VERSION,
        "backend": "nftables_timeout_set",
        "simulation_only": False,
        "production_ready": passed,
        "host_firewall_modified": True,
        "checks": sorted(
            ({"id": name, "passed": passed, "evidence": f"evidence for {name}"}
             for name in REQUIRED_LIVE_CHECKS),
            key=lambda item: item["id"],
        ),
    }


def test_the_report_this_executor_writes_satisfies_the_real_verifier(tmp_path, monkeypatch):
    """Build the exact report shape and run the production validator on it."""
    import hashlib

    path = tmp_path / "report.json"
    raw = json.dumps(_report(True), sort_keys=True).encode("utf-8")
    path.write_bytes(raw)
    monkeypatch.setattr(nft_module, "_read_root_owned_file", lambda p, *, maximum_bytes: raw)
    value = verify_live_acceptance(path, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert value["production_ready"] is True


def test_a_failed_check_cannot_produce_an_enabling_report(tmp_path, monkeypatch):
    import hashlib

    broken = _report(True)
    broken["checks"][0]["passed"] = False
    raw = json.dumps(broken, sort_keys=True).encode("utf-8")
    path = tmp_path / "report.json"
    path.write_bytes(raw)
    monkeypatch.setattr(nft_module, "_read_root_owned_file", lambda p, *, maximum_bytes: raw)
    with pytest.raises(Exception, match="incomplete"):
        verify_live_acceptance(path, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_extra_report_keys_are_rejected_so_provenance_must_be_a_sidecar(tmp_path, monkeypatch):
    """`verify_live_acceptance` demands exactly six keys.

    This is why the executor writes host/kernel/scope provenance to a separate
    `.provenance.json` instead of enriching the report.
    """
    import hashlib

    enriched = _report(True)
    enriched["host"] = "pi"
    raw = json.dumps(enriched, sort_keys=True).encode("utf-8")
    path = tmp_path / "report.json"
    path.write_bytes(raw)
    monkeypatch.setattr(nft_module, "_read_root_owned_file", lambda p, *, maximum_bytes: raw)
    with pytest.raises(Exception, match="fields are invalid"):
        verify_live_acceptance(path, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_executor_emits_every_required_check_id(source):
    """Each required id must be recorded somewhere in the executor."""
    body = _code_only(source)
    for name in REQUIRED_LIVE_CHECKS:
        assert f'"{name}"' in body, f"executor never records {name}"
