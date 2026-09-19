from __future__ import annotations

import hashlib
import inspect
import io
import json
import re
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import firewall_lab.nft_backend_service as nft_module
from firewall_lab.nft_backend_service import (
    ENABLEMENT_SCHEMA_VERSION,
    EXPECTED_RULE_EXPRESSION,
    LIVE_ACCEPTANCE_APPROVAL,
    LIVE_ACCEPTANCE_PLAN_SCHEMA_VERSION,
    LIVE_SCOPE_ACK,
    LIVE_NFT_ACTIVATION_ALLOWED,
    MAX_RESPONSE_TTL_SEC,
    MOCK_ACCEPTANCE_SCHEMA_VERSION,
    NFT_BINARY,
    NFT_CHAIN,
    NFT_CHAIN_COMMENT,
    NFT_CHAIN_PRIORITY,
    NFT_FAMILY,
    NFT_GC_INTERVAL_SEC,
    NFT_RULE_COMMENT,
    NFT_SET,
    NFT_SET_COMMENT,
    NFT_SET_SIZE,
    NFT_TABLE,
    NFT_TRAFFIC_SCOPE,
    PRODUCTION_BACKEND_ID,
    PRODUCTION_ACTION,
    NftCommandResult,
    NftRunner,
    NftablesTimeoutSetAdapter,
    PrivilegedNftBackendService,
    SubprocessNftRunner,
    main,
    live_acceptance_plan,
    render_bootstrap_ruleset_for_review,
    validate_enablement,
    verify_live_acceptance,
    write_mock_acceptance_report,
)
from firewall_lab.response_backend import (
    DEFAULT_MAX_AUDIT_EVENTS,
    DEFAULT_MAX_CONSUMED_TICKETS,
    BackendApplyError,
    BackendUnavailableError,
    DesiredResponse,
    Ed25519TicketIssuer,
    ResponseBackend,
    SQLiteResponseState,
    TicketVerificationError,
)


NOW_NS = 2_000_000_000_000_000_000


class MockNftRunner(NftRunner):
    production = False

    def __init__(self):
        self.entries: dict[str, int] = {}
        self.checked_batches: list[str] = []
        self.applied_batches: list[str] = []
        self.fail_check = False
        self.fail_apply = False
        self.mutate_document = None

    def document(self):
        document = {
            "nftables": [
                {"metainfo": {"json_schema_version": 1}},
                {"table": {"family": NFT_FAMILY, "name": NFT_TABLE}},
                {
                    "set": {
                        "family": NFT_FAMILY,
                        "table": NFT_TABLE,
                        "name": NFT_SET,
                        "type": "ipv4_addr",
                        "flags": ["timeout"],
                        "size": NFT_SET_SIZE,
                        "timeout": MAX_RESPONSE_TTL_SEC * 1000,
                        "gc-interval": NFT_GC_INTERVAL_SEC * 1000,
                        "policy": "memory",
                        "comment": NFT_SET_COMMENT,
                        "elem": [
                            {
                                "elem": {
                                    "val": source,
                                    "timeout": ttl_sec * 1000,
                                    "expires": ttl_sec * 1000,
                                }
                            }
                            for source, ttl_sec in sorted(self.entries.items())
                        ],
                    }
                },
                {
                    "chain": {
                        "family": NFT_FAMILY,
                        "table": NFT_TABLE,
                        "name": NFT_CHAIN,
                        "type": "filter",
                        "hook": "input",
                        "prio": NFT_CHAIN_PRIORITY,
                        "policy": "accept",
                        "comment": NFT_CHAIN_COMMENT,
                    }
                },
                {
                    "rule": {
                        "family": NFT_FAMILY,
                        "table": NFT_TABLE,
                        "chain": NFT_CHAIN,
                        "comment": NFT_RULE_COMMENT,
                        "expr": EXPECTED_RULE_EXPRESSION,
                    }
                },
            ]
        }
        if self.mutate_document is not None:
            self.mutate_document(document)
        return document

    @staticmethod
    def _result(return_code=0, stdout="", stderr=""):
        return NftCommandResult(("mock",), return_code, stdout, stderr)

    def list_fixed_table_json(self):
        return self._result(stdout=json.dumps(self.document(), sort_keys=True))

    def check_fixed_batch(self, batch):
        self.checked_batches.append(batch)
        return self._result(1, stderr="mock check rejected") if self.fail_check else self._result()

    def apply_fixed_batch(self, batch):
        self.applied_batches.append(batch)
        if self.fail_apply:
            return self._result(1, stderr="mock apply rejected")
        for line in batch.splitlines():
            delete = re.fullmatch(
                rf"delete element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} \{{ ([0-9.]+) \}}",
                line,
            )
            if delete:
                self.entries.pop(delete.group(1), None)
                continue
            add = re.fullmatch(
                rf"add element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} "
                r"\{ ([0-9.]+) timeout ([0-9]+)s \}",
                line,
            )
            if not add:
                return self._result(1, stderr=f"unexpected mock batch: {line}")
            self.entries[add.group(1)] = int(add.group(2))
        return self._result()


def _desired(source="10.77.0.10", seconds=30):
    return DesiredResponse(
        source=source,
        action=PRODUCTION_ACTION,
        adapter="network_helper",
        backend_id=PRODUCTION_BACKEND_ID,
        evidence_id="a" * 64,
        expires_at_ns=NOW_NS + seconds * 1_000_000_000,
        updated_at_ns=NOW_NS,
    )


def _disabled_config(**overrides):
    value = {
        "schema_version": ENABLEMENT_SCHEMA_VERSION,
        "enabled": False,
        "backend_id": PRODUCTION_BACKEND_ID,
        "authorized_sources": [],
        "protected_sources": [],
        "max_active_sources": NFT_SET_SIZE,
        "max_consumed_tickets": DEFAULT_MAX_CONSUMED_TICKETS,
        "max_audit_events": DEFAULT_MAX_AUDIT_EVENTS,
        "live_acceptance_sha256": "",
        "scope_ack": "",
    }
    value.update(overrides)
    return value


def test_bootstrap_ruleset_is_fixed_bounded_and_not_an_installer():
    text = render_bootstrap_ruleset_for_review()
    assert f"table {NFT_FAMILY} {NFT_TABLE}" in text
    assert f"set {NFT_SET}" in text
    assert "type ipv4_addr" in text
    assert "flags timeout" in text
    assert f"timeout {MAX_RESPONSE_TTL_SEC}s" in text
    assert f"size {NFT_SET_SIZE}" in text
    assert f"chain {NFT_CHAIN}" in text
    assert f"priority {NFT_CHAIN_PRIORITY}" in text
    assert f"ip saddr @{NFT_SET} counter drop" in text
    assert "sudo" not in text
    assert "flush ruleset" not in text


def test_drop_rule_requires_explicit_temporary_block_not_rate_limit():
    adapter = NftablesTimeoutSetAdapter(MockNftRunner())
    with pytest.raises(BackendApplyError, match="temporary_block"):
        adapter.apply(replace(_desired(), action="rate_limit"), now_ns=NOW_NS)


def test_signed_rate_limit_ticket_cannot_reach_temporary_block_adapter(tmp_path):
    issuer = Ed25519TicketIssuer.generate()
    runner = MockNftRunner()
    backend = ResponseBackend(
        verifier=issuer.verifier(),
        state=SQLiteResponseState(tmp_path / "semantic.sqlite3"),
        timeout_set=NftablesTimeoutSetAdapter(runner),
        backend_id=PRODUCTION_BACKEND_ID,
        authorized_sources=("10.77.0.0/24",),
        network_action=PRODUCTION_ACTION,
    )
    ticket = issuer.issue(
        evidence_id="a" * 64,
        source="10.77.0.10",
        source_kind="network_ip",
        action="rate_limit",
        adapter="network_helper",
        backend_id=PRODUCTION_BACKEND_ID,
        interface="mock0",
        identity="pytest",
        response_ttl_sec=30,
        issued_at_ns=NOW_NS,
        nonce="b" * 32,
    )
    with pytest.raises(TicketVerificationError, match="fixed signed contract"):
        backend.apply_ticket(ticket, now_ns=NOW_NS)
    assert runner.checked_batches == []
    assert runner.applied_batches == []


def test_subprocess_runner_uses_only_fixed_argv_stdin_and_shell_false(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"nftables":[]}', stderr="")

    monkeypatch.setattr(nft_module.subprocess, "run", fake_run)
    runner = SubprocessNftRunner()
    runner.list_fixed_table_json()
    batch = (
        f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} "
        "{ 10.77.0.10 timeout 30s }\n"
    )
    runner.check_fixed_batch(batch)
    runner.apply_fixed_batch(batch)
    assert calls[0][0] == [
        NFT_BINARY,
        "--numeric",
        "--json",
        "list",
        "table",
        NFT_FAMILY,
        NFT_TABLE,
    ]
    assert calls[1][0] == [NFT_BINARY, "--check", "--file", "-"]
    assert calls[2][0] == [NFT_BINARY, "--file", "-"]
    for argv, kwargs in calls:
        assert kwargs["shell"] is False
        assert kwargs["cwd"] == "/"
        assert kwargs["env"]["PATH"] == "/usr/sbin:/usr/bin:/bin"
        assert "10.77.0.10" not in argv
    assert calls[1][1]["input"] == batch
    assert calls[2][1]["input"] == batch

    monkeypatch.setattr(
        nft_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(args[0], timeout=5)
        ),
    )
    with pytest.raises(BackendUnavailableError, match="timed out"):
        runner.list_fixed_table_json()

    called = False

    def must_not_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("invalid batch must be rejected before subprocess")

    monkeypatch.setattr(nft_module.subprocess, "run", must_not_run)
    with pytest.raises(BackendUnavailableError, match="non-fixed statement"):
        runner.apply_fixed_batch("flush ruleset\n")
    assert called is False


def test_adapter_applies_per_element_timeout_and_reconciles_exact_state():
    runner = MockNftRunner()
    adapter = NftablesTimeoutSetAdapter(runner)
    response = _desired()
    adapter.apply(response, now_ns=NOW_NS)
    assert runner.entries == {"10.77.0.10": 30}
    assert len(runner.checked_batches) == 1
    assert runner.checked_batches == runner.applied_batches
    assert "10.77.0.10 timeout 30s" in runner.applied_batches[0]

    runner.entries["10.77.0.99"] = 60
    desired = {
        "10.77.0.10": replace(response, expires_at_ns=NOW_NS + 20_000_000_000),
        "10.77.0.11": _desired("10.77.0.11", 15),
    }
    adapter.reconcile(desired, now_ns=NOW_NS)
    assert runner.entries == {"10.77.0.10": 20, "10.77.0.11": 15}
    batch = runner.applied_batches[-1]
    assert f"delete element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} {{ 10.77.0.99 }}" in batch
    assert "10.77.0.11 timeout 15s" in batch


@pytest.mark.parametrize("source", ["010.077.0.10", "2001:db8::1", "10.77.0.0/24", "x; flush ruleset"])
def test_adapter_rejects_noncanonical_or_non_ipv4_sources(source):
    adapter = NftablesTimeoutSetAdapter(MockNftRunner())
    with pytest.raises(BackendApplyError, match="canonical IPv4"):
        adapter.apply(_desired(source), now_ns=NOW_NS)


def test_snapshot_rejects_namespace_rule_size_and_timed_element_drift():
    mutations = [
        lambda value: value["nftables"][1]["table"].update(name="wrong"),
        lambda value: value["nftables"][2]["set"].update(size=NFT_SET_SIZE + 1),
        lambda value: value["nftables"][3]["chain"].update(policy="drop"),
        lambda value: value["nftables"][4]["rule"].update(comment="wrong"),
    ]
    for mutate in mutations:
        runner = MockNftRunner()
        runner.mutate_document = mutate
        adapter = NftablesTimeoutSetAdapter(runner)
        with pytest.raises(BackendApplyError, match="not exact|contract"):
            adapter.snapshot(now_ns=NOW_NS)

    runner = MockNftRunner()
    runner.entries["10.77.0.10"] = MAX_RESPONSE_TTL_SEC + 1
    with pytest.raises(BackendApplyError, match="timeout exceeds"):
        NftablesTimeoutSetAdapter(runner).snapshot(now_ns=NOW_NS)


def test_check_or_apply_failure_stops_without_claiming_success():
    runner = MockNftRunner()
    runner.fail_check = True
    adapter = NftablesTimeoutSetAdapter(runner)
    with pytest.raises(BackendApplyError, match="check failed closed"):
        adapter.apply(_desired(), now_ns=NOW_NS)
    assert runner.applied_batches == []

    runner = MockNftRunner()
    runner.fail_apply = True
    adapter = NftablesTimeoutSetAdapter(runner)
    with pytest.raises(BackendApplyError, match="batch failed closed"):
        adapter.apply(_desired(), now_ns=NOW_NS)


def test_production_runner_rejects_non_root_before_any_nft_call(monkeypatch):
    called = False

    def forbidden(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("nft must not run")

    monkeypatch.setattr(nft_module.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(nft_module.subprocess, "run", forbidden)
    adapter = NftablesTimeoutSetAdapter()
    with pytest.raises(BackendUnavailableError, match="UID 0"):
        adapter.snapshot(now_ns=NOW_NS)
    assert called is False


def test_privileged_service_api_is_ticket_only_and_mock_runner_cannot_start(monkeypatch, tmp_path):
    signature = inspect.signature(PrivilegedNftBackendService.handle_ticket)
    assert list(signature.parameters) == ["self", "ticket"]
    assert not hasattr(PrivilegedNftBackendService, "apply_source")
    monkeypatch.setattr(nft_module.os, "geteuid", lambda: 0)

    # Constructor rejects a ResponseBackend using a mock adapter.  The generic
    # backend is already independently tested for Ed25519-only apply_ticket.
    issuer = Ed25519TicketIssuer.generate()
    backend = ResponseBackend(
        verifier=issuer.verifier(),
        state=SQLiteResponseState(tmp_path / "state.sqlite3"),
        timeout_set=NftablesTimeoutSetAdapter(MockNftRunner()),
        backend_id=PRODUCTION_BACKEND_ID,
        authorized_sources=("10.77.0.0/24",),
    )
    with pytest.raises(BackendUnavailableError, match="mock nft runner"):
        PrivilegedNftBackendService(backend)


def test_enablement_is_disabled_by_default_and_fixed_when_enabled():
    template_path = Path(nft_module.__file__).with_name(
        "nft_backend_config.disabled.json"
    )
    template = json.loads(template_path.read_text(encoding="utf-8"))
    assert template == _disabled_config()
    disabled = validate_enablement(_disabled_config())
    assert disabled.enabled is False
    assert disabled.authorized_sources == ()
    with pytest.raises(BackendUnavailableError, match="live acceptance"):
        validate_enablement(
            _disabled_config(
            enabled=True,
            authorized_sources=["10.77.0.0/24"],
            protected_sources=["10.77.0.0/30"],
            scope_ack=LIVE_SCOPE_ACK,
            )
        )
    enabled = validate_enablement(
        _disabled_config(
            enabled=True,
            authorized_sources=["10.77.0.0/24"],
            protected_sources=["10.77.0.0/30"],
            live_acceptance_sha256="a" * 64,
            scope_ack=LIVE_SCOPE_ACK,
        )
    )
    assert enabled.enabled is True
    with pytest.raises(BackendUnavailableError, match="canonical IPv4 CIDRs"):
        validate_enablement(
            _disabled_config(
                enabled=True,
                authorized_sources=["0.0.0.0/0"],
                live_acceptance_sha256="a" * 64,
                scope_ack=LIVE_SCOPE_ACK,
            )
        )
    with pytest.raises(BackendUnavailableError, match="protected"):
        validate_enablement(
            _disabled_config(
                enabled=True,
                authorized_sources=["10.77.0.0/24"],
                protected_sources=[],
                live_acceptance_sha256="a" * 64,
                scope_ack=LIVE_SCOPE_ACK,
            )
        )
    with pytest.raises(BackendUnavailableError, match="inside authorized"):
        validate_enablement(
            _disabled_config(
                enabled=True,
                authorized_sources=["10.77.0.0/24"],
                protected_sources=["10.78.0.0/30"],
                live_acceptance_sha256="a" * 64,
                scope_ack=LIVE_SCOPE_ACK,
            )
        )


@pytest.mark.parametrize(
    "cidr",
    ["10.0.0.0/16", "10.77.0.1/32", "192.0.2.0/24", "8.8.8.0/24"],
)
def test_enablement_rejects_broad_host_public_or_documentation_scopes(cidr):
    with pytest.raises(BackendUnavailableError, match="canonical IPv4 CIDRs"):
        validate_enablement(
            _disabled_config(
                enabled=True,
                authorized_sources=[cidr],
                protected_sources=["10.77.0.0/30"],
                live_acceptance_sha256="a" * 64,
                scope_ack=LIVE_SCOPE_ACK,
            )
        )


def test_source_gate_keeps_fixed_path_service_blocked_even_as_root(monkeypatch):
    assert LIVE_NFT_ACTIVATION_ALLOWED is False
    monkeypatch.setattr(nft_module.os, "geteuid", lambda: 0)
    with pytest.raises(BackendUnavailableError, match="source-gated"):
        PrivilegedNftBackendService.from_fixed_paths()


def test_private_umask_must_be_exactly_0077(monkeypatch):
    calls = []

    def accepted_umask(value):
        calls.append(value)
        return 0o077

    monkeypatch.setattr(nft_module.os, "umask", accepted_umask)
    nft_module._require_private_umask()
    assert calls == [0o077, 0o077]

    monkeypatch.setattr(nft_module.os, "umask", lambda value: 0o022)
    with pytest.raises(BackendUnavailableError, match="UMask=0077"):
        nft_module._require_private_umask()


def _mock_storage_lstat(monkeypatch, database_path, *, modes, owners=None):
    owners = {} if owners is None else owners

    def fake_lstat(path):
        key = str(path)
        if key not in modes:
            raise FileNotFoundError(key)
        return SimpleNamespace(st_mode=modes[key], st_uid=owners.get(key, 0))

    monkeypatch.setattr(Path, "lstat", fake_lstat)


def test_state_storage_accepts_only_exact_private_modes(monkeypatch):
    database_path = Path("/var/lib/sros2-firewall/response-state.sqlite3")
    modes = {
        str(database_path.parent): stat.S_IFDIR | 0o700,
        str(database_path): stat.S_IFREG | 0o600,
        f"{database_path}-wal": stat.S_IFREG | 0o600,
        f"{database_path}-shm": stat.S_IFREG | 0o600,
    }
    _mock_storage_lstat(monkeypatch, database_path, modes=modes)
    nft_module._validate_state_storage(database_path)


@pytest.mark.parametrize(
    ("target", "mode", "message"),
    [
        ("directory", stat.S_IFDIR | 0o755, "mode 0700"),
        ("database", stat.S_IFREG | 0o640, "mode 0600"),
        ("wal", stat.S_IFREG | 0o644, "mode 0600"),
        ("shm", stat.S_IFLNK | 0o777, "mode 0600"),
    ],
)
def test_state_storage_rejects_insecure_modes_and_symlink(
    monkeypatch, target, mode, message
):
    database_path = Path("/var/lib/sros2-firewall/response-state.sqlite3")
    modes = {
        str(database_path.parent): stat.S_IFDIR | 0o700,
        str(database_path): stat.S_IFREG | 0o600,
        f"{database_path}-wal": stat.S_IFREG | 0o600,
        f"{database_path}-shm": stat.S_IFREG | 0o600,
    }
    paths = {
        "directory": str(database_path.parent),
        "database": str(database_path),
        "wal": f"{database_path}-wal",
        "shm": f"{database_path}-shm",
    }
    modes[paths[target]] = mode
    _mock_storage_lstat(monkeypatch, database_path, modes=modes)
    with pytest.raises(BackendUnavailableError, match=message):
        nft_module._validate_state_storage(database_path)


def test_state_storage_rejects_wrong_owner_for_db_wal_or_shm(monkeypatch):
    database_path = Path("/var/lib/sros2-firewall/response-state.sqlite3")
    modes = {
        str(database_path.parent): stat.S_IFDIR | 0o700,
        str(database_path): stat.S_IFREG | 0o600,
        f"{database_path}-wal": stat.S_IFREG | 0o600,
        f"{database_path}-shm": stat.S_IFREG | 0o600,
    }
    owners = {f"{database_path}-wal": 1000}
    _mock_storage_lstat(
        monkeypatch,
        database_path,
        modes=modes,
        owners=owners,
    )
    with pytest.raises(BackendUnavailableError, match="root-owned"):
        nft_module._validate_state_storage(database_path)


def test_mock_report_is_explicitly_ineligible_for_live_enablement(tmp_path, monkeypatch):
    path = tmp_path / "mock-report.json"
    report = write_mock_acceptance_report(
        path,
        checks=[{"id": "argv_fixed", "passed": True, "evidence": "pytest"}],
    )
    assert report["schema_version"] == MOCK_ACCEPTANCE_SCHEMA_VERSION
    assert report["backend"] == "mock_nftables_timeout_set"
    assert report["simulation_only"] is True
    assert report["production_admission_eligible"] is False
    assert not any(
        "policy/catalog/authorizer alignment" in blocker
        for blocker in report["live_acceptance_blockers"]
    )
    raw = path.read_bytes()
    monkeypatch.setattr(nft_module, "_read_root_owned_file", lambda *args, **kwargs: raw)
    with pytest.raises(BackendUnavailableError, match="fields|mock evidence"):
        verify_live_acceptance(path, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_live_acceptance_plan_is_non_mutating_and_keeps_executor_blocked():
    plan = live_acceptance_plan()
    assert plan["schema_version"] == LIVE_ACCEPTANCE_PLAN_SCHEMA_VERSION
    assert plan["plan_only"] is True
    assert plan["host_firewall_modified"] is False
    assert plan["production_ready"] is False
    assert plan["live_executor_implemented"] is False
    assert plan["required_approval_phrase"] == LIVE_ACCEPTANCE_APPROVAL
    assert plan["production_source_gate"] is False
    assert plan["traffic_scope"] == NFT_TRAFFIC_SCOPE
    assert set(plan["required_live_checks"]) == set(nft_module.REQUIRED_LIVE_CHECKS)
    assert plan["future_executor_bounds"]["test_sources"] == 1
    assert plan["future_executor_bounds"]["maximum_test_ttl_sec"] == 30
    assert plan["future_executor_bounds"]["raw_source_or_ttl_service_api"] is False
    assert plan["future_executor_bounds"]["traffic_scope"] == NFT_TRAFFIC_SCOPE


def test_cli_live_acceptance_plan_never_calls_root_or_nft(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("plan command must not inspect root or execute nft")

    monkeypatch.setattr(nft_module, "_require_root", forbidden)
    monkeypatch.setattr(nft_module.subprocess, "run", forbidden)
    assert main(["plan-live-acceptance"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["plan_only"] is True
    assert plan["live_executor_implemented"] is False


def test_cli_has_no_source_or_ttl_option_and_blocks_non_root(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        main(["apply", "--ticket-stdin", "--source", "10.77.0.10"], stdin=io.StringIO("x"))
    with pytest.raises(SystemExit):
        main(["apply", "--ticket-stdin", "--ttl", "30"], stdin=io.StringIO("x"))
    monkeypatch.setattr(nft_module.os, "geteuid", lambda: 1000)
    assert main(["apply", "--ticket-stdin"], stdin=io.StringIO("x\n")) == 2
    assert "UID 0" in capsys.readouterr().err
