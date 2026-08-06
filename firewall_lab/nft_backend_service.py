#!/usr/bin/env python3
"""Reviewable, disabled-by-default nftables response service skeleton.

No function in this module accepts a raw source/TTL response request.  The
privileged service accepts one Ed25519 ticket on stdin and delegates only to
``ResponseBackend.apply_ticket``.  The nft adapter uses a fixed binary and a
fixed, dedicated table/set/chain/rule namespace with ``shell=False``.

The checked-in configuration is disabled.  Live activation additionally
requires a distinct real-kernel acceptance report; the offline mock schema is
explicitly ineligible.  This module never installs rules or changes sudoers.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, TextIO

from .response_backend import (
    DEFAULT_MAX_AUDIT_EVENTS,
    DEFAULT_MAX_CONSUMED_TICKETS,
    MAX_RESPONSE_TTL_SEC,
    MAX_TICKET_LENGTH,
    BackendApplyError,
    BackendApplyResult,
    BackendError,
    BackendUnavailableError,
    DesiredResponse,
    Ed25519TicketVerifier,
    ResponseBackend,
    SQLiteResponseState,
    TimeoutSetAdapter,
)
from .schema import atomic_write_json, safe_json_value, sha256_file


NFT_BINARY = "/usr/sbin/nft"
NFT_FAMILY = "inet"
NFT_TABLE = "sros2_ticket_guard"
NFT_SET = "blocked_ipv4"
NFT_CHAIN = "ticket_input"
NFT_RULE_COMMENT = "sros2-ed25519-ticket-only-drop"
NFT_SET_COMMENT = "sros2-ed25519-ticket-only-timeout-set"
NFT_CHAIN_COMMENT = "sros2-ed25519-ticket-only-chain"
NFT_CHAIN_PRIORITY = -10
NFT_TRAFFIC_SCOPE = "local_input_only_not_forward_gateway"
NFT_SET_SIZE = 1024
NFT_GC_INTERVAL_SEC = 5
NFT_COMMAND_TIMEOUT_SEC = 5.0
NFT_OUTPUT_LIMIT = 1024 * 1024
NFT_BATCH_LIMIT = 128 * 1024
PRODUCTION_BACKEND_ID = "sros2-nftables-timeout-set-v1"
PRODUCTION_ACTION = "temporary_block"

ENABLEMENT_SCHEMA_VERSION = "sros2-firewall-nft-backend-enablement/v1"
LIVE_ACCEPTANCE_SCHEMA_VERSION = "sros2-firewall-nft-live-acceptance/v1"
MOCK_ACCEPTANCE_SCHEMA_VERSION = "sros2-firewall-nft-mock-acceptance/v1"
LIVE_ACCEPTANCE_PLAN_SCHEMA_VERSION = "sros2-firewall-nft-live-acceptance-plan/v1"
FIXED_CONFIG_PATH = Path("/etc/sros2-firewall/nft-backend-enabled.json")
FIXED_PUBLIC_KEY_PATH = Path("/etc/sros2-firewall/ticket-public-key.raw")
FIXED_LIVE_ACCEPTANCE_PATH = Path("/etc/sros2-firewall/nft-live-acceptance.json")
FIXED_STATE_DB_PATH = Path("/var/lib/sros2-firewall/response-state.sqlite3")
LIVE_SCOPE_ACK = "I_CONFIRM_OWNED_ISOLATED_NFT_BACKEND"
LIVE_ACCEPTANCE_APPROVAL = "BEGIN_OWNED_ISOLATED_NFT_LIVE_ACCEPTANCE"
# This source-level gate stays false until a real isolated-host acceptance run
# verifies the target nft userspace JSON and kernel timeout behavior.
LIVE_NFT_ACTIVATION_ALLOWED = False

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

REQUIRED_LIVE_CHECKS = frozenset(
    {
        "fixed_nft_binary_verified",
        "nft_version_recorded",
        "dedicated_ruleset_verified",
        "kernel_timeout_expiry_verified",
        "kernel_set_capacity_verified",
        "packet_drop_verified",
        "temporary_block_semantics_verified",
        "restart_reconciliation_verified",
        "owned_isolated_host_verified",
    }
)

EXPECTED_RULE_EXPRESSION = [
    {
        "match": {
            "op": "in",
            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
            "right": f"@{NFT_SET}",
        }
    },
    {"counter": None},
    {"drop": None},
]


def render_bootstrap_ruleset_for_review() -> str:
    """Return the fixed ruleset text; the service never auto-installs it."""

    return (
        f"table {NFT_FAMILY} {NFT_TABLE} {{\n"
        f"  set {NFT_SET} {{\n"
        "    type ipv4_addr;\n"
        "    flags timeout;\n"
        f"    timeout {MAX_RESPONSE_TTL_SEC}s;\n"
        f"    gc-interval {NFT_GC_INTERVAL_SEC}s;\n"
        f"    size {NFT_SET_SIZE};\n"
        "    policy memory;\n"
        f'    comment "{NFT_SET_COMMENT}";\n'
        "  }\n"
        f"  chain {NFT_CHAIN} {{\n"
        f"    type filter hook input priority {NFT_CHAIN_PRIORITY}; policy accept;\n"
        f'    comment "{NFT_CHAIN_COMMENT}";\n'
        f"    ip saddr @{NFT_SET} counter drop comment \"{NFT_RULE_COMMENT}\"\n"
        "  }\n"
        "}\n"
    )


@dataclass(frozen=True)
class NftCommandResult:
    argv: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str


class NftRunner(ABC):
    """Narrow command capability; it cannot receive arbitrary argv."""

    production: bool = False

    @abstractmethod
    def list_fixed_table_json(self) -> NftCommandResult:
        pass

    @abstractmethod
    def check_fixed_batch(self, batch: str) -> NftCommandResult:
        pass

    @abstractmethod
    def apply_fixed_batch(self, batch: str) -> NftCommandResult:
        pass


class SubprocessNftRunner(NftRunner):
    """The only production runner: fixed nft path, argv, cwd, and environment."""

    production = True
    __slots__ = ()

    @staticmethod
    def _validate_batch(batch: str) -> bytes:
        try:
            encoded = batch.encode("ascii") if isinstance(batch, str) else b""
        except UnicodeEncodeError as exc:
            raise BackendUnavailableError("nft batch must be ASCII") from exc
        if not encoded or len(encoded) > NFT_BATCH_LIMIT:
            raise BackendUnavailableError("nft batch is empty or oversized")
        lines = batch.splitlines()
        if not lines or len(lines) > NFT_SET_SIZE * 2 or any(not line for line in lines):
            raise BackendUnavailableError("nft batch line count is invalid")
        seen: set[tuple[str, str]] = set()
        delete_pattern = re.compile(
            rf"delete element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} \{{ ([0-9.]+) \}}"
        )
        add_pattern = re.compile(
            rf"add element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} "
            r"\{ ([0-9.]+) timeout ([0-9]+)s \}"
        )
        for line in lines:
            delete = delete_pattern.fullmatch(line)
            add = add_pattern.fullmatch(line)
            if delete:
                source = _canonical_ipv4(delete.group(1))
                key = ("delete", source)
            elif add:
                source = _canonical_ipv4(add.group(1))
                ttl_sec = int(add.group(2))
                if not 1 <= ttl_sec <= MAX_RESPONSE_TTL_SEC:
                    raise BackendUnavailableError("nft batch TTL exceeds 1..300 seconds")
                key = ("add", source)
            else:
                raise BackendUnavailableError("nft batch contains a non-fixed statement")
            if key in seen:
                raise BackendUnavailableError("nft batch contains a duplicate statement")
            seen.add(key)
        return encoded

    @staticmethod
    def _run(argv: tuple[str, ...], *, batch: str | None = None) -> NftCommandResult:
        allowed = {
            (
                NFT_BINARY,
                "--numeric",
                "--json",
                "list",
                "table",
                NFT_FAMILY,
                NFT_TABLE,
            ),
            (NFT_BINARY, "--check", "--file", "-"),
            (NFT_BINARY, "--file", "-"),
        }
        if argv not in allowed:
            raise BackendUnavailableError("nft runner refused non-fixed argv")
        needs_batch = argv in {
            (NFT_BINARY, "--check", "--file", "-"),
            (NFT_BINARY, "--file", "-"),
        }
        if needs_batch is not (batch is not None):
            raise BackendUnavailableError("nft runner batch/argv mode mismatch")
        if batch is not None:
            SubprocessNftRunner._validate_batch(batch)
        try:
            result = subprocess.run(
                list(argv),
                input=batch,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=NFT_COMMAND_TIMEOUT_SEC,
                check=False,
                shell=False,
                cwd="/",
                env={
                    "PATH": "/usr/sbin:/usr/bin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
                close_fds=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise BackendUnavailableError("fixed nft command timed out") from exc
        except OSError as exc:
            raise BackendUnavailableError("fixed nft command could not start") from exc
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if len(stdout.encode("utf-8")) > NFT_OUTPUT_LIMIT or len(stderr.encode("utf-8")) > NFT_OUTPUT_LIMIT:
            raise BackendUnavailableError("nft output exceeded the fixed evidence limit")
        return NftCommandResult(
            argv=argv,
            return_code=int(result.returncode),
            stdout=stdout,
            stderr=stderr,
        )

    def list_fixed_table_json(self) -> NftCommandResult:
        return self._run(
            (
                NFT_BINARY,
                "--numeric",
                "--json",
                "list",
                "table",
                NFT_FAMILY,
                NFT_TABLE,
            )
        )

    def check_fixed_batch(self, batch: str) -> NftCommandResult:
        return self._run((NFT_BINARY, "--check", "--file", "-"), batch=batch)

    def apply_fixed_batch(self, batch: str) -> NftCommandResult:
        return self._run((NFT_BINARY, "--file", "-"), batch=batch)


def _canonical_ipv4(value: Any) -> str:
    if not isinstance(value, str):
        raise BackendApplyError("nft source must be text")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise BackendApplyError("nft source must be one canonical IPv4 address") from exc
    if address.version != 4 or str(address) != value:
        raise BackendApplyError("nft source must be one canonical IPv4 address")
    return value


def _require_root() -> None:
    getter = getattr(os, "geteuid", None)
    if getter is None or getter() != 0:
        raise BackendUnavailableError("privileged nft backend requires effective UID 0")


class NftablesTimeoutSetAdapter(TimeoutSetAdapter):
    """Strict adapter for one pre-installed, dedicated nftables timeout set."""

    backend_id = PRODUCTION_BACKEND_ID

    def __init__(self, runner: NftRunner | None = None):
        self._runner = runner if runner is not None else SubprocessNftRunner()
        if not isinstance(self._runner, NftRunner):
            raise TypeError("nft adapter requires a narrow NftRunner")
        self._lock = threading.Lock()

    @property
    def production_runner(self) -> bool:
        return type(self._runner) is SubprocessNftRunner

    def _root_if_production(self) -> None:
        if self.production_runner:
            _require_root()

    @staticmethod
    def _require_success(result: NftCommandResult, operation: str) -> None:
        if result.return_code != 0:
            raise BackendApplyError(
                f"nft {operation} failed closed: {result.stderr[:512]}"
            )

    @staticmethod
    def _parse_element(value: Any, *, now_ns: int) -> tuple[str, int]:
        if not isinstance(value, dict) or set(value) != {"elem"}:
            raise BackendApplyError("nft set element JSON is not recognized")
        element = value["elem"]
        if not isinstance(element, dict) or set(element) != {"val", "timeout", "expires"}:
            raise BackendApplyError("nft timed element metadata is incomplete")
        source = _canonical_ipv4(element["val"])
        timeout_ms = element["timeout"]
        expires_ms = element["expires"]
        for raw, name in ((timeout_ms, "timeout"), (expires_ms, "expires")):
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
                raise BackendApplyError(f"nft element {name} must be positive milliseconds")
        if timeout_ms > MAX_RESPONSE_TTL_SEC * 1000 or expires_ms > timeout_ms:
            raise BackendApplyError("nft element timeout exceeds the signed response bound")
        return source, now_ns + expires_ms * 1_000_000

    @classmethod
    def _parse_snapshot(cls, text: str, *, now_ns: int) -> dict[str, int]:
        if not isinstance(text, str) or not text or len(text.encode("utf-8")) > NFT_OUTPUT_LIMIT:
            raise BackendApplyError("nft JSON snapshot is missing or oversized")
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise BackendApplyError("nft JSON snapshot is malformed") from exc
        if not isinstance(document, dict) or set(document) != {"nftables"}:
            raise BackendApplyError("nft JSON root is not recognized")
        objects = document["nftables"]
        if not isinstance(objects, list):
            raise BackendApplyError("nft JSON object list is missing")
        recognized: dict[str, list[dict[str, Any]]] = {
            "table": [],
            "set": [],
            "chain": [],
            "rule": [],
        }
        for item in objects:
            if not isinstance(item, dict) or len(item) != 1:
                raise BackendApplyError("nft JSON contains an invalid object")
            kind = next(iter(item))
            if kind == "metainfo":
                continue
            if kind not in recognized or not isinstance(item[kind], dict):
                raise BackendApplyError("nft dedicated table contains an unexpected object")
            recognized[kind].append(item[kind])
        if any(len(recognized[kind]) != 1 for kind in recognized):
            raise BackendApplyError("nft dedicated namespace topology is not exact")
        table = recognized["table"][0]
        if table.get("family") != NFT_FAMILY or table.get("name") != NFT_TABLE:
            raise BackendApplyError("nft table identity is not exact")
        nft_set = recognized["set"][0]
        if (
            nft_set.get("family") != NFT_FAMILY
            or nft_set.get("table") != NFT_TABLE
            or nft_set.get("name") != NFT_SET
            or nft_set.get("type") != "ipv4_addr"
            or nft_set.get("flags") != ["timeout"]
            or nft_set.get("size") != NFT_SET_SIZE
            or nft_set.get("timeout") != MAX_RESPONSE_TTL_SEC * 1000
            or nft_set.get("gc-interval") != NFT_GC_INTERVAL_SEC * 1000
            or nft_set.get("policy") != "memory"
            or nft_set.get("comment") != NFT_SET_COMMENT
        ):
            raise BackendApplyError("nft timeout set contract is not exact")
        chain = recognized["chain"][0]
        if (
            chain.get("family") != NFT_FAMILY
            or chain.get("table") != NFT_TABLE
            or chain.get("name") != NFT_CHAIN
            or chain.get("type") != "filter"
            or chain.get("hook") != "input"
            or chain.get("prio") != NFT_CHAIN_PRIORITY
            or chain.get("policy") != "accept"
            or chain.get("comment") != NFT_CHAIN_COMMENT
        ):
            raise BackendApplyError("nft chain contract is not exact")
        rule = recognized["rule"][0]
        if (
            rule.get("family") != NFT_FAMILY
            or rule.get("table") != NFT_TABLE
            or rule.get("chain") != NFT_CHAIN
            or rule.get("comment") != NFT_RULE_COMMENT
            or rule.get("expr") != EXPECTED_RULE_EXPRESSION
        ):
            raise BackendApplyError("nft drop rule contract is not exact")
        elements = nft_set.get("elem", [])
        if not isinstance(elements, list) or len(elements) > NFT_SET_SIZE:
            raise BackendApplyError("nft set size is invalid or over capacity")
        snapshot: dict[str, int] = {}
        for item in elements:
            source, expiry = cls._parse_element(item, now_ns=now_ns)
            if source in snapshot:
                raise BackendApplyError("nft set contains a duplicate source")
            snapshot[source] = expiry
        return dict(sorted(snapshot.items()))

    def snapshot(self, *, now_ns: int) -> dict[str, int]:
        self._root_if_production()
        result = self._runner.list_fixed_table_json()
        self._require_success(result, "snapshot")
        return self._parse_snapshot(result.stdout, now_ns=now_ns)

    @staticmethod
    def _remaining_ttl(response: DesiredResponse, now_ns: int) -> int:
        if response.backend_id != PRODUCTION_BACKEND_ID:
            raise BackendApplyError("desired response is bound to another backend")
        if response.action != PRODUCTION_ACTION or response.adapter != "network_helper":
            raise BackendApplyError(
                "nft adapter accepts only signed temporary_block/network_helper responses"
            )
        _canonical_ipv4(response.source)
        remaining_ns = response.expires_at_ns - now_ns
        if remaining_ns <= 0:
            raise BackendApplyError("desired response already expired")
        seconds = int(math.ceil(remaining_ns / 1_000_000_000))
        if not 1 <= seconds <= MAX_RESPONSE_TTL_SEC:
            raise BackendApplyError("desired response TTL exceeds 1..300 seconds")
        return seconds

    @staticmethod
    def _render_batch(
        *,
        delete_sources: Iterable[str],
        additions: Mapping[str, int],
    ) -> str:
        lines: list[str] = []
        for source in sorted(set(delete_sources)):
            canonical = _canonical_ipv4(source)
            lines.append(
                f"delete element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} {{ {canonical} }}"
            )
        for source, ttl_sec in sorted(additions.items()):
            canonical = _canonical_ipv4(source)
            if isinstance(ttl_sec, bool) or not isinstance(ttl_sec, int) or not 1 <= ttl_sec <= MAX_RESPONSE_TTL_SEC:
                raise BackendApplyError("nft element TTL must be an integer in 1..300")
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_SET} "
                f"{{ {canonical} timeout {ttl_sec}s }}"
            )
        batch = "\n".join(lines) + ("\n" if lines else "")
        if not batch or len(batch.encode("ascii")) > NFT_BATCH_LIMIT:
            raise BackendApplyError("nft transaction batch is empty or oversized")
        return batch

    def _apply_transaction(self, batch: str) -> None:
        checked = self._runner.check_fixed_batch(batch)
        self._require_success(checked, "syntax/kernel check")
        applied = self._runner.apply_fixed_batch(batch)
        self._require_success(applied, "atomic batch")

    @staticmethod
    def _expiry_matches(actual: int, expected: int) -> bool:
        # Listing and applying consume time; never allow an expiry to extend
        # beyond the signed deadline by more than one rounding second.
        return expected - 2_000_000_000 <= actual <= expected + 1_000_000_000

    def apply(self, response: DesiredResponse, *, now_ns: int) -> None:
        self._root_if_production()
        ttl_sec = self._remaining_ttl(response, now_ns)
        with self._lock:
            current = self.snapshot(now_ns=now_ns)
            batch = self._render_batch(
                delete_sources=(response.source,) if response.source in current else (),
                additions={response.source: ttl_sec},
            )
            self._apply_transaction(batch)
            after = self.snapshot(now_ns=now_ns)
            if response.source not in after or not self._expiry_matches(
                after[response.source], response.expires_at_ns
            ):
                raise BackendApplyError("nft post-apply snapshot failed closed")

    def reconcile(
        self,
        desired: Mapping[str, DesiredResponse],
        *,
        now_ns: int,
    ) -> None:
        self._root_if_production()
        if not isinstance(desired, Mapping) or len(desired) > NFT_SET_SIZE:
            raise BackendApplyError("nft reconciliation exceeds fixed set capacity")
        additions: dict[str, int] = {}
        for source, response in desired.items():
            if source != response.source:
                raise BackendApplyError("desired source key does not match response")
            additions[_canonical_ipv4(source)] = self._remaining_ttl(response, now_ns)
        with self._lock:
            current = self.snapshot(now_ns=now_ns)
            if current or additions:
                batch = self._render_batch(
                    delete_sources=current,
                    additions=additions,
                )
                self._apply_transaction(batch)
            after = self.snapshot(now_ns=now_ns)
            if set(after) != set(desired):
                raise BackendApplyError("nft reconciliation source set differs from durable state")
            for source, response in desired.items():
                if not self._expiry_matches(after[source], response.expires_at_ns):
                    raise BackendApplyError("nft reconciliation expiry differs from durable state")


@dataclass(frozen=True)
class ProductionEnablement:
    enabled: bool
    authorized_sources: tuple[str, ...]
    protected_sources: tuple[str, ...]
    live_acceptance_sha256: str


def _canonical_networks(value: Any, name: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise BackendUnavailableError(f"{name} must be a non-empty CIDR list")
    if len(value) > 64:
        raise BackendUnavailableError(f"{name} exceeds the 64-CIDR limit")
    result: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise BackendUnavailableError(f"{name} contains a non-text CIDR")
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise BackendUnavailableError(f"{name} contains an invalid CIDR") from exc
        if (
            network.version != 4
            or str(network) != raw
            or not 24 <= network.prefixlen <= 30
            or not any(network.subnet_of(private) for private in RFC1918_NETWORKS)
            or network.is_loopback
            or network.is_multicast
            or network.is_link_local
            or network.is_unspecified
        ):
            raise BackendUnavailableError(f"{name} must contain canonical IPv4 CIDRs")
        result.append(raw)
    if len(set(result)) != len(result):
        raise BackendUnavailableError(f"{name} contains duplicate CIDRs")
    return tuple(result)


def validate_enablement(value: Any) -> ProductionEnablement:
    required = {
        "schema_version",
        "enabled",
        "backend_id",
        "authorized_sources",
        "protected_sources",
        "max_active_sources",
        "max_consumed_tickets",
        "max_audit_events",
        "live_acceptance_sha256",
        "scope_ack",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise BackendUnavailableError("nft enablement configuration fields are invalid")
    if value.get("schema_version") != ENABLEMENT_SCHEMA_VERSION:
        raise BackendUnavailableError("unsupported nft enablement schema")
    if not isinstance(value.get("enabled"), bool):
        raise BackendUnavailableError("nft enablement flag must be bool")
    if value.get("backend_id") != PRODUCTION_BACKEND_ID:
        raise BackendUnavailableError("nft enablement backend_id is not fixed")
    if (
        value.get("max_active_sources") != NFT_SET_SIZE
        or value.get("max_consumed_tickets") != DEFAULT_MAX_CONSUMED_TICKETS
        or value.get("max_audit_events") != DEFAULT_MAX_AUDIT_EVENTS
    ):
        raise BackendUnavailableError("nft enablement capacity limits are not fixed")
    enabled = value["enabled"]
    authorized = _canonical_networks(
        value.get("authorized_sources"),
        "authorized_sources",
        allow_empty=not enabled,
    )
    protected = _canonical_networks(
        value.get("protected_sources"),
        "protected_sources",
        allow_empty=True,
    )
    digest = value.get("live_acceptance_sha256")
    if not isinstance(digest, str) or (
        digest and (len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest))
    ):
        raise BackendUnavailableError("live acceptance SHA-256 is invalid")
    if enabled and (not digest or value.get("scope_ack") != LIVE_SCOPE_ACK):
        raise BackendUnavailableError("enabled nft backend lacks live acceptance/scope acknowledgement")
    if enabled and not protected:
        raise BackendUnavailableError(
            "enabled nft backend requires at least one protected RFC1918 subnet"
        )
    if enabled:
        authorized_networks = tuple(ipaddress.ip_network(item) for item in authorized)
        for protected_item in protected:
            protected_network = ipaddress.ip_network(protected_item)
            if not any(
                protected_network.subnet_of(authorized_network)
                for authorized_network in authorized_networks
            ):
                raise BackendUnavailableError(
                    "each protected subnet must be inside authorized_sources"
                )
    if not enabled and value.get("scope_ack") not in {"", LIVE_SCOPE_ACK}:
        raise BackendUnavailableError("disabled nft backend has an invalid scope acknowledgement")
    return ProductionEnablement(
        enabled=enabled,
        authorized_sources=authorized,
        protected_sources=protected,
        live_acceptance_sha256=digest,
    )


def _read_root_owned_file(path: Path, *, maximum_bytes: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise BackendUnavailableError("production file reads require O_NOFOLLOW")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | nofollow,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise BackendUnavailableError(f"production path is not a regular file: {path}")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise BackendUnavailableError(
                f"production file must be root-owned and not group/world writable: {path}"
            )
        if info.st_size < 1 or info.st_size > maximum_bytes:
            raise BackendUnavailableError(f"production file has an invalid size: {path}")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            value = handle.read(maximum_bytes + 1)
        if len(value) != info.st_size:
            raise BackendUnavailableError(f"production file changed while reading: {path}")
        return value
    except OSError as exc:
        raise BackendUnavailableError(
            f"required production file could not be opened safely: {path}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_private_umask() -> None:
    """Require the service manager to launch this process with UMask=0077."""

    previous = os.umask(0o077)
    os.umask(previous)
    if previous != 0o077:
        raise BackendUnavailableError(
            "production nft backend requires process UMask=0077"
        )


def _validate_state_storage(
    database_path: Path,
    *,
    expected_uid: int = 0,
) -> None:
    """Validate the fixed DB directory and any DB/WAL/SHM files fail closed."""

    parent = database_path.parent
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise BackendUnavailableError(
            "production state directory must be pre-created by the disabled installer"
        ) from exc
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != expected_uid
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise BackendUnavailableError(
            "production state directory must be root-owned, non-symlinked, and mode 0700"
        )
    for candidate in (
        database_path,
        Path(f"{database_path}-wal"),
        Path(f"{database_path}-shm"),
    ):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise BackendUnavailableError(
                f"production state file could not be inspected: {candidate}"
            ) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise BackendUnavailableError(
                "production DB/WAL/SHM must be root-owned, regular, non-symlinked, "
                "and mode 0600"
            )


def load_fixed_enablement() -> ProductionEnablement:
    raw = _read_root_owned_file(FIXED_CONFIG_PATH, maximum_bytes=16 * 1024)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackendUnavailableError("nft enablement configuration is invalid JSON") from exc
    enablement = validate_enablement(value)
    if not enablement.enabled:
        raise BackendUnavailableError("production nft backend is disabled")
    return enablement


def verify_live_acceptance(path: Path, *, expected_sha256: str) -> dict[str, Any]:
    raw = _read_root_owned_file(path, maximum_bytes=256 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise BackendUnavailableError("live nft acceptance digest does not match enablement")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackendUnavailableError("live nft acceptance is invalid JSON") from exc
    required = {
        "schema_version",
        "backend",
        "simulation_only",
        "production_ready",
        "host_firewall_modified",
        "checks",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise BackendUnavailableError("live nft acceptance fields are invalid")
    if (
        value.get("schema_version") != LIVE_ACCEPTANCE_SCHEMA_VERSION
        or value.get("backend") != "nftables_timeout_set"
        or value.get("simulation_only") is not False
        or value.get("production_ready") is not True
        or value.get("host_firewall_modified") is not True
    ):
        raise BackendUnavailableError("offline/mock evidence cannot enable production nft backend")
    checks = value.get("checks")
    if not isinstance(checks, list):
        raise BackendUnavailableError("live nft acceptance checks are missing")
    by_id = {
        item.get("id"): item
        for item in checks
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if set(by_id) != REQUIRED_LIVE_CHECKS or any(
        item.get("passed") is not True
        or not isinstance(item.get("evidence"), str)
        or not item["evidence"].strip()
        for item in by_id.values()
    ):
        raise BackendUnavailableError("live nft acceptance checks are incomplete")
    return safe_json_value(value)


class PrivilegedNftBackendService:
    """Root-only ticket service.  Its public method accepts only one ticket."""

    __slots__ = ("_backend",)

    def __init__(self, backend: ResponseBackend):
        _require_root()
        if type(backend) is not ResponseBackend:
            raise TypeError("privileged service requires ResponseBackend")
        if type(backend.timeout_set) is not NftablesTimeoutSetAdapter:
            raise BackendUnavailableError("privileged service requires the nft adapter")
        if not backend.timeout_set.production_runner:
            raise BackendUnavailableError("mock nft runner cannot start privileged service")
        self._backend = backend

    @classmethod
    def from_fixed_paths(cls) -> "PrivilegedNftBackendService":
        _require_root()
        if not LIVE_NFT_ACTIVATION_ALLOWED:
            raise BackendUnavailableError(
                "production nft activation remains source-gated pending real-kernel "
                "live acceptance; mock reports cannot change this gate"
            )
        _require_private_umask()
        _validate_state_storage(FIXED_STATE_DB_PATH)
        enablement = load_fixed_enablement()
        verify_live_acceptance(
            FIXED_LIVE_ACCEPTANCE_PATH,
            expected_sha256=enablement.live_acceptance_sha256,
        )
        public_key = _read_root_owned_file(FIXED_PUBLIC_KEY_PATH, maximum_bytes=32)
        if len(public_key) != 32:
            raise BackendUnavailableError("Ed25519 public key must contain 32 raw bytes")
        verifier = Ed25519TicketVerifier(public_key)
        state = SQLiteResponseState(
            FIXED_STATE_DB_PATH,
            max_active_sources=NFT_SET_SIZE,
            max_consumed_tickets=DEFAULT_MAX_CONSUMED_TICKETS,
            max_audit_events=DEFAULT_MAX_AUDIT_EVENTS,
        )
        _validate_state_storage(FIXED_STATE_DB_PATH)
        adapter = NftablesTimeoutSetAdapter()
        backend = ResponseBackend(
            verifier=verifier,
            state=state,
            timeout_set=adapter,
            backend_id=PRODUCTION_BACKEND_ID,
            authorized_sources=enablement.authorized_sources,
            protected_sources=enablement.protected_sources,
            network_action=PRODUCTION_ACTION,
        )
        # Strict restart reconciliation before the first ticket.  It only
        # manages the pre-installed dedicated set and never creates rules.
        backend.reconcile(now_ns=time.time_ns())
        return cls(backend)

    def handle_ticket(self, ticket: str) -> BackendApplyResult:
        return self._backend.apply_ticket(ticket)


def write_mock_acceptance_report(
    path: str | Path,
    *,
    checks: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Write an explicitly ineligible mock report for code-review evidence."""

    normalized = [safe_json_value(dict(item)) for item in checks]
    report = {
        "schema_version": MOCK_ACCEPTANCE_SCHEMA_VERSION,
        "backend": "mock_nftables_timeout_set",
        "simulation_only": True,
        "production_ready": False,
        "production_admission_eligible": False,
        "host_firewall_modified": False,
        "nft_binary_executed": False,
        "checks": normalized,
        "live_acceptance_blockers": [
            "signed temporary_block end-to-end live application not verified",
            "real /usr/sbin/nft version and JSON schema not verified",
            "real kernel timeout expiry not verified",
            "real packet drop path not verified",
            "real restart reconciliation not verified",
            "gateway forward/egress enforcement is outside this local-input backend",
        ],
    }
    destination = Path(path)
    atomic_write_json(destination, report)
    digest = sha256_file(destination)
    sidecar = destination.with_suffix(destination.suffix + ".sha256")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{sidecar.name}.", suffix=".tmp", dir=sidecar.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(f"{digest}  {destination.name}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, sidecar)
    finally:
        temporary.unlink(missing_ok=True)
    return report


def live_acceptance_plan() -> dict[str, Any]:
    """Return the non-mutating bootstrap plan for a future live runner.

    This deliberately does not run nft, create a live report, or bypass
    ``LIVE_NFT_ACTIVATION_ALLOWED``.  A separately reviewed acceptance-only
    executor must eventually generate the real report before the production
    source gate can be changed.
    """

    return {
        "schema_version": LIVE_ACCEPTANCE_PLAN_SCHEMA_VERSION,
        "plan_only": True,
        "simulation_only": True,
        "host_firewall_modified": False,
        "production_ready": False,
        "live_executor_implemented": False,
        "human_approval_required": True,
        "required_approval_phrase": LIVE_ACCEPTANCE_APPROVAL,
        "production_source_gate": LIVE_NFT_ACTIVATION_ALLOWED,
        "traffic_scope": NFT_TRAFFIC_SCOPE,
        "preconditions": [
            "two separately owned hosts on an isolated RFC1918 link",
            "no default route, internet route, NAT, or third-party systems",
            "reviewed authorized /24-/30 scope and protected subnet",
            "reviewed fixed dedicated nft table/set/chain/rule",
            "operator maintenance window and physical stop procedure",
        ],
        "future_executor_bounds": {
            "requires_uid_0": True,
            "requires_exact_human_approval_phrase": True,
            "nft_binary": NFT_BINARY,
            "test_sources": 1,
            "maximum_test_ttl_sec": 30,
            "requires_signed_temporary_block_ticket": True,
            "raw_source_or_ttl_service_api": False,
            "allows_scan_flood_persistence_or_rule_flush": False,
            "dedicated_namespace_only": f"{NFT_FAMILY} {NFT_TABLE}",
            "traffic_scope": NFT_TRAFFIC_SCOPE,
        },
        "required_live_checks": sorted(REQUIRED_LIVE_CHECKS),
        "required_report_schema": LIVE_ACCEPTANCE_SCHEMA_VERSION,
        "bootstrap_sequence": [
            "review this plan and the rendered fixed ruleset",
            "implement and separately review the bounded acceptance-only executor",
            "receive explicit human approval on the owned isolated hosts",
            "run one signed temporary_block case and collect real nft/kernel evidence",
            "review and pin the live report SHA-256 in the root-owned enablement file",
            "only then review a source change that opens LIVE_NFT_ACTIVATION_ALLOWED",
            "start the production ticket-only service and repeat restart reconciliation",
        ],
        "current_blocker": (
            "bounded live executor is not implemented; this plan cannot create a "
            "production-eligible report"
        ),
    }


def _read_ticket_stdin(stream: TextIO) -> str:
    value = stream.read(MAX_TICKET_LENGTH + 2)
    if len(value) > MAX_TICKET_LENGTH + 1:
        raise BackendUnavailableError("authorization ticket stdin is oversized")
    if value.count("\n") > 1 or ("\n" in value and not value.endswith("\n")):
        raise BackendUnavailableError("authorization ticket stdin must contain one line")
    ticket = value.rstrip("\n")
    if not ticket or "\r" in ticket:
        raise BackendUnavailableError("authorization ticket stdin is missing or malformed")
    try:
        ticket.encode("ascii")
    except UnicodeEncodeError as exc:
        raise BackendUnavailableError("authorization ticket stdin must be ASCII") from exc
    return ticket


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--ticket-stdin", action="store_true", required=True)
    subparsers.add_parser(
        "plan-live-acceptance",
        help="print a non-mutating, human-gated live acceptance plan",
    )
    args = parser.parse_args(argv)
    if args.command == "plan-live-acceptance":
        print(json.dumps(live_acceptance_plan(), sort_keys=True))
        return 0
    if args.command != "apply" or args.ticket_stdin is not True:
        return 2
    try:
        service = PrivilegedNftBackendService.from_fixed_paths()
        ticket = _read_ticket_stdin(stdin or sys.stdin)
        result = service.handle_ticket(ticket)
        print(json.dumps(result.to_dict(), sort_keys=True))
        return 0
    except (BackendError, OSError, ValueError, TypeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
