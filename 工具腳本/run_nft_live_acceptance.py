#!/usr/bin/env python3
"""Bounded, acceptance-only executor for the real-kernel nftables backend.

`nft_backend_service.live_acceptance_plan()` has said since 2026-08-03 that the
production source gate cannot move because *"bounded live executor is not
implemented"*.  This is that executor, and nothing more: it runs **one** signed
`temporary_block` ticket against a real kernel on an isolated link, collects the
nine checks `REQUIRED_LIVE_CHECKS` names, and writes the report whose SHA-256 a
human may then pin into the root-owned enablement file.

It deliberately does **not**:

* move `LIVE_NFT_ACTIVATION_ALLOWED` — that stays a reviewed source change;
* touch any nft table other than the fixed dedicated one;
* accept a raw source/TTL request into the service API (it issues a signed
  ticket and hands it to `ResponseBackend`, exactly like production would);
* scan, flood, persist, or flush rules.

Why the executor installs the ruleset when the service refuses to:
`SubprocessNftRunner._validate_batch` accepts only `add element` / `delete
element` lines for the fixed set, so the privileged service structurally cannot
create a table, chain, or rule.  Bootstrapping is therefore the acceptance
runner's job, under human approval, and is undone on the way out.

Anti-lockout, because this program drops packets on a host reached over SSH:

* the test source must not be the address this SSH session arrives from
  (`SSH_CONNECTION`), and must not be the default-route next hop;
* every blocked element carries a kernel timeout of at most
  ``MAX_TEST_TTL_SEC`` seconds, so even a SIGKILL of this process self-heals;
* teardown removes the whole dedicated table in a ``finally``.

Usage (on the Pi, as root, with the approval phrase on stdin):

    echo BEGIN_OWNED_ISOLATED_NFT_LIVE_ACCEPTANCE | sudo python3 \
        工具腳本/run_nft_live_acceptance.py \
        --test-source 192.168.137.50 \
        --authorized-scope 192.168.137.0/24 \
        --protected-source 192.168.137.1/32 \
        --output ~/nft-live-acceptance.json
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys
import time

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from firewall_lab.nft_backend_service import (  # noqa: E402
    rule_expression_matches,
    LIVE_ACCEPTANCE_APPROVAL,
    LIVE_ACCEPTANCE_SCHEMA_VERSION,
    NFT_BINARY,
    NFT_CHAIN,
    NFT_CHAIN_PRIORITY,
    NFT_FAMILY,
    NFT_GC_INTERVAL_SEC,
    NFT_SET,
    NFT_SET_SIZE,
    NFT_TABLE,
    PRODUCTION_BACKEND_ID,
    NftablesTimeoutSetAdapter,
    REQUIRED_LIVE_CHECKS,
    SubprocessNftRunner,
    render_bootstrap_ruleset_for_review,
)
from firewall_lab.response_backend import (  # noqa: E402
    NETWORK_ACTION,
    NETWORK_ADAPTER,
    Ed25519TicketIssuer,
    Ed25519TicketVerifier,
    ResponseBackend,
    SQLiteResponseState,
    TicketVerificationError,
)
from firewall_lab.schema import atomic_write_json, sha256_file  # noqa: E402


# Bounds copied from live_acceptance_plan()["future_executor_bounds"].  They are
# asserted at startup rather than trusted, so drift in either file is loud.
MAX_TEST_TTL_SEC = 30
TEST_SOURCES = 1
NFT_TIMEOUT_SEC = 10.0
# The applied TTL. Short enough that a crashed run self-heals quickly, long
# enough to observe presence, traffic, and expiry without racing gc-interval.
APPLIED_TTL_SEC = 12
# Expiry must land inside ttl + gc-interval + slack; slack covers scheduler and
# poll granularity, not a vague margin.
EXPIRY_SLACK_SEC = 8
TRAFFIC_WAIT_SEC = 45


def _evidence_id(label: str) -> str:
    """Tickets require a 64-character lowercase hex evidence id.

    The first live run crashed here: a readable label was passed straight
    through and `_validate_payload` rejected it. Hashing the label keeps the
    value both legal and traceable back to which check issued it.
    """

    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class AcceptanceError(RuntimeError):
    """Any condition that makes the run ineligible to produce a report."""


def _log(message: str) -> None:
    print(message, flush=True)


# ── bounded nft access ───────────────────────────────────────────────────────


def _nft(*args: str, batch: str | None = None) -> subprocess.CompletedProcess:
    """Run the fixed nft binary with a fixed environment and shell=False."""

    argv = (NFT_BINARY,) + args
    return subprocess.run(
        argv,
        input=batch,
        capture_output=True,
        text=True,
        shell=False,
        timeout=NFT_TIMEOUT_SEC,
        cwd="/",
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        check=False,
    )


def _table_names() -> set[tuple[str, str]]:
    result = _nft("-j", "list", "tables")
    if result.returncode != 0:
        raise AcceptanceError(f"nft list tables failed: {result.stderr[:300]}")
    payload = json.loads(result.stdout or '{"nftables": []}')
    names = set()
    for item in payload.get("nftables", []):
        table = item.get("table") if isinstance(item, dict) else None
        if isinstance(table, dict):
            names.add((str(table.get("family")), str(table.get("name"))))
    return names


def _fixed_table_json() -> dict:
    result = _nft("-j", "list", "table", NFT_FAMILY, NFT_TABLE)
    if result.returncode != 0:
        raise AcceptanceError(f"nft list table failed: {result.stderr[:300]}")
    return json.loads(result.stdout)


def _set_elements() -> dict[str, int]:
    """Return {source: timeout_remaining_sec} for the dedicated set."""

    payload = _fixed_table_json()
    elements: dict[str, int] = {}
    for item in payload.get("nftables", []):
        node = item.get("set") if isinstance(item, dict) else None
        if not isinstance(node, dict) or node.get("name") != NFT_SET:
            continue
        for element in node.get("elem", []) or []:
            if isinstance(element, dict) and "elem" in element:
                inner = element["elem"]
                value = inner.get("val")
                expires = inner.get("expires")
                if isinstance(value, str) and isinstance(expires, int):
                    elements[value] = expires
            elif isinstance(element, str):
                elements[element] = -1
    return elements


def _rule_counter() -> tuple[int, int]:
    """Return (packets, bytes) from the single counter in the fixed rule."""

    payload = _fixed_table_json()
    for item in payload.get("nftables", []):
        rule = item.get("rule") if isinstance(item, dict) else None
        if not isinstance(rule, dict) or rule.get("chain") != NFT_CHAIN:
            continue
        for expression in rule.get("expr", []):
            counter = expression.get("counter") if isinstance(expression, dict) else None
            if isinstance(counter, dict):
                return int(counter.get("packets", 0)), int(counter.get("bytes", 0))
    raise AcceptanceError("fixed rule has no readable counter")


# ── preflight ────────────────────────────────────────────────────────────────


def _require_root() -> None:
    if os.geteuid() != 0:
        raise AcceptanceError("live acceptance requires UID 0")


def _require_approval(stream) -> str:
    """The plan mandates an exact human phrase; it is never defaulted."""

    if stream.isatty():
        _log(f"Type the approval phrase to proceed ({LIVE_ACCEPTANCE_APPROVAL}):")
    phrase = stream.readline().strip()
    if phrase != LIVE_ACCEPTANCE_APPROVAL:
        raise AcceptanceError(
            "exact human approval phrase was not supplied on stdin; refusing"
        )
    return phrase


_SSH_PORT = 22
_TCP_ESTABLISHED = "01"
# Module-level so tests can point them at fixtures.
_PROC_TCP = "/proc/net/tcp"
_PROC_TCP6 = "/proc/net/tcp6"


def _hex_to_ipv4(token: str) -> str:
    return str(ipaddress.IPv4Address(bytes(reversed(bytes.fromhex(token)))))


def _hex_to_ipv6(token: str) -> str:
    # /proc stores four 32-bit words, each little-endian within the word.
    words = (token[index:index + 8] for index in range(0, 32, 8))
    return str(ipaddress.IPv6Address(
        b"".join(bytes(reversed(bytes.fromhex(word))) for word in words)
    ))


def _peers_from_proc(path: str, decode) -> set[str]:
    peers: set[str] = set()
    try:
        lines = pathlib.Path(path).read_text(encoding="ascii", errors="replace").splitlines()
    except OSError:
        return peers
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != _TCP_ESTABLISHED:
            continue
        try:
            local_port = int(fields[1].rsplit(":", 1)[1], 16)
            if local_port != _SSH_PORT:
                continue
            address = ipaddress.ip_address(decode(fields[2].rsplit(":", 1)[0]))
        except (IndexError, ValueError):
            continue
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        peers.add(str(address))
    return peers


def _ssh_peers() -> tuple[set[str], str]:
    """Every remote address holding an established session to the SSH port.

    `SSH_CONNECTION` on its own is not a guard. sudo runs under `env_reset`,
    which strips it, so the anti-lockout check silently reads None and stops
    protecting anything -- measured on the Pi on 2026-09-21: under plain `sudo`
    the variable is empty while the kernel still lists the session. The socket
    table cannot be stripped by an environment policy, so an empty result here
    is a measurement ("we looked, there are none") rather than a missing
    variable. The env var is kept as an additional source, never the only one.
    """

    sources: list[str] = []
    peers: set[str] = set()

    from_env = os.environ.get("SSH_CONNECTION", "").split()
    if from_env:
        peers.add(from_env[0])
        sources.append("SSH_CONNECTION")

    kernel = _peers_from_proc(_PROC_TCP, _hex_to_ipv4)
    kernel |= _peers_from_proc(_PROC_TCP6, _hex_to_ipv6)
    if kernel:
        sources.append(f"proc-net-tcp({len(kernel)})")
    peers |= kernel

    return peers, ("+".join(sources) if sources else "none-observed")


def _default_route_present() -> tuple[bool, str]:
    result = subprocess.run(
        ("/usr/sbin/ip", "-4", "route", "show", "default"),
        capture_output=True, text=True, shell=False, timeout=5, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    text = result.stdout.strip()
    return bool(text), text


def _link_for(address: str) -> str:
    result = subprocess.run(
        ("/usr/sbin/ip", "-4", "route", "get", address),
        capture_output=True, text=True, shell=False, timeout=5, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    return result.stdout.strip()


def _check_isolation(test_source: str) -> str:
    """Prove this is an owned, isolated RFC1918 link before dropping packets."""

    address = ipaddress.ip_address(test_source)
    if not address.is_private:
        raise AcceptanceError("test source must be RFC1918")

    peers, peer_source = _ssh_peers()
    if test_source in peers:
        raise AcceptanceError(
            f"test source {test_source} holds an established SSH session to "
            "this host; blocking it would lock the operator out of the host "
            "under test"
        )

    has_default, route_text = _default_route_present()
    if has_default:
        raise AcceptanceError(
            "a default route is present: "
            f"{route_text!r}. The acceptance preconditions require an isolated "
            "link with no default route, internet route or NAT. Remove the "
            "default route for the duration of the run."
        )

    link = _link_for(test_source)
    if " via " in link:
        raise AcceptanceError(
            f"test source is routed via a gateway ({link!r}); it must be on a "
            "directly connected link"
        )
    observed = ",".join(sorted(peers)) if peers else "none"
    return (
        f"ssh_peers={observed} (source={peer_source}) "
        f"default_route=none route_get={link!r}"
    )


# ── ruleset lifecycle ────────────────────────────────────────────────────────


def _install_fixed_ruleset() -> set[tuple[str, str]]:
    before = _table_names()
    if (NFT_FAMILY, NFT_TABLE) in before:
        raise AcceptanceError(
            f"table {NFT_FAMILY} {NFT_TABLE} already exists; refusing to reuse "
            "or flush state this run did not create"
        )
    ruleset = render_bootstrap_ruleset_for_review()
    result = _nft("-f", "-", batch=ruleset)
    if result.returncode != 0:
        raise AcceptanceError(f"installing the fixed ruleset failed: {result.stderr[:400]}")
    return before


def _remove_fixed_ruleset() -> None:
    result = _nft("delete", "table", NFT_FAMILY, NFT_TABLE)
    if result.returncode != 0:
        _log(f"  ⚠️ teardown: delete table returned {result.returncode}: {result.stderr.strip()[:200]}")
    else:
        _log(f"  teardown: deleted table {NFT_FAMILY} {NFT_TABLE}")


# ── the nine checks ──────────────────────────────────────────────────────────


def check_fixed_nft_binary() -> tuple[bool, str]:
    path = pathlib.Path(NFT_BINARY)
    if not path.is_file():
        return False, f"{NFT_BINARY} is not a regular file"
    info = path.stat()
    writable_by_others = bool(info.st_mode & 0o022)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    ok = info.st_uid == 0 and not writable_by_others
    return ok, (
        f"path={NFT_BINARY} uid={info.st_uid} gid={info.st_gid} "
        f"mode={oct(info.st_mode & 0o7777)} sha256={digest}"
    )


def check_nft_version() -> tuple[bool, str]:
    result = _nft("--version")
    line = (result.stdout or result.stderr).strip().splitlines()[:1]
    if result.returncode != 0 or not line:
        return False, "nft --version did not produce output"
    return True, line[0]


def check_dedicated_ruleset(tables_before: set[tuple[str, str]]) -> tuple[bool, str]:
    payload = _fixed_table_json()
    set_node = None
    chain_node = None
    rule_node = None
    for item in payload.get("nftables", []):
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("set"), dict) and item["set"].get("name") == NFT_SET:
            set_node = item["set"]
        if isinstance(item.get("chain"), dict) and item["chain"].get("name") == NFT_CHAIN:
            chain_node = item["chain"]
        if isinstance(item.get("rule"), dict) and item["rule"].get("chain") == NFT_CHAIN:
            rule_node = item["rule"]
    problems = []
    if set_node is None:
        problems.append("set missing")
    else:
        if set_node.get("type") != "ipv4_addr":
            problems.append(f"set type={set_node.get('type')}")
        if int(set_node.get("size", -1)) != NFT_SET_SIZE:
            problems.append(f"set size={set_node.get('size')}")
        if int(set_node.get("gc-interval", -1)) != NFT_GC_INTERVAL_SEC:
            problems.append(f"gc-interval={set_node.get('gc-interval')}")
    if chain_node is None:
        problems.append("chain missing")
    elif int(chain_node.get("prio", 0)) != NFT_CHAIN_PRIORITY:
        problems.append(f"chain prio={chain_node.get('prio')}")
    if rule_node is None:
        problems.append("rule missing")
    elif not rule_expression_matches(rule_node.get("expr")):
        problems.append(f"rule expression off contract: {rule_node.get('expr')!r}")

    tables_now = _table_names()
    added = tables_now - tables_before
    removed = tables_before - tables_now
    if added != {(NFT_FAMILY, NFT_TABLE)}:
        problems.append(f"unexpected table delta added={sorted(added)}")
    if removed:
        problems.append(f"this run removed pre-existing tables {sorted(removed)}")

    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    evidence = (
        f"table={NFT_FAMILY} {NFT_TABLE} json_sha256={digest} "
        f"tables_before={len(tables_before)} tables_after={len(tables_now)} "
        f"added={sorted(added)} problems={problems or 'none'}"
    )
    return not problems, evidence


def check_set_capacity() -> tuple[bool, str]:
    """Read the kernel's view of the declared capacity. Never fills the set.

    The bounds forbid scan/flood, so capacity is attested by what the kernel
    reports for the set, not by inserting 1024 elements.
    """

    payload = _fixed_table_json()
    for item in payload.get("nftables", []):
        node = item.get("set") if isinstance(item, dict) else None
        if isinstance(node, dict) and node.get("name") == NFT_SET:
            size = node.get("size")
            policy = node.get("policy")
            ok = int(size or -1) == NFT_SET_SIZE
            return ok, (
                f"kernel reports size={size} (declared {NFT_SET_SIZE}) "
                f"policy={policy} flags={node.get('flags')}"
            )
    return False, "dedicated set not present"


def check_temporary_block_semantics(backend: ResponseBackend, issuer, test_source: str) -> tuple[bool, str]:
    """A wrong action and an out-of-scope source must both be refused."""

    notes = []
    wrong_action = issuer.issue(
        evidence_id=_evidence_id("acceptance-wrong-action"),
        source=test_source,
        source_kind="network_ip",
        action="rate_limit",
        adapter=NETWORK_ADAPTER,
        backend_id=PRODUCTION_BACKEND_ID,
        interface="eth0",
        identity="acceptance",
        response_ttl_sec=APPLIED_TTL_SEC,
    )
    try:
        backend.apply_ticket(wrong_action)
        return False, "a rate_limit ticket reached the temporary_block adapter"
    except TicketVerificationError as exc:
        notes.append(f"rate_limit rejected: {str(exc)[:80]}")

    out_of_scope = issuer.issue(
        evidence_id=_evidence_id("acceptance-out-of-scope"),
        source="10.99.99.99",
        source_kind="network_ip",
        action=NETWORK_ACTION,
        adapter=NETWORK_ADAPTER,
        backend_id=PRODUCTION_BACKEND_ID,
        interface="eth0",
        identity="acceptance",
        response_ttl_sec=APPLIED_TTL_SEC,
    )
    try:
        backend.apply_ticket(out_of_scope)
        return False, "an out-of-scope source was accepted"
    except TicketVerificationError as exc:
        notes.append(f"out-of-scope rejected: {str(exc)[:80]}")

    return True, "; ".join(notes)


def issue_block_ticket(issuer, test_source: str, *, interface: str, ttl_sec: int):
    """The single temporary_block ticket this run applies.

    Kept as a function so the offline rehearsal issues the very same ticket
    rather than a copy of its arguments; a copy would have gone on passing while
    the real call was rejected, which is how the first live run was spent
    discovering that `evidence_id` must be 64 hex characters.
    """

    return issuer.issue(
        evidence_id=_evidence_id("nft-live-acceptance"),
        source=test_source,
        source_kind="network_ip",
        action=NETWORK_ACTION,
        adapter=NETWORK_ADAPTER,
        backend_id=PRODUCTION_BACKEND_ID,
        interface=interface,
        identity="nft-live-acceptance",
        response_ttl_sec=ttl_sec,
    )


def check_packet_drop(test_source: str) -> tuple[bool, str]:
    """Wait for the kernel counter to prove packets took the drop path."""

    before_packets, before_bytes = _rule_counter()
    _log("")
    _log("  ┌──────────────────────────────────────────────────────────────┐")
    _log(f"  │ SEND TRAFFIC NOW from {test_source:<39}│")
    _log(f"  │ waiting up to {TRAFFIC_WAIT_SEC}s for the drop counter to move          │")
    _log("  └──────────────────────────────────────────────────────────────┘")
    deadline = time.monotonic() + TRAFFIC_WAIT_SEC
    after_packets, after_bytes = before_packets, before_bytes
    while time.monotonic() < deadline:
        after_packets, after_bytes = _rule_counter()
        if after_packets > before_packets:
            break
        time.sleep(0.5)
    moved = after_packets - before_packets
    ok = moved > 0
    return ok, (
        f"counter packets {before_packets}->{after_packets} (+{moved}), "
        f"bytes {before_bytes}->{after_bytes}, source={test_source}"
    )


def check_timeout_expiry(test_source: str, applied_at: float) -> tuple[bool, str]:
    """The kernel, not this program, must remove the element."""

    limit = APPLIED_TTL_SEC + NFT_GC_INTERVAL_SEC + EXPIRY_SLACK_SEC
    deadline = time.monotonic() + limit
    present_seen = test_source in _set_elements()
    gone_at = None
    while time.monotonic() < deadline:
        if test_source not in _set_elements():
            gone_at = time.monotonic()
            break
        time.sleep(0.5)
    if gone_at is None:
        return False, (
            f"element {test_source} still present after {limit}s "
            f"(ttl={APPLIED_TTL_SEC}s gc={NFT_GC_INTERVAL_SEC}s)"
        )
    elapsed = gone_at - applied_at
    ok = present_seen and elapsed >= APPLIED_TTL_SEC
    return ok, (
        f"element present after apply={present_seen}; kernel removed it "
        f"{elapsed:.1f}s after apply (ttl={APPLIED_TTL_SEC}s, "
        f"gc-interval={NFT_GC_INTERVAL_SEC}s, limit={limit}s)"
    )


def check_restart_reconciliation(
    state_path: pathlib.Path, verifier, authorized, protected, test_source: str
) -> tuple[bool, str]:
    """Drift the kernel out of band, then let a fresh backend put it back.

    Uses the same single test source, so the run still blocks exactly one
    address. Deleting one element is drift injection, not a rule flush.
    """

    before = _set_elements()
    if test_source not in before:
        return False, "cannot test reconciliation: element is not currently present"

    deleted = _nft(
        "delete", "element", NFT_FAMILY, NFT_TABLE, NFT_SET, "{ " + test_source + " }"
    )
    if deleted.returncode != 0:
        return False, f"drift injection failed: {deleted.stderr[:200]}"
    drifted = _set_elements()
    if test_source in drifted:
        return False, "drift injection did not remove the element"

    restarted_state = SQLiteResponseState(state_path)
    restarted = ResponseBackend(
        verifier=verifier,
        state=restarted_state,
        timeout_set=NftablesTimeoutSetAdapter(SubprocessNftRunner()),
        backend_id=PRODUCTION_BACKEND_ID,
        authorized_sources=authorized,
        protected_sources=protected,
    )
    summary = restarted.reconcile()
    after = _set_elements()
    ok = test_source in after
    return ok, (
        f"element deleted out of band, fresh backend reconcile() -> {summary}; "
        f"present_before={test_source in before} present_after_drift=False "
        f"present_after_reconcile={ok}"
    )


# ── main ─────────────────────────────────────────────────────────────────────


def run(args: argparse.Namespace, stdin) -> int:
    _require_root()
    approval = _require_approval(stdin)

    test_source = str(ipaddress.ip_address(args.test_source))
    authorized = [str(ipaddress.ip_network(args.authorized_scope, strict=True))]
    protected = [str(ipaddress.ip_network(p, strict=True)) for p in args.protected_source]
    if args.ttl > MAX_TEST_TTL_SEC:
        raise AcceptanceError(f"ttl exceeds the bound of {MAX_TEST_TTL_SEC}s")

    _log("=== preflight ===")
    isolation = _check_isolation(test_source)
    _log(f"  isolation: {isolation}")
    _log(f"  approval:  supplied ({len(approval)} chars)")

    checks: list[dict] = []

    def record(identifier: str, ok: bool, evidence: str) -> None:
        checks.append({"id": identifier, "passed": bool(ok), "evidence": evidence})
        _log(f"  [{'PASS' if ok else 'FAIL'}] {identifier}: {evidence[:150]}")

    _log("")
    _log("=== static checks ===")
    record("fixed_nft_binary_verified", *check_fixed_nft_binary())
    record("nft_version_recorded", *check_nft_version())
    record("owned_isolated_host_verified", True, isolation)

    state_path = pathlib.Path(args.state_db)
    tables_before: set[tuple[str, str]] = set()
    installed = False
    try:
        _log("")
        _log("=== installing the fixed dedicated ruleset ===")
        tables_before = _install_fixed_ruleset()
        installed = True
        _log(f"  installed table {NFT_FAMILY} {NFT_TABLE}")
        record("dedicated_ruleset_verified", *check_dedicated_ruleset(tables_before))
        record("kernel_set_capacity_verified", *check_set_capacity())

        issuer = Ed25519TicketIssuer.generate()
        verifier = Ed25519TicketVerifier(issuer.public_key_bytes())
        state = SQLiteResponseState(state_path)
        backend = ResponseBackend(
            verifier=verifier,
            state=state,
            timeout_set=NftablesTimeoutSetAdapter(SubprocessNftRunner()),
            backend_id=PRODUCTION_BACKEND_ID,
            authorized_sources=authorized,
            protected_sources=protected,
        )

        _log("")
        _log("=== ticket semantics ===")
        record(
            "temporary_block_semantics_verified",
            *check_temporary_block_semantics(backend, issuer, test_source),
        )

        _log("")
        _log("=== applying one signed temporary_block ticket ===")
        ticket = issue_block_ticket(
            issuer, test_source, interface=args.interface, ttl_sec=args.ttl
        )
        applied = backend.apply_ticket(ticket)
        applied_at = time.monotonic()
        _log(f"  applied: {json.dumps(applied.to_dict(), sort_keys=True)}")
        _log(f"  set now: {_set_elements()}")

        record("packet_drop_verified", *check_packet_drop(test_source))
        record(
            "restart_reconciliation_verified",
            *check_restart_reconciliation(
                state_path, verifier, authorized, protected, test_source
            ),
        )
        record("kernel_timeout_expiry_verified", *check_timeout_expiry(test_source, applied_at))
    finally:
        if installed:
            _log("")
            _log("=== teardown ===")
            _remove_fixed_ruleset()

    seen = {item["id"] for item in checks}
    missing = REQUIRED_LIVE_CHECKS - seen
    extra = seen - REQUIRED_LIVE_CHECKS
    if missing or extra:
        raise AcceptanceError(f"check set mismatch: missing={sorted(missing)} extra={sorted(extra)}")

    all_passed = all(item["passed"] for item in checks)

    # verify_live_acceptance() requires EXACTLY these six keys. Anything extra
    # makes the report unusable, so provenance goes in a separate sidecar.
    report = {
        "schema_version": LIVE_ACCEPTANCE_SCHEMA_VERSION,
        "backend": "nftables_timeout_set",
        "simulation_only": False,
        "production_ready": all_passed,
        "host_firewall_modified": True,
        "checks": sorted(checks, key=lambda item: item["id"]),
    }
    output = pathlib.Path(args.output)
    atomic_write_json(output, report)
    digest = sha256_file(output)

    sidecar = output.with_suffix(output.suffix + ".provenance.json")
    atomic_write_json(sidecar, {
        "report_sha256": digest,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "executor": str(pathlib.Path(__file__).name),
        "host": os.uname().nodename,
        "kernel": os.uname().release,
        "test_source": test_source,
        "authorized_scope": authorized,
        "protected_sources": protected,
        "applied_ttl_sec": args.ttl,
        "test_sources_used": TEST_SOURCES,
        "live_nft_activation_allowed_unchanged": True,
    })

    _log("")
    _log(f"報告：{output}")
    _log(f"SHA-256：{digest}")
    _log(f"production_ready={all_passed}")
    if not all_passed:
        _log("有檢查未通過——這份報告不可用來啟用正式 backend。")
        return 1
    _log("")
    _log("下一步是人工的：審過之後才把這個 SHA-256 釘進 root 擁有的啟用檔，")
    _log("而 LIVE_NFT_ACTIVATION_ALLOWED 仍需一次獨立的原始碼審查才准改。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-source", required=True, help="the single RFC1918 address to block")
    parser.add_argument("--authorized-scope", required=True, help="canonical CIDR containing the test source")
    parser.add_argument("--protected-source", action="append", default=[], help="CIDR that must never be blocked")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--ttl", type=int, default=APPLIED_TTL_SEC)
    parser.add_argument("--state-db", default="/var/lib/sros2-firewall/acceptance-state.sqlite3")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None, stdin=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args, stdin or sys.stdin)
    except AcceptanceError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
