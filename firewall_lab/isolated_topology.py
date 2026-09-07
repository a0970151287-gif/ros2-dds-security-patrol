#!/usr/bin/env python3
"""Read-only two-host isolation evidence for cross-host admission.

Each host records its own machine fingerprint, interface, addresses and route
state without sending packets.  The coordinator only accepts two distinct
machines on one private directly-connected subnet, with no gateway, forwarding,
default route, or other active non-loopback interface.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .schema import SchemaError, atomic_write_json, sha256_file, utc_now


HOST_SCHEMA = "sros2-firewall-isolated-host-observation/v1"
TOPOLOGY_SCHEMA = "sros2-firewall-isolated-topology/v1"
HOST_ACK = "I_CONFIRM_THIS_IS_MY_ISOLATED_LAB_HOST"
PAIR_ACK = "I_CONFIRM_OWNED_ISOLATED_LAB"
INTERFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,32}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
ROLES = frozenset({"attacker", "target"})
NETWORK_MODES = frozenset({"owned_isolated_switch", "direct_owned_ethernet"})
HARDWARE_ID_SOURCES = frozenset(
    {
        "dmi_product_uuid",
        "dmi_board_serial",
        "device_tree_serial",
    }
)
RFC1918 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _digest_machine_value(value: str, label: str) -> str:
    text = value.strip()
    if not text or len(text) > 256:
        raise SchemaError(f"invalid {label}")
    return hashlib.sha256(f"{label}:{text}".encode("utf-8")).hexdigest()


def _physical_identity(value: str) -> str:
    text = value.strip()
    compact = re.sub(r"[-: ]", "", text).lower()
    placeholders = {
        "none",
        "unknown",
        "defaultstring",
        "tobefilledbyo.e.m.",
        "notspecified",
    }
    if (
        not text
        or len(text) > 256
        or compact in placeholders
        or (compact and set(compact) <= {"0"})
        or (compact and set(compact) <= {"f"})
    ):
        raise SchemaError("physical hardware identity is missing or a placeholder")
    return text


def _run_ip_json(argv: list[str]) -> list[dict[str, Any]]:
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=5.0,
        shell=False,
    )
    if result.returncode != 0:
        raise SchemaError(f"read-only topology command failed: {argv[-2:]}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SchemaError("invalid iproute2 JSON output") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise SchemaError("unexpected iproute2 JSON root")
    return value


def _rfc1918_network(address: str, prefixlen: int) -> ipaddress.IPv4Network:
    ip = ipaddress.ip_address(address)
    if not isinstance(ip, ipaddress.IPv4Address) or not any(ip in block for block in RFC1918):
        raise SchemaError("isolated interface must use one RFC1918 IPv4 address")
    network = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
    if prefixlen < 24 or prefixlen > 30:
        raise SchemaError("isolated lab prefix must be /24 through /30")
    return network


def build_host_observation(
    *,
    role: str,
    interface: str,
    link_records: list[dict[str, Any]],
    address_records: list[dict[str, Any]],
    route_records: list[dict[str, Any]],
    ipv6_route_records: list[dict[str, Any]],
    machine_id: str,
    boot_id: str,
    hardware_id: str,
    hardware_id_source: str,
    ipv4_forwarding: int,
    owned_ack: str,
) -> dict[str, Any]:
    if role not in ROLES:
        raise SchemaError("host role must be attacker or target")
    if not isinstance(interface, str) or not INTERFACE_RE.fullmatch(interface) or interface == "lo":
        raise SchemaError("invalid isolated interface")
    if owned_ack != HOST_ACK:
        raise SchemaError("explicit per-host ownership acknowledgement required")
    if hardware_id_source not in HARDWARE_ID_SOURCES:
        raise SchemaError("a supported physical hardware identity is required")
    hardware_id = _physical_identity(hardware_id)
    selected_links = [item for item in link_records if item.get("ifname") == interface]
    if len(selected_links) != 1:
        raise SchemaError("isolated interface must exist exactly once")
    selected = selected_links[0]
    if selected.get("operstate") != "UP" or not isinstance(selected.get("ifindex"), int):
        raise SchemaError("isolated interface must be up with an ifindex")
    unexpected_up = sorted(
        str(item.get("ifname"))
        for item in link_records
        if item.get("ifname") not in {"lo", interface}
        and item.get("operstate") == "UP"
    )
    selected_addresses = [item for item in address_records if item.get("ifname") == interface]
    if len(selected_addresses) != 1:
        raise SchemaError("address snapshot must contain the isolated interface once")
    global_v4 = [
        item
        for item in selected_addresses[0].get("addr_info", [])
        if isinstance(item, dict)
        and item.get("family") == "inet"
        and item.get("scope") == "global"
        and isinstance(item.get("local"), str)
        and isinstance(item.get("prefixlen"), int)
    ]
    if len(global_v4) != 1:
        raise SchemaError("isolated interface must have exactly one global IPv4 address")
    address = global_v4[0]["local"]
    prefixlen = global_v4[0]["prefixlen"]
    network = _rfc1918_network(address, prefixlen)
    default_routes = [item for item in route_records if item.get("dst") == "default"]
    ipv6_default_routes = [
        item for item in ipv6_route_records if item.get("dst") == "default"
    ]
    global_v6 = sorted(
        str(address["local"])
        for record in address_records
        for address in record.get("addr_info", [])
        if isinstance(address, dict)
        and address.get("family") == "inet6"
        and address.get("scope") == "global"
        and isinstance(address.get("local"), str)
    )
    gateways = sorted(
        str(item["gateway"])
        for item in route_records
        if isinstance(item.get("gateway"), str) and item["gateway"]
    )
    off_interface_routes = sorted(
        str(item.get("dst", "unknown"))
        for item in route_records
        if item.get("dev") not in {None, "lo", interface}
    )
    if isinstance(ipv4_forwarding, bool) or ipv4_forwarding not in {0, 1}:
        raise SchemaError("ipv4_forwarding must be 0 or 1")
    isolation_verified = (
        not default_routes
        and not ipv6_default_routes
        and not global_v6
        and not gateways
        and not off_interface_routes
        and not unexpected_up
        and ipv4_forwarding == 0
    )
    return {
        "schema_version": HOST_SCHEMA,
        "created_utc": utc_now(),
        "role": role,
        "owned": True,
        "scope_ack": HOST_ACK,
        "machine_id_sha256": _digest_machine_value(machine_id, "machine_id"),
        "boot_id_sha256": _digest_machine_value(boot_id, "boot_id"),
        "hardware_id_source": hardware_id_source,
        "hardware_id_sha256": _digest_machine_value(
            hardware_id,
            hardware_id_source,
        ),
        "interface": interface,
        "ifindex": selected["ifindex"],
        "operstate": "UP",
        "ipv4_address": str(ipaddress.ip_address(address)),
        "prefix_length": prefixlen,
        "network_cidr": str(network),
        "default_route_present": bool(default_routes),
        "ipv6_default_route_present": bool(ipv6_default_routes),
        "global_ipv6_addresses": global_v6,
        "route_gateways": gateways,
        "unexpected_up_interfaces": unexpected_up,
        "off_interface_routes": off_interface_routes,
        "ipv4_forwarding": bool(ipv4_forwarding),
        "isolation_verified": isolation_verified,
        "network_activity": "none_read_only_route_inspection",
    }


def collect_host_observation(*, role: str, interface: str, output: Path, owned_ack: str) -> dict[str, Any]:
    if shutil.which("ip") is None:
        raise SchemaError("iproute2 is required for topology observation")
    machine_path = Path("/etc/machine-id")
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    forwarding_path = Path("/proc/sys/net/ipv4/ip_forward")
    for path in (machine_path, boot_path, forwarding_path):
        if path.is_symlink() or not path.is_file():
            raise SchemaError(f"required host identity/state file missing: {path}")
    hardware_candidates = (
        ("dmi_product_uuid", Path("/sys/class/dmi/id/product_uuid")),
        ("dmi_board_serial", Path("/sys/class/dmi/id/board_serial")),
        ("device_tree_serial", Path("/proc/device-tree/serial-number")),
        ("device_tree_serial", Path("/sys/firmware/devicetree/base/serial-number")),
    )
    hardware_source = ""
    hardware_value = ""
    for source, candidate in hardware_candidates:
        if candidate.is_file() and not candidate.is_symlink():
            try:
                value = candidate.read_bytes().rstrip(b"\x00\r\n \t")
            except OSError:
                continue
            if value:
                try:
                    hardware_value = value.decode("ascii")
                except UnicodeDecodeError:
                    hardware_value = value.hex()
                hardware_source = source
                break
    if not hardware_value:
        raise SchemaError(
            "physical hardware identity unavailable; cross-host proof remains blocked"
        )
    observation = build_host_observation(
        role=role,
        interface=interface,
        link_records=_run_ip_json(["ip", "-j", "link", "show"]),
        address_records=_run_ip_json(["ip", "-j", "address", "show"]),
        route_records=_run_ip_json(["ip", "-j", "route", "show", "table", "main"]),
        ipv6_route_records=_run_ip_json(
            ["ip", "-j", "-6", "route", "show", "table", "main"]
        ),
        machine_id=machine_path.read_text(encoding="utf-8"),
        boot_id=boot_path.read_text(encoding="utf-8"),
        hardware_id=hardware_value,
        hardware_id_source=hardware_source,
        ipv4_forwarding=int(forwarding_path.read_text(encoding="ascii").strip()),
        owned_ack=owned_ack,
    )
    atomic_write_json(output, observation)
    return observation


def _read_host(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SchemaError("host observation must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError("invalid host observation JSON") from exc
    required = {
        "schema_version", "created_utc", "role", "owned", "scope_ack",
        "machine_id_sha256", "boot_id_sha256", "interface", "ifindex",
        "hardware_id_source", "hardware_id_sha256",
        "operstate", "ipv4_address", "prefix_length", "network_cidr",
        "default_route_present", "route_gateways", "unexpected_up_interfaces",
        "ipv6_default_route_present", "global_ipv6_addresses",
        "off_interface_routes", "ipv4_forwarding", "isolation_verified",
        "network_activity",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise SchemaError("host observation has unexpected keys")
    if value["schema_version"] != HOST_SCHEMA or value["role"] not in ROLES:
        raise SchemaError("unsupported host observation")
    if value["owned"] is not True or value["scope_ack"] != HOST_ACK:
        raise SchemaError("host ownership is not confirmed")
    if value["isolation_verified"] is not True:
        raise SchemaError("host isolation checks did not pass")
    if (
        value["default_route_present"] is not False
        or value["ipv6_default_route_present"] is not False
        or value["global_ipv6_addresses"] != []
        or value["route_gateways"] != []
        or value["unexpected_up_interfaces"] != []
        or value["off_interface_routes"] != []
        or value["ipv4_forwarding"] is not False
        or value["operstate"] != "UP"
        or value["network_activity"] != "none_read_only_route_inspection"
    ):
        raise SchemaError("host observation contradicts isolation claim")
    if value["hardware_id_source"] not in HARDWARE_ID_SOURCES:
        raise SchemaError("unsupported physical hardware identity source")
    for name in ("machine_id_sha256", "boot_id_sha256", "hardware_id_sha256"):
        if not isinstance(value[name], str) or not HEX64_RE.fullmatch(value[name]):
            raise SchemaError(f"invalid {name}")
    if not isinstance(value["interface"], str) or not INTERFACE_RE.fullmatch(value["interface"]) or value["interface"] == "lo":
        raise SchemaError("invalid host interface")
    if isinstance(value["ifindex"], bool) or not isinstance(value["ifindex"], int) or value["ifindex"] < 1:
        raise SchemaError("invalid host interface index")
    address = ipaddress.ip_address(value["ipv4_address"])
    network = _rfc1918_network(str(address), value["prefix_length"])
    if str(network) != value["network_cidr"]:
        raise SchemaError("host network CIDR mismatch")
    return value


def assemble_isolated_topology(
    *,
    attacker_observation: Path,
    target_observation: Path,
    output: Path,
    network_mode: str,
    pair_ack: str,
) -> dict[str, Any]:
    if pair_ack != PAIR_ACK:
        raise SchemaError("explicit owned isolated lab acknowledgement required")
    if network_mode not in NETWORK_MODES:
        raise SchemaError("unsupported isolated network mode")
    attacker = _read_host(attacker_observation)
    target = _read_host(target_observation)
    if attacker["role"] != "attacker" or target["role"] != "target":
        raise SchemaError("host observation roles are swapped")
    if attacker["machine_id_sha256"] == target["machine_id_sha256"]:
        raise SchemaError("attacker and target have the same machine identity")
    if attacker["boot_id_sha256"] == target["boot_id_sha256"]:
        raise SchemaError("attacker and target have the same boot identity")
    if attacker["hardware_id_sha256"] == target["hardware_id_sha256"]:
        raise SchemaError("attacker and target have the same physical hardware identity")
    attacker_ip = ipaddress.ip_address(attacker["ipv4_address"])
    target_ip = ipaddress.ip_address(target["ipv4_address"])
    if attacker_ip == target_ip or attacker["network_cidr"] != target["network_cidr"]:
        raise SchemaError("hosts must use distinct IPs on one isolated subnet")
    output_root = output.parent.resolve(strict=True)
    evidence: list[dict[str, Any]] = []
    for role, path in (("attacker", attacker_observation), ("target", target_observation)):
        resolved = path.resolve(strict=True)
        if resolved.parent != output_root:
            raise SchemaError("topology report and host observations must share one evidence directory")
        evidence.append({"role": role, "path": path.name, "sha256": sha256_file(path)})
    report = {
        "schema_version": TOPOLOGY_SCHEMA,
        "created_utc": utc_now(),
        "attacker_ip": str(attacker_ip),
        "target_ip": str(target_ip),
        "attacker_owned": True,
        "target_owned": True,
        "same_physical_host": False,
        "default_route_present": False,
        "internet_reachable": False,
        "network_mode": network_mode,
        "capture_interface": target["interface"],
        "scope_ack": PAIR_ACK,
        "host_evidence": evidence,
    }
    atomic_write_json(output, report)
    return report


def verify_isolated_topology_report(path: Path) -> tuple[bool, str]:
    if path.is_symlink() or not path.is_file():
        raise SchemaError("topology report must be a regular non-symlink file")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError("invalid topology report JSON") from exc
    expected = {
        "schema_version", "created_utc", "attacker_ip", "target_ip",
        "attacker_owned", "target_owned", "same_physical_host",
        "default_route_present", "internet_reachable", "network_mode",
        "capture_interface", "scope_ack", "host_evidence",
    }
    if not isinstance(report, dict) or set(report) != expected:
        raise SchemaError("topology report has unexpected keys")
    evidence = report["host_evidence"]
    if not isinstance(evidence, list) or len(evidence) != 2:
        raise SchemaError("topology report needs two host evidence files")
    by_role: dict[str, Path] = {}
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"role", "path", "sha256"}:
            raise SchemaError("invalid topology host evidence record")
        role = item["role"]
        if role not in ROLES or role in by_role or Path(item["path"]).name != item["path"]:
            raise SchemaError("invalid topology evidence role or path")
        host_path = path.parent / item["path"]
        if host_path.is_symlink() or not host_path.is_file() or sha256_file(host_path) != item["sha256"]:
            raise SchemaError("topology host evidence missing or hash mismatch")
        by_role[role] = host_path
    attacker = _read_host(by_role["attacker"])
    target = _read_host(by_role["target"])
    if attacker["role"] != "attacker" or target["role"] != "target":
        raise SchemaError("topology host roles do not match evidence bindings")
    if (
        attacker["machine_id_sha256"] == target["machine_id_sha256"]
        or attacker["boot_id_sha256"] == target["boot_id_sha256"]
        or attacker["hardware_id_sha256"] == target["hardware_id_sha256"]
    ):
        raise SchemaError("topology evidence does not prove distinct hosts")
    if report != {
        **report,
        "attacker_ip": attacker["ipv4_address"],
        "target_ip": target["ipv4_address"],
        "capture_interface": target["interface"],
    }:
        raise SchemaError("topology summary does not match host evidence")
    if (
        report["schema_version"] != TOPOLOGY_SCHEMA
        or report["attacker_owned"] is not True
        or report["target_owned"] is not True
        or report["same_physical_host"] is not False
        or report["default_route_present"] is not False
        or report["internet_reachable"] is not False
        or report["network_mode"] not in NETWORK_MODES
        or report["scope_ack"] != PAIR_ACK
        or attacker["network_cidr"] != target["network_cidr"]
        or attacker["ipv4_address"] == target["ipv4_address"]
    ):
        raise SchemaError("topology safety assertions failed")
    return True, "two distinct owned hosts have hashed no-route isolation evidence"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect")
    collect.add_argument("--role", choices=sorted(ROLES), required=True)
    collect.add_argument("--interface", required=True)
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument("--owned-ack", required=True)
    combine = subparsers.add_parser("combine")
    combine.add_argument("--attacker", type=Path, required=True)
    combine.add_argument("--target", type=Path, required=True)
    combine.add_argument("--output", type=Path, required=True)
    combine.add_argument("--network-mode", choices=sorted(NETWORK_MODES), required=True)
    combine.add_argument("--pair-ack", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "collect":
        collect_host_observation(role=args.role, interface=args.interface, output=args.output, owned_ack=args.owned_ack)
    else:
        assemble_isolated_topology(
            attacker_observation=args.attacker,
            target_observation=args.target,
            output=args.output,
            network_mode=args.network_mode,
            pair_ack=args.pair_ack,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
