"""Passive isolated two-host topology evidence tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall_lab.cross_host_admission import _check_topology
from firewall_lab.isolated_topology import (
    HOST_ACK,
    PAIR_ACK,
    assemble_isolated_topology,
    build_host_observation,
    verify_isolated_topology_report,
)
from firewall_lab.schema import SchemaError, atomic_write_json


def _host(
    role: str,
    address: str,
    *,
    machine: str,
    boot: str,
    hardware: str | None = None,
):
    interface = "eth-test"
    return build_host_observation(
        role=role,
        interface=interface,
        link_records=[
            {"ifname": "lo", "ifindex": 1, "operstate": "UNKNOWN"},
            {"ifname": interface, "ifindex": 2, "operstate": "UP"},
        ],
        address_records=[
            {
                "ifname": interface,
                "addr_info": [
                    {"family": "inet", "scope": "global", "local": address, "prefixlen": 30}
                ],
            }
        ],
        route_records=[{"dst": "10.10.10.0/30", "dev": interface, "scope": "link"}],
        ipv6_route_records=[],
        machine_id=machine,
        boot_id=boot,
        hardware_id=hardware or f"hardware-{role}",
        hardware_id_source="dmi_product_uuid",
        ipv4_forwarding=0,
        owned_ack=HOST_ACK,
    )


def _pair(tmp_path: Path):
    attacker = tmp_path / "attacker.json"
    target = tmp_path / "target.json"
    atomic_write_json(attacker, _host("attacker", "10.10.10.1", machine="machine-a", boot="boot-a"))
    atomic_write_json(target, _host("target", "10.10.10.2", machine="machine-b", boot="boot-b"))
    report = tmp_path / "topology.json"
    assemble_isolated_topology(
        attacker_observation=attacker,
        target_observation=target,
        output=report,
        network_mode="direct_owned_ethernet",
        pair_ack=PAIR_ACK,
    )
    return attacker, target, report


def test_two_distinct_no_route_hosts_produce_verifiable_report(tmp_path):
    _attacker, _target, report = _pair(tmp_path)
    assert verify_isolated_topology_report(report) == (
        True,
        "two distinct owned hosts have hashed no-route isolation evidence",
    )
    assert _check_topology(report)[0]


def test_default_route_or_other_up_interface_fails_isolation(tmp_path):
    target = _host("target", "10.10.10.2", machine="machine-b", boot="boot-b")
    target["default_route_present"] = True
    target["isolation_verified"] = False
    target_path = tmp_path / "target.json"
    attacker_path = tmp_path / "attacker.json"
    atomic_write_json(target_path, target)
    atomic_write_json(
        attacker_path,
        _host("attacker", "10.10.10.1", machine="machine-a", boot="boot-a"),
    )

    with pytest.raises(SchemaError, match="isolation checks"):
        assemble_isolated_topology(
            attacker_observation=attacker_path,
            target_observation=target_path,
            output=tmp_path / "topology.json",
            network_mode="direct_owned_ethernet",
            pair_ack=PAIR_ACK,
        )


def test_ipv6_route_or_global_address_fails_isolation():
    observation = build_host_observation(
        role="target",
        interface="eth-test",
        link_records=[
            {"ifname": "lo", "ifindex": 1, "operstate": "UNKNOWN"},
            {"ifname": "eth-test", "ifindex": 2, "operstate": "UP"},
        ],
        address_records=[
            {
                "ifname": "eth-test",
                "addr_info": [
                    {
                        "family": "inet",
                        "scope": "global",
                        "local": "10.10.10.2",
                        "prefixlen": 30,
                    },
                    {
                        "family": "inet6",
                        "scope": "global",
                        "local": "fd00::2",
                        "prefixlen": 64,
                    },
                ],
            }
        ],
        route_records=[
            {"dst": "10.10.10.0/30", "dev": "eth-test", "scope": "link"}
        ],
        ipv6_route_records=[
            {"dst": "default", "gateway": "fd00::1", "dev": "eth-test"}
        ],
        machine_id="machine-b",
        boot_id="boot-b",
        hardware_id="hardware-b",
        hardware_id_source="dmi_product_uuid",
        ipv4_forwarding=0,
        owned_ack=HOST_ACK,
    )
    assert observation["ipv6_default_route_present"] is True
    assert observation["global_ipv6_addresses"] == ["fd00::2"]
    assert observation["isolation_verified"] is False


def test_same_machine_identity_is_rejected(tmp_path):
    attacker = tmp_path / "attacker.json"
    target = tmp_path / "target.json"
    atomic_write_json(attacker, _host("attacker", "10.10.10.1", machine="same", boot="boot-a"))
    atomic_write_json(target, _host("target", "10.10.10.2", machine="same", boot="boot-b"))

    with pytest.raises(SchemaError, match="same machine"):
        assemble_isolated_topology(
            attacker_observation=attacker,
            target_observation=target,
            output=tmp_path / "topology.json",
            network_mode="direct_owned_ethernet",
            pair_ack=PAIR_ACK,
        )


def test_same_physical_hardware_identity_is_rejected(tmp_path):
    attacker = tmp_path / "attacker.json"
    target = tmp_path / "target.json"
    atomic_write_json(
        attacker,
        _host(
            "attacker",
            "10.10.10.1",
            machine="machine-a",
            boot="boot-a",
            hardware="same-board",
        ),
    )
    atomic_write_json(
        target,
        _host(
            "target",
            "10.10.10.2",
            machine="machine-b",
            boot="boot-b",
            hardware="same-board",
        ),
    )

    with pytest.raises(SchemaError, match="same physical hardware"):
        assemble_isolated_topology(
            attacker_observation=attacker,
            target_observation=target,
            output=tmp_path / "topology.json",
            network_mode="direct_owned_ethernet",
            pair_ack=PAIR_ACK,
        )


def test_placeholder_hardware_identity_is_rejected():
    with pytest.raises(SchemaError, match="placeholder"):
        _host(
            "target",
            "10.10.10.2",
            machine="machine-b",
            boot="boot-b",
            hardware="00000000-0000-0000-0000-000000000000",
        )


def test_tampered_host_observation_breaks_report_hash(tmp_path):
    attacker, _target, report = _pair(tmp_path)
    value = json.loads(attacker.read_text(encoding="utf-8"))
    value["ipv4_address"] = "10.10.10.3"
    attacker.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(SchemaError, match="hash mismatch"):
        verify_isolated_topology_report(report)


def test_evidence_role_cannot_be_relabelled(tmp_path):
    _attacker, _target, report = _pair(tmp_path)
    value = json.loads(report.read_text(encoding="utf-8"))
    value["host_evidence"][0]["role"] = "target"
    report.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(SchemaError, match="role"):
        verify_isolated_topology_report(report)
