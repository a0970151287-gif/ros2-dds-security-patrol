#!/usr/bin/env python3
"""Detect keystore permissions that are stale relative to the canonical policy.

The structural audit already proves each enclave's signed ``permissions.p7s``
matches its own ``permissions.xml``.  That check stays green when the whole
keystore is simply old: on 2026-08-03 the canonical policy granted
``velocity_guard_node`` a ``security/heartbeat`` subscription, the keystore was
never regenerated, and SROS2 Enforce then refused to create the subscription at
runtime with

    rt/security/heartbeat topic not found in allow rule.

which killed the node and tore the whole stack down while the audit still
reported 47/47.  This module closes that gap by expanding the canonical policy
and every keystore ``permissions.xml`` into comparable grant sets.

Read-only: nothing under the keystore is modified.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# DDS name-mangling applied by `ros2 security create_permission`.
TOPIC_PREFIX = "rt/"
SERVICE_REQUEST_PREFIX = "rq/"
SERVICE_REPLY_PREFIX = "rr/"


def _text_items(node: ET.Element | None) -> list[str]:
    if node is None:
        return []
    items = []
    for child in node:
        value = (child.text or "").strip()
        if value:
            items.append(value)
    return items


def canonical_topic_grants(policy_path: Path) -> dict[str, set[str]]:
    """Map enclave directory name -> set of mangled topics the policy grants.

    The unit is the ``<enclave path=...>`` element, not ``<profile node=...>``:
    one enclave may host several nodes (``/gazebo`` covers ``gazebo``,
    ``ros_gz_bridge``, ``ros_gz_sim`` and ``robot_state_publisher``), and an
    enclave's directory name can differ from its node name (``/mission_manager``
    hosts ``mission_manager_node``).  ``ros2 security create_permission`` signs
    per enclave, so the comparison must aggregate the same way.
    """
    root = ET.parse(policy_path).getroot()
    grants: dict[str, set[str]] = {}
    for enclave in root.iter("enclave"):
        path = (enclave.get("path") or "").strip()
        if not path:
            continue
        name = path.strip("/")
        if not name:
            continue
        wanted: set[str] = set()
        for topics in enclave.iter("topics"):
            # Only ALLOW rules create grants; DENY rules never widen access.
            if "ALLOW" not in {topics.get("publish"), topics.get("subscribe")}:
                continue
            for topic in _text_items(topics):
                if "*" in topic:
                    continue  # wildcards are separately rejected by the audit
                wanted.add(TOPIC_PREFIX + topic.lstrip("/"))
        grants.setdefault(name, set()).update(wanted)
    return grants


def keystore_topic_grants(permissions_xml: Path) -> set[str]:
    """Set of rt/ topic names actually granted by a signed enclave policy."""
    text = permissions_xml.read_text(encoding="utf-8", errors="replace")
    return {
        match
        for match in re.findall(r"<topic>([^<]+)</topic>", text)
        if match.startswith(TOPIC_PREFIX)
    }


def check(keystore: Path, policy: Path) -> tuple[int, list[str]]:
    """Return (failure_count, human-readable lines)."""
    lines: list[str] = []
    failures = 0
    try:
        expected = canonical_topic_grants(policy)
    except (OSError, ET.ParseError) as exc:
        return 1, [f"canonical policy unreadable: {type(exc).__name__}: {exc}"]

    enclaves_dir = keystore / "enclaves"
    for node_name in sorted(expected):
        permissions_xml = enclaves_dir / node_name / "permissions.xml"
        if not permissions_xml.is_file():
            failures += 1
            lines.append(f"{node_name}: no permissions.xml in keystore")
            continue
        try:
            actual = keystore_topic_grants(permissions_xml)
        except OSError as exc:
            failures += 1
            lines.append(f"{node_name}: unreadable permissions.xml ({exc})")
            continue
        missing = sorted(expected[node_name] - actual)
        if missing:
            failures += 1
            lines.append(
                f"{node_name}: keystore is missing {len(missing)} granted "
                f"topic(s): {', '.join(missing)}"
            )
    return failures, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare keystore permissions against the canonical policy"
    )
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args(argv)

    failures, lines = check(args.keystore, args.policy)
    for line in lines:
        print(line)
    if failures:
        print(f"DRIFT={failures}")
        return 1
    print("DRIFT=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
