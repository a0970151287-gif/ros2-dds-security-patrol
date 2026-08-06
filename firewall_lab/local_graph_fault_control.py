#!/usr/bin/env python3
"""Prepare or arm the bounded test-only ROS graph fault seam.

This controller only writes two short-lived mode-0600 files below a dedicated
mode-0700 local runtime directory.  It never talks to ROS, kills a process, or
changes a firewall.  The monitor and IDS each atomically consume their own arm
file once.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import time
from pathlib import Path

from .schema import SchemaError


ARM_SCHEMA = "sros2-firewall-controlled-graph-fault-arm/v1"
LIVE_ACK = "I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE"
GRAPH_FAULT_ACK = "I_CONFIRM_ONE_SHOT_CONTROLLED_GRAPH_FAULT"
ROLE_FILES = ("monitor.arm", "ids.arm")


def _require_gates(live_ack: str, graph_fault_ack: str) -> None:
    if live_ack != LIVE_ACK or graph_fault_ack != GRAPH_FAULT_ACK:
        raise SchemaError("both live and one-shot graph-fault acknowledgements are required")
    expected = {
        "ROS_LOCALHOST_ONLY": "1",
        "ROS_SECURITY_ENABLE": "true",
        "ROS_SECURITY_STRATEGY": "Enforce",
    }
    if any(os.environ.get(name) != value for name, value in expected.items()):
        raise SchemaError("controlled graph fault requires loopback-only SROS2 Enforce")


def _uid() -> int:
    getuid = getattr(os, "getuid", None)
    if not callable(getuid):
        raise SchemaError("controlled graph fault is supported only on Linux")
    return int(getuid())


def _validate_parent(path: Path) -> None:
    parent = path.parent
    if not path.is_absolute() or path.name != "controlled_graph_fault":
        raise SchemaError("runtime directory must be an absolute controlled_graph_fault path")
    if parent.is_symlink() or not parent.is_dir():
        raise SchemaError("controlled graph fault parent must be a real directory")
    metadata = parent.stat()
    if metadata.st_uid != _uid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise SchemaError("controlled graph fault parent must be owned and not group/world writable")


def _validate_directory(path: Path) -> None:
    _validate_parent(path)
    if path.is_symlink() or not path.is_dir():
        raise SchemaError("controlled graph fault directory is missing or symlinked")
    metadata = path.stat()
    if metadata.st_uid != _uid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SchemaError("controlled graph fault directory must be owner mode 0700")


def prepare_directory(
    path: Path, *, live_ack: str, graph_fault_ack: str
) -> Path:
    _require_gates(live_ack, graph_fault_ack)
    _validate_parent(path)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _validate_directory(path)
    if any(path.glob("*.arm")) or any(path.glob(".*.claim")):
        raise SchemaError("controlled graph fault directory contains stale control files")
    return path.resolve(strict=True)


def arm_once(
    path: Path,
    *,
    ttl_sec: float,
    live_ack: str,
    graph_fault_ack: str,
) -> dict[str, object]:
    _require_gates(live_ack, graph_fault_ack)
    _validate_directory(path)
    if (
        isinstance(ttl_sec, bool)
        or not isinstance(ttl_sec, (int, float))
        or not 5.0 <= float(ttl_sec) <= 30.0
    ):
        raise SchemaError("controlled graph fault ttl_sec must be in 5..30")
    targets = [path / name for name in ROLE_FILES]
    if any(target.exists() or target.is_symlink() for target in targets):
        raise SchemaError("controlled graph fault is already armed")
    created = time.time_ns()
    record = {
        "schema_version": ARM_SCHEMA,
        "kind": "graph_inspection",
        "created_unix_ns": created,
        "expires_unix_ns": created + int(float(ttl_sec) * 1e9),
        "nonce": secrets.token_hex(16),
    }
    written: list[Path] = []
    try:
        for target in targets:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                payload = (
                    json.dumps(
                        record,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("utf-8")
                if os.write(descriptor, payload) != len(payload):
                    raise OSError("short controlled graph fault arm write")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            written.append(target)
    except Exception:
        for target in written:
            try:
                target.unlink()
            except OSError:
                pass
        raise
    return {
        "armed": True,
        "kind": "graph_inspection",
        "roles": ["monitor", "ids"],
        "expires_unix_ns": record["expires_unix_ns"],
        "controlled_fault_injection": True,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "arm"))
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--ttl-sec", type=float, default=20.0)
    parser.add_argument("--live-loopback-ack", required=True)
    parser.add_argument("--graph-fault-ack", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "prepare":
        directory = prepare_directory(
            args.runtime_dir,
            live_ack=args.live_loopback_ack,
            graph_fault_ack=args.graph_fault_ack,
        )
        print(f"controlled_graph_fault_prepared={directory}")
        return 0
    result = arm_once(
        args.runtime_dir,
        ttl_sec=args.ttl_sec,
        live_ack=args.live_loopback_ack,
        graph_fault_ack=args.graph_fault_ack,
    )
    print(
        "controlled_graph_fault_armed=true "
        f"expires_unix_ns={result['expires_unix_ns']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
