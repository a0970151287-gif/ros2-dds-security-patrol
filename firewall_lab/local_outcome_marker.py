#!/usr/bin/env python3
"""Place one fact-free boundary marker in the local telemetry stream.

The marker defines a window only.  It cannot claim a result and it never sends
ROS/DDS traffic.  The semantic probe later re-opens the events between a
start/end pair and computes the facts itself.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import time
from pathlib import Path

from .live_telemetry_collector import (
    OUTCOME_MARKER_STAGES,
    RUNTIME_TELEMETRY_SCHEMA_VERSION,
    validate_runtime_record,
)
from .local_outcomes import LIVE_ACK
from .schema import SchemaError


def emit_marker(
    *,
    socket_path: Path,
    check_id: str,
    stage: str,
    boundary: str,
    live_ack: str,
) -> None:
    if live_ack != LIVE_ACK:
        raise SchemaError("explicit live same-host loopback acknowledgement required")
    required_environment = {
        "ROS_LOCALHOST_ONLY": "1",
        "ROS_SECURITY_ENABLE": "true",
        "ROS_SECURITY_STRATEGY": "Enforce",
    }
    if any(os.environ.get(name) != value for name, value in required_environment.items()):
        raise SchemaError("outcome markers require loopback-only SROS2 Enforce")
    if (
        check_id not in OUTCOME_MARKER_STAGES
        or stage not in OUTCOME_MARKER_STAGES[check_id]
        or boundary not in {"start", "end"}
    ):
        raise SchemaError("unsupported local outcome marker")
    if not socket_path.is_absolute() or socket_path.is_symlink():
        raise SchemaError("telemetry socket must be an absolute non-symlink path")
    try:
        metadata = socket_path.lstat()
    except FileNotFoundError as exc:
        raise SchemaError("telemetry socket does not exist") from exc
    if not stat.S_ISSOCK(metadata.st_mode):
        raise SchemaError("telemetry destination is not a Unix socket")
    record = validate_runtime_record(
        {
            "schema_version": RUNTIME_TELEMETRY_SCHEMA_VERSION,
            "ts_unix_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "source": "local_outcome_controller",
            "event_type": "outcome_marker",
            "details": {
                "check_id": check_id,
                "stage": stage,
                "boundary": boundary,
            },
        }
    )
    payload = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        client.settimeout(1.0)
        written = client.sendto(payload, str(socket_path))
    finally:
        client.close()
    if written != len(payload):
        raise SchemaError("outcome marker datagram was not written completely")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--check-id", choices=tuple(OUTCOME_MARKER_STAGES), required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--boundary", choices=("start", "end"), required=True)
    parser.add_argument("--live-loopback-ack", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    emit_marker(
        socket_path=args.socket,
        check_id=args.check_id,
        stage=args.stage,
        boundary=args.boundary,
        live_ack=args.live_loopback_ack,
    )
    print(f"outcome_marker={args.check_id}/{args.stage}/{args.boundary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
