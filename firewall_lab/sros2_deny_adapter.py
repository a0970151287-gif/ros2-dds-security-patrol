#!/usr/bin/env python3
"""Import bounded SROS2/DDS-Security deny logs as secret-free telemetry.

Only a deny category and count leave this adapter.  Raw middleware log text,
certificates, paths, identities, tokens, and policy contents are never copied
into the telemetry stream.
"""

from __future__ import annotations

import argparse
import re
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Iterable, TextIO

from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer


MAX_LOG_LINE_CHARS = 8192
MAX_LINES_PER_BATCH = 4096

# Calibrated against strings extracted from the installed vendor build
# (rmw_fastrtps_cpp / libfastrtps.so.2.14.5).  Fast DDS reports most security
# failures as "Error ...", "Cannot ...", "Unable to ..." or "Not found ..."
# rather than the deny/reject vocabulary an earlier generic pattern assumed,
# so those forms must be part of the denial gate or live SROS2 deny telemetry
# stays silently near zero.  See tests/test_runtime_telemetry.py for the
# vendor-string regression set.
_DENIAL = re.compile(
    r"(?:den(?:y|ied|ies)|reject(?:ed|ion)?|fail(?:ed|ure)?|"
    r"not[ _-]+(?:allow(?:ed)?|found|receive[d]?|support(?:ed)?|configured|"
    r"of[ _-]+the[ _-]+type)|"
    r"unauthori[sz]ed|invalid|error|cannot|unable)",
    re.IGNORECASE,
)
# Governance is evaluated before authentication because vendor governance
# errors legitimately contain "unauthenticated" (e.g. the
# allow_unauthenticated_participants / rtps_protection_kind conflict).
_GOVERNANCE = re.compile(
    r"(?:governance|protection[ _-]?kind)",
    re.IGNORECASE,
)
# Deliberately does NOT match a bare "identity": the vendor also emits
# "the identity subject name in permissions file", which is a permission
# failure, not an authentication one.
_AUTHENTICATION = re.compile(
    r"(?:authenticat(?:e|ed|ion)|handshake|identity[ _-]+certificate|"
    r"validate_(?:local|remote)_identity|identity[ _-]+validation|"
    r"identity[ _-]?handle|pkiidentity|identity_ca|dds\.sec\.auth)",
    re.IGNORECASE,
)
_PERMISSION = re.compile(
    r"(?:permission|access[ _-]+control|check_remote_(?:datareader|datawriter)|"
    r"readwrite[ _-]+permissions?|topic[ _-]+access|"
    r"deny[ _-]+rule|access[ _-]+rule|access-permissions)",
    re.IGNORECASE,
)


def classify_sros2_deny(line: str) -> str | None:
    """Return one stable category for a bounded denial line."""
    if not isinstance(line, str) or not line or len(line) > MAX_LOG_LINE_CHARS:
        return None
    if not _DENIAL.search(line):
        return None
    if _GOVERNANCE.search(line):
        return "governance"
    if _AUTHENTICATION.search(line):
        return "authentication"
    if _PERMISSION.search(line):
        return "permission"
    return None


class Sros2DenyLogAdapter:
    def __init__(self, producer: RuntimeTelemetryProducer) -> None:
        self.producer = producer
        self.lines_seen = 0
        self.denies_emitted = 0
        self.ignored = 0

    def ingest_line(self, line: str) -> str | None:
        self.lines_seen += 1
        kind = classify_sros2_deny(line.rstrip("\r\n"))
        if kind is None:
            self.ignored += 1
            return None
        if self.producer.emit_sros2_deny(kind):
            self.denies_emitted += 1
        return kind

    def ingest_lines(
        self,
        lines: Iterable[str],
        *,
        maximum: int = MAX_LINES_PER_BATCH,
    ) -> int:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
            raise ValueError("maximum must be a positive integer")
        processed = 0
        for line in lines:
            if processed >= maximum:
                break
            self.ingest_line(line)
            processed += 1
        return processed


def follow_log(
    path: Path,
    *,
    adapter: Sros2DenyLogAdapter,
    stop_event: threading.Event,
    poll_sec: float = 0.2,
    start_at_end: bool = True,
) -> None:
    """Follow one regular log file with bounded work per polling cycle."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("SROS2 log must be a regular non-symlink file")
    if not 0.05 <= float(poll_sec) <= 10.0:
        raise ValueError("poll_sec must be in 0.05..10")
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        if start_at_end:
            handle.seek(0, 2)
        while not stop_event.is_set():
            processed = 0
            while processed < MAX_LINES_PER_BATCH:
                line = handle.readline(MAX_LOG_LINE_CHARS + 2)
                if not line:
                    break
                adapter.ingest_line(line)
                processed += 1
            if processed == 0:
                stop_event.wait(float(poll_sec))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import SROS2 deny categories into local telemetry"
    )
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--source", default="sros2_log_adapter")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", type=Path)
    source.add_argument("--follow", type=Path)
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--poll-sec", type=float, default=0.2)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    producer = RuntimeTelemetryProducer(
        source=args.source,
        socket_path=args.socket,
    )
    adapter = Sros2DenyLogAdapter(producer)
    stop_event = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop_event.set()

    old_term = signal.signal(signal.SIGTERM, request_stop)
    old_int = signal.signal(signal.SIGINT, request_stop)
    handle: TextIO | None = None
    try:
        if args.follow is not None:
            follow_log(
                args.follow,
                adapter=adapter,
                stop_event=stop_event,
                poll_sec=args.poll_sec,
                start_at_end=not args.from_start,
            )
        else:
            if args.input is None:
                handle = sys.stdin
            else:
                if args.input.is_symlink() or not args.input.is_file():
                    raise SystemExit("--input must be a regular non-symlink file")
                handle = args.input.open("r", encoding="utf-8", errors="replace")
            adapter.ingest_lines(handle)
    finally:
        if handle is not None and handle is not sys.stdin:
            handle.close()
        producer.close()
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)
    print(
        f"lines_seen={adapter.lines_seen} denies_emitted={adapter.denies_emitted} "
        f"ignored={adapter.ignored}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
