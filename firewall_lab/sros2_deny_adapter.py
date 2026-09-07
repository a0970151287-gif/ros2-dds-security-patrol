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

# These are precise message fragments extracted from the installed Fast DDS
# 2.14.5 vendor binary.  They are vocabulary fixtures, not proof that a live
# denial occurred.  The old classifier combined a generic word such as ERROR
# with an authentication-related word anywhere in the line.  That mislabeled
# application messages such as "[ERROR] ... authenticated clear" as DDS
# authentication failures.  Exact phrases keep an arbitrary ROS application
# log from manufacturing security telemetry merely by mentioning security.
_AUTHENTICATION_DENIALS = re.compile(
    r"(?:\bhandshake\s+failed\b|"
    r"\bhandshake\s+message\s+not\s+supported\b|"
    r"\binvalid\s+handshake\s+handle\b|"
    r"\binvalid\s+identity\s+handle\b|"
    r"\binvalid\s+pki\s+identity\s+handle\s+or\s+invalid\s+certificate\b|"
    r"\bidentityhandle\s+is\s+not\s+of\s+the\s+type\s+pkiidentityhandle\b|"
    r"\bnot\s+found\s+dds\.sec\.auth\.builtin\.pki-dh\."
    r"identity_(?:ca|certificate)\s+property\b|"
    r"\bunable\s+to\s+authenticate\s+the\s+message\b|"
    r"\bauthentication\s+plugin\s+not\s+configured\b)",
    re.IGNORECASE,
)
_PERMISSION_DENIALS = re.compile(
    r"(?:\baccess\s+control\s+permission\s+denied\b|"
    r"\baccess\s+permission\s+denied\b|"
    r"\btopic\s+denied\s+by\s+deny\s+rule\b|"
    r"\bnot\s+found\s+topic\s+access\s+rule\s+for\s+topic\b|"
    r"\berror\s+validating\s+remote\s+permissions\s+for\b|"
    r"\bnot\s+receive\s+remote\s+permissions\s+of\s+participant\b|"
    r"\bparticipant\s+is\s+not\s+allowed\s+with\s+its\s+own\s+"
    r"permissions\s+file\b|"
    r"\bcannot\s+find\s+permissions\s+file\s+in\s+permissions\s+"
    r"credential\s+token\b|"
    r"\bcannot\s+read\s+as\s+pkcs7\s+the\s+permissions\s+file\b|"
    r"\berror\s+loading\s+permissions\s+xml\b|"
    r"\binvalid\s+permissions\s+handle\b|"
    r"\bnot\s+found\s+root\s+node\s+in\s+permissions\s+xml\b|"
    r"\bnot\s+found\s+any\s+dds\.sec\.access\.builtin\."
    r"access-permissions\s+property\b|"
    r"\bnot\s+found\s+the\s+identity\s+subject\s+name\s+in\s+"
    r"permissions\s+file\b)",
    re.IGNORECASE,
)
_GOVERNANCE_DENIALS = re.compile(
    r"(?:\bgovernance\s+protection\s+kind\s+rejected\b|"
    r"\berror\s+loading\s+governance\s+xml\b|"
    r"\bnot\s+found\s+root\s+node\s+in\s+governance\s+xml\b|"
    r"\bnot\s+found\s+dds\.sec\.access\.builtin\."
    r"access-permissions\.governance\s+property\b|"
    r"\ballow_unauthenticated_participants\s+cannot\s+be\s+enabled\s+if\s+"
    r"rtps_protection_kind\s+is\s+not\s+none\b)",
    re.IGNORECASE,
)

# ROS application records are not a trusted DDS Security audit source.  A
# node can log arbitrary prose, including exact words such as "authenticated"
# and "permission denied".  Dedicated Fast DDS security records use a
# different header and should eventually be supplied by a configured security
# logging sink rather than the generic stack stdout currently followed here.
_ROS_APPLICATION_RECORD = re.compile(
    r"^\[(?:DEBUG|INFO|WARN|ERROR|FATAL)\]\s+"
    r"\[[0-9]+(?:\.[0-9]+)?\]\s+\[[^\]]+\]:",
    re.IGNORECASE,
)


def classify_sros2_deny(line: str) -> str | None:
    """Return one stable category for a bounded denial line."""
    if not isinstance(line, str) or not line or len(line) > MAX_LOG_LINE_CHARS:
        return None
    if _ROS_APPLICATION_RECORD.search(line):
        return None
    if _GOVERNANCE_DENIALS.search(line):
        return "governance"
    if _AUTHENTICATION_DENIALS.search(line):
        return "authentication"
    if _PERMISSION_DENIALS.search(line):
        return "permission"
    return None


class Sros2DenyLogAdapter:
    def __init__(self, producer: RuntimeTelemetryProducer) -> None:
        self.producer = producer
        self.lines_seen = 0
        self.records_classified = 0
        self.denies_emitted = 0
        self.send_failures = 0
        self.ignored = 0
        self.oversize_lines = 0
        self.ros_application_lines = 0

    def ingest_line(self, line: str) -> str | None:
        self.lines_seen += 1
        bounded = line.rstrip("\r\n") if isinstance(line, str) else line
        if isinstance(bounded, str) and len(bounded) > MAX_LOG_LINE_CHARS:
            self.oversize_lines += 1
        if isinstance(bounded, str) and _ROS_APPLICATION_RECORD.search(bounded):
            self.ros_application_lines += 1
        kind = classify_sros2_deny(bounded)
        if kind is None:
            self.ignored += 1
            return None
        self.records_classified += 1
        if self.producer.emit_sros2_deny(kind):
            self.denies_emitted += 1
        else:
            self.send_failures += 1
        return kind

    def summary(self) -> dict[str, int | str]:
        """Return secret-free counters without claiming zero means observed."""
        if self.records_classified:
            observability = "deny_records_observed"
        elif self.lines_seen:
            observability = "no_deny_records_observed"
        else:
            observability = "no_records_observed"
        return {
            "lines_seen": self.lines_seen,
            "records_classified": self.records_classified,
            "denies_emitted": self.denies_emitted,
            "send_failures": self.send_failures,
            "ignored": self.ignored,
            "oversize_lines": self.oversize_lines,
            "ros_application_lines": self.ros_application_lines,
            "observability": observability,
        }

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
    summary = adapter.summary()
    print(" ".join(f"{key}={value}" for key, value in summary.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
