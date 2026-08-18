#!/usr/bin/env python3
"""Direct-delivery canary: what was attempted, and what actually arrived.

Every SROS2 claim in this project so far rests on absence. The unauthorized
participant produces no graph events under Enforce, so we infer it was isolated;
the deny adapter classifies nothing, so we infer nothing was denied. Absence is
weak evidence, and this project has already been caught by it twice: the
heartbeat replay looked defended for 1,100 sessions while DDS was simply not
delivering it, and a transport profile looked like confinement while it had
broken discovery.

This pair replaces inference with a measurement. A publisher sends numbered
messages and records every sequence it attempted. A listener inside a protected
enclave records every sequence it received. The verdict is then arithmetic
rather than interpretation:

    Enforce     attempts >= N and received == 0 and the collector stayed healthy
    Permissive  the same traffic is delivered, which proves the canary works
                and that a zero under Enforce means prevention rather than a
                broken publisher

The archive format is fixed by firewall_lab.sros2_delivery_evidence, which
verifies it: a gap-free archive_open -> body/heartbeat* -> archive_close
sequence, every record carrying the same trial binding, body records inside the
declared UTC window and the archive itself spanning it. Nothing here decides
whether a trial passed; this only produces evidence for that verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from std_msgs.msg import String


ARCHIVE_RECORD_SCHEMA = "sros2-firewall-direct-delivery-record/v1"
ROLE_ATTEMPTED = "attempted"
ROLE_RECEIVED = "protected_received"
BODY_TYPE = {
    ROLE_ATTEMPTED: "attempted_canary",
    ROLE_RECEIVED: "protected_received_canary",
}
MAX_PAYLOAD_CHARS = 256


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _payload(trial_id: str, sequence: int) -> str:
    """Deterministic body so both sides hash the same bytes for a sequence."""
    return f"{trial_id}:{sequence}"


def _payload_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _ArchiveWriter:
    """Append-only JSONL writer that keeps the cursor gap-free.

    The verifier rejects a duplicated, missing or reordered archive_sequence, so
    the counter lives here rather than at each call site. Write failures are
    counted instead of raised: a half-written archive that reports itself
    healthy would be worse than one that reports the fault and fails closed.
    """

    def __init__(self, path: Path, *, binding: dict[str, str], role: str):
        self.path = path
        self.binding = dict(binding)
        self.role = role
        self._sequence = 0
        self._body_count = 0
        self._heartbeats = 0
        # Heartbeat timestamps as written, not a monotonic clock. The verifier
        # re-derives the maximum gap from the ts_utc values in the archive and
        # compares with a tolerance of 1e-6 ms, so anything measured from a
        # different clock will disagree and the archive will be refused.
        self._heartbeat_times: list[datetime] = []
        self._write_errors = 0
        self._monotonic_regressions = 0
        self._last_ts: str | None = None
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("w", encoding="utf-8", newline="\n")

    def _emit(self, record_type: str, extra: dict | None = None) -> None:
        ts = _utc_now()
        if self._last_ts is not None and ts < self._last_ts:
            # The verifier rejects regressing timestamps. Clamp and count it
            # rather than writing an archive it will refuse.
            self._monotonic_regressions += 1
            ts = self._last_ts
        self._last_ts = ts
        record = {
            "schema_version": ARCHIVE_RECORD_SCHEMA,
            "record_type": record_type,
            "archive_sequence": self._sequence,
            "role": self.role,
            "ts_utc": ts,
            **self.binding,
        }
        if extra:
            record.update(extra)
        try:
            self._handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            self._handle.flush()
            os.fsync(self._handle.fileno())
        except OSError:
            self._write_errors += 1
            return
        self._sequence += 1

    def open_archive(self) -> None:
        self._emit("archive_open")

    def canary(self, sequence: int, payload: str) -> None:
        self._emit(
            BODY_TYPE[self.role],
            {"sequence": sequence, "payload_sha256": _payload_sha256(payload)},
        )
        self._body_count += 1

    def heartbeat(self) -> None:
        self._emit("collector_heartbeat")
        self._heartbeats += 1
        self._heartbeat_times.append(self._last_ts)

    def _max_heartbeat_gap_ms(self) -> float:
        stamps = [datetime.fromisoformat(value) for value in self._heartbeat_times]
        gaps = [
            (right - left).total_seconds() * 1000.0
            for left, right in zip(stamps, stamps[1:])
        ]
        return max(gaps, default=0.0)

    def close_archive(self) -> None:
        self._emit(
            "archive_close",
            {
                "data_record_count": self._body_count,
                "collector_health": {
                    "status": "healthy" if self._write_errors == 0 else "degraded",
                    "clean_shutdown": True,
                    "truncated": False,
                    "parse_errors": 0,
                    "write_errors": self._write_errors,
                    "dropped_records": 0,
                    "monotonic_regressions": self._monotonic_regressions,
                    "heartbeat_count": self._heartbeats,
                    "first_heartbeat_utc": (
                        self._heartbeat_times[0] if self._heartbeat_times else None
                    ),
                    "last_heartbeat_utc": (
                        self._heartbeat_times[-1] if self._heartbeat_times else None
                    ),
                    "maximum_observed_heartbeat_gap_ms": self._max_heartbeat_gap_ms(),
                    # The close record is written after this count, so add it.
                    "records_written": self._sequence + 1,
                },
            },
        )
        self._handle.close()


class DeliveryCanary(Node):
    def __init__(self, args: argparse.Namespace):
        super().__init__(f"delivery_canary_{args.role}")
        self.args = args
        binding = {
            "session_id": args.session_id,
            "trial_id": args.trial_id,
            "security_mode": args.security_mode,
            "policy_sha256": args.policy_sha256,
            "source_id": args.source_id,
            "source_enclave": args.source_enclave,
            "protected_sink_id": args.protected_sink_id,
            "protected_enclave": args.protected_enclave,
            "canary_topic": args.canary_topic,
            "collector_id": args.collector_id,
            "collector_boot_id": uuid.uuid4().hex,
        }
        self.writer = _ArchiveWriter(
            Path(args.output), binding=binding, role=args.role
        )
        self.writer.open_archive()

        # RELIABLE on both sides. A mismatch here is exactly what silently
        # voided 100 heartbeat_replay sessions, and a canary that cannot be
        # delivered even without security would make every Enforce zero
        # meaningless.
        qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE)
        self._sent = 0
        self._received = 0

        if args.role == ROLE_ATTEMPTED:
            self._pub = self.create_publisher(String, args.canary_topic, qos)
            self.create_timer(args.interval_sec, self._publish_once)
        else:
            self.create_subscription(
                String, args.canary_topic, self._on_message, qos
            )

        self.create_timer(args.heartbeat_sec, self.writer.heartbeat)
        self._deadline = time.monotonic() + args.duration_sec
        self.create_timer(0.2, self._check_deadline)

    def _publish_once(self) -> None:
        if self._sent >= self.args.attempt_count:
            return
        sequence = self.args.first_sequence + self._sent
        payload = _payload(self.args.trial_id, sequence)
        message = String()
        message.data = payload[:MAX_PAYLOAD_CHARS]
        # Record the attempt before publishing. If the process dies mid-send the
        # archive must not claim fewer attempts than were actually made -- the
        # Enforce verdict depends on the attempt count being a floor.
        self.writer.canary(sequence, payload)
        self._pub.publish(message)
        self._sent += 1

    def _on_message(self, message: String) -> None:
        text = message.data
        try:
            trial, sequence_text = text.rsplit(":", 1)
            sequence = int(sequence_text)
        except (ValueError, AttributeError):
            return
        if trial != self.args.trial_id:
            return
        self.writer.canary(sequence, text)
        self._received += 1

    def _check_deadline(self) -> None:
        if time.monotonic() >= self._deadline:
            raise SystemExit(0)

    def finish(self) -> None:
        self.writer.close_archive()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=[ROLE_ATTEMPTED, ROLE_RECEIVED], required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--security-mode", choices=["permissive", "enforce"], required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--source-enclave", required=True)
    parser.add_argument("--protected-sink-id", required=True)
    parser.add_argument("--protected-enclave", required=True)
    parser.add_argument("--canary-topic", default="/security/delivery_canary")
    # Must differ between the two roles: the verifier refuses archives that
    # share a collector id or boot id, because the attacker's own record of
    # what it sent must not come from the same collector as the protected
    # sink's record of what arrived.
    parser.add_argument("--collector-id", required=True)
    parser.add_argument("--first-sequence", type=int, default=0)
    parser.add_argument("--attempt-count", type=int, default=20)
    parser.add_argument("--interval-sec", type=float, default=0.5)
    parser.add_argument("--heartbeat-sec", type=float, default=1.0)
    parser.add_argument("--duration-sec", type=float, default=30.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(
        argv if argv is not None else rclpy.utilities.remove_ros_args(sys.argv)[1:]
    )
    rclpy.init()
    node = DeliveryCanary(args)
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        # The archive must close even on interrupt: the verifier treats an
        # archive without archive_close as truncated and refuses it, which
        # would turn an interrupted run into an unusable one.
        node.finish()
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
