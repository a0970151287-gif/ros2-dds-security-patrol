"""Bounded, non-blocking runtime security telemetry producer.

ROS callbacks must never wait for evidence storage.  This module therefore
sends one small, allowlisted JSON datagram to a local Unix socket and drops the
event when the collector is unavailable or back-pressured.  It never opens a
network socket, stores a secret, or accepts arbitrary event names/details.
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import time
from pathlib import Path
from typing import Callable


RUNTIME_TELEMETRY_SCHEMA_VERSION = "sros2-firewall-runtime-telemetry/v1"
TELEMETRY_SOCKET_ENV = "SROS2_FIREWALL_TELEMETRY_SOCKET"
MAX_RUNTIME_DATAGRAM_BYTES = 4096
MAX_COUNTER = 10_000_000
MAX_HEARTBEAT_GAP_SEC = 300.0
MAX_GRAPH_NODE_COUNT = 100_000

_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

HMAC_REASONS = frozenset(
    {
        "accepted",
        "invalid_configuration",
        "invalid_input",
        "malformed_envelope",
        "invalid_signature",
        "malformed_body",
        "channel_mismatch",
        "timestamp_violation",
        "nonce_reuse_or_capacity",
    }
)
DETECTORS = frozenset({"d1", "d2", "d3", "d4", "d5", "d6"})
DETECTOR_STATES = frozenset({"incident", "recovery"})
HEARTBEAT_STATES = frozenset({"gap", "recovery"})
GRAPH_STATES = frozenset({"fault", "overflow", "recovery"})
SROS2_DENY_KINDS = frozenset({"authentication", "permission", "governance"})
PROBE_TOPICS = frozenset({"scan", "odom", "imu", "cmd_vel"})
DELIVERY_PROBES = frozenset(
    {
        "unauthorized_participant",
        "hmac_forgery",
        "replay",
        "oversized_input",
        "valid_input",
    }
)
GUARD_STATES = frozenset({"locked", "released"})
GUARD_REASONS = frozenset(
    {
        "none",
        "monitor_lease_missing",
        "monitor_fault",
        "generic_alert",
        "source_none",
        "stale_command",
    }
)
AUTHENTICATED_ACTIONS = frozenset(
    {"heartbeat", "guard_lock", "guard_clear"}
)
PROCESS_STATES = frozenset({"healthy", "unhealthy"})
OUTCOME_MARKER_STAGES = {
    "normal_traffic_preserved": frozenset({"baseline"}),
    "unauthorized_participant_denied": frozenset({"trigger", "protected", "recovery"}),
    "hmac_forgery_dropped": frozenset({"trigger", "protected", "recovery"}),
    "replay_dropped": frozenset({"trigger", "protected", "recovery"}),
    "oversized_input_dropped": frozenset({"trigger", "protected", "recovery"}),
    "parameter_unchanged": frozenset({"baseline", "trigger", "protected", "recovery"}),
    "velocity_guard_zeroed": frozenset({"trigger", "protected"}),
    "velocity_guard_recovered": frozenset({"baseline", "trigger", "recovery"}),
    "graph_failure_fail_safe": frozenset({"trigger", "protected", "recovery"}),
}
# Must stay identical to the collector's vocabulary in live_telemetry_collector.
# heartbeat_suppression was added there when the second seam was written but not
# here, so the emitter rejected its own event, ControlledFaultSeam._emit swallowed
# the ValueError, and the suppression ran while emitting nothing at all.  Five
# velocity_guard_recovered attempts were read as "the seam was never consumed"
# when the seam had in fact worked every time.  tests/test_runtime_telemetry pins
# the two sides together so one can never be widened alone again.
CONTROLLED_FAULT_KINDS = frozenset({"graph_inspection", "heartbeat_suppression"})
CONTROLLED_FAULT_STATES = frozenset({"trigger", "recovery"})


def _require_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"{name} must be a bounded lowercase identifier")
    return value


def _require_choice(value: str, choices: frozenset[str], name: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"unsupported {name}")
    return value


def _require_counter(value: int, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_COUNTER
    ):
        raise ValueError(f"{name} must be an integer in 0..{MAX_COUNTER}")
    return value


class RuntimeTelemetryProducer:
    """Best-effort local producer with constant memory and bounded work.

    ``emit_*`` returns ``True`` only when the operating system accepted the
    datagram.  A missing/full collector is observable through ``dropped`` but
    never blocks or raises into the ROS callback.
    """

    def __init__(
        self,
        *,
        source: str,
        socket_path: str | os.PathLike[str] | None,
        socket_factory: Callable[..., socket.socket] = socket.socket,
    ) -> None:
        self.source = _require_identifier(source, "telemetry source")
        self.socket_path = None if socket_path is None else str(socket_path)
        if self.socket_path is not None:
            encoded = os.fsencode(self.socket_path)
            if not encoded or len(encoded) > 100 or "\x00" in self.socket_path:
                raise ValueError("telemetry socket path is invalid or too long")
        self.attempted = 0
        self.sent = 0
        self.dropped = 0
        self._socket: socket.socket | None = None
        if self.socket_path is not None:
            try:
                sock = socket_factory(socket.AF_UNIX, socket.SOCK_DGRAM)
                sock.setblocking(False)
                self._socket = sock
            except OSError:
                self._socket = None

    @classmethod
    def from_environment(cls, source: str) -> "RuntimeTelemetryProducer":
        value = os.environ.get(TELEMETRY_SOCKET_ENV)
        return cls(source=source, socket_path=value or None)

    @property
    def enabled(self) -> bool:
        return self._socket is not None and self.socket_path is not None

    def _emit(self, event_type: str, details: dict[str, object]) -> bool:
        self.attempted = min(MAX_COUNTER, self.attempted + 1)
        record = {
            "schema_version": RUNTIME_TELEMETRY_SCHEMA_VERSION,
            "ts_unix_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "source": self.source,
            "event_type": event_type,
            "details": details,
        }
        try:
            payload = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError):
            self.dropped = min(MAX_COUNTER, self.dropped + 1)
            return False
        if len(payload) > MAX_RUNTIME_DATAGRAM_BYTES or not self.enabled:
            self.dropped = min(MAX_COUNTER, self.dropped + 1)
            return False
        try:
            assert self._socket is not None and self.socket_path is not None
            written = self._socket.sendto(payload, self.socket_path)
        except (BlockingIOError, FileNotFoundError, ConnectionRefusedError, OSError):
            self.dropped = min(MAX_COUNTER, self.dropped + 1)
            return False
        if written != len(payload):
            self.dropped = min(MAX_COUNTER, self.dropped + 1)
            return False
        self.sent = min(MAX_COUNTER, self.sent + 1)
        return True

    def emit_hmac_result(self, *, accepted: bool, reason: str) -> bool:
        if not isinstance(accepted, bool):
            raise ValueError("accepted must be boolean")
        normalized = _require_choice(reason, HMAC_REASONS, "HMAC reason")
        if accepted != (normalized == "accepted"):
            raise ValueError("HMAC outcome and reason disagree")
        return self._emit(
            "hmac_result",
            {
                "outcome": "accepted" if accepted else "rejected",
                "reason": normalized,
            },
        )

    def emit_detector_state(self, detector: str, state: str) -> bool:
        return self._emit(
            "detector_state",
            {
                "detector": _require_choice(
                    detector.lower(), DETECTORS, "detector"
                ),
                "state": _require_choice(state, DETECTOR_STATES, "detector state"),
            },
        )

    def emit_heartbeat_state(self, state: str, gap_sec: float) -> bool:
        normalized_state = _require_choice(
            state, HEARTBEAT_STATES, "heartbeat state"
        )
        if (
            isinstance(gap_sec, bool)
            or not isinstance(gap_sec, (int, float))
            or not math.isfinite(float(gap_sec))
            or not 0.0 <= float(gap_sec) <= MAX_HEARTBEAT_GAP_SEC
        ):
            raise ValueError("heartbeat gap must be finite and in 0..300")
        return self._emit(
            "authenticated_heartbeat_state",
            {"state": normalized_state, "gap_sec": float(gap_sec)},
        )

    def emit_graph_state(self, state: str, node_count: int) -> bool:
        normalized_state = _require_choice(state, GRAPH_STATES, "graph state")
        if (
            isinstance(node_count, bool)
            or not isinstance(node_count, int)
            or not -1 <= node_count <= MAX_GRAPH_NODE_COUNT
        ):
            raise ValueError("graph node_count must be an integer in -1..100000")
        if normalized_state == "fault" and node_count != -1:
            raise ValueError("graph fault must use node_count=-1")
        if normalized_state != "fault" and node_count < 0:
            raise ValueError("graph overflow/recovery requires node_count >= 0")
        return self._emit(
            "graph_state",
            {"state": normalized_state, "node_count": node_count},
        )

    def emit_sros2_deny(self, kind: str, *, count: int = 1) -> bool:
        return self._emit(
            "sros2_deny",
            {
                "kind": _require_choice(kind, SROS2_DENY_KINDS, "SROS2 deny kind"),
                "count": _require_counter(count, "SROS2 deny count"),
            },
        )

    def emit_participant_change(self, *, count: int = 1) -> bool:
        """ROS graph membership churn: nodes that joined or left this poll.

        Feeds participant_churn_rate, which had no live producer until the
        2026-08-06 pilot showed the feature was structurally zero.
        """
        return self._emit(
            "participant_change",
            {"count": _require_counter(count, "participant change count")},
        )

    def emit_unknown_node(self, *, count: int = 1) -> bool:
        """Graph nodes seen that are not on the security whitelist.

        Feeds unknown_node_rate.
        """
        return self._emit(
            "unknown_node",
            {"count": _require_counter(count, "unknown node count")},
        )

    def emit_parameter_call(self, *, count: int = 1) -> bool:
        """Parameter-set attempts reaching this node, vetoed or not.

        Feeds parameter_call_rate.  Distinct from emit_parameter_veto, which
        counts only the attempts that were refused.
        """
        return self._emit(
            "parameter_call",
            {"count": _require_counter(count, "parameter call count")},
        )

    def emit_alert_observation(
        self, *, count: int = 1, reflection_count: int = 0
    ) -> bool:
        """Alert-channel traffic observed, and how much of it was a reflection
        attempt (unsigned, replayed or cross-channel input that an earlier
        confused-deputy design would have re-signed and re-published).

        Feeds alert_reflection_ratio.
        """
        total = _require_counter(count, "alert observation count")
        reflected = _require_counter(reflection_count, "alert reflection count")
        if reflected > total:
            raise ValueError("reflection count may not exceed observed count")
        return self._emit(
            "alert_observation",
            {"count": total, "reflection_count": reflected},
        )

    def emit_qos_delivery(
        self, *, expected_count: int, delivered_count: int
    ) -> bool:
        """Messages the middleware should have handed over vs. what arrived.

        ``expected = delivered + lost``, where ``lost`` comes from the DDS
        message-lost QoS event.  Feeds qos_drop_ratio, the last of the five
        telemetry features that had no live producer after the 2026-08-06
        pilot.
        """
        expected = _require_counter(expected_count, "QoS expected count")
        delivered = _require_counter(delivered_count, "QoS delivered count")
        if delivered > expected:
            raise ValueError("delivered count may not exceed expected count")
        return self._emit(
            "qos_delivery",
            {"expected_count": expected, "delivered_count": delivered},
        )

    def emit_message_validation(
        self, *, count: int = 1, oversized_count: int = 0
    ) -> bool:
        total = _require_counter(count, "message validation count")
        oversized = _require_counter(
            oversized_count, "oversized message count"
        )
        if oversized > total:
            raise ValueError("oversized count may not exceed total count")
        return self._emit(
            "message_validation",
            {"count": total, "oversized_count": oversized},
        )

    def emit_topic_probe(
        self,
        topic: str,
        *,
        message_count: int,
        publisher_count: int,
        authorized_publisher_count: int,
    ) -> bool:
        normalized_topic = _require_choice(topic, PROBE_TOPICS, "probe topic")
        messages = _require_counter(message_count, "message_count")
        publishers = _require_counter(publisher_count, "publisher_count")
        authorized = _require_counter(
            authorized_publisher_count, "authorized_publisher_count"
        )
        if authorized > publishers:
            raise ValueError(
                "authorized publisher count may not exceed publisher count"
            )
        return self._emit(
            "topic_probe",
            {
                "topic": normalized_topic,
                "message_count": messages,
                "publisher_count": publishers,
                "authorized_publisher_count": authorized,
            },
        )

    def emit_delivery_probe(self, probe: str, *, observed_count: int) -> bool:
        return self._emit(
            "delivery_probe",
            {
                "probe": _require_choice(
                    probe, DELIVERY_PROBES, "delivery probe"
                ),
                "observed_count": _require_counter(
                    observed_count, "observed_count"
                ),
            },
        )

    def emit_state_digest(self, name: str, sha256: str) -> bool:
        _require_identifier(name, "state digest name")
        if not isinstance(sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", sha256
        ):
            raise ValueError("state digest must be lowercase SHA-256")
        return self._emit("state_digest", {"name": name, "sha256": sha256})

    def emit_parameter_digest(
        self, node: str, parameter: str, sha256: str
    ) -> bool:
        _require_identifier(node, "parameter node")
        _require_identifier(parameter, "parameter name")
        if not isinstance(sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", sha256
        ):
            raise ValueError("parameter digest must be lowercase SHA-256")
        return self._emit(
            "parameter_digest",
            {"node": node, "parameter": parameter, "sha256": sha256},
        )

    def emit_process_health(self, node: str, state: str) -> bool:
        return self._emit(
            "process_health",
            {
                "node": _require_identifier(node, "process node"),
                "state": _require_choice(
                    state, PROCESS_STATES, "process health state"
                ),
            },
        )

    def emit_guard_state(self, state: str, reason: str) -> bool:
        normalized_state = _require_choice(state, GUARD_STATES, "guard state")
        normalized_reason = _require_choice(
            reason, GUARD_REASONS, "guard reason"
        )
        if normalized_state == "released" and normalized_reason != "none":
            raise ValueError("released guard state must use reason=none")
        if normalized_state == "locked" and normalized_reason == "none":
            raise ValueError("locked guard state requires a blocking reason")
        return self._emit(
            "guard_state",
            {"state": normalized_state, "reason": normalized_reason},
        )

    def emit_authenticated_action(self, action: str) -> bool:
        return self._emit(
            "authenticated_action",
            {
                "action": _require_choice(
                    action, AUTHENTICATED_ACTIONS, "authenticated action"
                )
            },
        )

    def emit_guard_input(self, *, accepted_count: int = 1) -> bool:
        return self._emit(
            "guard_input",
            {
                "accepted_count": _require_counter(
                    accepted_count, "accepted_count"
                )
            },
        )

    def emit_guard_output(
        self, linear_x: float, angular_z: float, *, blocked: bool
    ) -> bool:
        if not isinstance(blocked, bool):
            raise ValueError("blocked must be boolean")
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or abs(float(value)) > 1_000.0
            for value in (linear_x, angular_z)
        ):
            raise ValueError("guard output must contain bounded finite values")
        return self._emit(
            "guard_output",
            {
                "linear_x": float(linear_x),
                "angular_z": float(angular_z),
                "blocked": blocked,
            },
        )

    def emit_parameter_veto(
        self, *, count: int = 1, layer: str = "application"
    ) -> bool:
        """一次「參數變更被拒絕」。

        `layer` 記的是**哪一層拒絕的**：`application` 是本專案自己的
        on_set_parameters veto，`rcl_read_only` 是 rcl 在 callback 之前就擋掉。
        兩者結果相同（參數沒被改）但機制不同，分開記才能分辨防線在哪裡。
        """
        if layer not in {"application", "rcl_read_only"}:
            raise ValueError("parameter veto layer is not recognised")
        return self._emit(
            "parameter_veto",
            {
                "count": _require_counter(count, "parameter veto count"),
                "layer": layer,
            },
        )

    def emit_outcome_marker(
        self, check_id: str, stage: str, boundary: str
    ) -> bool:
        if (
            check_id not in OUTCOME_MARKER_STAGES
            or stage not in OUTCOME_MARKER_STAGES[check_id]
            or boundary not in {"start", "end"}
        ):
            raise ValueError("unsupported local outcome marker")
        return self._emit(
            "outcome_marker",
            {"check_id": check_id, "stage": stage, "boundary": boundary},
        )

    def emit_controlled_fault_injection(self, kind: str, state: str) -> bool:
        return self._emit(
            "controlled_fault_injection",
            {
                "kind": _require_choice(
                    kind, CONTROLLED_FAULT_KINDS, "controlled fault kind"
                ),
                "state": _require_choice(
                    state, CONTROLLED_FAULT_STATES, "controlled fault state"
                ),
            },
        )

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None


__all__ = [
    "DETECTORS",
    "DETECTOR_STATES",
    "GRAPH_STATES",
    "GUARD_REASONS",
    "GUARD_STATES",
    "HEARTBEAT_STATES",
    "HMAC_REASONS",
    "MAX_RUNTIME_DATAGRAM_BYTES",
    "RUNTIME_TELEMETRY_SCHEMA_VERSION",
    "RuntimeTelemetryProducer",
    "AUTHENTICATED_ACTIONS",
    "DELIVERY_PROBES",
    "PROCESS_STATES",
    "PROBE_TOPICS",
    "OUTCOME_MARKER_STAGES",
    "CONTROLLED_FAULT_KINDS",
    "CONTROLLED_FAULT_STATES",
    "SROS2_DENY_KINDS",
    "TELEMETRY_SOCKET_ENV",
]


def record_parameter_refusals(node, answer) -> int:
    """Record every unsuccessful result in a parameter-service response.

    Only set-style responses carry results; get_parameters and the rest have
    nothing to refuse, so they contribute nothing rather than an empty count.
    """
    results = getattr(answer, "results", None)
    if results is None:
        result = getattr(answer, "result", None)
        results = [result] if result is not None else []
    refused = sum(
        1 for item in results
        if getattr(item, "successful", True) is False
    )
    if not refused:
        return 0
    telemetry = getattr(node, "_telemetry", None)
    emit_veto = getattr(telemetry, "emit_parameter_veto", None)
    if callable(emit_veto):
        try:
            emit_veto(count=refused, layer="rcl_read_only")
        except Exception:
            # Same rule as the attempt counter: evidence must never break or
            # delay the node's own answer.
            pass
    return refused


