"""Strict one-shot controlled fault seam for isolated local evidence only.

Production launch files expose no parameter, topic, or service for this seam.
It is inert unless five independent gates are present in the node environment
and a short-lived, role-specific mode-0600 arm file is atomically consumed.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path


ARM_SCHEMA = "sros2-firewall-controlled-graph-fault-arm/v2"
LIVE_ACK = "I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE"
GRAPH_FAULT_ACK = "I_CONFIRM_ONE_SHOT_CONTROLLED_GRAPH_FAULT"
LIVE_ACK_ENV = "SROS2_FIREWALL_LIVE_ACK"
GRAPH_FAULT_ACK_ENV = "SROS2_FIREWALL_GRAPH_FAULT_ACK"
GRAPH_FAULT_DIR_ENV = "SROS2_FIREWALL_GRAPH_FAULT_DIR"
MAX_ARM_BYTES = 2048
MAX_ARM_TTL_NS = 30_000_000_000
# A v1 arm produced a fault that healed on the monitor's very next graph check,
# roughly 1-2 seconds later.  That is too short to evidence: local_outcomes wants
# the fault, the guard lock and the recovery in three separate bounded windows,
# and a marker alone takes ~0.7s to be confirmed.  v2 therefore carries an
# explicit hold, measured on the monotonic clock so no wall-clock change can
# extend it, and hard-capped here regardless of what the arm record asks for.
MAX_HOLD_NS = 25_000_000_000
ROLE_FILES = {
    "monitor": "monitor.arm",
    "ids": "ids.arm",
}
# Heartbeat suppression is a second, independent seam.  It carries its own
# acknowledgement rather than sharing the graph one: arming a graph fault must
# not implicitly grant the ability to silence the monitor's heartbeat, and each
# acknowledgement is popped by exactly one consumer in each process.
HEARTBEAT_SUPPRESS_ACK = "I_CONFIRM_ONE_SHOT_CONTROLLED_HEARTBEAT_SUPPRESS"
HEARTBEAT_SUPPRESS_ACK_ENV = "SROS2_FIREWALL_HEARTBEAT_SUPPRESS_ACK"
HEARTBEAT_ROLE_FILES = {"monitor": "monitor.heartbeat.arm"}

# Refusals that are the ordinary resting state rather than a lost arm.  A seam
# whose gates are not met, and an enabled seam with nothing armed, both refuse
# on every single poll; reporting those would drown the cases that matter.
QUIET_REFUSALS = frozenset({"seam_disabled", "no_arm_file"})
NONCE_RE = re.compile(r"[0-9a-f]{32}")


def _current_uid() -> int:
    getuid = getattr(os, "getuid", None)
    return int(getuid()) if callable(getuid) else -1


def _verified_private_directory(path: Path) -> tuple[int, int]:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise RuntimeError("controlled fault directory must be an absolute real directory")
    metadata = path.stat()
    if _current_uid() < 0 or metadata.st_uid != _current_uid():
        raise RuntimeError("controlled fault directory owner mismatch")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("controlled fault directory must be mode 0700")
    return metadata.st_dev, metadata.st_ino


class ControlledFaultSeam:
    """Consume at most one arm record and report one recovery transition.

    Two seams exist and they are deliberately independent: a graph inspection
    fault and a heartbeat suppression.  Each has its own acknowledgement
    environment variable and its own arm file, so enabling one never enables
    the other, and each process pops its own copy of exactly one ack.
    """

    KIND = "graph_inspection"
    ROLE_FILE_MAP = ROLE_FILES
    ACK_ENV = GRAPH_FAULT_ACK_ENV
    ACK_VALUE = GRAPH_FAULT_ACK

    def __init__(
        self,
        *,
        role: str,
        telemetry,
        directory: Path | None,
        enabled: bool,
        directory_identity: tuple[int, int] | None = None,
    ) -> None:
        if role not in self.ROLE_FILE_MAP:
            raise ValueError("unsupported controlled fault role")
        self.role = role
        self.telemetry = telemetry
        self.directory = directory
        self.enabled = bool(enabled)
        self._directory_identity = directory_identity
        self._triggered = False
        self._recovery_pending = False
        self._hold_until_ns: int | None = None
        self._last_refusal: str | None = None
        self._reported_refusal: str | None = None
        self._last_emit_error: str | None = None

    @classmethod
    def from_environment(cls, role: str, telemetry):
        # Pop the acknowledgement in this process so it cannot be reused by a
        # later dynamically loaded component.  Each supervised ROS process has
        # its own environment and independently consumes its copy.
        graph_ack = os.environ.pop(cls.ACK_ENV, None)
        directory_text = os.environ.get(GRAPH_FAULT_DIR_ENV, "")
        gates = (
            os.environ.get("ROS_LOCALHOST_ONLY") == "1",
            os.environ.get("ROS_SECURITY_ENABLE") == "true",
            os.environ.get("ROS_SECURITY_STRATEGY") == "Enforce",
            os.environ.get(LIVE_ACK_ENV) == LIVE_ACK,
            graph_ack == cls.ACK_VALUE,
        )
        if not all(gates) or not directory_text or len(directory_text) > 256:
            return cls(role=role, telemetry=telemetry, directory=None, enabled=False)
        directory = Path(directory_text)
        try:
            identity = _verified_private_directory(directory)
        except (OSError, RuntimeError):
            return cls(role=role, telemetry=telemetry, directory=None, enabled=False)
        return cls(
            role=role,
            telemetry=telemetry,
            directory=directory.resolve(strict=True),
            enabled=True,
            directory_identity=identity,
        )

    def _directory_unchanged(self) -> bool:
        if self.directory is None or self._directory_identity is None:
            return False
        try:
            return _verified_private_directory(self.directory) == self._directory_identity
        except (OSError, RuntimeError):
            return False

    def _emit(self, state_value: str) -> None:
        """Report a seam transition, without ever letting telemetry break it.

        Swallowing the failure is deliberate -- a telemetry fault must not stop
        the seam -- but swallowing it *silently* is what hid the missing
        heartbeat_suppression vocabulary for ten days: the suppression ran
        correctly and emitted nothing, and every reader concluded the seam had
        not been consumed.  The exception is now recorded so the caller can say
        so out loud.
        """
        callback = getattr(
            self.telemetry, "emit_controlled_fault_injection", None
        )
        if not callable(callback):
            self._last_emit_error = f"{state_value}: no telemetry callback"
            return
        try:
            callback(self.KIND, state_value)
        except Exception as exc:  # noqa: BLE001 - the seam must survive this
            self._last_emit_error = f"{state_value}: {type(exc).__name__}: {exc}"

    def take_emit_error(self) -> str | None:
        """Return an unreported telemetry failure once, then forget it."""
        error = self._last_emit_error
        self._last_emit_error = None
        return error

    def _sustaining(self) -> bool:
        """True while an already-consumed arm is still holding the fault open.

        The deadline is monotonic and is set once, at consume time.  Nothing
        here re-reads the arm file, so a hold cannot be extended by touching
        the directory, and it expires on its own even if the seam is later
        disabled or the directory disappears.
        """
        if self._hold_until_ns is None:
            return False
        if time.monotonic_ns() < self._hold_until_ns:
            return True
        self._hold_until_ns = None
        return False

    def _refuse(self, reason: str) -> bool:
        """Record why an arm was not consumed and refuse it.

        Non-consumption used to be indistinguishable from a defence that did
        not react, which cost five inconclusive velocity_guard_recovered runs.
        The reason is recorded on every call; take_refusal decides what is
        worth telling anyone about.
        """
        self._last_refusal = reason
        return False

    @property
    def last_refusal(self) -> str | None:
        return self._last_refusal

    def take_refusal(self) -> str | None:
        """Return a reportable refusal once, on the edge where it changes.

        seam_disabled and no_arm_file are the ordinary resting states of any
        process that is not currently armed, so they are recorded but never
        reported; reporting them every heartbeat would bury the ones that mean
        an arm was thrown away.
        """
        reason = self._last_refusal
        if reason is None or reason in QUIET_REFUSALS:
            return None
        if reason == self._reported_refusal:
            return None
        self._reported_refusal = reason
        return reason

    def consume_if_armed(self) -> bool:
        # Sustain first: while holding, report the fault without looking at the
        # directory at all, so the hold cannot consume a second arm record.
        if self._sustaining():
            return True
        if not self.enabled:
            return self._refuse("seam_disabled")
        if self._triggered:
            # One-shot: a later arm is ignored and, because this returns before
            # touching the directory, its file is left on disk.
            return self._refuse("already_triggered")
        if not self._directory_unchanged():
            return self._refuse("directory_changed")
        assert self.directory is not None
        source = self.directory / self.ROLE_FILE_MAP[self.role]
        claim = self.directory / f".{self.role}.{os.getpid()}.{time.time_ns()}.claim"
        try:
            os.replace(source, claim)
        except FileNotFoundError:
            return self._refuse("no_arm_file")
        except OSError:
            self.enabled = False
            return self._refuse("claim_failed")
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(claim, flags)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != _current_uid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or not 0 < metadata.st_size <= MAX_ARM_BYTES
                ):
                    return self._refuse("arm_file_attributes")
                raw = os.read(descriptor, MAX_ARM_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(raw) > MAX_ARM_BYTES:
                return self._refuse("arm_too_large")
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                return self._refuse("arm_not_json")
            if not isinstance(value, dict) or set(value) != {
                "schema_version",
                "kind",
                "created_unix_ns",
                "expires_unix_ns",
                "hold_ns",
                "nonce",
            }:
                return self._refuse("arm_schema_keys")
            created = value["created_unix_ns"]
            expires = value["expires_unix_ns"]
            hold = value["hold_ns"]
            now = time.time_ns()
            if (
                value["schema_version"] != ARM_SCHEMA
                or value["kind"] != self.KIND
                or isinstance(created, bool)
                or not isinstance(created, int)
                or isinstance(expires, bool)
                or not isinstance(expires, int)
                or not created <= now <= expires
                or not 0 < expires - created <= MAX_ARM_TTL_NS
                or isinstance(hold, bool)
                or not isinstance(hold, int)
                or not 0 < hold <= MAX_HOLD_NS
                or not isinstance(value["nonce"], str)
                or NONCE_RE.fullmatch(value["nonce"]) is None
            ):
                return self._refuse("arm_field_invalid")
        finally:
            try:
                claim.unlink()
            except OSError:
                self.enabled = False
        self._triggered = True
        self._recovery_pending = True
        self._hold_until_ns = time.monotonic_ns() + hold
        self._emit("trigger")
        return True

    def record_normal_graph(self) -> None:
        if not self._recovery_pending:
            return
        self._recovery_pending = False
        self._emit("recovery")


class ControlledGraphFaultSeam(ControlledFaultSeam):
    """Makes one ROS graph inspection call fail for the length of the hold."""


class ControlledHeartbeatSuppressSeam(ControlledFaultSeam):
    """Silences the monitor's signed heartbeat for the length of the hold.

    velocity_guard_recovered needs the monitor heartbeat to lapse and then come
    back.  Doing that with SIGSTOP on the whole process does not work: five
    attempts produced the latched fault twice and a clean recovery twice, but
    never both in one session, because a freeze long enough for D5 to fire is
    also long enough for the DDS liveliness lease to declare the participant
    dead, after which the heartbeat never returns.  Suppressing only the
    publish call leaves the process, its participant and every other duty
    running, so the two stages stop competing for the same freeze duration.
    """

    KIND = "heartbeat_suppression"
    ROLE_FILE_MAP = HEARTBEAT_ROLE_FILES
    ACK_ENV = HEARTBEAT_SUPPRESS_ACK_ENV
    ACK_VALUE = HEARTBEAT_SUPPRESS_ACK

    def suppress_if_armed(self) -> bool:
        return self.consume_if_armed()

    def record_normal_heartbeat(self) -> None:
        self.record_normal_graph()


__all__ = [
    "ARM_SCHEMA",
    "ControlledFaultSeam",
    "ControlledGraphFaultSeam",
    "ControlledHeartbeatSuppressSeam",
    "HEARTBEAT_ROLE_FILES",
    "HEARTBEAT_SUPPRESS_ACK",
    "HEARTBEAT_SUPPRESS_ACK_ENV",
    "QUIET_REFUSALS",
    "GRAPH_FAULT_ACK",
    "GRAPH_FAULT_ACK_ENV",
    "GRAPH_FAULT_DIR_ENV",
    "LIVE_ACK_ENV",
    "MAX_HOLD_NS",
    "ROLE_FILES",
]
