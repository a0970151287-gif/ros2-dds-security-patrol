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


ARM_SCHEMA = "sros2-firewall-controlled-graph-fault-arm/v1"
LIVE_ACK = "I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE"
GRAPH_FAULT_ACK = "I_CONFIRM_ONE_SHOT_CONTROLLED_GRAPH_FAULT"
LIVE_ACK_ENV = "SROS2_FIREWALL_LIVE_ACK"
GRAPH_FAULT_ACK_ENV = "SROS2_FIREWALL_GRAPH_FAULT_ACK"
GRAPH_FAULT_DIR_ENV = "SROS2_FIREWALL_GRAPH_FAULT_DIR"
MAX_ARM_BYTES = 2048
MAX_ARM_TTL_NS = 30_000_000_000
ROLE_FILES = {
    "monitor": "monitor.arm",
    "ids": "ids.arm",
}
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


class ControlledGraphFaultSeam:
    """Consume at most one arm record and report one recovery transition."""

    def __init__(
        self,
        *,
        role: str,
        telemetry,
        directory: Path | None,
        enabled: bool,
        directory_identity: tuple[int, int] | None = None,
    ) -> None:
        if role not in ROLE_FILES:
            raise ValueError("unsupported controlled graph fault role")
        self.role = role
        self.telemetry = telemetry
        self.directory = directory
        self.enabled = bool(enabled)
        self._directory_identity = directory_identity
        self._triggered = False
        self._recovery_pending = False

    @classmethod
    def from_environment(cls, role: str, telemetry):
        # Pop the acknowledgement in this process so it cannot be reused by a
        # later dynamically loaded component.  Each supervised ROS process has
        # its own environment and independently consumes its copy.
        graph_ack = os.environ.pop(GRAPH_FAULT_ACK_ENV, None)
        directory_text = os.environ.get(GRAPH_FAULT_DIR_ENV, "")
        gates = (
            os.environ.get("ROS_LOCALHOST_ONLY") == "1",
            os.environ.get("ROS_SECURITY_ENABLE") == "true",
            os.environ.get("ROS_SECURITY_STRATEGY") == "Enforce",
            os.environ.get(LIVE_ACK_ENV) == LIVE_ACK,
            graph_ack == GRAPH_FAULT_ACK,
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
        callback = getattr(
            self.telemetry, "emit_controlled_fault_injection", None
        )
        if callable(callback):
            try:
                callback("graph_inspection", state_value)
            except Exception:
                pass

    def consume_if_armed(self) -> bool:
        if not self.enabled or self._triggered or not self._directory_unchanged():
            return False
        assert self.directory is not None
        source = self.directory / ROLE_FILES[self.role]
        claim = self.directory / f".{self.role}.{os.getpid()}.{time.time_ns()}.claim"
        try:
            os.replace(source, claim)
        except FileNotFoundError:
            return False
        except OSError:
            self.enabled = False
            return False
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
                    return False
                raw = os.read(descriptor, MAX_ARM_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(raw) > MAX_ARM_BYTES:
                return False
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                return False
            if not isinstance(value, dict) or set(value) != {
                "schema_version",
                "kind",
                "created_unix_ns",
                "expires_unix_ns",
                "nonce",
            }:
                return False
            created = value["created_unix_ns"]
            expires = value["expires_unix_ns"]
            now = time.time_ns()
            if (
                value["schema_version"] != ARM_SCHEMA
                or value["kind"] != "graph_inspection"
                or isinstance(created, bool)
                or not isinstance(created, int)
                or isinstance(expires, bool)
                or not isinstance(expires, int)
                or not created <= now <= expires
                or not 0 < expires - created <= MAX_ARM_TTL_NS
                or not isinstance(value["nonce"], str)
                or NONCE_RE.fullmatch(value["nonce"]) is None
            ):
                return False
        finally:
            try:
                claim.unlink()
            except OSError:
                self.enabled = False
        self._triggered = True
        self._recovery_pending = True
        self._emit("trigger")
        return True

    def record_normal_graph(self) -> None:
        if not self._recovery_pending:
            return
        self._recovery_pending = False
        self._emit("recovery")


__all__ = [
    "ARM_SCHEMA",
    "ControlledGraphFaultSeam",
    "GRAPH_FAULT_ACK",
    "GRAPH_FAULT_ACK_ENV",
    "GRAPH_FAULT_DIR_ENV",
    "LIVE_ACK_ENV",
    "ROLE_FILES",
]
