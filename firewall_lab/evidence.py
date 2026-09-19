"""Authenticated evidence envelopes for dynamic firewall responses.

The response layer must not trust a caller-supplied ``source`` or a bare
64-character identifier.  A trusted collector signs the source attribution,
model decision, feature digest, independent signals, and observation window.
The authorizer verifies that immutable envelope before it can issue a live
response ticket.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import secrets
import signal
import subprocess
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .decision import FirewallDecision
from .response_backend import (
    BackendUnavailableError,
    Ed25519TicketIssuer,
    Ed25519TicketVerifier,
    TICKET_SCHEMA_VERSION,
    TicketVerificationError,
)
from .schema import (
    SchemaError,
    atomic_write_json,
    safe_json_value,
    sha256_file,
    utc_now,
)


class JsonlWriter:
    """Append bounded JSON records without following output symlinks."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or (
            self.path.exists() and self.path.is_symlink()
        ):
            raise SchemaError("JSONL evidence path may not be symlinked")
        self._lock = threading.Lock()

    def append(self, value: Any) -> None:
        encoded = json.dumps(
            safe_json_value(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        with self._lock:
            if self.path.exists() and self.path.is_symlink():
                raise SchemaError("JSONL evidence path became a symlink")
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())


@dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    return_code: int
    started_utc: str
    ended_utc: str
    duration_sec: float
    terminated_by_factory: bool
    timed_out: bool
    stdout_path: str
    stderr_path: str

    def to_dict(self) -> dict[str, Any]:
        return safe_json_value(asdict(self))


class ManagedProcess:
    """A bounded subprocess with explicit output files and deterministic stop."""

    def __init__(
        self,
        *,
        argv: list[str],
        cwd: str | Path,
        env: Mapping[str, str],
        stdout_path: str | Path,
        stderr_path: str | Path,
    ):
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(item, str) or not item for item in argv)
        ):
            raise ValueError("managed process argv must be a non-empty string list")
        self.argv = tuple(argv)
        self.cwd = Path(cwd)
        self.env = {str(key): str(value) for key, value in env.items()}
        self.stdout_path = Path(stdout_path)
        self.stderr_path = Path(stderr_path)
        self._process: subprocess.Popen[str] | None = None
        self._stdout_handle: Any | None = None
        self._stderr_handle: Any | None = None
        self._started_utc = ""
        self._started_monotonic = 0.0
        self._result: ProcessResult | None = None

    def start(self) -> None:
        if self._process is not None or self._result is not None:
            raise RuntimeError("managed process may only be started once")
        for path in (self.stdout_path, self.stderr_path):
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.parent.is_symlink() or (path.exists() and path.is_symlink()):
                raise SchemaError("process evidence output may not be symlinked")
        self._stdout_handle = self.stdout_path.open(
            "w", encoding="utf-8", newline="\n"
        )
        self._stderr_handle = self.stderr_path.open(
            "w", encoding="utf-8", newline="\n"
        )
        self._started_utc = utc_now()
        self._started_monotonic = time.monotonic()
        try:
            self._process = subprocess.Popen(
                list(self.argv),
                cwd=self.cwd,
                env=self.env,
                stdout=self._stdout_handle,
                stderr=self._stderr_handle,
                text=True,
                shell=False,
                start_new_session=True,
            )
        except Exception:
            self._close_handles()
            raise

    def _close_handles(self) -> None:
        for handle in (self._stdout_handle, self._stderr_handle):
            if handle is not None and not handle.closed:
                handle.flush()
                handle.close()

    def poll(self) -> int | None:
        """Exit code if the process has finished, else None.

        Lets a caller waiting on a startup side effect (a socket appearing,
        a file being written) notice that the process died instead of sitting
        out its whole timeout.
        """
        if self._process is None:
            return None
        return self._process.poll()

    def _signal_group(self, sig: int) -> None:
        """Signal the whole process group, not just the direct child.

        ``start()`` uses ``start_new_session=True``, so the child is its own
        process-group leader and its descendants share that group.  Signalling
        only the child leaves those descendants running: the
        ``unauthorized_participant`` runner is ``ros2 run demo_nodes_cpp
        talker``, where ``ros2 run`` is a CLI wrapper that execs the real
        talker, and the 2026-08-07 ten-session batch left one talker alive
        afterwards.  Across the 50 such sessions in a 550-session arm those
        survivors would accumulate on domain 30 and publish into every later
        session, contaminating the network features of runs that were supposed
        to be attack-free.

        Falls back to signalling the child alone if the group is already gone,
        so a race during teardown cannot raise here.
        """
        if self._process is None:
            return
        try:
            os.killpg(os.getpgid(self._process.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                self._process.send_signal(sig)
            except (ProcessLookupError, OSError):
                pass

    def stop(self, *, grace_sec: float = 3.0) -> ProcessResult:
        if self._result is not None:
            return self._result
        if self._process is None:
            raise RuntimeError("managed process was not started")
        if (
            isinstance(grace_sec, bool)
            or not isinstance(grace_sec, (int, float))
            or not math.isfinite(float(grace_sec))
            or float(grace_sec) < 0.0
        ):
            raise ValueError("grace_sec must be a non-negative finite number")
        terminated = self._process.poll() is None
        timed_out = False
        if terminated:
            self._signal_group(signal.SIGTERM)
            try:
                self._process.wait(timeout=float(grace_sec))
            except subprocess.TimeoutExpired:
                timed_out = True
                self._signal_group(signal.SIGKILL)
                self._process.wait(timeout=3.0)
        return_code = self._process.returncode
        self._close_handles()
        self._result = ProcessResult(
            argv=self.argv,
            return_code=int(return_code if return_code is not None else -9),
            started_utc=self._started_utc,
            ended_utc=utc_now(),
            duration_sec=max(0.0, time.monotonic() - self._started_monotonic),
            terminated_by_factory=terminated,
            timed_out=timed_out,
            stdout_path=str(self.stdout_path),
            stderr_path=str(self.stderr_path),
        )
        return self._result


class ResourceSampler:
    """Write bounded host resource samples on a daemon thread."""

    def __init__(self, path: str | Path, *, interval_sec: float = 1.0):
        if (
            isinstance(interval_sec, bool)
            or not isinstance(interval_sec, (int, float))
            or not math.isfinite(float(interval_sec))
            or float(interval_sec) <= 0.0
        ):
            raise ValueError("interval_sec must be a positive finite number")
        self.writer = JsonlWriter(path)
        self.interval_sec = float(interval_sec)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "schema_version": "sros2-firewall-resource-sample/v1",
            "ts_unix_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "pid": os.getpid(),
        }
        try:
            load = os.getloadavg()
            record["load_1m"] = float(load[0])
            record["load_5m"] = float(load[1])
            record["load_15m"] = float(load[2])
        except (AttributeError, OSError):
            record["load_1m"] = None
            record["load_5m"] = None
            record["load_15m"] = None
        return record

    def _run(self) -> None:
        while not self._stop.is_set():
            self.writer.append(self._sample())
            self._stop.wait(self.interval_sec)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("resource sampler may only be started once")
        self._thread = threading.Thread(
            target=self._run, name="firewall-resource-sampler", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(2.0, self.interval_sec * 2.0))


def run_snapshot(
    *,
    argv: list[str],
    cwd: str | Path,
    env: Mapping[str, str],
    output_path: str | Path,
    timeout_sec: float,
) -> dict[str, Any]:
    """Run one read-only command and atomically preserve its bounded result."""

    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) or not item for item in argv)
    ):
        raise ValueError("snapshot argv must be a non-empty string list")
    if (
        isinstance(timeout_sec, bool)
        or not isinstance(timeout_sec, (int, float))
        or not math.isfinite(float(timeout_sec))
        or float(timeout_sec) <= 0.0
    ):
        raise ValueError("timeout_sec must be a positive finite number")
    started_utc = utc_now()
    started = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run(
            argv,
            cwd=Path(cwd),
            env={str(key): str(value) for key, value in env.items()},
            capture_output=True,
            text=True,
            timeout=float(timeout_sec),
            check=False,
            shell=False,
        )
        return_code = int(result.returncode)
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        return_code = -9
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    record = {
        "schema_version": "sros2-firewall-process-snapshot/v1",
        "argv": list(argv),
        "started_utc": started_utc,
        "ended_utc": utc_now(),
        "duration_sec": max(0.0, time.monotonic() - started),
        "return_code": return_code,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
    }
    bounded = safe_json_value(record)
    atomic_write_json(output_path, bounded)
    return bounded


def evidence_inventory(root: str | Path) -> dict[str, dict[str, Any]]:
    """Hash regular evidence files, excluding the self-referential manifest."""

    directory = Path(root)
    if not directory.is_dir() or directory.is_symlink():
        raise SchemaError("evidence root must be a real directory")
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise SchemaError(f"evidence may not contain symlinks: {path}")
        if not path.is_file() or path.name == "manifest.json":
            continue
        relative = path.relative_to(directory).as_posix()
        result[relative] = {
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    return result


EVIDENCE_SCHEMA_VERSION = "sros2-firewall-evidence/v1"
EVIDENCE_TICKET_SCHEMA_VERSION = TICKET_SCHEMA_VERSION
SOURCE_KINDS = frozenset(
    {"network_ip", "dds_identity", "local_process", "unknown"}
)
SIGNAL_NAMES = frozenset(
    {"network", "telemetry", "sros2", "application_hmac", "ros_behavior", "host"}
)
_HEX = frozenset("0123456789abcdef")
_MAX_TEXT = 128
_MAX_RESPONSE_TTL_SEC = 300


def _text(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SchemaError(f"{name} must be text")
    result = value.strip()
    if (not result and not allow_empty) or len(result) > _MAX_TEXT:
        raise SchemaError(f"{name} must be 1..{_MAX_TEXT} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise SchemaError(f"{name} contains control characters")
    return result


def _hex(value: Any, length: int, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(char not in _HEX for char in value)
    ):
        raise SchemaError(f"{name} must be {length} lowercase hexadecimal characters")
    return value


def _probability(value: Any, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise SchemaError(f"{name} must be finite and in 0..1")
    return float(value)


def _normalize_source(source: Any, source_kind: str) -> str:
    result = _text(source, "source")
    if source_kind == "network_ip":
        try:
            return str(ipaddress.ip_address(result))
        except ValueError as exc:
            raise SchemaError("network evidence source must be one IP address") from exc
    return result


def _normalize_signals(value: Mapping[str, float]) -> tuple[tuple[str, float], ...]:
    if not isinstance(value, Mapping):
        raise SchemaError("signals must be a mapping")
    unknown = set(value) - SIGNAL_NAMES
    if unknown:
        raise SchemaError(f"unknown response signals: {sorted(unknown)}")
    return tuple(
        sorted(
            (
                _text(name, "signal name"),
                _probability(score, f"signals.{name}"),
            )
            for name, score in value.items()
        )
    )


def feature_sha256(features: Mapping[str, Any]) -> str:
    """Hash a finite numeric feature mapping using one canonical encoding."""

    if not isinstance(features, Mapping) or not features:
        raise SchemaError("features must be a non-empty mapping")
    normalized: dict[str, float] = {}
    for name, raw in features.items():
        key = _text(name, "feature name")
        if (
            isinstance(raw, bool)
            or not isinstance(raw, (int, float))
            or not math.isfinite(float(raw))
        ):
            raise SchemaError(f"feature {key} must be a finite number")
        normalized[key] = float(raw)
    encoded = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class EvidenceEnvelope:
    source: str
    source_kind: str
    interface: str
    identity: str
    feature_sha256: str
    session_id: str
    window_id: str
    collector_id: str
    model_sha256: str
    policy_sha256: str
    backend_id: str
    observed_at_ns: int
    nonce: str
    attribution_confidence: float
    signals: tuple[tuple[str, float], ...]
    source_shared: bool
    confirmation_windows: int
    predicted_class: str
    decision_confidence: float
    anomaly: bool
    action: str
    adapter: str
    executable: bool
    evidence_id: str
    signature: str
    schema_version: str = EVIDENCE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["signals"] = dict(self.signals)
        return safe_json_value(value)


class EvidenceAuthority:
    """Issue and verify HMAC-authenticated response evidence.

    The secret belongs to the trusted local collector/orchestrator.  Network
    input and the legacy ML response object must never be allowed to supply it.
    """

    def __init__(
        self,
        secret: bytes,
        *,
        collector_id: str,
        max_claims: int = 4096,
        ticket_issuer: Ed25519TicketIssuer | None = None,
    ):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("evidence authority secret must contain at least 32 bytes")
        if isinstance(max_claims, bool) or not isinstance(max_claims, int) or max_claims < 1:
            raise ValueError("max_claims must be a positive integer")
        self._secret = bytes(secret)
        self.collector_id = _text(collector_id, "collector_id")
        self.max_claims = max_claims
        if ticket_issuer is not None and type(ticket_issuer) is not Ed25519TicketIssuer:
            raise TypeError("ticket_issuer must be an Ed25519TicketIssuer")
        try:
            self._ticket_issuer = ticket_issuer or Ed25519TicketIssuer.generate()
        except BackendUnavailableError:
            # Evidence collection and observe-mode inference remain available,
            # but claim() will fail closed instead of falling back to a shared
            # HMAC ticket that a privileged verifier could also forge.
            self._ticket_issuer = None
        self._claims: OrderedDict[
            str, tuple[str, str, str, int, str]
        ] = OrderedDict()
        self._consumed_tickets: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _payload(envelope: EvidenceEnvelope) -> dict[str, Any]:
        return {
            "schema_version": envelope.schema_version,
            "source": envelope.source,
            "source_kind": envelope.source_kind,
            "interface": envelope.interface,
            "identity": envelope.identity,
            "feature_sha256": envelope.feature_sha256,
            "session_id": envelope.session_id,
            "window_id": envelope.window_id,
            "collector_id": envelope.collector_id,
            "model_sha256": envelope.model_sha256,
            "policy_sha256": envelope.policy_sha256,
            "backend_id": envelope.backend_id,
            "observed_at_ns": envelope.observed_at_ns,
            "nonce": envelope.nonce,
            "attribution_confidence": envelope.attribution_confidence,
            "signals": dict(envelope.signals),
            "source_shared": envelope.source_shared,
            "confirmation_windows": envelope.confirmation_windows,
            "predicted_class": envelope.predicted_class,
            "decision_confidence": envelope.decision_confidence,
            "anomaly": envelope.anomaly,
            "action": envelope.action,
            "adapter": envelope.adapter,
            "executable": envelope.executable,
        }

    @classmethod
    def _encoded_payload(cls, envelope: EvidenceEnvelope) -> bytes:
        return json.dumps(
            cls._payload(envelope),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def issue(
        self,
        *,
        source: str,
        source_kind: str,
        interface: str,
        identity: str,
        feature_digest: str,
        session_id: str,
        window_id: str,
        model_sha256: str,
        policy_sha256: str,
        backend_id: str,
        attribution_confidence: float,
        signals: Mapping[str, float],
        source_shared: bool,
        confirmation_windows: int,
        decision: FirewallDecision,
        observed_at_ns: int | None = None,
        nonce: str | None = None,
    ) -> EvidenceEnvelope:
        if source_kind not in SOURCE_KINDS:
            raise SchemaError("unsupported evidence source_kind")
        if not isinstance(source_shared, bool):
            raise SchemaError("source_shared must be bool")
        if (
            isinstance(confirmation_windows, bool)
            or not isinstance(confirmation_windows, int)
            or confirmation_windows < 0
        ):
            raise SchemaError("confirmation_windows must be a non-negative integer")
        timestamp = time.time_ns() if observed_at_ns is None else observed_at_ns
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 1:
            raise SchemaError("observed_at_ns must be a positive integer")
        if not isinstance(decision.anomaly, bool):
            raise SchemaError("decision anomaly must be bool")
        if not isinstance(decision.executable, bool):
            raise SchemaError("decision executable must be bool")
        envelope = EvidenceEnvelope(
            source=_normalize_source(source, source_kind),
            source_kind=source_kind,
            interface=_text(interface, "interface"),
            identity=_text(identity, "identity"),
            feature_sha256=_hex(feature_digest, 64, "feature_sha256"),
            session_id=_text(session_id, "session_id"),
            window_id=_text(window_id, "window_id"),
            collector_id=self.collector_id,
            model_sha256=_hex(model_sha256, 64, "model_sha256"),
            policy_sha256=_hex(policy_sha256, 64, "policy_sha256"),
            backend_id=_text(backend_id, "backend_id"),
            observed_at_ns=timestamp,
            nonce=_hex(nonce or secrets.token_hex(16), 32, "nonce"),
            attribution_confidence=_probability(
                attribution_confidence, "attribution_confidence"
            ),
            signals=_normalize_signals(signals),
            source_shared=source_shared,
            confirmation_windows=confirmation_windows,
            predicted_class=_text(decision.predicted_class, "predicted_class"),
            decision_confidence=_probability(
                decision.confidence, "decision_confidence"
            ),
            anomaly=decision.anomaly,
            action=_text(decision.action, "action"),
            adapter=_text(decision.adapter, "adapter"),
            executable=decision.executable,
            evidence_id="0" * 64,
            signature="0" * 64,
        )
        encoded = self._encoded_payload(envelope)
        evidence_id = hashlib.sha256(encoded).hexdigest()
        signature = hmac.new(
            self._secret, b"evidence\x00" + encoded, hashlib.sha256
        ).hexdigest()
        return EvidenceEnvelope(
            **{
                **asdict(envelope),
                "evidence_id": evidence_id,
                "signature": signature,
            }
        )

    def verify(self, envelope: EvidenceEnvelope) -> EvidenceEnvelope:
        if not isinstance(envelope, EvidenceEnvelope):
            raise SchemaError("evidence envelope is missing or has the wrong type")
        if envelope.schema_version != EVIDENCE_SCHEMA_VERSION:
            raise SchemaError("unsupported evidence schema")
        if envelope.collector_id != self.collector_id:
            raise SchemaError("evidence collector is not trusted")
        # Re-run all canonical validators before verifying bytes.  A forged
        # dataclass instance must not bypass the issuer's validation path.
        if envelope.source_kind not in SOURCE_KINDS:
            raise SchemaError("unsupported evidence source_kind")
        if _normalize_source(envelope.source, envelope.source_kind) != envelope.source:
            raise SchemaError("evidence source is not canonical")
        for value, name in (
            (envelope.interface, "interface"),
            (envelope.identity, "identity"),
            (envelope.session_id, "session_id"),
            (envelope.window_id, "window_id"),
            (envelope.collector_id, "collector_id"),
            (envelope.backend_id, "backend_id"),
            (envelope.predicted_class, "predicted_class"),
            (envelope.action, "action"),
            (envelope.adapter, "adapter"),
        ):
            _text(value, name)
        _hex(envelope.feature_sha256, 64, "feature_sha256")
        _hex(envelope.model_sha256, 64, "model_sha256")
        _hex(envelope.policy_sha256, 64, "policy_sha256")
        _hex(envelope.nonce, 32, "nonce")
        _hex(envelope.evidence_id, 64, "evidence_id")
        _hex(envelope.signature, 64, "signature")
        _probability(envelope.attribution_confidence, "attribution_confidence")
        _probability(envelope.decision_confidence, "decision_confidence")
        if (
            not isinstance(envelope.source_shared, bool)
            or not isinstance(envelope.anomaly, bool)
            or not isinstance(envelope.executable, bool)
        ):
            raise SchemaError("evidence booleans have invalid types")
        if (
            isinstance(envelope.confirmation_windows, bool)
            or not isinstance(envelope.confirmation_windows, int)
            or envelope.confirmation_windows < 0
        ):
            raise SchemaError("confirmation_windows must be a non-negative integer")
        if (
            isinstance(envelope.observed_at_ns, bool)
            or not isinstance(envelope.observed_at_ns, int)
            or envelope.observed_at_ns < 1
        ):
            raise SchemaError("observed_at_ns must be a positive integer")
        if _normalize_signals(dict(envelope.signals)) != envelope.signals:
            raise SchemaError("evidence signals are not canonical")
        encoded = self._encoded_payload(envelope)
        expected_id = hashlib.sha256(encoded).hexdigest()
        expected_signature = hmac.new(
            self._secret, b"evidence\x00" + encoded, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(envelope.evidence_id, expected_id):
            raise SchemaError("evidence identifier does not match its payload")
        if not hmac.compare_digest(envelope.signature, expected_signature):
            raise SchemaError("evidence signature is invalid")
        return envelope

    def claim(
        self,
        envelope: EvidenceEnvelope,
        *,
        action: str,
        adapter: str,
        ttl_sec: int,
    ) -> str:
        """Bind one evidence ID to one source/action and return an auth ticket.

        Repeating the exact same claim is idempotent.  Reusing the evidence for
        another source, action, or adapter fails closed.
        """

        verified = self.verify(envelope)
        normalized_action = _text(action, "action")
        normalized_adapter = _text(adapter, "adapter")
        if normalized_action != verified.action or normalized_adapter != verified.adapter:
            raise SchemaError("ticket response does not match signed evidence")
        if (
            isinstance(ttl_sec, bool)
            or not isinstance(ttl_sec, int)
            or not 1 <= ttl_sec <= _MAX_RESPONSE_TTL_SEC
        ):
            raise SchemaError("ticket ttl_sec must be an integer in 1..300")
        claim_prefix = (
            verified.source,
            normalized_action,
            normalized_adapter,
            ttl_sec,
        )
        with self._lock:
            previous = self._claims.get(verified.evidence_id)
            if previous is not None and previous[:4] != claim_prefix:
                raise SchemaError("evidence was already claimed for another response")
            if previous is not None:
                return previous[4]
            if self._ticket_issuer is None:
                raise SchemaError(
                    "Ed25519 ticket signing is unavailable; live response is disabled"
                )
            ticket = self._ticket_issuer.issue(
                evidence_id=verified.evidence_id,
                source=verified.source,
                source_kind=verified.source_kind,
                action=normalized_action,
                adapter=normalized_adapter,
                backend_id=verified.backend_id,
                interface=verified.interface,
                identity=verified.identity,
                response_ttl_sec=ttl_sec,
                issued_at_ns=time.time_ns(),
            )
            self._claims[verified.evidence_id] = (*claim_prefix, ticket)
            self._claims.move_to_end(verified.evidence_id)
            while len(self._claims) > self.max_claims:
                self._claims.popitem(last=False)
        return ticket

    def verify_ticket(
        self,
        ticket: str,
        *,
        source: str,
        action: str,
        adapter: str,
        evidence_id: str,
        backend_id: str,
        interface: str,
        identity: str,
        ttl_sec: int,
        consume: bool = False,
    ) -> dict[str, Any]:
        """Verify a short-lived response ticket before a privileged action."""

        if self._ticket_issuer is None:
            raise SchemaError(
                "Ed25519 ticket verification is unavailable; live response is disabled"
            )
        try:
            verified_ticket = self._ticket_issuer.verifier().verify(
                ticket,
                now_ns=time.time_ns(),
            )
        except TicketVerificationError as exc:
            raise SchemaError(str(exc)) from exc
        payload = verified_ticket.to_dict()
        expected = {
            "source": source,
            "action": action,
            "adapter": adapter,
            "evidence_id": evidence_id,
            "backend_id": backend_id,
            "interface": interface,
            "identity": identity,
            "response_ttl_sec": ttl_sec,
        }
        for value, name in (
            (source, "expected source"),
            (action, "expected action"),
            (adapter, "expected adapter"),
            (backend_id, "expected backend_id"),
            (interface, "expected interface"),
            (identity, "expected identity"),
        ):
            _text(value, name)
        _hex(evidence_id, 64, "expected evidence_id")
        if isinstance(ttl_sec, bool) or not isinstance(ttl_sec, int) or not 1 <= ttl_sec <= 300:
            raise SchemaError("expected ttl_sec must be an integer in 1..300")
        if any(payload[name] != value for name, value in expected.items()):
            raise SchemaError("authorization ticket does not match the requested response")
        with self._lock:
            registered = self._claims.get(evidence_id)
            if registered is None or registered[4] != ticket:
                raise SchemaError("authorization ticket is not registered")
            ticket_digest = hashlib.sha256(ticket.encode("ascii")).hexdigest()
            if consume and ticket_digest in self._consumed_tickets:
                raise SchemaError("authorization ticket was already consumed")
            if consume:
                self._consumed_tickets[ticket_digest] = None
                self._consumed_tickets.move_to_end(ticket_digest)
                while len(self._consumed_tickets) > self.max_claims:
                    self._consumed_tickets.popitem(last=False)
        return safe_json_value(payload)

    def ticket_verifier(self) -> Ed25519TicketVerifier:
        """Return a public-key-only verifier for the privileged backend."""

        if self._ticket_issuer is None:
            raise BackendUnavailableError(
                "Ed25519 ticket verification is unavailable; live response is disabled"
            )
        return self._ticket_issuer.verifier()

    def verifier(self) -> "EvidenceVerifier":
        """Return a verify/claim capability that cannot issue new evidence."""

        return EvidenceVerifier(self)


class EvidenceVerifier:
    """Narrow capability exposed to authorizers and privileged backends.

    Production deployment should place the issuer and verifier in separate
    processes.  This object already prevents ordinary response-engine code from
    calling ``issue()`` through the supported API.
    """

    __slots__ = ("collector_id", "_verify", "_claim", "_verify_ticket")

    def __init__(self, authority: EvidenceAuthority):
        if type(authority) is not EvidenceAuthority:
            raise TypeError("EvidenceVerifier requires an EvidenceAuthority")
        self.collector_id = authority.collector_id
        self._verify = authority.verify
        self._claim = authority.claim
        self._verify_ticket = authority.verify_ticket

    def verify(self, envelope: EvidenceEnvelope) -> EvidenceEnvelope:
        return self._verify(envelope)

    def claim(
        self,
        envelope: EvidenceEnvelope,
        *,
        action: str,
        adapter: str,
        ttl_sec: int,
    ) -> str:
        return self._claim(
            envelope,
            action=action,
            adapter=adapter,
            ttl_sec=ttl_sec,
        )

    def verify_ticket(
        self,
        ticket: str,
        *,
        source: str,
        action: str,
        adapter: str,
        evidence_id: str,
        backend_id: str,
        interface: str,
        identity: str,
        ttl_sec: int,
        consume: bool = False,
    ) -> dict[str, Any]:
        return self._verify_ticket(
            ticket,
            source=source,
            action=action,
            adapter=adapter,
            evidence_id=evidence_id,
            backend_id=backend_id,
            interface=interface,
            identity=identity,
            ttl_sec=ttl_sec,
            consume=consume,
        )
