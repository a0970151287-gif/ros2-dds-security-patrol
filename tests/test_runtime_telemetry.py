import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from dds_security_monitor import intelligent_defense_node, monitor_node
from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer
from firewall_lab.live_telemetry_collector import (
    TelemetryCollector,
    ingest_runtime_datagram,
    serve_runtime_socket,
)
from firewall_lab.orchestrator import _telemetry_stream_succeeded
from firewall_lab.schema import SchemaError, new_session_id
from firewall_lab.sros2_deny_adapter import (
    Sros2DenyLogAdapter,
    classify_sros2_deny,
)


class _FakeSocket:
    def __init__(self):
        self.blocking = None
        self.sent = []
        self.closed = False

    def setblocking(self, value):
        self.blocking = value

    def sendto(self, payload, path):
        self.sent.append((payload, path))
        return len(payload)

    def close(self):
        self.closed = True


def _producer_with_fake_socket(source="intelligent_defense_node"):
    fake = _FakeSocket()
    producer = RuntimeTelemetryProducer(
        source=source,
        socket_path="/tmp/runtime-telemetry-test.sock",
        socket_factory=lambda *_args: fake,
    )
    return producer, fake


def test_nonblocking_producer_emits_only_bounded_allowlisted_records(tmp_path):
    producer, fake = _producer_with_fake_socket()
    assert fake.blocking is False
    assert producer.emit_hmac_result(
        accepted=False, reason="invalid_signature", channel="alerts"
    )
    assert producer.emit_detector_state("D4", "incident")
    assert producer.emit_heartbeat_state("gap", 12.5)
    assert producer.emit_graph_state("overflow", 257)
    assert producer.emit_sros2_deny("permission")
    assert producer.sent == 5
    assert producer.dropped == 0

    collector = TelemetryCollector(
        tmp_path / "telemetry_events.jsonl",
        session_id=new_session_id("normal_patrol"),
        source="telemetry_collector",
    )
    for payload, _path in fake.sent:
        ingest_runtime_datagram(payload, collector=collector)
    events = [
        json.loads(line)
        for line in collector.path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["event_type"] for event in events] == [
        "hmac_result",
        "detector_state",
        "authenticated_heartbeat_state",
        "graph_state",
        "sros2_deny",
    ]
    assert all(event["source"] == "intelligent_defense_node" for event in events)
    assert all("payload" not in event["details"] for event in events)


def test_disabled_or_backpressured_producer_drops_without_raising():
    disabled = RuntimeTelemetryProducer(source="monitor_node", socket_path=None)
    assert not disabled.emit_detector_state("d1", "incident")
    assert disabled.dropped == 1

    class FullSocket(_FakeSocket):
        def sendto(self, payload, path):
            raise BlockingIOError()

    full = FullSocket()
    producer = RuntimeTelemetryProducer(
        source="monitor_node",
        socket_path="/tmp/full.sock",
        socket_factory=lambda *_args: full,
    )
    assert not producer.emit_graph_state("fault", -1)
    assert producer.dropped == 1


def test_semantic_probe_and_guard_records_are_typed_and_bounded(tmp_path):
    producer, fake = _producer_with_fake_socket("local_outcome_probe")
    assert producer.emit_topic_probe(
        "cmd_vel",
        message_count=2,
        publisher_count=1,
        authorized_publisher_count=1,
    )
    assert producer.emit_state_digest("runtime_state", "a" * 64)
    assert producer.emit_parameter_digest(
        "dds_security_monitor", "whitelist", "b" * 64
    )
    assert producer.emit_process_health("dds_security_monitor", "healthy")
    assert producer.emit_delivery_probe(
        "unauthorized_participant", observed_count=0
    )

    guard, guard_socket = _producer_with_fake_socket("velocity_guard_node")
    assert guard.emit_guard_state("locked", "monitor_fault")
    assert guard.emit_authenticated_action("guard_clear")
    assert guard.emit_guard_input(accepted_count=1)
    assert guard.emit_guard_output(0.0, 0.0, blocked=True)
    assert guard.emit_parameter_veto(count=1)
    assert guard.emit_message_validation(count=1, oversized_count=1)

    collector = TelemetryCollector(
        tmp_path / "semantic.jsonl",
        session_id=new_session_id("normal_patrol"),
        source="telemetry_collector",
    )
    for payload, _path in fake.sent + guard_socket.sent:
        ingest_runtime_datagram(payload, collector=collector)
    events = [
        json.loads(line)
        for line in collector.path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["event_type"] for event in events] == [
        "topic_probe",
        "state_digest",
        "parameter_digest",
        "process_health",
        "delivery_probe",
        "guard_state",
        "authenticated_action",
        "guard_input",
        "guard_output",
        "parameter_veto",
        "message_validation",
    ]


@pytest.mark.parametrize(
    "operation",
    [
        lambda p: p.emit_hmac_result(
            accepted=True, reason="invalid_signature", channel="alerts"
        ),
        # channel 不在詞彙表 → 必須拒絕，不可放行成未知頻道
        lambda p: p.emit_hmac_result(
            accepted=False, reason="invalid_signature", channel="not_a_channel"
        ),
        lambda p: p.emit_detector_state("d7", "incident"),
        lambda p: p.emit_heartbeat_state("gap", float("nan")),
        lambda p: p.emit_graph_state("fault", 0),
        lambda p: p.emit_sros2_deny("unknown"),
        lambda p: p.emit_guard_state("released", "monitor_fault"),
        lambda p: p.emit_guard_output(float("inf"), 0.0, blocked=True),
        lambda p: p.emit_topic_probe(
            "cmd_vel",
            message_count=0,
            publisher_count=0,
            authorized_publisher_count=1,
        ),
        lambda p: p.emit_state_digest("runtime_state", "not-a-digest"),
    ],
)
def test_producer_rejects_ambiguous_or_unbounded_semantics(operation):
    producer = RuntimeTelemetryProducer(source="monitor_node", socket_path=None)
    with pytest.raises(ValueError):
        operation(producer)


def test_collector_rejects_arbitrary_runtime_details(tmp_path):
    collector = TelemetryCollector(
        tmp_path / "events.jsonl",
        session_id=new_session_id("normal_patrol"),
        source="telemetry_collector",
    )
    record = {
        "schema_version": "sros2-firewall-runtime-telemetry/v1",
        "ts_unix_ns": 1,
        "monotonic_ns": 1,
        "source": "monitor_node",
        "event_type": "hmac_result",
        "details": {
            "outcome": "rejected",
            "reason": "invalid_signature",
            "secret": "must_not_enter_evidence",
        },
    }
    with pytest.raises(SchemaError, match="unexpected detail keys"):
        ingest_runtime_datagram(json.dumps(record).encode(), collector=collector)


def test_runtime_timestamps_are_fresh_and_canonical_order_is_monotonic(tmp_path):
    collector = TelemetryCollector(
        tmp_path / "events.jsonl",
        session_id=new_session_id("normal_patrol"),
        source="telemetry_collector",
    )
    producer, fake = _producer_with_fake_socket()
    assert producer.emit_detector_state("d1", "incident")
    first = json.loads(fake.sent[-1][0])
    second = dict(first)
    second["details"] = {"detector": "d1", "state": "recovery"}
    second["ts_unix_ns"] -= 1
    second["monotonic_ns"] -= 1
    ingest_runtime_datagram(json.dumps(first).encode(), collector=collector)
    ingest_runtime_datagram(json.dumps(second).encode(), collector=collector)
    events = [
        json.loads(line)
        for line in collector.path.read_text(encoding="utf-8").splitlines()
    ]
    assert events[1]["ts_unix_ns"] > events[0]["ts_unix_ns"]
    assert events[1]["monotonic_ns"] > events[0]["monotonic_ns"]

    stale = dict(first)
    stale["ts_unix_ns"] = 1
    with pytest.raises(SchemaError, match="freshness"):
        ingest_runtime_datagram(json.dumps(stale).encode(), collector=collector)


def test_live_training_gate_rejects_tick_only_stream(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    collector = TelemetryCollector(
        session / "telemetry_events.jsonl",
        session_id=new_session_id("normal_patrol"),
        source="telemetry_collector",
    )
    collector.emit("collector_tick", {})
    result = {"return_code": 0}
    assert not _telemetry_stream_succeeded(session, result)
    collector.emit_from(
        "velocity_guard_node",
        "hmac_result",
        {"outcome": "accepted", "reason": "accepted"},
    )
    assert _telemetry_stream_succeeded(session, result)


def test_unix_socket_collector_is_single_writer_and_emits_ticks(tmp_path):
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix sockets are unavailable")
    path = tmp_path / "telemetry.sock"
    collector = TelemetryCollector(
        tmp_path / "events.jsonl",
        session_id=new_session_id("normal_patrol"),
        source="telemetry_collector",
    )
    stop = threading.Event()
    failures = []

    def run_server():
        try:
            serve_runtime_socket(
                collector=collector,
                socket_path=path,
                stop_event=stop,
                tick_sec=0.1,
            )
        except Exception as exc:  # pragma: no cover - surfaced below
            failures.append(exc)

    thread = threading.Thread(target=run_server)
    thread.start()
    deadline = time.monotonic() + 2.0
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert path.exists()
    producer = RuntimeTelemetryProducer(source="monitor_node", socket_path=path)
    assert producer.emit_graph_state("fault", -1)
    raw = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    raw.sendto(b"not-json", str(path))
    raw.close()
    deadline = time.monotonic() + 2.0
    while producer.sent > 0 and not collector.path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.15)
    stop.set()
    thread.join(timeout=3.0)
    producer.close()
    assert not failures
    assert not thread.is_alive()
    assert not path.exists()
    events = [
        json.loads(line)
        for line in collector.path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["sequence"] for event in events] == list(range(len(events)))
    assert any(event["event_type"] == "collector_tick" for event in events)
    assert any(event["event_type"] == "graph_state" for event in events)
    rejects = [event for event in events if event["event_type"] == "log_reject"]
    assert sum(event["details"]["count"] for event in rejects) == 1


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("DDS Security authentication handshake failed", "authentication"),
        ("Access control permission denied for topic rt/cmd_vel", "permission"),
        ("Governance protection kind rejected", "governance"),
        ("participant authenticated successfully", None),
        ("ordinary application warning", None),
        ("x" * 9000, None),
    ],
)
def test_sros2_deny_classifier_is_bounded_and_secret_free(line, expected):
    assert classify_sros2_deny(line) == expected


# Verbatim message strings extracted from the INSTALLED vendor build
# (/opt/ros/jazzy/lib/libfastrtps.so.2.14.5, rmw_fastrtps_cpp).  These are what
# this exact Fast DDS version can actually emit, not hand-written examples.
# This is a parser vocabulary fixture: it proves the classifier recognises the
# phrases this build can emit.  It is NOT evidence that a denial ever occurred.
# Across the 1,100-session campaign the adapter read 249,670 lines and
# classified none of them as a denial, because no Fast DDS security audit sink
# is configured; sros_auth_fail_rate and sros_permission_deny_rate are
# source_unavailable, not measured zeros.  Keep this set green whenever the RMW
# vendor or version changes.
VENDOR_DENY_STRINGS = [
    ("Handshake failed: ", "authentication"),
    ("Handshake message not supported (", "authentication"),
    ("Invalid handshake handle", "authentication"),
    ("Invalid identity handle", "authentication"),
    ("Invalid PKI Identity handle or Invalid Certificate", "authentication"),
    ("IdentityHandle is not of the type PKIIdentityHandle", "authentication"),
    ("Not found dds.sec.auth.builtin.PKI-DH.identity_ca property", "authentication"),
    (
        "Not found dds.sec.auth.builtin.PKI-DH.identity_certificate property",
        "authentication",
    ),
    (
        "Unable to authenticate the message. "
        "EVP_DecryptFinal_ex function returns an error",
        "authentication",
    ),
    ("Authentication plugin not configured. Security will be disabled", "authentication"),
    ("access permission denied", "permission"),
    ("Topic denied by deny rule.", "permission"),
    ("Not found topic access rule for topic ", "permission"),
    ("Error validating remote permissions for ", "permission"),
    ("Not receive remote permissions of participant ", "permission"),
    ("Participant is not allowed with its own permissions file.", "permission"),
    ("Cannot find permissions file in permissions credential token", "permission"),
    ("Cannot read as PKCS7 the permissions file.", "permission"),
    ("Error loading Permissions XML", "permission"),
    ("Invalid permissions handle", "permission"),
    ("Not found root node in Permissions XML.", "permission"),
    (
        "Not found any dds.sec.access.builtin.Access-Permissions property",
        "permission",
    ),
    (
        "Not found the identity subject name in permissions file. Subject name: ",
        "permission",
    ),
    ("Error loading Governance XML", "governance"),
    ("Not found root node in Governance XML.", "governance"),
    (
        "Not found dds.sec.access.builtin.Access-Permissions.governance property",
        "governance",
    ),
    (
        "allow_unauthenticated_participants cannot be enabled if "
        "rtps_protection_kind is not none",
        "governance",
    ),
]


@pytest.mark.parametrize(("line", "expected"), VENDOR_DENY_STRINGS)
def test_installed_vendor_deny_strings_are_classified(line, expected):
    assert classify_sros2_deny(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "[INFO] [rcl]: Found security directory: "
        "/home/jesse/ros2_ws/sros2_keystore/enclaves/patrol_node",
        "[INFO] [security_readiness_probe]: Gazebo readiness passed: "
        "scan, odom, imu, clock and tf are live",
        "get_permissions_credential_token",
        "set_permissions_credential_and_token",
        "identity_certificate",
        "SECURITY_AUTHENTICATION",
        "participant matched with 0 errors reported",
    ],
)
def test_benign_vendor_lines_are_not_classified_as_denials(line):
    assert classify_sros2_deny(line) is None


def test_sros2_adapter_emits_categories_not_raw_log_text():
    producer, fake = _producer_with_fake_socket("sros2_log_adapter")
    adapter = Sros2DenyLogAdapter(producer)
    raw = "Access control permission denied token=do-not-copy topic=rt/cmd_vel"
    assert adapter.ingest_line(raw) == "permission"
    payload = json.loads(fake.sent[0][0])
    assert payload["details"] == {"kind": "permission", "count": 1}
    assert "do-not-copy" not in fake.sent[0][0].decode("utf-8")


def test_hmac_reason_codes_cover_signature_channel_time_and_replay():
    secret = b"runtime_telemetry_test_secret_32_bytes_minimum"
    signed = monitor_node.sign_alert("payload", secret, channel=monitor_node.CH_ALERTS)
    assert monitor_node.verify_alert_detailed(
        signed, secret, expected_channel=monitor_node.CH_ALERTS
    )[1] == "accepted"
    assert monitor_node.verify_alert_detailed(
        signed.replace("payload", "tampered"),
        secret,
        expected_channel=monitor_node.CH_ALERTS,
    )[1] == "invalid_signature"
    assert monitor_node.verify_alert_detailed(
        signed, secret, expected_channel=monitor_node.CH_HEARTBEAT
    )[1] == "channel_mismatch"
    stale = monitor_node.sign_alert(
        "payload", secret, channel=monitor_node.CH_ALERTS, ts=0.0
    )
    assert monitor_node.verify_alert_detailed(
        stale, secret, expected_channel=monitor_node.CH_ALERTS
    )[1] == "timestamp_violation"
    cache = monitor_node.ReplayCache()
    fresh = monitor_node.sign_alert("payload", secret, channel=monitor_node.CH_ALERTS)
    assert monitor_node.verify_alert_detailed(
        fresh, secret, expected_channel=monitor_node.CH_ALERTS, cache=cache
    )[1] == "accepted"
    assert monitor_node.verify_alert_detailed(
        fresh, secret, expected_channel=monitor_node.CH_ALERTS, cache=cache
    )[1] == "nonce_reuse_or_capacity"

    observed = []
    telemetry = SimpleNamespace(
        emit_hmac_result=lambda **item: observed.append(item)
    )
    assert monitor_node.verify_alert(
        signed.replace("payload", "tampered"),
        secret,
        expected_channel=monitor_node.CH_ALERTS,
        telemetry=telemetry,
    ) is None
    assert observed == [{"accepted": False, "reason": "invalid_signature", "channel": "alerts"}]


class _TransitionTelemetry:
    def __init__(self):
        self.detectors = []
        self.heartbeats = []
        self.graph = []

    # The real producer returns whether the datagram went out, and the caller
    # now only records a transition as announced when it did.
    def emit_detector_state(self, detector, state):
        self.detectors.append((detector, state))
        return True

    def emit_heartbeat_state(self, state, gap_sec):
        self.heartbeats.append((state, gap_sec))
        return True

    def emit_graph_state(self, state, node_count):
        self.graph.append((state, node_count))
        return True


class _DroppingTelemetry(_TransitionTelemetry):
    """Reports every detector datagram as undelivered."""

    def emit_detector_state(self, detector, state):
        self.detectors.append((detector, state))
        return False


def test_d1_d6_and_authenticated_heartbeat_emit_only_transitions(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(intelligent_defense_node.time, "monotonic", lambda: now[0])
    telemetry = _TransitionTelemetry()
    fake = SimpleNamespace(
        _telemetry=telemetry,
        _detector_runtime_state={name: False for name in ("D1", "D2", "D3", "D4", "D5", "D6")},
        _startup_wall=90.0,
        _last_heartbeat_wall=0.0,
    )
    for detector in ("D1", "D2", "D3", "D4", "D5", "D6"):
        intelligent_defense_node.IntelligentDefenseNode._record_detector_transition(
            fake, detector, True
        )
        intelligent_defense_node.IntelligentDefenseNode._record_detector_transition(
            fake, detector, True
        )
        intelligent_defense_node.IntelligentDefenseNode._record_detector_transition(
            fake, detector, False
        )
    assert telemetry.detectors == [
        item
        for detector in ("d1", "d2", "d3", "d4", "d5", "d6")
        for item in ((detector, "incident"), (detector, "recovery"))
    ]
    assert [state for state, _gap in telemetry.heartbeats] == ["gap", "recovery"]

    stale = SimpleNamespace(_scan_history=[[]] * 5, _last_scan_wall=0.0)
    assert not intelligent_defense_node.IntelligentDefenseNode._detector_recovery_observable(
        stale, "D3"
    )


def test_graph_fault_overflow_recovery_are_deduplicated():
    telemetry = _TransitionTelemetry()
    fake = SimpleNamespace(_telemetry=telemetry, _graph_runtime_state="healthy")
    monitor_node.DDSSecurityMonitor._record_graph_transition(fake, "fault", -1)
    monitor_node.DDSSecurityMonitor._record_graph_transition(fake, "fault", -1)
    monitor_node.DDSSecurityMonitor._record_graph_transition(fake, "overflow", 300)
    monitor_node.DDSSecurityMonitor._record_graph_transition(fake, "recovery", 20)
    assert telemetry.graph == [
        ("fault", -1),
        ("overflow", 300),
        ("recovery", 20),
    ]


@pytest.mark.parametrize(
    ("method", "kwargs", "event_type", "details"),
    [
        ("emit_participant_change", {"count": 3}, "participant_change", {"count": 3}),
        ("emit_unknown_node", {"count": 2}, "unknown_node", {"count": 2}),
        ("emit_parameter_call", {"count": 5}, "parameter_call", {"count": 5}),
        (
            "emit_alert_observation",
            {"count": 4, "reflection_count": 1},
            "alert_observation",
            {"count": 4, "reflection_count": 1},
        ),
    ],
)
def test_producers_added_for_previously_dead_features(
    method, kwargs, event_type, details
):
    """These four features were structurally zero in live data until 2026-08-06.

    The loopback pilot showed features.py consumed participant_change,
    unknown_node, parameter_call and alert_observation, but no ROS node emitted
    any of them, so the columns existed and could never leave zero.
    """
    producer, fake = _producer_with_fake_socket("monitor_node")
    assert getattr(producer, method)(**kwargs)
    payload = json.loads(fake.sent[0][0])
    assert payload["event_type"] == event_type
    assert payload["details"] == details


def test_alert_observation_rejects_more_reflections_than_observations():
    producer, _ = _producer_with_fake_socket("system_status_node")
    with pytest.raises(ValueError, match="reflection count"):
        producer.emit_alert_observation(count=1, reflection_count=2)


def test_every_feature_consuming_event_type_has_a_producer():
    """features.py must not consume an event type nobody can emit.

    Guards the class of defect the loopback pilot found: a feature column that
    can never leave zero because its source event has no producer.
    """
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    producer_src = (
        root / "src/dds_security_monitor/dds_security_monitor/runtime_telemetry.py"
    ).read_text(encoding="utf-8")
    produced = {
        node.args[0].value
        for node in ast.walk(ast.parse(producer_src))
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", None) == "_emit"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }

    features_src = (root / "firewall_lab/features.py").read_text(encoding="utf-8")
    consumed = set()
    for node in ast.walk(ast.parse(features_src)):
        if isinstance(node, ast.FunctionDef) and node.name == "_accumulate_telemetry":
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Compare)
                    and isinstance(sub.left, ast.Name)
                    and sub.left.id == "event_type"
                ):
                    consumed |= {
                        c.value
                        for c in sub.comparators
                        if isinstance(c, ast.Constant)
                    }

    # collector_tick is synthesised by the collector, not by a ROS node.
    # The *_observation / *_validation / sros_* names below are legacy aliases
    # kept for older evidence; each has a live equivalent that IS produced.
    LEGACY_ALIASES = {
        "hmac_validation",          # live: hmac_result
        "heartbeat_observation",    # live: authenticated_heartbeat_state
        "publisher_observation",    # live: detector_state d4
        "control_observation",      # live: detector_state d1/d2
        "scan_observation",         # live: detector_state d3
        "odom_cmd_observation",     # live: detector_state d6
        "log_reject",               # live: graph_state fault/overflow
        "sros_auth_failure",        # live: sros2_deny kind=authentication
        "sros_permission_denied",   # live: sros2_deny kind=permission
    }
    orphans = consumed - produced - {"collector_tick"} - LEGACY_ALIASES
    assert orphans == set(), (
        "feature-consuming event types without a producer: "
        f"{sorted(orphans)}"
    )


def test_qos_delivery_producer_bounds_delivered_by_expected():
    producer, fake = _producer_with_fake_socket("sensor_hub_node")
    assert producer.emit_qos_delivery(expected_count=12, delivered_count=9)
    payload = json.loads(fake.sent[0][0])
    assert payload["event_type"] == "qos_delivery"
    assert payload["details"] == {"expected_count": 12, "delivered_count": 9}

    with pytest.raises(ValueError, match="delivered count"):
        producer.emit_qos_delivery(expected_count=3, delivered_count=4)


def test_stale_telemetry_socket_is_reclaimed_but_live_one_is_not(tmp_path):
    """Sessions share one socket path; a slow unlink must not fail the next run.

    Two of nine sessions in the 2026-08-06 Permissive sweep died with
    "telemetry socket path already exists" because the previous collector had
    not finished cleaning up.  Reclaiming must stay conservative: only a socket
    with nothing bound to it may be removed.
    """
    import socket as _socket

    from firewall_lab.live_telemetry_collector import _reclaim_stale_socket

    # A leftover socket file with no listener -> reclaimable.
    stale = tmp_path / "stale.sock"
    dead = _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)
    dead.bind(str(stale))
    dead.close()
    assert stale.exists()
    assert _reclaim_stale_socket(stale) is True
    assert not stale.exists()

    # A socket someone is still bound to -> must be left alone.
    live = tmp_path / "live.sock"
    holder = _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)
    holder.bind(str(live))
    try:
        assert _reclaim_stale_socket(live) is False
        assert live.exists()
    finally:
        holder.close()

    # A regular file at the socket path is never removed.
    regular = tmp_path / "not-a-socket"
    regular.write_text("", encoding="utf-8")
    assert _reclaim_stale_socket(regular) is False
    assert regular.exists()


class _FakeService:
    """Stands in for an rclpy Service: a name plus a swappable callback."""

    def __init__(self, srv_name, callback):
        self.srv_name = srv_name
        self.callback = callback


class _FakeTelemetry:
    def __init__(self):
        self.parameter_calls = 0

    def emit_parameter_call(self, *, count=1):
        self.parameter_calls += count
        return True


class _FakeNode:
    def __init__(self, services):
        self._telemetry = _FakeTelemetry()
        self.services = services


def _param_node():
    handled = []

    def handler(request, response):
        handled.append(request)
        return response

    services = [
        _FakeService("/dds_security_monitor/get_parameters", handler),
        _FakeService("/dds_security_monitor/set_parameters", handler),
        _FakeService("/dds_security_monitor/list_parameters", handler),
        _FakeService("/dds_security_monitor/some_other_service", handler),
    ]
    return _FakeNode(services), handled


def test_parameter_calls_are_counted_at_the_service_not_the_set_callback():
    """The read-only rejection happens inside rcl, before any set callback.

    On the 1,100-session campaign the whitelist-hijack attack was refused 18
    times per session with "Trying to set a read-only parameter" and produced
    zero telemetry, because the old hook sat in the on_set_parameters callback
    that rcl never reaches. Counting at the service records the attempt.
    """

    node, handled = _param_node()
    monitor_node.count_parameter_service_calls(node)

    for service in node.services:
        if service.srv_name.endswith("/set_parameters"):
            service.callback(object(), "response")

    assert node._telemetry.parameter_calls == 1
    assert len(handled) == 1


def test_get_parameters_flood_is_counted():
    """The service-flood scenario calls get_parameters ~1,300 times a second.

    It never touches a set callback, so the old hook could not see it at all.
    """

    node, handled = _param_node()
    monitor_node.count_parameter_service_calls(node)

    getter = next(
        s for s in node.services if s.srv_name.endswith("/get_parameters")
    )
    for _ in range(50):
        getter.callback(object(), "response")

    assert node._telemetry.parameter_calls == 50
    assert len(handled) == 50


def test_non_parameter_services_are_left_alone():
    node, _ = _param_node()
    other = next(
        s for s in node.services if s.srv_name.endswith("/some_other_service")
    )
    original = other.callback
    monitor_node.count_parameter_service_calls(node)
    assert other.callback is original

    other.callback(object(), "response")
    assert node._telemetry.parameter_calls == 0


def test_wrapping_parameter_services_twice_does_not_double_count():
    node, _ = _param_node()
    monitor_node.count_parameter_service_calls(node)
    monitor_node.count_parameter_service_calls(node)

    getter = next(
        s for s in node.services if s.srv_name.endswith("/get_parameters")
    )
    getter.callback(object(), "response")
    assert node._telemetry.parameter_calls == 1


def test_telemetry_failure_never_breaks_the_parameter_service():
    """Evidence is best-effort; the node must still answer the request."""

    node, handled = _param_node()

    class _Broken:
        def emit_parameter_call(self, *, count=1):
            raise RuntimeError("socket is gone")

    node._telemetry = _Broken()
    monitor_node.count_parameter_service_calls(node)

    getter = next(
        s for s in node.services if s.srv_name.endswith("/get_parameters")
    )
    assert getter.callback(object(), "response") == "response"
    assert len(handled) == 1


def test_a_dropped_detector_datagram_is_retried_not_lost(monkeypatch):
    """A lost transition must not be recorded as announced.

    telemetry is a Unix datagram socket and drops under load -- the marker
    mechanism was already changed to confirm landing for the same reason. The
    caller used to set the state before emitting and ignore the returned bool,
    so one dropped datagram silently cost the transition forever: the detector
    would never re-announce it, leaving a recovery with no incident. That is
    exactly what d4 did on 2026-08-29, blocking graph_failure_fail_safe's
    trigger while D4 had in fact fired 51 times.
    """
    now = [100.0]
    monkeypatch.setattr(intelligent_defense_node.time, "monotonic", lambda: now[0])
    dropping = _DroppingTelemetry()
    fake = SimpleNamespace(
        _telemetry=dropping,
        _detector_runtime_state={name: False for name in ("D1", "D2", "D3", "D4", "D5", "D6")},
        _startup_wall=90.0,
        _last_heartbeat_wall=0.0,
    )
    record = intelligent_defense_node.IntelligentDefenseNode._record_detector_transition
    record(fake, "D4", True)
    # The attempt happened, but nothing was recorded as announced.
    assert dropping.detectors == [("d4", "incident")]
    assert fake._detector_runtime_state["D4"] is False

    # Next detector cycle: the socket recovers and the incident finally lands.
    working = _TransitionTelemetry()
    fake._telemetry = working
    record(fake, "D4", True)
    assert working.detectors == [("d4", "incident")]
    assert fake._detector_runtime_state["D4"] is True

    # And the matching recovery is still emitted exactly once afterwards.
    record(fake, "D4", False)
    assert working.detectors == [("d4", "incident"), ("d4", "recovery")]


def test_a_recovery_is_never_emitted_without_its_incident(monkeypatch):
    """The invariant the d4 failure violated, stated directly."""
    now = [100.0]
    monkeypatch.setattr(intelligent_defense_node.time, "monotonic", lambda: now[0])
    dropping = _DroppingTelemetry()
    fake = SimpleNamespace(
        _telemetry=dropping,
        _detector_runtime_state={name: False for name in ("D1", "D2", "D3", "D4", "D5", "D6")},
        _startup_wall=90.0,
        _last_heartbeat_wall=0.0,
    )
    record = intelligent_defense_node.IntelligentDefenseNode._record_detector_transition
    record(fake, "D4", True)      # dropped
    working = _TransitionTelemetry()
    fake._telemetry = working
    record(fake, "D4", False)     # detector cleared while never having announced

    # Nothing at all, rather than a recovery with no incident before it.
    assert working.detectors == []
