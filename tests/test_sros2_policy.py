"""Offline consistency checks for the canonical SROS2 least-privilege policy."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "展示指令" / "sros2_policy_least_privilege.xml"


def test_sros2_provisioning_is_private_and_fails_without_canonical_policy():
    script = (ROOT / "展示指令" / "10_SROS2啟用.sh").read_text(
        encoding="utf-8"
    )
    assert "umask 077" in script
    assert "canonical SROS2 policy missing" in script
    assert "沿用預設權限" not in script
PKG = ROOT / "src" / "dds_security_monitor"
TQC = ROOT / "src" / "turtlebot3_dqn" / "turtlebot3_dqn"


def _profiles():
    tree = ET.parse(POLICY)
    result = {}
    for enclave in tree.findall(".//enclave"):
        path = enclave.attrib["path"]
        result[path] = list(enclave.findall("./profiles/profile"))
    return result


def _topics(profile, permission: str) -> set[str]:
    values = set()
    for group in profile.findall(f"./topics[@{permission}='ALLOW']"):
        values.update((topic.text or "").strip() for topic in group.findall("topic"))
    return values


def test_canonical_policy_has_required_enclaves_and_no_wildcards():
    profiles = _profiles()
    required = {
        "/gazebo",
        "/dds_security_monitor",
        "/sensor_hub_node",
        "/patrol_node",
        "/velocity_guard_node",
        "/security_readiness_probe",
        "/local_outcome_probe",
        "/mission_manager",
        "/system_status_node",
        "/intelligent_defense_node",
    }
    assert required <= set(profiles)

    for element in ET.parse(POLICY).iter():
        if element.tag in {"topic", "service", "action"}:
            assert "*" not in (element.text or "")


def test_only_velocity_guard_policy_can_publish_final_cmd_vel():
    publishers = []
    for enclave, profiles in _profiles().items():
        for profile in profiles:
            if "cmd_vel" in _topics(profile, "publish"):
                publishers.append((enclave, profile.attrib["node"]))
    assert publishers == [("/velocity_guard_node", "velocity_guard_node")]


def test_local_outcome_probe_is_read_only_and_narrow():
    probe = _profiles()["/local_outcome_probe"][0]
    assert _topics(probe, "publish") == {"rosout", "parameter_events"}
    assert {"scan", "odom", "imu", "cmd_vel", "chatter"} <= _topics(
        probe, "subscribe"
    )
    requested = {
        (service.text or "").strip()
        for group in probe.findall("./services[@request='ALLOW']")
        for service in group.findall("service")
    }
    assert requested == {"dds_security_monitor/get_parameters"}


def test_controller_policy_topics_are_private():
    profiles = _profiles()
    patrol = profiles["/patrol_node"][0]
    tqc = profiles["/burger_env_top"][0]
    guard = profiles["/velocity_guard_node"][0]

    assert "cmd_vel/patrol" in _topics(patrol, "publish")
    assert "cmd_vel/tqc" in _topics(tqc, "publish")
    assert {
        "cmd_vel/patrol",
        "cmd_vel/nav2",
        "cmd_vel/tqc",
        "security/alerts",
    } <= _topics(guard, "subscribe")


def test_gazebo_enclave_covers_jazzy_spawner_and_sim_clock():
    gazebo_profiles = {
        profile.attrib["node"]: profile
        for profile in _profiles()["/gazebo"]
    }
    assert "ros_gz_sim" in gazebo_profiles
    assert "robot_state_publisher" in gazebo_profiles
    assert "clock" in _topics(
        gazebo_profiles["robot_state_publisher"], "subscribe"
    )
    readiness = _profiles()["/security_readiness_probe"][0]
    assert {"scan", "odom", "imu", "clock", "tf"} <= _topics(
        readiness, "subscribe"
    )


def test_source_publishers_do_not_bypass_velocity_guard():
    controller_sources = [
        PKG / "dds_security_monitor" / "patrol_node.py",
        PKG / "dds_security_monitor" / "monitor_node.py",
        TQC / "burger_env_top.py",
        TQC / "burger_env.py",
        TQC / "environment.py",
    ]
    direct_publisher = re.compile(
        r"create_publisher\s*\(\s*TwistStamped\s*,\s*['\"]/?cmd_vel['\"]"
    )
    for source in controller_sources:
        assert not direct_publisher.search(source.read_text(encoding="utf-8"))

    guard = (
        PKG / "dds_security_monitor" / "velocity_guard_node.py"
    ).read_text(encoding="utf-8")
    assert 'TwistStamped, "/cmd_vel", 10' in guard


def test_launch_and_enforce_supervisor_include_guard():
    launch = (PKG / "launch" / "full_system.launch.py").read_text(
        encoding="utf-8"
    )
    enforce = (ROOT / "展示指令" / "01c_啟動系統_enforce.sh").read_text(
        encoding="utf-8"
    )
    assert "velocity_guard_node" in launch
    assert "SetRemap(src='/cmd_vel', dst='/cmd_vel/nav2')" in launch
    assert "allow_hardware_motion" in launch
    assert "cannot assign a distinct SROS2 enclave" in launch
    assert "01c_啟動系統_enforce.sh" in launch
    assert "start_node /velocity_guard_node velocity_guard_node" in enforce
    assert "security_readiness_probe" in enforce
    assert "Enforce readiness 通過" in enforce
    assert 'wait -n "${PIDS[@]}"' in enforce

    for script_name in (
        "01_啟動系統.sh",
        "01b_啟動系統_跨主機.sh",
    ):
        script = (ROOT / "展示指令" / script_name).read_text(
            encoding="utf-8"
        )
        assert "start_node velocity_guard_node" in script
        assert "start_node intelligent_defense_node" in script
        assert 'wait -n "${PIDS[@]}"' in script

    permissive = (ROOT / "展示指令" / "01_啟動系統.sh").read_text(
        encoding="utf-8"
    )
    assert "security_readiness_probe" in permissive
    assert "Permissive readiness 通過" in permissive

    gazebo = (PKG / "launch" / "gazebo.launch.py").read_text(
        encoding="utf-8"
    )
    assert 'default_value="false"' in gazebo
    assert 'IfCondition(LaunchConfiguration("gui"))' in gazebo


def test_legacy_permission_generator_and_cmd_vel_demo_fail_safe():
    generator = (ROOT / "工具腳本" / "generate_permissions.py").read_text(
        encoding="utf-8"
    )
    cmd_vel_gate = (
        ROOT / "展示指令" / "12_cmd_vel_enforce對照.sh"
    ).read_text(encoding="utf-8")

    assert "return 2" in generator
    assert "subprocess" not in generator
    assert "NODE_PERMISSIONS" not in generator
    assert "ros2 topic pub" not in cmd_vel_gate
    assert "velocity_guard_node" in cmd_vel_gate


def _drift_checker():
    import importlib.util

    path = ROOT / "工具腳本" / "check_keystore_policy_drift.py"
    spec = importlib.util.spec_from_file_location("_drift_checker", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_drift_checker_aggregates_by_enclave_not_node_name():
    """One enclave can host several nodes, and names need not match.

    /gazebo hosts gazebo, ros_gz_bridge, ros_gz_sim and robot_state_publisher;
    /mission_manager hosts a node called mission_manager_node.  Keying on node
    names instead of enclave paths produced four bogus failures.
    """
    grants = _drift_checker().canonical_topic_grants(POLICY)

    assert "gazebo" in grants
    assert "mission_manager" in grants
    assert "mission_manager_node" not in grants
    assert "ros_gz_bridge" not in grants
    assert "robot_state_publisher" not in grants
    assert all(topic.startswith("rt/") for topic in grants["gazebo"])


def test_drift_checker_flags_a_keystore_missing_a_granted_topic(tmp_path):
    """Regression for the 2026-08-03 stale-keystore outage.

    The canonical policy granted velocity_guard_node a security/heartbeat
    subscription, the keystore was never re-signed, and SROS2 Enforce killed the
    node at runtime while the structural audit still reported 47/47.
    """
    checker = _drift_checker()
    grants = checker.canonical_topic_grants(POLICY)
    assert "rt/security/heartbeat" in grants["velocity_guard_node"]

    enclaves = tmp_path / "enclaves"
    for name, topics in grants.items():
        # Reproduce the outage exactly: only velocity_guard_node is stale.
        # security/heartbeat is granted to several enclaves, so dropping it
        # everywhere would not isolate the regression under test.
        if name == "velocity_guard_node":
            topics = topics - {"rt/security/heartbeat"}
        body = "".join(f"<topic>{topic}</topic>" for topic in sorted(topics))
        target = enclaves / name
        target.mkdir(parents=True)
        (target / "permissions.xml").write_text(
            f"<permissions>{body}</permissions>", encoding="utf-8"
        )

    failures, lines = checker.check(tmp_path, POLICY)
    assert failures == 1
    assert any(
        "velocity_guard_node" in line and "rt/security/heartbeat" in line
        for line in lines
    )


def test_drift_checker_passes_when_keystore_matches_policy(tmp_path):
    checker = _drift_checker()
    grants = checker.canonical_topic_grants(POLICY)

    enclaves = tmp_path / "enclaves"
    for name, topics in grants.items():
        body = "".join(f"<topic>{topic}</topic>" for topic in sorted(topics))
        target = enclaves / name
        target.mkdir(parents=True)
        (target / "permissions.xml").write_text(
            f"<permissions>{body}</permissions>", encoding="utf-8"
        )

    failures, lines = checker.check(tmp_path, POLICY)
    assert failures == 0, lines


def test_audit_script_wires_in_the_drift_check():
    audit = (ROOT / "展示指令" / "sros2_稽核.sh").read_text(encoding="utf-8")
    assert "check_keystore_policy_drift.py" in audit
    assert "DRIFT=0" in audit
