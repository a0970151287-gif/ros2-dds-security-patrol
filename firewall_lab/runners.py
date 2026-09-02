"""Fixed attack runner registry for the isolated firewall lab."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .catalog import Scenario

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]


SECRET_ENV_NAMES = frozenset(
    {
        "DDS_ALERT_SECRET",
        "LINE_CHANNEL_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    }
)
SECURITY_ENV_NAMES = frozenset(
    {
        "ROS_SECURITY_KEYSTORE",
        "ROS_SECURITY_ENABLE",
        "ROS_SECURITY_STRATEGY",
        "ROS_SECURITY_ENCLAVE_OVERRIDE",
        "SROS2_FIREWALL_TELEMETRY_SOCKET",
    }
)


def attacker_environment(
    *,
    domain_id: int,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Create an uncredentialed attacker environment for before/after tests."""
    env = dict(os.environ if base is None else base)
    for name in SECRET_ENV_NAMES | SECURITY_ENV_NAMES:
        env.pop(name, None)
    env["ROS_DOMAIN_ID"] = str(domain_id)
    env.setdefault("RMW_IMPLEMENTATION", "rmw_fastrtps_cpp")
    env["PYTHONUNBUFFERED"] = "1"
    return env


# runner → 被竊用的 enclave 名稱。
#
# 內部威脅模型（C2C-019）：攻擊者取得**某個既有節點**的身分憑證，因此只拿到
# 那個節點的權限——這比新增一個權限很寬的紅隊 enclave 更貼近現實，也不會削弱
# 最小權限論述本身。HMAC 共享金鑰不在 keystore 裡，所以 SROS2 放行之後仍會被
# HMAC 或 rcl 擋下，而那正是這個模型要量的分層。
CREDENTIALED_RUNNERS: dict[str, str] = {
    "insider_hmac_forgery": "intelligent_defense_node",
    "insider_parameter_write": "parameter_write_probe",
}


def _runner_env_extras(runner: str, duration_sec: float) -> dict[str, str]:
    """個別 runner 需要、但不能走 argv 的環境變數。

    N30 沒有 argparse——它用 `rclpy.init(args=sys.argv)` 直接吃掉 argv，位置全
    留給 `--ros-args --enclave`，所以 duration 只能走環境變數。這是那支腳本的
    既有介面，不是這裡發明的。
    """
    if runner == "insider_parameter_write":
        return {"N30_DURATION_SEC": f"{duration_sec:.3f}"}
    return {}


def insider_environment(
    *,
    domain_id: int,
    enclave: str,
    keystore: str | Path,
    duration_sec: float,
    runner: str,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """持有合法 SROS2 憑證、但**沒有** HMAC 金鑰的內部攻擊者環境。

    與 `attacker_environment` 的唯一差別是保留 SROS2 憑證。**秘密仍然全部剝掉**
    ——內部威脅模型的定義就是「SROS2 放行、應用層擋下」，把 `DDS_ALERT_SECRET`
    留著會讓攻擊者簽得出有效訊息，量到的就不是分層防禦而是一次成功的入侵。
    """
    keystore_path = Path(keystore).resolve()
    enclave_root = keystore_path / "enclaves"
    enclave_dir = enclave_root / enclave.lstrip("/")
    if not enclave_root.is_dir():
        raise FileNotFoundError(f"keystore has no enclaves directory: {enclave_root}")
    if not enclave_dir.is_dir():
        raise FileNotFoundError(f"stolen enclave is not in the keystore: {enclave_dir}")

    env = dict(os.environ if base is None else base)
    for name in SECRET_ENV_NAMES:
        env.pop(name, None)
    env["ROS_DOMAIN_ID"] = str(domain_id)
    env.setdefault("RMW_IMPLEMENTATION", "rmw_fastrtps_cpp")
    env["PYTHONUNBUFFERED"] = "1"
    env["ROS_SECURITY_KEYSTORE"] = str(keystore_path)
    env["ROS_SECURITY_ENABLE"] = "true"
    env["ROS_SECURITY_STRATEGY"] = "Enforce"
    # enclave 走 argv 的 `--ros-args --enclave`；override 若同時存在會與它相爭。
    env.pop("ROS_SECURITY_ENCLAVE_OVERRIDE", None)
    # 攻擊者不得有寫入遙測的能力，否則它可以自己偽造「防禦有反應」的證據。
    env.pop("SROS2_FIREWALL_TELEMETRY_SOCKET", None)
    env.update(_runner_env_extras(runner, duration_sec))

    # fail-closed：這個環境的定義就是「有憑證、沒有金鑰」。任何一個秘密漏進來，
    # 這一場收到的證據就不再支持分層防禦的宣稱。
    leaked = sorted(name for name in SECRET_ENV_NAMES if name in env)
    if leaked:
        raise RuntimeError(f"insider environment must not carry secrets: {leaked}")
    return env


def session_environment(
    scenario: Scenario,
    *,
    domain_id: int,
    duration_sec: float,
    keystore: str | Path | None = None,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """依 runner 決定這一場的攻擊者是外部者還是持證內鬼。

    預設仍是**沒有憑證**的外部者。只有明確登記在 `CREDENTIALED_RUNNERS` 的
    runner 才拿得到 keystore，而且拿不到 keystore 時直接拒絕執行，不會安靜地
    退回成外部者——那會讓一場內鬼實驗變成第十一場外部者實驗而沒有人發現。
    """
    enclave = CREDENTIALED_RUNNERS.get(scenario.runner)
    if enclave is None:
        return attacker_environment(domain_id=domain_id, base=base)
    if keystore is None:
        raise ValueError(
            f"runner {scenario.runner!r} is a credentialed insider and requires a "
            "keystore; refusing to fall back to an uncredentialed outsider"
        )
    return insider_environment(
        domain_id=domain_id,
        enclave=enclave,
        keystore=keystore,
        duration_sec=duration_sec,
        runner=scenario.runner,
        base=base,
    )


def _script(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"allowlisted attack script missing: {path}")
    return str(path)


def build_attack_argv(
    scenario: Scenario,
    *,
    workspace_root: str | Path,
    duration_sec: float,
    intensity: float,
) -> list[str] | None:
    """Translate one catalog runner key to a fixed argv list."""
    root = Path(workspace_root).resolve()
    duration = max(1.0, min(float(duration_sec), 300.0))
    intensity = max(0.0, min(float(intensity), 1.0))
    python = sys.executable
    poc = "紅隊測試/PoC腳本"

    if scenario.runner == "normal":
        return None
    if scenario.runner == "unauthorized_participant":
        ros2 = shutil.which("ros2")
        if ros2 is None:
            raise FileNotFoundError("ros2 executable is not on PATH")
        return [ros2, "run", "demo_nodes_cpp", "talker"]
    if scenario.runner == "cmd_vel_injection":
        return [
            python,
            _script(root, f"{poc}/N9_cmd_vel_race.py"),
            f"{duration:.3f}",
        ]
    if scenario.runner == "sensor_status_spoof":
        return [
            python,
            _script(root, f"{poc}/N6_sensor_status_spoof.py"),
            f"{duration:.3f}",
        ]
    if scenario.runner == "parameter_tamper":
        # Duration is required, not optional: the orchestrator labels the whole
        # [attack_start, attack_end] phase as this attack class, so a one-shot
        # runner would mark the rest of the phase as attack traffic while the
        # system sat idle.
        return [
            python,
            _script(root, f"{poc}/N14_param_whitelist_hijack.py"),
            f"{duration:.3f}",
        ]
    if scenario.runner == "oversized_scan":
        # Dataset generation must not turn one sample into a host OOM.  Scale
        # only within a bounded 5k..50k points and 1..3 Hz.
        points = int(5_000 + intensity * 45_000)
        rate_hz = 1.0 + intensity * 2.0
        return [
            python,
            _script(root, f"{poc}/N24_oversized_scan.py"),
            str(points),
            f"{rate_hz:.3f}",
            f"{duration:.3f}",
        ]
    if scenario.runner == "parameter_flood":
        workers = int(2 + intensity * 6)
        return [
            python,
            _script(root, f"{poc}/N19_param_service_flood.py"),
            "dds_security_monitor",
            str(workers),
            f"{duration:.3f}",
        ]
    if scenario.runner == "heartbeat_replay":
        return [
            python,
            _script(root, f"{poc}/N1_heartbeat_replay.py"),
            f"{duration:.3f}",
        ]
    # 候選攻擊要在視窗邊界**之前**自己結束。持續時間等於視窗時，
    # orchestrator 會在邊界送 SIGTERM，rclpy 的 signal handler 先 shutdown，
    # 腳本的 finally 再 shutdown 一次就拋 RCLError → 退出碼 1 →
    # `_attack_process_succeeded` 判定攻擊沒有執行，整場作廢。
    # 既有七支 runner 不動：它們在 1,100 場裡是通過的。
    candidate_duration = max(1.0, duration - 5.0)

    # ── 2026-09-01 的候選 ─────────────────────────────────────────────
    # 這八支尚未通過證據排他性 gate，只能經由
    # scenarios_smoke_candidates.json 觸發。argv 介面是從腳本讀出來的：
    #   N5、N2  : [偽裝名稱] [持續秒數]
    #   N20     : [topic] [持續秒數] [reliability]
    #   其餘     : [持續秒數]
    if scenario.runner == "baseline_poisoning":
        return [
            python,
            _script(root, f"{poc}/N5_baseline_poison.py"),
            "smoke_candidate_probe",
            f"{candidate_duration:.3f}",
        ]
    if scenario.runner == "confused_deputy":
        return [
            python,
            _script(root, f"{poc}/N13_health_reflection.py"),
            f"{candidate_duration:.3f}",
        ]
    if scenario.runner == "cross_channel_relay":
        return [
            python,
            _script(root, f"{poc}/N4_channel_confusion.py"),
            f"{candidate_duration:.3f}",
        ]
    if scenario.runner == "health_spoof":
        return [
            python,
            _script(root, f"{poc}/N8_system_health_spoof.py"),
            f"{candidate_duration:.3f}",
        ]
    if scenario.runner == "mission_spoof":
        return [
            python,
            _script(root, f"{poc}/N7_mission_cmd_spoof.py"),
            f"{candidate_duration:.3f}",
        ]
    if scenario.runner == "node_name_evasion":
        return [
            python,
            _script(root, f"{poc}/N2_ros2cli_regex_bypass.py"),
            "smoke_candidate_probe",
            f"{candidate_duration:.3f}",
        ]
    if scenario.runner == "scan_drift":
        return [
            python,
            _script(root, f"{poc}/N24b_varlen_scan_regression.py"),
            f"{candidate_duration:.3f}",
        ]
    if scenario.runner == "verify_flood":
        return [
            python,
            _script(root, f"{poc}/N20_verify_flood.py"),
            "/security/heartbeat",
            f"{candidate_duration:.3f}",
            "be",
        ]
    if scenario.runner == "discovery_recon":
        # 被動偵察：加入 domain 但不建立任何 publisher／subscriber，
        # 只讀 DDS 主動公告出來的拓撲。intensity 只影響輪詢密度，
        # **不影響送出的流量**——這一類的定義就是不送東西。
        interval = 2.0 - intensity * 1.5      # 0.5 .. 2.0 秒
        return [
            python,
            _script(root, f"{poc}/N32_discovery_recon.py"),
            f"{candidate_duration:.3f}",
            "--mode", "silent-participant",
            "--interval", f"{interval:.3f}",
        ]
    if scenario.runner == "alert_replay":
        return [
            python,
            _script(root, f"{poc}/N3_alert_replay_dos.py"),
            f"{duration:.3f}",
        ]
    if scenario.runner == "node_churn":
        # cycle 由 intensity 決定：0.25 秒（最兇）到 2.0 秒。
        cycle = 2.0 - intensity * 1.75
        return [
            python,
            _script(root, f"{poc}/N33_node_churn.py"),
            f"{candidate_duration:.3f}",
            "--cycle-sec", f"{cycle:.3f}",
        ]
    if scenario.runner == "odom_spoof":
        # 必須蓋過真 odometry 的頻率才有效，所以下限已經高於典型的 30Hz。
        return [
            python,
            _script(root, f"{poc}/N34_odom_spoof.py"),
            f"{candidate_duration:.3f}",
            "--rate-hz", f"{40.0 + intensity * 40.0:.1f}",
        ]
    if scenario.runner == "spdp_flood":
        return [
            python,
            _script(root, f"{poc}/N35_spdp_flood.py"),
            f"{candidate_duration:.3f}",
            "--participants", str(int(round(10 + intensity * 50))),
        ]
    if scenario.runner == "insider_hmac_forgery":
        # 內鬼：持 /intelligent_defense_node 的合法憑證，但沒有 HMAC 金鑰。
        # SROS2 放行、訊息真的抵達節點，被 HMAC 檢查擋下（C2C-019 的 11/0）。
        # N29 用 `remove_ros_args` 剝掉 --ros-args，所以兩者可以並存。
        return [
            python,
            _script(root, f"{poc}/N29_insider_credentialed.py"),
            "--mode", "hmac_forgery",
            "--duration-sec", f"{candidate_duration:.3f}",
            "--count", str(int(round(6 + intensity * 18))),
            "--ros-args", "--enclave",
            "/" + CREDENTIALED_RUNNERS["insider_hmac_forgery"],
        ]
    if scenario.runner == "insider_parameter_write":
        # 內鬼：/parameter_write_probe 只被授權一條 set_parameters（連
        # get_parameters 都沒有）。請求合法抵達，由 rcl 的 read_only 描述子拒絕
        # （C2C-044 的 7 次嘗試、7 次被拒）。intensity 不影響——這一類的定義是
        # 「合法呼叫者踢到 read-only」，次數多寡不改變語意。
        return [
            python,
            _script(root, f"{poc}/N30_authorized_parameter_write.py"),
            "--ros-args", "--enclave",
            "/" + CREDENTIALED_RUNNERS["insider_parameter_write"],
        ]
    raise ValueError(f"runner has no fixed argv implementation: {scenario.runner}")
