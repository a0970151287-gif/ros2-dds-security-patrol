"""內鬼 runner 的安全不變量。

`attacker_environment` 從專案開始就刻意剝掉所有 SROS2 憑證——campaign runner
沒有能力給攻擊者憑證，那是設計上的保證，不是巧合。2026-09-01 為了量身份通道
對**持證內鬼**的沉默程度，必須讓兩個 runner 拿到 keystore。

這個檔案鎖住那個豁免的邊界：

1. **預設仍然是外部者。** 只有明確登記的 runner 拿得到憑證。
2. **內鬼有憑證但沒有秘密。** 內部威脅模型的定義就是「SROS2 放行、應用層擋下」
   （C2C-019）。`DDS_ALERT_SECRET` 漏進去，攻擊者就簽得出有效訊息，量到的
   不再是分層防禦而是一次成功的入侵。
3. **拿不到 keystore 就拒絕執行**，不會安靜退回成外部者——那會讓一場內鬼實驗
   變成第十一場外部者實驗而沒有人發現。
"""

from __future__ import annotations

import pytest

from firewall_lab.catalog import load_catalog
from firewall_lab.runners import (
    CREDENTIALED_RUNNERS,
    SECRET_ENV_NAMES,
    attacker_environment,
    build_attack_argv,
    session_environment,
)
from firewall_lab.schema import SchemaError  # noqa: F401  (import health)


WORKSPACE = __import__("pathlib").Path(__file__).resolve().parents[1]
KEYSTORE = WORKSPACE / "sros2_keystore"

# 憑證是真的機密，不是所有開發機都有。沒有 keystore 時跳過需要它的測試，
# 但**不跳過**「外部者拿不到憑證」那幾項——那是最重要的一項，且不需要 keystore。
_HAS_KEYSTORE = (KEYSTORE / "enclaves").is_dir()
needs_keystore = pytest.mark.skipif(
    not _HAS_KEYSTORE, reason="這台機器沒有正式 keystore"
)


def _base_env() -> dict[str, str]:
    """一個「什麼都有」的父環境，用來確認該剝的真的被剝掉。"""
    return {
        "PATH": "/usr/bin",
        "DDS_ALERT_SECRET": "super-secret-hmac-key",
        "ANTHROPIC_API_KEY": "sk-should-never-reach-an-attacker",
        "ROS_SECURITY_KEYSTORE": "/somewhere/else",
        "ROS_SECURITY_ENABLE": "true",
        "ROS_SECURITY_STRATEGY": "Enforce",
        "ROS_SECURITY_ENCLAVE_OVERRIDE": "/talker",
        "SROS2_FIREWALL_TELEMETRY_SOCKET": "/run/telemetry.sock",
    }


# ---------------------------------------------------------------- 預設是外部者


@pytest.mark.parametrize(
    "scenario_id",
    [
        "normal_patrol",
        "unauthorized_participant",
        "cmd_vel_injection",
        "oversized_scan",
        "discovery_recon",
    ],
)
def test_non_insider_scenarios_never_receive_credentials(scenario_id):
    """出貨 catalog 的其餘場次一律拿不到憑證，即使 keystore 就在手邊。"""
    scenario = load_catalog()[scenario_id]
    env = session_environment(
        scenario,
        domain_id=30,
        duration_sec=20.0,
        keystore=str(KEYSTORE),
        base=_base_env(),
    )
    assert "ROS_SECURITY_KEYSTORE" not in env
    assert "ROS_SECURITY_ENABLE" not in env
    assert "ROS_SECURITY_STRATEGY" not in env
    assert "ROS_SECURITY_ENCLAVE_OVERRIDE" not in env
    assert "SROS2_FIREWALL_TELEMETRY_SOCKET" not in env
    for name in SECRET_ENV_NAMES:
        assert name not in env
    # 與原本那條路徑逐項相同——加入內鬼不得改變外部者的環境。
    assert env == attacker_environment(domain_id=30, base=_base_env())


def test_every_shipped_scenario_is_outsider_except_the_two_insiders():
    """避免哪天有人把某個 runner 悄悄加進憑證清單而沒有人注意到。"""
    catalog = load_catalog()
    credentialed = {
        sid for sid, sc in catalog.items() if sc.runner in CREDENTIALED_RUNNERS
    }
    assert credentialed == {"insider_hmac_forgery", "insider_parameter_write"}


# ---------------------------------------------------------------- 內鬼的邊界


@needs_keystore
@pytest.mark.parametrize(
    "scenario_id", ["insider_hmac_forgery", "insider_parameter_write"]
)
def test_insider_gets_credentials_but_never_secrets(scenario_id):
    scenario = load_catalog()[scenario_id]
    env = session_environment(
        scenario,
        domain_id=30,
        duration_sec=20.0,
        keystore=str(KEYSTORE),
        base=_base_env(),
    )
    # 有憑證：SROS2 會放行它。
    assert env["ROS_SECURITY_KEYSTORE"] == str(KEYSTORE.resolve())
    assert env["ROS_SECURITY_ENABLE"] == "true"
    assert env["ROS_SECURITY_STRATEGY"] == "Enforce"
    # 沒有金鑰：這是整個內部威脅模型的定義。
    for name in SECRET_ENV_NAMES:
        assert name not in env, f"內鬼環境不得帶著 {name}"
    # enclave 走 argv，override 會與它相爭。
    assert "ROS_SECURITY_ENCLAVE_OVERRIDE" not in env
    # 攻擊者不得能寫遙測，否則它可以自己偽造「防禦有反應」的證據。
    assert "SROS2_FIREWALL_TELEMETRY_SOCKET" not in env


@needs_keystore
def test_insider_without_keystore_refuses_instead_of_silently_downgrading():
    """安靜退回成外部者，會讓一場內鬼實驗變成外部者實驗而沒有人發現。"""
    scenario = load_catalog()["insider_hmac_forgery"]
    with pytest.raises(ValueError, match="requires a keystore"):
        session_environment(
            scenario, domain_id=30, duration_sec=20.0, keystore=None
        )


def test_insider_with_missing_enclave_refuses(tmp_path):
    """竊用的 enclave 不在 keystore 裡就沒有這個威脅模型，必須直接失敗。"""
    scenario = load_catalog()["insider_hmac_forgery"]
    (tmp_path / "enclaves").mkdir()
    with pytest.raises(FileNotFoundError, match="stolen enclave"):
        session_environment(
            scenario,
            domain_id=30,
            duration_sec=20.0,
            keystore=str(tmp_path),
            base=_base_env(),
        )


def test_keystore_without_enclaves_directory_refuses(tmp_path):
    scenario = load_catalog()["insider_hmac_forgery"]
    with pytest.raises(FileNotFoundError, match="no enclaves directory"):
        session_environment(
            scenario,
            domain_id=30,
            duration_sec=20.0,
            keystore=str(tmp_path),
            base=_base_env(),
        )


# ---------------------------------------------------------------- argv 與介面


@needs_keystore
def test_parameter_write_duration_travels_by_environment():
    """N30 沒有 argparse——`rclpy.init(args=sys.argv)` 吃掉 argv，位置全留給
    `--ros-args --enclave`，所以 duration 只能走環境變數。"""
    scenario = load_catalog()["insider_parameter_write"]
    env = session_environment(
        scenario,
        domain_id=30,
        duration_sec=17.5,
        keystore=str(KEYSTORE),
        base=_base_env(),
    )
    assert float(env["N30_DURATION_SEC"]) == pytest.approx(17.5)

    argv = build_attack_argv(
        scenario, workspace_root=WORKSPACE, duration_sec=17.5, intensity=0.5
    )
    assert argv is not None
    # duration 不得同時出現在 argv，否則會被 rclpy 當成 ROS 參數。
    assert "17.5" not in " ".join(argv)


@needs_keystore
def test_hmac_forgery_duration_travels_by_argv_not_environment():
    """N29 反過來——它用 `remove_ros_args`，所以 argv 與 --ros-args 可以並存。"""
    scenario = load_catalog()["insider_hmac_forgery"]
    env = session_environment(
        scenario,
        domain_id=30,
        duration_sec=17.5,
        keystore=str(KEYSTORE),
        base=_base_env(),
    )
    assert "N30_DURATION_SEC" not in env

    argv = build_attack_argv(
        scenario, workspace_root=WORKSPACE, duration_sec=20.0, intensity=0.5
    )
    assert argv is not None
    assert "--duration-sec" in argv
    assert "--mode" in argv and "hmac_forgery" in argv


@pytest.mark.parametrize(
    "scenario_id, enclave",
    [
        ("insider_hmac_forgery", "/intelligent_defense_node"),
        ("insider_parameter_write", "/parameter_write_probe"),
    ],
)
def test_insider_argv_carries_the_stolen_enclave(scenario_id, enclave):
    scenario = load_catalog()[scenario_id]
    argv = build_attack_argv(
        scenario, workspace_root=WORKSPACE, duration_sec=20.0, intensity=0.5
    )
    assert argv is not None
    assert argv[-3:] == ["--ros-args", "--enclave", enclave]
    assert "shell" not in " ".join(argv).lower()


def test_insider_scenarios_declare_classes_the_policy_already_knows():
    """這兩類是 policy 裡 23 條規則中從未有 runner 產生過的其中兩條。"""
    import json

    policy = json.loads(
        (WORKSPACE / "firewall_lab" / "action_policy.json").read_text(
            encoding="utf-8"
        )
    )
    catalog = load_catalog()
    assert catalog["insider_hmac_forgery"].attack_class == "hmac_forgery"
    assert catalog["insider_parameter_write"].attack_class == "confused_deputy"
    for name in ("hmac_forgery", "confused_deputy"):
        assert name in policy["rules"]

def test_orchestrator_does_not_take_the_keystore_from_the_environment(monkeypatch):
    """內鬼竊的是**防守方**的憑證，不是 campaign 執行者 shell 裡那個。

    2026-09-02：orchestrator 原本讀 `ROS_SECURITY_KEYSTORE`，而執行環境裡那個
    指向 `/home/jesse/ros2_security_keystore`（沒有那些 enclave），整批 680 場
    在第 8 場中止。防守方用哪一個由啟動腳本決定，是工作區的 `sros2_keystore`。
    """
    import inspect

    from firewall_lab import orchestrator

    source = inspect.getsource(orchestrator.run_session)
    call = source[source.index("session_environment("):]
    call = call[: call.index(")")]
    # ⚠️ 不可以只找 "environ"——`session_environment` 這個名字本身就含它。
    # 第一版就是這樣誤判成失敗的。要找的是 `os.environ` 這個取值動作。
    assert "os.environ" not in call and "getenv" not in call, (
        "run_session 不可從環境變數取 keystore：那是執行者的值，不是防守方的"
    )
    assert "sros2_keystore" in call
