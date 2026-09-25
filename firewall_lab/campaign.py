#!/usr/bin/env python3
"""Plan and resume balanced, live SROS2 firewall data campaigns.

The plan contains declarative scenario identifiers only.  Execution delegates
to the orchestrator's allowlisted runner registry, never to commands stored in
the plan file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import shutil
from pathlib import Path
from typing import Any

from .catalog import load_catalog
from .runners import runner_requires_enforce
from .orchestrator import (
    DEFAULT_OUTPUT,
    _prepare_output_root,
    _resolve_domain,
    run_session,
)
from .schema import (
    SchemaError,
    atomic_write_json,
    require_identifier,
    sha256_file,
    utc_now,
)


CAMPAIGN_SCHEMA_VERSION = "sros2-firewall-campaign/v1"
# "ineligible": the session ran to completion but did not qualify for training.
# Terminal within a run and within `repair` -- see repair_campaign_plan's
# --reset-ineligible for why requeueing is a deliberate act rather than an
# automatic one.
ENTRY_STATUSES = frozenset(
    {"pending", "running", "complete", "failed", "ineligible"}
)
DEFAULT_PLAN = Path(__file__).resolve().parent / "campaign_1100.json"
DEFAULT_LIVE_OUTPUT = DEFAULT_OUTPUT.with_name("dataset_live")
DEFAULT_MINIMUM_FREE_GIB = 8.0
MAXIMUM_FREE_RESERVE_GIB = 1024.0
MAX_CAMPAIGN_SESSIONS = 10_000
# Completed evidence must remain independently verifiable after a catalog
# policy migration. Archived catalogs bind only the fields stored in a plan
# and can never be used to execute pending work.
ARCHIVED_COMPLETED_CATALOGS = {
    # 2026-09-20 把 verify_flood 升級到出貨之前的十九情境 catalog。
    # verify_flood 連續兩輪通過證據排他性 gate（9–12 個專屬訊號，
    # 其中 5–6 個是機制綁定的:heartbeat 通道被 HMAC 拒絕），
    # 而且與另外兩個候選都分得開。2026-09-02/09-15/09-19 三輪之所以
    # 判「攻擊沒有執行」,是 N20 有一個 SyntaxError。
    #
    # 表的來源:升級腳本在改檔**之前**直接對磁碟取 sha256,並由同一份
    # 內容產生下表,所以鍵與值必然一致。
    "f466946b99e07baac3c7d3fc92c3ff0e7c4461ca5fcf51b4f133b7115cf4ef36": {
        "normal_patrol": ("normal", "allow"),
        "unauthorized_participant": ("identity_abuse", "deny_participant"),
        "cmd_vel_injection": ("command_injection", "lock_velocity"),
        "sensor_status_spoof": ("sensor_spoof", "drop_message"),
        "parameter_tamper": ("parameter_tamper", "deny_participant"),
        "oversized_scan": ("message_dos", "drop_message"),
        "parameter_flood": ("service_dos", "temporary_block"),
        "heartbeat_replay": ("replay", "drop_message"),
        "alert_replay": ("replay_dos", "drop_message"),
        "discovery_recon": ("discovery_recon", "alert"),
        "insider_hmac_forgery": ("hmac_forgery", "drop_message"),
        "insider_parameter_write": ("confused_deputy", "alert"),
        "cross_channel_relay": ("cross_channel_relay", "drop_message"),
        "scan_drift": ("scan_drift", "lock_velocity"),
        "health_spoof": ("health_spoof", "drop_message"),
        "mission_spoof": ("mission_spoof", "drop_message"),
        "node_churn": ("node_churn", "temporary_block"),
        "odom_spoof": ("odom_spoof", "lock_velocity"),
        "spdp_flood": ("spdp_flood", "temporary_block"),
    },
    # 2026-09-15 把 spdp_flood 與 odom_spoof 升級到出貨之前的十七情境
    # catalog。640 場 refresh campaign 釘著這個雜湊。
    #
    # 表的來源：升級腳本在改檔**之前**直接對磁碟上的 scenarios.json 取
    # sha256，並由同一份內容產生下表，所以鍵與值必然一致。
    "701ba0ae9767d7f0bf0ad3c7004649f0ef1318ec80e937b299e9e57c6be7e818": {
        "normal_patrol": ("normal", "allow"),
        "unauthorized_participant": ("identity_abuse", "deny_participant"),
        "cmd_vel_injection": ("command_injection", "lock_velocity"),
        "sensor_status_spoof": ("sensor_spoof", "drop_message"),
        "parameter_tamper": ("parameter_tamper", "deny_participant"),
        "oversized_scan": ("message_dos", "drop_message"),
        "parameter_flood": ("service_dos", "temporary_block"),
        "heartbeat_replay": ("replay", "drop_message"),
        "alert_replay": ("replay_dos", "drop_message"),
        "discovery_recon": ("discovery_recon", "alert"),
        "insider_hmac_forgery": ("hmac_forgery", "drop_message"),
        "insider_parameter_write": ("confused_deputy", "alert"),
        "cross_channel_relay": ("cross_channel_relay", "drop_message"),
        "scan_drift": ("scan_drift", "lock_velocity"),
        "health_spoof": ("health_spoof", "drop_message"),
        "mission_spoof": ("mission_spoof", "drop_message"),
        "node_churn": ("node_churn", "temporary_block"),
    },
    # 2026-09-02 把 node_churn 升級到出貨之前的十六情境 catalog。
    # 這個版本沒有 campaign 釘著它；登記是因為封存表要涵蓋每個曾出貨的版本。
    "f2596e622a4e2661a2d9a3a98ea7eb39299c8a8906c800e222e48b8accf655b0": {
        "normal_patrol": ("normal", "allow"),
        "unauthorized_participant": ("identity_abuse", "deny_participant"),
        "cmd_vel_injection": ("command_injection", "lock_velocity"),
        "sensor_status_spoof": ("sensor_spoof", "drop_message"),
        "parameter_tamper": ("parameter_tamper", "deny_participant"),
        "oversized_scan": ("message_dos", "drop_message"),
        "parameter_flood": ("service_dos", "temporary_block"),
        "heartbeat_replay": ("replay", "drop_message"),
        "alert_replay": ("replay_dos", "drop_message"),
        "discovery_recon": ("discovery_recon", "alert"),
        "insider_hmac_forgery": ("hmac_forgery", "drop_message"),
        "insider_parameter_write": ("confused_deputy", "alert"),
        "cross_channel_relay": ("cross_channel_relay", "drop_message"),
        "scan_drift": ("scan_drift", "lock_velocity"),
        "health_spoof": ("health_spoof", "drop_message"),
        "mission_spoof": ("mission_spoof", "drop_message"),
    },
    # 2026-09-02 把 health_spoof 與 mission_spoof 升級到出貨之前的十四情境
    # catalog。這個版本只存在數小時，期間沒有 campaign 釘著它；登記是因為
    # 封存表的用途是「任何曾經出貨過的版本都要可驗證」，不是只登記有資料的。
    "ea22bd154fa60f6c6503580403f0fc4bef69264f37845380a50822a22813562a": {
        "normal_patrol": ("normal", "allow"),
        "unauthorized_participant": ("identity_abuse", "deny_participant"),
        "cmd_vel_injection": ("command_injection", "lock_velocity"),
        "sensor_status_spoof": ("sensor_spoof", "drop_message"),
        "parameter_tamper": ("parameter_tamper", "deny_participant"),
        "oversized_scan": ("message_dos", "drop_message"),
        "parameter_flood": ("service_dos", "temporary_block"),
        "heartbeat_replay": ("replay", "drop_message"),
        "alert_replay": ("replay_dos", "drop_message"),
        "discovery_recon": ("discovery_recon", "alert"),
        "insider_hmac_forgery": ("hmac_forgery", "drop_message"),
        "insider_parameter_write": ("confused_deputy", "alert"),
        "cross_channel_relay": ("cross_channel_relay", "drop_message"),
        "scan_drift": ("scan_drift", "lock_velocity"),
    },
    # 2026-09-01 把 cross_channel_relay 與 scan_drift 從候選升級到出貨之前的
    # 十二情境 catalog。80 場內鬼對照 campaign 釘著這個雜湊。
    #
    # 表的來源：從 git 取升級前的 scenarios.json，確認其 sha256 逐字元等於下面
    # 這個鍵；另從那份 campaign 的 entries 反推一次，4 個 scenario 相符。
    "d488380d14939a013cc29493b802f5ede50f23478536371b344643a8c9c71fdd": {
        "normal_patrol": ("normal", "allow"),
        "unauthorized_participant": ("identity_abuse", "deny_participant"),
        "cmd_vel_injection": ("command_injection", "lock_velocity"),
        "sensor_status_spoof": ("sensor_spoof", "drop_message"),
        "parameter_tamper": ("parameter_tamper", "deny_participant"),
        "oversized_scan": ("message_dos", "drop_message"),
        "parameter_flood": ("service_dos", "temporary_block"),
        "heartbeat_replay": ("replay", "drop_message"),
        "alert_replay": ("replay_dos", "drop_message"),
        "discovery_recon": ("discovery_recon", "alert"),
        "insider_hmac_forgery": ("hmac_forgery", "drop_message"),
        "insider_parameter_write": ("confused_deputy", "alert"),
    },
    # 2026-09-01 加入兩個內鬼 scenario 之前的十情境 catalog。
    # 身份通道試跑 A（50 場）與 B″（200 場）都釘著這個雜湊。
    #
    # 表的來源：從 git 取改動前的 scenarios.json，確認其 sha256 逐字元等於
    # 下面這個鍵，再用它的內容產生；另從那兩份 campaign 的 entries 反推
    # 一次，10 個 scenario 全部相符。
    "2561e18f01a01851f2917a8c3495c7b7192750fce500cadf7c074b94f7bbabba": {
        "normal_patrol": ("normal", "allow"),
        "unauthorized_participant": ("identity_abuse", "deny_participant"),
        "cmd_vel_injection": ("command_injection", "lock_velocity"),
        "sensor_status_spoof": ("sensor_spoof", "drop_message"),
        "parameter_tamper": ("parameter_tamper", "deny_participant"),
        "oversized_scan": ("message_dos", "drop_message"),
        "parameter_flood": ("service_dos", "temporary_block"),
        "heartbeat_replay": ("replay", "drop_message"),
        "alert_replay": ("replay_dos", "drop_message"),
        "discovery_recon": ("discovery_recon", "alert"),
    },
    "e1d376e2633e000183e0f1e644d9f9969c2f8dc5d91a0535c5cd6a98da6dfe9b": {
        "normal_patrol": ("normal", "allow"),
        "unauthorized_participant": ("identity_abuse", "deny_participant"),
        "cmd_vel_injection": ("command_injection", "lock_velocity"),
        "sensor_status_spoof": ("sensor_spoof", "drop_message"),
        "parameter_tamper": ("parameter_tamper", "deny_participant"),
        "oversized_scan": ("message_dos", "drop_message"),
        "parameter_flood": ("service_dos", "rate_limit"),
        "heartbeat_replay": ("replay", "drop_message"),
        "alert_replay": ("replay_dos", "drop_message"),
    },
    # 2026-08 的九情境 catalog。campaign_1100.json（1,100 場）與
    # campaign_rerun_300.json（300 場受控重跑）都釘著這個雜湊。
    #
    # 2026-09-01 新增 discovery_recon 之後 catalog 的雜湊改變，這兩份完成的
    # campaign 會變成「不符合現行也不符合任何封存的 catalog」——整個資料集的
    # 來源憑證失效。登記於此讓它們保持可驗證。
    #
    # 表的來源：從 git 取出改動前的 scenarios.json，確認其 sha256 逐字元等於
    # 下面這個鍵，再用它的內容產生；另從 1,100 場的 entries 反推一次，相符。
    "c9caf5800ab6ccfd0e51799e63cb08b857d24c500d4a7ad81cf93345f8af0067": {
        "normal_patrol": ("normal", "allow"),
        "unauthorized_participant": ("identity_abuse", "deny_participant"),
        "cmd_vel_injection": ("command_injection", "lock_velocity"),
        "sensor_status_spoof": ("sensor_spoof", "drop_message"),
        "parameter_tamper": ("parameter_tamper", "deny_participant"),
        "oversized_scan": ("message_dos", "drop_message"),
        "parameter_flood": ("service_dos", "temporary_block"),
        "heartbeat_replay": ("replay", "drop_message"),
        "alert_replay": ("replay_dos", "drop_message"),
    },
}
PLAN_KEYS = frozenset(
    {
        "schema_version",
        "campaign_id",
        "created_utc",
        "experiment_mode",
        "catalog_sha256",
        "seed",
        "requested_counts",
        "entries",
    }
)
ENTRY_KEYS = frozenset(
    {
        "entry_id",
        "scenario_id",
        "attack_class",
        "security_mode",
        "domain_id",
        "seed",
        "expected_action",
        "status",
        "session_id",
        "error",
    }
)


def _require_int(
    value: Any,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise SchemaError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _validate_minimum_free_gib(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) <= MAXIMUM_FREE_RESERVE_GIB
    ):
        raise ValueError(
            "minimum_free_gib must be finite and in "
            f"0..{MAXIMUM_FREE_RESERVE_GIB}"
        )
    return float(value)


def _ensure_minimum_free_space(
    output: Path,
    minimum_free_gib: float,
) -> int:
    """Fail before a session starts if its evidence volume is unsafe."""
    reserve_gib = _validate_minimum_free_gib(minimum_free_gib)
    required_bytes = math.ceil(reserve_gib * 1024**3)
    free_bytes = int(shutil.disk_usage(output).free)
    if free_bytes < required_bytes:
        raise RuntimeError(
            "campaign stopped before starting the next session: "
            f"free_bytes={free_bytes} required_bytes={required_bytes}"
        )
    return free_bytes


def _security_modes(count: int) -> list[str]:
    """Split each scenario across prevention-on and prevention-off sessions."""
    permissive = count // 2
    enforce = count - permissive
    return ["permissive"] * permissive + ["enforce"] * enforce


def _unique_seeds(rng: random.Random, count: int) -> list[int]:
    seeds: set[int] = set()
    while len(seeds) < count:
        seeds.add(rng.randrange(1, 2_147_483_647))
    return sorted(seeds)


def create_campaign_plan(
    *,
    normal_sessions: int = 300,
    attack_sessions_per_scenario: int = 100,
    seed: int = 20260727,
) -> dict[str, Any]:
    """Create the default 300-normal + 8x100-attack live campaign."""
    _require_int(
        normal_sessions,
        "normal_sessions",
        minimum=2,
        maximum=MAX_CAMPAIGN_SESSIONS,
    )
    _require_int(
        attack_sessions_per_scenario,
        "attack_sessions_per_scenario",
        minimum=2,
        maximum=MAX_CAMPAIGN_SESSIONS,
    )
    _require_int(seed, "seed", minimum=0, maximum=2_147_483_647)

    catalog = load_catalog()
    normal_ids = [
        scenario_id
        for scenario_id, scenario in catalog.items()
        if scenario.attack_class == "normal"
    ]
    attack_ids = [
        scenario_id
        for scenario_id, scenario in catalog.items()
        if scenario.attack_class != "normal"
    ]
    if len(normal_ids) != 1 or not attack_ids:
        raise SchemaError(
            "campaign requires exactly one normal scenario and attacks"
        )

    counts = {
        normal_ids[0]: normal_sessions,
        **{
            scenario_id: attack_sessions_per_scenario
            for scenario_id in sorted(attack_ids)
        },
    }
    total = sum(counts.values())
    if total > MAX_CAMPAIGN_SESSIONS:
        raise SchemaError(
            f"campaign total exceeds {MAX_CAMPAIGN_SESSIONS} sessions"
        )

    rng = random.Random(seed)
    entry_seeds = iter(_unique_seeds(rng, total))
    candidates: list[dict[str, Any]] = []
    requested_counts: dict[str, dict[str, int]] = {}
    for scenario_id in sorted(counts):
        scenario = catalog[scenario_id]
        if runner_requires_enforce(scenario.runner):
            # 持證內鬼在 Permissive 下沒有意義：SROS2 對誰都放行，竊得的憑證
            # 不帶來任何額外能力，而 `session_environment` 會 fail-closed 拒絕。
            #
            # 2026-09-20 實跑抓到：計畫產生器沒有問過 `runner_requires_enforce`，
            # 於是把內鬼場次也分給 Permissive。那些 entry 每次被排到就讓**整批**
            # 以 ValueError 中止——不是跳過一場，是整批死掉，連帶浪費一次
            # stack 啟動。實測 12 小時內 permissive 只跑到 43 場而 enforce 有
            # 147 場，就是這樣來的。
            modes = ["enforce"] * counts[scenario_id]
        else:
            modes = _security_modes(counts[scenario_id])
        requested_counts[scenario_id] = {
            "total": len(modes),
            "permissive": modes.count("permissive"),
            "enforce": modes.count("enforce"),
        }
        for security_mode in modes:
            candidates.append(
                {
                    "scenario_id": scenario_id,
                    "attack_class": scenario.attack_class,
                    "security_mode": security_mode,
                    # Both sides of the before/after comparison deliberately
                    # use domain 30.  Different domain-derived RTPS ports would
                    # leak the security-mode label into network features.
                    "domain_id": _resolve_domain(security_mode, None),
                    "seed": next(entry_seeds),
                    "expected_action": scenario.expected_action,
                    "status": "pending",
                    "session_id": None,
                    "error": None,
                }
            )
    rng.shuffle(candidates)
    for index, entry in enumerate(candidates, start=1):
        entry["entry_id"] = f"run_{index:05d}"

    catalog_path = Path(__file__).with_name("scenarios.json")
    fingerprint = (
        f"{sha256_file(catalog_path)}:{seed}:{normal_sessions}:"
        f"{attack_sessions_per_scenario}"
    )
    campaign_digest = hashlib.sha256(
        fingerprint.encode("utf-8")
    ).hexdigest()[:16]
    plan = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": f"campaign_{campaign_digest}",
        "created_utc": utc_now(),
        "experiment_mode": "live",
        "catalog_sha256": sha256_file(catalog_path),
        "seed": seed,
        "requested_counts": requested_counts,
        "entries": candidates,
    }
    validate_campaign_plan(plan)
    return plan


def validate_campaign_plan(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PLAN_KEYS:
        raise SchemaError("campaign plan has unexpected keys")
    if value["schema_version"] != CAMPAIGN_SCHEMA_VERSION:
        raise SchemaError("unsupported campaign plan schema")
    require_identifier(value["campaign_id"], "campaign_id")
    if value["experiment_mode"] != "live":
        raise SchemaError("campaign plans are reserved for live sessions")
    catalog_hash = value["catalog_sha256"]
    if (
        not isinstance(catalog_hash, str)
        or len(catalog_hash) != 64
        or any(character not in "0123456789abcdef" for character in catalog_hash)
    ):
        raise SchemaError("invalid catalog_sha256")
    catalog_path = Path(__file__).with_name("scenarios.json")
    current_catalog = catalog_hash == sha256_file(catalog_path)
    archived_catalog = ARCHIVED_COMPLETED_CATALOGS.get(catalog_hash)
    if not current_catalog:
        entries = value.get("entries")
        if archived_catalog is None:
            raise SchemaError(
                "campaign catalog_sha256 does not match current or archived catalog"
            )
        if (
            not isinstance(entries, list)
            or not entries
            or any(
                not isinstance(entry, dict) or entry.get("status") != "complete"
                for entry in entries
            )
        ):
            raise SchemaError(
                "archived catalogs are verification-only for completed campaigns"
            )
    _require_int(value["seed"], "seed", minimum=0, maximum=2_147_483_647)
    if not isinstance(value["requested_counts"], dict):
        raise SchemaError("requested_counts must be an object")
    if not isinstance(value["entries"], list) or not value["entries"]:
        raise SchemaError("campaign entries must be a non-empty list")
    if len(value["entries"]) > MAX_CAMPAIGN_SESSIONS:
        raise SchemaError("campaign contains too many entries")

    catalog = load_catalog() if current_catalog else None
    seen_ids: set[str] = set()
    actual_counts: dict[str, dict[str, int]] = {}
    for entry in value["entries"]:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise SchemaError("campaign entry has unexpected keys")
        entry_id = require_identifier(entry["entry_id"], "entry_id")
        if entry_id in seen_ids:
            raise SchemaError("duplicate campaign entry_id")
        seen_ids.add(entry_id)
        scenario_id = require_identifier(
            entry["scenario_id"], "entry.scenario_id"
        )
        if current_catalog:
            assert catalog is not None
            if scenario_id not in catalog:
                raise SchemaError(f"unknown campaign scenario: {scenario_id}")
            scenario = catalog[scenario_id]
            expected_attack_class = scenario.attack_class
            expected_action = scenario.expected_action
        else:
            assert archived_catalog is not None
            if scenario_id not in archived_catalog:
                raise SchemaError(f"unknown archived campaign scenario: {scenario_id}")
            expected_attack_class, expected_action = archived_catalog[scenario_id]
        if entry["attack_class"] != expected_attack_class:
            raise SchemaError("campaign attack_class does not match catalog")
        if entry["expected_action"] != expected_action:
            raise SchemaError("campaign expected_action does not match catalog")
        security_mode = entry["security_mode"]
        if security_mode not in {"permissive", "enforce"}:
            raise SchemaError("invalid campaign security_mode")
        if (
            current_catalog
            and runner_requires_enforce(catalog[scenario_id].runner)
            and security_mode != "enforce"
        ):
            # 持證內鬼在 Permissive 下沒有意義,而 `session_environment` 會以
            # ValueError 拒絕——那個例外會讓**整批** campaign 中止(見
            # `execute_campaign` 的 `raise`),不是跳過一場。
            #
            # 2026-09-20：`mega_plan.json` 有 160 個這種 entry,每一批
            # permissive 都在撞到第一個時死掉。12.4 小時裡 permissive 只完成
            # 54 場而 enforce 有 136 場。載入時就拒絕,比執行到一半才炸好。
            # 修法是 `campaign repair`,不是放寬這條。
            raise SchemaError(
                f"campaign entry {entry['entry_id']} schedules credentialed "
                f"insider {scenario_id!r} under {security_mode!r}; insiders "
                "are only meaningful under Enforce (run `campaign repair`)"
            )
        expected_domain = 30
        if entry["domain_id"] != expected_domain:
            raise SchemaError("campaign domain does not match security mode")
        _require_int(
            entry["seed"],
            "entry.seed",
            minimum=1,
            maximum=2_147_483_646,
        )
        if entry["status"] not in ENTRY_STATUSES:
            raise SchemaError("invalid campaign entry status")
        if entry["session_id"] is not None and not isinstance(
            entry["session_id"], str
        ):
            raise SchemaError("campaign session_id must be string or null")
        if entry["error"] is not None and not isinstance(entry["error"], str):
            raise SchemaError("campaign error must be string or null")
        per_scenario = actual_counts.setdefault(
            scenario_id,
            {"total": 0, "permissive": 0, "enforce": 0},
        )
        per_scenario["total"] += 1
        per_scenario[security_mode] += 1

    if value["requested_counts"] != actual_counts:
        raise SchemaError("requested_counts do not match campaign entries")
    return value


def repair_campaign_plan(
    path: str | Path,
    *,
    dry_run: bool = False,
    reset_ineligible: bool = False,
) -> dict[str, Any]:
    """把排錯模式的持證內鬼 entry 就地改成 Enforce,保住已完成的進度。

    為什麼需要一支修復工具,而不是重新產生計畫:重新產生會丟掉
    `status=complete` 與 `session_id`,而那是已經跑出來的 live 場次與計畫
    entry 之間**唯一**的對應關係。190 場的進度不能為了修一個排程錯誤而作廢。

    三條界線:

    * **只動不可執行的 entry。** 已完成的內鬼-permissive entry 在物理上不可能
      存在（`session_environment` 會先拒絕）,所以遇到一個就是有更深的問題,
      直接 fail-closed,不要安靜地改掉它。
    * **failed 一併回到 pending。** 它們的 error 正是那個 ValueError,
      不是真的攻擊失敗;留著 failed 會讓 `--retry-failed` 之外的批次跳過它們。
    * **`requested_counts` 要跟著重算。** 摘要與 entry 是分開算的,
      `validate_campaign_plan` 會逐項比對——只改一邊會在下次載入時被擋下。
      （這正是 2026-09-20 合成資料集 gate 的同一課:名字說 per_scenario 而
      實際數 per_class,不一致的兩份計數遲早會量錯東西。）
    * **`ineligible` 預設不動。** 它代表「場次跑完但不合格」,而監督器每一輪
      都會呼叫 repair——自動重排會讓一個系統性壞掉的 scenario 無限重跑。
      修好成因之後用 `reset_ineligible=True` 明確把它們放回 pending。
    """
    plan_path = Path(path).expanduser()
    if plan_path.is_symlink():
        raise SchemaError("campaign plan may not be a symlink")
    plan_path = plan_path.resolve()
    catalog = load_catalog()

    with _CampaignLock(plan_path):
        # ⚠️ 刻意不走 `load_campaign_plan`:它現在會因為這個缺陷本身而拒絕
        # 載入,修復工具不能依賴一個被它要修的東西擋住的入口。
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        if not isinstance(plan, dict) or not isinstance(
            plan.get("entries"), list
        ):
            raise SchemaError("campaign plan is not a plan")

        repaired: list[dict[str, str]] = []
        requeued: list[str] = []
        impossible: list[str] = []
        for entry in plan["entries"]:
            scenario = catalog.get(entry.get("scenario_id"))
            if scenario is None:
                continue
            if not runner_requires_enforce(scenario.runner):
                continue
            if entry.get("security_mode") == "enforce":
                continue
            if entry.get("status") == "complete":
                impossible.append(str(entry.get("entry_id")))
                continue
            repaired.append(
                {
                    "entry_id": str(entry.get("entry_id")),
                    "scenario_id": str(entry.get("scenario_id")),
                    "was_mode": str(entry.get("security_mode")),
                    "was_status": str(entry.get("status")),
                }
            )
            entry["security_mode"] = "enforce"
            if entry.get("status") == "failed":
                entry["status"] = "pending"
            entry["error"] = None

        # A separate pass, over *every* entry: an ineligible session is not an
        # insider-scheduling problem and has nothing to do with the mode flip
        # above. Folding it into that loop would have requeued only the handful
        # of entries that also needed repairing, and said nothing about it.
        if reset_ineligible:
            for entry in plan["entries"]:
                if entry.get("status") != "ineligible":
                    continue
                entry["status"] = "pending"
                entry["error"] = None
                requeued.append(str(entry.get("entry_id")))

        if impossible:
            raise SchemaError(
                "refusing to repair: these insider entries are marked complete "
                "under a non-Enforce mode, which session_environment makes "
                f"impossible — investigate before repairing: {impossible}"
            )

        counts: dict[str, dict[str, int]] = {}
        for entry in plan["entries"]:
            per = counts.setdefault(
                entry["scenario_id"],
                {"total": 0, "permissive": 0, "enforce": 0},
            )
            per["total"] += 1
            per[entry["security_mode"]] += 1
        plan["requested_counts"] = counts

        validate_campaign_plan(plan)
        # `requeued` alone is a real change; gating the write on `repaired`
        # would silently discard a --reset-ineligible pass.
        if (repaired or requeued) and not dry_run:
            atomic_write_json(plan_path, plan)

    return {
        "plan": str(plan_path),
        "dry_run": dry_run,
        "repaired": len(repaired),
        "entries": repaired[:20],
        "requeued_ineligible": len(requeued),
        "pending_enforce_after": sum(
            entry["security_mode"] == "enforce"
            and entry["status"] == "pending"
            for entry in plan["entries"]
        ),
        "pending_permissive_after": sum(
            entry["security_mode"] == "permissive"
            and entry["status"] == "pending"
            for entry in plan["entries"]
        ),
    }


def load_campaign_plan(path: str | Path) -> dict[str, Any]:
    plan_path = Path(path).expanduser()
    if plan_path.is_symlink():
        raise SchemaError("campaign plan may not be a symlink")
    return validate_campaign_plan(
        json.loads(plan_path.read_text(encoding="utf-8"))
    )


# 一個 campaign 行程的 cmdline 裡一定有這兩個之一。用來分辨「鎖的持有者還活著」
# 與「那個 pid 被系統回收給了別人」——後者在 Linux 上是常態,pid 會繞回。
_CAMPAIGN_CMDLINE_MARKERS = ("firewall_lab.campaign", "run_mega_campaign")


def _lock_holder_pid(path: Path) -> int | None:
    """讀出鎖裡登記的 pid。讀不出來就回 None——那與「沒有人持有」不同。"""
    try:
        raw = path.read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    for line in raw.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "pid":
            try:
                pid = int(value.strip())
            except ValueError:
                return None
            return pid if pid > 0 else None
    return None


def _campaign_process_alive(pid: int) -> bool:
    """那個 pid 現在是不是一個活著的 campaign 行程。

    兩道都要成立,因為 pid 會被回收：行程存在,**而且**它的 cmdline 看起來
    真的是 campaign。只檢查「存在」會讓一個拿到同號碼的無關行程冒充持有者,
    於是鎖永遠解不開——那正是這個函式要消除的死結。

    ⚠️ 讀不到 `/proc`（非 Linux、或權限不足）時**保守回 True**：
    分不出來的時候要當成「有人在跑」,fail-closed 比自作聰明安全。
    """

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # 存在但不屬於我們。分不出是不是 campaign,保守當成活的。
        return True
    except OSError:
        return True

    cmdline = Path(f"/proc/{pid}/cmdline")
    try:
        raw = cmdline.read_bytes().replace(b"\0", b" ").decode(
            "utf-8", errors="replace"
        )
    except OSError:
        return True  # 拿不到 cmdline 就不推論
    return any(marker in raw for marker in _CAMPAIGN_CMDLINE_MARKERS)


class _CampaignLock:
    """計畫檔的互斥鎖,而且**認得自己的屍體**。

    ## 為什麼不能只用 O_EXCL

    原本的版本把 `pid=` 寫進鎖檔卻從來沒有人讀它,所以任何一次崩潰
    （斷電、SIGKILL、OOM）留下的鎖會**永久**擋住之後每一次 campaign 與每一次
    `repair`,而唯一的復原方式是 `rm -f`。

    2026-09-25 實測到這件事：重開機之後 `mega_plan.json.lock` 記著
    `pid=168734`,那個行程早就不存在,計畫因此完全動不了。

    ⚠️ 而那個 `rm -f` 正是 C2C-069 記的那次事故的成因——因為鎖分不出死活,
    「刪掉它」變成例行動作,於是我刪掉了一個**活著的**鎖,兩個 campaign
    同時把記憶體裡的計畫寫回同一個檔案。**把判斷放進鎖裡,那條危險的路就
    不再是例行動作。**

    ## 三種情況,三種處置

    | 鎖裡的 pid | 處置 |
    |---|---|
    | 活著且是 campaign | 拒絕（與原本相同） |
    | 已死,或活著但不是 campaign（pid 被回收） | **接手**,並大聲記錄接手了誰 |
    | 讀不出來 | **拒絕**,並明講要人工確認什麼 |

    最後一種刻意不接手：一個被截斷的鎖沒辦法證明持有者死了,而猜錯的代價
    是兩個 campaign 併寫。這一條讓 `rm -f` 仍然存在,但只留給真正罕見的情況,
    而且錯誤訊息會說清楚「先確認沒有 campaign 行程」。
    """

    def __init__(self, plan_path: Path):
        self.path = plan_path.with_suffix(plan_path.suffix + ".lock")
        self.fd: int | None = None
        self.stole_from: int | None = None

    def _acquire(self) -> bool:
        try:
            self.fd = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            return False
        os.write(self.fd, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(self.fd)
        return True

    def __enter__(self):
        if self._acquire():
            return self

        holder = _lock_holder_pid(self.path)
        if holder is None:
            raise RuntimeError(
                f"campaign lock exists but names no readable pid: {self.path}. "
                "Confirm no campaign process is running "
                "(pgrep -af 'firewall_lab.campaign|run_mega_campaign') "
                "before removing it by hand."
            )
        if _campaign_process_alive(holder):
            raise RuntimeError(
                f"campaign is already locked by live pid {holder}: {self.path}"
            )

        # 持有者死了。接手,並且記錄——一個安靜的接手會把「崩潰過」這件事藏起來。
        print(
            f"♻️ 接手已死的 campaign 鎖（原持有者 pid={holder} 已不存在）："
            f"{self.path}",
            flush=True,
        )
        self.path.unlink(missing_ok=True)
        if not self._acquire():
            raise RuntimeError(
                f"campaign lock reappeared while taking it over: {self.path}"
            )
        self.stole_from = holder
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.path.unlink(missing_ok=True)


# A batch tolerates a few ineligible sessions and aborts on a bad rate.
#
# Both conditions must hold: at least this many, *and* above this share. The
# count stops a three-session smoke run from aborting on its first miss; the
# share is what actually detects a broken stack. The healthy ineligible rate
# measured on 2026-09-24 was 7 in 406 (1.7%) once the N37 budget defect was
# accounted for, so 25% is far above anything normal operation produces.
MAX_INELIGIBLE_BEFORE_ABORT = 5
MAX_INELIGIBLE_RATE = 0.25


def execute_campaign(
    *,
    plan_path: str | Path,
    dataset_root: str | Path,
    security_mode: str,
    capture_interface: str,
    limit: int | None = None,
    duration_override: float | None = None,
    jitter: bool = False,
    adaptive: bool = False,
    ros_snapshots: bool = False,
    retry_failed: bool = False,
    confirm_isolated_lab: bool = False,
    minimum_free_gib: float = DEFAULT_MINIMUM_FREE_GIB,
) -> dict[str, Any]:
    """Run one security mode at a time so the external stack cannot drift."""
    if not confirm_isolated_lab:
        raise ValueError(
            "live campaign refused without isolated-lab confirmation"
        )
    if security_mode not in {"permissive", "enforce"}:
        raise ValueError("security_mode must be permissive or enforce")
    if not capture_interface:
        raise ValueError(
            "live campaign requires packet capture for training eligibility"
        )
    if limit is not None:
        _require_int(limit, "limit", minimum=1, maximum=MAX_CAMPAIGN_SESSIONS)
    minimum_free_gib = _validate_minimum_free_gib(minimum_free_gib)

    path = Path(plan_path).expanduser()
    if path.is_symlink():
        raise SchemaError("campaign plan may not be a symlink")
    path = path.resolve()
    output = _prepare_output_root(Path(dataset_root))
    catalog = load_catalog()
    completed: list[str] = []
    # Entries whose session completed but did not qualify for training. They
    # are recorded, not retried and not silently dropped.
    ineligible: list[str] = []
    attempted = 0
    with _CampaignLock(path):
        plan = load_campaign_plan(path)
        candidates = [
            entry
            for entry in plan["entries"]
            if entry["security_mode"] == security_mode
            and (
                entry["status"] == "pending"
                or (
                    retry_failed
                    and entry["status"] in {"failed", "running"}
                )
            )
        ]
        for entry in candidates:
            if limit is not None and attempted >= limit:
                break
            _ensure_minimum_free_space(output, minimum_free_gib)
            attempted += 1
            print(
                f"▶ {entry['entry_id']} {entry['scenario_id']} "
                f"mode={security_mode} seed={entry['seed']}",
                flush=True,
            )
            entry["status"] = "running"
            entry["error"] = None
            atomic_write_json(path, plan)
            try:
                session_dir = run_session(
                    scenario=catalog[entry["scenario_id"]],
                    output_root=output,
                    mode="live",
                    security_mode=security_mode,
                    domain_id=entry["domain_id"],
                    seed=entry["seed"],
                    duration_override=duration_override,
                    jitter=jitter,
                    adaptive=adaptive,
                    # campaign 一律跑出貨 catalog（`plan` 的 catalog_sha256
                    # 也是對它取的），所以直接指過去,不用再傳一層。
                    catalog_path=str(
                        Path(__file__).with_name("scenarios.json")),
                    capture_interface=capture_interface,
                    ros_snapshots=ros_snapshots,
                )
                manifest = json.loads(
                    (session_dir / "manifest.json").read_text(
                        encoding="utf-8"
                    )
                )
                if (
                    manifest.get("status") != "complete"
                    or manifest.get("origin") != "live_lab"
                    or manifest.get("training_eligible") is not True
                ):
                    gate = (
                        manifest.get("result", {})
                        .get("training_gate", "unknown")
                    )
                    reason = (
                        "live session failed training gate: "
                        f"status={manifest.get('status')} gate={gate}"
                    )
                    # The session is already on disk with
                    # `training_eligible: false`, so it can never reach a
                    # training set. Raising here would additionally destroy
                    # every remaining entry in the batch and the stack startup
                    # that paid for it.
                    #
                    # Measured 2026-09-24: 14.3% of adaptive sessions were
                    # being SIGKILLed past their budget, so a 40-session batch
                    # survived with probability 0.857^40 ~ 0.2%. Throughput
                    # went from 69 sessions a round to 2.
                    #
                    # Still fail-closed, but on the rate: a run where most
                    # sessions are ineligible is a broken stack, not bad luck.
                    ineligible.append(entry["entry_id"])
                    entry["status"] = "ineligible"
                    entry["error"] = reason
                    atomic_write_json(path, plan)
                    print(f"⚠️ {entry['entry_id']} {reason}", flush=True)
                    if len(ineligible) >= MAX_INELIGIBLE_BEFORE_ABORT and (
                        len(ineligible) > MAX_INELIGIBLE_RATE * (
                            len(completed) + len(ineligible)
                        )
                    ):
                        raise RuntimeError(
                            f"{len(ineligible)} of "
                            f"{len(completed) + len(ineligible)} sessions "
                            "failed the training gate; the stack is not "
                            f"producing usable evidence. Last: {reason}"
                        )
                    continue
            except Exception as exc:
                entry["status"] = "failed"
                entry["error"] = (
                    f"{type(exc).__name__}: {str(exc)[:1000]}"
                )
                atomic_write_json(path, plan)
                raise
            entry["status"] = "complete"
            entry["session_id"] = session_dir.name
            completed.append(session_dir.name)
            atomic_write_json(path, plan)
            print(
                f"✅ {entry['entry_id']} session={session_dir.name}",
                flush=True,
            )
    return {
        "campaign_id": plan["campaign_id"],
        "security_mode": security_mode,
        "attempted": attempted,
        "completed": completed,
        "remaining": sum(
            entry["security_mode"] == security_mode
            and entry["status"] != "complete"
            for entry in plan["entries"]
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan or resume a balanced live SROS2 firewall campaign"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    planner = subparsers.add_parser("plan")
    planner.add_argument("--output", type=Path, default=DEFAULT_PLAN)
    planner.add_argument("--normal-sessions", type=int, default=300)
    planner.add_argument(
        "--attack-sessions-per-scenario",
        type=int,
        default=100,
    )
    planner.add_argument("--seed", type=int, default=20260727)

    runner = subparsers.add_parser("run")
    runner.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    runner.add_argument("--dataset", type=Path, default=DEFAULT_LIVE_OUTPUT)
    runner.add_argument(
        "--security-mode",
        choices=("permissive", "enforce"),
        required=True,
    )
    runner.add_argument("--capture-interface", required=True)
    runner.add_argument("--limit", type=int, default=None)
    runner.add_argument("--duration", type=float, default=None)
    runner.add_argument(
        "--adaptive", action="store_true",
        help="用 N37 自適應驅動器,見 orchestrator")
    runner.add_argument(
        "--jitter", action="store_true",
        help="每一場另外抽 warmup／duration／cooldown，見 orchestrator")
    runner.add_argument("--ros-snapshots", action="store_true")
    runner.add_argument("--retry-failed", action="store_true")
    runner.add_argument(
        "--minimum-free-gib",
        type=float,
        default=DEFAULT_MINIMUM_FREE_GIB,
        help=(
            "stop before the next session when free space falls below "
            f"this reserve (default: {DEFAULT_MINIMUM_FREE_GIB:g} GiB)"
        ),
    )
    runner.add_argument("--confirm-isolated-lab", action="store_true")

    repairer = subparsers.add_parser(
        "repair",
        help="把排成 Permissive 的持證內鬼 entry 改回 Enforce（保留進度）",
    )
    repairer.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    repairer.add_argument(
        "--dry-run",
        action="store_true",
        help="只報告要改什麼，不寫檔",
    )
    repairer.add_argument(
        "--reset-ineligible",
        action="store_true",
        help=(
            "把 status=ineligible 的 entry 放回 pending。"
            "只在修好造成不合格的成因之後才用——監督器每輪都會呼叫 repair，"
            "自動重排會讓系統性的失敗無限重跑。"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "plan":
        plan = create_campaign_plan(
            normal_sessions=args.normal_sessions,
            attack_sessions_per_scenario=args.attack_sessions_per_scenario,
            seed=args.seed,
        )
        output = args.output.expanduser()
        if output.is_symlink():
            raise SystemExit("campaign output may not be a symlink")
        atomic_write_json(output, plan)
        print(
            f"✅ campaign plan：{len(plan['entries'])} sessions → {output}"
        )
        return 0

    if args.command == "repair":
        report = repair_campaign_plan(
            args.plan,
            dry_run=args.dry_run,
            reset_ineligible=args.reset_ineligible,
        )
        verb = "會改" if args.dry_run else "已改"
        print(
            f"{'🔍' if args.dry_run else '✅'} {verb} {report['repaired']} "
            f"個內鬼 entry → enforce；之後 pending："
            f"enforce {report['pending_enforce_after']}／"
            f"permissive {report['pending_permissive_after']}"
        )
        if report["requeued_ineligible"]:
            print(
                f"   ♻️ {report['requeued_ineligible']} 個 ineligible entry "
                "放回 pending"
            )
        for item in report["entries"]:
            print(
                f"   {item['entry_id']} {item['scenario_id']} "
                f"{item['was_mode']}/{item['was_status']} → enforce"
            )
        if report["repaired"] > len(report["entries"]):
            print(f"   …另外 {report['repaired'] - len(report['entries'])} 個")
        return 0

    result = execute_campaign(
        plan_path=args.plan,
        dataset_root=args.dataset,
        security_mode=args.security_mode,
        capture_interface=args.capture_interface,
        limit=args.limit,
        duration_override=args.duration,
        jitter=args.jitter,
        adaptive=args.adaptive,
        ros_snapshots=args.ros_snapshots,
        retry_failed=args.retry_failed,
        confirm_isolated_lab=args.confirm_isolated_lab,
        minimum_free_gib=args.minimum_free_gib,
    )
    print(
        f"✅ {result['security_mode']} completed "
        f"{len(result['completed'])}/{result['attempted']}; "
        f"remaining={result['remaining']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
