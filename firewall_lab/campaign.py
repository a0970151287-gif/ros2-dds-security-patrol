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
ENTRY_STATUSES = frozenset({"pending", "running", "complete", "failed"})
DEFAULT_PLAN = Path(__file__).resolve().parent / "campaign_1100.json"
DEFAULT_LIVE_OUTPUT = DEFAULT_OUTPUT.with_name("dataset_live")
DEFAULT_MINIMUM_FREE_GIB = 8.0
MAXIMUM_FREE_RESERVE_GIB = 1024.0
MAX_CAMPAIGN_SESSIONS = 10_000
# Completed evidence must remain independently verifiable after a catalog
# policy migration. Archived catalogs bind only the fields stored in a plan
# and can never be used to execute pending work.
ARCHIVED_COMPLETED_CATALOGS = {
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


def load_campaign_plan(path: str | Path) -> dict[str, Any]:
    plan_path = Path(path).expanduser()
    if plan_path.is_symlink():
        raise SchemaError("campaign plan may not be a symlink")
    return validate_campaign_plan(
        json.loads(plan_path.read_text(encoding="utf-8"))
    )


class _CampaignLock:
    def __init__(self, plan_path: Path):
        self.path = plan_path.with_suffix(plan_path.suffix + ".lock")
        self.fd: int | None = None

    def __enter__(self):
        try:
            self.fd = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError as exc:
            raise RuntimeError(
                f"campaign is already locked: {self.path}"
            ) from exc
        os.write(self.fd, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(self.fd)
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.path.unlink(missing_ok=True)


def execute_campaign(
    *,
    plan_path: str | Path,
    dataset_root: str | Path,
    security_mode: str,
    capture_interface: str,
    limit: int | None = None,
    duration_override: float | None = None,
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
                    raise RuntimeError(
                        "live session failed training gate: "
                        f"status={manifest.get('status')} gate={gate}"
                    )
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

    result = execute_campaign(
        plan_path=args.plan,
        dataset_root=args.dataset,
        security_mode=args.security_mode,
        capture_interface=args.capture_interface,
        limit=args.limit,
        duration_override=args.duration,
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
