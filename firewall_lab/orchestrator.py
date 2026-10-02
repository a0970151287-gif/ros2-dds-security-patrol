#!/usr/bin/env python3
"""Generate precisely labelled SROS2 firewall experiment sessions.

Smoke mode validates the pipeline but is permanently marked non-trainable.
Live mode executes only allowlisted runners and requires an explicit isolated
lab confirmation.  No runner is loaded from a command string in the catalog.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .catalog import Scenario, load_catalog
from .evidence import (
    JsonlWriter,
    ManagedProcess,
    ResourceSampler,
    evidence_inventory,
    run_snapshot,
)
from .runners import build_adaptive_argv, build_attack_argv, session_environment
from .schema import (
    SessionManifest,
    atomic_write_json,
    make_event,
    make_label,
    new_session_id,
    sha256_file,
    utc_now,
)


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
# CLOCK_MONOTONIC 的絕對期限,傳給自適應驅動器。見上面的說明。
ATTACK_DEADLINE_ENV = "SROS2_ATTACK_DEADLINE_MONOTONIC"

DEFAULT_OUTPUT = Path(__file__).resolve().parent / "dataset"
POLICY_PATH = (
    WORKSPACE_ROOT / "展示指令" / "sros2_policy_least_privilege.xml"
)
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
MAX_SESSIONS_PER_INVOCATION = 10_000
TELEMETRY_SOCKET_NAME = "runtime_telemetry.sock"


class SessionEvents:
    def __init__(self, path: Path, session_id: str, attack_class: str):
        self.writer = JsonlWriter(path)
        self.session_id = session_id
        self.attack_class = attack_class
        self.sequence = 0

    def emit(
        self,
        event_type: str,
        phase: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = make_event(
            session_id=self.session_id,
            sequence=self.sequence,
            event_type=event_type,
            phase=phase,
            attack_class=self.attack_class,
            details=details,
        )
        self.sequence += 1
        self.writer.append(event)
        return event


def _git_revision() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
        )
        revision = result.stdout.strip().lower()
        if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", revision):
            return revision
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _resolve_domain(security_mode: str, requested: int | None) -> int:
    if requested is not None:
        if not 0 <= requested <= 232:
            raise ValueError("domain id must be in 0..232")
        domain = requested
    else:
        # Keep Permissive/Enforce comparisons on the same RTPS port family.
        # Otherwise a model can learn the domain-derived port instead of the
        # attack behavior.  The two modes must be run at different times.
        domain = 30
    if security_mode == "enforce" and domain != 30:
        raise ValueError(
            "canonical SROS2 policy is signed for domain 30; "
            "regenerate a dedicated lab keystore before using another domain"
        )
    return domain


def _prepare_output_root(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path.exists() and path.is_symlink():
        raise ValueError("dataset output root may not be a symlink")
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("dataset output root may not be a symlink")
    return path


def _phase_sleep(seconds: float, mode: str) -> None:
    if mode == "smoke":
        time.sleep(min(0.02, max(0.0, seconds)))
    else:
        time.sleep(seconds)


def _write_smoke_observations(
    path: Path,
    *,
    rng: random.Random,
    attack_class: str,
    intensity: float,
) -> None:
    writer = JsonlWriter(path)
    for index in range(12):
        attack = attack_class != "normal" and 3 <= index <= 8
        multiplier = 1.0 + (intensity * 8.0 if attack else 0.0)
        writer.append(
            {
                "schema_version": "sros2-firewall-smoke-observation/v1",
                "training_eligible": False,
                "sample_index": index,
                "ts_unix_ns": time.time_ns(),
                "participant_count": int(8 + rng.randint(0, 2) + attack),
                "spdp_rate": round(
                    (2.0 + rng.random()) * multiplier, 4
                ),
                "data_rate": round(
                    (20.0 + rng.random() * 5.0) * multiplier, 4
                ),
                "auth_failures": int(attack and intensity > 0.25),
                "permission_denies": int(attack and intensity > 0.5),
                "label": attack_class if attack else "normal",
            }
        )


def _start_capture(
    *,
    interface: str | None,
    session_dir: Path,
    env: dict[str, str],
) -> ManagedProcess | None:
    if interface is None:
        return None
    if not INTERFACE_RE.fullmatch(interface):
        raise ValueError("capture interface contains invalid characters")
    dumpcap = shutil.which("dumpcap")
    if dumpcap is None:
        raise FileNotFoundError(
            "dumpcap is not on PATH; configure non-root packet capture first"
        )
    process = ManagedProcess(
        argv=[
            dumpcap,
            "-q",
            "-i",
            interface,
            "-f",
            "udp portrange 7400-15200",
            "-w",
            str(session_dir / "traffic.pcapng"),
        ],
        cwd=WORKSPACE_ROOT,
        env=env,
        stdout_path=session_dir / "capture.stdout.log",
        stderr_path=session_dir / "capture.stderr.log",
    )
    process.start()
    return process


def _live_runtime_dir() -> Path:
    configured = os.environ.get("FIREWALL_LIVE_RUNTIME")
    return Path(configured) if configured else WORKSPACE_ROOT / "firewall_lab" / "live_runtime"


def _start_runtime_telemetry(
    *,
    session_dir: Path,
    session_id: str,
    env: dict[str, str],
) -> tuple[ManagedProcess, Path]:
    socket_path = _live_runtime_dir() / TELEMETRY_SOCKET_NAME
    process = ManagedProcess(
        argv=[
            sys.executable,
            "-m",
            "firewall_lab.live_telemetry_collector",
            "--session-id",
            session_id,
            "--source",
            "telemetry_collector",
            "--output",
            str(session_dir / "telemetry_events.jsonl"),
            "--socket",
            str(socket_path),
            "--tick-sec",
            "1.0",
        ],
        cwd=WORKSPACE_ROOT,
        env=env,
        stdout_path=session_dir / "telemetry_collector.stdout.log",
        stderr_path=session_dir / "telemetry_collector.stderr.log",
    )
    process.start()
    # A slow start is not a failure.  The collector has to spawn an interpreter
    # and import this package, which costs ~0.8s when the workspace sits on the
    # WSL 9p mount; measured socket-bind time is 0.9-1.1s idle and 1.9s under
    # the load a campaign generates.  Against the original 2.0s deadline that
    # left 50-120ms of margin, so the Permissive arm ran 856 sessions and then
    # lost the whole batch to a coin flip at session 857.
    #
    # Waiting longer costs nothing when the collector is healthy: the loop
    # returns the moment the socket appears.  To keep genuine failures fast,
    # stop as soon as the process exits rather than sitting out the deadline,
    # and report its stderr instead of a bare timeout.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if socket_path.is_socket() and not socket_path.is_symlink():
            return process, socket_path
        if process.poll() is not None:
            break
        time.sleep(0.02)
    result = process.stop(grace_sec=1.0)
    detail = ""
    try:
        stderr = (session_dir / "telemetry_collector.stderr.log").read_text(
            encoding="utf-8", errors="replace"
        ).strip()
        if stderr:
            detail = f"; collector stderr: {stderr.splitlines()[-1][:200]}"
    except OSError:
        pass
    raise RuntimeError(
        "runtime telemetry collector did not create its local socket "
        f"(exit={result.return_code}){detail}"
    )


def _start_sros2_log_adapter(
    *,
    security_mode: str,
    socket_path: Path,
    session_dir: Path,
    env: dict[str, str],
) -> ManagedProcess | None:
    stack_log = _live_runtime_dir() / f"{security_mode}.log"
    if stack_log.is_symlink() or not stack_log.is_file():
        return None
    process = ManagedProcess(
        argv=[
            sys.executable,
            "-m",
            "firewall_lab.sros2_deny_adapter",
            "--socket",
            str(socket_path),
            "--source",
            "sros2_log_adapter",
            "--follow",
            str(stack_log),
        ],
        cwd=WORKSPACE_ROOT,
        env=env,
        stdout_path=session_dir / "sros2_adapter.stdout.log",
        stderr_path=session_dir / "sros2_adapter.stderr.log",
    )
    process.start()
    return process


def _telemetry_stream_succeeded(
    session_dir: Path,
    result: dict[str, Any] | None,
) -> bool:
    if not isinstance(result, dict) or result.get("return_code") != 0:
        return False
    path = session_dir / "telemetry_events.jsonl"
    if path.is_symlink() or not path.is_file():
        return False
    try:
        events = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    has_tick = any(item.get("event_type") == "collector_tick" for item in events)
    has_runtime = any(
        item.get("source") != "telemetry_collector"
        and item.get("event_type") != "collector_tick"
        for item in events
    )
    return has_tick and has_runtime


# Zeek closes a UDP flow only after this much inactivity, and writes one
# conn.log record per closed flow stamped with the flow's FIRST packet.  DDS
# keeps its participant flows open for the whole session, so at Zeek's 60s
# default a 45s session yields a single burst of records at t0 and nothing
# afterwards -- the 2026-08-06 loopback pilot collapsed every session into
# window 0, discarding all attack-interval signal.
#
# The timeout must stay below the 8s feature window (features.build_features
# window_sec / synthetic_dataset.DEFAULT_WINDOW_SEC) so any flow still carrying
# traffic during a window is re-logged inside it.  Measured on the pilot PCAPs,
# 5s reproduces exactly the window count that packet timestamps give as ground
# truth (6 and 3), whereas 10s misses windows and 2s degenerates to one record
# per packet, destroying the connection semantics the 14 network features and
# the synthetic pretraining set are built on.
ZEEK_UDP_INACTIVITY_TIMEOUT_SEC = 5


def _run_offline_zeek(session_dir: Path, env: dict[str, str]) -> dict[str, Any]:
    pcap = session_dir / "traffic.pcapng"
    if not pcap.is_file() or pcap.stat().st_size <= 128:
        return {"status": "skipped", "reason": "missing_or_empty_pcap"}
    zeek = shutil.which("zeek")
    if zeek is None and Path("/opt/zeek/bin/zeek").is_file():
        zeek = "/opt/zeek/bin/zeek"
    if zeek is None:
        return {"status": "skipped", "reason": "zeek_not_found"}
    zeek_dir = session_dir / "zeek"
    zeek_dir.mkdir()
    record = run_snapshot(
        argv=[
            zeek,
            # -C：不要因為校驗和錯誤丟棄封包。
            #
            # loopback 與虛擬介面有 checksum offload——核心不計算校驗和，所以
            # 擷取到的封包校驗和是無效的，Zeek 預設把它們當成損壞。2026-08-31
            # 在同一份 pcap 上實測：
            #
            #   不加 -C : 582 conn 列，orig_bytes/orig_pkts/duration 全部未設定
            #             或 0，history=CC（兩個方向都是校驗和錯誤）
            #   加了 -C :  76 conn 列，orig_bytes=12840、orig_pkts=15、
            #             duration=40.78，history=D
            #
            # 影響不只是「拿不到位元組」：**連線數本身差 7.6 倍**，因為流組不
            # 起來就會碎成大量假紀錄。conn_count 與 conn_rate 是現用特徵，
            # 它們先前量到的是校驗和造成的碎裂，不是連線行為。
            "-C",
            "-r",
            str(pcap),
            "-e",
            "redef udp_inactivity_timeout = "
            f"{ZEEK_UDP_INACTIVITY_TIMEOUT_SEC}sec;",
        ],
        cwd=zeek_dir,
        env=env,
        output_path=session_dir / "zeek_process.json",
        timeout_sec=120,
    )
    return {
        "status": "complete" if record["return_code"] == 0 else "failed",
        "return_code": record["return_code"],
        "conn_log": (zeek_dir / "conn.log").is_file(),
        "udp_inactivity_timeout_sec": ZEEK_UDP_INACTIVITY_TIMEOUT_SEC,
    }


PACKET_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
)


def _extract_packet_windows(
    session_dir: Path, env: dict[str, str]
) -> dict[str, Any]:
    """把 pcap 攤成逐封包 TSV，供按時間分窗的網路特徵使用。

    `conn.log` 一筆代表整條流、時間戳是流的起點，所以按它分窗量到的是「這個
    視窗裡開始了幾條流」而不是「這個視窗裡有多少流量」。2026-08-31 實測一場：
    真實流量跨度 46 秒，但 462 條流的起點全擠在前 9 秒。

    只抽取、不聚合——分窗與特徵怎麼算是下游的決定，逐封包紀錄留著才能重算。
    """
    pcap = session_dir / "traffic.pcapng"
    if not pcap.is_file() or pcap.stat().st_size <= 128:
        return {"status": "skipped", "reason": "missing_or_empty_pcap"}
    tshark = shutil.which("tshark")
    if tshark is None:
        return {"status": "skipped", "reason": "tshark_not_found"}

    # 逾時要跟著擷取量走,不能是固定值。
    #
    # 2026-09-25 實測：836 場裡 **94 場**在這裡逾時,而它們的 pcap 是
    # 126–795 MB（中位 263 MB、合計 28.4 GB）——全部是 `reason: timeout`,
    # 沒有一場是別的原因。固定的 300 秒對小場次綽綽有餘,對大場次必然不夠,
    # 所以它篩掉的不是「壞掉的場次」而是「流量大的場次」——那是一種會讓
    # 資料集系統性偏斜的失效,而且偏掉的正好是攻擊最兇的那些。
    #
    # ⚠️ 這與同日加進訓練閘的 `packet_windows` 條件是一組的:閘會把逾時的
    # 場次判為不合格,所以若逾時不跟著量體走,大 pcap 的場次會被系統性丟掉。
    #
    # 逾時的用途是攔住**卡死**的行程,不是排程——卡死的永遠不會結束,慢的會。
    # 所以寧可寬。上限 3600 秒仍然擋得住真的卡死。
    # ⚠️ 抽取在場次的牆鐘裡面,所以放寬會推高 `inside`,而步調熔斷器判的是
    # 對擷取量模型（`inside ≈ 85.7s + 0.376 s/MB`,C2C-073）的殘差。
    # 那個模型是在抽取**會被砍斷**的資料上配的,所以放寬之後殘差會系統性變大,
    # 下一輪要重配它,否則熔斷器會對健康的 campaign 誤判。
    size_mb = pcap.stat().st_size / 1e6
    extract_timeout = min(3600.0, 300.0 + 2.0 * size_mb)

    out_dir = session_dir / "packet_windows"
    out_dir.mkdir(exist_ok=True)
    argv = [tshark, "-r", str(pcap), "-T", "fields"]
    for field in PACKET_FIELDS:
        argv += ["-e", field]
    argv += ["-E", "header=n", "-E", "occurrence=f"]

    # 不用 run_snapshot：它把 stdout 存進 JSON，而這裡的 stdout 是上萬行封包。
    raw = out_dir / "packets.tsv"
    try:
        with raw.open("wb") as handle:
            completed = subprocess.run(
                argv,
                cwd=out_dir,
                env=env,
                stdout=handle,
                stderr=subprocess.PIPE,
                timeout=extract_timeout,
                check=False,
            )
    except subprocess.TimeoutExpired:
        raw.unlink(missing_ok=True)
        # 記下當時給了多久與 pcap 多大,否則「逾時」看不出是設定太緊還是真卡住。
        return {
            "status": "failed",
            "reason": "timeout",
            "timeout_sec": round(extract_timeout, 1),
            "pcap_mb": round(size_mb, 1),
        }
    if completed.returncode != 0:
        raw.unlink(missing_ok=True)
        return {
            "status": "failed",
            "return_code": completed.returncode,
            "stderr": completed.stderr.decode("utf-8", "replace")[:2000],
        }

    kept = 0
    with raw.open(encoding="utf-8", errors="replace") as src, gzip.open(
        out_dir / "packets.tsv.gz", "wt", encoding="utf-8", newline="\n"
    ) as dst:
        dst.write("\t".join(PACKET_FIELDS) + "\n")
        for line in src:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != len(PACKET_FIELDS):
                continue
            # 非 IP／非 UDP 的框沒有本專案要的欄位，跳過。
            if not parts[0] or not parts[1] or not parts[4]:
                continue
            dst.write(line if line.endswith("\n") else line + "\n")
            kept += 1
    raw.unlink(missing_ok=True)
    if kept == 0:
        (out_dir / "packets.tsv.gz").unlink(missing_ok=True)
        return {"status": "failed", "reason": "no_packets"}
    return {"status": "complete", "return_code": 0, "packets": kept}


def _ros_snapshots(
    *,
    prefix: str,
    session_dir: Path,
    env: dict[str, str],
) -> list[dict[str, Any]]:
    ros2 = shutil.which("ros2")
    if ros2 is None:
        return []
    return [
        run_snapshot(
            argv=[ros2, "node", "list"],
            cwd=WORKSPACE_ROOT,
            env=env,
            output_path=session_dir / f"{prefix}_ros_nodes.json",
            timeout_sec=12,
        ),
        run_snapshot(
            argv=[ros2, "topic", "list", "-t"],
            cwd=WORKSPACE_ROOT,
            env=env,
            output_path=session_dir / f"{prefix}_ros_topics.json",
            timeout_sec=12,
        ),
    ]


def _attack_process_succeeded(
    scenario: Scenario,
    result: dict[str, Any] | None,
    *,
    adaptive: bool = False,
) -> bool:
    """Return whether the allowlisted runner produced credible process evidence.

    Most bounded PoCs handle the factory's end-of-window signal and exit zero.
    The ROS demo talker is intentionally long-running, so it is valid only when
    the factory terminated it at the window boundary.  A runner that crashes
    early must never leave an attack-labelled session training eligible.

    ⚠️ 2026-09-20：那條 talker 專用規則在自適應模式下**把判定反過來了**。
    開了 `--adaptive` 之後,被啟動的行程一律是 N37 驅動器,不是 catalog 宣告的
    那支 runner——而 N37 的契約是「自己在視窗結束前 `os._exit(0)`」。於是
    `unauthorized_participant` 的場次裡:

    * 乾淨收尾的（rc=0、`terminated_by_factory=False`、有 DECISION_TRACE）
      被判**不合格** —— 7 場;
    * 被工廠 SIGKILL 的（rc=-9、決策軌跡整份遺失）反而判**合格** —— 5 場。

    規則是按 `scenario.runner` 寫的,而在自適應模式下那個名字已經不代表實際
    執行的東西。所以要問的是「這一場實際啟動了什麼」,不是「catalog 說它是誰」。
    """
    if scenario.runner == "normal":
        return result is None
    if not isinstance(result, dict):
        return False
    return_code = result.get("return_code")
    if isinstance(return_code, bool) or not isinstance(return_code, int):
        return False
    if adaptive:
        # N37 自己收尾。rc=-9 代表它在寬限期內沒退出——那一場的
        # DECISION_TRACE 一定是缺的,不可當成完整證據。
        return return_code == 0
    if scenario.runner == "unauthorized_participant":
        return (
            result.get("terminated_by_factory") is True
            and return_code in {0, -9, -15}
        )
    return return_code == 0


# ── 場次抖動（2026-09-20）─────────────────────────────────────────────
#
# 在這之前,orchestrator **只隨機化 intensity**;warmup／duration／cooldown
# 全部照 catalog、每一類固定。後果是 2026-09-15 量到的
# 「攻擊起始視窗 274／280（98%）固定在 window 1」——任何編碼「第幾個視窗」
# 的東西都會有效,而那在攻擊時間任意的真實部署上不會轉移。
#
# ⚠️ 最重要的約束：**warmup 與 cooldown 對每一個類別（含 normal）抽自同一個
# 分布**。若某一類的起點分布不同,模型會學到「起點 ⇒ 類別」,那是比原本更糟
# 的混淆——原本至少是所有類別一起偏。
#
# duration 用**乘數**而不是絕對值,因為各類攻擊的機制需要的時間本來就不同
# （graph_overflow 要 75 秒才跨得過 256 個 node,壓到 30 秒就什麼都沒發生）。
# ⚠️ 代價是 duration 的分布**與類別相關**。這一點必須用「場次長度能不能預測
# 類別」的對照去量,不能假設它無害。
JITTER_WARMUP_SEC = (4.0, 28.0)      # 8 秒一個視窗 ⇒ 攻擊起點落在 window 0–3
JITTER_COOLDOWN_SEC = (3.0, 12.0)
JITTER_DURATION_SCALE = (0.6, 1.3)   # 乘在 catalog 宣告的 duration 上
# 自適應模式需要更長的場次:一次「試探 → 觀察 → 決策」約 10 秒,
# 要看得出適應至少要 4–6 個回合。實測 29 秒的場次只塞得下 1 個。
# ⚠️ 這**不會**降低產出效率——場次長一倍產生的列數也接近一倍,
# 而每場約 7 秒的固定開銷（擷取啟停）反而被攤薄。
# 下限要保證塞得下 ≥3 個決策回合：(30×1.6 − 4) / (10 + 4) = 3.1。
# 1.4 只有 2.7 個回合，2026-09-20 的測試抓到。
JITTER_DURATION_SCALE_ADAPTIVE = (1.6, 2.6)


def run_session(
    *,
    scenario: Scenario,
    output_root: Path,
    mode: str,
    security_mode: str,
    domain_id: int,
    seed: int,
    duration_override: float | None,
    capture_interface: str | None,
    ros_snapshots: bool,
    jitter: bool = False,
    adaptive: bool = False,
    catalog_path: str | None = None,
) -> Path:
    rng = random.Random(seed)
    intensity = rng.uniform(
        scenario.intensity_min, scenario.intensity_max
    )
    if duration_override is not None:
        duration = float(duration_override)
    elif jitter:
        scale = (JITTER_DURATION_SCALE_ADAPTIVE if adaptive
                 else JITTER_DURATION_SCALE)
        duration = scenario.duration_sec * rng.uniform(*scale)
    else:
        duration = scenario.duration_sec
    duration = max(1.0, min(duration, 300.0))
    if jitter:
        # 先抽 warmup 與 cooldown,順序固定——換順序會改變同一個 seed 抽到的值,
        # 而 seed 是這一場唯一可重現的依據。
        warmup = rng.uniform(*JITTER_WARMUP_SEC)
        cooldown = rng.uniform(*JITTER_COOLDOWN_SEC)
    else:
        warmup = scenario.warmup_sec
        cooldown = scenario.cooldown_sec
    if not 1.0 <= duration <= 300.0:
        raise ValueError("session duration must be in 1..300 seconds")

    session_id = new_session_id(scenario.scenario_id)
    session_dir = output_root / session_id
    session_dir.mkdir(mode=0o700)
    if session_dir.is_symlink():
        raise ValueError("session directory may not be a symlink")

    policy_digest = sha256_file(POLICY_PATH) if POLICY_PATH.is_file() else ""
    manifest = SessionManifest(
        session_id=session_id,
        scenario_id=scenario.scenario_id,
        attack_class=scenario.attack_class,
        binary_label=(
            "normal" if scenario.attack_class == "normal" else "attack"
        ),
        security_mode=security_mode,
        ros_domain_id=domain_id,
        seed=seed,
        origin="live_lab" if mode == "live" else "simulated_smoke",
        training_eligible=False,
        expected_action=scenario.expected_action,
        policy_sha256=policy_digest,
        code_revision=_git_revision(),
        randomization={
            "intensity": intensity,
            "duration_sec": duration,
            "warmup_sec": warmup,
            "cooldown_sec": cooldown,
            "requires_gazebo": scenario.requires_gazebo,
            # 抖動開著時上面三個是**抽到的值**,不是 catalog 的宣告值。
            # 沒有這個旗標的話,事後無從分辨哪一批是抖動過的。
            "jitter": jitter,
            "adaptive": adaptive,
            "catalog_duration_sec": scenario.duration_sec,
            "catalog_warmup_sec": scenario.warmup_sec,
            "catalog_cooldown_sec": scenario.cooldown_sec,
        },
    )
    manifest_path = session_dir / "manifest.json"
    manifest.write(manifest_path)
    events = SessionEvents(
        session_dir / "events.jsonl",
        session_id,
        scenario.attack_class,
    )
    labels = JsonlWriter(session_dir / "labels.jsonl")
    resources = ResourceSampler(session_dir / "resources.jsonl")
    attack_process: ManagedProcess | None = None
    capture_process: ManagedProcess | None = None
    telemetry_process: ManagedProcess | None = None
    sros_adapter_process: ManagedProcess | None = None
    attack_result = None
    capture_result = None
    telemetry_result = None
    sros_adapter_result = None
    # 預設是沒有憑證的外部者；只有登記在 `CREDENTIALED_RUNNERS` 的內鬼 runner
    # 拿得到 keystore。
    #
    # keystore **不讀環境變數**。內鬼竊的是**防守方**的憑證，而防守方用哪一個
    # 由啟動腳本決定（`展示指令/01c_啟動系統_enforce.sh` 寫死
    # `$HOME/ros2_ws/sros2_keystore`）。`ROS_SECURITY_KEYSTORE` 只是 campaign
    # 執行者當下 shell 裡的值，與防守方無關——2026-09-02 就是因為讀了它而指到
    # `/home/jesse/ros2_security_keystore`（沒有那些 enclave），整批在第 8 場中止。
    #
    # 路徑或 enclave 不存在時 `insider_environment` 會直接拒絕，不會安靜降級。
    env = session_environment(
        scenario,
        domain_id=domain_id,
        duration_sec=duration,
        security_mode=security_mode,
        keystore=str(WORKSPACE_ROOT / "sros2_keystore"),
    )

    try:
        manifest.status = "running"
        manifest.started_utc = utc_now()
        manifest.write(manifest_path)
        events.emit(
            "session_started",
            "setup",
            {
                "mode": mode,
                "security_mode": security_mode,
                "domain_id": domain_id,
                "intensity": intensity,
            },
        )
        resources.start()
        if mode == "live":
            telemetry_process, telemetry_socket = _start_runtime_telemetry(
                session_dir=session_dir,
                session_id=session_id,
                env=env,
            )
            sros_adapter_process = _start_sros2_log_adapter(
                security_mode=security_mode,
                socket_path=telemetry_socket,
                session_dir=session_dir,
                env=env,
            )
            capture_process = _start_capture(
                interface=capture_interface,
                session_dir=session_dir,
                env=env,
            )
            if ros_snapshots:
                _ros_snapshots(
                    prefix="pre",
                    session_dir=session_dir,
                    env=env,
                )
        else:
            _write_smoke_observations(
                session_dir / "smoke_observations.jsonl",
                rng=rng,
                attack_class=scenario.attack_class,
                intensity=intensity,
            )

        events.emit("warmup_started", "warmup")
        _phase_sleep(warmup, mode)
        events.emit("warmup_completed", "warmup")

        attack_start = time.time_ns()
        events.emit(
            "attack_started",
            "attack",
            {
                "runner": scenario.runner,
                "credential_mode": "none",
            },
        )
        if mode == "live":
            if adaptive:
                # 自適應驅動器自己決定每個 burst 的 intensity,所以這裡不傳。
                # 它需要 catalog 路徑才能取回同一個 scenario 物件。
                argv = build_adaptive_argv(
                    scenario,
                    workspace_root=WORKSPACE_ROOT,
                    duration_sec=duration,
                    catalog_path=catalog_path or (
                        WORKSPACE_ROOT / "firewall_lab" / "scenarios.json"),
                    seed=seed,
                )
            else:
                argv = build_attack_argv(
                    scenario,
                    workspace_root=WORKSPACE_ROOT,
                    duration_sec=duration,
                    intensity=intensity,
                )
            if argv is not None:
                attack_env = dict(env)
                if adaptive:
                    # 把**絕對期限**交給驅動器,而不是讓它自己從「我什麼時候
                    # 開始跑」去推。
                    #
                    # 2026-09-24 實測:N37 自報在預算內 4.7 秒就結束,卻仍然被
                    # SIGKILL。兩邊的時鐘起點不同——工廠從 Popen() 起算,N37 從
                    # 模組第一行起算,而中間的直譯器開機加上從 /mnt/c 讀檔是
                    # **4.85 秒**,比它整個 4 秒的收尾預留還多。那段時間在模組
                    # 裡量不到,因為模組還沒開始跑。
                    #
                    # Linux 的 time.monotonic() 是 CLOCK_MONOTONIC,自開機起算
                    # 且每個行程一致,所以父行程指得出子行程認得的同一個瞬間。
                    # 開機的成本於是從攻擊視窗扣掉——那才是它該扣的地方——
                    # 而不是無聲地從收尾預留裡扣。
                    attack_env[ATTACK_DEADLINE_ENV] = repr(
                        time.monotonic() + duration
                    )
                attack_process = ManagedProcess(
                    argv=argv,
                    cwd=WORKSPACE_ROOT,
                    env=attack_env,
                    stdout_path=session_dir / "attack.stdout.log",
                    stderr_path=session_dir / "attack.stderr.log",
                )
                attack_process.start()
        _phase_sleep(duration, mode)
        attack_end = time.time_ns()
        events.emit("attack_completed", "attack")
        labels.append(
            make_label(
                session_id=session_id,
                attack_class=scenario.attack_class,
                start_unix_ns=attack_start,
                end_unix_ns=attack_end,
                source="allowlisted_runner" if mode == "live" else "smoke",
            )
        )

        if attack_process is not None:
            attack_result = attack_process.stop().to_dict()
            attack_process = None

        events.emit("cooldown_started", "cooldown")
        _phase_sleep(cooldown, mode)
        events.emit("cooldown_completed", "cooldown")

        if mode == "live" and ros_snapshots:
            _ros_snapshots(
                prefix="post",
                session_dir=session_dir,
                env=env,
            )
        if capture_process is not None:
            capture_result = capture_process.stop().to_dict()
            capture_process = None
        if sros_adapter_process is not None:
            sros_adapter_result = sros_adapter_process.stop().to_dict()
            sros_adapter_process = None
        if telemetry_process is not None:
            telemetry_result = telemetry_process.stop().to_dict()
            telemetry_process = None

        zeek_result = (
            _run_offline_zeek(session_dir, env)
            if mode == "live"
            else {"status": "skipped", "reason": "smoke"}
        )
        packet_result = (
            _extract_packet_windows(session_dir, env)
            if mode == "live"
            else {"status": "skipped", "reason": "smoke"}
        )
        pcap = session_dir / "traffic.pcapng"
        pcap_ok = (
            mode == "live"
            and pcap.is_file()
            and pcap.stat().st_size > 128
        )
        zeek_ok = (
            mode == "live"
            and zeek_result.get("status") == "complete"
            and zeek_result.get("return_code") == 0
            and zeek_result.get("conn_log") is True
        )
        capture_ok = (
            mode == "live"
            and isinstance(capture_result, dict)
            and capture_result.get("return_code") == 0
        )
        attack_ok = _attack_process_succeeded(
            scenario, attack_result, adaptive=adaptive
        )
        telemetry_ok = (
            mode == "live"
            and _telemetry_stream_succeeded(session_dir, telemetry_result)
        )
        # ⚠️ 2026-09-25 補上的第六項。它先前不在閘裡,而 `zeek` 的檢查
        # （status ＋ return_code ＋ conn_log）就在隔壁——同樣形狀的檢查
        # 對逐封包抽取就是沒寫。
        #
        # 實測 836 場裡 **94 場 `packet_windows: failed` 仍然
        # `training_eligible=true`**。那不會偷偷污染特徵表——`features.py`
        # 對「有 pcap 卻沒有 packets.tsv.gz」是 fail-closed 的——
        # **但它會讓重訓時的特徵抽取在第一場就整個中止**,而那時候已經是
        # 幾千場之後、離缺陷發生很遠了。閘是唯一能在當場擋下來的地方。
        #
        # 判準刻意與 `features.py:1479` **逐字對齊**：只有在 pcap 本身可用時
        # 才要求逐封包紀錄。沒有 pcap 的場次由 `pcap` 那一項自己擋,
        # 不需要在這裡重複判一次。
        packet_windows_ok = (not pcap_ok) or (
            packet_result.get("status") == "complete"
            and packet_result.get("return_code") == 0
        )
        gate_failures = [
            name
            for name, passed in (
                ("pcap", pcap_ok),
                ("zeek", zeek_ok),
                ("packet_windows", packet_windows_ok),
                ("capture_process", capture_ok),
                ("attack_process", attack_ok),
                ("runtime_telemetry", telemetry_ok),
            )
            if not passed
        ]
        manifest.training_eligible = not gate_failures
        manifest.result = {
            "attack_process": attack_result,
            "capture_process": capture_result,
            "telemetry_process": telemetry_result,
            "sros2_adapter_process": sros_adapter_result,
            "zeek": zeek_result,
            # ⚠️ 這段註解在 2026-10-02 之前聲稱這一項被刻意留在閘外,
            # 而 2026-09-25 已經把 `packet_windows` **加進**閘裡（見上面的
            # 第六項,並由 tests/test_packet_windows_gate.py 釘住）。
            # 一個說出程式相反行為的註解,比沒有註解更糟:它會讓下一個人
            # 以為抽取失敗不影響合格,然後去別的地方找原因。
            #
            # 原本那個理由（「讓一個後處理步驟否決掉一場真實 live 資料
            # 是不成比例的」）被一個量測推翻:缺紀錄不是「少一張表」,
            # 而是 features.py 對整個資料集 fail-closed,而且會在幾千場
            # 之後才中止。閘是唯一能在當場擋下來的地方。
            "packet_windows": packet_result,
            "label_interval_written": True,
            "training_gate": (
                "eligible"
                if not gate_failures
                else "not_eligible:" + ",".join(gate_failures)
            ),
        }
        manifest.status = "complete"
        events.emit(
            "session_completed",
            "finalize",
            {
                "training_eligible": manifest.training_eligible,
                "zeek_status": zeek_result.get("status"),
            },
        )
    except Exception as exc:
        manifest.status = "failed"
        manifest.training_eligible = False
        manifest.result = {
            "error_type": type(exc).__name__,
            "error": str(exc)[:2048],
            "attack_process": attack_result,
            "capture_process": capture_result,
            "telemetry_process": telemetry_result,
            "sros2_adapter_process": sros_adapter_result,
        }
        try:
            events.emit(
                "session_failed",
                "finalize",
                {
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        except Exception:
            pass
        raise
    finally:
        if attack_process is not None:
            try:
                manifest.result["attack_process"] = (
                    attack_process.stop().to_dict()
                )
            except Exception as stop_exc:
                manifest.result["attack_stop_error"] = str(stop_exc)[:1024]
        if capture_process is not None:
            try:
                manifest.result["capture_process"] = (
                    capture_process.stop().to_dict()
                )
            except Exception as stop_exc:
                manifest.result["capture_stop_error"] = str(stop_exc)[:1024]
        if sros_adapter_process is not None:
            try:
                manifest.result["sros2_adapter_process"] = (
                    sros_adapter_process.stop().to_dict()
                )
            except Exception as stop_exc:
                manifest.result["sros2_adapter_stop_error"] = str(stop_exc)[:1024]
        if telemetry_process is not None:
            try:
                manifest.result["telemetry_process"] = (
                    telemetry_process.stop().to_dict()
                )
            except Exception as stop_exc:
                manifest.result["telemetry_stop_error"] = str(stop_exc)[:1024]
        resources.stop()
        manifest.ended_utc = utc_now()
        try:
            manifest.evidence = evidence_inventory(session_dir)
        except Exception as inventory_exc:
            manifest.status = "failed"
            manifest.training_eligible = False
            manifest.result["inventory_error"] = str(inventory_exc)[:1024]
        manifest.write(manifest_path)

    return session_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SROS2 intelligent firewall dataset session factory"
    )
    parser.add_argument(
        "--scenario",
        default="all",
        help="scenario id or 'all' for seeded catalog rotation",
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=1,
        help=f"number of sessions (1..{MAX_SESSIONS_PER_INVOCATION})",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--adaptive", action="store_true",
        help="用 N37 自適應驅動器:場次內試探→觀察防禦→升級或退避")
    parser.add_argument(
        "--jitter", action="store_true",
        help="每一場另外抽 warmup／duration／cooldown。"
             "warmup 與 cooldown 對所有類別用同一個分布；"
             "duration 是乘在 catalog 宣告值上的乘數。")
    parser.add_argument(
        "--mode",
        choices=("smoke", "live"),
        default="smoke",
    )
    parser.add_argument(
        "--security-mode",
        choices=("permissive", "enforce"),
        default=None,
    )
    parser.add_argument("--domain-id", type=int, default=None)
    parser.add_argument("--duration", type=float, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )
    parser.add_argument(
        "--capture-interface",
        default=None,
        help="non-root dumpcap interface; omit to create a non-trainable live session",
    )
    parser.add_argument(
        "--ros-snapshots",
        action="store_true",
        help="capture ros2 node/topic CLI snapshots (best for Permissive)",
    )
    parser.add_argument(
        "--catalog",
        default=None,
        help=(
            "情境目錄檔，預設 firewall_lab/scenarios.json。候選情境用另一份"
            "檔案跑 smoke，才不必為了驗證而先寫進出貨 catalog——那會讓未驗證"
            "的情境進入預設 campaign，並改變 catalog 的 SHA-256，使既有"
            "campaign 的來源憑證失效。"
        ),
    )
    parser.add_argument(
        "--confirm-isolated-lab",
        action="store_true",
        help="required for live attack execution",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if (
        isinstance(args.sessions, bool)
        or not 1 <= args.sessions <= MAX_SESSIONS_PER_INVOCATION
    ):
        raise SystemExit(
            f"--sessions must be in 1..{MAX_SESSIONS_PER_INVOCATION}"
        )
    if args.mode == "live" and not args.confirm_isolated_lab:
        raise SystemExit(
            "live mode refused: add --confirm-isolated-lab only after "
            "verifying the ROS domain/network is isolated and authorized"
        )
    if args.capture_interface and args.mode != "live":
        raise SystemExit("--capture-interface is only valid in live mode")

    catalog = load_catalog(args.catalog)
    if args.scenario != "all" and args.scenario not in catalog:
        raise SystemExit(
            f"unknown scenario {args.scenario!r}; "
            f"choose one of {sorted(catalog)} or all"
        )
    output_root = _prepare_output_root(args.output)
    ordered = [catalog[key] for key in sorted(catalog)]
    generated = []
    for index in range(args.sessions):
        scenario = (
            catalog[args.scenario]
            if args.scenario != "all"
            else ordered[(args.seed + index) % len(ordered)]
        )
        security_mode = (
            args.security_mode or scenario.default_security_mode
        )
        domain = _resolve_domain(security_mode, args.domain_id)
        session_seed = args.seed + index
        generated.append(
            run_session(
                scenario=scenario,
                output_root=output_root,
                mode=args.mode,
                security_mode=security_mode,
                domain_id=domain,
                seed=session_seed,
                duration_override=args.duration,
                jitter=args.jitter,
                adaptive=args.adaptive,
                catalog_path=str(args.catalog),
                capture_interface=args.capture_interface,
                ros_snapshots=args.ros_snapshots,
            )
        )
        print(
            f"✅ {generated[-1].name}: {scenario.scenario_id} "
            f"({args.mode}, {security_mode}, seed={session_seed})"
        )

    index_record = {
        "schema_version": "sros2-firewall-batch/v1",
        "created_utc": utc_now(),
        "mode": args.mode,
        "sessions": [path.name for path in generated],
    }
    atomic_write_json(
        output_root / f"batch_{time.time_ns()}.json",
        index_record,
    )
    print(f"輸出：{output_root}")
    if args.mode == "smoke":
        print("注意：smoke session 永久標記 training_eligible=false。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
