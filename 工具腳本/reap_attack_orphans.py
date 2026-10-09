# -*- coding: utf-8 -*-
"""收掉攻擊端的孤兒行程，而**不打斷進行中的攻擊**。

## 為什麼

2026-10-09 量到 `unauthorized_participant` 的 runner（`ros2 run demo_nodes_cpp
talker`）每場留下 4–8 個孤兒，而它們累積會拖慢每一場：場次內部中位
83s → 117s（兩小時），先前一輪更到 337s 而讓步調熔斷器自停。

監督器的兜底清除（`STACK_PATTERNS`）是對的，但它在 `stack_down` 跑，而**一批
要將近兩小時**——批次內的累積有兩小時可以拖慢步調。修在批次邊界太晚。

## 判準：為什麼這樣殺是安全的

orchestrator 在 `Popen()` 旁把絕對期限交給攻擊行程（C2C-074 的
`ATTACK_DEADLINE_ENV`），用 `CLOCK_MONOTONIC`——那是**每個行程一致**的時鐘。
所以：

    deadline 在未來  ⇒ 那一場還在跑   ⇒ 殺它會破壞那一場的攻擊，不可以
    deadline 已過期  ⇒ 那一場結束了   ⇒ 孤兒

實測 24/24 的 talker 都帶那個變數，而且 24 個全部過期（最老超過期限 54 分鐘）。

**fail-closed**：讀不到那個變數的行程**一律不殺**。寧可漏殺也不要誤殺——
那與監督器 `STACK_PATTERNS` 的註解是同一條原則。寬限期預設 120 秒，
讓場次自己的收尾有時間跑完。
"""

from __future__ import annotations

import argparse
import os
import pathlib
import signal
import sys
import time

DEADLINE_ENV = "SROS2_ATTACK_DEADLINE_MONOTONIC"
# 只收這些名字。與監督器的註解同一條原則：只列夠特定的，寧可漏殺。
ATTACK_COMMS = frozenset({"talker"})


def _environ_of(pid: str) -> dict[str, str]:
    raw = pathlib.Path("/proc", pid, "environ").read_bytes()
    out: dict[str, str] = {}
    for item in raw.decode("utf-8", "replace").split("\0"):
        if "=" in item:
            key, value = item.split("=", 1)
            out[key] = value
    return out


def find_orphans(grace_sec: float, now: float | None = None) -> list[dict]:
    """回傳期限已過 `grace_sec` 的攻擊行程。

    不殺任何讀不到 `DEADLINE_ENV` 的行程——那包含使用者自己起的 talker。
    """
    if now is None:
        now = time.clock_gettime(time.CLOCK_MONOTONIC)
    uid = os.getuid()
    found: list[dict] = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() not in ATTACK_COMMS:
                continue
            if entry.stat().st_uid != uid:
                continue
            env = _environ_of(entry.name)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue
        raw = env.get(DEADLINE_ENV)
        if raw is None:
            continue  # fail-closed：不是 campaign 起的，不碰
        try:
            deadline = float(raw)
        except ValueError:
            continue
        overdue = now - deadline
        if overdue > grace_sec:
            found.append(
                {"pid": int(entry.name), "overdue_sec": overdue,
                 "domain": env.get("ROS_DOMAIN_ID")}
            )
    return found


def reap(grace_sec: float, dry_run: bool) -> int:
    orphans = find_orphans(grace_sec)
    if not orphans:
        return 0
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    worst = max(o["overdue_sec"] for o in orphans)
    verb = "會收" if dry_run else "收掉"
    print(
        f"{stamp} {verb} {len(orphans)} 個攻擊孤兒"
        f"（最久超過期限 {worst / 60:.1f} 分，domain "
        f"{sorted({o['domain'] for o in orphans})}）",
        flush=True,
    )
    if dry_run:
        return 0
    for sig in (signal.SIGTERM, signal.SIGKILL):
        alive = [o for o in orphans if pathlib.Path("/proc", str(o["pid"])).exists()]
        if not alive:
            break
        for item in alive:
            try:
                os.kill(item["pid"], sig)
            except (ProcessLookupError, PermissionError):
                pass
        time.sleep(3 if sig is signal.SIGTERM else 1)
    left = sum(1 for o in orphans if pathlib.Path("/proc", str(o["pid"])).exists())
    if left:
        print(f"  ⚠️ 還剩 {left} 個沒收掉", flush=True)
    return len(orphans) - left


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grace-sec", type=float, default=120.0,
                        help="期限過了多久才算孤兒（預設 120 秒）")
    parser.add_argument("--loop", action="store_true",
                        help="持續執行；用 setsid 起在背景")
    parser.add_argument("--interval-sec", type=float, default=300.0,
                        help="--loop 的間隔（預設 300 秒）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只報告不殺")
    args = parser.parse_args(argv)
    if args.grace_sec < 30.0:
        parser.error("寬限期不可小於 30 秒——場次自己的收尾需要時間")
    if not args.loop:
        reap(args.grace_sec, args.dry_run)
        return 0
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"=== reaper 啟動 {stamp}  寬限 {args.grace_sec}s"
          f"  間隔 {args.interval_sec}s ===", flush=True)
    while True:
        try:
            reap(args.grace_sec, args.dry_run)
        except Exception as exc:  # 清理失敗不可以讓迴圈停掉
            print(f"  ⚠️ 這一輪失敗（繼續）：{exc!r}", flush=True)
        time.sleep(args.interval_sec)


if __name__ == "__main__":
    sys.exit(main())
