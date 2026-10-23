#!/usr/bin/env python3
"""比對一台遠端機器上的部署副本與 repo 的版本——**比對摘要，不是比對存在性**。

## 為什麼需要這一支

2026-10-07 的跨主機鏈第一次執行時，跑到第 8 項才炸：

    AttributeError: 'ResponseBackend' object has no attribute 'revoke_source'

樹莓派上帶的是 2026-09-24 的 `response_backend.py`，而 `revoke_source` 是
2026-09-25 加的——正好就是那條鏈的撤銷那一半。我在佈建前盤點過那台機器，
但那次盤點問的是「檔案在不在」，而三個相關模組**都在**。

> **存在性是一個幾乎永遠成立的檢查。** 它在這裡回答了「有」，
> 而正確的答案是「有，但是舊的」。

這與本專案記過的那一類缺陷同形狀（C2C-092 的 `packet_windows*` glob 配到
目錄、C2C-098 的 `manifest["adaptive"]` 查一個不存在的鍵回傳令人安心的答案）：
**一個不可能失敗的檢查不是證據。**

## 它刻意不做的事

- **不自動同步。** 它只回報。遠端的檔案有可能是刻意改過的（除錯、臨時修補），
  而靜默覆蓋會把那種修改連同它的理由一起抹掉。要不要同步是一個決定，
  不是這支工具的預設行為。
- **不走 repo 以外的路徑。** 清單裡的每一項都必須是 repo 相對路徑，
  而且必須存在於本機——拿一個本機也沒有的檔案去比對遠端沒有意義。

## fail-closed

`ssh` 失敗、`sha256sum` 沒有輸出、或任何一項算不出摘要，都以非零退出。
**「我連不上所以看起來一致」是這支工具最該避免的輸出。**

## 用法

    python3 工具腳本/check_remote_deployment.py \\
        --remote jesse@192.168.0.145 --remote-root /home/jesse/sros2 \\
        --ssh-key ~/.ssh/id_ed25519_pi \\
        --path firewall_lab/response_backend.py \\
        --path 工具腳本/run_attribution_driven_block.py

或把清單放進 JSON（`{"paths": [...]}`）用 `--manifest`。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

EXIT_OK = 0
EXIT_DRIFT = 1          # 有檔案不一致或缺席——這是這支工具存在的理由
EXIT_UNUSABLE = 2       # 參數、本機檔案或連線的問題，**不可讀成一致**

_SHA256_LEN = 64


@dataclass(frozen=True)
class Finding:
    path: str
    verdict: str          # match | mismatch | missing | unreadable
    local_sha: str
    remote_sha: str | None

    @property
    def ok(self) -> bool:
        return self.verdict == "match"


def local_digest(repo_root: Path, rel: str) -> str:
    target = (repo_root / rel).resolve()
    try:
        target.relative_to(repo_root.resolve())
    except ValueError:
        raise SystemExit(f"⛔ 路徑逃出 repo：{rel}")
    if not target.is_file():
        raise SystemExit(f"⛔ 本機沒有這個檔案，無從比對：{rel}")
    return hashlib.sha256(target.read_bytes()).hexdigest()


def default_runner(remote: str, ssh_key: str | None, command: str) -> str:
    """跑一個遠端命令並回傳 stdout；失敗就讓呼叫端 fail-closed。"""
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if ssh_key:
        argv += ["-i", ssh_key]
    argv += [remote, command]
    # ⚠️ encoding 必須明寫 utf-8。`text=True` 單獨使用時會拿
    # `locale.getpreferredencoding()` 去解碼,而在 Windows 上那是 cp950／cp1252——
    # 遠端回傳的是 UTF-8 檔名,於是中文路徑被解成亂碼,前綴比對失敗,
    # 一個**存在**的檔案就被回報成「遠端沒有這個檔案」。
    # 2026-10-07 實測:firewall_lab/*.py（ASCII）全部正確,工具腳本/*.py（中文）
    # 五個全部誤報缺席,而它們正是那條鏈剛剛用過的檔案。
    proc = subprocess.run(argv, capture_output=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise SystemExit(
            f"⛔ 遠端命令失敗（rc={proc.returncode}）。**不可把這讀成一致。**\n"
            f"   {proc.stderr.strip()[:300]}"
        )
    return proc.stdout


def remote_digests(paths: list[str], remote_root: str, *, runner) -> dict[str, str | None]:
    """一次問完所有檔案的摘要。

    刻意用一個命令而不是每個檔案一次 ssh：N 次連線在慢網路上會很久，
    而且中途斷線會讓一部分檔案「看起來沒問題」。
    """
    quoted = " ".join(shlex.quote(f"{remote_root}/{p}") for p in paths)
    out = runner(f"sha256sum {quoted} 2>/dev/null || true")

    by_path: dict[str, str | None] = {p: None for p in paths}
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, full = parts[0].strip(), parts[1].strip()
        if len(digest) != _SHA256_LEN:
            continue
        prefix = remote_root.rstrip("/") + "/"
        if full.startswith(prefix):
            rel = full[len(prefix):]
            if rel in by_path:
                by_path[rel] = digest
    return by_path


def compare(repo_root: Path, paths: list[str], remote_root: str, *, runner) -> list[Finding]:
    local = {p: local_digest(repo_root, p) for p in paths}
    remote = remote_digests(paths, remote_root, runner=runner)
    findings = []
    for p in paths:
        r = remote.get(p)
        if r is None:
            verdict = "missing"
        elif r == local[p]:
            verdict = "match"
        else:
            verdict = "mismatch"
        findings.append(Finding(p, verdict, local[p], r))
    return findings


def render(findings: list[Finding]) -> str:
    lines = []
    for f in findings:
        mark = {"match": "✅", "mismatch": "⛔", "missing": "⛔", "unreadable": "⛔"}[f.verdict]
        if f.verdict == "match":
            lines.append(f"  {mark} {f.path}  {f.local_sha[:16]}")
        elif f.verdict == "missing":
            lines.append(f"  {mark} {f.path}  遠端沒有這個檔案")
        else:
            lines.append(
                f"  {mark} {f.path}\n"
                f"       本機 {f.local_sha[:16]}\n"
                f"       遠端 {(f.remote_sha or '')[:16]}  ← 版本不同"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--remote", required=True, help="user@host（IPv6 link-local 要帶 %%iface）")
    parser.add_argument("--remote-root", required=True, help="遠端那份 checkout 的根目錄")
    parser.add_argument("--ssh-key", default=None)
    parser.add_argument("--repo-root", default=".", type=Path)
    parser.add_argument("--path", action="append", default=[], dest="paths")
    parser.add_argument("--manifest", type=Path, default=None,
                        help='JSON：{"paths": ["firewall_lab/x.py", ...]}')
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    paths = list(args.paths)
    if args.manifest:
        data = json.loads(args.manifest.read_text(encoding="utf-8"))
        paths += list(data.get("paths") or [])
    if not paths:
        print("⛔ 沒有要比對的檔案：請給 --path 或 --manifest", file=sys.stderr)
        return EXIT_UNUSABLE

    repo_root = args.repo_root.resolve()
    runner = lambda cmd: default_runner(args.remote, args.ssh_key, cmd)

    findings = compare(repo_root, paths, args.remote_root, runner=runner)

    print(f"=== 部署版本比對：{args.remote}:{args.remote_root} ===")
    print(render(findings))
    bad = [f for f in findings if not f.ok]
    print(f"\n  一致 {len(findings) - len(bad)}／{len(findings)}")

    if args.output:
        args.output.write_text(json.dumps({
            "schema": "sros2-firewall-remote-deployment-check/v1",
            "remote": args.remote,
            "remote_root": args.remote_root,
            "all_match": not bad,
            "findings": [
                {"path": f.path, "verdict": f.verdict,
                 "local_sha256": f.local_sha, "remote_sha256": f.remote_sha}
                for f in findings
            ],
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"  → {args.output}")

    if bad:
        print("\n⛔ 遠端的部署與 repo 不一致。**不要假設功能可用**——"
              "2026-10-07 就是因為一個舊版模組缺了 revoke_source，"
              "整條鏈跑到第 8 項才炸。")
        return EXIT_DRIFT
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
