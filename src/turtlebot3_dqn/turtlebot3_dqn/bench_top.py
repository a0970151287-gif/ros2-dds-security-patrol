#!/usr/bin/env python3
"""
Multi-tier TQC benchmark suite.

Runs deterministic eval across difficulty tiers (easy/medium/hard waypoint
counts) on one or more model checkpoints, then writes:

    bench/leaderboard.json           — appended entry per run, cross-model history
    bench/<model_stem>.csv           — per-episode raw data
    bench/<model_stem>_radar.png     — radar chart of normalized metrics

Why a separate tool from eval_top.py:
    eval_top.py answers "how good is this one model at one difficulty".
    bench_top.py answers "how does this model compare across difficulties,
    and against past models on my leaderboard". This is the artifact you
    show in POC slides and paper tables.

Usage:
    python3 bench_top.py --models runs_top/models/tqc_latest
    python3 bench_top.py --models A.zip B.zip --episodes-per-tier 20
    python3 bench_top.py --models tqc_latest --tiers easy,hard --no-viz
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import rclpy
from sb3_contrib import TQC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from turtlebot3_dqn.burger_env_top import BurgerEnvTop, N_WP_TOTAL
from turtlebot3_dqn.eval_top import bootstrap_ci
from turtlebot3_dqn.feature_extractors import LiDARConvExtractor  # noqa: F401

try:
    from dds_security_monitor.monitor_node import verify_file, _load_alert_secret
    _SEC_AVAILABLE = True
except Exception:
    _SEC_AVAILABLE = False
    def verify_file(_p, _s): return False
    def _load_alert_secret(): return b""


@dataclass(frozen=True)
class Tier:
    name: str
    max_wp: int
    seed_offset: int  # disjoint seed ranges per tier → no scenario reuse


TIERS = {
    "easy":   Tier("easy",   max_wp=1,            seed_offset=0),
    "medium": Tier("medium", max_wp=3,            seed_offset=10_000),
    "hard":   Tier("hard",   max_wp=N_WP_TOTAL,   seed_offset=20_000),
}


def _verify_model(model_zip: Path, strict: bool) -> None:
    if not _SEC_AVAILABLE:
        return
    secret = _load_alert_secret()
    sig = model_zip.with_suffix(".zip.sha256.hmac")
    if not (sig.exists() and secret):
        print(f"  ⚠️  no HMAC signature on {model_zip.name} — proceeding")
        return
    if verify_file(model_zip, secret):
        print(f"  ✓ HMAC verified: {model_zip.name}")
        return
    msg = f"✗ HMAC FAILED for {model_zip.name}"
    if strict:
        print(msg + " — refusing (strict mode)")
        sys.exit(2)
    print(msg + " — continuing (non-strict)")


def run_tier(env: BurgerEnvTop, model: TQC, tier: Tier, n_episodes: int,
             seed_base: int) -> list[dict]:
    env.set_curriculum_max_wp(tier.max_wp)
    results: list[dict] = []
    for i in range(n_episodes):
        seed = seed_base + tier.seed_offset + i
        obs, _ = env.reset(seed=seed)
        terminated = truncated = False
        ep_r = 0.0
        steps = 0
        last_info: dict = {}
        while not (terminated or truncated):
            action, _ = model.predict(obs, deterministic=True)
            obs, r, terminated, truncated, info = env.step(action)
            ep_r += float(r)
            steps += 1
            last_info = info
        results.append({
            "tier":      tier.name,
            "ep":        i,
            "seed":      seed,
            "max_wp":    tier.max_wp,
            "reward":    ep_r,
            "steps":     steps,
            "spl":       float(last_info.get("spl", 0.0)),
            "success":   int(bool(last_info.get("is_full_success", False))),
            "collision": int(bool(last_info.get("is_collision", False))),
            "timeout":   int(bool(last_info.get("is_timeout", False))),
            "wp_done":   int(last_info.get("waypoints_done", 0)),
            "clearance": float(last_info.get("min_clearance", float("inf"))),
        })
        flag = "✓" if results[-1]["success"] else ("✗" if results[-1]["collision"] else "·")
        print(f"    [{tier.name:6}] ep{i:02d} seed={seed:5d} {flag} "
              f"spl={results[-1]['spl']:.3f} wp={results[-1]['wp_done']}/{tier.max_wp} "
              f"r={ep_r:+.1f}")
    return results


def summarize(results: list[dict]) -> dict:
    spl   = np.array([r["spl"]       for r in results], dtype=np.float64)
    succ  = np.array([r["success"]   for r in results], dtype=np.float64)
    coll  = np.array([r["collision"] for r in results], dtype=np.float64)
    to    = np.array([r["timeout"]   for r in results], dtype=np.float64)
    steps = np.array([r["steps"]     for r in results], dtype=np.float64)
    wps   = np.array([r["wp_done"]   for r in results], dtype=np.float64)
    clrs  = np.array([r["clearance"] for r in results
                      if np.isfinite(r["clearance"])], dtype=np.float64)

    spl_lo, spl_hi = bootstrap_ci(spl)
    sr_lo,  sr_hi  = bootstrap_ci(succ)
    co_lo,  co_hi  = bootstrap_ci(coll)

    return {
        "n":              len(results),
        "spl_mean":       float(spl.mean()),
        "spl_ci":         [spl_lo, spl_hi],
        "success_rate":   float(succ.mean()),
        "success_ci":     [sr_lo, sr_hi],
        "collision_rate": float(coll.mean()),
        "collision_ci":   [co_lo, co_hi],
        "timeout_rate":   float(to.mean()),
        "mean_steps":     float(steps.mean()),
        "mean_waypoints": float(wps.mean()),
        "mean_clearance": float(clrs.mean()) if len(clrs) else 0.0,
    }


def print_tier_summary(model_name: str, tier: Tier, s: dict) -> None:
    print(f"\n  ── {model_name} @ {tier.name} (max_wp={tier.max_wp}, n={s['n']}) ──")
    print(f"    SPL            {s['spl_mean']:.3f}  [95% CI {s['spl_ci'][0]:.3f}, {s['spl_ci'][1]:.3f}]")
    print(f"    Success        {100*s['success_rate']:5.1f}%  [95% CI {100*s['success_ci'][0]:5.1f}, {100*s['success_ci'][1]:5.1f}]")
    print(f"    Collision      {100*s['collision_rate']:5.1f}%  [95% CI {100*s['collision_ci'][0]:5.1f}, {100*s['collision_ci'][1]:5.1f}]")
    print(f"    Timeout        {100*s['timeout_rate']:5.1f}%")
    print(f"    Mean steps     {s['mean_steps']:.1f}")
    print(f"    Mean clearance {s['mean_clearance']:.3f} m")


def radar_plot(model_stem: str, tier_summaries: dict[str, dict], out_png: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")  # headless — WSL/CI has no display
    import matplotlib.pyplot as plt

    axes = ["SPL", "Success", "Safe", "On-Time", "Clearance"]
    angles = np.linspace(0, 2 * np.pi, len(axes), endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
    for tier_name, s in tier_summaries.items():
        vals = [
            s["spl_mean"],
            s["success_rate"],
            1.0 - s["collision_rate"],
            1.0 - s["timeout_rate"],
            min(s["mean_clearance"] / 1.0, 1.0),  # normalize to [0,1] over 1 m
        ]
        vals += vals[:1]
        ax.plot(angles, vals, linewidth=2, label=f"{tier_name} (n={s['n']})")
        ax.fill(angles, vals, alpha=0.10)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(axes)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0.25", "0.50", "0.75", "1.00"], fontsize=8)
    ax.set_title(f"TQC Benchmark — {model_stem}", pad=18)
    ax.legend(loc="lower right", bbox_to_anchor=(1.25, -0.05), fontsize=9)
    plt.tight_layout()
    fig.savefig(out_png, dpi=140, bbox_inches="tight")
    plt.close(fig)
    print(f"  📊 Radar → {out_png}")


def append_leaderboard(leaderboard: Path, entry: dict) -> None:
    """Atomically append entry. JSON-list format for easy pandas/jq ingest."""
    if leaderboard.exists():
        try:
            history = json.loads(leaderboard.read_text())
            if not isinstance(history, list):
                history = []
        except json.JSONDecodeError:
            print(f"  ⚠️  leaderboard corrupted, starting fresh")
            history = []
    else:
        history = []
    history.append(entry)
    tmp = leaderboard.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(history, indent=2, ensure_ascii=False))
    tmp.replace(leaderboard)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--models", nargs="+", required=True,
                   help="One or more model paths (with or without .zip)")
    p.add_argument("--tiers", default="easy,medium,hard",
                   help="Comma-separated tier names")
    p.add_argument("--episodes-per-tier", type=int, default=30)
    p.add_argument("--seed-base", type=int, default=0)
    p.add_argument("--out-dir",
                   default=str(Path(__file__).parent / "runs_top/bench"))
    p.add_argument("--no-viz", action="store_true")
    p.add_argument("--strict-hmac", action="store_true",
                   help="Refuse to run on models with bad/missing HMAC")
    args = p.parse_args()

    tier_names = [t.strip() for t in args.tiers.split(",") if t.strip()]
    for t in tier_names:
        if t not in TIERS:
            sys.exit(f"unknown tier '{t}' (valid: {list(TIERS)})")
    selected_tiers = [TIERS[t] for t in tier_names]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    leaderboard = out_dir / "leaderboard.json"

    rclpy.init()
    env = BurgerEnvTop(eval_mode=True, curriculum_max_wp=N_WP_TOTAL)

    try:
        for model_path in args.models:
            mp = Path(model_path)
            model_zip = mp if mp.suffix == ".zip" else mp.with_suffix(".zip")
            if not model_zip.exists():
                print(f"⚠️  skip {model_zip} — not found")
                continue

            print(f"\n{'='*72}\n▶ Benchmarking {model_zip.name}\n{'='*72}")
            _verify_model(model_zip, args.strict_hmac)
            model = TQC.load(str(model_zip.with_suffix("")), env=None)

            all_rows: list[dict] = []
            tier_summaries: dict[str, dict] = {}
            for tier in selected_tiers:
                print(f"\n  ▷ Tier '{tier.name}'  (max_wp={tier.max_wp}, "
                      f"n={args.episodes_per_tier})")
                rows = run_tier(env, model, tier, args.episodes_per_tier,
                                args.seed_base)
                all_rows.extend(rows)
                tier_summaries[tier.name] = summarize(rows)
                print_tier_summary(model_zip.stem, tier, tier_summaries[tier.name])

            # CSV
            csv_path = out_dir / f"{model_zip.stem}.csv"
            with csv_path.open("w") as f:
                f.write("tier,ep,seed,max_wp,reward,steps,spl,success,"
                        "collision,timeout,wp_done,clearance\n")
                for r in all_rows:
                    f.write(f"{r['tier']},{r['ep']},{r['seed']},{r['max_wp']},"
                            f"{r['reward']:.3f},{r['steps']},{r['spl']:.4f},"
                            f"{r['success']},{r['collision']},{r['timeout']},"
                            f"{r['wp_done']},{r['clearance']:.4f}\n")
            print(f"\n  💾 CSV → {csv_path}")

            # Leaderboard
            sha = hashlib.sha256(model_zip.read_bytes()).hexdigest()[:12]
            entry = {
                "timestamp_utc":     dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "model_path":        str(model_zip),
                "model_sha256_12":   sha,
                "episodes_per_tier": args.episodes_per_tier,
                "seed_base":         args.seed_base,
                "tiers":             tier_summaries,
            }
            append_leaderboard(leaderboard, entry)
            print(f"  🏆 Leaderboard → {leaderboard}")

            # Viz
            if not args.no_viz:
                radar_plot(model_zip.stem, tier_summaries,
                           out_dir / f"{model_zip.stem}_radar.png")

    finally:
        env.close()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
