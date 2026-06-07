#!/usr/bin/env python3
"""
Deterministic evaluation of a trained TQC policy.

Runs N fixed-seed episodes against BurgerEnvTop(eval_mode=True) and reports:
    - Success rate (all waypoints reached)
    - SPL — Habitat-style success-weighted path length
    - Collision rate
    - Timeout rate
    - Mean min clearance
    - Mean completion steps
    - 95% bootstrap CIs (B=1000)

This is the metric you cite in the report / poster. Do NOT report
rolling training stats as "final results".

Usage:
    python3 eval_top.py [--model PATH] [--episodes 50] [--max-wp 5] [--seed-base 0]
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import numpy as np
import rclpy
from sb3_contrib import TQC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from turtlebot3_dqn.burger_env_top import BurgerEnvTop, N_WP_TOTAL
from turtlebot3_dqn.feature_extractors import LiDARConvExtractor  # noqa: F401  (needed for unpickle)

try:
    from dds_security_monitor.monitor_node import verify_file, _load_alert_secret
    _SEC_AVAILABLE = True
except Exception:
    _SEC_AVAILABLE = False
    def verify_file(_p, _s): return False
    def _load_alert_secret(): return b""


def bootstrap_ci(arr, B: int = 1000, lo: float = 2.5, hi: float = 97.5, seed: int = 0):
    arr = np.asarray(arr, dtype=np.float64)
    if len(arr) == 0:
        return 0.0, 0.0
    rng = np.random.default_rng(seed)
    n = len(arr)
    samples = rng.choice(arr, size=(B, n), replace=True).mean(axis=1)
    return float(np.percentile(samples, lo)), float(np.percentile(samples, hi))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model",
                   default=str(Path(__file__).parent / "runs_top/models/tqc_best"))
    p.add_argument("--episodes", type=int, default=50)
    p.add_argument("--max-wp",   type=int, default=N_WP_TOTAL)
    p.add_argument("--seed-base", type=int, default=0)
    args = p.parse_args()

    rclpy.init()

    # ── Integrity check before loading model (refuse tampered) ────────
    model_zip = Path(args.model).with_suffix(".zip")
    if _SEC_AVAILABLE:
        secret = _load_alert_secret()
        fp = hashlib.sha256(secret).hexdigest()[:8] if secret else "(none)"
        print(f"🔐 HMAC fingerprint sha256:{fp}")
        sig = model_zip.with_suffix(".zip.sha256.hmac")
        if sig.exists() and secret:
            if verify_file(model_zip, secret):
                print(f"  ✓ Model HMAC verified")
            else:
                print(f"  ✗ MODEL HMAC FAILED — refusing to eval tampered model")
                rclpy.shutdown()
                sys.exit(2)
        else:
            print(f"  ⚠️  no signature on model — proceeding without verification")

    env = BurgerEnvTop(eval_mode=True, curriculum_max_wp=args.max_wp)
    model = TQC.load(args.model, env=None)
    print(f"▶ Loaded model: {args.model}")
    print(f"  Episodes: {args.episodes}   max_wp: {args.max_wp}   seed base: {args.seed_base}\n")

    results: list[dict] = []
    for i in range(args.episodes):
        seed = args.seed_base + i
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
            "ep":        i,
            "seed":      seed,
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
        print(f"  ep{i:02d} seed={seed:3d}  {flag}  spl={results[-1]['spl']:.3f}  "
              f"wp={results[-1]['wp_done']}/{args.max_wp}  steps={steps}  r={ep_r:+.1f}")

    spl   = [r["spl"]       for r in results]
    succ  = [r["success"]   for r in results]
    coll  = [r["collision"] for r in results]
    to    = [r["timeout"]   for r in results]
    steps = [r["steps"]     for r in results]
    wps   = [r["wp_done"]   for r in results]
    clrs  = [r["clearance"] for r in results if np.isfinite(r["clearance"])]

    spl_lo, spl_hi = bootstrap_ci(spl)
    sr_lo,  sr_hi  = bootstrap_ci(succ)
    co_lo,  co_hi  = bootstrap_ci(coll)

    print("\n" + "=" * 64)
    print(f"  EVAL REPORT — {len(results)} episodes @ max_wp={args.max_wp}")
    print("=" * 64)
    print(f"  SPL              : {np.mean(spl):.3f}     [95% CI {spl_lo:.3f}, {spl_hi:.3f}]")
    print(f"  Success rate     : {100*np.mean(succ):5.1f} %   [95% CI {100*sr_lo:5.1f}, {100*sr_hi:5.1f}]")
    print(f"  Collision rate   : {100*np.mean(coll):5.1f} %   [95% CI {100*co_lo:5.1f}, {100*co_hi:5.1f}]")
    print(f"  Timeout rate     : {100*np.mean(to):5.1f} %")
    print(f"  Mean steps       : {np.mean(steps):.1f}")
    print(f"  Mean waypoints   : {np.mean(wps):.2f} / {args.max_wp}")
    print(f"  Mean clearance   : {np.mean(clrs):.3f} m" if clrs else "  Mean clearance   : n/a")
    print("=" * 64)

    out_csv = Path(args.model).parent / f"eval_{Path(args.model).stem}_n{len(results)}.csv"
    with out_csv.open("w") as f:
        f.write("ep,seed,reward,steps,spl,success,collision,timeout,wp_done,clearance\n")
        for r in results:
            f.write(f"{r['ep']},{r['seed']},{r['reward']:.3f},{r['steps']},"
                    f"{r['spl']:.4f},{r['success']},{r['collision']},{r['timeout']},"
                    f"{r['wp_done']},{r['clearance']:.4f}\n")
    print(f"\n  Per-episode CSV → {out_csv}")

    env.close()
    rclpy.shutdown()


if __name__ == "__main__":
    main()
