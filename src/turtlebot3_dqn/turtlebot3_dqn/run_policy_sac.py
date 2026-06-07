#!/usr/bin/env python3
"""SAC policy 部署 / 評估腳本（reviewer A6 修補）

兩個模式：
    1. deploy: 用 best.zip 部署在 Gazebo，無限循環巡邏
    2. eval  : 用固定 seed 跑 N episodes，回報 deterministic success rate

Usage:
    # 部署模式
    source ~/dqn_env/bin/activate
    source ~/ros2_ws/install/setup.bash
    python3 run_policy_sac.py --mode deploy

    # 評估模式（固定 seed，可重現）
    python3 run_policy_sac.py --mode eval --episodes 20 --seed 42

評估輸出：
    回報 success rate / collision rate / mean waypoints / mean ep length
    結果存到 logs_sac/eval_<timestamp>.csv，可後續 plot
"""
from __future__ import annotations

import argparse
import csv
import datetime
import sys
import time
from pathlib import Path

import numpy as np
import rclpy
from stable_baselines3 import SAC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from turtlebot3_dqn.burger_env import BurgerEnv


BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models_sac"
LOG_DIR   = BASE_DIR / "logs_sac"
BEST_PATH = MODEL_DIR / "sac_burger_best"
LATEST_PATH = MODEL_DIR / "sac_burger_latest"


def find_model() -> Path | None:
    """優先用 best，沒有就 latest。"""
    for p in (BEST_PATH, LATEST_PATH):
        zip_path = p.with_suffix(".zip")
        if zip_path.exists():
            return p
    return None


def verify_model_integrity(model_path: Path) -> bool:
    """攻擊 M 修補：載入前驗 HMAC 簽章。"""
    try:
        from dds_security_monitor.monitor_node import verify_file, _load_alert_secret
    except ImportError:
        print("⚠️  dds_security_monitor 未安裝，跳過完整性驗證")
        return True
    secret = _load_alert_secret(strict=False)
    if not secret:
        print("⚠️  alert_secret 未設定，跳過完整性驗證")
        return True
    zip_path = model_path.with_suffix(".zip")
    sig_path = zip_path.with_suffix(".zip.sha256.hmac")
    if not sig_path.exists():
        print(f"⚠️  {sig_path.name} 不存在（model 未簽章），允許 load 但不安全")
        return True
    if verify_file(zip_path, secret):
        print(f"✅ Model 完整性驗章通過: {zip_path.name}")
        return True
    print(f"❌ Model HMAC 驗章失敗！可能被竄改，拒絕 load: {zip_path}")
    return False


def run_eval(n_episodes: int, seed: int) -> dict:
    """跑 N episodes，固定 seed，回報統計。Reviewer A4 修補：deterministic eval。"""
    rclpy.init()
    raw_env = BurgerEnv()

    model_path = find_model()
    if not model_path:
        print("❌ 找不到模型（models_sac/sac_burger_best.zip 或 latest.zip）")
        return {}
    if not verify_model_integrity(model_path):
        sys.exit(2)

    model = SAC.load(str(model_path), env=raw_env)
    print(f"\n載入模型: {model_path.name}")
    print(f"裝置: {model.device}")
    print(f"評估 {n_episodes} episodes（seed={seed}, deterministic policy）\n")

    results = []
    for ep in range(n_episodes):
        # Reviewer A4 關鍵：每個 episode 用 seed + ep 確保 reproducible
        obs, _ = raw_env.reset(seed=seed + ep)
        ep_reward = 0.0
        ep_steps  = 0
        ep_wp     = 0
        terminated = False
        truncated  = False
        last_info  = {}

        while not (terminated or truncated):
            # Reviewer A4: 用 deterministic action（停用 stochastic policy）
            action, _ = model.predict(obs, deterministic=True)
            obs, reward, terminated, truncated, info = raw_env.step(action)
            ep_reward += reward
            ep_steps += 1
            last_info = info

        ep_wp = last_info.get("waypoints_done", 0)
        event = last_info.get("event", "?")
        success = bool(last_info.get("is_full_success", False))
        collided = bool(last_info.get("is_collision", False))

        results.append({
            "episode": ep,
            "reward":  round(ep_reward, 2),
            "steps":   ep_steps,
            "wp":      ep_wp,
            "event":   event,
            "success": int(success),
            "collision": int(collided),
        })
        print(f"  Ep {ep+1:3d}/{n_episodes}  "
              f"reward={ep_reward:7.1f}  steps={ep_steps:4d}  "
              f"wp={ep_wp}/5  event={event}")

    raw_env.close()
    raw_env.destroy_node()
    rclpy.shutdown()

    # 統計
    n = len(results)
    summary = {
        "n_episodes":        n,
        "seed":              seed,
        "success_rate":      sum(r["success"]   for r in results) / n,
        "collision_rate":    sum(r["collision"] for r in results) / n,
        "mean_reward":       float(np.mean([r["reward"] for r in results])),
        "std_reward":        float(np.std ([r["reward"] for r in results])),
        "mean_waypoints":    float(np.mean([r["wp"]     for r in results])),
        "mean_episode_len":  float(np.mean([r["steps"]  for r in results])),
        "model":             model_path.name,
    }
    return {"summary": summary, "episodes": results}


def run_deploy():
    """部署模式：載入 model 並無限循環 — 用於展示。"""
    rclpy.init()
    raw_env = BurgerEnv()

    model_path = find_model()
    if not model_path:
        print("❌ 找不到模型")
        return
    if not verify_model_integrity(model_path):
        sys.exit(2)

    model = SAC.load(str(model_path), env=raw_env)
    print(f"\n載入模型: {model_path.name}  (部署模式 / Ctrl+C 結束)\n")

    ep = 0
    try:
        while True:
            ep += 1
            obs, _ = raw_env.reset()
            done = False
            ep_steps = 0
            while not done:
                action, _ = model.predict(obs, deterministic=True)
                obs, reward, terminated, truncated, info = raw_env.step(action)
                ep_steps += 1
                done = terminated or truncated
            event = info.get("event", "?")
            wp = info.get("waypoints_done", 0)
            print(f"  Ep {ep}  steps={ep_steps}  wp={wp}/5  event={event}")
    except KeyboardInterrupt:
        print("\n中斷")
    finally:
        raw_env.close()
        raw_env.destroy_node()
        rclpy.shutdown()


def save_eval_csv(result: dict):
    """把 eval 結果寫成 CSV 給 reviewer 看（A6 修補 — 實驗報告）。"""
    if not result:
        return
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = LOG_DIR / f"eval_{ts}.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["episode", "reward", "steps", "waypoints", "event", "success", "collision"])
        for r in result["episodes"]:
            writer.writerow([r["episode"], r["reward"], r["steps"], r["wp"],
                            r["event"], r["success"], r["collision"]])
    print(f"\n結果已存: {csv_path}")
    s = result["summary"]
    print(f"\n══════ Summary ({s['n_episodes']} eps, seed={s['seed']}) ══════")
    print(f"  Success rate:    {s['success_rate']*100:5.1f}%")
    print(f"  Collision rate:  {s['collision_rate']*100:5.1f}%")
    print(f"  Mean reward:     {s['mean_reward']:.2f} ± {s['std_reward']:.2f}")
    print(f"  Mean waypoints:  {s['mean_waypoints']:.2f} / 5")
    print(f"  Mean ep length:  {s['mean_episode_len']:.1f} steps")


def main():
    parser = argparse.ArgumentParser(description="SAC policy 部署 / 評估")
    parser.add_argument("--mode", choices=["deploy", "eval"], default="eval")
    parser.add_argument("--episodes", type=int, default=20,
                        help="eval mode: 跑幾個 episode（建議 20+ 才有統計意義）")
    parser.add_argument("--seed", type=int, default=42,
                        help="eval mode: deterministic seed（reviewer 要求可重現）")
    args = parser.parse_args()

    if args.mode == "eval":
        result = run_eval(args.episodes, args.seed)
        save_eval_csv(result)
    else:
        run_deploy()


if __name__ == "__main__":
    main()
