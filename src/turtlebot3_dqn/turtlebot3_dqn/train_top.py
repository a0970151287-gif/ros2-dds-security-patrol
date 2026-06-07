#!/usr/bin/env python3
"""
Tier-1 TQC training launcher.

    Algorithm        : Truncated Quantile Critics (sb3-contrib)
    Policy / Critic  : LiDARConvExtractor + 256x256 MLP w/ LayerNorm
    Reward           : potential-based shaping + smooth + sparse
    Sampling         : domain randomization + 5% adversarial events
    Curriculum       : 1 → 5 waypoints, success ≥ 0.7 → promote
    Best model       : saved by rolling SPL (top stage only)
    Eval (separate)  : run eval_top.py against tqc_best.zip

Usage:
    source ~/dqn_env/bin/activate
    source ~/ros2_ws/install/setup.bash
    python3 train_top.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import hashlib
import rclpy
from sb3_contrib import TQC
from stable_baselines3.common.callbacks import CallbackList, CheckpointCallback
from stable_baselines3.common.monitor import Monitor

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from turtlebot3_dqn.burger_env_top import BurgerEnvTop, N_WP_TOTAL
from turtlebot3_dqn.feature_extractors import LiDARConvExtractor
from turtlebot3_dqn.scoreboard_top_callback import ScoreboardTopCallback

# ── Security: file integrity (model + replay buffer) ─────────────────────
# fail-safe: if dds_security_monitor isn't installed, training still runs
# but integrity protection is off (banner makes this explicit).
try:
    from dds_security_monitor.monitor_node import (
        sign_file, verify_file, _load_alert_secret,
    )
    _SEC_AVAILABLE = True
except Exception:
    _SEC_AVAILABLE = False
    def sign_file(_p, _s): return ""
    def verify_file(_p, _s): return False
    def _load_alert_secret(): return b""


def _secret_fingerprint(secret: bytes) -> str:
    """Short HMAC-key fingerprint for boot-time consistency check.

    Why: if DDS_ALERT_SECRET env / ~/.config/dds-monitor/alert_secret is
    missing, monitor_node._load_alert_secret() falls back to per-process
    random bytes — meaning every node sees a *different* key and HMAC
    verify silently fails everywhere. Printing the fingerprint lets a
    human compare across nodes and catch this silent-DoS state.
    """
    if not secret:
        return "(none)"
    return hashlib.sha256(secret).hexdigest()[:8]


BASE      = Path(__file__).resolve().parent
RUN_DIR   = BASE / "runs_top"
MODEL_DIR = RUN_DIR / "models"
LOG_DIR   = RUN_DIR / "logs"
TB_DIR    = LOG_DIR / "tensorboard"
CKPT_DIR  = MODEL_DIR / "checkpoints"
LATEST    = MODEL_DIR / "tqc_latest"
BEST      = MODEL_DIR / "tqc_best"
BUFFER    = MODEL_DIR / "tqc_buffer.pkl"

for d in (MODEL_DIR, LOG_DIR, TB_DIR, CKPT_DIR):
    d.mkdir(parents=True, exist_ok=True)


TOTAL_STEPS     = 2_000_000   # safety upper bound; expect plateau ~1.0-1.5M
CHECKPOINT_FREQ = 25_000      # Ctrl+C anytime — best.zip is preserved

TQC_CFG = dict(
    policy            = "MlpPolicy",
    device            = "auto",
    learning_rate     = 3e-4,
    buffer_size       = 500_000,
    batch_size        = 256,
    tau               = 0.005,
    gamma             = 0.99,
    learning_starts   = 5_000,
    train_freq        = 1,
    gradient_steps    = 1,
    ent_coef          = "auto",
    target_entropy    = "auto",
    top_quantiles_to_drop_per_net = 2,
    policy_kwargs     = dict(
        net_arch = [256, 256],
        features_extractor_class  = LiDARConvExtractor,
        features_extractor_kwargs = dict(
            frame_stack=4, lidar_beams=180, state_dim=6, features_dim=256
        ),
        share_features_extractor = False,
    ),
    tensorboard_log   = str(TB_DIR),
    verbose           = 1,
)


def main() -> None:
    rclpy.init()

    # ── Security boot banner ───────────────────────────────────────────
    secret = _load_alert_secret()
    fp = _secret_fingerprint(secret)
    print("─" * 64)
    if not _SEC_AVAILABLE:
        print(" ⚠️  dds_security_monitor not importable — integrity OFF")
    elif not secret:
        print(" ⚠️  no HMAC secret loaded — integrity OFF")
    else:
        print(f" 🔐  HMAC secret loaded   fingerprint=sha256:{fp}")
        print(f"     (must match across monitor/patrol/training nodes)")
    print("─" * 64)

    train_env_raw = BurgerEnvTop(eval_mode=False, curriculum_max_wp=1)
    monitor_dir = LOG_DIR / "monitor"
    monitor_dir.mkdir(parents=True, exist_ok=True)
    train_env = Monitor(
        train_env_raw,
        str(monitor_dir),
        info_keywords=(
            "waypoints_done", "is_collision", "is_full_success",
            "is_timeout", "spl", "path_length", "optimal_length",
            "dr_noise", "dr_max_lin",
        ),
    )

    resuming = LATEST.with_suffix(".zip").exists()
    print(f"\n{'▶ Resuming' if resuming else '▶ Fresh start'} TQC training")
    print(f"  Target steps : {TOTAL_STEPS:,}")
    print(f"  TensorBoard  : tensorboard --logdir {TB_DIR}")
    print(f"  Best model   : {BEST}.zip\n")

    if resuming:
        model_zip = LATEST.with_suffix(".zip")
        if _SEC_AVAILABLE and secret:
            sig = model_zip.with_suffix(".zip.sha256.hmac")
            if sig.exists():
                if verify_file(model_zip, secret):
                    print(f"  ✓ Model HMAC verified: {model_zip.name}")
                else:
                    print(f"  ✗ MODEL HMAC FAILED — refusing to load tampered model")
                    print(f"    file: {model_zip}")
                    rclpy.shutdown()
                    sys.exit(2)
            else:
                print(f"  ⚠️  model has no signature (legacy) — loaded but unverified")
        model = TQC.load(str(LATEST), env=train_env)
        if BUFFER.exists():
            if _SEC_AVAILABLE and secret:
                sig = BUFFER.with_suffix(".pkl.sha256.hmac")
                if sig.exists():
                    if verify_file(BUFFER, secret):
                        print(f"  ✓ Buffer HMAC verified")
                    else:
                        # Pickle RCE risk — refuse to load tampered buffer
                        print(f"  ✗ BUFFER HMAC FAILED — refusing to load (pickle RCE risk)")
                        rclpy.shutdown()
                        sys.exit(3)
                else:
                    print(f"  ⚠️  buffer has no signature (legacy) — loaded but unverified")
            model.load_replay_buffer(str(BUFFER))
            print(f"  ↳ Loaded replay buffer ({BUFFER.stat().st_size // (1024*1024)} MB)")
        remaining = max(0, TOTAL_STEPS - model.num_timesteps)
        print(f"  ↳ {model.num_timesteps:,} steps done → remaining {remaining:,}")
    else:
        model = TQC(env=train_env, **TQC_CFG)
        remaining = TOTAL_STEPS

    n_params = sum(p.numel() for p in model.policy.parameters())
    print(f"  Device       : {model.device}    Params: {n_params:,}\n")

    if remaining <= 0:
        print("✓ Training target already reached.")
        train_env.close()
        rclpy.shutdown()
        return

    callbacks = CallbackList([
        CheckpointCallback(
            save_freq          = CHECKPOINT_FREQ,
            save_path          = str(CKPT_DIR),
            name_prefix        = "tqc",
            save_replay_buffer = False,
            verbose            = 1,
        ),
        ScoreboardTopCallback(
            window            = 100,
            print_freq        = 20,
            total_steps       = TOTAL_STEPS,
            best_save_path    = BEST,
            promote_threshold = 0.7,
            max_wp            = N_WP_TOTAL,
            initial_stage     = 1,
            warmup_eps        = 100,
            stage_min_eps     = 30,
            verbose           = 1,
        ),
    ])

    try:
        model.learn(
            total_timesteps     = remaining,
            callback            = callbacks,
            log_interval        = 10,
            progress_bar        = True,
            reset_num_timesteps = False,
        )
    except KeyboardInterrupt:
        print("\n⏸ Interrupted — saving snapshot…")
    finally:
        def _save_model() -> None:
            model.save(str(LATEST))
            if _SEC_AVAILABLE and secret:
                sign_file(LATEST.with_suffix(".zip"), secret)

        def _save_buffer() -> None:
            model.save_replay_buffer(str(BUFFER))
            if _SEC_AVAILABLE and secret:
                sign_file(BUFFER, secret)

        for label, action in [
            ("model",  _save_model),
            ("buffer", _save_buffer),
            ("env",    train_env.close),
            ("rclpy",  rclpy.shutdown),
        ]:
            try:
                action()
            except Exception as e:
                print(f"⚠️  cleanup [{label}] failed: {e}")

        # also re-sign best model if it exists (best is saved by callback)
        best_zip = BEST.with_suffix(".zip")
        if _SEC_AVAILABLE and secret and best_zip.exists():
            try:
                sign_file(best_zip, secret)
            except Exception as e:
                print(f"⚠️  best.zip re-sign failed: {e}")

        print(f"\n✓ Saved latest → {LATEST}.zip  (signed: {_SEC_AVAILABLE and bool(secret)})")
        print(f"  Best model  → {BEST}.zip (if produced)")


if __name__ == "__main__":
    main()
