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
from stable_baselines3.common.callbacks import BaseCallback, CallbackList
from stable_baselines3.common.monitor import Monitor

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from turtlebot3_dqn.burger_env_top import BurgerEnvTop, N_WP_TOTAL
from turtlebot3_dqn.atomic_io import (
    ArtifactIntegrityError,
    atomic_save,
    open_verified_snapshot,
)
from turtlebot3_dqn.feature_extractors import LiDARConvExtractor
from turtlebot3_dqn.scoreboard_top_callback import ScoreboardTopCallback

# ── Security: file integrity (model + replay buffer) ─────────────────────
# Training refuses to load or write model artifacts unless the shared,
# file-only HMAC key is available.  This prevents a tampered SB3/pickle
# artifact from becoming a code-execution path during resume/evaluation.
try:
    from dds_security_monitor.monitor_node import (
        sign_file, _load_alert_secret,
    )
    _SEC_AVAILABLE = True
except Exception:
    _SEC_AVAILABLE = False
    def sign_file(_p, _s): return ""
    def _load_alert_secret(): return b""


def _secret_fingerprint(secret: bytes) -> str:
    """Short HMAC-key fingerprint for boot-time consistency check.

    The key is loaded only from ``~/.config/dds-monitor/alert_secret`` by
    ``monitor_node._load_alert_secret``; it is never accepted from an
    environment variable and never falls back to a random per-process value.
    Printing a short fingerprint lets operators compare nodes without exposing
    the key.
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


class AuthenticatedCheckpointCallback(BaseCallback):
    """Save every periodic checkpoint atomically with a matching HMAC."""

    def __init__(self, save_freq: int, save_path: Path, secret: bytes):
        super().__init__(verbose=1)
        self.save_freq = save_freq
        self.save_path = save_path
        self.secret = secret

    def _on_step(self) -> bool:
        if self.n_calls % self.save_freq:
            return True
        target = self.save_path / f"tqc_{self.num_timesteps}_steps.zip"
        atomic_save(
            self.model.save,
            target,
            sign_fn=sign_file,
            secret=self.secret,
        )
        if self.verbose:
            print(f"  🔐 Authenticated checkpoint → {target}")
        return True

# Hyperparameters aligned to SB3-Zoo BipedalWalker-v3 TQC baseline
# (rl-baselines3-zoo/hyperparams/tqc.yml) — the canonical proven
# continuous-control config. Diverges from defaults specifically:
#   train_freq=64 + gradient_steps=64 : batched updates, big wall-time win
#   use_sde=True                      : gSDE exploration for cont. actions
#   lr 3e-4 → 7.3e-4, tau 0.005 → 0.02 : faster off-policy convergence
#   gamma 0.99 → 0.98                 : more sensible for 500-step horizon
TQC_CFG = dict(
    policy            = "MlpPolicy",
    device            = "auto",
    learning_rate     = 7.3e-4,
    buffer_size       = 500_000,
    batch_size        = 256,
    tau               = 0.02,
    gamma             = 0.98,
    learning_starts   = 10_000,
    train_freq        = 64,
    gradient_steps    = 64,
    use_sde           = True,
    sde_sample_freq   = 4,
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
        log_std_init = -3,  # SB3-Zoo BipedalWalker setting
    ),
    tensorboard_log   = str(TB_DIR),
    verbose           = 1,
)


def main() -> None:
    rclpy.init()

    # ── Security boot banner ───────────────────────────────────────────
    if not _SEC_AVAILABLE:
        rclpy.shutdown()
        sys.exit(
            "dds_security_monitor 不可匯入；拒絕在無模型驗章能力下訓練"
        )
    try:
        secret = _load_alert_secret()
    except Exception as exc:
        rclpy.shutdown()
        sys.exit(f"無法載入模型 HMAC 金鑰，拒絕訓練：{exc}")
    fp = _secret_fingerprint(secret)
    print("─" * 64)
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
        try:
            with open_verified_snapshot(
                model_zip,
                secret=secret,
                label="TQC model",
            ) as model_snapshot:
                model = TQC.load(model_snapshot, env=train_env)
        except (ArtifactIntegrityError, OSError) as exc:
            print(f"  ✗ {exc}")
            rclpy.shutdown()
            sys.exit(2)
        print(f"  ✓ Model HMAC verified and loaded from snapshot: {model_zip.name}")
        if BUFFER.exists():
            try:
                with open_verified_snapshot(
                    BUFFER,
                    secret=secret,
                    label="TQC replay buffer (pickle)",
                ) as buffer_snapshot:
                    model.load_replay_buffer(buffer_snapshot)
            except (ArtifactIntegrityError, OSError) as exc:
                print(f"  ✗ {exc}")
                print("    replay buffer 可能執行任意程式，沒有 legacy bypass")
                rclpy.shutdown()
                sys.exit(3)
            print("  ✓ Buffer HMAC verified and loaded from snapshot")
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
        AuthenticatedCheckpointCallback(
            save_freq=CHECKPOINT_FREQ,
            save_path=CKPT_DIR,
            secret=secret,
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
            atomic_save(
                model.save,
                LATEST.with_suffix(".zip"),
                sign_fn=sign_file if _SEC_AVAILABLE else None,
                secret=secret,
            )

        def _save_buffer() -> None:
            atomic_save(
                model.save_replay_buffer,
                BUFFER,
                sign_fn=sign_file if _SEC_AVAILABLE else None,
                secret=secret,
            )

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

        print(f"\n✓ Saved latest → {LATEST}.zip  (signed: {_SEC_AVAILABLE and bool(secret)})")
        print(f"  Best model  → {BEST}.zip (if produced)")


if __name__ == "__main__":
    main()
