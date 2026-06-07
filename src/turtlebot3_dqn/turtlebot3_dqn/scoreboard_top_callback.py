"""
ScoreboardTopCallback — TQC training instrumentation.

Responsibilities:
    1. Rolling SPL / success / collision / clearance stats to TensorBoard
    2. Adaptive curriculum: promote env.curriculum_max_wp when stage success ≥ τ
    3. Best-by-SPL checkpoint (only after reaching final curriculum stage)
    4. ASCII scoreboard print every N episodes (CJK-width aware)
"""
from __future__ import annotations

import sys
import time
import unicodedata
from collections import deque
from pathlib import Path

import numpy as np
from stable_baselines3.common.callbacks import BaseCallback

try:
    from tqdm import tqdm as _tqdm
    def _w(text: str) -> None: _tqdm.write(text, file=sys.stdout)
except ImportError:
    def _w(text: str) -> None: print(text, flush=True)

# Sign best.zip immediately when callback writes it — eval / production
# refuse to load unsigned-or-mismatched checkpoints (attack M mitigation).
try:
    from dds_security_monitor.monitor_node import sign_file, _load_alert_secret
    _BEST_SECRET = _load_alert_secret()
except Exception:
    _BEST_SECRET = b""
    def sign_file(_p, _s): return ""


_W = 76


def _vw(s: str) -> int:
    w = 0
    for c in s:
        if unicodedata.east_asian_width(c) in ("W", "F"):
            w += 2
        elif ord(c) >= 0x1F300:
            w += 2
        else:
            w += 1
    return w


def _row(content: str) -> str:
    pad = max(0, _W - _vw(content))
    return f"║  {content}{' ' * pad}  ║"


def _top() -> str: return "╔" + "═" * (_W + 4) + "╗"
def _bot() -> str: return "╚" + "═" * (_W + 4) + "╝"
def _sep() -> str: return "╠" + "═" * (_W + 4) + "╣"


def _bar(value: float, width: int = 16) -> str:
    value = max(0.0, min(1.0, value))
    n = int(round(value * width))
    return "█" * n + "░" * (width - n)


def _hms(sec: float) -> str:
    sec = max(0, int(sec))
    h, r = divmod(sec, 3600)
    m, s = divmod(r, 60)
    return f"{h:d}:{m:02d}:{s:02d}"


class ScoreboardTopCallback(BaseCallback):
    def __init__(
        self,
        window: int = 100,
        print_freq: int = 20,
        total_steps: int = 1_500_000,
        best_save_path: str | Path | None = None,
        promote_threshold: float = 0.7,
        max_wp: int = 5,
        initial_stage: int = 1,
        warmup_eps: int = 100,
        stage_min_eps: int = 30,
        verbose: int = 1,
    ) -> None:
        super().__init__(verbose)
        self.window = window
        self.print_freq = print_freq
        self.total_steps = total_steps
        self.best_save_path = Path(best_save_path) if best_save_path else None
        self.promote_threshold = promote_threshold
        self.max_wp = max_wp
        self.warmup_eps = warmup_eps
        self.stage_min_eps = stage_min_eps

        self.ep_r   = deque(maxlen=window)
        self.ep_l   = deque(maxlen=window)
        self.ep_spl = deque(maxlen=window)
        self.ep_succ = deque(maxlen=window)
        self.ep_coll = deque(maxlen=window)
        self.ep_to   = deque(maxlen=window)
        self.ep_wp   = deque(maxlen=window)
        self.ep_clr  = deque(maxlen=window)

        self.stage_succ_window = deque(maxlen=50)
        self.current_stage = max(1, min(max_wp, initial_stage))

        self.best_spl = -1.0
        self.total_eps = 0
        self.start_t: float | None = None

    def _on_training_start(self) -> None:
        self.start_t = time.time()
        try:
            self.training_env.env_method("set_curriculum_max_wp", self.current_stage)
        except Exception as e:
            _w(f"⚠️ failed to set initial curriculum stage: {e}")

    def _on_step(self) -> bool:
        for info in self.locals.get("infos", []):
            if "episode" not in info:
                continue
            self._record(info)
        return True

    def _record(self, info: dict) -> None:
        self.total_eps += 1
        self.ep_r.append(float(info["episode"]["r"]))
        self.ep_l.append(int(info["episode"]["l"]))
        self.ep_spl.append(float(info.get("spl", 0.0)))
        succ = bool(info.get("is_full_success", False))
        self.ep_succ.append(int(succ))
        self.ep_coll.append(int(info.get("is_collision", False)))
        self.ep_to.append(int(info.get("is_timeout", False)))
        self.ep_wp.append(int(info.get("waypoints_done", 0)))
        clr = float(info.get("min_clearance", float("inf")))
        if np.isfinite(clr):
            self.ep_clr.append(clr)
        self.stage_succ_window.append(int(succ))

        self.logger.record("scoreboard/spl_mean",       float(np.mean(self.ep_spl)))
        self.logger.record("scoreboard/success_rate",   float(np.mean(self.ep_succ)))
        self.logger.record("scoreboard/collision_rate", float(np.mean(self.ep_coll)))
        self.logger.record("scoreboard/timeout_rate",   float(np.mean(self.ep_to)))
        self.logger.record("scoreboard/mean_waypoints", float(np.mean(self.ep_wp)))
        self.logger.record("scoreboard/mean_reward",    float(np.mean(self.ep_r)))
        self.logger.record("scoreboard/curriculum_stage", self.current_stage)
        if self.ep_clr:
            self.logger.record("scoreboard/mean_clearance", float(np.mean(self.ep_clr)))

        # Curriculum advance
        if (
            len(self.stage_succ_window) >= self.stage_min_eps
            and float(np.mean(self.stage_succ_window)) >= self.promote_threshold
            and self.current_stage < self.max_wp
        ):
            self.current_stage += 1
            try:
                self.training_env.env_method("set_curriculum_max_wp", self.current_stage)
            except Exception as e:
                _w(f"⚠️ curriculum env_method failed: {e}")
            self.stage_succ_window.clear()
            _w(f"🎓 Curriculum 升級 → max_wp = {self.current_stage}")

        # Save best by SPL — only at the top stage to avoid easy-stage bias
        if (
            self.total_eps >= self.warmup_eps
            and self.best_save_path is not None
            and self.current_stage == self.max_wp
        ):
            spl_now = float(np.mean(self.ep_spl))
            if spl_now > self.best_spl:
                old = self.best_spl
                self.best_spl = spl_now
                try:
                    self.model.save(str(self.best_save_path))
                    # Sign immediately so any tampering between training and
                    # eval/deploy gets detected (attack M: model swap).
                    if _BEST_SECRET:
                        try:
                            sign_file(self.best_save_path.with_suffix(".zip"), _BEST_SECRET)
                        except Exception as e:
                            _w(f"⚠️ best HMAC sign failed: {e}")
                    _w(f"💎 New best SPL = {spl_now:.3f} (was {old:.3f}) → {self.best_save_path.name}.zip")
                except Exception as e:
                    _w(f"⚠️ best save failed: {e}")

        if self.total_eps % self.print_freq == 0:
            self._print()

    def _print(self) -> None:
        elapsed = time.time() - (self.start_t or time.time())
        sps = self.num_timesteps / elapsed if elapsed > 0 else 0.0
        remaining = max(0, self.total_steps - self.num_timesteps)
        eta = remaining / sps if sps > 0 else 0.0
        progress = self.num_timesteps / self.total_steps if self.total_steps > 0 else 0.0

        n = len(self.ep_r)
        mean_r   = float(np.mean(self.ep_r))
        mean_spl = float(np.mean(self.ep_spl))
        sr = float(np.mean(self.ep_succ))
        cr = float(np.mean(self.ep_coll))
        tr = float(np.mean(self.ep_to))
        mwp = float(np.mean(self.ep_wp))
        mclr = float(np.mean(self.ep_clr)) if self.ep_clr else 0.0

        lines = [
            "",
            _top(),
            _row("TQC TIER-1 SCOREBOARD"),
            _sep(),
            _row(f"Episode {self.total_eps:>7,}    Step {self.num_timesteps:>11,} / {self.total_steps:,}  ({progress:5.1%})"),
            _row(f"Elapsed {_hms(elapsed):>10}    SPS {sps:6.1f}    ETA {_hms(eta):>10}"),
            _row(f"Curriculum stage: {self.current_stage}/{self.max_wp} waypoints  (window n={n})"),
            _sep(),
            _row(f"SPL              {_bar(mean_spl)} {mean_spl*100:5.1f}%   (best @ top-stage: {self.best_spl*100:5.1f}%)"),
            _row(f"Success rate     {_bar(sr)} {sr*100:5.1f}%"),
            _row(f"Collision rate   {_bar(cr)} {cr*100:5.1f}%"),
            _row(f"Timeout rate     {_bar(tr)} {tr*100:5.1f}%"),
            _row(f"Mean reward      {mean_r:8.2f}"),
            _row(f"Mean waypoints   {mwp:4.2f} / {self.max_wp}"),
            _row(f"Mean clearance   {mclr:5.2f} m"),
            _bot(),
            "",
        ]
        _w("\n".join(lines))
