"""
ScoreboardCallback — SAC 訓練計分板

設計目標：
    1. 把關鍵 RL 指標寫進 TensorBoard（success / collision / timeout / waypoints）
    2. 每 N episode 在終端機印一份 ASCII 計分板，掃一眼就知道訓練狀況
    3. 對比「最近 100 ep」vs「上一個 100 ep」，看趨勢有沒有往好的方向走

統計欄位由 BurgerEnv._build_info() 提供：
    info["event"]            : collision / waypoint / all_done / timeout / running / security_stop
    info["waypoints_done"]   : 該 ep 到達的 waypoint 數
    info["total_waypoints"]  : 場景中 waypoint 總數（用來算完成率）
    info["min_clearance"]    : 該 ep 最接近障礙物的距離（公尺）
    info["is_collision"]     : 是否因碰撞結束
    info["is_full_success"]  : 是否到達所有 waypoint
    info["is_timeout"]       : 是否因 MAX_STEPS 截斷

外加 Monitor wrapper 自動塞入的 info["episode"]:
    info["episode"]["r"]     : episode 累計 reward
    info["episode"]["l"]     : episode 長度（steps）
    info["episode"]["t"]     : episode 結束時的 wall time
"""
from __future__ import annotations

import sys
import time
import unicodedata
from collections import deque
from typing import Deque

import numpy as np
from stable_baselines3.common.callbacks import BaseCallback

try:
    # tqdm.write 避免跟 SB3 的 progress_bar 搶 stdout 互相覆蓋
    from tqdm import tqdm as _tqdm
    def _writeln(text: str) -> None:
        _tqdm.write(text, file=sys.stdout)
except ImportError:
    def _writeln(text: str) -> None:
        print(text, flush=True)

# 給 best model 簽 HMAC 章（修補紅隊攻擊 M）
try:
    from dds_security_monitor.monitor_node import sign_file, _load_alert_secret
    _BEST_SECRET = _load_alert_secret()
except Exception:
    _BEST_SECRET = b""
    def sign_file(_p, _s): return ""


# ── 框框 helpers（處理中文/emoji 寬度，避免邊框跑掉）────────────────────────
_INNER = 70   # 框內容區寬度（cell 數，不含左右 padding）

def _vwidth(s: str) -> int:
    """終端機可見寬度：CJK / 全形 / emoji → 2，其餘 → 1。"""
    w = 0
    for ch in s:
        if unicodedata.east_asian_width(ch) in ("W", "F"):
            w += 2
        elif ord(ch) >= 0x1F300:        # emoji 主區
            w += 2
        else:
            w += 1
    return w


def _row(content: str) -> str:
    """把一行內容包進 ║ ... ║，自動處理中文寬度。"""
    pad = max(0, _INNER - _vwidth(content))
    return f"║  {content}{' ' * pad}  ║"


def _top()    -> str: return "╔" + "═" * (_INNER + 4) + "╗"
def _bot()    -> str: return "╚" + "═" * (_INNER + 4) + "╝"
def _sep()    -> str: return "╠" + "═" * (_INNER + 4) + "╣"
def _section(title: str) -> str:
    """中段分隔線：╠═══ title ═══╣"""
    raw = f" {title} "
    total = _INNER + 4 - _vwidth(raw)
    left  = total // 2
    right = total - left
    return "╠" + "═" * left + raw + "═" * right + "╣"


def _bar(value: float, width: int = 14, fill: str = "█", empty: str = "░") -> str:
    """0~1 → 進度條字串。"""
    value = max(0.0, min(1.0, value))
    filled = int(round(value * width))
    return fill * filled + empty * (width - filled)


def _trend(curr: float, prev: float | None, fmt: str = "{:+.2f}") -> str:
    """趨勢箭頭 + 變化量。prev 為 None 時回傳空字串。"""
    if prev is None:
        return ""
    delta = curr - prev
    arrow = "↑" if delta > 1e-6 else ("↓" if delta < -1e-6 else "→")
    return f"{arrow} {fmt.format(delta)}"


def _split_halves(values) -> tuple[float | None, float | None]:
    """把 deque/list 切成「前半」「後半」，回傳 (recent_half_mean, prev_half_mean)。

    用來算「不重疊」的趨勢：之前 _prev_snapshot 是上次 print 時的 window，
    跟當前 window 重疊 80%~95%，趨勢數字幾乎無意義。

    視窗至少 20 個樣本才有意義（避免早期 noise 誤判趨勢）。
    """
    n = len(values)
    if n < 20:
        return None, None
    arr = list(values)
    half = n // 2
    recent = arr[-half:]
    prev   = arr[:half]
    return float(np.mean(recent)), float(np.mean(prev))


class ScoreboardCallback(BaseCallback):
    """
    每個 episode 結束時收集統計，每 print_freq 個 episode 印一次計分板。
    所有指標同時寫進 TensorBoard 的 scoreboard/* namespace。

    Args:
        window:       滾動視窗大小（episodes）
        print_freq:   每 N episode 印一次終端機計分板
        total_steps:  訓練總步數（用來算 ETA 和進度百分比）
    """

    def __init__(
        self,
        window: int = 100,
        print_freq: int = 20,
        total_steps: int = 3_000_000,
        verbose: int = 0,
    ):
        super().__init__(verbose)
        self.window      = window
        self.print_freq  = print_freq
        self.total_steps = total_steps

        # 滾動視窗
        self.ep_rewards:    Deque[float] = deque(maxlen=window)
        self.ep_lengths:    Deque[int]   = deque(maxlen=window)
        self.ep_collisions: Deque[int]   = deque(maxlen=window)
        self.ep_full_succ:  Deque[int]   = deque(maxlen=window)
        self.ep_partial:    Deque[int]   = deque(maxlen=window)  # 至少到 1 個 waypoint
        self.ep_wp_done:    Deque[int]   = deque(maxlen=window)
        self.ep_timeouts:   Deque[int]   = deque(maxlen=window)
        self.ep_clearance:  Deque[float] = deque(maxlen=window)

        # 全期累計
        self.total_episodes = 0
        self.best_reward    = -float("inf")
        self.best_wp_done   = 0
        self.total_wp       = 5     # 由第一個 info 更新
        self.start_time:    float | None = None

    # ── SB3 hooks ────────────────────────────────────────────────────────────

    def _on_training_start(self) -> None:
        self.start_time = time.time()

    def _on_step(self) -> bool:
        for info in self.locals.get("infos", []):
            if "episode" not in info:
                continue
            self._record_episode(info)
        return True

    def _on_training_end(self) -> None:
        if self.ep_rewards:
            self._print_scoreboard(final=True)

    # ── 紀錄 episode ─────────────────────────────────────────────────────────

    def _record_episode(self, info: dict) -> None:
        ep_r = float(info["episode"]["r"])
        ep_l = int(info["episode"]["l"])

        self.total_episodes += 1
        self.ep_rewards.append(ep_r)
        self.ep_lengths.append(ep_l)
        self.ep_collisions.append(int(info.get("is_collision", False)))
        self.ep_full_succ.append(int(info.get("is_full_success", False)))
        self.ep_timeouts.append(int(info.get("is_timeout", False)))

        wp_done = int(info.get("waypoints_done", 0))
        self.ep_wp_done.append(wp_done)
        self.ep_partial.append(int(wp_done >= 1))
        self.total_wp = int(info.get("total_waypoints", self.total_wp))

        clearance = float(info.get("min_clearance", float("inf")))
        if np.isfinite(clearance):
            self.ep_clearance.append(clearance)

        # 歷史最佳
        if ep_r > self.best_reward:
            self.best_reward = ep_r
        if wp_done > self.best_wp_done:
            self.best_wp_done = wp_done

        # 寫 TensorBoard（用 mean 而不是個別值，較平滑）
        self.logger.record("scoreboard/success_rate",         np.mean(self.ep_full_succ))
        self.logger.record("scoreboard/partial_success_rate", np.mean(self.ep_partial))
        self.logger.record("scoreboard/collision_rate",       np.mean(self.ep_collisions))
        self.logger.record("scoreboard/timeout_rate",         np.mean(self.ep_timeouts))
        self.logger.record("scoreboard/mean_waypoints",       np.mean(self.ep_wp_done))
        self.logger.record("scoreboard/mean_episode_reward",  np.mean(self.ep_rewards))
        self.logger.record("scoreboard/mean_episode_length",  np.mean(self.ep_lengths))
        self.logger.record("scoreboard/best_reward",          self.best_reward)
        self.logger.record("scoreboard/best_waypoints",       self.best_wp_done)
        if self.ep_clearance:
            self.logger.record("scoreboard/mean_min_clearance", np.mean(self.ep_clearance))

        # 達到 print_freq 就印計分板
        if self.total_episodes % self.print_freq == 0:
            self._print_scoreboard()

    # ── 印計分板 ─────────────────────────────────────────────────────────────

    def _print_scoreboard(self, final: bool = False) -> None:
        elapsed = time.time() - (self.start_time or time.time())
        sps = self.num_timesteps / elapsed if elapsed > 0 else 0.0
        remaining = max(0, self.total_steps - self.num_timesteps)
        eta_s = remaining / sps if sps > 0 else 0.0
        progress = self.num_timesteps / self.total_steps if self.total_steps > 0 else 0.0

        # 滾動視窗統計
        n        = len(self.ep_rewards)
        mean_r   = float(np.mean(self.ep_rewards))
        std_r    = float(np.std(self.ep_rewards))
        mean_l   = float(np.mean(self.ep_lengths))
        full_sr  = float(np.mean(self.ep_full_succ))
        part_sr  = float(np.mean(self.ep_partial))
        coll_r   = float(np.mean(self.ep_collisions))
        time_r   = float(np.mean(self.ep_timeouts))
        mean_wp  = float(np.mean(self.ep_wp_done))
        total_wp = self.total_wp
        mean_clr = float(np.mean(self.ep_clearance)) if self.ep_clearance else 0.0

        # 趨勢：把 window 內切成前半 / 後半比較（不重疊）
        # 之前用 _prev_snapshot 是「上次 print 時的整個 window」跟「這次的整個 window」相比，
        # 兩 window 有 80%~95% 樣本重疊，趨勢數字幾乎被「相同的 95 個 ep」拉平，沒意義。
        recent_r,  prev_r  = _split_halves(self.ep_rewards)
        recent_sr, prev_sr = _split_halves(self.ep_full_succ)
        recent_ps, prev_ps = _split_halves(self.ep_partial)
        recent_cr, prev_cr = _split_halves(self.ep_collisions)
        recent_wp, prev_wp = _split_halves(self.ep_wp_done)
        t_r   = _trend(recent_r,  prev_r)
        t_sr  = _trend(recent_sr, prev_sr, "{:+.1%}")
        t_psr = _trend(recent_ps, prev_ps, "{:+.1%}")
        t_cr  = _trend(recent_cr, prev_cr, "{:+.1%}")
        t_wp  = _trend(recent_wp, prev_wp)

        # 累計 banner
        title = "FINAL SCOREBOARD" if final else "SAC TRAINING SCOREBOARD"

        lines = [
            "",
            _top(),
            _row(title),
            _sep(),
            _row(f"Episode: {self.total_episodes:>7,}   │   "
                 f"Steps: {self.num_timesteps:>10,} / {self.total_steps:,} ({progress:5.1%})"),
            _row(f"Elapsed: {_fmt_hms(elapsed):>10}   │   "
                 f"SPS: {sps:>6.1f}   │   ETA: {_fmt_hms(eta_s):>10}"),
            _section(f"Last {n} episodes"),
            _row(f"Mean reward      {mean_r:>8.2f} ± {std_r:>6.2f}   {t_r:<12}   (best: {self.best_reward:>7.2f})"),
            _row(f"Mean length      {mean_l:>8.1f} steps"),
            _row(f"Full success     {_bar(full_sr)} {full_sr*100:>5.1f}%   {t_sr}"),
            _row(f"Partial (≥1 wp)  {_bar(part_sr)} {part_sr*100:>5.1f}%   {t_psr}"),
            _row(f"Collision        {_bar(coll_r)} {coll_r*100:>5.1f}%   {t_cr}"),
            _row(f"Timeout          {_bar(time_r)} {time_r*100:>5.1f}%"),
            _row(f"Mean waypoints   {mean_wp:>4.2f} / {total_wp}   {t_wp:<10}   (best: {self.best_wp_done}/{total_wp})"),
            _row(f"Mean clearance   {mean_clr:>5.2f} m   (越大越好，< 0.20 m 就快撞了)"),
            _bot(),
            "",
        ]
        _writeln("\n".join(lines))


def _fmt_hms(seconds: float) -> str:
    """秒數 → H:MM:SS。"""
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}"


class BestRewardCallback(BaseCallback):
    """
    監聽 episode 結束時的 reward，當「最近 N 集 mean reward」創新高就存模型。

    與 SB3 EvalCallback 的差別：
        - EvalCallback 要獨立 eval_env，但 ROS2/Gazebo 不能兩個 BurgerEnv 同時跑
        - 此 callback 直接用訓練資料的 rolling mean，不暫停訓練、不需要額外 env

    參數:
        save_path:      存最佳模型的路徑（不含 .zip）
        window:         rolling 視窗大小（建議 100）
        warmup:         前 N ep 不評估（避免 buffer 還沒填滿就被 high-variance 早期 reward 誤判）
    """

    def __init__(
        self,
        save_path,
        window: int = 100,
        warmup: int = 50,
        verbose: int = 1,
    ):
        from pathlib import Path
        super().__init__(verbose)
        self.save_path = Path(save_path)
        self.window  = window
        self.warmup  = warmup
        self.ep_rewards: Deque[float] = deque(maxlen=window)
        self.best_mean_reward = -float("inf")
        self.total_eps = 0

    def _on_step(self) -> bool:
        for info in self.locals.get("infos", []):
            if "episode" not in info:
                continue
            self.total_eps += 1
            self.ep_rewards.append(float(info["episode"]["r"]))

            if self.total_eps < self.warmup:
                continue

            mean_r = float(np.mean(self.ep_rewards))
            # 每 ep 都寫 TB，方便看 best 軌跡的連續曲線（之前只在創新高時記，曲線會斷斷續續）
            self.logger.record("scoreboard/best_mean_reward", self.best_mean_reward)

            if mean_r > self.best_mean_reward:
                old = self.best_mean_reward
                self.best_mean_reward = mean_r
                self.model.save(str(self.save_path))
                # 簽 best.zip 完整性章（修補 M）— 部署時驗章才信任
                if _BEST_SECRET:
                    try:
                        sign_file(self.save_path.with_suffix(".zip"), _BEST_SECRET)
                    except Exception as e:
                        _writeln(f"⚠️  best.zip 簽章失敗: {e}")
                if self.verbose:
                    _writeln(
                        f"💎 New best mean_reward={mean_r:+.2f} "
                        f"(prev: {old:+.2f}) → saved {self.save_path.name}"
                    )
        return True
