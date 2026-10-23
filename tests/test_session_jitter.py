"""場次抖動的回歸測試。

## 為什麼要抖動

2026-09-15 量到：**攻擊起始視窗 274／280（98%）固定在 window 1**。
成因是 orchestrator 只隨機化 `intensity`，`warmup_sec` 對每一類都是 catalog
裡的同一個常數（10 秒），而特徵視窗是 8 秒。任何編碼「第幾個視窗」的東西
都會有效，而那在攻擊時間任意的真實部署上不會轉移。

## 這裡守的那一條線

**抖動本身不可以變成新的混淆。** `warmup` 與 `cooldown` 必須對**每一個類別
（含 normal）**抽自同一個分布；只要某一類的起點分布不同，模型就會學到
「起點 ⇒ 類別」——那比原本更糟，因為原本至少是所有類別一起偏。

`duration` 是例外：它用**乘數**，因為各類攻擊需要的時間本來就不同
（`graph_overflow` 要 75 秒才跨得過 256 個 node）。**代價是 duration 的分布
與類別相關**，所以這裡也把那個事實釘起來，讓它是一個已知且寫明的限制，
而不是一個沒人發現的混淆。
"""
from __future__ import annotations

import collections
import random
import statistics

import pytest

from firewall_lab import orchestrator as orch
from firewall_lab.catalog import Scenario


def _scenario(scenario_id, duration=30.0, warmup=10.0, cooldown=5.0):
    return Scenario(
        scenario_id=scenario_id,
        attack_class=scenario_id,
        runner=scenario_id,
        description="測試用",
        default_security_mode="permissive",
        duration_sec=duration,
        warmup_sec=warmup,
        cooldown_sec=cooldown,
        intensity_min=0.1,
        intensity_max=1.0,
        expected_action="alert",
        requires_gazebo=False,
    )


def _draw(scenario, seed, jitter=True):
    """重現 `run_session` 開頭那幾個抽樣，順序必須一致。"""
    rng = random.Random(seed)
    intensity = rng.uniform(scenario.intensity_min, scenario.intensity_max)
    if jitter:
        duration = scenario.duration_sec * rng.uniform(
            *orch.JITTER_DURATION_SCALE)
    else:
        duration = scenario.duration_sec
    duration = max(1.0, min(duration, 300.0))
    if jitter:
        warmup = rng.uniform(*orch.JITTER_WARMUP_SEC)
        cooldown = rng.uniform(*orch.JITTER_COOLDOWN_SEC)
    else:
        warmup, cooldown = scenario.warmup_sec, scenario.cooldown_sec
    return {"intensity": intensity, "duration": duration,
            "warmup": warmup, "cooldown": cooldown}


# ── 宣告的範圍 ────────────────────────────────────────────────


def test_jitter_ranges_are_declared_and_sane():
    lo, hi = orch.JITTER_WARMUP_SEC
    assert 0 < lo < hi
    # 8 秒一個視窗；範圍要橫跨數個視窗，否則起點還是集中在同一格。
    assert (hi - lo) >= 3 * 8.0, "warmup 的範圍不到三個視窗寬，起點仍會集中"
    assert orch.JITTER_COOLDOWN_SEC[0] > 0
    scale_lo, scale_hi = orch.JITTER_DURATION_SCALE
    assert 0 < scale_lo < 1.0 < scale_hi


# ── 核心：起點與冷卻不可以帶類別資訊 ─────────────────────────


@pytest.mark.parametrize("field", ["warmup", "cooldown"])
def test_start_and_cooldown_are_class_independent(field):
    """不同 scenario、同一組 seed ⇒ 抽到的 warmup／cooldown 必須逐位相同。

    這是抖動不變成新混淆的**充分條件**：分布不只同形，連取值都一樣，
    所以那兩個量對類別完全沒有資訊。
    """
    a = _scenario("attack_alpha", duration=30.0, warmup=10.0, cooldown=5.0)
    b = _scenario("attack_beta", duration=75.0, warmup=2.0, cooldown=40.0)
    normal = _scenario("normal", duration=30.0, warmup=10.0, cooldown=5.0)
    for seed in range(50):
        va = _draw(a, seed)[field]
        vb = _draw(b, seed)[field]
        vn = _draw(normal, seed)[field]
        assert va == pytest.approx(vb) == pytest.approx(vn), (
            f"seed={seed} 的 {field} 隨 scenario 改變 ⇒ 它會變成類別線索")


def test_catalog_warmup_no_longer_leaks_into_the_timeline():
    """catalog 宣告的 warmup 差 20 倍，抖動之後也不可以有差別。"""
    short = _scenario("s", warmup=2.0)
    long = _scenario("l", warmup=40.0)
    assert _draw(short, 7)["warmup"] == pytest.approx(_draw(long, 7)["warmup"])


def test_attack_start_spreads_across_several_windows():
    """抖動的目的就是這個：起始視窗不可以再集中在同一格。

    2026-09-15 的現況是 98% 落在 window 1。
    """
    window = 8.0
    starts = collections.Counter(
        int(_draw(_scenario("x"), seed)["warmup"] // window)
        for seed in range(400))
    assert len(starts) >= 4, f"起始視窗只落在 {sorted(starts)}，沒有散開"
    top_share = max(starts.values()) / sum(starts.values())
    assert top_share < 0.5, f"最集中的一格佔 {top_share:.0%}，仍然過度集中"


# ── duration 是已知的例外 ─────────────────────────────────────


def test_duration_scales_with_the_catalog_value_and_that_is_on_purpose():
    """各類攻擊需要的時間不同（graph_overflow 壓到 30 秒就什麼都沒發生），
    所以 duration 用乘數。**代價是它與類別相關**，這裡把它釘成已知限制。"""
    short = _scenario("s", duration=30.0)
    long = _scenario("l", duration=75.0)
    ratios = [_draw(long, seed)["duration"] / _draw(short, seed)["duration"]
              for seed in range(30)]
    assert all(r == pytest.approx(75.0 / 30.0) for r in ratios)


def test_duration_still_varies_within_a_class():
    values = [_draw(_scenario("x"), seed)["duration"] for seed in range(200)]
    assert statistics.pstdev(values) > 2.0, "同一類的 duration 幾乎沒有變化"
    assert min(values) >= 1.0 and max(values) <= 300.0


# ── 關掉抖動時必須逐位回到舊行為 ─────────────────────────────


def test_without_jitter_the_catalog_values_are_used_exactly():
    """既有的 640 場必須維持可重現。"""
    s = _scenario("x", duration=30.0, warmup=10.0, cooldown=5.0)
    for seed in (0, 1, 12345):
        drawn = _draw(s, seed, jitter=False)
        assert drawn["duration"] == 30.0
        assert drawn["warmup"] == 10.0
        assert drawn["cooldown"] == 5.0


def test_intensity_is_drawn_first_so_disabling_jitter_keeps_it_identical():
    """intensity 必須在抖動之前抽，否則開關抖動會連 intensity 都變，
    而那會讓「有沒有抖動」與「強度不同」混在一起。"""
    s = _scenario("x")
    for seed in range(20):
        assert (_draw(s, seed, jitter=True)["intensity"]
                == pytest.approx(_draw(s, seed, jitter=False)["intensity"]))


# ── 接線 ──────────────────────────────────────────────────────


def test_run_session_accepts_jitter_and_records_it():
    import inspect

    sig = inspect.signature(orch.run_session)
    assert "jitter" in sig.parameters
    assert sig.parameters["jitter"].default is False
    source = inspect.getsource(orch.run_session)
    # manifest 必須留下「這一場有沒有抖動」與 catalog 的原值，
    # 否則事後分不出哪一批是抖動過的。
    for key in ('"jitter": jitter', '"catalog_duration_sec"',
                '"catalog_warmup_sec"', '"catalog_cooldown_sec"'):
        assert key in source, f"manifest 沒有記 {key}"
    assert "_phase_sleep(warmup, mode)" in source
    assert "_phase_sleep(cooldown, mode)" in source
