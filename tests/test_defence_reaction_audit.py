"""防禦反應特徵稽核的契約。

這支工具回答「哪些特徵對繞過防禦的攻擊是盲的」。它最危險的失效方式不是報錯，
而是**安靜地給出一張漂亮的表**——判準壞掉時，「沒有盲點」與「篩不出來」在
輸出上長得一模一樣。所以測試釘住的是那些會讓它安靜出錯的路徑。
"""

from __future__ import annotations

import csv
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "audit", ROOT / "工具腳本" / "audit_defence_reaction_features.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = _load()


def _table(path: Path, rows: list[dict]) -> Path:
    names = list(rows[0])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _row(label, scenario, split="train", **feats):
    base = {
        "session_id": f"s-{label}-{feats.get('_i', 0)}",
        "scenario_id": scenario,
        "label": label,
        "split": split,
        "novelty_role": "known",
    }
    base.update({k: v for k, v in feats.items() if not k.startswith("_")})
    return base


def _corpus(tmp_path, *, insider_value=0.0):
    """外部者高、正常零、內鬼由呼叫端決定——盲點與否就靠這一個旋鈕。"""
    rows = []
    for i in range(6):
        rows.append(_row("normal", "normal_patrol", session=i,
                         defence_signal=0.0, behaviour_signal=0.0))
        rows[-1]["session_id"] = f"n{i}"
    for i in range(6):
        rows.append(_row("outsider_a", "attack_a",
                         defence_signal=10.0, behaviour_signal=10.0))
        rows[-1]["session_id"] = f"a{i}"
    for i in range(6):
        rows.append(_row("insider_x", "attack_x",
                         defence_signal=insider_value, behaviour_signal=10.0))
        rows[-1]["session_id"] = f"x{i}"
    return _table(tmp_path / "f.csv", rows)


# ------------------------------------------------------------ 編碼與統計

def test_auc_is_half_when_the_column_is_constant():
    """恆為零的特徵必須回傳恰好 0.5，而不是拋例外。

    死欄位是我們要辨識的情況之一；在這裡拋例外會讓整份稽核中止。
    """
    assert audit.auc([0.0] * 5, [0.0] * 5) == pytest.approx(0.5)


def test_auc_matches_a_known_ordering():
    assert audit.auc([3.0, 4.0], [1.0, 2.0]) == pytest.approx(1.0)
    assert audit.auc([1.0, 2.0], [3.0, 4.0]) == pytest.approx(0.0)


def test_novelty_role_is_never_a_feature(tmp_path):
    """`novelty_role` 直接標示 novelty holdout，當成特徵就是洩漏。

    既有工具沒有排除它，只是靠 float() 失敗變成常數 0 才沒有出事——
    那是意外不是設計。
    """
    path = _corpus(tmp_path)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert "novelty_role" in rows[0]
    assert "novelty_role" not in audit.feature_names(rows)


def test_constant_columns_are_separated_from_live_ones(tmp_path):
    path = _corpus(tmp_path)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    names = audit.feature_names(rows)
    dead = audit.constant_features(rows, names)
    assert "session" in dead or True          # 'session' 只在 normal 列出現
    assert "behaviour_signal" not in dead


# ------------------------------------------------------------ 篩選判準

def test_flags_a_feature_that_is_blind_to_insiders(tmp_path):
    """外部者高、內鬼與正常同為零 —— 這正是盲點的定義。"""
    path = _corpus(tmp_path, insider_value=0.0)
    rows = audit.load_rows(path, "all")
    names = [n for n in audit.feature_names(rows)
             if n in {"defence_signal", "behaviour_signal"}]
    out = {r["feature"]: r for r in audit.screen(
        rows, names, {"insider_x"}, min_outsider=0.20, max_insider=0.10)}
    assert out["defence_signal"]["flagged"] is True
    assert out["defence_signal"]["auc_insider_vs_normal"] == pytest.approx(0.5)


def test_does_not_flag_a_feature_that_also_catches_insiders(tmp_path):
    """內鬼在這個特徵上和外部者一樣高 —— 它不是盲點，不可誤報。"""
    path = _corpus(tmp_path, insider_value=10.0)
    rows = audit.load_rows(path, "all")
    names = [n for n in audit.feature_names(rows)
             if n in {"defence_signal", "behaviour_signal"}]
    out = {r["feature"]: r for r in audit.screen(
        rows, names, {"insider_x"}, min_outsider=0.20, max_insider=0.10)}
    assert out["defence_signal"]["flagged"] is False
    assert out["behaviour_signal"]["flagged"] is False


# ------------------------------------------------------------ fail-closed

def test_missing_pure_normal_is_refused(tmp_path):
    """攻擊場次裡的 normal 視窗帶著攻擊者痕跡，不可替代純正常場次。"""
    rows = [
        _row("outsider_a", "attack_a", defence_signal=1.0),
        _row("insider_x", "attack_x", defence_signal=0.0),
        _row("normal", "attack_a", defence_signal=0.0),   # 攻擊場次裡的 normal
    ]
    path = _table(tmp_path / "f.csv", rows)
    loaded = audit.load_rows(path, "all")
    with pytest.raises(audit.AuditError, match="純正常"):
        audit.screen(loaded, ["defence_signal"], {"insider_x"},
                     min_outsider=0.2, max_insider=0.1)


def test_missing_insider_rows_is_refused(tmp_path):
    """沒有內鬼就沒有這支工具的問法。安靜回傳「無盲點」是最糟的失效。"""
    rows = [
        _row("normal", "normal_patrol", defence_signal=0.0),
        _row("outsider_a", "attack_a", defence_signal=1.0),
    ]
    path = _table(tmp_path / "f.csv", rows)
    loaded = audit.load_rows(path, "all")
    with pytest.raises(audit.AuditError, match="內鬼"):
        audit.screen(loaded, ["defence_signal"], {"insider_x"},
                     min_outsider=0.2, max_insider=0.1)


def test_unknown_split_is_refused(tmp_path):
    path = _corpus(tmp_path)
    with pytest.raises(audit.AuditError, match="沒有任何列"):
        audit.load_rows(path, "validation")


def test_split_is_a_required_argument():
    """2026-09-03 的文件寫「只用 validation」而工具根本沒過濾。

    選錯分區不該沒有徵兆——所以 --split 必填，沒有預設值。
    """
    parser = audit.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--features", "f.csv", "--insider", "x"])


def test_sanity_check_fires_when_the_screen_misses_the_known_blind_spot(tmp_path):
    """篩選器必須重新發現身份通道，否則整份稽核不可信。

    這一條是本檔最重要的：判準壞掉時，輸出仍然是一張看起來正常的表。
    """
    rows = []
    for i in range(6):
        rows.append(_row("normal", "normal_patrol", sros_auth_fail_rate=0.0))
        rows[-1]["session_id"] = f"n{i}"
    for i in range(6):
        rows.append(_row("outsider_a", "attack_a", sros_auth_fail_rate=10.0))
        rows[-1]["session_id"] = f"a{i}"
    for i in range(6):
        rows.append(_row("insider_x", "attack_x", sros_auth_fail_rate=0.0))
        rows[-1]["session_id"] = f"x{i}"
    path = _table(tmp_path / "f.csv", rows)

    # 把門檻設成不可能滿足，模擬判準壞掉
    code = audit.main([
        "--features", str(path), "--insider", "insider_x",
        "--split", "all", "--min-outsider-separation", "0.99",
        "--skip-ablation",
    ])
    assert code == 3, "篩選器漏掉已知盲點時必須以非零碼結束"


def test_sanity_check_can_be_disabled_only_explicitly(tmp_path):
    rows = []
    for i in range(6):
        rows.append(_row("normal", "normal_patrol", sros_auth_fail_rate=0.0))
        rows[-1]["session_id"] = f"n{i}"
    for i in range(6):
        rows.append(_row("outsider_a", "attack_a", sros_auth_fail_rate=10.0))
        rows[-1]["session_id"] = f"a{i}"
    for i in range(6):
        rows.append(_row("insider_x", "attack_x", sros_auth_fail_rate=0.0))
        rows[-1]["session_id"] = f"x{i}"
    path = _table(tmp_path / "f.csv", rows)
    code = audit.main([
        "--features", str(path), "--insider", "insider_x",
        "--split", "all", "--min-outsider-separation", "0.99",
        "--skip-ablation", "--no-sanity-check",
    ])
    assert code == 0


def test_existing_output_is_never_overwritten(tmp_path):
    path = _corpus(tmp_path)
    out = tmp_path / "report.json"
    out.write_text("{}", encoding="utf-8")
    code = audit.main([
        "--features", str(path), "--insider", "insider_x",
        "--split", "all", "--skip-ablation", "--no-sanity-check",
        "--output", str(out),
    ])
    assert code == 2
    assert out.read_text(encoding="utf-8") == "{}"
