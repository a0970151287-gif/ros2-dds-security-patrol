"""兩支 open-set CLI 必須真的把整份表餵進模型。

`tests/test_stream_replay.py` 只證明 helper 是對的。但 2026-08-25 那個 bug 的
形態是「CLI 自己抄了一份迴圈、繞過守衛」——helper 再正確也擋不住。所以這裡
直接載入兩支 CLI、換掉模型、跑 `main()`，斷言**模型看過的列數等於整份表**，
而統計到的只有 holdout 子集。

這是 C2C-037 指出缺的那一道。
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

WORKSPACE = Path(__file__).resolve().parents[1]
RAW_FEATURES = ("alpha", "beta")


def _load_cli(name: str):
    path = WORKSPACE / "工具腳本" / name
    spec = importlib.util.spec_from_file_location(f"_cli_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _RecordingModel:
    """記下每一次 predict 的 (session, source, window)。

    判定寫死：holdout 標籤一律回 `unknown_attack`，其餘回 `normal`。
    這樣輸出的統計是可預期的，測試才能斷言得精準。
    """

    def __init__(self, path, *, data_policy_sha256, action_policy_sha256):
        self.bundle = {"raw_features": list(RAW_FEATURES)}
        self.seen: list[tuple[str, str, int]] = []
        self.resets: list[tuple[str, str]] = []

    def reset_stream(self, *, session_id, source):
        self.resets.append((session_id, source))
        return True

    def predict(self, features, *, security_mode, source_availability,
                session_id, source, window):
        assert set(features) == set(RAW_FEATURES)
        self.seen.append((session_id, source, window))
        unknown = features["alpha"] > 0.5
        return {
            "predicted_class": "unknown_attack" if unknown else "normal",
            "attack_probability": 0.9 if unknown else 0.1,
            "binary_threshold": 0.5,
            "unknown_vs_known_attack": unknown,
        }


HOLDOUT_LABELS = {"sensor_spoof", "service_dos"}


def _write_fixture(tmp_path: Path) -> tuple[Path, Path, Path, int, int]:
    """兩場 session，每場都同時含 normal 與攻擊列——這正是會咬人的形態。"""
    rows = []
    for session, attack_label in (("s1", "sensor_spoof"), ("s2", "service_dos")):
        for window in range(3):
            attack = window > 0
            rows.append({
                "session_id": session,
                "source": "127.0.0.1",
                "window": window,
                "label": attack_label if attack else "normal",
                "novelty_role": "novelty_holdout_candidate" if attack else "",
                "alpha": 0.9 if attack else 0.1,
                "beta": 0.0,
            })
    # 第三場全是 normal，用來當 normal 誤判率的分母
    for window in range(3):
        rows.append({
            "session_id": "s3", "source": "127.0.0.1", "window": window,
            "label": "normal", "novelty_role": "",
            "alpha": 0.1, "beta": 0.0,
        })

    features = tmp_path / "features.csv"
    with features.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    metrics = tmp_path / "training_metrics.json"
    metrics.write_text(json.dumps({
        "novelty_protocol": {
            "holdout_labels": ["sensor_spoof", "service_dos"],
            "supervised_train_rows_used": 0,
            "calibration_rows_used": 0,
            "selection_rows_used": 0,
            "threshold_rows_used": 0,
        },
        "source_availability": {},
        "security_mode": "permissive",
    }, ensure_ascii=False), encoding="utf-8")

    (tmp_path / "release_manifest.json").write_text(json.dumps({
        "data_policy_sha256": "0" * 64,
        "action_policy_sha256": "1" * 64,
    }), encoding="utf-8")

    model = tmp_path / "model.joblib"
    model.write_bytes(b"unused")
    # 期望值由 fixture 推導，不寫死——寫死過一次就是錯的。
    total = len(rows)
    holdout = sum(1 for row in rows if row["label"] in HOLDOUT_LABELS)
    return features, metrics, model, total, holdout


@pytest.mark.parametrize("script", [
    "evaluate_openset_holdout.py",
    "diagnose_openset_paths.py",
])
def test_cli_feeds_every_row_not_just_the_tallied_subset(tmp_path, monkeypatch, script):
    """回歸：CLI 必須餵整份表（含每場的 normal 列），只統計 holdout 子集。

    先前的版本只餵 holdout 列，串流因此從 window 1 開始。若有人把過濾器
    加回去，這裡會因為 `replay_in_order` 的 window 0 契約而直接失敗。
    """
    features, metrics, model, total, holdout = _write_fixture(tmp_path)
    assert holdout < total, "fixture 必須有不被統計的列，否則測不到重點"
    module = _load_cli(script)
    captured: dict[str, _RecordingModel] = {}

    def _factory(path, **kwargs):
        instance = _RecordingModel(path, **kwargs)
        captured["model"] = instance
        return instance

    monkeypatch.setattr(module, "HierarchicalFirewallModel", _factory)
    output = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", [
        script, "--model", str(model), "--metrics", str(metrics),
        "--features", str(features), "--output", str(output),
    ])

    assert module.main() == 0

    seen = captured["model"].seen
    assert len(seen) == total, "CLI 必須餵整份表，不能只餵要統計的列"
    # 每條串流都從 window 0 起、逐一遞增
    for session in ("s1", "s2", "s3"):
        windows = [w for s, _, w in seen if s == session]
        assert windows == [0, 1, 2]
    assert captured["model"].resets == [
        ("s1", "127.0.0.1"), ("s2", "127.0.0.1"), ("s3", "127.0.0.1")
    ]

    report = json.loads(output.read_text(encoding="utf-8"))
    # 兩支腳本的欄位名不同，但統計到的都必須只有 holdout 子集，而不是整份表
    assert report.get("holdout_rows", report.get("rows")) == holdout


def test_evaluator_refuses_to_overwrite_a_previous_result(tmp_path, monkeypatch):
    """一次性評估：輸出已存在就必須拒絕，不能覆寫掉原始數字。"""
    features, metrics, model, _, _ = _write_fixture(tmp_path)
    module = _load_cli("evaluate_openset_holdout.py")
    output = tmp_path / "report.json"
    output.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "evaluate_openset_holdout.py", "--model", str(model),
        "--metrics", str(metrics), "--features", str(features),
        "--output", str(output),
    ])
    assert module.main() == 1
