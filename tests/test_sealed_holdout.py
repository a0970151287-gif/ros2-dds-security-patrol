"""Evaluate-once, enforced by a file rather than by remembering.

This project's open-set holdout has been spent three times (C2C-054). Each
time the reason was the same: nothing stopped it. The numbers were disclosed
honestly afterwards -- "the holdout has been used a third time, so it is not
citable" -- but disclosure after the fact does not give back an independent
test.

A seal binds three things, and dropping any one of them leaves a way round:

    the test session list   -- or the sessions inside test could be swapped
    the feature table       -- or features could be re-extracted under an old seal
    the pre-registration    -- or settings could be chosen after sealing

Opening is a one-way write. The evaluator has to open before it may read test
rows, so a second run stops before it touches data, not after it produces a
number someone might quote.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL = _ROOT / "工具腳本" / "seal_holdout.py"


def _load():
    spec = importlib.util.spec_from_file_location("_seal", _TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_seal"] = module
    spec.loader.exec_module(module)
    return module


seal_mod = _load()


def _features(tmp_path, rows=None) -> pathlib.Path:
    rows = rows or [
        ("s1", "train"), ("s2", "train"), ("s3", "validation"),
        ("s4", "test"), ("s5", "test"), ("s6", "test"),
    ]
    path = tmp_path / "features.csv"
    lines = ["group_id,split,value"]
    lines += [f"{g},{s},1.0" for g, s in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _registration(tmp_path, sha: str | None = None) -> pathlib.Path:
    path = tmp_path / "reg.json"
    body = {"schema_version": "x", "registration_sha256": sha or ("a" * 64)}
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


@pytest.fixture()
def sealed(tmp_path):
    features = _features(tmp_path)
    registration = _registration(tmp_path)
    seal = seal_mod.create_seal(features, registration)
    path = tmp_path / "seal.json"
    path.write_text(json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True),
                    encoding="utf-8")
    return {"path": path, "seal": seal, "features": features,
            "registration": registration}


# ─────────────────────── what the seal binds ───────────────────────


def test_the_seal_records_exactly_the_test_sessions(sealed):
    assert sealed["seal"]["test_sessions"] == ["s4", "s5", "s6"]
    assert sealed["seal"]["test_session_count"] == 3


def test_the_session_hash_ignores_row_order(tmp_path):
    """Order is an artefact of extraction, not part of the holdout's identity."""
    a = seal_mod.create_seal(
        _features(tmp_path, [("s4", "test"), ("s5", "test")]),
        _registration(tmp_path),
    )
    other = tmp_path / "b"
    other.mkdir()
    b = seal_mod.create_seal(
        _features(other, [("s5", "test"), ("s4", "test")]),
        _registration(other),
    )
    assert a["test_sessions_sha256"] == b["test_sessions_sha256"]


def test_swapping_which_sessions_are_in_test_breaks_the_seal(sealed, tmp_path):
    """The failure the session hash exists to catch."""
    swapped = _features(tmp_path, [
        ("s1", "train"), ("s2", "test"), ("s3", "validation"),
        ("s4", "test"), ("s5", "test"), ("s6", "train"),
    ])
    result = seal_mod.verify_seal(sealed["seal"], swapped)
    assert result["valid"] is False
    assert any("特徵表" in p for p in result["problems"])


def test_re_extracting_features_breaks_the_seal(sealed, tmp_path):
    """Same test sessions, different table -- the seal must not carry over."""
    same_sessions = _features(tmp_path, [
        ("s1", "train"), ("s2", "train"), ("s3", "validation"),
        ("s4", "test"), ("s5", "test"), ("s6", "test"),
    ])
    same_sessions.write_text(
        same_sessions.read_text(encoding="utf-8").replace("1.0", "2.0"),
        encoding="utf-8",
    )
    result = seal_mod.verify_seal(sealed["seal"], same_sessions)
    assert result["valid"] is False
    assert any("特徵表已經變動" in p for p in result["problems"])


def test_the_seal_carries_the_registration_digest(sealed):
    """Settings must be fixed before the holdout is sealed, not after."""
    assert sealed["seal"]["registration_sha256"] == "a" * 64


def test_a_registration_without_a_digest_is_refused(tmp_path):
    bad = tmp_path / "reg.json"
    bad.write_text(json.dumps({"schema_version": "x"}), encoding="utf-8")
    with pytest.raises(seal_mod.SealError, match="registration_sha256"):
        seal_mod.create_seal(_features(tmp_path), bad)


def test_a_table_with_no_test_rows_is_refused(tmp_path):
    """Sealing nothing would read as a valid seal for ever after."""
    features = _features(tmp_path, [("s1", "train"), ("s2", "validation")])
    with pytest.raises(seal_mod.SealError, match="沒有任何 split=test"):
        seal_mod.create_seal(features, _registration(tmp_path))


@pytest.mark.parametrize("column", ["split", "group_id"])
def test_a_table_missing_a_required_column_is_refused(tmp_path, column):
    path = tmp_path / "features.csv"
    header = ",".join(c for c in ("group_id", "split", "value") if c != column)
    path.write_text(header + "\n", encoding="utf-8")
    with pytest.raises(seal_mod.SealError, match=column):
        seal_mod.read_test_sessions(path)


# ─────────────────────── opening happens once ───────────────────────


def test_a_fresh_seal_is_unopened(sealed):
    assert sealed["seal"]["opened"] is False
    assert seal_mod.require_unopened(sealed["path"])["opened"] is False


def test_opening_records_when_and_why(sealed):
    opened = seal_mod.open_once(sealed["path"], "final evaluation")
    assert opened["opened"] is True
    assert opened["opened_reason"] == "final evaluation"
    assert opened["opened_utc"]


def test_opening_twice_is_refused(sealed):
    seal_mod.open_once(sealed["path"], "final evaluation")
    with pytest.raises(seal_mod.SealError, match="已經在"):
        seal_mod.open_once(sealed["path"], "just one more look")


def test_the_refusal_says_why_a_second_number_is_not_citable(sealed):
    seal_mod.open_once(sealed["path"], "final evaluation")
    with pytest.raises(seal_mod.SealError, match="不可引用"):
        seal_mod.open_once(sealed["path"], "again")


def test_opening_without_a_reason_is_refused(sealed):
    for blank in ("", "   "):
        with pytest.raises(seal_mod.SealError, match="必須寫理由"):
            seal_mod.open_once(sealed["path"], blank)


def test_the_open_state_survives_on_disk(sealed):
    seal_mod.open_once(sealed["path"], "final evaluation")
    reloaded = json.loads(sealed["path"].read_text(encoding="utf-8"))
    assert reloaded["opened"] is True


def test_the_evaluator_gate_refuses_after_opening(sealed):
    """The point: it stops before reading data, not after producing a number."""
    seal_mod.open_once(sealed["path"], "final evaluation")
    with pytest.raises(seal_mod.SealError, match="不可再讀 test 列"):
        seal_mod.require_unopened(sealed["path"])


def test_a_broken_seal_cannot_be_opened(sealed):
    """Opening a seal that no longer describes its own contents proves nothing."""
    tampered = json.loads(sealed["path"].read_text(encoding="utf-8"))
    tampered["test_sessions"].append("s7")
    sealed["path"].write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(seal_mod.SealError, match="封印不成立"):
        seal_mod.open_once(sealed["path"], "final evaluation")


# ─────────────────── self-consistency of the record ───────────────────


def test_editing_the_session_list_is_detected(sealed):
    tampered = dict(sealed["seal"])
    tampered["test_sessions"] = ["s4", "s5"]
    result = seal_mod.verify_seal(tampered)
    assert result["valid"] is False


def test_editing_the_count_is_detected(sealed):
    tampered = dict(sealed["seal"], test_session_count=99)
    result = seal_mod.verify_seal(tampered)
    assert result["valid"] is False


def test_an_unknown_schema_is_refused(sealed):
    with pytest.raises(seal_mod.SealError, match="未知的 schema"):
        seal_mod.verify_seal(dict(sealed["seal"], schema_version="other/v9"))


def test_an_intact_seal_verifies_against_its_own_table(sealed):
    result = seal_mod.verify_seal(sealed["seal"], sealed["features"])
    assert result["valid"] is True
    assert result["problems"] == []


# ─────────────────────── the CLI ───────────────────────


def test_the_cli_refuses_to_overwrite_a_seal(tmp_path):
    features = _features(tmp_path)
    registration = _registration(tmp_path)
    target = tmp_path / "seal.json"
    target.write_text("{}", encoding="utf-8")
    code = seal_mod.main([
        "seal", "--features", str(features),
        "--registration", str(registration), "--output", str(target),
    ])
    assert code == 2
    assert target.read_text(encoding="utf-8") == "{}"


def test_the_cli_seals_and_then_reports_status(tmp_path, capsys):
    features = _features(tmp_path)
    registration = _registration(tmp_path)
    target = tmp_path / "seal.json"
    assert seal_mod.main([
        "seal", "--features", str(features),
        "--registration", str(registration), "--output", str(target),
    ]) == 0
    capsys.readouterr()
    assert seal_mod.main(["status", "--seal", str(target),
                          "--features", str(features)]) == 0
    out = capsys.readouterr().out
    assert "已開封      : False" in out


def test_the_cli_status_reports_a_broken_seal_nonzero(tmp_path):
    features = _features(tmp_path)
    target = tmp_path / "seal.json"
    seal_mod.main(["seal", "--features", str(features),
                   "--registration", str(_registration(tmp_path)),
                   "--output", str(target)])
    features.write_text(features.read_text(encoding="utf-8").replace("1.0", "9.9"),
                        encoding="utf-8")
    assert seal_mod.main(["status", "--seal", str(target),
                          "--features", str(features)]) == 1
