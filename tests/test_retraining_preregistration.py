"""The settings for the next retraining, pinned before the data exists.

Every identification setting this project uses was chosen on cross-validation
between 2026-09-15 and 2026-09-19. Each round honestly wrote "CV is not a
held-out test, the percentage does not move" -- but the rounds *together* are
a search, and a search whose endpoint can still move after seeing the new test
makes that test dependent on it.

C2C-028 already recorded the weak form: the scorer was chosen entirely on
training rows and the holdout never participated, yet knowing how it had failed
last time steered the search. That round disclosed it as weak contamination.
This registration exists so the next round does not even have that.

What is tested here is not that the settings are good -- they are still only CV
choices. It is that they cannot be changed quietly between now and the test.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL = _ROOT / "工具腳本" / "preregister_retraining.py"


def _load():
    spec = importlib.util.spec_from_file_location("_prereg", _TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_prereg"] = module
    spec.loader.exec_module(module)
    return module


prereg = _load()


@pytest.fixture()
def registration():
    return prereg.build_registration()


# ─────────────────────── every setting is backed ───────────────────────


def test_every_setting_cites_a_file_that_exists(registration):
    for name, spec in registration["settings"].items():
        path = _ROOT / spec["evidence_path"]
        assert path.is_file(), f"{name} cites a missing file: {spec['evidence_path']}"


def test_every_setting_pins_the_size_and_digest_of_its_evidence(registration):
    for name, spec in registration["settings"].items():
        data = (_ROOT / spec["evidence_path"]).read_bytes()
        assert spec["evidence_bytes"] == len(data), name
        assert len(spec["evidence_sha256"]) == 64, name


def test_a_setting_with_no_evidence_file_is_refused(monkeypatch):
    """A registration whose citation cannot be checked is not a registration."""
    broken = copy.deepcopy(prereg.SETTINGS)
    broken["formulation"] = dict(broken["formulation"], evidence="文件/不存在.md")
    monkeypatch.setattr(prereg, "SETTINGS", broken)
    with pytest.raises(prereg.RegistrationError, match="證據檔案不存在"):
        prereg.build_registration()


# ─────────────────── undecided must stay undecided ───────────────────


def test_the_enforce_scorer_is_registered_as_undecided(registration):
    """Two measurements contradict each other, so there is no choice to pin.

    A setting that pretends to be decided is more dangerous than an honest
    blank: it would let the next round claim the value was pre-registered.
    """
    assert registration["settings"]["ood_scorer_enforce"]["value"] == prereg.UNDECIDED
    assert "ood_scorer_enforce" in registration["undecided"]


def test_filling_in_an_undecided_setting_is_a_mismatch(registration):
    result = prereg.verify_registration(
        registration, actual={"ood_scorer_enforce": "mahalanobis"}
    )
    assert result["valid"] is False
    assert any("未定" in m for m in result["settings_mismatched"])


def test_leaving_an_undecided_setting_undecided_is_fine(registration):
    result = prereg.verify_registration(
        registration, actual={"ood_scorer_enforce": prereg.UNDECIDED}
    )
    assert result["settings_mismatched"] == []


# ─────────────────── the registration cannot be edited ───────────────────


def test_a_matching_registration_verifies(registration):
    assert prereg.verify_registration(registration)["valid"] is True


def test_editing_a_value_breaks_the_self_digest(registration):
    tampered = copy.deepcopy(registration)
    tampered["settings"]["model"]["value"] = "hist_gradient_boosting"
    with pytest.raises(prereg.RegistrationError, match="註冊自身的雜湊不符"):
        prereg.verify_registration(tampered)


def test_editing_a_rationale_also_breaks_it(registration):
    """The reason is part of the record, not decoration."""
    tampered = copy.deepcopy(registration)
    tampered["settings"]["model"]["rationale"] = "because I like it"
    with pytest.raises(prereg.RegistrationError, match="註冊自身的雜湊不符"):
        prereg.verify_registration(tampered)


def test_an_unknown_schema_is_refused(registration):
    tampered = dict(registration, schema_version="something/v9")
    with pytest.raises(prereg.RegistrationError, match="未知的 schema"):
        prereg.verify_registration(tampered)


# ─────────────── the actual run must match what was registered ───────────────


def test_a_changed_setting_at_training_time_is_caught(registration):
    result = prereg.verify_registration(
        registration, actual={"model": "hist_gradient_boosting"}
    )
    assert result["valid"] is False
    assert any("model" in m for m in result["settings_mismatched"])


def test_the_registered_settings_pass(registration):
    actual = {k: v["value"] for k, v in registration["settings"].items()}
    assert prereg.verify_registration(registration, actual=actual)["valid"] is True


def test_evidence_drift_is_reported_without_being_called_fraud(registration, tmp_path):
    """A cited document evolving is expected; it is not tampering.

    C2C-033 set the precedent: an immutable checkpoint whose cited files later
    change means "valid when generated", not "falsified". The verifier reports
    the drift separately from a settings mismatch so the two cannot be confused.
    """
    tampered = copy.deepcopy(registration)
    spec = tampered["settings"]["model"]
    spec["evidence_sha256"] = "0" * 64
    tampered["registration_sha256"] = None  # recompute below
    body = {k: v for k, v in tampered.items() if k != "registration_sha256"}
    import hashlib
    tampered["registration_sha256"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    result = prereg.verify_registration(tampered)
    assert result["evidence_drifted"] == [spec["evidence_path"]]
    assert result["settings_mismatched"] == []


# ─────────────────── the choices that were superseded ───────────────────


def test_superseded_choices_are_recorded_not_erased(registration):
    """Three settings reversed an earlier recommendation. Say which and why.

    The model and the temporal setting both flipped when the fold defect was
    found; the Permissive scorer reversed C2C-028. A registration that only
    showed the winners would hide that the search moved.
    """
    superseded = {
        name for name, spec in registration["settings"].items()
        if spec["supersedes_earlier_choice"]
    }
    assert {"model", "temporal_expansion", "ood_scorer_permissive"} <= superseded


def test_the_pooling_choice_admits_it_was_picked_after_seeing_results(registration):
    """k=3 was the best of a pre-declared sweep -- the sweep was registered, the
    winner was not. That is exactly what this file is for, so it must say so."""
    note = registration["settings"]["unknown_session_pooling"]["supersedes_earlier_choice"]
    assert note and "看過" in note


# ─────────────────── the protocol around the sealed test ───────────────────


def test_the_sealed_test_protocol_is_recorded(registration):
    rules = registration["sealed_test_protocol"]
    assert len(rules) >= 5
    joined = " ".join(rules)
    assert "一次" in joined          # evaluate once
    assert "拒絕覆寫" in joined      # refuse to overwrite
    assert "不得再調" in joined      # no tuning afterwards


def test_the_registration_disclaims_quality(registration):
    """It proves nobody swapped the values. It does not prove they are right."""
    assert "不宣稱任何設定是好的" in registration["claims_nothing_about_quality"]


# ─────────────────────── the published artifact ───────────────────────


def test_the_published_registration_still_verifies():
    published = _ROOT / "文件" / "重訓預先註冊_2026-09-25.json"
    if not published.is_file():
        pytest.skip("registration not published in this tree")
    result = prereg.verify_registration(
        json.loads(published.read_text(encoding="utf-8"))
    )
    assert result["settings_mismatched"] == []
    # evidence_drifted may be non-empty later; that is expected drift, not failure


def test_the_cli_refuses_to_overwrite(tmp_path):
    target = tmp_path / "reg.json"
    target.write_text("{}", encoding="utf-8")
    assert prereg.main(["--output", str(target)]) == 2
    assert target.read_text(encoding="utf-8") == "{}"
