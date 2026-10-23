"""The registered settings have to be executable, and the test spendable once.

`preregister_retraining.py` pins the settings and `seal_holdout.py` seals the
test, but until now nothing executed either. The winning formulation
(`session_aggregate`) lived only inside `compare_session_models.py`, a
comparison tool that runs CV, produces no model and never touches test. The gap
between "registered" and "retrained" was a manual hand-off -- exactly where a
setting drifts.

Two orderings in this tool are safety properties, not style:

    verify the seal is unopened  BEFORE any test row is read
    open the seal                AFTER the fit succeeds

The first stops a second evaluation from producing a quotable number. The
second stops a failed fit from spending the whole holdout.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL = _ROOT / "工具腳本" / "retrain_from_registration.py"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


retrain = _load(_TOOL, "_retrain")
prereg = _load(_ROOT / "工具腳本" / "preregister_retraining.py", "_prereg_t")


@pytest.fixture()
def registration():
    return prereg.build_registration()


# ─────────────────── the registration must be obeyed ───────────────────


def test_the_published_registration_can_actually_be_executed(registration):
    """Every setting this tool runs must be present and concrete.

    The first registration failed this: `temporal_expansion` was "enabled",
    which does not say *which* expansion, and `feature_variant` was absent
    entirely -- while the winning arm was named
    `random_forest/full/d1_m3_x3`. A registration that cannot be executed
    unambiguously has not done its one job.
    """
    checked = retrain.check_settings(registration)
    assert set(checked["executed"]) == set(retrain.EXECUTED_SETTINGS)
    assert checked["executed"]["temporal_expansion"] == "d1_m3_x3"
    assert checked["executed"]["feature_variant"] == "full"
    assert checked["executed"]["formulation"] == "session_aggregate"
    assert checked["executed"]["model"] == "random_forest"


def test_the_temporal_setting_is_not_the_tools_default(registration):
    """`compare_session_models.py` defaults to the *other* expansion.

    Anyone retraining with the tool default would silently use
    `d1_m3_x3_m5_x5`, which is not what was selected.
    """
    compare = (_ROOT / "工具腳本" / "compare_session_models.py").read_text(
        encoding="utf-8")
    assert '"--temporal", default="d1_m3_x3_m5_x5"' in compare
    assert registration["settings"]["temporal_expansion"]["value"] == "d1_m3_x3"


def test_an_undecided_setting_stops_the_run(registration):
    """`ood_scorer_enforce` is honestly undecided; filling it in silently is
    how a guess becomes an unrepeatable test number."""
    broken = json.loads(json.dumps(registration))
    broken["settings"]["model"]["value"] = prereg.UNDECIDED
    with pytest.raises(retrain.RetrainError, match="未定"):
        retrain.check_settings(broken)


def test_a_registration_missing_a_setting_is_refused(registration):
    broken = json.loads(json.dumps(registration))
    del broken["settings"]["feature_variant"]
    with pytest.raises(retrain.RetrainError, match="少了這些項目"):
        retrain.check_settings(broken)


def test_a_tampered_registration_is_refused(registration):
    """Matched on the message, not the class.

    `retrain` loads its own copy of the registration module via importlib, so
    its `RegistrationError` is a different class object from the one this file
    imported -- an `except` on identity would pass for the wrong reason.
    Both classes derive from RuntimeError, which is the stable thing to catch.
    """
    broken = json.loads(json.dumps(registration))
    broken["settings"]["model"]["value"] = "hist_gradient_boosting"
    with pytest.raises(RuntimeError, match="註冊自身的雜湊不符"):
        retrain.check_settings(broken)


def test_the_delegated_settings_are_checked_but_not_executed(registration):
    """The unknown-attack half runs elsewhere; pretending otherwise would tie
    two independent evaluations together."""
    checked = retrain.check_settings(registration)
    assert set(checked["delegated"]) == set(retrain.DELEGATED_SETTINGS)
    assert "unknown_session_pooling" in checked["delegated"]
    assert "unknown_session_pooling" not in checked["executed"]


# ─────────────────── the orderings that make it safe ───────────────────


def test_the_seal_is_opened_only_after_the_fit():
    """A failed fit must not cost the holdout."""
    body = _TOOL.read_text(encoding="utf-8")
    fit = body.index("model.fit(Xs[fit_mask]")
    opened = body.index("seal_record = open_seal()")
    predict = body.index("predicted = np.asarray(model.predict")
    assert fit < opened < predict


def test_unopened_is_checked_before_the_features_are_read():
    """`require_unopened` has to come first, so a second run stops before it
    touches data rather than after producing a number someone might quote."""
    body = _TOOL.read_text(encoding="utf-8")
    unopened = body.index("seal_mod.require_unopened(args.seal)")
    fit_call = body.index("result = fit_and_evaluate(")
    assert unopened < fit_call


def test_open_seal_is_passed_as_a_callable_not_a_flag():
    """A boolean would let the call site drift away from the ordering above."""
    import inspect

    assert "open_seal" in inspect.signature(retrain.fit_and_evaluate).parameters
    body = _TOOL.read_text(encoding="utf-8")
    assert "open_seal=lambda: seal_mod.open_once(" in body


# ─────────────────── it refuses the things it should ───────────────────


def test_a_formulation_it_cannot_run_is_refused_not_approximated(tmp_path):
    with pytest.raises(retrain.RetrainError, match="只實作 session_aggregate"):
        retrain.fit_and_evaluate(
            tmp_path / "x.csv", formulation="per_window_pooled",
            model_name="random_forest", temporal="d1_m3_x3",
            feature_variant="full", seed=1, open_seal=lambda: None)


def test_a_feature_variant_it_cannot_run_is_refused(tmp_path):
    with pytest.raises(retrain.RetrainError, match="只實作 full"):
        retrain.fit_and_evaluate(
            tmp_path / "x.csv", formulation="session_aggregate",
            model_name="random_forest", temporal="d1_m3_x3",
            feature_variant="drop_dead", seed=1, open_seal=lambda: None)


def test_the_cli_refuses_to_overwrite_its_output(tmp_path, capsys):
    target = tmp_path / "out.json"
    target.write_text("{}", encoding="utf-8")
    code = retrain.main([
        "--registration", str(tmp_path / "r.json"),
        "--features", str(tmp_path / "f.csv"),
        "--seal", str(tmp_path / "s.json"),
        "--output", str(target),
    ])
    assert code == 2
    assert target.read_text(encoding="utf-8") == "{}"


# ─────────────────── the artifact remembers how to rerun ───────────────────


def test_the_artifact_records_everything_that_moves_the_numbers():
    """2026-09-25: a tool that omitted seed and n_estimators could not
    reproduce its own previous day's result, and "cannot rerun" reads exactly
    like "the result changed"."""
    body = _TOOL.read_text(encoding="utf-8")
    report = body[body.index("    report = {"):]
    for field in ('"seed"', '"executed_settings"', '"registration_sha256"',
                  '"features_sha256"', '"test_sessions_sha256"'):
        assert field in report, field


def test_sessions_may_not_straddle_two_splits():
    """A per-row split would put the same session in train and test.

    C2C-035's stream bug was the same shape: a row-level operation quietly
    violating a session-level invariant.
    """
    body = _TOOL.read_text(encoding="utf-8")
    assert "split 不一致" in body
    assert 'len(values) > 1' in body


def test_predictions_must_be_one_dimensional():
    """CatBoost 2026-09-16 returned (n, 1) and scored exactly 0.0000, which
    looked like a terrible model rather than a broken comparison."""
    body = _TOOL.read_text(encoding="utf-8")
    assert "predicted.ndim != 1" in body
