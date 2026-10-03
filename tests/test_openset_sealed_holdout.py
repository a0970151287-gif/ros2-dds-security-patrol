"""The open-set half must go through the seal, and the three defects the
rehearsal caught must stay caught.

Until 2026-10-03 the identification half had an indivisible path (verify
registration, verify seal, fit, open once, evaluate, write) and the open-set
half had only "refuse to overwrite the output" -- which a different --output
path walks straight past. That is not hypothetical: the project's own backlog
records the previous holdout as spent three times.

Rehearsing the new path on the already-spent 2026-09-03 holdout caught three
real defects before any fresh holdout was touched:

  1. an uninformative refusal when the wrong training_metrics was passed
  2. the seal's scope name used where the feature column's value belongs
  3. the recall denominator including the holdout sessions' `normal` rows
     -- 161 of 537, so the number would have been wrong by 30% in the
     denominator, on a holdout that can only be opened once

These tests pin all three, plus the ordering and the refusals.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TOOL = _ROOT / "工具腳本" / "evaluate_openset_from_registration.py"
_SEAL = _ROOT / "工具腳本" / "seal_holdout.py"


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tool():
    return _load(_TOOL, "_openset_tool")


def _seal():
    return _load(_SEAL, "_seal_mod")


# ---------- defect 2: two vocabularies that must not be interchanged ----------

def test_the_scope_name_and_the_column_value_are_not_the_same_string():
    """The rehearsal's second defect.

    `novelty_holdout` names the seal's scope; `novelty_holdout_candidate` is
    the value in the feature table's `novelty_role` column. Comparing the
    column against the scope name matched nothing, and "matched nothing"
    reads the same as "there is no holdout" until someone checks.
    """
    tool, seal = _tool(), _seal()
    assert tool.REQUIRED_SCOPE == "novelty_holdout"
    assert seal.HOLDOUT_ROLE == "novelty_holdout_candidate"
    assert tool.REQUIRED_SCOPE != seal.HOLDOUT_ROLE


def test_the_tool_takes_the_column_value_from_the_seal_module():
    """One source of truth, so the two cannot drift apart again."""
    source = _TOOL.read_text(encoding="utf-8")
    assert "seal_mod.HOLDOUT_ROLE" in source
    assert 'frame["novelty_role"].astype(str) == REQUIRED_SCOPE' not in source


# ---------- defect 3: the recall denominator ----------

def test_the_recall_denominator_is_labels_not_sessions():
    """The rehearsal's third and most consequential defect.

    `novelty_role` marks whole sessions, and 393 of 550 sessions carry both
    normal and attack rows (C2C-035). So a holdout session's normal rows are
    marked too -- 161 of 537 in the rehearsal. Counting them as "unknown
    attack" opportunities depresses recall by 30% in the denominator, and a
    sealed holdout only opens once, so there is no second chance to notice.
    """
    source = _TOOL.read_text(encoding="utf-8")
    assert "np.flatnonzero(official & np.isin(labels, holdout_labels))" in source, (
        "the evaluated rows must be the holdout labels' rows, not every row "
        "of the holdout sessions"
    )
    # 兩個層級都要被記下來，否則讀者無法檢查分母
    for key in ("holdout_rows_evaluated", "holdout_session_rows_total",
                "holdout_normal_rows_excluded"):
        assert f'"{key}"' in source


def test_the_exclusion_from_fitting_is_still_session_level():
    """Sessions are excluded whole; only the *evaluation* is label-level.

    Excluding by label would leave the holdout sessions' normal rows in the
    fit, and those rows share a session -- and therefore a traffic context --
    with the held-out attack.
    """
    source = _TOOL.read_text(encoding="utf-8")
    assert "base_train = (split == \"train\") & ~official" in source
    assert "validation = (split == \"validation\") & ~official" in source


# ---------- the seal's scope ----------

def test_a_seal_without_a_scope_is_read_as_the_legacy_scope():
    """Absent is provenance, not a guess: the field was added 2026-10-03, and
    every seal written before it sealed `split == test` by definition."""
    seal = _seal()
    assert seal.scope_of({}) == seal.LEGACY_SCOPE == "test"


def test_an_unrecognised_scope_is_refused_and_never_defaulted():
    """Absent and unreadable are different. Defaulting an unreadable scope
    would let a seal be consumed as some other seal entirely."""
    seal = _seal()
    with pytest.raises(seal.SealError, match="不認識的封印 scope"):
        seal.scope_of({"scope": "something_else"})


def test_the_wrong_scope_cannot_burn_the_other_halfs_holdout(tmp_path):
    """Both seals share a schema, so without this check they are swappable --
    and swapping them means one evaluator spends the other's holdout."""
    seal = _seal()
    path = tmp_path / "seal.json"
    path.write_text(json.dumps({
        "schema_version": seal.SCHEMA, "scope": "test", "opened": False,
    }), encoding="utf-8")
    with pytest.raises(seal.SealError, match="scope"):
        seal.require_unopened(path, expected_scope="novelty_holdout")
    # 同一份封印在它自己的 scope 下是可以用的
    assert seal.require_unopened(path, expected_scope="test")["scope"] == "test"


def test_the_evaluator_actually_asks_for_the_scope_it_needs():
    """Testing the mechanism is not testing the wiring.

    The first version of this file checked that `require_unopened` honours
    `expected_scope` -- and passed unchanged when the evaluator's own call
    site dropped the argument. That is the same defect as the `--scope` flag
    that existed before it reached `create_seal`, and as `stream_replay.py`,
    which was written, tested, and imported by nobody for a month (C2C-038).
    """
    source = _TOOL.read_text(encoding="utf-8")
    assert (
        "seal_mod.require_unopened(args.seal, expected_scope=REQUIRED_SCOPE)"
        in source
    ), "the evaluator must demand the novelty_holdout scope, not any seal"


def test_the_cli_actually_passes_the_scope_through():
    """The argument existed before it was wired to create_seal.

    `stream_replay.py` was written, tested, and imported by nobody for a
    month (C2C-038); the same shape appeared here within one edit.
    """
    source = _SEAL.read_text(encoding="utf-8")
    assert "create_seal(args.features, args.registration, args.scope)" in source


# ---------- settings and ordering ----------

def test_an_undecided_scorer_is_refused_for_that_mode():
    """r4 leaves `ood_scorer_enforce` undecided because C2C-088 measured all
    24 declared cells at 0.0000 -- the choice provably cannot matter there.
    Filling it in to make the tool run would spend the holdout on a guess."""
    tool = _tool()
    prereg = _load(_ROOT / "工具腳本" / "preregister_retraining.py", "_pre")
    registration = {
        "settings": {
            "ood_scorer_permissive": {"value": "max_softmax"},
            "ood_scorer_enforce": {"value": prereg.UNDECIDED},
            "unknown_session_pooling": {"value": "k_of_n_k2"},
        }
    }
    with pytest.raises(tool.OpenSetError, match="未定"):
        tool.check_settings(registration, "enforce")


def test_a_missing_setting_is_refused_rather_than_assumed():
    tool = _tool()
    registration = {"settings": {"ood_scorer_permissive": {"value": "max_softmax"}}}
    with pytest.raises(tool.OpenSetError, match="註冊少了"):
        tool.check_settings(registration, "permissive")


@pytest.mark.parametrize("value", ["k_of_n_k2", "k_of_n_k1", "k_of_n_k13"])
def test_the_pooling_setting_parses_to_its_k(value):
    tool = _tool()
    assert tool.parse_pooling(value) == int(value[len("k_of_n_k"):])


@pytest.mark.parametrize("value", ["any", "k_of_n", "k_of_n_k0", "k_of_n_kx",
                                   "proportion_50", "", None, 2])
def test_an_unrecognised_pooling_setting_is_refused(value):
    tool = _tool()
    with pytest.raises(tool.OpenSetError):
        tool.parse_pooling(value)


def test_the_seal_opens_only_after_fitting():
    """Order is a safety property, not style.

    Opening before fitting means one failed fit spends the whole holdout;
    the identification path (C2C-086) settled on the same order for the same
    reason. `open_seal` is passed as a callable so the call site cannot drift
    away from the order.
    """
    source = _TOOL.read_text(encoding="utf-8")
    fit_at = source.index("attack_ood = full.fit_attack_ood(")
    open_at = source.index("seal_record = open_seal()")
    eval_at = source.index("unknown_i = np.flatnonzero(")
    assert fit_at < open_at < eval_at, (
        "the seal must open after the fit and before the holdout is read"
    )
    assert "open_seal=lambda: seal_mod.open_once(" in source


def test_the_unopened_check_precedes_any_holdout_read():
    """`require_unopened` has to run before the evaluator touches a row, so
    a second attempt stops before the data rather than after a number exists."""
    source = _TOOL.read_text(encoding="utf-8")
    require_at = source.index("seal_mod.require_unopened(")
    evaluate_at = source.index("report = evaluate(")
    assert require_at < evaluate_at


def test_leakage_assertions_cover_every_fitting_partition():
    """A holdout row in any of fit/threshold/reference leaks the answer."""
    source = _TOOL.read_text(encoding="utf-8")
    for name in ("fit", "threshold", "normal_reference", "known_reference"):
        assert f'("{name}"' in source
    assert "holdout 列漏進了" in source


# ---------- provenance ----------

def test_the_artifact_records_everything_that_moves_the_number():
    """2026-09-25's lesson: an artifact that does not record its own seed and
    n_estimators cannot reproduce itself, and "cannot reproduce" reads exactly
    like "the result changed"."""
    source = _TOOL.read_text(encoding="utf-8")
    for key in ("seed", "n_estimators", "maximum_normal_fpr",
                "maximum_known_attack_ood_fpr", "registration_sha256",
                "executed_settings", "features_path", "metrics_path"):
        assert f'"{key}"' in source


def test_it_reuses_the_measured_helpers_rather_than_reimplementing_them():
    """Two implementations drift (C2C-060), and here the cost is sharper: the
    holdout opens once, so an evaluator that disagrees with the validation
    measurements spends the only chance on a number that cannot be compared."""
    source = _TOOL.read_text(encoding="utf-8")
    assert 'evaluate_unknown_at_full_resolution.py' in source
    for helper in ("load_codex_module", "fit_attack_ood", "k_of_n_rate"):
        assert helper in source
    assert "from firewall_lab.hierarchical_training import" in source


def test_it_declares_that_it_changes_no_shipping_default():
    source = _TOOL.read_text(encoding="utf-8")
    assert '"changes_shipped_defaults": False,' in source
