"""k-of-n pooling: the arithmetic, and the fact that k is now a knob.

`POOLING_K = 3` was frozen in C2C-060 after a sweep on Mahalanobis and
IsolationForest. C2C-076 then replaced the Permissive scorer with max_softmax,
which asks a structurally different question ("does any known class dare claim
this row") -- and 2026-09-25 measured that its best k is **not** 3:

    max_softmax, validation resolution, worst_family unknown recall
        k=1 (any)  0.8889   but normal false alarm 0.1818  -> over budget
        k=2        0.7778         normal false alarm 0.0000
        k=3        0.3333         normal false alarm 0.0000

So a constant that was correct for one scorer silently became wrong for
another. That is the same shape as the three defects in C2C-069: a rule written
under conditions that later changed, still running, still reporting, now
measuring the wrong thing.

These tests cover the pooling arithmetic itself and the threading of k, not the
whole evaluator -- that tool shipped without tests and retro-testing all of it
is a separate job.
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_FULL = _ROOT / "工具腳本" / "evaluate_unknown_at_full_resolution.py"
_SWEEP = _ROOT / "工具腳本" / "sweep_unknown_session_pooling.py"


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


full = _load(_FULL, "_full_resolution")
sweep = _load(_SWEEP, "_pooling_sweep")


# ─────────────────────── the pooling arithmetic ───────────────────────


def _rate(groups, flagged, k):
    import numpy as np

    return full.k_of_n_rate(np.array(groups), np.array(flagged), k)


def test_k_of_one_is_any():
    """k=1 must be exactly `any()` -- the rule C2C-060 measured as a bad trade."""
    groups = ["s1", "s1", "s1", "s2", "s2", "s2"]
    flagged = [True, False, False, False, False, False]
    assert _rate(groups, flagged, 1) == pytest.approx(0.5)


def test_a_session_needs_k_flagged_windows():
    groups = ["s1"] * 4 + ["s2"] * 4
    flagged = [True, True, False, False, True, False, False, False]
    assert _rate(groups, flagged, 2) == pytest.approx(0.5)
    assert _rate(groups, flagged, 3) == pytest.approx(0.0)


def test_raising_k_can_only_lower_the_rate():
    """Monotonic by construction: a stricter rule flags no extra session.

    This is why k trades recall against false alarms rather than improving both.
    """
    groups = ["a"] * 5 + ["b"] * 5 + ["c"] * 5
    flagged = ([True] * 4 + [False]) + ([True] * 2 + [False] * 3) + [False] * 5
    rates = [_rate(groups, flagged, k) for k in (1, 2, 3, 4, 5)]
    assert rates == sorted(rates, reverse=True)


def test_a_session_with_every_window_flagged_counts_at_every_reachable_k():
    groups = ["only"] * 3
    flagged = [True] * 3
    for k in (1, 2, 3):
        assert _rate(groups, flagged, k) == pytest.approx(1.0)
    assert _rate(groups, flagged, 4) == pytest.approx(0.0)


def test_sessions_are_weighted_equally_regardless_of_window_count():
    """One long session must not outvote one short session.

    Window counts vary 6-21 per session in this project, so counting rows would
    let Enforce sessions dominate the statistic.
    """
    groups = ["long"] * 20 + ["short"] * 2
    flagged = [True] * 20 + [False, False]
    assert _rate(groups, flagged, 1) == pytest.approx(0.5)


# ─────────────────────── k is threaded, not hardcoded ───────────────────────


def test_the_default_k_is_still_three():
    """Unchanged behaviour when nobody asks: C2C-060's value stays the default."""
    assert full.POOLING_K == 3
    assert inspect.signature(full.run).parameters["pooling_k"].default == 3
    assert inspect.signature(full.summarise).parameters["pooling_k"].default == 3


def test_the_cli_exposes_k(capsys):
    """Without a flag the constant is unreachable and the wrong k stays frozen."""
    with pytest.raises(SystemExit):
        full.main(["--help"])
    assert "--pooling-k" in capsys.readouterr().out


def _fold(name: str, k2: float, sessions: int = 6) -> dict:
    """A fold shaped the way `summarise` reads it, k=2 only.

    `sessions` is included because `summarise` also builds
    `sessions_per_family`; omitting it made an earlier version of the k test
    below pass on the wrong KeyError.
    """
    return {
        "held_family": name,
        "block": {"sessions": sessions, "rows": sessions * 3,
                  "row_recall": 0.1, "any_recall": 0.9, "k2_recall": k2},
    }


def test_summarise_reports_the_requested_k():
    out = full.summarise([_fold("f1", 0.7), _fold("f2", 0.5)], "block", 2)
    assert "k2_recall" in out
    assert out["k2_recall"]["worst"] == pytest.approx(0.5)
    assert out["k2_recall"]["macro"] == pytest.approx(0.6)


def test_summarise_refuses_a_k_the_folds_do_not_carry():
    """Asking for k=3 out of a k=2 run must fail loudly, not report nothing.

    The fold is otherwise complete, so `k3_recall` is the only thing missing --
    that is what makes this test about k rather than about a typo in the fixture.
    """
    with pytest.raises(KeyError, match="k3_recall"):
        full.summarise([_fold("f1", 0.7)], "block", 3)


# ─────────────── the sweep reports the binding constraint ───────────────


def test_the_sweep_accepts_max_softmax():
    """Codex's `_fit_attack_ood` raises for it, so the sweep could not ask.

    The scorer frozen for Permissive in C2C-076 has to be sweepable, or the
    registered k can never be checked against the scorer it will run with.
    """
    parser = sweep.build_parser()
    action = next(a for a in parser._actions
                  if a.dest == "attack_ood_scorer")
    assert "max_softmax" in action.choices


def test_the_sweep_borrows_the_checked_adapter_instead_of_reimplementing():
    """A third max_softmax implementation would be a third thing to drift.

    C2C-060 recorded that failure mode; the adapter also carries a sign
    self-check, which a fresh copy would not.
    """
    body = _SWEEP.read_text(encoding="utf-8")
    assert "load_scorer_adapter" in body
    assert "evaluate_unknown_at_full_resolution.py" in body
    assert "_scores_max_softmax" not in body


def test_the_adapter_is_the_one_with_the_sign_self_check():
    """Identity would be the wrong assertion -- importlib loads a fresh module.

    What matters is provenance: the function the sweep uses must be *defined in*
    the full-resolution tool, so it inherits that file's sign self-check rather
    than being a lookalike defined somewhere else.
    """
    adapter = sweep.load_scorer_adapter()
    assert adapter.__qualname__ == "fit_attack_ood"
    assert pathlib.Path(adapter.__code__.co_filename).name == _FULL.name


def test_a_scorer_without_a_reference_uses_a_proxy_for_equivalence():
    """max_softmax has no Codex artifact, so faithfulness is proved another way.

    The rebuilt fold loop is checked against a scorer that *does* have a
    reference, in the same process and code path; that property is
    scorer-independent. Without this the max_softmax numbers would rest on an
    unverified rebuild -- exactly what C2C-060's tolerance check exists to stop.
    """
    assert sweep.EQUIVALENCE_PROXY in sweep.SCORERS_WITH_REFERENCE
    assert "max_softmax" not in sweep.SCORERS_WITH_REFERENCE


def test_the_sweep_gates_on_worst_family_not_macro():
    """macro hides a fold at zero: C2C-060's 0.7000 was three 1.0s and a 0.0.

    `worst_family_unknown_recall` is the constraint the acceptance check reads,
    so it is the one the printed gate has to follow.
    """
    body = _SWEEP.read_text(encoding="utf-8")
    assert "worst_family_unknown_recall" in body
    gate = body.index('gate = "✅" if')
    assert "worst >= 0.70" in body[gate:gate + 80]


def test_the_sweep_artifact_declares_the_new_schema():
    """v1 readers must not treat a v2 summary as the same shape."""
    body = _SWEEP.read_text(encoding="utf-8")
    assert "sros2-firewall-unknown-session-pooling/v2" in body


# ─────────────────── the settings have to be in the artifact ───────────────────


def test_the_full_resolution_artifact_records_seed_and_estimators():
    """C2C-076's artifact recorded neither, so nobody could rerun it.

    2026-09-25: the tool at its committed revision would not reproduce its own
    09-24 artifact. Twenty minutes went into ruling out non-determinism (two
    runs agreed bit-for-bit), a venv drift (pinned versions all matched, nothing
    installed since 2026-07-28) and changed data (every fold saw identical
    session and row counts) before the answer turned out to be
    `--seed 20260825 --n-estimators 80` -- the *sweep* tool's defaults, which
    the reference was built with and which this tool does not share.

    "Cannot be rerun" and "the result changed" produce the same error message,
    so an artifact that omits its own settings turns a correct result into a
    suspected regression.
    """
    body = _FULL.read_text(encoding="utf-8")
    report = body[body.index("    report = {"):]
    assert '"seed": args.seed' in report
    assert '"n_estimators": args.n_estimators' in report


def test_the_documented_command_passes_the_settings_it_needs():
    """Following the usage example verbatim used to fail the equivalence check."""
    docstring = full.__doc__ or ""
    usage = docstring[docstring.index("## 用法"):]
    assert "--seed 20260825" in usage
    assert "--n-estimators 80" in usage
    # The example also named a reference file that does not exist on disk.
    named = "文件/未知攻擊場次池化_permissive_2026-09-15.json"
    assert named in usage
    assert (_ROOT / named).is_file()


# ─────────────── a wrong reference must say so, not traceback ───────────────


def test_a_pooling_artifact_used_as_a_reference_is_rejected_clearly(tmp_path):
    """Passing the tool's own previous output gave `KeyError: 'metrics'`.

    That reads like broken code rather than a wrong argument, and this project
    has lost time to misleading failure messages repeatedly (C2C-048, C2C-051,
    C2C-075). The message now names the kind of file the check actually wants.
    """
    wrong = tmp_path / "pooling.json"
    wrong.write_text(json.dumps({
        "schema_version": "sros2-firewall-unknown-session-pooling/v1",
        "folds": [{"held_family": "alert_only",
                   "row": {"unknown_recall": 0.0},
                   "any": {"unknown_recall": 0.0}}],
    }), encoding="utf-8")
    with pytest.raises(sweep.SweepError) as excinfo:
        sweep.check_equivalence([], wrong)
    message = str(excinfo.value)
    assert "family-LOO" in message
    assert "unknown-session-pooling/v1" in message


def test_a_reference_without_folds_is_rejected(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"folds": []}), encoding="utf-8")
    with pytest.raises(sweep.SweepError, match="沒有 folds"):
        sweep.check_equivalence([], empty)


def test_the_check_compares_the_rebuilt_folds_not_the_reference_ones(tmp_path):
    """The bug this catches: a local named `folds` shadowing the parameter.

    2026-09-27 the schema guard above was first written as
    `folds = ref.get("folds")`, which shadowed the rebuilt folds passed in, so
    the loop compared the reference against itself and raised
    `KeyError: 'row'`. Every existing test still passed, because none of them
    called `check_equivalence` with a non-empty fold list -- the two tests above
    pass `[]`, so the loop body never ran.

    This one passes real rebuilt folds and a real reference, and disagrees on
    purpose: the mismatch has to be reported, which is only possible if the
    rebuilt values were the ones read.
    """
    reference = tmp_path / "family_loo.json"
    reference.write_text(json.dumps({
        "schema_version": "sros2-firewall-parallel-gate-family-loo/v1",
        "folds": [{
            "held_family": "alert_only",
            "metrics": {
                "parallel_unknown_recall": 0.25,
                "normal_false_unknown_rate": 0.0,
                "parallel_unknown_session_recall": 0.5,
                "normal_false_unknown_session_rate": 0.0,
            },
        }],
    }), encoding="utf-8")

    rebuilt = [{
        "held_family": "alert_only",
        "row": {"unknown_recall": 0.99, "normal_false_unknown_rate": 0.0},
        "any": {"unknown_recall": 0.5, "normal_false_unknown_rate": 0.0},
    }]
    problems = sweep.check_equivalence(rebuilt, reference)
    assert any("parallel_unknown_recall" in p for p in problems), problems

    rebuilt[0]["row"]["unknown_recall"] = 0.25
    assert sweep.check_equivalence(rebuilt, reference) == []
