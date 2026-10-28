"""Unit tests for the leave-batch-out CV tool (batch_reference_cv.py).

The tool answers H1/H2 of 文件/預測_新campaign的批次校準_2026-10-28.md and runs
on data that does not exist yet. These pin the building blocks against small
synthetic arrays -- C2C-091/114's lesson is that wiring errors only surface
when something actually executes, so the parts are executed here before the
live run.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import numpy as np
import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TOOL = _ROOT / "工具腳本" / "batch_reference_cv.py"


def _load():
    spec = importlib.util.spec_from_file_location("_batch_cv", _TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


BCV = _load()


# ---------------- batch_centre: the three arms ----------------

def _toy():
    # two batches, each with one normal (the benign reference) and two attacks.
    Xs = np.array([
        [10.0, 10.0],   # s0 normal, batch A
        [12.0, 11.0],   # s1 attack, batch A
        [13.0, 12.0],   # s2 attack, batch A
        [20.0, 20.0],   # s3 normal, batch B   (background shifted +10)
        [22.0, 21.0],   # s4 attack, batch B
        [23.0, 22.0],   # s5 attack, batch B
    ])
    ys = ["normal", "a", "b", "normal", "a", "b"]
    sessions = [f"s{i}" for i in range(6)]
    batch_of = {"s0": "A", "s1": "A", "s2": "A",
                "s3": "B", "s4": "B", "s5": "B"}
    return Xs, ys, sessions, batch_of


def test_v0_is_the_identity():
    Xs, ys, sessions, batch_of = _toy()
    out = BCV.batch_centre(Xs, ys, sessions, batch_of, scope="none")
    assert np.array_equal(out, Xs)


def test_v1_removes_the_per_batch_background():
    """The two batches differ only by a +10 background. After subtracting each
    batch's own normal, the attack rows of both batches should coincide -- that
    is exactly the background the single-batch ceiling is about."""
    Xs, ys, sessions, batch_of = _toy()
    out = BCV.batch_centre(Xs, ys, sessions, batch_of, scope="batch")
    # attack 'a' in batch A (row 1) vs batch B (row 4): identical after centering
    assert np.allclose(out[1], out[4])
    assert np.allclose(out[2], out[5])


def test_v1_leaves_out_the_normal_itself():
    """A batch with a single normal: centering it on peers (none) must fall
    back to the global median, not to itself (which would make it the zero
    vector and trivially separable)."""
    Xs, ys, sessions, batch_of = _toy()
    out = BCV.batch_centre(Xs, ys, sessions, batch_of, scope="batch")
    # global normal median is median([10,20])=15, [10,20]... per column:
    # col0 median(10,20)=15, col1 median(10,20)=15
    assert np.allclose(out[0], [10.0 - 15.0, 10.0 - 15.0])
    assert not np.allclose(out[0], [0.0, 0.0]), (
        "a normal centered on itself would be the zero vector -- that is the "
        "leakage boundary 2 this must not cross"
    )


def test_v3_is_global_centering():
    Xs, ys, sessions, batch_of = _toy()
    out = BCV.batch_centre(Xs, ys, sessions, batch_of, scope="global")
    global_med = np.median(Xs[[0, 3]], axis=0)
    assert np.allclose(out, Xs - global_med)


def test_batch_centre_needs_a_normal():
    Xs, ys, sessions, batch_of = _toy()
    ys = ["a", "a", "b", "a", "a", "b"]  # no normal at all
    with pytest.raises(BCV.BatchCvError, match="normal"):
        BCV.batch_centre(Xs, ys, sessions, batch_of, scope="batch")


# ---------------- leakage boundary 3: group isolation ----------------

class _DummyModel:
    def fit(self, X, y):
        self._y = list(y)
        return self

    def predict(self, X):
        return np.array([self._y[0]] * len(X), dtype=object)


class _CmpStub:
    def make_model(self, name, seed):
        return _DummyModel()


class _SelectStub:
    @staticmethod
    def apply_variant(variant, width, Xtr, Xte):
        return Xtr, Xte


def _leaky_splitter(_r):
    class S:
        def split(self, X, y, groups):
            n = len(groups)
            idx = np.arange(n)
            # train and test deliberately share group 0 -> must be caught
            yield idx, idx
    return S()


def test_run_cv_refuses_group_leakage():
    Xs = np.zeros((6, 2))
    ys = np.array(["a", "a", "b", "a", "b", "b"], dtype=object)
    groups = np.array(["A", "A", "A", "B", "B", "B"])
    with pytest.raises(BCV.BatchCvError, match="界線 3"):
        BCV._run_cv(_SelectStub(), _CmpStub(), Xs, ys,
                    [f"s{i}" for i in range(6)], 2,
                    splitter_factory=_leaky_splitter, groups=groups, repeats=1)


# ---------------- _batch_from_manifests ----------------

def test_batch_from_manifests_reads_the_observed_id(tmp_path):
    def _mk(name, status, bid):
        d = tmp_path / name
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({
            "session_id": name,
            "result": {"stack_instance": {"status": status, "id": bid}},
        }), encoding="utf-8")

    _mk("sess_a", "observed", "enforce-111")
    _mk("sess_b", "observed", "enforce-111")
    _mk("sess_c", "unknown", None)  # mid-session restart: excluded
    mapping = BCV._batch_from_manifests(tmp_path)
    assert mapping == {"sess_a": "enforce-111", "sess_b": "enforce-111"}


def test_a_corrupt_manifest_is_skipped_not_fatal(tmp_path):
    good = tmp_path / "ok"
    good.mkdir()
    (good / "manifest.json").write_text(json.dumps({
        "session_id": "ok",
        "result": {"stack_instance": {"status": "observed", "id": "e-1"}},
    }), encoding="utf-8")
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "manifest.json").write_text("{ not json", encoding="utf-8")
    mapping = BCV._batch_from_manifests(tmp_path)
    assert mapping == {"ok": "e-1"}


# ---------------- splitter choice ----------------

def test_lbo_uses_leave_one_group_out_when_batches_are_scarce():
    from sklearn.model_selection import GroupKFold, LeaveOneGroupOut
    assert isinstance(BCV._lbo(5, 3)(0), LeaveOneGroupOut)
    assert isinstance(BCV._lbo(5, 10)(0), GroupKFold)


def test_the_arm_is_frozen():
    assert BCV._ARM == ("random_forest", "full", "d1_m3_x3")
