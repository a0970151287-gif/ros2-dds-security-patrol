"""`工具腳本/select_identification_model.py` 的回歸測試。

這支的用途是**選一個模型出來用**，所以它一旦量錯，錯誤會被帶進下一次重訓。
測試集中在四件會讓「選型」這個結論失效的事：

1. **配對必須真的是配對**——所有臂在第 r 輪必須看到同一個分割，而且分割要
   真的隨 r 改變。分割不變就退化成 2026-09-16 那種單一固定折。
2. **特徵變體只能看訓練折**。`drop_dead` 若用整表決定要丟哪些欄位，就是洩漏。
3. **統計量子集要切到正確的欄位**。切片位置綁在 `AGGREGATE_STATS` 的順序上，
   那個順序在 `compare_session_models.py`，兩邊漂移就會靜默切到別的統計量。
4. **同源檢查要會咬人**。重現不了舊 artifact 就必須拒絕輸出——否則這一支
   可能整個與既有流程分岔，而我們拿它的數字去換掉出貨模型。

⚠️ 真的模型跑在平行的 `~/.venvs/sros2-seqmodel`。這裡多數測試用一個**樁模型**
（可預測、零成本），要的是協定的性質不是學習法的性質。
"""
from __future__ import annotations

import collections
import importlib.util
import json
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_MODULE_PATH = _ROOT / "工具腳本" / "select_identification_model.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "select_identification_model", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sel = _load()
np = pytest.importorskip("numpy")
pytest.importorskip("sklearn")


class _Stub:
    """樁模型：記住每一類的重心，預測最近的那個。確定性，不吃 seed。"""

    def __init__(self, ndim=False):
        self._ndim = ndim
        self.centroids = {}

    def set_params(self, **kwargs):
        self.params = kwargs
        return self

    def fit(self, X, y):
        for label in sorted(set(y)):
            self.centroids[label] = X[np.asarray(y) == label].mean(axis=0)
        return self

    def predict(self, X):
        labels = sorted(self.centroids)
        stacked = np.vstack([self.centroids[k] for k in labels])
        choice = np.array(
            [labels[int(np.argmin(((stacked - row) ** 2).sum(axis=1)))]
             for row in X])
        return choice.reshape(-1, 1) if self._ndim else choice


class _StubFactory:
    """站在 `compare_session_models` 的位置，只提供 `make_model`。"""

    def __init__(self, ndim=False):
        self._ndim = ndim
        self.seeds_seen = []

    def make_model(self, name, seed):
        self.seeds_seen.append((name, seed))
        return _Stub(ndim=self._ndim)


def _toy(n_classes=4, per_class=10, width=3, noise=0.05, seed=0):
    """每類一個重心 ＋ 小雜訊。回傳 (Xs, ys, sessions, width)。"""
    rng = np.random.default_rng(seed)
    centres = rng.normal(size=(n_classes, width)) * 3
    rows, labels, sessions = [], [], []
    for c in range(n_classes):
        for k in range(per_class):
            rows.append(centres[c] + rng.normal(scale=noise, size=width))
            labels.append(f"class{c}")
            sessions.append(f"s{c:02d}_{k:02d}")
    return np.array(rows), np.array(labels), sessions, width


# ── 宣告的空間 ────────────────────────────────────────────────


def test_aggregate_stat_order_matches_the_aggregator():
    """切片位置綁在這個順序上。兩邊漂移就會靜默切到別的統計量。"""
    spec = importlib.util.spec_from_file_location(
        "_cmp_for_test", _ROOT / "工具腳本" / "compare_session_models.py")
    other = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(other)
    assert tuple(other.AGGREGATE_STATS) == sel.AGGREGATE_STATS


def test_declared_variants_and_grid_are_explicit():
    assert sel.VARIANTS[:2] == ("full", "drop_dead")
    assert set(sel.STAT_SUBSETS) <= set(sel.VARIANTS)
    for stats in sel.STAT_SUBSETS.values():
        assert set(stats) <= set(sel.AGGREGATE_STATS)
    # 格點是預先宣告的,跑完不追加。
    assert set(sel.HGB_GRID) == {"learning_rate", "max_leaf_nodes",
                                 "min_samples_leaf", "l2_regularization"}


def test_loader_rejects_a_diverged_aggregator(monkeypatch, tmp_path):
    """統計量順序不一致時必須拒絕載入,而不是算出切錯欄位的分數。"""
    fake = tmp_path / "compare_session_models.py"
    fake.write_text(
        "AGGREGATE_STATS = ('max', 'mean')\n"
        "def aggregate_sessions(*a, **k): pass\n"
        "def make_model(*a, **k): pass\n"
        "def _load_cv(): pass\n", encoding="utf-8")
    monkeypatch.setattr(sel, "_HERE", tmp_path)
    with pytest.raises(sel.SelectError, match="順序"):
        sel._load_compare()


# ── 臂的解析 ──────────────────────────────────────────────────


def test_arm_defaults_to_full_and_no_temporal():
    assert sel.parse_arm("random_forest") == ("random_forest", "full", "none")
    assert sel.parse_arm("rf/drop_dead") == ("rf", "drop_dead", "none")
    assert sel.parse_arm("rf/full/d1_m3_x3") == ("rf", "full", "d1_m3_x3")


@pytest.mark.parametrize("bad", ["rf/made_up", "rf/full/tomorrow", "a/b/c/d"])
def test_undeclared_arm_is_rejected(bad):
    with pytest.raises(sel.SelectError):
        sel.parse_arm(bad)


# ── 特徵變體 ──────────────────────────────────────────────────


def test_full_variant_changes_nothing():
    Xtr, Xte = np.arange(12.0).reshape(4, 3), np.arange(6.0).reshape(2, 3)
    a, b = sel.apply_variant("full", 1, Xtr, Xte)
    assert a is Xtr and b is Xte


def test_drop_dead_decides_on_the_training_fold_only():
    """欄位 1 在訓練折恆為常數、在測試折有變異。

    正確的行為是**丟掉它**——因為決定只能看訓練折。若實作偷看整表或測試折,
    它會被留下來,這個斷言就會失敗。那正是洩漏的樣子。
    """
    Xtr = np.array([[1.0, 5.0, 3.0],
                    [2.0, 5.0, 9.0],
                    [3.0, 5.0, 4.0]])
    Xte = np.array([[1.0, 99.0, 3.0],
                    [2.0, -7.0, 8.0]])
    a, b = sel.apply_variant("drop_dead", 3, Xtr, Xte)
    assert a.shape[1] == 2 and b.shape[1] == 2
    assert not (b == 99.0).any(), "訓練折恆為常數的欄位不可以因為測試折有變異而留下"


def test_drop_dead_refuses_an_all_constant_training_fold():
    Xtr = np.ones((3, 4))
    with pytest.raises(sel.SelectError):
        sel.apply_variant("drop_dead", 4, Xtr, np.ones((2, 4)))


def test_stat_subset_slices_the_declared_blocks():
    """6 個統計量 × 寬度 2。每個區塊填上自己的序號,切完必須拿到正確的區塊。"""
    width = 2
    blocks = [np.full((3, width), float(i))
              for i in range(len(sel.AGGREGATE_STATS))]
    X = np.hstack(blocks)
    for name, wanted in sel.STAT_SUBSETS.items():
        a, _ = sel.apply_variant(name, width, X, X)
        assert a.shape[1] == len(wanted) * width, name
        got = sorted({float(v) for v in a[0]})
        expect = sorted(float(sel.AGGREGATE_STATS.index(s)) for s in wanted)
        assert got == expect, f"{name} 切到了 {got}，應該是 {expect}"


# ── 重複 CV 的協定 ────────────────────────────────────────────


def test_every_session_is_predicted_exactly_once_per_repeat():
    Xs, ys, sessions, width = _toy()
    factory = _StubFactory()
    result = sel.repeated_cv(
        factory, Xs, ys, sessions, width, model="stub", variant="full",
        folds=5, repeats=3)
    hits, totals = result["hits"], result["totals"]
    # 每一輪每一場恰好一次 ⇒ 每類總數 = 輪數 × 每類場次數
    assert set(totals.values()) == {3 * 10}
    assert sum(totals.values()) == 3 * len(sessions)
    assert all(hits[k] <= totals[k] for k in totals)
    assert len(result["per_repeat_class"]) == 3


def test_partitions_actually_change_between_repeats():
    """分割不變的話,重複 CV 就退化成 2026-09-16 那個單一固定折。"""
    from sklearn.model_selection import StratifiedGroupKFold

    _Xs, ys, sessions, _w = _toy()
    assignments = []
    for r in range(3):
        a = np.zeros(len(sessions), dtype=int)
        splitter = StratifiedGroupKFold(n_splits=5, shuffle=True,
                                        random_state=r)
        for k, (_tr, te) in enumerate(
                splitter.split(np.zeros((len(sessions), 1)), ys,
                               groups=np.array(sessions))):
            a[te] = k
        assignments.append(a)
    assert not (assignments[0] == assignments[1]).all()
    assert not (assignments[1] == assignments[2]).all()


def test_each_repeat_uses_its_own_model_seed():
    Xs, ys, sessions, width = _toy()
    factory = _StubFactory()
    sel.repeated_cv(factory, Xs, ys, sessions, width, model="stub",
                    variant="full", folds=5, repeats=4)
    assert {seed for _name, seed in factory.seeds_seen} == {0, 1, 2, 3}


def test_two_dimensional_predict_is_rejected():
    """CatBoost 2026-09-16 就是這樣量到 0.0000——看起來像模型很差。"""
    Xs, ys, sessions, width = _toy()
    with pytest.raises(sel.SelectError, match="一維"):
        sel.repeated_cv(_StubFactory(ndim=True), Xs, ys, sessions, width,
                        model="stub", variant="full", folds=5, repeats=1)


def test_shuffling_labels_destroys_the_score():
    Xs, ys, sessions, width = _toy(noise=0.02)
    factory = _StubFactory()
    real = sel.repeated_cv(factory, Xs, ys, sessions, width, model="stub",
                           variant="full", folds=5, repeats=3)["scores"]
    fake = sel.repeated_cv(factory, Xs, ys, sessions, width, model="stub",
                           variant="full", folds=5, repeats=3,
                           shuffle_labels=True)["scores"]
    assert min(real) > 0.9
    assert max(fake) < 0.6, "打亂之後還很高,代表分數不是來自標籤關聯"


def test_model_kwargs_reach_the_estimator():
    Xs, ys, sessions, width = _toy()

    seen = []

    class _Factory(_StubFactory):
        def make_model(self, name, seed):
            model = super().make_model(name, seed)
            original = model.set_params

            def spy(**kwargs):
                seen.append(kwargs)
                return original(**kwargs)

            model.set_params = spy
            return model

    sel.repeated_cv(_Factory(), Xs, ys, sessions, width, model="stub",
                    variant="full", folds=5, repeats=1,
                    model_kwargs={"learning_rate": 0.05})
    assert seen and all(k == {"learning_rate": 0.05} for k in seen)


# ── 算術上限 ──────────────────────────────────────────────────


def _result(per_repeat_class):
    """從逐輪逐類 recall 反推出 `ceilings` 需要的形狀（每類 10 場）。"""
    hits, totals = collections.Counter(), collections.Counter()
    for recalls in per_repeat_class:
        for label, recall in recalls.items():
            totals[label] += 10
            hits[label] += int(round(recall * 10))
    return {"hits": hits, "totals": totals,
            "per_repeat_class": per_repeat_class}


def test_ceiling_matches_the_existing_definition():
    """沿用 `cross_validate_identification.ceiling()`：(類別數 − 恆零) / 類別數。

    17 類、恆零 1 類 ⇒ 16/17 = 0.9412,就是 CLAUDE.md 記的那個數。
    """
    recalls = {f"c{i}": 0.5 for i in range(17)}
    recalls["c0"] = 0.0
    out = sel.ceilings(_result([recalls]))
    assert out["classes"] == 17
    assert out["ceiling_per_repeat_mean"] == pytest.approx(0.9412, abs=1e-4)
    assert out["never_correct_classes"] == ["c0"]
    assert out["worst_class"] == "c0" and out["worst_class_recall"] == 0.0


def test_pooled_ceiling_is_more_lenient_than_per_repeat():
    """一類只在其中一輪對過 ⇒ 逐輪會算它零、累加不會。兩個尺度必須分開。"""
    good = {"a": 1.0, "b": 1.0}
    only_once = {"a": 1.0, "b": 0.0}
    out = sel.ceilings(_result([good, only_once, only_once, only_once]))
    assert out["ceiling_pooled"] == 1.0            # 累加起來 b 有對過
    assert out["ceiling_per_repeat_mean"] == pytest.approx(0.625)  # (1+.5*3)/4
    assert out["ceiling_per_repeat_min"] == 0.5
    assert out["never_correct_classes"] == []
    assert out["zero_in_how_many_repeats"] == {"b": 3}


def test_a_class_never_correct_lowers_both_ceilings():
    dead = {"a": 1.0, "b": 0.0}
    out = sel.ceilings(_result([dead, dead]))
    assert out["ceiling_pooled"] == 0.5
    assert out["ceiling_per_repeat_mean"] == 0.5
    assert out["never_correct_classes"] == ["b"]


def test_ceiling_refuses_an_empty_result():
    with pytest.raises(sel.SelectError):
        sel.ceilings({"hits": collections.Counter(),
                      "totals": collections.Counter(),
                      "per_repeat_class": []})


def test_ceiling_is_computed_from_the_real_repeated_cv():
    """端到端：樁模型在可分的玩具資料上不該有恆零類別。"""
    Xs, ys, sessions, width = _toy(noise=0.02)
    result = sel.repeated_cv(_StubFactory(), Xs, ys, sessions, width,
                             model="stub", variant="full", folds=5, repeats=3)
    out = sel.ceilings(result)
    assert out["classes"] == 4
    assert out["ceiling_per_repeat_mean"] == 1.0
    assert out["never_correct_classes"] == []


# ── 配對統計 ──────────────────────────────────────────────────


def test_reference_arm_has_exactly_zero_delta():
    scores = {"ref": [0.5, 0.6, 0.7], "other": [0.55, 0.60, 0.80]}
    out = sel.paired_summary(scores, "ref", boots=200)
    assert out["ref"]["paired_delta_vs_reference"] == 0.0
    assert out["ref"]["paired_delta_ci95"] == [0.0, 0.0]
    assert out["ref"]["wins_vs_reference"] == 0
    assert out["ref"]["ties_vs_reference"] == 3


def test_paired_delta_is_the_mean_of_per_repeat_differences():
    scores = {"ref": [0.50, 0.60, 0.70], "other": [0.55, 0.60, 0.80]}
    out = sel.paired_summary(scores, "ref", boots=200)
    assert out["other"]["paired_delta_vs_reference"] == pytest.approx(0.05)
    assert out["other"]["wins_vs_reference"] == 2
    assert out["other"]["ties_vs_reference"] == 1
    assert out["other"]["mean"] == pytest.approx(0.65)


def test_paired_std_is_smaller_than_the_absolute_spread():
    """配對就是為了把共同擾動消掉。這個性質不成立,配對比較就沒有意義。"""
    common = np.array([0.0, 0.08, -0.05, 0.03, -0.06])
    base = 0.60 + common
    other = base + 0.01
    out = sel.paired_summary({"ref": list(base), "o": list(other)}, "ref",
                             boots=200)
    assert out["o"]["paired_std"] == pytest.approx(0.0, abs=1e-9)
    assert out["o"]["std"] > 0.05


def test_unequal_repeat_counts_are_rejected():
    with pytest.raises(sel.SelectError, match="配對"):
        sel.paired_summary({"ref": [0.5, 0.6], "o": [0.5]}, "ref", boots=10)


# ── 同源檢查與 fail-closed ───────────────────────────────────


def test_eval_split_only_accepts_train_validation():
    parser = sel.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--features", "f.csv", "--reference", "rf",
                           "--eval-split", "test"])
    args = parser.parse_args(["--features", "f.csv", "--reference", "rf",
                              "--eval-split", "train_validation"])
    assert args.eval_split == "train_validation"
    assert args.repeats == 12 or args.repeats == 15   # 預設值有記在輸出裡


def _tiny_table(tmp_path, sessions=20, windows=3):
    """兩類、可分的小表,欄位名沿用真實表的必要欄位。

    ⚠️ 標籤**刻意不照 `i % folds` 分配**。同源檢查跑的是舊協定的
    `GroupKFold`,而它對等大小的群組就是照排序輪流指派——標籤若與折數同餘,
    每一折的訓練側都會只剩一個類別。那正是本輪查到的缺陷,不要讓 fixture 也踩。
    """
    rng = np.random.default_rng(7)
    path = tmp_path / "features.csv"
    lines = ["session_id,source,window,label,split,f0,f1"]
    for i in range(sessions):
        label = "normal" if i < sessions // 2 else "attack"
        centre = 0.0 if label == "normal" else 5.0
        for w in range(windows):
            v0 = centre + rng.normal(scale=0.1)
            v1 = rng.normal(scale=0.1)
            lines.append(f"s{i:03d},127.0.0.1,{w},{label},train,{v0},{v1}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_same_source_check_refuses_when_the_legacy_score_does_not_match(
        tmp_path):
    """重現不了舊 artifact 就必須拒絕輸出,而不是照樣給一組新數字。"""
    features = _tiny_table(tmp_path)
    artifact = tmp_path / "legacy.json"
    artifact.write_text(json.dumps(
        {"scores": {"session_aggregate/lda_shrinkage": 0.1234}}),
        encoding="utf-8")
    with pytest.raises(sel.SelectError, match="同源檢查失敗"):
        sel.main(["--features", str(features),
                  "--eval-split", "train_validation",
                  "--reference", "lda_shrinkage",
                  "--arms", "lda_shrinkage",
                  "--legacy-artifact", str(artifact),
                  "--folds", "2", "--repeats", "2", "--skip-control"])


def test_missing_reference_in_the_legacy_artifact_is_refused(tmp_path):
    features = _tiny_table(tmp_path)
    artifact = tmp_path / "legacy.json"
    artifact.write_text(json.dumps({"scores": {}}), encoding="utf-8")
    with pytest.raises(sel.SelectError):
        sel.main(["--features", str(features),
                  "--eval-split", "train_validation",
                  "--reference", "lda_shrinkage", "--arms", "lda_shrinkage",
                  "--legacy-artifact", str(artifact),
                  "--folds", "2", "--repeats", "2", "--skip-control"])


def test_reference_must_be_one_of_the_arms(tmp_path):
    features = _tiny_table(tmp_path)
    with pytest.raises(sel.SelectError, match="參考臂"):
        sel.main(["--features", str(features),
                  "--eval-split", "train_validation",
                  "--reference", "lda_shrinkage", "--arms", "ridge",
                  "--folds", "2", "--repeats", "2", "--skip-control"])


def test_end_to_end_writes_an_auditable_artifact(tmp_path):
    features = _tiny_table(tmp_path)
    out = tmp_path / "out.json"
    assert sel.main(["--features", str(features),
                     "--eval-split", "train_validation",
                     "--reference", "lda_shrinkage",
                     "--arms", "lda_shrinkage", "ridge",
                     "--folds", "2", "--repeats", "3",
                     "--output", str(out)]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["test_rows_used"] == 0
    assert payload["changes_shipped_defaults"] is False
    assert payload["shuffle_control"]["ran"] is True
    # 判準是「亂猜與真實的中點」,不是真實的一半——兩類的亂猜就是 0.5,
    # 用真實的一半當門檻會把一個完全正常的對照誤判成量測壞掉。
    assert payload["shuffle_control"]["bar"] == pytest.approx(0.75)
    assert payload["same_source_check"]["ran"] is False    # 沒給 artifact
    assert payload["repeats"] == 3
    assert len(payload["summary"]["ridge"]["per_repeat"]) == 3
    assert payload["splitter"].startswith("StratifiedGroupKFold")
    # 選型的主判準是上限,所以它必須進 artifact 並且是主排序鍵。
    assert payload["ranking_key"].startswith("ceiling_per_repeat_mean")
    assert set(payload["ranking_by_ceiling"]) == {"lda_shrinkage", "ridge"}
    assert set(payload["ceiling_detail"]) == {"lda_shrinkage", "ridge"}
    for block in payload["summary"].values():
        assert "ceiling_per_repeat_mean" in block
        assert "never_correct_classes" in block


def test_ranking_puts_ceiling_before_mean_score():
    """上限低但分數高的臂不可以排在前面——那正是這個判準要避免的選擇。"""
    summary = {
        "high_score_low_ceiling": {"mean": 0.90, "ceiling_per_repeat_mean":
                                   0.70, "ceiling_pooled": 0.70,
                                   "worst_class_recall": 0.0},
        "low_score_high_ceiling": {"mean": 0.60, "ceiling_per_repeat_mean":
                                   1.00, "ceiling_pooled": 1.00,
                                   "worst_class_recall": 0.2},
    }
    key = lambda kv: (-kv[1]["ceiling_per_repeat_mean"],
                      -kv[1]["ceiling_pooled"],
                      -kv[1]["worst_class_recall"],
                      -kv[1]["mean"])
    assert [a for a, _ in sorted(summary.items(), key=key)] == [
        "low_score_high_ceiling", "high_score_low_ceiling"]

    # 上限打平時,改由**最差類別**決定,不是平均分。
    tied = {
        "better_worst_class": {"mean": 0.60, "ceiling_per_repeat_mean": 1.0,
                               "ceiling_pooled": 1.0,
                               "worst_class_recall": 0.30},
        "higher_mean": {"mean": 0.70, "ceiling_per_repeat_mean": 1.0,
                        "ceiling_pooled": 1.0, "worst_class_recall": 0.05},
    }
    assert [a for a, _ in sorted(tied.items(), key=key)] == [
        "better_worst_class", "higher_mean"]
