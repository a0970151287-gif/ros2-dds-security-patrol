"""`MahalanobisNoveltyDetector` 的界線與訓練線接點。"""

from __future__ import annotations

import numpy as np
import pytest

from firewall_lab.hierarchical_training import ATTACK_OOD_SCORERS
from firewall_lab.ood_scorers import MahalanobisNoveltyDetector


def _two_clusters(rng):
    a = rng.normal(loc=0.0, scale=0.5, size=(60, 6))
    b = rng.normal(loc=6.0, scale=0.5, size=(60, 6))
    x = np.concatenate([a, b])
    y = np.array(["a"] * 60 + ["b"] * 60)
    return x, y


def test_score_is_lower_for_points_far_from_every_known_centroid():
    """這正是它取代 IsolationForest 的理由：離群但**不極端**也要被抓到。

    第三群刻意放在兩個已知群的正中間——密度式評分會把它當成中央的密集區，
    距離式評分看到的是「離每個中心都遠」。
    """
    rng = np.random.default_rng(20260825)
    x, y = _two_clusters(rng)
    detector = MahalanobisNoveltyDetector().fit(x, y)

    between = rng.normal(loc=3.0, scale=0.5, size=(40, 6))
    assert detector.score_samples(between).mean() < detector.score_samples(x).mean()


def test_score_samples_is_lower_when_more_anomalous():
    """方向必須與 IsolationForest 一致，否則模型端的門檻比較會反過來。"""
    rng = np.random.default_rng(11)
    x, y = _two_clusters(rng)
    detector = MahalanobisNoveltyDetector().fit(x, y)

    near = detector.score_samples(np.zeros((1, 6)))[0]
    far = detector.score_samples(np.full((1, 6), 40.0))[0]
    assert far < near


def test_singular_covariance_is_tolerated():
    """來源不可得的特徵恆為零，共變異必然奇異；不可以炸掉。"""
    rng = np.random.default_rng(3)
    x, y = _two_clusters(rng)
    x = np.concatenate([x, np.zeros((len(x), 3))], axis=1)  # 三個恆零欄位
    detector = MahalanobisNoveltyDetector().fit(x, y)
    scores = detector.score_samples(x)
    assert np.isfinite(scores).all()


def test_labels_are_required():
    """沒有標籤就退化成單一中心，等於丟掉這個評分器唯一的優勢。"""
    rng = np.random.default_rng(5)
    x, _ = _two_clusters(rng)
    with pytest.raises(ValueError, match="requires class labels"):
        MahalanobisNoveltyDetector().fit(x)


def test_single_class_is_rejected():
    rng = np.random.default_rng(7)
    x = rng.normal(size=(30, 4))
    with pytest.raises(ValueError, match="at least two classes"):
        MahalanobisNoveltyDetector().fit(x, np.array(["only"] * 30))


def test_unfitted_detector_refuses_to_score():
    with pytest.raises(ValueError, match="not fitted"):
        MahalanobisNoveltyDetector().score_samples(np.zeros((1, 4)))


def test_feature_width_mismatch_is_rejected():
    rng = np.random.default_rng(9)
    x, y = _two_clusters(rng)
    detector = MahalanobisNoveltyDetector().fit(x, y)
    with pytest.raises(ValueError, match="feature width"):
        detector.score_samples(np.zeros((1, 3)))


def test_default_scorer_is_unchanged():
    """既有 artifact 必須逐位可重現；改良版只能明示選用。"""
    import inspect

    from firewall_lab.hierarchical_training import train_hierarchical_candidate

    signature = inspect.signature(train_hierarchical_candidate)
    assert signature.parameters["attack_ood_scorer"].default == "isolation_forest"
    assert set(ATTACK_OOD_SCORERS) == {"isolation_forest", "mahalanobis"}


def test_unknown_scorer_name_is_rejected():
    from firewall_lab.hierarchical_training import train_hierarchical_candidate

    with pytest.raises(ValueError, match="attack_ood_scorer must be one of"):
        train_hierarchical_candidate(
            feature_csv="unused.csv",
            output_dir="unused",
            security_mode="permissive",
            attack_ood_scorer="nearest_neighbour",
        )
