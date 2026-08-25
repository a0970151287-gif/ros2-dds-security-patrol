"""未知攻擊評分器。

現行的 attack-OOD 頭是 IsolationForest，密度式：只有比已知攻擊**更極端**的樣本
才會被判成異常。用 leave-one-known-class-out 當模擬未知量過，Permissive 六類的
macro AUC 只有 **0.5381**，其中四類低於 0.5——被抽掉時它們看起來比已知攻擊還正常。

`message_dos` 是關鍵反例：它 closed-set recall 0.970（有專屬的
`oversized_message_ratio`），OOD AUC 卻只有 0.3207。所以瓶頸不是「沒有專屬證據」，
而是評分方式。安全上這是最糟的失效方向——**安靜的新型攻擊看不見**。

`MahalanobisNoveltyDetector` 改成判別式：量到最近的已知類別中心的距離。
一個「不一樣但不極端」的類別仍然離每個已知中心都很遠，而密度式評分會把它
算進中央的密集區。

兩場對抗性驗證（各自針對一個候選最差的兩類，全新 holdout，選擇步驟從未看過）：

| 評分器 | 測試 A | 測試 B | 最差 |
|---|---:|---:|---:|
| isolation_forest | 0.4316 | 0.6834 | 0.4316 |
| max_softmax | 0.9950 | 0.6900 | 0.6900 |
| **mahalanobis** | 0.8781 | 0.8935 | **0.8781** |

max-softmax 被針對時從 0.995 崩到 0.690；Mahalanobis 兩場都守住。安全系統該看的是
最差情況，所以選 Mahalanobis。

**這只對 Permissive 成立。** Enforce 三種評分器在全新 holdout 上都是 0.38–0.59，
因為 SROS2 在 handshake 就擋掉攻擊，應用層證據根本不存在。那不是評分器的問題。
"""

from __future__ import annotations

from typing import Any

__all__ = ["MahalanobisNoveltyDetector"]


class MahalanobisNoveltyDetector:
    """到最近的已知類別中心的馬氏距離，共用組內共變異。

    介面刻意與 `IsolationForest` 對齊——`fit`／`score_samples`，且
    `score_samples` **越低越異常**——這樣 `hierarchical_model.py` 的
    duck-typing 檢查與門檻比較方向都不必改。
    """

    def __init__(self, *, shrinkage: float = 1e-6) -> None:
        if not shrinkage > 0.0:
            raise ValueError("shrinkage must be positive")
        self.shrinkage = float(shrinkage)
        self.classes_: Any = None
        self._centroids: Any = None
        self._precision: Any = None

    def fit(self, x, y=None, sample_weight=None) -> "MahalanobisNoveltyDetector":
        """y 是已知攻擊的類別標籤。

        沒有標籤就退化成單一中心，那等於丟掉這個評分器唯一的優勢，所以直接拒絕。
        """
        import numpy as np

        if y is None:
            raise ValueError("mahalanobis novelty scoring requires class labels")
        matrix = np.asarray(x, dtype=float)
        labels = np.asarray(y)
        if matrix.ndim != 2 or len(matrix) != len(labels):
            raise ValueError("feature matrix and labels must align")
        classes = np.unique(labels)
        if len(classes) < 2:
            raise ValueError("mahalanobis novelty scoring requires at least two classes")

        centroids = np.stack([matrix[labels == value].mean(axis=0) for value in classes])
        centred = np.concatenate(
            [matrix[labels == value] - centroids[index]
             for index, value in enumerate(classes)]
        )
        covariance = np.cov(centred, rowvar=False)
        if covariance.ndim == 0:
            covariance = covariance.reshape(1, 1)
        # 148 維裡有恆為零的欄位（來源不可得的特徵），共變異必然奇異。
        # 用 pinv 而不是 inv，並加一點 shrinkage 讓結果對重複欄位穩定。
        self._precision = np.linalg.pinv(
            covariance + self.shrinkage * np.eye(covariance.shape[0])
        )
        self._centroids = centroids
        self.classes_ = classes
        return self

    def score_samples(self, x):
        """越低越異常，與 IsolationForest 的慣例一致。"""
        import numpy as np

        if self._centroids is None:
            raise ValueError("detector is not fitted")
        matrix = np.asarray(x, dtype=float)
        if matrix.ndim == 1:
            matrix = matrix.reshape(1, -1)
        if matrix.shape[1] != self._centroids.shape[1]:
            raise ValueError("feature width does not match the fitted detector")
        best = None
        for centroid in self._centroids:
            delta = matrix - centroid
            squared = np.einsum("ij,jk,ik->i", delta, self._precision, delta)
            best = squared if best is None else np.minimum(best, squared)
        return -np.sqrt(np.maximum(best, 0.0))

    def decision_function(self, x):
        return self.score_samples(x)
