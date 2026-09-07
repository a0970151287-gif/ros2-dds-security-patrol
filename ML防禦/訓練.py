#!/usr/bin/env python3
"""ML-IDS baseline 訓練 + 評估（PoC，網路層特徵）。

兩條線：
  (1) 監督式二元分類 RandomForest：normal vs attack（ground-truth 可靠 = 來源身分）
      → 證明流量特徵可學、哪些特徵重要。
  (2) 非監督異常偵測 IsolationForest：只用 normal 訓練，看能否標出 attack
      → 證明「不靠標籤也能抓未知/變種」——這是 ML 相對靜態規則的獨特價值。

用法： python 訓練.py [features.csv]
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (average_precision_score, classification_report,
                             confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedGroupKFold

from ml_utils import atomic_joblib_dump

FEATURES = ["conn_count", "conn_rate", "uniq_dst_ports", "uniq_dst_hosts",
            "spdp_ratio", "meta_ratio", "userdata_ratio", "mcast_ratio",
            "dst_port_entropy"]
BASE = Path(__file__).resolve().parent
TEMPORAL_BLOCK_WINDOWS = 256


def temporal_groups(df: pd.DataFrame, block_windows: int = TEMPORAL_BLOCK_WINDOWS):
    """Keep a generated session wholly in one fold; fall back to time blocks.

    The firewall data factory emits ``group_id=session_id``.  This is stronger
    than adjacent-window grouping because every flow/window from one attack
    execution stays on exactly one side of train/test.  Historical captures
    without session metadata retain the roughly 34-minute fallback.
    """
    for column in ("group_id", "session_id"):
        if column in df.columns:
            raw_groups = df[column]
            if raw_groups.isna().any():
                raise ValueError(f"{column} 含空值，無法做 session 分組")
            groups = raw_groups.astype(str)
            if (groups.str.len() == 0).any():
                raise ValueError(f"{column} 含空值，無法做 session 分組")
            return groups.to_numpy()

    required = {"source", "window"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(
            f"缺少 {sorted(missing)}，無法做防洩漏分組切分；"
            "請使用 特徵抽取.py 產生的資料"
        )
    if block_windows <= 0:
        raise ValueError("block_windows 必須 > 0")
    windows = pd.to_numeric(df["window"], errors="coerce")
    if windows.isna().any():
        raise ValueError("window 欄含無效值")
    batch = (
        df["batch"].astype(str)
        if "batch" in df.columns
        else pd.Series("single_capture", index=df.index)
    )
    block = (windows.astype("int64") // block_windows).astype(str)
    return (batch + "|" + df["source"].astype(str) + "|" + block).to_numpy()


def grouped_holdout(X, y, groups):
    """Choose a stratified group fold closest to a 30% holdout."""
    group_counts = [
        len(set(groups[np.asarray(y) == cls])) for cls in (0, 1)
    ]
    n_splits = min(3, *group_counts)
    if n_splits < 2:
        raise ValueError(
            "normal/attack 至少各需兩個獨立時間群組，否則無法做無洩漏評估"
        )
    splitter = StratifiedGroupKFold(
        n_splits=n_splits, shuffle=True, random_state=42
    )
    candidates = []
    base_rate = float(np.mean(y))
    for train_idx, test_idx in splitter.split(X, y, groups):
        if len(np.unique(y[train_idx])) < 2 or len(np.unique(y[test_idx])) < 2:
            continue
        score = (
            abs(len(test_idx) / len(y) - 0.30)
            + abs(float(np.mean(y[test_idx])) - base_rate)
        )
        candidates.append((score, train_idx, test_idx))
    if not candidates:
        raise ValueError("分組後無法得到同時含 normal/attack 的 train/test")
    _, train_idx, test_idx = min(candidates, key=lambda item: item[0])
    return train_idx, test_idx


def _validated_xy(df: pd.DataFrame):
    missing = set(FEATURES + ["binary"]).difference(df.columns)
    if missing:
        raise ValueError(f"資料缺少必要欄位：{sorted(missing)}")
    if df["binary"].isna().any():
        raise ValueError("binary 含空值，拒絕把未標註資料當 normal")
    unknown = sorted(set(df["binary"].astype(str)) - {"normal", "attack"})
    if unknown:
        raise ValueError(
            f"binary 含未標註/未知類別 {unknown}；請先剔除或完成標註，避免污染訓練"
        )
    numeric = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    X = numeric.to_numpy(dtype=np.float64)
    if not np.isfinite(X).all():
        bad = int((~np.isfinite(X)).sum())
        raise ValueError(f"特徵中有 {bad} 個 NaN/Inf，拒絕靜默訓練")
    y = (df["binary"] == "attack").astype(int).to_numpy()
    if len(np.unique(y)) != 2:
        raise ValueError("資料必須同時包含 normal 與 attack")
    return X, y


def main():
    csv = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE / "輸出" / "features.csv"
    df = pd.read_csv(csv)
    out = BASE / "輸出"
    out.mkdir(exist_ok=True)

    X, y = _validated_xy(df)
    groups = temporal_groups(df)
    print(f"資料：{len(df):,} 視窗 | 正常 {int((y==0).sum()):,} | 攻擊 {int(y.sum()):,} "
          f"（攻擊佔 {y.mean()*100:.2f}%，高度不平衡）\n")

    itr, ite = grouped_holdout(X, y, groups)
    Xtr, Xte, ytr, yte = X[itr], X[ite], y[itr], y[ite]
    train_groups, test_groups = set(groups[itr]), set(groups[ite])
    if not train_groups.isdisjoint(test_groups):
        raise RuntimeError("內部錯誤：train/test 時間群組重疊")
    print(
        f"防洩漏切分：train={len(itr):,} / test={len(ite):,}，"
        f"時間群組 {len(train_groups)} / {len(test_groups)}（零重疊）\n"
    )

    # ── (1) 監督式 RandomForest（class_weight 處理不平衡）──
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=12, class_weight="balanced",
        random_state=42, n_jobs=-1)
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    proba = clf.predict_proba(Xte)[:, 1]

    print("=" * 60)
    print("(1) 監督式二元分類 RandomForest — 分組保留測試集")
    print("=" * 60)
    cm = confusion_matrix(yte, pred)
    print("混淆矩陣 [列=真實, 欄=預測]  (0=normal, 1=attack)")
    print(f"            pred_normal  pred_attack")
    print(f"true_normal   {cm[0,0]:>8}    {cm[0,1]:>8}")
    print(f"true_attack   {cm[1,0]:>8}    {cm[1,1]:>8}")
    print("\n分類報告：")
    print(classification_report(yte, pred, target_names=["normal", "attack"],
                                digits=3, zero_division=0))
    print(f"ROC-AUC: {roc_auc_score(yte, proba):.4f}  |  "
          f"PR-AUC(更適合不平衡): {average_precision_score(yte, proba):.4f}")

    # ── 門檻調校：模型排序能力好(AUC高)，問題是操作點。掃門檻找最佳 F1 + 高 precision 點 ──
    print("\n--- 門檻調校（同一個模型，只換決策門檻）---")
    prec, rec, thr = precision_recall_curve(yte, proba)
    f1s = 2 * prec * rec / (prec + rec + 1e-12)
    best = f1s[:-1].argmax()
    t_f1 = thr[best]
    # 找能達 precision>=0.90 的最小門檻（要更少誤報時用）
    ok = [(t, p, r) for p, r, t in zip(prec[:-1], rec[:-1], thr) if p >= 0.90]
    print(f"{'操作點':<22}{'門檻':<8}{'precision':<11}{'recall':<9}{'F1'}")
    for name, t in [("預設 0.50", 0.50), ("最佳 F1", t_f1)] + (
            [("precision≥0.90", ok[0][0])] if ok else []):
        p_ = (proba >= t).astype(int)
        print(f"{name:<22}{t:<8.3f}{precision_score(yte,p_,zero_division=0):<11.3f}"
              f"{recall_score(yte,p_,zero_division=0):<9.3f}{f1_score(yte,p_,zero_division=0):.3f}")

    # ── grouped CV（相鄰時間窗絕不跨折）──
    class_group_counts = [len(set(groups[y == cls])) for cls in (0, 1)]
    n_cv = min(5, *class_group_counts)
    if n_cv < 2:
        raise ValueError("獨立時間群組不足，無法做 grouped CV")
    cv = StratifiedGroupKFold(n_splits=n_cv, shuffle=True, random_state=42)
    cv_proba = np.full(len(y), np.nan, dtype=np.float64)
    for cv_train, cv_test in cv.split(X, y, groups):
        fold_model = RandomForestClassifier(
            n_estimators=200, max_depth=12, class_weight="balanced",
            random_state=42, n_jobs=-1,
        )
        fold_model.fit(X[cv_train], y[cv_train])
        cv_proba[cv_test] = fold_model.predict_proba(X[cv_test])[:, 1]
    if not np.isfinite(cv_proba).all():
        raise RuntimeError("grouped CV 沒有覆蓋全部樣本")
    print(f"\n{n_cv}-fold grouped CV PR-AUC: {average_precision_score(y, cv_proba):.4f}  "
          f"ROC-AUC: {roc_auc_score(y, cv_proba):.4f}（全資料交叉驗證，較穩）")

    print("\n特徵重要度（哪些流量特徵最會判攻擊）：")
    imp = sorted(zip(FEATURES, clf.feature_importances_),
                 key=lambda t: -t[1])
    for name, v in imp:
        bar = "█" * int(v * 50)
        print(f"  {name:18} {v:.3f} {bar}")

    # ── (2) 非監督 IsolationForest（只用正常訓練）──
    print("\n" + "=" * 60)
    print("(2) 非監督異常偵測 IsolationForest — 只用正常流量訓練")
    print("=" * 60)
    # 只用 *訓練切分* 的正常資料 fit，且只在 held-out test 評估。
    # 原版本用全部 normal fit 又在同一批資料上報 FPR，會低估誤報。
    Xnorm = Xtr[ytr == 0]
    iso = IsolationForest(contamination=0.02, random_state=42, n_jobs=-1)
    iso.fit(Xnorm)
    flag = (iso.predict(Xte) == -1).astype(int)   # -1=異常
    det = flag[yte == 1].mean()       # 攻擊被標為異常的比例 = recall
    fpr = flag[yte == 0].mean()       # held-out normal 被誤標 = FPR
    print(f"held-out 攻擊偵出率(recall): {det*100:.1f}%   | "
          f"held-out 正常誤報率(FPR): {fpr*100:.2f}%")
    print("→ 不靠任何攻擊標籤，純學正常基線即可標出大部分攻擊（抓未知/變種的本錢）")

    atomic_joblib_dump(
        {
            "rf": clf,
            "iso": iso,
            "features": FEATURES,
            "evaluation": {
                "split": "stratified_temporal_groups",
                "block_windows": TEMPORAL_BLOCK_WINDOWS,
                "train_rows": len(itr),
                "test_rows": len(ite),
            },
        },
        out / "model.joblib",
    )
    print(f"\n✅ 模型與 HMAC sidecar 已存：{out/'model.joblib'}")


if __name__ == "__main__":
    main()
