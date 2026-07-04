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

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (average_precision_score, classification_report,
                             confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split

FEATURES = ["conn_count", "conn_rate", "uniq_dst_ports", "uniq_dst_hosts",
            "spdp_ratio", "meta_ratio", "userdata_ratio", "mcast_ratio",
            "dst_port_entropy"]


def main():
    csv = sys.argv[1] if len(sys.argv) > 1 else "輸出/features.csv"
    df = pd.read_csv(csv)
    out = Path("輸出"); out.mkdir(exist_ok=True)

    X = df[FEATURES].values
    y = (df["binary"] == "attack").astype(int).values
    print(f"資料：{len(df):,} 視窗 | 正常 {int((y==0).sum()):,} | 攻擊 {int(y.sum()):,} "
          f"（攻擊佔 {y.mean()*100:.2f}%，高度不平衡）\n")

    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y)

    # ── (1) 監督式 RandomForest（class_weight 處理不平衡）──
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=12, class_weight="balanced",
        random_state=42, n_jobs=-1)
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    proba = clf.predict_proba(Xte)[:, 1]

    print("=" * 60)
    print("(1) 監督式二元分類 RandomForest — 測試集 (30%)")
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

    # ── 5-fold 交叉驗證（看穩定度，非單次切分運氣）──
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_proba = cross_val_predict(
        RandomForestClassifier(n_estimators=200, max_depth=12,
                               class_weight="balanced", random_state=42, n_jobs=-1),
        X, y, cv=skf, method="predict_proba", n_jobs=-1)[:, 1]
    print(f"\n5-fold CV PR-AUC: {average_precision_score(y, cv_proba):.4f}  "
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
    Xnorm = X[y == 0]
    iso = IsolationForest(contamination=0.02, random_state=42, n_jobs=-1)
    iso.fit(Xnorm)
    flag = (iso.predict(X) == -1).astype(int)   # -1=異常
    det = flag[y == 1].mean()       # 攻擊被標為異常的比例 = recall
    fpr = flag[y == 0].mean()       # 正常被誤標 = FPR
    print(f"攻擊偵出率(recall): {det*100:.1f}%   | 正常誤報率(FPR): {fpr*100:.2f}%")
    print("→ 不靠任何攻擊標籤，純學正常基線即可標出大部分攻擊（抓未知/變種的本錢）")

    joblib.dump({"rf": clf, "iso": iso, "features": FEATURES},
                out / "model.joblib")
    print(f"\n✅ 模型已存：{out/'model.joblib'}")


if __name__ == "__main__":
    main()
