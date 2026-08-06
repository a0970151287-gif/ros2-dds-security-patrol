#!/usr/bin/env python3
"""用外部乾淨資料集（HCRL RTPS Attack Dataset）訓練注入偵測模型。

目的：證明「乾淨標籤 + 對的協定特徵 → 真實高準確率」，與我們 conn.log PoC
（PR-AUC 0.20，弱標籤+薄特徵）對照。

設計重點（誠實、可泛化）：
  ★ 只用 RTPS 協定欄位 + payload 統計當特徵，**不用 IP/MAC**——否則模型只是背
    攻擊者身分（像我們 PoC 的循環標籤陷阱），無法泛化到別的攻擊者。
  ★ 標籤用資料集自帶的 RTPS_Attack（乾淨 ground truth，非啟發式）。

CSV 欄位：Time,Source_IP,Destination_IP,Source_MAC,Destination_MAC,ARP_OPCode,
         ARP_Attack,writerSeqNumLow,writerEntityIdKey,writerEntityIdKind,
         serializedData,RTPS_Attack
serializedData 可能含逗號 → 手動解析（前 10 欄固定、末欄為標籤、中間全是 payload）。
"""
from __future__ import annotations

import glob
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (average_precision_score, classification_report,
                             confusion_matrix, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

from ml_utils import atomic_joblib_dump

FEATURES = ["writer_seq", "writer_key", "writer_kind", "arp_opcode",
            "sd_len", "sd_zero", "sd_nonzero_frac", "time_delta"]
BASE = Path(__file__).resolve().parent


def _to_int(s: str, default: int = 0) -> int:
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return default


def parse_csv(path: str) -> pd.DataFrame:
    """手動解析（穩健對付 serializedData 內嵌逗號）。"""
    rows = []
    prev_t = {}
    with open(path, "r", errors="replace") as f:
        next(f)  # header
        for line in f:
            p = line.rstrip("\n").split(",")
            if len(p) < 12:
                continue
            t = float(p[0]) if p[0] else 0.0
            src = p[1]
            arp_op = _to_int(p[5], -1) if p[5] else -1
            seq = _to_int(p[7]); key = _to_int(p[8]); kind = _to_int(p[9])
            sd = ",".join(p[10:-1])               # serializedData（可能含逗號）
            label = 1 if p[-1].strip() == "Attack" else 0

            sd_len = len(sd)
            sd_zero = sd.count("\\x00")            # payload 內零位元組數（idle 遙測多零）
            nz = max(sd_len // 4, 1)
            dt = t - prev_t.get(src, t)
            prev_t[src] = t

            rows.append((seq, key, kind, arp_op, sd_len, sd_zero,
                         1 - sd_zero / nz, round(dt, 4), label))
    return pd.DataFrame(rows, columns=FEATURES + ["label"])


def capture_groups(df: pd.DataFrame, fallback_block_rows: int = 2048):
    """Keep captures (or contiguous blocks for one capture) out of both splits."""
    if "capture" not in df:
        raise ValueError("缺少 capture provenance，無法做防洩漏切分")
    capture = df["capture"].astype(str)
    if capture.nunique() >= 2:
        return capture.to_numpy()
    if fallback_block_rows <= 0:
        raise ValueError("fallback_block_rows 必須 > 0")
    order = df.groupby("capture", sort=False).cumcount()
    return (capture + "|block=" + (order // fallback_block_rows).astype(str)).to_numpy()


def grouped_holdout(X, y, groups):
    """Select a capture-disjoint holdout containing both classes."""
    if len(set(groups)) < 2:
        raise ValueError("至少需要兩個獨立 capture/連續區塊才能評估")
    splitter = GroupShuffleSplit(n_splits=32, test_size=0.30, random_state=42)
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
        raise ValueError("無法得到同時含 normal/attack 的 capture-disjoint 切分")
    _, train_idx, test_idx = min(candidates, key=lambda item: item[0])
    return train_idx, test_idx


def main():
    pat = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/jesse/datasets/rtps/extracted/Dataset/CSV/Command Injection_*_labled.csv"
    files = sorted(glob.glob(pat))
    if not files:
        raise SystemExit(f"找不到 CSV：{pat}")
    print(f"載入 {len(files)} 個 CSV：")
    for fp in files:
        print("  •", Path(fp).name)

    frames = []
    for fp in files:
        frame = parse_csv(fp)
        frame["capture"] = Path(fp).name
        frames.append(frame)
    df = pd.concat(frames, ignore_index=True)
    out = BASE / "輸出"
    out.mkdir(exist_ok=True)

    X = df[FEATURES].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=np.float64)
    if not np.isfinite(X).all():
        raise ValueError("RTPS 特徵含 NaN/Inf，拒絕靜默訓練")
    y = df["label"].to_numpy()
    if len(np.unique(y)) != 2:
        raise ValueError("資料必須同時包含 normal 與 attack")
    print(f"\n資料：{len(df):,} 封包 | 正常 {int((y==0).sum()):,} | "
          f"攻擊 {int(y.sum()):,}（攻擊佔 {y.mean()*100:.2f}%）")

    groups = capture_groups(df)
    itr, ite = grouped_holdout(X, y, groups)
    if not set(groups[itr]).isdisjoint(set(groups[ite])):
        raise RuntimeError("內部錯誤：train/test capture 群組重疊")
    Xtr, Xte, ytr, yte = X[itr], X[ite], y[itr], y[ite]
    print(
        f"防洩漏切分：train={len(itr):,} / test={len(ite):,}，"
        f"capture/區塊 {len(set(groups[itr]))} / {len(set(groups[ite]))}（零重疊）"
    )
    clf = RandomForestClassifier(n_estimators=150, max_depth=14,
                                 class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    proba = clf.predict_proba(Xte)[:, 1]

    print("\n" + "=" * 58)
    print("RTPS 指令注入偵測 — 外部乾淨資料集 (capture-disjoint 測試集)")
    print("=" * 58)
    cm = confusion_matrix(yte, pred)
    print("混淆矩陣           pred_normal  pred_attack")
    print(f"  true_normal   {cm[0,0]:>10}  {cm[0,1]:>10}")
    print(f"  true_attack   {cm[1,0]:>10}  {cm[1,1]:>10}")
    print("\n" + classification_report(yte, pred, target_names=["normal", "attack"],
                                        digits=4, zero_division=0))
    print(f"ROC-AUC: {roc_auc_score(yte, proba):.4f}  |  "
          f"PR-AUC: {average_precision_score(yte, proba):.4f}")

    print("\n特徵重要度：")
    for name, v in sorted(zip(FEATURES, clf.feature_importances_), key=lambda t: -t[1]):
        print(f"  {name:18} {v:.3f} {'█'*int(v*50)}")

    atomic_joblib_dump(
        {
            "rf": clf,
            "features": FEATURES,
            "evaluation": {
                "split": "capture_groups",
                "train_rows": len(itr),
                "test_rows": len(ite),
                "train_groups": sorted(set(groups[itr])),
                "test_groups": sorted(set(groups[ite])),
            },
        },
        out / "rtps_inject_model.joblib",
    )
    print(f"\n✅ 模型與 HMAC sidecar 已存：{out/'rtps_inject_model.joblib'}")


if __name__ == "__main__":
    main()
