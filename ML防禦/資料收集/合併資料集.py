#!/usr/bin/env python3
"""整合所有可用、且與本實驗室情境相關的歷史資料成一份可訓練資料集。

盤點結果（2026-07-04 更新，誠實排除不相關來源）：
  ✅ ML防禦/輸出/features.csv       — Phase 1 既有特徵（18,868 視窗，含真實攻擊活動，
                                       原始 conn.log 已被後續 Zeek 執行覆蓋，但特徵已保存）
  ✅ 網路記錄/conn.log              — 涵蓋 2026-07-02 23:09 ~ 2026-07-03 00:59（3,207 筆連線）。
                                       含真實紅隊活動（910 筆 10.10.10.1 + 1 筆偽造來源
                                       10.10.10.250）→ 用 bootstrap 弱標籤重新抽取（與 Phase 1
                                       同方法，非 label.sh 精確時間窗標註）。
  ❌ 網路記錄/archive/2026-04-25_舊擷取/    — 來源 IP 172.30.123.103，非本實驗室網段
                                              (10.10.10.0/24)，無 10.10.10.1 攻擊機活動，
                                              是完全不同情境的擷取 → 排除，避免汙染標籤
  ❌ 網路記錄/archive/2026-05-05_Zeek監控舊擷取/ — 同上，172.30.123.103，排除
  ⚪ Zeek監控/test/conn.log         — 合成 fixture，34 筆全落在同一個 8s 視窗，
                                       粒度與本管線的視窗特徵不合（見腳本內說明），
                                       不強塞進訓練集，留做規則偵測的獨立驗證用

輸出：ML防禦/輸出/dataset_combined.csv，含 `batch` 欄位標明每筆來源，方便追溯。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from 特徵抽取 import extract, load_conn_log  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "ML防禦" / "輸出" / "dataset_combined.csv"


def main():
    frames = []

    # ① Phase 1 既有特徵（保留原標籤與 provenance）
    p1 = ROOT / "ML防禦" / "輸出" / "features.csv"
    if p1.exists():
        df1 = pd.read_csv(p1)
        df1["batch"] = "phase1_歷史攻防(conn.log已覆蓋僅存特徵)"
        frames.append(df1)
        print(f"✅ 併入 {p1.name}：{len(df1):,} 列（標籤分布: "
              f"{dict(df1['label'].value_counts())}）")
    else:
        print(f"⚠️ 找不到 {p1}，跳過")

    # ② 網路記錄/conn.log（涵蓋 2026-07-02 23:09~2026-07-03 00:59，含真實紅隊活動）
    #    用 bootstrap 弱標籤重新抽取（與 特徵抽取.py／Phase 1 同方法）——
    #    誠實標註：非 label.sh 精確時間窗標籤，仍是「來源身分推得」的弱標籤。
    p2 = ROOT / "網路記錄" / "conn.log"
    if p2.exists():
        df_raw = load_conn_log(str(p2))
        df2 = extract(df_raw, window_sec=8.0)
        df2["batch"] = "2026-07-03擷取_含紅隊活動_bootstrap弱標籤"
        frames.append(df2)
        print(f"✅ 併入 {p2.relative_to(ROOT)}：{len(df2):,} 列"
              f"（標籤分布: {dict(df2['label'].value_counts())}）")
    else:
        print(f"⚠️ 找不到 {p2}，跳過")

    # ③ 明確記錄排除項（不是漏掉，是刻意不用）
    print("\n❌ 已排除（來源網段與本實驗室無關，避免汙染標籤）：")
    print("   網路記錄/archive/2026-04-25_舊擷取/、2026-05-05_Zeek監控舊擷取/")
    print("   （來源 IP 172.30.123.103，非 10.10.10.0/24；無本專案攻擊機活動）")
    print("\n⚪ 未併入（粒度不合，留作規則偵測獨立驗證）：Zeek監控/test/conn.log")

    if not frames:
        raise SystemExit("沒有任何可用資料，無法輸出。")

    combined = pd.concat(frames, ignore_index=True, sort=False)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUT, index=False)

    print(f"\n{'='*60}\n✅ 合併完成 → {OUT.relative_to(ROOT)}")
    print(f"總列數: {len(combined):,}")
    print("\n各 batch 列數：")
    print(combined["batch"].value_counts().to_string())
    print("\n多類標籤分布（合併後）：")
    print(combined["label"].value_counts().to_string())
    print("\n二元標籤分布：")
    print(combined["binary"].value_counts().to_string())
    atk_ratio = (combined["binary"] == "attack").mean() * 100
    print(f"\n攻擊佔比: {atk_ratio:.2f}%")


if __name__ == "__main__":
    main()
