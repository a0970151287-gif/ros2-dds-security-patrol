#!/usr/bin/env python3
"""ML-IDS 特徵抽取 — Zeek conn.log → 滑動視窗 per-source 特徵向量。

兩層融合 ML 防禦的【網路層】特徵管線（行為層特徵 phase 2 再融合）。

設計：把連線記錄按「來源 IP × 時間視窗」聚合，算出能區分攻擊類型的流量統計特徵。
conn.log 多數 byte/pkt 欄位是 '-'（UDP 無狀態），故特徵聚焦在**速率 / 埠散布 / 目標分布**
——這正是 recon（廣埠列舉）、DoS（高速 SPDP 風暴）、spoof（非預期來源）的判別訊號。

用法：
    python 特徵抽取.py <conn.log> [輸出.csv] [視窗秒數=8]
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pandas as pd

# domain 30 RTPS 埠語意（與 Zeek dds_monitor.zeek 對齊）
SPDP_PORT = 14900                  # participant 探索（多播）
META_PORTS = {14910, 14911, 14912}  # metatraffic
USERDATA_LO, USERDATA_HI = 14913, 15200
TRUSTED_SRC = {"10.10.10.2", "127.0.0.1"}   # 目標自身 / 本地
ATTACKER_SRC = "10.10.10.1"                 # 已知攻擊機


def _is_multicast(ip: str) -> bool:
    """239.x / 224-239.x 多播；簡化判斷第一個 octet。"""
    try:
        first = int(ip.split(".")[0])
        return 224 <= first <= 239
    except (ValueError, IndexError):
        return False


def _entropy(counts) -> float:
    """目標埠分布的 Shannon entropy（廣埠掃描 → 高 entropy）。"""
    total = sum(counts)
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


def load_conn_log(path: str) -> pd.DataFrame:
    """解析 Zeek conn.log（TSV，#fields 那行給欄名）。"""
    fields = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                break
    if fields is None:
        raise SystemExit(f"找不到 #fields 表頭：{path}")

    df = pd.read_csv(
        path, sep="\t", comment="#", names=fields,
        dtype=str, na_values=["-"], keep_default_na=False,
    )
    df = df[df["proto"].notna()]
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df["id.resp_p"] = pd.to_numeric(df["id.resp_p"], errors="coerce")
    df = df.dropna(subset=["ts", "id.orig_h", "id.resp_p"])
    return df


def label_window(src: str, conn_rate: float, uniq_ports: int,
                 spdp_ratio: float) -> str:
    """Bootstrap 弱標籤（PoC 用，透明規則；phase 2 換乾淨 ground-truth）。

    可靠 ground truth = 來源機器身分（攻擊機 10.10.10.1、偽造 10.10.10.250 皆已知）。
    fe80::（IPv6 link-local）、169.254（APIPA）是區域協定噪訊 → 正常。
    攻擊機內部再用流量型態粗分 dos/recon（此分法為 indicative，非驗證標籤）。
    inject/param 需 payload（conn.log 看不到）→ phase 2 加 udp_contents 特徵或行為層。
    """
    if src in TRUSTED_SRC or src.startswith("fe80") or src.startswith("169.254"):
        return "normal"                        # 授權/本地正常流量
    if src == "10.10.10.250":
        return "spoof"                         # F7-C 偽造來源（真 spoof）
    if src == ATTACKER_SRC:
        if conn_rate >= 3.0 and spdp_ratio >= 0.3:
            return "dos"                       # 高速 SPDP 風暴
        return "recon"                         # 廣埠列舉 / 探索流量
    return "normal"


def binary_label(label: str) -> str:
    """二元標籤：normal vs attack（attack = 未授權來源活動，ground truth 可靠）。"""
    return "normal" if label == "normal" else "attack"


def extract(df: pd.DataFrame, window_sec: float = 8.0) -> pd.DataFrame:
    df = df.copy()
    t0 = df["ts"].min()
    df["win"] = ((df["ts"] - t0) // window_sec).astype(int)

    rows = []
    for (src, win), g in df.groupby(["id.orig_h", "win"]):
        ports = g["id.resp_p"].astype(int)
        n = len(g)
        spdp = int((ports == SPDP_PORT).sum())
        meta = int(ports.isin(META_PORTS).sum())
        udata = int(((ports >= USERDATA_LO) & (ports <= USERDATA_HI)).sum())
        mcast = int(g["id.resp_h"].map(_is_multicast).sum())
        port_counts = ports.value_counts().tolist()

        conn_rate = n / window_sec
        uniq_ports = int(ports.nunique())
        spdp_ratio = spdp / n if n else 0.0

        rows.append({
            "source": src,
            "window": int(win),
            "conn_count": n,
            "conn_rate": round(conn_rate, 3),
            "uniq_dst_ports": uniq_ports,
            "uniq_dst_hosts": int(g["id.resp_h"].nunique()),
            "spdp_ratio": round(spdp_ratio, 3),
            "meta_ratio": round(meta / n, 3) if n else 0.0,
            "userdata_ratio": round(udata / n, 3) if n else 0.0,
            "mcast_ratio": round(mcast / n, 3) if n else 0.0,
            "dst_port_entropy": round(_entropy(port_counts), 3),
            "label": label_window(src, conn_rate, uniq_ports, spdp_ratio),
        })
        rows[-1]["binary"] = binary_label(rows[-1]["label"])

    feat = pd.DataFrame(rows)
    return feat.sort_values(["window", "source"]).reset_index(drop=True)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    conn_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "輸出/features.csv"
    window = float(sys.argv[3]) if len(sys.argv) > 3 else 8.0

    df = load_conn_log(conn_path)
    feat = extract(df, window)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    feat.to_csv(out_path, index=False)

    print(f"✅ 特徵抽取完成：{len(df):,} 筆連線 → {len(feat):,} 個視窗特徵")
    print(f"   視窗={window}s，輸出={out_path}")
    print("\n多類標籤分布：")
    print(feat["label"].value_counts().to_string())
    print("\n二元標籤分布：")
    print(feat["binary"].value_counts().to_string())
    print("\n各標籤特徵均值（速率/埠散布）：")
    cols = ["conn_rate", "uniq_dst_ports", "spdp_ratio", "dst_port_entropy"]
    print(feat.groupby("label")[cols].mean().round(2).to_string())
    atk = feat[feat["source"] == ATTACKER_SRC]
    if len(atk):
        print(f"\n攻擊機(10.10.10.1) {len(atk)} 視窗 conn_rate 分布：")
        print(atk["conn_rate"].describe()[["min", "50%", "max"]].round(2).to_string())


if __name__ == "__main__":
    main()
