#!/usr/bin/env python3
"""Phase 2：用 labels.txt 的真實時間窗做精確標註，取代 Phase 1 的啟發式弱標籤。

設計（承接 ML防禦/README.md 的 Phase 2 協定）：
  - 來源身分仍是可靠 ground truth：自身/受信來源（10.10.10.2、127.0.0.1、
    link-local）任何時候都是 normal——這點不必靠時間窗，本來就對。
  - 「非受信來源」的活動，用 label.sh 記錄的時間窗查出**精確類別**
    （recon/dos/inject/param/spoof/metasploit_scan/... 任意名稱），
    取代 Phase 1 用速率門檻猜的粗糙分法。
  - 落在任何 labels.txt 區間外的非受信活動 → 標 "unlabeled"（誠實：不硬猜）。

用法：
  bash label.sh start recon ... bash label.sh end recon   （攻擊時，紅隊/你來記）
  python 精確標註_重抽特徵.py <conn.log> [labels.txt] [輸出.csv] [視窗秒數]
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from 特徵抽取 import (ATTACKER_SRC, TRUSTED_SRC, _entropy, load_conn_log,  # noqa: E402
                   META_PORTS, SPDP_PORT, USERDATA_HI, USERDATA_LO, _is_multicast)


def load_labels(path: str) -> list[tuple[float, float, str]]:
    """labels.txt → [(start_ts, end_ts, class), ...]（start/end 依 class 各自配對）。"""
    opens: dict[str, list[float]] = {}
    intervals: list[tuple[float, float, str]] = []
    if not Path(path).exists():
        print(f"⚠️ 找不到 {path}，全部非受信來源將標為 unlabeled")
        return intervals
    with open(path, "r") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            ts, action, cls = parts[0], parts[1], parts[2]
            if action == "note":
                continue
            ts = float(ts)
            if action == "start":
                opens.setdefault(cls, []).append(ts)
            elif action == "end":
                if opens.get(cls):
                    st = opens[cls].pop(0)
                    intervals.append((st, ts, cls))
                else:
                    print(f"⚠️ {cls} 有 end 沒對應 start（忽略）")
    # 還沒 end 的 start（例如收集到一半）→ 開放到 +inf，並警告
    for cls, starts in opens.items():
        for st in starts:
            print(f"⚠️ {cls} 的 start({st}) 尚未 end → 視為持續到現在")
            intervals.append((st, float("inf"), cls))
    return intervals


def label_at(t: float, src: str, intervals: list[tuple[float, float, str]]) -> str:
    if src in TRUSTED_SRC or src.startswith("fe80") or src.startswith("169.254"):
        return "normal"
    for st, en, cls in intervals:
        if st <= t <= en:
            return cls
    return "unlabeled"


def extract_precise(df: pd.DataFrame, intervals, window_sec: float = 8.0) -> pd.DataFrame:
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
        win_mid_t = g["ts"].mean()

        rows.append({
            "source": src, "window": int(win),
            "conn_count": n, "conn_rate": round(n / window_sec, 3),
            "uniq_dst_ports": int(ports.nunique()),
            "uniq_dst_hosts": int(g["id.resp_h"].nunique()),
            "spdp_ratio": round(spdp / n, 3) if n else 0.0,
            "meta_ratio": round(meta / n, 3) if n else 0.0,
            "userdata_ratio": round(udata / n, 3) if n else 0.0,
            "mcast_ratio": round(mcast / n, 3) if n else 0.0,
            "dst_port_entropy": round(_entropy(port_counts), 3),
            "label": label_at(win_mid_t, src, intervals),
        })
    feat = pd.DataFrame(rows)
    feat["binary"] = feat["label"].apply(lambda l: "normal" if l in ("normal",) else
                                          ("unlabeled" if l == "unlabeled" else "attack"))
    return feat.sort_values(["window", "source"]).reset_index(drop=True)


def main():
    conn_path = sys.argv[1] if len(sys.argv) > 1 else "../../conn.log"
    labels_path = sys.argv[2] if len(sys.argv) > 2 else "labels.txt"
    out_path = sys.argv[3] if len(sys.argv) > 3 else "../輸出/features_precise.csv"
    window = float(sys.argv[4]) if len(sys.argv) > 4 else 8.0

    intervals = load_labels(labels_path)
    print(f"載入 {len(intervals)} 個標註時間窗：")
    for st, en, cls in intervals:
        dur = "進行中" if en == float("inf") else f"{en-st:.0f}s"
        print(f"  • {cls:<20} 長度={dur}")

    df = load_conn_log(conn_path)
    feat = extract_precise(df, intervals, window)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    feat.to_csv(out_path, index=False)

    print(f"\n✅ 精確標註完成：{len(df):,} 筆連線 → {len(feat):,} 視窗 → {out_path}")
    print("\n多類標籤分布（ground truth，非啟發式猜測）：")
    print(feat["label"].value_counts().to_string())
    n_unlabeled = int((feat["label"] == "unlabeled").sum())
    if n_unlabeled:
        print(f"\n⚠️ {n_unlabeled} 個視窗是「非受信來源但落在任何標註區間外」→ unlabeled"
              f"（訓練前建議剔除或回頭補記 label.sh 時間窗）")


if __name__ == "__main__":
    main()
