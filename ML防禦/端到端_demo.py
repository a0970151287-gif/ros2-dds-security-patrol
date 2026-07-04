#!/usr/bin/env python3
"""端到端閉環 demo：真 ML 模型偵測 → 回應引擎出對應防禦。

流程：載入 RTPS 注入模型 → 對真實封包分類 → 依預測類別+信心 → ResponseEngine 出手。
證明「偵測後配合對應防禦」是接通的，不是兩個分離的東西。
"""
from __future__ import annotations

import joblib
import pandas as pd

from RTPS資料集_訓練 import FEATURES, parse_csv
from 回應引擎 import Detection, ResponseEngine

CSV = ("/home/jesse/datasets/rtps/extracted/Dataset/CSV/"
       "Command Injection_180_labled.csv")


def main():
    bundle = joblib.load("輸出/rtps_inject_model.joblib")
    clf = bundle["rf"]

    df = parse_csv(CSV)
    atk = df[df.label == 1].sample(4, random_state=1)
    nrm = df[df.label == 0].sample(4, random_state=1)
    sample = pd.concat([atk, nrm]).sample(frac=1, random_state=7)

    print("=" * 70)
    print("端到端：RTPS 模型偵測 → 回應引擎對應防禦（dry-run）")
    print("=" * 70)
    eng = ResponseEngine(mode="dry_run", confidence_min=0.70)

    for _, row in sample.iterrows():
        X = row[FEATURES].values.reshape(1, -1)
        p_atk = float(clf.predict_proba(X)[0, 1])
        cls = "inject" if p_atk >= 0.5 else "normal"
        conf = p_atk if cls == "inject" else 1 - p_atk
        det = Detection(
            attack_class=cls,
            source="10.10.10.1" if cls == "inject" else "192.168.0.3",
            confidence=round(conf, 2),
            evidence=f"(真實標籤={'攻擊' if row.label else '正常'})")
        eng.respond(det)

    n_act = sum(r.executed for r in eng.log)
    print(f"\n處理 {len(eng.log)} 封包 → 執行 {n_act} 個防禦動作（含告警）")
    print("注：dry-run 下封鎖/急停只印指令；live 模式才真執行。")


if __name__ == "__main__":
    main()
