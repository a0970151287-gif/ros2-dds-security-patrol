#!/usr/bin/env python3
"""把下一次重訓的設定**在資料存在之前**釘死。

## 為什麼

這個專案最大的方法論風險不是模型不夠好，是**最後那個 test 被污染**。

從 2026-09-15 到 09-19，識別率的每一個設定都是從 CV 選出來的——問題表述、
模型類別、時序深度、OOD 評分器、未知攻擊的池化 k。每一輪都誠實寫了
「CV 不是 held-out test，百分比不動」，但那些選擇**加起來**就是一個搜尋過程，
而搜尋過程的終點若能在看到新 test 之後再調整，那個 test 就不是獨立的。

C2C-028 已經示範過這個失效模式的弱形式：評分器完全用訓練列選的，holdout
從未參與選擇，但「我知道它上次的失敗形態」這件事本身影響了搜尋方向。
那一輪把它揭露成「弱污染」。這一支的目的是讓下一輪**連弱污染都沒有**。

## 做法

1. **現在**（新資料還沒收完）把每一個設定寫下來，附上它的證據來源與該來源
   檔案的 SHA-256。
2. 對整份註冊取一個 canonical SHA-256。
3. 重訓時 `verify_registration()` 比對實際用的設定；**不符就拒絕**。

⚠️ 這**不會**讓設定變得正確——它們仍然只是 CV 上的選擇。它保證的是
「跑新 test 的時候沒有人偷偷換過」，而那是可驗證的，前者不是。

## 未定的項目要明寫成未定

`Enforce` 的 OOD 評分器**沒有**被選定（C2C-076：兩個量測互相矛盾，
而真正的瓶頸是閘門否決 88%）。註冊裡寫 `undecided` 並記下理由，
**不是**隨便填一個。一個假裝已決定的設定比誠實的未定更危險。

## 用法

    python3 工具腳本/preregister_retraining.py --output 文件/重訓預先註冊_<日期>.json
    python3 工具腳本/preregister_retraining.py --verify 文件/重訓預先註冊_<日期>.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCHEMA = "sros2-firewall-retraining-preregistration/v1"

UNDECIDED = "undecided"


class RegistrationError(RuntimeError):
    """註冊不完整或與實際設定不符。刻意不吞。"""


# 每一項：值、為什麼、證據檔案。證據檔案必須在 repo 裡，因為註冊要能被反查。
SETTINGS: dict[str, dict] = {
    "formulation": {
        "value": "session_aggregate",
        "rationale": (
            "一場一個向量直接分類。2026-09-16 量到換表述值 +0.093（Enforce "
            "0.5571 → 0.6505），遠大於換遍 24 個學習法的 +0.021；RF 與 HistGB "
            "在該表述下同分，代表功勞在表述不在模型。機制最清楚的是 "
            "parameter_tamper 0.059 → 0.765：爆量被逐視窗機率平均稀釋，"
            "在特徵層取 max／max_abs_delta 不會。"
        ),
        "evidence": "文件/換問題表述與模型類別_2026-09-16.md",
        "superseded_warning": None,
    },
    "model": {
        "value": "random_forest",
        "rationale": (
            "2026-09-19 用 StratifiedGroupKFold(shuffle) × 12 輪重複 ＋ 配對統計"
            "重選。Enforce 唯一 12／12 全勝（0.6851，配對 CI [+0.0138, +0.0288]）、"
            "Permissive 255／255。sklearn 內建無額外相依，Pi 上推論 1.88 ms／場。"
            "另量到它**略微低估**自己（ECE 0.0414、過度自信 −0.0102），"
            "而 HistGB 嚴重高估（+0.2435）——與通用文獻相反，但這是本專案的量測。"
        ),
        "evidence": "文件/識別模型選型_折的缺陷與重複分層CV_2026-09-19.md",
        "superseded_warning": (
            "⚠️ 這推翻了 2026-09-16 推薦的 hist_gradient_boosting。那一輪用 "
            "GroupKFold，而它**不洗牌也不吃 seed**，所有數字來自同一個偏掉的"
            "折分割（每折缺 2–3 個完整類別）。排名因此重排。"
        ),
    },
    "temporal_expansion": {
        "value": "enabled",
        "rationale": (
            "2026-09-19 在修好的折上值 +0.0101。"
        ),
        "evidence": "文件/識別模型選型_折的缺陷與重複分層CV_2026-09-19.md",
        "superseded_warning": (
            "⚠️ 這推翻了 2026-09-16 的「換表述之後時序展開幾乎多餘（+0.003）」。"
            "同樣是壞折的產物。"
        ),
    },
    "ood_scorer_permissive": {
        "value": "max_softmax",
        "rationale": (
            "2026-09-24：worst_family 0.0000 → 0.9216（any）／0.5294（k3）、"
            "macro 0.6941 → 0.9843，**而且正常誤報更低**（0.0714 → 0.0455）。"
            "用 C2C-028 自己設計的對抗性協定重做，最差情況 0.9212 對 "
            "Mahalanobis 0.4514——連在專門針對它最弱兩類的那組上都是。"
        ),
        "evidence": "文件/未知攻擊_解析度與評分器_2026-09-24.md",
        "superseded_warning": (
            "⚠️ 這反轉了 C2C-028 在舊資料上選 Mahalanobis 的結論。"
            "未驗證的解釋：那一輪做在網路特徵壞掉的資料上（Zeek 無 -C、"
            "conn_count 虛增 7.96×），距離式對那種扭曲最敏感。"
        ),
    },
    "ood_scorer_enforce": {
        "value": UNDECIDED,
        "rationale": (
            "**刻意不決定。** 兩個量測互相矛盾：max_softmax 在對抗性最差情況贏"
            "（0.4275 對 0.3579）卻在 family-LOO 的閘門指標上輸（any-macro "
            "0.1168 對 0.2252），而三組 holdout 呈互補。真正的約束是閘門否決了 "
            "OOD 頭 88% 的拒絕，換評分器碰不到那個。出貨預設 isolation_forest "
            "不動，直到有證據能分開它們。"
        ),
        "evidence": "文件/未知攻擊_解析度與評分器_2026-09-24.md",
        "superseded_warning": None,
    },
    "unknown_session_pooling": {
        "value": "k_of_n_k2",
        "rationale": (
            "2026-09-25：**k 必須跟著評分器一起定。** C2C-060 在 mahalanobis／"
            "isolation_forest 上選 k=3，理由是四組的正常誤報全部降到 0.0000，"
            "那在當時是對的；但 2026-09-24 把 Permissive 的評分器凍結成 "
            "`max_softmax`，而它問的是完全不同的問題（有沒有任何已知類別敢認領"
            "這一列），最佳 k 不是 3。全解析度實測 k=3 的 "
            "`worst_family_unknown_recall` 只有 0.5294，**k=2 是 0.7647**，"
            "而兩者的最差正常誤報都是 **0.0000**——五折全部為零。"
            "⇒ 兩個驗收約束第一次同時成立，而且不付誤報代價。"
            "`alert_only`（只有 `discovery_recon`）從 P1 起每一組設定都是 0.0000，"
            "k=2 讓它變成 0.9412。兩種解析度互相印證（validation 0.7778 對"
            "全解析度 0.7647，差 0.013）。"
        ),
        "evidence": "文件/未知攻擊_k2讓兩個約束同時過_2026-09-25.md",
        "superseded_warning": (
            "⚠️ 這取代同一天早先註冊的 k=3（`文件/重訓預先註冊_2026-09-25.json`，"
            "canonical `e0342f49…6360`，**保留不刪**）。改動發生在 campaign 的"
            "新資料**存在之前**，那是這份註冊的設計用途；看過新 test 之後再改"
            "才是污染。"
            "⚠️ 而 k=2 本身仍然是**看過掃描結果之後**選的——掃描範圍"
            "（k=1..4 ＋ 三個比例）是 C2C-060 預先定義的，勝出的值是量出來的。"
            "把它釘在這裡，就是為了讓新 test 上不能再挑一次。"
            "⚠️ 這個值只對 **Permissive** 有量測支持。Enforce 的瓶頸是閘門否決了"
            "OOD 頭 88% 的拒絕，換 k 碰不到那個。"
        ),
    },
    "blind_spot_features": {
        "value": "retained_with_known_limitation",
        "rationale": (
            "`sros_auth_fail_rate` 與 `mean_bytes_per_packet` 是同一件事的兩個"
            "代理（這個 participant 合不合法）。2026-09-04 量到拿掉它們讓未見"
            "持證內鬼 recall 0.0885 → 0.6010，**但**同一天用 family-LOO 重量發現"
            "Enforce 的未見**外部**攻擊從 0.0667 塌到 0.0012。兩邊都不可接受 ⇒ "
            "留著並記錄限制，正解是換一個不在這條軸上的證據（封包層 RTPS 身份）。"
        ),
        "evidence": "文件/防禦反應特徵稽核_2026-09-04.md",
        "superseded_warning": (
            "⚠️ C2C-056 一度寫「代價幾乎是零」，是 C2C-057 用 family-LOO "
            "推翻的——我當時只量了三個軸，漏了整條未知偵測鏈。"
        ),
    },
}

# 最後那個 test 的規矩。這些不是設定，是協定。
SEALED_TEST_PROTOCOL = [
    "切分在任何模型擬合**之前**產生，並記下 test 場次清單的 SHA-256。",
    "test 只准評估**一次**。評估器對已存在的輸出檔必須拒絕覆寫。",
    "評估之後不得再調任何設定。要調就等下一批資料。",
    "若評估結果不如預期，那是結果，不是重跑的理由。",
    "open-set holdout 的 family 必須在切分時就決定，不可在看過分數後更換。",
]


def _digest(path: Path) -> tuple[int, str] | None:
    full = ROOT / path
    if not full.is_file():
        return None
    data = full.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()


def build_registration() -> dict:
    """組出註冊內容。每一項的證據檔案都必須存在,否則拒絕。"""
    settings = {}
    missing = []
    for name, spec in SETTINGS.items():
        info = _digest(Path(spec["evidence"]))
        if info is None:
            missing.append(spec["evidence"])
            continue
        size, sha = info
        settings[name] = {
            "value": spec["value"],
            "rationale": spec["rationale"],
            "evidence_path": spec["evidence"],
            "evidence_bytes": size,
            "evidence_sha256": sha,
            "supersedes_earlier_choice": spec["superseded_warning"],
        }
    if missing:
        raise RegistrationError(f"證據檔案不存在：{sorted(set(missing))}")

    undecided = sorted(k for k, v in settings.items() if v["value"] == UNDECIDED)
    body = {
        "schema_version": SCHEMA,
        "settings": settings,
        "undecided": undecided,
        "sealed_test_protocol": SEALED_TEST_PROTOCOL,
        "claims_nothing_about_quality": (
            "這份註冊不宣稱任何設定是好的。它們全部只是 CV 上的選擇，"
            "而 CV 不是 held-out test。它保證的只有一件事：跑新 test 的時候，"
            "這些值沒有被偷偷換過。"
        ),
    }
    body["registration_sha256"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return body


def verify_registration(registration: dict, *, actual: dict | None = None) -> dict:
    """反查:證據檔案沒變,而且(有給的話)實際設定與註冊相符。"""
    if registration.get("schema_version") != SCHEMA:
        raise RegistrationError(f"未知的 schema：{registration.get('schema_version')!r}")

    recorded = registration.get("registration_sha256")
    body = {k: v for k, v in registration.items() if k != "registration_sha256"}
    recomputed = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if recorded != recomputed:
        raise RegistrationError(
            f"註冊自身的雜湊不符：記的是 {recorded}，重算是 {recomputed}"
        )

    drifted, mismatched = [], []
    for name, spec in registration["settings"].items():
        info = _digest(Path(spec["evidence_path"]))
        if info is None or info[1] != spec["evidence_sha256"]:
            drifted.append(spec["evidence_path"])
        if actual is not None and name in actual:
            if actual[name] != spec["value"]:
                mismatched.append(
                    f"{name}: 註冊 {spec['value']!r} vs 實際 {actual[name]!r}"
                )

    if actual is not None:
        undecided_used = [
            n for n in registration["undecided"]
            if n in actual and actual[n] != UNDECIDED
        ]
        if undecided_used:
            mismatched.append(
                f"註冊為未定卻被填值：{undecided_used}"
                "——未定就是未定，要決定請另出一份註冊"
            )

    return {
        "registration_sha256": recorded,
        "evidence_drifted": sorted(drifted),
        "settings_mismatched": sorted(mismatched),
        "valid": not drifted and not mismatched,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path, help="產生一份新的註冊")
    group.add_argument("--verify", type=Path, help="反查一份既有的註冊")
    args = parser.parse_args(argv)

    if args.verify:
        registration = json.loads(args.verify.read_text(encoding="utf-8"))
        result = verify_registration(registration)
        print(f"registration_sha256 : {result['registration_sha256']}")
        print(f"valid               : {result['valid']}")
        if result["evidence_drifted"]:
            print("⚠️ 證據檔案已變動（引用檔演進，不是造假）：")
            for path in result["evidence_drifted"]:
                print(f"    {path}")
        return 0 if result["valid"] else 1

    if args.output.exists():
        print(f"⛔ 輸出已存在，拒絕覆寫：{args.output}", file=sys.stderr)
        return 2

    registration = build_registration()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(registration, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"{len(registration['settings'])} 項設定已註冊")
    for name, spec in sorted(registration["settings"].items()):
        mark = "⚠️ 未定" if spec["value"] == UNDECIDED else "  "
        print(f"  {mark} {name:<28} {spec['value']}")
    print()
    print(f"registration_sha256 : {registration['registration_sha256']}")
    print(f"註冊：{args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
