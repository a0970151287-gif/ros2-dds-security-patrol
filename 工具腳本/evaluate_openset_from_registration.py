#!/usr/bin/env python3
"""照預先註冊評估未知攻擊，並把封印的 novelty holdout 開封**一次**。

## 為什麼需要它

識別那一半有一條不可分割的路徑（`retrain_from_registration.py`：驗註冊 →
驗封印 → 擬合 → 開封一次 → 評估 → 寫產物）。**未知攻擊那一半沒有。**

它的一次性保護**只有** `evaluate_openset_holdout.py` 的「輸出檔已存在就拒絕
覆寫」——而換一個 `--output` 路徑就能再跑一次。那不是假設性的弱點：活狀態表
的待辦自己寫著「現有的已用第三次，數字不可引用」。

> **強機制（封印）存在，而它從來沒有被接到這一半。** 這一支把它接上。

## 兩個 holdout 是兩件不同的東西

| | 識別（多類） | 未知攻擊（open-set） |
|---|---|---|
| holdout | `split == test`（場次層級，每一類都在） | `novelty_role == novelty_holdout_candidate`（**整個類別**被留出） |
| 分布 | 只在 test | **跨 train／validation／test 三處** |
| 封印 scope | `test` | `novelty_holdout` |

實測（refresh permissive）：test 45 場、novelty 40 場、**交集只有 6 場**。
`novelty_role` 與 `split` 是**正交**的，所以兩個封印並存而互不擋住對方
——「只開一次」這個性質**不必**被鬆成「每個消費者各開一次」。

## 它拒絕做的事

| 情況 | 行為 |
|---|---|
| 註冊自己的雜湊對不上 | 拒絕 |
| 這個模式的 OOD scorer 是 `undecided` | 拒絕（Enforce 現況就是；見下） |
| 封印的 scope 不是 `novelty_holdout` | 拒絕（拿錯封印會燒掉另一半） |
| 封印已經開過 | 拒絕，**在讀任何 holdout 列之前** |
| 封印與這批特徵不符 | 拒絕 |
| 輸出已存在 | 拒絕覆寫 |

⚠️ **開封在擬合之後才發生。** 擬合只用 train＋validation 的非 holdout 列，
所以即使評估失敗，holdout 也不會被多花一次；反過來若先開封再擬合，
一次擬合失敗就浪費掉整個 holdout（`retrain_from_registration.py` 同一個順序）。

⚠️ **Enforce 會被拒絕，而那是誠實的。** r4 的 `ood_scorer_enforce` 是
`undecided`，理由是 C2C-088 把三個評分器 × 八種池化規則共 24 格掃完，
`worst_family_unknown_recall` **全部是 0.0000** ⇒ 那個選擇在宣告的格子裡
不可能有影響。隨手填一個值會讓這一輪的 holdout 變成一次不可重複的猜測。

## 它不重寫任何既有實作

`load_codex_module`／`fit_attack_ood`／`k_of_n_rate` 全部從
`evaluate_unknown_at_full_resolution.py` **匯入**，擬合用的是
`hierarchical_training` 的同一組函式。C2C-060 記過兩份實作會慢慢分歧，
而這裡的後果特別嚴重：holdout 只能開一次，所以一個與 validation 量測分歧的
評估器會把唯一的機會花在一個不可比的數字上。

用法：

    python3 工具腳本/seal_holdout.py seal --scope novelty_holdout \\
        --features <features>/fusion_features_permissive.csv \\
        --registration 文件/重訓預先註冊_2026-09-27_r4.json \\
        --output 文件/封印_openset_permissive.json

    python3 工具腳本/evaluate_openset_from_registration.py \\
        --registration 文件/重訓預先註冊_2026-09-27_r4.json \\
        --seal 文件/封印_openset_permissive.json \\
        --features <features>/fusion_features_permissive.csv \\
        --metrics <models_hier/permissive>/training_metrics.json \\
        --output 文件/未知攻擊_封印holdout_permissive.json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCHEMA = "sros2-firewall-openset-sealed-holdout/v1"
# ⚠️ 兩套詞彙,別搞混（演練抓到的第二個缺陷就是拿前者去比對後者）:
#   REQUIRED_SCOPE  是**封印的 scope 名**（seal_holdout.py 的 SCOPE_READERS 的鍵）
#   HOLDOUT_ROLE    是**特徵表 novelty_role 欄的值**
# 後者從 seal_holdout 匯入,所以只有一個來源。
REQUIRED_SCOPE = "novelty_holdout"
# 這一支只執行這兩項；其餘由識別那一半執行（retrain_from_registration.py）。
EXECUTED_SETTINGS = ("ood_scorer_permissive", "ood_scorer_enforce",
                     "unknown_session_pooling")
POOLING_PREFIX = "k_of_n_k"


class OpenSetError(RuntimeError):
    """註冊、封印或設定不符。刻意不吞。"""


def _load(name: str, filename: str, needs: tuple[str, ...]):
    path = ROOT / "工具腳本" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    for need in needs:
        if not hasattr(module, need):
            raise OpenSetError(f"{filename} 缺少 {need}——介面變了，請先對齊")
    return module


def parse_pooling(value: str) -> int:
    """`k_of_n_k2` → 2。只接受註冊宣告過的形狀。"""
    if not isinstance(value, str) or not value.startswith(POOLING_PREFIX):
        raise OpenSetError(
            f"不認識的池化設定：{value!r}（要 {POOLING_PREFIX}<k>）"
        )
    tail = value[len(POOLING_PREFIX):]
    if not tail.isdigit() or int(tail) < 1:
        raise OpenSetError(f"池化的 k 不合法：{value!r}")
    return int(tail)


def check_settings(registration: dict, mode: str) -> dict:
    """要用的設定必須與註冊逐字相符，而且未定的不能被填。"""
    prereg = _load("_prereg_os", "preregister_retraining.py",
                   ("verify_registration", "UNDECIDED"))
    settings = registration["settings"]
    missing = [k for k in EXECUTED_SETTINGS if k not in settings]
    if missing:
        raise OpenSetError(
            f"註冊少了這些項目，無法確認會照它跑：{missing}。"
            "一份不完整的註冊比沒有註冊更危險——它看起來像有保證。"
        )

    key = f"ood_scorer_{mode}"
    scorer = settings[key]["value"]
    if scorer == prereg.UNDECIDED:
        raise OpenSetError(
            f"註冊把 {key} 寫成未定，本工具需要它才能跑。"
            "隨手填一個值會讓這一輪的 holdout 變成一次不可重複的猜測"
            "（Enforce 的理由見 C2C-088：宣告的 24 格全是 0.0000）。"
        )
    pooling = settings["unknown_session_pooling"]["value"]
    if pooling == prereg.UNDECIDED:
        raise OpenSetError("註冊把 unknown_session_pooling 寫成未定")

    actual = {k: settings[k]["value"] for k in EXECUTED_SETTINGS}
    result = prereg.verify_registration(registration, actual=actual)
    if result["settings_mismatched"]:
        raise OpenSetError(f"設定與註冊不符：{result['settings_mismatched']}")
    return {
        "registration_sha256": result["registration_sha256"],
        "evidence_drifted": result["evidence_drifted"],
        "scorer": scorer,
        "pooling": pooling,
        "pooling_k": parse_pooling(pooling),
    }


def evaluate(features: Path, metrics_path: Path, *, scorer: str, pooling_k: int,
             holdout_sessions: list[str], seed: int, n_estimators: int,
             maximum_normal_fpr: float, maximum_known_attack_ood_fpr: float,
             open_seal) -> dict:
    """擬合非 holdout 的列 → 開封一次 → 只評估一次。

    `open_seal` 刻意傳成 callable 而不是旗標:呼叫點因此與「擬合成功之後才開封」
    這個順序綁在一起,而不是依賴呼叫者記得照順序做。
    """
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    from firewall_lab.hierarchical_training import (
        _expanded_matrix, _fit_isolation_detector, _quantile_threshold,
        _session_equal_weights, choose_binary_threshold,
    )

    full = _load("_fullres", "evaluate_unknown_at_full_resolution.py",
                 ("load_codex_module", "fit_attack_ood", "k_of_n_rate"))
    codex = full.load_codex_module()
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    frame = pd.read_csv(features)

    required = set(codex.RAW_FEATURES) | {
        "group_id", "session_id", "source", "window", "label", "split",
        "security_mode", "novelty_role",
    }
    missing = required - set(frame)
    if missing:
        raise OpenSetError(f"特徵表缺欄位：{sorted(missing)}")
    if set(frame["security_mode"].astype(str)) != {metrics["security_mode"]}:
        raise OpenSetError("特徵表的模式與 training metrics 不符")

    excluded = set(metrics.get("applicable_excluded_sessions", []))
    if excluded:
        frame = frame.loc[
            ~frame["group_id"].astype(str).isin(excluded)
        ].reset_index(drop=True)

    matrix = _expanded_matrix(frame, metrics["source_availability"])
    labels = frame["label"].astype(str).to_numpy()
    groups = frame["group_id"].astype(str).to_numpy()
    split = frame["split"].astype(str).to_numpy()
    attack = labels != "normal"

    # 封印綁的場次清單就是 holdout 的定義。特徵表自己標的 novelty_role 必須
    # 與它逐一相符——不符代表資料被換過,而那會讓這次開封評估到另一批東西。
    sealed = set(holdout_sessions)
    seal_mod = _load("_seal_os_eval", "seal_holdout.py", ("HOLDOUT_ROLE",))
    marked = set(frame.loc[
        frame["novelty_role"].astype(str) == seal_mod.HOLDOUT_ROLE, "group_id"
    ].astype(str))
    if sealed != marked:
        raise OpenSetError(
            f"封印的 holdout 場次與特徵表的 novelty_role 不符"
            f"（封印 {len(sealed)}／表 {len(marked)}／交集 {len(sealed & marked)}）"
        )
    official = np.isin(groups, list(sealed))
    if not official.any():
        raise OpenSetError("holdout 在特徵表裡一列都沒有")

    # ⚠️ 兩個層級,演練抓到我把它們混在一起。
    #
    # `novelty_role` 是**場次**層級的標記,而 C2C-035 量過 393／550 場同時含
    # `normal` 與攻擊列 ⇒ 一個 holdout 場次的 normal 列也被標了。
    #
    #   排除擬合  → 用**場次**（整場都不准進 fit／threshold／reference）
    #   評估 recall → 用**類別**（只有留出類別的攻擊列才是「未知攻擊」）
    #
    # 把 holdout 場次的 normal 列算進 recall 的分母會系統性地壓低它,
    # 而 `evaluate_openset_holdout.py` 一直都是按 label 選的。
    declared = sorted(set(metrics["novelty_protocol"]["holdout_labels"]))
    present = sorted(set(labels[official]))
    if not set(declared) <= set(present):
        raise OpenSetError(
            f"training metrics 宣告的 holdout 類別沒有全部出現在封印的場次裡："
            f"宣告 {declared}／實際 {present}"
        )
    unexpected = sorted(set(present) - set(declared) - {"normal"})
    if unexpected:
        raise OpenSetError(
            f"封印的 holdout 場次含既不是留出類別也不是 normal 的列：{unexpected}"
        )
    holdout_labels = declared

    base_train = (split == "train") & ~official
    validation = (split == "validation") & ~official
    threshold_groups = set(metrics["validation_protocol"]["threshold_groups"])
    reference_groups = set(metrics["validation_protocol"]["selection_groups"])
    if threshold_groups & reference_groups:
        raise OpenSetError("threshold 與 reference 的場次重疊")
    tg_mask = np.isin(groups, list(threshold_groups))
    rg_mask = np.isin(groups, list(reference_groups))

    fit_i = np.flatnonzero(base_train)
    thr_i = np.flatnonzero(validation & tg_mask)
    nor_i = np.flatnonzero(validation & rg_mask & ~attack)
    kno_i = np.flatnonzero(validation & rg_mask & attack)
    if any(not len(i) for i in (fit_i, thr_i, nor_i, kno_i)):
        raise OpenSetError("協定分區有空的")

    # 硬性：holdout 一列都不准進擬合或定門檻的任何一處。
    for name, index in (("fit", fit_i), ("threshold", thr_i),
                        ("normal_reference", nor_i), ("known_reference", kno_i)):
        if bool(official[index].any()):
            raise OpenSetError(f"holdout 列漏進了 {name}——會洩漏")
    if bool(((split == "test") & base_train).any()):
        raise OpenSetError("test 列漏進了 base_train")

    fit_binary = np.where(labels[fit_i] == "normal", "normal", "attack")
    binary = RandomForestClassifier(
        n_estimators=n_estimators, max_depth=16, min_samples_leaf=2,
        max_features="sqrt", class_weight="balanced_subsample",
        random_state=seed, n_jobs=1)
    binary.fit(matrix[fit_i], fit_binary,
               sample_weight=_session_equal_weights(frame, fit_i))

    normal_fit = fit_i[labels[fit_i] == "normal"]
    attack_fit = fit_i[labels[fit_i] != "normal"]
    normality = _fit_isolation_detector(
        matrix[normal_fit], _session_equal_weights(frame, normal_fit),
        seed=seed + 100, n_estimators=n_estimators)
    attack_ood = full.fit_attack_ood(
        codex, scorer, matrix[attack_fit], labels[attack_fit],
        _session_equal_weights(frame, attack_fit),
        seed=seed + 200, n_estimators=n_estimators)

    thr_binary = np.where(labels[thr_i] == "normal", "normal", "attack")
    binary_sel = choose_binary_threshold(
        thr_binary, codex._probability(binary, matrix[thr_i], "attack"),
        maximum_normal_fpr=maximum_normal_fpr,
        sample_weight=_session_equal_weights(frame, thr_i))
    normality_thr = _quantile_threshold(
        normality.score_samples(matrix[thr_i[labels[thr_i] == "normal"]]),
        maximum_normal_fpr)
    attack_ood_thr = _quantile_threshold(
        attack_ood.score_samples(matrix[thr_i[labels[thr_i] != "normal"]]),
        maximum_known_attack_ood_fpr)

    def flagged(index):
        """閘門：`rejected AND (binary OR abnormal)`，三個成分分開記。

        C2C-042 用這個分解證明 59% 的損失來自閘門，C2C-045 又證明那 59% 不可
        回收。一個只報結論的產物沒辦法回答「是閘門擋掉還是證據沒有」。
        """
        binary_says = (
            codex._probability(binary, matrix[index], "attack")
            >= float(binary_sel["threshold"])
        )
        abnormal = normality.score_samples(matrix[index]) < normality_thr
        rejected = attack_ood.score_samples(matrix[index]) < attack_ood_thr
        unknown = rejected & (binary_says | abnormal)
        return binary_says, abnormal, rejected, unknown

    # ⚠️ 到這裡為止一列 holdout 都沒有被讀。開封在擬合成功之後。
    seal_record = open_seal()

    # 只有留出類別的攻擊列。holdout 場次的 normal 列已經被排除在擬合之外,
    # 但它們不是「未知攻擊」,所以不進 recall 的分母。
    unknown_i = np.flatnonzero(official & np.isin(labels, holdout_labels))
    if not len(unknown_i):
        raise OpenSetError("封印的 holdout 場次裡沒有任何留出類別的列")
    b, a, r, u = flagged(unknown_i)
    nb, na, nr, nu = flagged(nor_i)
    kb, ka, kr, ku = flagged(kno_i)

    row_recall = float(u.mean())
    session_recall = float(full.k_of_n_rate(groups[unknown_i], u, pooling_k))
    normal_row = float(nu.mean())
    normal_session = float(full.k_of_n_rate(groups[nor_i], nu, pooling_k))
    known_row = float(ku.mean())

    per_label = {}
    for label in holdout_labels:
        hit = labels[unknown_i] == label
        if not hit.any():
            continue
        per_label[label] = {
            "rows": int(hit.sum()),
            "sessions": int(len(set(groups[unknown_i][hit]))),
            "row_recall": round(float(u[hit].mean()), 4),
            "session_recall": round(float(full.k_of_n_rate(
                groups[unknown_i][hit], u[hit], pooling_k)), 4),
            "ood_rejected": round(float(r[hit].mean()), 4),
            "binary_says_attack": round(float(b[hit].mean()), 4),
            "abnormal": round(float(a[hit].mean()), 4),
        }

    return {
        "seal": seal_record,
        "holdout_labels": holdout_labels,
        "holdout_sessions": int(len(sealed)),
        "holdout_rows_evaluated": int(len(unknown_i)),
        # 分母是「留出類別的攻擊列」,不是 holdout 場次的全部列。
        # 兩者的差就是那些場次裡的 normal 列,記下來讓它可稽核。
        "holdout_session_rows_total": int(official.sum()),
        "holdout_normal_rows_excluded": int(official.sum() - len(unknown_i)),
        "fit_rows": int(len(fit_i)),
        "row_recall": round(row_recall, 4),
        "session_recall_k_of_n": round(session_recall, 4),
        "normal_false_unknown_row_rate": round(normal_row, 4),
        "normal_false_unknown_session_rate": round(normal_session, 4),
        "known_attack_false_unknown_row_rate": round(known_row, 4),
        "per_label": per_label,
        "binary_threshold": float(binary_sel["threshold"]),
        "thresholds": {
            "normality": float(normality_thr),
            "attack_ood": float(attack_ood_thr),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--seal", type=Path, required=True)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260825)
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--maximum-normal-fpr", type=float, default=0.02)
    parser.add_argument("--maximum-known-attack-ood-fpr", type=float, default=0.05)
    args = parser.parse_args(argv)

    if args.output.exists():
        print(f"⛔ 產物已存在，拒絕覆寫：{args.output}", file=sys.stderr)
        return 2

    seal_mod = _load("_seal_os", "seal_holdout.py",
                     ("require_unopened", "verify_seal", "open_once",
                      "scope_of"))
    registration = json.loads(args.registration.read_text(encoding="utf-8"))
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    mode = str(metrics.get("security_mode") or "")
    if mode not in ("permissive", "enforce"):
        # ⚠️ 空字串幾乎一定是「挑錯 metrics 檔」:grouped 線的 training_metrics
        # 沒有 security_mode／novelty_protocol／validation_protocol 三者,
        # 而這一支要的是 hierarchical（parallel gate）線的那一份。
        # 演練時我自己就挑錯了,而原本的訊息沒說出它讀的是哪個鍵。
        print(
            f"⛔ {args.metrics} 的 security_mode 是 {mode!r}（要 permissive "
            "或 enforce）。這一支要的是 **hierarchical（parallel gate）線**的 "
            "training_metrics.json——它同時有 security_mode、"
            "novelty_protocol.holdout_labels 與 validation_protocol."
            "{threshold_groups,selection_groups}。grouped 線的那一份沒有後兩者。",
            file=sys.stderr,
        )
        return 2

    try:
        checked = check_settings(registration, mode)
        # ⚠️ 在讀任何 holdout 列之前。scope 必須相符,否則會燒掉另一半。
        seal = seal_mod.require_unopened(args.seal, expected_scope=REQUIRED_SCOPE)
        verdict = seal_mod.verify_seal(seal, args.features)
        if not verdict["valid"]:
            raise OpenSetError(f"封印不成立：{verdict['problems']}")
        if seal.get("registration_sha256") != checked["registration_sha256"]:
            raise OpenSetError("封印綁的註冊與這次給的註冊不是同一份")

        report = evaluate(
            args.features, args.metrics,
            scorer=checked["scorer"], pooling_k=checked["pooling_k"],
            holdout_sessions=list(seal["test_sessions"]),
            seed=args.seed, n_estimators=args.n_estimators,
            maximum_normal_fpr=args.maximum_normal_fpr,
            maximum_known_attack_ood_fpr=args.maximum_known_attack_ood_fpr,
            open_seal=lambda: seal_mod.open_once(
                args.seal,
                f"open-set 評估（{mode}／{checked['scorer']}／"
                f"{checked['pooling']}）",
            ),
        )
    except Exception as exc:  # noqa: BLE001 - 原因要出現在 stderr
        print(f"⛔ {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 4

    report.update({
        "schema_version": SCHEMA,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "security_mode": mode,
        # 產物要記得住自己（2026-09-25 的教訓：沒記 seed／n_estimators 的產物
        # 重現不了自己前一天的結果，而「重現不了」與「結果變了」長得一樣）。
        "registration_path": str(args.registration),
        "registration_sha256": checked["registration_sha256"],
        "registration_evidence_drifted": checked["evidence_drifted"],
        "executed_settings": {
            "attack_ood_scorer": checked["scorer"],
            "unknown_session_pooling": checked["pooling"],
            "pooling_k": checked["pooling_k"],
        },
        "seed": args.seed,
        "n_estimators": args.n_estimators,
        "maximum_normal_fpr": args.maximum_normal_fpr,
        "maximum_known_attack_ood_fpr": args.maximum_known_attack_ood_fpr,
        "features_path": str(args.features),
        "metrics_path": str(args.metrics),
        "holdout_opened_once": True,
        "changes_shipped_defaults": False,
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"模式                : {mode}")
    print(f"評分器／池化        : {checked['scorer']}／{checked['pooling']}")
    print(f"holdout             : {report['holdout_sessions']} 場"
          f"／評估 {report['holdout_rows_evaluated']} 列"
          f"（場次共 {report['holdout_session_rows_total']} 列，"
          f"其中 normal {report['holdout_normal_rows_excluded']} 列不計）"
          f"  {report['holdout_labels']}")
    print(f"open-set recall 列  : {report['row_recall']}")
    print(f"open-set recall 場次: {report['session_recall_k_of_n']}"
          f"  （k={checked['pooling_k']}）")
    print(f"正常誤報 列／場次   : "
          f"{report['normal_false_unknown_row_rate']}"
          f"／{report['normal_false_unknown_session_rate']}")
    print(f"已知攻擊誤否決 列   : "
          f"{report['known_attack_false_unknown_row_rate']}")
    print(f"\n寫出: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
