#!/usr/bin/env python3
"""哪些特徵是「盲點製造機」——對已知攻擊有用、對繞過防禦的攻擊視而不見？

## 為什麼要查

2026-09-03 量到身份通道（`sros_auth_fail_rate` 等）有一個危險的性質：
它對 14 個外部者攻擊類別的訊號是 59–417、對 `normal` 是 0，於是模型學到

    身份訊號 = 0  ⇒  正常

而**成功混進來的持證內鬼身份訊號正好也是 0**。結果：留出內鬼時，
帶著這個特徵的閘門 recall 是 0.1062，拿掉之後反而是 0.3187（**−0.2125**）。

> 用「防禦的反應」當特徵，會讓模型對防禦不反應的攻擊視而不見。

**但那次只查了一個特徵。** 出貨的遙測特徵裡，記錄「防禦拒絕了什麼」的
不只它一個：`hmac_failure_rate`、`log_reject_rate`、`oversized_message_ratio`、
`timestamp_violation_ratio`、`publisher_violation_ratio`、`qos_drop_ratio` …
每一個都是同一種形狀的東西。

**這支把那個問法套到每一個特徵上。**

## 判準不靠我分類

我可以憑直覺把特徵分成「防禦反應」與「攻擊行為」，但那是斷言不是量測。
改成**直接量那個性質**，兩個條件都成立才算：

| 條件 | 意思 | 判準 |
|---|---|---|
| 對外部者有判別力 | 模型會學著依賴它 | `abs(AUC_outsider - 0.5) >= --min-outsider-separation` |
| 對內鬼沒有判別力 | 內鬼會落在「正常」那一側 | `abs(AUC_insider - 0.5) < --max-insider-separation` |

兩個都成立 ⇒ 這個特徵**在已知威脅上有用、在繞過者身上是盲的**。

## 內建的有效性檢查

身份通道那兩個特徵**必須**被篩出來——它們的代價已經獨立量過。
篩不出來就是篩選器壞了，程式直接以非零碼結束，不會安靜地給出一張漂亮的表。
（要刻意關掉才能繞過，見 `--no-sanity-check`。）

## 兩個階段

1. **篩選**（全部特徵，不訓練）：上表兩個條件。便宜。
2. **消融**（只跑被篩出來的）：留出內鬼類別**整場**排除，訓練二元閘門，
   比較有無該特徵的 recall。這一步才是代價的實測。

## 分區

`--split` **必填**。這是刻意的：2026-09-03 那份文件寫「只用 validation
分區」，但它用的工具**根本沒有依 split 過濾**，訓練集裡混著 `split=test`
的列。結論沒有因此失效（留出類別整場排除、沒有調任何東西、評估集完全未見），
但那句話是錯的。**選錯分區不該沒有徵兆。**

## 用法

    python3 工具腳本/audit_defence_reaction_features.py \\
        --features ~/features_refresh_split/fusion_features_enforce.csv \\
        --insider hmac_forgery confused_deputy \\
        --split all \\
        --output 文件/防禦反應特徵稽核.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# 身份通道：代價已於 2026-09-03 獨立量到 −0.2125，用來驗篩選器有沒有壞
KNOWN_BLIND_SPOT_FEATURES = ("sros_auth_fail_rate", "sros_permission_deny_rate")

NON_FEATURE = frozenset({
    "session_id", "group_id", "capture_id", "scenario_id", "security_mode",
    "ros_domain_id", "origin", "source", "window", "window_start_unix",
    "label", "binary", "label_scope", "training_eligible",
    "evaluation_eligible", "policy_sha256", "split",
    # novelty_role 是字串（known／novelty_holdout_candidate），它直接標示
    # novelty holdout。既有工具沒有排除它，只是靠 float() 失敗變成常數 0
    # 才沒有洩漏——那是意外不是設計。明確排除。
    "novelty_role",
})

PURE_NORMAL_SCENARIO = "normal_patrol"


class AuditError(RuntimeError):
    """輸入不足以支撐判斷。刻意不吞——空表與「沒有盲點」是兩件事。"""


def load_rows(path: Path, split: str) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise AuditError(f"特徵表是空的：{path}")
    if split != "all":
        rows = [r for r in rows if r.get("split") == split]
        if not rows:
            raise AuditError(f"分區 {split!r} 沒有任何列")
    return rows


def feature_names(rows: list[dict]) -> list[str]:
    return sorted(n for n in rows[0] if n not in NON_FEATURE)


def column(rows: list[dict], name: str) -> list[float]:
    out = []
    for row in rows:
        raw = row.get(name)
        try:
            out.append(float(raw) if raw not in (None, "") else 0.0)
        except (TypeError, ValueError):
            out.append(0.0)
    return out


def auc(positive: list[float], negative: list[float]) -> float:
    """P(隨機正樣本 > 隨機負樣本)，同分算 0.5。

    自己算而不呼叫 sklearn，因為這一步要能在沒有變異的欄位上回傳恰好 0.5，
    而不是拋例外——恆為零的特徵正是我們要辨識的情況之一。
    """
    if not positive or not negative:
        raise AuditError("AUC 需要兩側都有樣本")
    merged = sorted((v, side) for side, vals in ((1, positive), (0, negative))
                    for v in vals)
    ranks: dict[int, float] = {}
    i = 0
    rank_sum_pos = 0.0
    while i < len(merged):
        j = i
        while j + 1 < len(merged) and merged[j + 1][0] == merged[i][0]:
            j += 1
        average_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            if merged[k][1] == 1:
                rank_sum_pos += average_rank
        i = j + 1
    n_pos, n_neg = len(positive), len(negative)
    return (rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def constant_features(rows: list[dict], names: list[str]) -> list[str]:
    """在這張表上完全沒有變異的特徵。

    死欄位**造不出盲點**——它對外部者也沒有判別力，模型學不到任何依賴它的
    規則。但它是另一種問題，必須分開報告：把「恆為零」和「有訊號但對繞過者
    盲目」混在一起，會讓兩個結論都失真。
    """
    dead = []
    for name in names:
        values = column(rows, name)
        if min(values) == max(values):
            dead.append(name)
    return dead


def screen(
    rows: list[dict],
    names: list[str],
    insider_labels: set[str],
    *,
    min_outsider: float,
    max_insider: float,
) -> list[dict]:
    """階段一：不訓練，只問兩個條件。"""
    normal = [r for r in rows
              if r["label"] == "normal"
              and r.get("scenario_id") == PURE_NORMAL_SCENARIO]
    insider = [r for r in rows if r["label"] in insider_labels]
    outsider = [r for r in rows
                if r["label"] != "normal" and r["label"] not in insider_labels]
    if not normal:
        raise AuditError("沒有純正常場次；攻擊場次裡的 normal 視窗帶著攻擊者痕跡，不可替代")
    if not insider:
        raise AuditError("沒有內鬼列——這支工具的整個問法就建立在它們身上")
    if not outsider:
        raise AuditError("沒有外部者列")

    results = []
    for name in names:
        n_vals = column(normal, name)
        out_auc = auc(column(outsider, name), n_vals)
        in_auc = auc(column(insider, name), n_vals)
        out_sep = abs(out_auc - 0.5)
        in_sep = abs(in_auc - 0.5)
        results.append({
            "feature": name,
            "auc_outsider_vs_normal": round(out_auc, 4),
            "auc_insider_vs_normal": round(in_auc, 4),
            "outsider_separation": round(out_sep, 4),
            "insider_separation": round(in_sep, 4),
            "discriminates_outsiders": out_sep >= min_outsider,
            "blind_to_insiders": in_sep < max_insider,
            "flagged": out_sep >= min_outsider and in_sep < max_insider,
        })
    results.sort(key=lambda r: (-r["outsider_separation"], r["insider_separation"]))
    return results


def gate_arm(train_rows, unseen_rows, normal_rows, names, seed) -> dict:
    """訓練二元閘門，回傳它對未見類別的 recall 與正常誤報率。

    協定與 `measure_unseen_gate_recall.py` 相同，好讓兩支的數字可以互相對照。
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    def matrix(rows):
        out = np.zeros((len(rows), len(names)), dtype=float)
        for i, row in enumerate(rows):
            for j, name in enumerate(names):
                out[i, j] = column([row], name)[0]
        return out

    y = np.array([0 if r["label"] == "normal" else 1 for r in train_rows])
    model = RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=-1,
    )
    model.fit(matrix(train_rows), y)
    return {
        "unseen_recall": float(model.predict(matrix(unseen_rows)).mean()),
        "normal_false_positive_rate": float(model.predict(matrix(normal_rows)).mean()),
        "features_used": len(names),
    }


def ablate(rows, names, holdout_labels: set[str], dropped: list[str], seed) -> dict:
    """留出類別**整場**排除，比較有無 `dropped` 的閘門。

    整場排除是必要的：同一場裡攻擊區間外的 normal 視窗也帶著攻擊者的痕跡，
    留在訓練集裡等於讓模型看過那個類別。
    """
    holdout_sessions = {r["session_id"] for r in rows if r["label"] in holdout_labels}
    train = [r for r in rows if r["session_id"] not in holdout_sessions]
    unseen = [r for r in rows
              if r["session_id"] in holdout_sessions and r["label"] in holdout_labels]
    normal = [r for r in train
              if r["label"] == "normal" and r.get("scenario_id") == PURE_NORMAL_SCENARIO]
    if not unseen or not normal:
        raise AuditError(f"留出 {sorted(holdout_labels)} 之後沒有可評估的列")

    kept = [n for n in names if n not in set(dropped)]
    if len(kept) == len(names):
        raise AuditError(f"要拿掉的特徵不在表裡：{dropped}")

    with_it = gate_arm(train, unseen, normal, names, seed)
    without = gate_arm(train, unseen, normal, kept, seed)
    return {
        "holdout_labels": sorted(holdout_labels),
        "dropped": sorted(dropped),
        "holdout_sessions": len(holdout_sessions),
        "unseen_rows": len(unseen),
        "normal_rows": len(normal),
        "train_rows": len(train),
        "with_feature": with_it,
        "without_feature": without,
        "delta_unseen_recall": round(
            with_it["unseen_recall"] - without["unseen_recall"], 4),
        "harmful": with_it["unseen_recall"] < without["unseen_recall"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--insider", nargs="+", required=True,
                        help="持證內鬼類別——繞過第一道防線的那些")
    parser.add_argument("--split", required=True,
                        choices=("all", "train", "validation", "test"),
                        help="必填。選錯分區不該沒有徵兆")
    parser.add_argument("--min-outsider-separation", type=float, default=0.20,
                        help="對外部者的判別力下限（AUC 距 0.5），預設 0.20")
    parser.add_argument("--max-insider-separation", type=float, default=0.10,
                        help="對內鬼的判別力上限，預設 0.10")
    parser.add_argument("--no-sanity-check", action="store_true",
                        help="關掉「篩選器必須重新發現身份通道」的檢查")
    parser.add_argument("--skip-ablation", action="store_true",
                        help="只跑階段一")
    parser.add_argument("--controls", type=int, default=3,
                        help="拿幾個沒被篩出來的高判別力特徵當陰性對照")
    parser.add_argument("--seed", type=int, default=20260904)
    parser.add_argument("--output", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rows = load_rows(args.features, args.split)
        names = feature_names(rows)
        insider = set(args.insider)
        missing = sorted(insider - {r["label"] for r in rows})
        if missing:
            raise AuditError(f"特徵表裡沒有這些內鬼類別：{missing}")

        dead = constant_features(rows, names)
        live = [n for n in names if n not in set(dead)]
        if not live:
            raise AuditError("這張表上沒有任何有變異的特徵")
        screened = screen(rows, live, insider,
                          min_outsider=args.min_outsider_separation,
                          max_insider=args.max_insider_separation)
    except AuditError as exc:
        print(f"⛔ {exc}")
        return 2

    flagged = [r["feature"] for r in screened if r["flagged"]]

    print("=== 階段〇：死欄位 ===")
    print(f"  {len(dead)} / {len(names)} 個特徵在這張表上恆為常數，"
          f"對任何模型都沒有作用。")
    for name in dead:
        print(f"    {name}")
    print("  死欄位造不出盲點——它對外部者也沒有判別力。分開報告，不進篩選。")
    print()

    print("=== 階段一：盲點篩選 ===")
    print(f"  特徵表   : {args.features}")
    print(f"  分區     : {args.split}（{len(rows)} 列）")
    print(f"  活特徵   : {len(live)}")
    print(f"  內鬼類別 : {sorted(insider)}")
    print(f"  判準     : 外部者 AUC 距 0.5 >= {args.min_outsider_separation}"
          f" 且 內鬼 < {args.max_insider_separation}")
    print()
    print("  %-30s %10s %10s  %s" % ("特徵", "外部者AUC", "內鬼AUC", "判定"))
    for r in screened:
        if not r["discriminates_outsiders"]:
            continue
        mark = "⚠ 盲點" if r["flagged"] else "  ok"
        print("  %-30s %10.4f %10.4f  %s"
              % (r["feature"], r["auc_outsider_vs_normal"],
                 r["auc_insider_vs_normal"], mark))
    print()
    print(f"  被篩出來的 : {flagged or '（無）'}")

    if not args.no_sanity_check:
        # 死掉的已知特徵不算漏掉：它連對外部者都沒有判別力，模型學不到任何
        # 依賴它的規則，所以它不可能製造盲點。要求它被篩出來才是判準有問題。
        undetected = [f for f in KNOWN_BLIND_SPOT_FEATURES
                      if f in live and f not in flagged]
        if undetected:
            print()
            print("⛔ 篩選器沒有重新發現已知的盲點特徵：%s" % undetected)
            print("   它們的代價（−0.2125）已於 2026-09-03 獨立量到。")
            print("   篩不出來代表判準或資料有問題，不是「沒有盲點」。")
            return 3
        dead_known = [f for f in KNOWN_BLIND_SPOT_FEATURES if f in dead]
        if dead_known:
            print()
            print("  ⓘ 已知盲點特徵裡有 %s 在這張表上恆為常數。" % dead_known)
            print("    2026-09-03 把身份通道當成一對來量，但**只有一個帶訊號**；")
            print("    另一個從頭到尾是死欄位，那次的 −0.2125 完全來自帶訊號的那個。")

    ablations = []
    if flagged and not args.skip_ablation:
        print()
        print("=== 階段二：消融（留出內鬼整場排除）===")
        groups = [([f], "flagged") for f in flagged]
        if len(flagged) > 1:
            groups.append((list(flagged), "flagged"))
        # 陰性對照：拿掉判別力最強但**沒被篩出來**的特徵。如果隨便拿掉哪個
        # 特徵內鬼 recall 都會上升，那這個消融量的就不是「盲點」而是別的東西。
        controls = [r["feature"] for r in screened
                    if not r["flagged"] and r["discriminates_outsiders"]][:args.controls]
        groups.extend(([c], "control") for c in controls)
        if controls:
            print(f"  陰性對照：{controls}")
        for dropped, role in groups:
            try:
                result = ablate(rows, names, insider, dropped, args.seed)
            except AuditError as exc:
                print(f"  ⛔ {dropped}: {exc}")
                return 2
            result["role"] = role
            ablations.append(result)
            label = "全部" if len(dropped) > 1 else dropped[0]
            tag = "⚠ 有害" if result["harmful"] else ""
            if role == "control":
                label = "[對照] " + label
            print("  %-38s 有 %.4f  無 %.4f  差 %+.4f %s"
                  % (label, result["with_feature"]["unseen_recall"],
                     result["without_feature"]["unseen_recall"],
                     result["delta_unseen_recall"], tag))

    report = {
        "schema_version": "sros2-firewall-defence-reaction-audit/v1",
        "features_table": str(args.features),
        "split": args.split,
        "rows": len(rows),
        "insider_labels": sorted(insider),
        "thresholds": {
            "min_outsider_separation": args.min_outsider_separation,
            "max_insider_separation": args.max_insider_separation,
        },
        "sanity_check_enforced": not args.no_sanity_check,
        "screen": screened,
        "flagged_features": flagged,
        "constant_features": dead,
        "live_features": len(live),
        "ablations": ablations,
        "seed": args.seed,
        "changes_shipped_defaults": False,
    }
    if args.output:
        if args.output.exists():
            print(f"\n⛔ 輸出已存在，拒絕覆寫：{args.output}")
            return 2
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8")
        print(f"\n  報告：{args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
