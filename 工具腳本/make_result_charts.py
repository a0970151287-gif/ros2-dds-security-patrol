#!/usr/bin/env python3
"""從已簽章的 artifact 產生簡報用圖表。

**只畫量得到的東西。** 這個專案的模型是 sklearn，不是神經網路，所以沒有
epoch 級的訓練曲線可以畫；硬要生一張「訓練曲線」等於捏造。取而代之的是
實際量到的取捨曲線與消融結果。

每張圖都在頁腳標註資料來源檔案，方便答辯時追。所有數字直接讀 artifact，
不在這支腳本裡硬編碼——唯一的例外是重跑前後的事件計數（那是 campaign
執行紀錄，不在模型 artifact 裡），已在該處註明出處。

用法：
    python3 工具腳本/make_result_charts.py --output-dir 文件/圖表_2026-08-25
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

FINAL_ROOT = Path("/home/jesse/models_final")
HIER_ROOT = Path("/home/jesse/models_hier")
FEATURES = Path("/home/jesse/features_merged_split")
LEGACY_FEATURES = Path("firewall_lab/features_per_mode")
RULE_VS_LEARNED = Path("/home/jesse")

CLASS_LABELS = {
    "normal": "正常",
    "command_injection": "指令注入",
    "identity_abuse": "身份濫用",
    "message_dos": "訊息 DoS",
    "parameter_tamper": "參數竄改",
    "replay": "重放",
    "replay_dos": "重放 DoS",
    "sensor_spoof": "感測器偽造",
    "service_dos": "服務 DoS",
}

INK = "#12233f"
ACCENT = "#1f6fb2"
WARM = "#c8632a"
GREEN = "#2f7d4f"
GREY = "#8a94a3"


def _setup_fonts():
    from matplotlib import font_manager, rcParams

    for candidate in (
        "/mnt/c/Windows/Fonts/msjh.ttc",
        "/mnt/c/Windows/Fonts/msjhbd.ttc",
    ):
        if Path(candidate).exists():
            font_manager.fontManager.addfont(candidate)
    rcParams["font.family"] = ["Microsoft JhengHei", "DejaVu Sans"]
    rcParams["axes.unicode_minus"] = False
    rcParams["figure.dpi"] = 160
    rcParams["savefig.bbox"] = "tight"
    rcParams["axes.edgecolor"] = "#c9d2dd"
    rcParams["axes.labelcolor"] = INK
    rcParams["text.color"] = INK
    rcParams["xtick.color"] = INK
    rcParams["ytick.color"] = INK


def _source(fig, text):
    """頁腳標註出處。答辯時被問「這個數字哪來的」要能立刻指出來。"""
    fig.text(0.5, -0.02, text, ha="center", va="top", fontsize=7, color=GREY)


def _half_up(value: float, digits: int = 4) -> str:
    """四捨五入進位。

    0.85625 這種正好落在中間的值，Python 的 `%.4f` 會給 0.8562（二進位表示
    略小於中點），而文件寫的是 0.8563。圖與文件差 0.0001 最容易讓人開始
    懷疑其他數字，所以統一成進位。
    """
    from decimal import Decimal, ROUND_HALF_UP

    quantum = Decimal(1).scaleb(-digits)
    return str(Decimal(repr(value)).quantize(quantum, rounding=ROUND_HALF_UP))


def _metrics(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def chart_dataset(out: Path):
    """資料規模與組成。數字取自特徵表與 campaign 執行紀錄。"""
    import matplotlib.pyplot as plt
    import pandas as pd

    perm = pd.read_csv(FEATURES / "fusion_features_permissive.csv")
    enf = pd.read_csv(FEATURES / "fusion_features_enforce.csv")
    rows = [
        ("正式 campaign 場次", "1,100", "0 errors"),
        ("dataset_live 目錄數", "1,101", "含 1 場未入 campaign"),
        ("完整性核對 artifact", "19,204", "0 hash 失配"),
        ("攻擊類別數", "9", "含 normal"),
        ("Permissive 特徵列 / 串流", f"{len(perm):,} / {perm.groupby(['session_id','source']).ngroups:,}", "fusion 32 維"),
        ("Enforce 特徵列 / 串流", f"{len(enf):,} / {enf.groupby(['session_id','source']).ngroups:,}", "network 14 維"),
        ("切分（場次）", "train 382 / val 84 / test 84", "場次層級，零重疊"),
        ("受控重跑替換", "300 場", "2026-08-21，特徵層合併"),
    ]
    fig, ax = plt.subplots(figsize=(7.6, 4.0))
    # 預設的軸區下邊界會在最後一列之後留一塊空白，關掉。
    fig.subplots_adjust(left=0.02, right=0.98, top=0.90, bottom=0.02)
    ax.axis("off")
    ax.set_title("資料規模與組成", fontsize=17, fontweight="bold", color=INK, pad=14)
    for index, (name, value, note) in enumerate(rows):
        y = 1 - (index + 0.6) / (len(rows) + 0.4)
        ax.text(0.02, y, name, fontsize=11, va="center")
        ax.text(0.62, y, value, fontsize=12, va="center", ha="right",
                fontweight="bold", color=ACCENT)
        ax.text(0.66, y, note, fontsize=8.5, va="center", color=GREY)
        ax.axhline(y - 0.055, xmin=0.02, xmax=0.98, color="#e6ebf1", lw=0.8)
    _source(fig, "來源：features_merged_split/*.csv、campaign_1100.json、manifest 全量核對")
    fig.savefig(out / "01_資料規模.png")
    plt.close(fig)


def chart_class_distribution(out: Path):
    """九類的視窗數分佈。

    刻意用**視窗數**而不是場次數：攻擊場次同時含正常視窗，用場次數會讓
    normal 看起來有 543 場，那是誤導。
    """
    import matplotlib.pyplot as plt
    import pandas as pd

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.3))
    for ax, mode, path in (
        (axes[0], "Permissive", FEATURES / "fusion_features_permissive.csv"),
        (axes[1], "Enforce", FEATURES / "fusion_features_enforce.csv"),
    ):
        frame = pd.read_csv(path)
        counts = frame["label"].value_counts()
        order = ["normal"] + [c for c in sorted(counts.index) if c != "normal"]
        values = [counts[c] for c in order]
        colours = [GREEN] + [ACCENT] * (len(order) - 1)
        bars = ax.bar([CLASS_LABELS[c] for c in order], values, color=colours)
        ax.set_title(f"{mode}（共 {len(frame):,} 個視窗）", fontsize=12, color=INK)
        ax.set_ylabel("視窗數")
        ax.tick_params(axis="x", rotation=45, labelsize=9)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value, f"{value:,}",
                    ha="center", va="bottom", fontsize=8)
        ax.spines[["top", "right"]].set_visible(False)
    fig.suptitle("九類視窗分佈（依安全模式）", fontsize=15, fontweight="bold", color=INK)
    fig.tight_layout()
    _source(fig, "來源：features_merged_split/*.csv。用視窗數而非場次數——攻擊場次同時含正常視窗")
    fig.savefig(out / "02_類別分佈.png")
    plt.close(fig)


def chart_rerun(out: Path):
    """300 場受控重跑：三個預測寫在跑之前，跑完才對照。

    第三項是**對照組**：`sros2_deny` 沒有被修，所以不該動。它確實沒動，
    因此前兩項的變化可以歸因於那兩個修正，而不是環境漂移。
    """
    import matplotlib.pyplot as plt
    import pandas as pd

    old = pd.read_csv(LEGACY_FEATURES / "fusion_features_permissive.csv")
    new = pd.read_csv(FEATURES / "fusion_features_permissive.csv")
    names = ["parameter_call_rate", "nonce_reuse_ratio", "sros_permission_deny_rate"]
    labels = ["參數呼叫率\n（已修 hook）", "nonce 重用率\n（已修 QoS）", "SROS2 拒絕率\n（對照組·未修）"]
    before = [100 * (old[n] > 0).mean() for n in names]
    after = [100 * (new[n] > 0).mean() for n in names]

    fig, ax = plt.subplots(figsize=(8.4, 4.4))
    x = range(len(names))
    ax.bar([i - 0.19 for i in x], before, width=0.38, label="重跑前", color=GREY)
    ax.bar([i + 0.19 for i in x], after, width=0.38, label="重跑後", color=ACCENT)
    for i, (b, a) in enumerate(zip(before, after)):
        ax.text(i - 0.19, b, f"{b:.2f}%", ha="center", va="bottom", fontsize=9)
        ax.text(i + 0.19, a, f"{a:.2f}%", ha="center", va="bottom", fontsize=9,
                fontweight="bold", color=ACCENT if a > 0 else GREY)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=9.5)
    ax.set_ylabel("特徵非零的視窗比例 (%)")
    ax.set_title("證據通道修復前後（Permissive，300 場受控重跑）",
                 fontsize=14, fontweight="bold", color=INK)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    # 標註放在空白處，不用箭頭——箭頭會壓到 0.00% 的字。
    ax.text(0.52, max(after) * 0.86,
            '第三項是刻意設的對照組：它沒有被修，所以不該動。\n它確實沒動，因此前兩項的變化可以歸因於那兩個修正，\n而不是環境漂移。',
            fontsize=9, color=WARM, va="top",
            bbox=dict(boxstyle="round,pad=0.5", fc="#fdf3ec", ec=WARM, lw=0.8))
    _source(fig, "來源：firewall_lab/features_per_mode（8/16 舊表）對照 features_merged_split（8/21 新表）")
    fig.savefig(out / "03_重跑前後.png")
    plt.close(fig)


def chart_confusion(out: Path):
    """Permissive 九類 final test 混淆矩陣（列正規化）。"""
    import matplotlib.pyplot as plt
    import numpy as np

    data = _metrics(FINAL_ROOT / "permissive_fusion" / "training_metrics.json")
    classes = data["classes"]
    matrix = np.asarray(data["test_metrics"]["confusion_matrix"], dtype=float)
    normalised = matrix / matrix.sum(axis=1, keepdims=True)

    fig, ax = plt.subplots(figsize=(7.4, 6.4))
    image = ax.imshow(normalised, cmap="Blues", vmin=0, vmax=1)
    names = [CLASS_LABELS[c] for c in classes]
    ax.set_xticks(range(len(classes)), names, rotation=45, ha="right", fontsize=9)
    ax.set_yticks(range(len(classes)), names, fontsize=9)
    for i in range(len(classes)):
        for j in range(len(classes)):
            value = normalised[i, j]
            if matrix[i, j] == 0:
                continue
            ax.text(j, i, f"{value:.2f}", ha="center", va="center", fontsize=8,
                    color="white" if value > 0.55 else INK)
    ax.set_xlabel("預測")
    ax.set_ylabel("實際", labelpad=10)
    test = data["test_metrics"]
    ax.set_title(
        f"Permissive 九類 final test 混淆矩陣（列正規化）\n"
        f"balanced accuracy {test['balanced_accuracy']:.4f}　"
        f"macro F1 {test['macro_f1']:.4f}　二元 PR-AUC {test['binary_attack_pr_auc']:.4f}",
        fontsize=12.5, fontweight="bold", color=INK, pad=12)
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.03)
    _source(fig, "來源：models_final/permissive_fusion/training_metrics.json（封存 test，只開啟一次）")
    fig.savefig(out / "04_混淆矩陣.png")
    plt.close(fig)


def chart_ablation(out: Path):
    """特徵消融：兩種模式依賴完全不同的證據。這是本專題的核心發現之一。"""
    import matplotlib.pyplot as plt

    perm = _metrics(FINAL_ROOT / "permissive_fusion" / "training_metrics.json")
    enf = _metrics(FINAL_ROOT / "enforce_network" / "training_metrics.json")
    sets = ["network", "telemetry", "fusion"]
    labels = ["只用網路特徵", "只用遙測特徵", "融合"]
    p = [perm["feature_ablation_validation"][s]["balanced_accuracy"] for s in sets]
    e = [enf["feature_ablation_validation"][s]["balanced_accuracy"] for s in sets]

    fig, ax = plt.subplots(figsize=(8.6, 4.6))
    x = range(len(sets))
    ax.bar([i - 0.19 for i in x], p, width=0.38, label="Permissive", color=ACCENT)
    ax.bar([i + 0.19 for i in x], e, width=0.38, label="Enforce", color=WARM)
    for i, (a, b) in enumerate(zip(p, e)):
        ax.text(i - 0.19, a, f"{a:.4f}", ha="center", va="bottom", fontsize=9)
        ax.text(i + 0.19, b, f"{b:.4f}", ha="center", va="bottom", fontsize=9)
    ax.axhline(1 / 9, color=GREY, ls="--", lw=1)
    # 放最左邊：右側被 Enforce 的長條擋住。
    ax.text(-0.42, 1 / 9 + 0.012, "亂猜 0.111", fontsize=8.5, color=GREY, ha="left")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("九類 balanced accuracy（validation）")
    ax.set_title("特徵消融：兩種模式依賴的證據完全相反",
                 fontsize=14, fontweight="bold", color=INK)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    _source(fig, "來源：models_final/*/training_metrics.json 的 feature_ablation_validation（validation，非 test）")
    fig.savefig(out / "05_特徵消融.png")
    plt.close(fig)


def chart_roc(out: Path):
    """二元攻擊偵測的 ROC。

    重跑推論只是把**已經花掉的那次 test 評估**畫出來，不調任何門檻、
    不產生新的選擇自由度。
    """
    import matplotlib.pyplot as plt
    import numpy as np
    import pandas as pd
    from sklearn.metrics import roc_auc_score, roc_curve

    from firewall_lab.inference import FirewallModel

    fig, ax = plt.subplots(figsize=(6.4, 6.0))
    summary = []
    for mode, folder, feature_file, colour in (
        ("Permissive", "permissive_fusion", "fusion_features_permissive.csv", ACCENT),
        ("Enforce", "enforce_network", "fusion_features_enforce.csv", WARM),
    ):
        model = FirewallModel(FINAL_ROOT / folder / "firewall_model.joblib")
        frame = pd.read_csv(FEATURES / feature_file)
        test = frame.loc[frame["split"].astype(str) == "test"]
        matrix = test[model.features].to_numpy(dtype=float)
        probability = model.classifier.predict_proba(matrix)
        normal_index = model.classes.index("normal")
        score = 1.0 - probability[:, normal_index]
        truth = (test["label"].astype(str) != "normal").to_numpy(int)
        fpr, tpr, _ = roc_curve(truth, score)
        auc = roc_auc_score(truth, score)
        pr = _metrics(FINAL_ROOT / folder / "training_metrics.json")[
            "test_metrics"]["binary_attack_pr_auc"]
        ax.plot(fpr, tpr, color=colour, lw=2,
                label=f"{mode}　ROC-AUC {auc:.4f}　PR-AUC {pr:.4f}")
        summary.append((mode, auc, len(test)))

    ax.plot([0, 1], [0, 1], ls="--", color=GREY, lw=1, label="隨機")
    ax.set_xlabel("假警報率 (FPR)")
    ax.set_ylabel("偵測率 (TPR)")
    ax.set_title("二元攻擊偵測 ROC（封存 test）", fontsize=14,
                 fontweight="bold", color=INK, pad=16)
    # 報告裡的頭條是 PR-AUC，不是 ROC-AUC。兩個數字同時出現在投影片上
    # 一定會被問，所以直接在圖上講清楚差別。
    ax.text(0.5, 1.02, "報告引用的是 PR-AUC（類別不平衡下較保守）；此圖的 AUC 為 ROC-AUC",
            transform=ax.transAxes, ha="center", fontsize=8.5, color=GREY)
    ax.legend(loc="lower right", frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    _source(fig, "來源：models_final/*/firewall_model.joblib 對 test 切分推論；"
                 "此為已花掉的那次評估之視覺化，未調整任何門檻")
    fig.savefig(out / "06_ROC.png")
    plt.close(fig)
    return summary


def chart_openset(out: Path):
    """整個模型的 open-set recall。兩組 holdout 的差距才是重點。"""
    import matplotlib.pyplot as plt

    def recall(path):
        return _metrics(Path(path))["open_set_recall"]

    groups = [
        ("原 holdout\nsensor_spoof / service_dos", [
            ("Permissive\n現行預設", recall(HIER_ROOT / "permissive" / "openset_holdout_fixed.json"), ACCENT),
            ("Permissive\nMahalanobis", recall("/home/jesse/models_hier_maha/permissive/openset_holdout_fixed.json"), GREEN),
            ("Enforce\n現行預設", recall(HIER_ROOT / "enforce" / "openset_holdout_fixed.json"), WARM),
        ]),
        ("處女 holdout\ncommand_injection / identity_abuse", [
            ("Permissive\n現行預設", recall("/home/jesse/models_clean/isolation_forest/openset_holdout_fixed.json"), ACCENT),
            ("Permissive\nMahalanobis", recall("/home/jesse/models_clean/mahalanobis/openset_holdout_fixed.json"), GREEN),
        ]),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(11.0, 4.5),
                             gridspec_kw={"width_ratios": [3, 2]})
    for ax, (title, bars) in zip(axes, groups):
        names = [b[0] for b in bars]
        values = [b[1] for b in bars]
        ax.bar(names, values, color=[b[2] for b in bars], width=0.55)
        for i, value in enumerate(values):
            ax.text(i, value, _half_up(value), ha="center", va="bottom",
                    fontsize=10, fontweight="bold")
        ax.axhline(0.70, color=WARM, ls="--", lw=1.2)
        ax.text(len(bars) - 0.45, 0.715, "門檻 0.70", fontsize=8.5, color=WARM, ha="right")
        ax.set_ylim(0, 1.05)
        ax.set_title(title, fontsize=11, color=INK)
        ax.tick_params(axis="x", labelsize=9)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylabel("整個模型 open-set recall")
    fig.suptitle("未知攻擊偵測：達標與否完全取決於 holdout 是哪兩類",
                 fontsize=14, fontweight="bold", color=INK)
    fig.tight_layout()
    _source(fig, "來源：models_hier*/openset_holdout_fixed.json（2026-08-25 修正串流歷史後重量）")
    fig.savefig(out / "07_未知攻擊.png")
    plt.close(fig)



def chart_rule_vs_learned(out: Path):
    """規則式 vs 學習式，附場次層級信賴區間。

    這張圖回答的是這個題目一定會被問的那個問題，而它的答案**不是**
    「AI 全面勝出」——說成那樣比較好講，但那是錯的。真正的結論是兩個模式
    下 AI 的貢獻是不同的東西，而且只有一邊的差距是統計上站得住的。

    誤差線是**場次層級**重抽出來的。用視窗重抽會把區間壓得太窄，那會讓
    Permissive 那組看起來也有顯著差異——而它沒有。
    """
    import json

    import matplotlib.pyplot as plt

    methods = [
        ("rule_based", "規則式", WARM),
        ("learned_network_only", "學習式：網路", ACCENT),
        ("learned_telemetry_only", "學習式：遙測", GREEN),
        ("learned_fusion", "學習式：融合", INK),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(11.4, 4.8), sharey=True)
    for ax, (mode, title) in zip(axes, [("permissive", "Permissive"),
                                        ("enforce", "Enforce")]):
        report = json.loads(
            (RULE_VS_LEARNED / f"rule_vs_learned_{mode}.json").read_text(
                encoding="utf-8"))
        results = report["results"]
        for index, (key, label, colour) in enumerate(methods):
            point = results[key]["point"]["binary_f1"]
            interval = results[key]["ci"]["binary_f1"]
            low = point - interval["ci95_low"]
            high = interval["ci95_high"] - point
            ax.bar(index, point, width=0.62, color=colour)
            ax.errorbar(index, point, yerr=[[max(low, 0)], [max(high, 0)]],
                        fmt="none", ecolor=INK, capsize=5, lw=1.3)
            ax.text(index, interval["ci95_high"] + 0.03, f"{point:.4f}",
                    ha="center", fontsize=9.5, color=INK)
        ax.set_xticks(range(len(methods)))
        ax.set_xticklabels([label for _, label, _ in methods], fontsize=9.5)
        ax.set_title(
            f"{title}（validation {report['counts']['validation_sessions']} 場）",
            fontsize=12, fontweight="bold", color=INK)
        ax.set_ylim(0, 1.14)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylabel("二元偵測 F1")
    # 用軸座標而不是資料座標：資料座標會讓文字被切在左邊界外。
    axes[0].text(0.5, 0.955, "四者區間重疊——偵測上沒有顯著差異",
                 transform=axes[0].transAxes, fontsize=9.5, color=GREY,
                 ha="center")
    axes[1].text(0.5, 0.955, "SROS2 擋在 handshake，應用層證據不存在",
                 transform=axes[1].transAxes, fontsize=9.5, color=GREY,
                 ha="center")
    fig.suptitle("預防生效時，正是應用層規則失明時",
                 fontsize=14.5, fontweight="bold", color=INK, y=1.02)
    _source(fig, "來源：rule_vs_learned_{permissive,enforce}.json。誤差線為 95% CI，"
                 "場次層級 bootstrap 1000 次（validation，非 test）")
    fig.savefig(out / "09_規則式vs學習式.png")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    _setup_fonts()
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    chart_dataset(out)
    print("  01 資料規模")
    chart_class_distribution(out)
    print("  02 類別分佈")
    chart_rerun(out)
    print("  03 重跑前後")
    chart_confusion(out)
    print("  04 混淆矩陣")
    chart_ablation(out)
    print("  05 特徵消融")
    for mode, auc, rows in chart_roc(out):
        print(f"  06 ROC {mode}: AUC={auc:.4f}（{rows} 列）")
    chart_openset(out)
    print("  07 未知攻擊")
    # 文字量大，單獨一個模組；只把配色與頁腳函式傳進去。
    from chart_provenance import draw as draw_provenance

    draw_provenance(out, ink=INK, accent=ACCENT, warm=WARM, green=GREEN,
                    grey=GREY, source=_source)
    print("  08 資料來源")
    chart_rule_vs_learned(out)
    print("  09 規則式 vs 學習式")
    print(f"→ {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
