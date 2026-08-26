"""資料來源與產生管線圖。

答辯必問「資料哪來的」。本專題沒有可用的公開 benchmark——ROS 2／DDS 層在
SROS2 兩種模式下的成對攻防資料不存在——所以資料是自己跑出來的。這張圖把
管線、可追溯欄位與限制一次講完。

**限制也畫進圖裡**，因為講在前面比被問出來好。

單獨一個模組是因為它的文字量大；`make_result_charts.py` 只負責呼叫。
"""

from __future__ import annotations

import json
from pathlib import Path

STAGE_TEXT = [
    ("受測系統", ["Gazebo + TurtleBot3", "/scan  /odom  /imu  /cmd_vel"]),
    ("中介軟體", ["ROS 2 Jazzy + rmw_fastrtps", "DDS domain 30"]),
    ("安全模式", None),  # 由 campaign 實際計數填入
    ("攻擊產生", ["自寫紅隊腳本 27 支", "8 情境 × 100 場 ＋ normal 300 場"]),
    ("每場證據", ["18 種 artifact", "pcap／Zeek／遙測／逐視窗標籤"]),
]

TRACEABLE = [
    "session_id ＋ code_revision",
    "seed（可原樣重跑）",
    "policy_sha256",
    "scenario_id ／ attack_class",
    "security_mode ／ ros_domain_id",
    "warmup 5s → attack 40s → cooldown 5s",
    "全檔 size ＋ sha256",
]

LIMITS = [
    "同機 loopback（WSL2），非跨主機",
    "來源位址只有 127.0.0.1 與",
    "　10.255.255.254 → 無法可信歸因",
    "Gazebo 模擬，非實體機器人",
    "1,101 場中 0 場具 RTPS 身份證據",
    "300 場重跑是替換，不是 +300",
]


def draw(out: Path, *, ink: str, accent: str, warm: str, green: str,
         grey: str, source):
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

    campaign = json.loads(
        Path("firewall_lab/campaign_1100.json").read_text(encoding="utf-8"))
    entries = campaign["entries"] if isinstance(campaign, dict) else campaign
    rows = entries if isinstance(entries, list) else list(entries.values())
    modes: dict[str, int] = {}
    for row in rows:
        modes[row["security_mode"]] = modes.get(row["security_mode"], 0) + 1

    stages = []
    for title, body in STAGE_TEXT:
        if body is None:
            body = [
                f"SROS2　permissive {modes.get('permissive', 0)} 場",
                f"　　　　enforce {modes.get('enforce', 0)} 場",
            ]
        stages.append((title, body))

    colours = [green, accent, accent, warm, accent]

    fig, ax = plt.subplots(figsize=(10.8, 5.2))
    ax.set_xlim(0, 10)
    # 內容只落在 0.28~5.95，下方留白收掉。
    ax.set_ylim(0.22, 6.0)
    ax.axis("off")

    for index, ((title, body), colour) in enumerate(zip(stages, colours)):
        y = 5.05 - index * 1.02
        ax.add_patch(FancyBboxPatch(
            (0.30, y - 0.38), 5.15, 0.80, boxstyle="round,pad=0.06",
            fc="white", ec=colour, lw=1.6))
        ax.text(0.58, y + 0.19, title, fontsize=10.5, fontweight="bold",
                color=colour)
        for line_index, line in enumerate(body):
            ax.text(0.58, y - 0.06 - line_index * 0.24, line, fontsize=8.8,
                    color=ink)
        if index < len(stages) - 1:
            ax.add_patch(FancyArrowPatch(
                (2.88, y - 0.40), (2.88, y - 0.62), arrowstyle="-|>",
                mutation_scale=11, color=grey, lw=1.1))

    ax.text(6.05, 5.36, "每場可追溯欄位", fontsize=10.5, fontweight="bold",
            color=ink)
    for index, line in enumerate(TRACEABLE):
        ax.text(6.15, 4.98 - index * 0.29, "・" + line, fontsize=8.8, color=ink)

    ax.add_patch(FancyBboxPatch(
        (6.00, 0.38), 3.80, 2.35, boxstyle="round,pad=0.08",
        fc="#fdf3ec", ec=warm, lw=1.2))
    ax.text(6.20, 2.48, "必須主動講的限制", fontsize=10, fontweight="bold",
            color=warm)
    for index, line in enumerate(LIMITS):
        ax.text(6.20, 2.14 - index * 0.29, line, fontsize=8.4, color=ink)

    ax.text(5.0, 5.72, "資料來源：自建 live campaign，不是公開資料集",
            fontsize=15, fontweight="bold", color=ink, ha="center")
    source(fig, "來源：firewall_lab/campaign_1100.json、"
                "dataset_live/*/manifest.json、README.md")
    fig.savefig(out / "08_資料來源.png")
    plt.close(fig)
