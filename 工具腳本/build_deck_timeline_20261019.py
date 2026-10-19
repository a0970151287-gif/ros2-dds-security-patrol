# -*- coding: utf-8 -*-
"""從「七月初到現在做了什麼」那份回顧建一份簡報。

來源：文件/七月初到現在做了什麼_2026-10-19.md（本身的數字全部從 git 重新量）
樣式：從 文件/SROS2智慧防火牆_專題最終報告_自然色系_2026-08-21.pptx 的 XML 量出來

不覆寫既有任何一份 pptx（C2C-033／037）。
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from deck_lib import (Deck, INK, PAPER, MUTED, SAGE, BRICK, TAN, STONE, MIST,
                      BLUE, GREY, L0)
from pptx.enum.text import PP_ALIGN

OUT = "文件/SROS2智慧防火牆_七月初到現在的時間軸回顧_自然色系_2026-10-19.pptx"

d = Deck()
RAIL = ("rail", SAGE)
PANEL = ("panel", 3.600, MIST)
W_R = 11.2      # rail 頁的內容寬（右緣 11.87 < 頁碼 12.33）
W_P = 8.3       # panel 頁的內容寬（右緣 8.97 < 面板 9.733）
n = 1   # 封面是第 1 頁（與既有兩份增補的慣例一致），所以頁碼從 02 起


def page(band):
    global n
    n += 1
    s = d.slide(band)
    d.pagenum(s, n)
    return s


def B(t):   # 粗體 run
    return (t, None, True)


def C(t, c):
    return (t, c, None)


# ── P1 封面 ──────────────────────────────────────────────────────────
s = d.slide(("full", 10.523, 2.810, SAGE))
d.text(s, L0, 2.020, 9.000, 1.000, "SROS2 智慧防火牆", size=33.8, color=INK, bold=True)
d.text(s, L0, 3.060, 8.400, 0.440,
       "TIMELINE RETROSPECTIVE  ·  2026-07-04 → 2026-10-19  ·  107 天",
       size=12.0, color=TAN, space=1.4)
d.rule(s, 3.700, 4.200)
d.text(s, L0, 3.980, 8.600, 1.100,
       "從 PR-AUC 0.25 到一個被量過的天花板", size=20.2, color=INK, bold=True)
d.text(s, L0, 5.080, 8.600, 1.100,
       [("七月初有一個被硬化過的 SROS2 系統，和一個在自有資料上 PR-AUC "),
        B("0.25"), (" 的機器學習基線。\n那 0.25 對外部乾淨資料 "), B("0.98"),
        (" 的落差，是這 107 天唯一的題目。")],
       size=13.5, color=MUTED, line=1.55)
d.text(s, L0, 6.420, 7.600, 0.350, "人工智慧系專題｜Jesse｜目標 2027.05",
       size=10.5, color=GREY, space=0.8)
d.text(s, 10.920, 1.730, 2.000, 2.900,
       "0.25\n↓\n0.98\n\n150 → 1,035\n24 → 1,767",
       size=13.5, color=PAPER, line=1.70)
for i, c in enumerate((PAPER, MIST, STONE, TAN)):
    d.rect(s, 11.150, 5.690 + i * 0.330, 1.580, 0.190, c)

# ── P2 起點 ──────────────────────────────────────────────────────────
s = page(RAIL)
d.eyebrow(s, "THE STARTING LINE  ·  2026-07-04")
y = d.title(s, "起點：一個被硬化過的系統，和一個知道自己為什麼不夠好的基線")
y = d.lead(s, "那一天有 5 個 commit，然後整整一個月沒有任何 commit（07-05 → 08-05 零筆）"
              "⇒ 它是一個乾淨的分界線。", y + 0.10, W_R)
ya = d.kv(s, [
    ("雙 CA 分離", "identity CA ≠ permissions CA"),
    ("最小權限 ACL", "取代 wildcard 授權"),
    ("sros2_稽核.sh", "28 項離線稽核"),
    ("N25 crash 修正", "畸形 /scan 的 ZeroDivisionError"),
], y + 0.26, left=L0, w=5.30, header=("已經做完的（現在仍然成立）", ""), kw=0.52)
yb = d.kv(s, [
    ("firewall_lab/", "0 個檔案"),
    ("tests/", "2 個檔案 ／ 24 個測試"),
    ("工具腳本/", "3 支"),
    ("文件/", "14 份"),
], y + 0.26, left=6.37, w=5.50, header=("當時不存在的東西", ""), kw=0.52)
y = max(ya, yb)
d.band_note(s, y + 0.30,
            [B("⇒ 沒有資料工廠、沒有驗收機制、沒有證據治理。"),
             ("　整個 firewall_lab／特徵管線／決策引擎／回應 backend／證據治理都還不存在。")],
            w=W_R, h=0.620)
d.footer(s, "[Sources] git log fa6b58c…42da766 的 commit body 逐字讀過；git ls-tree -r 計數")

# ── P3 0.25 對 0.98 ─────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "THE ONLY QUESTION")
y = d.title(s, "那個 0.25 對 0.98，是整個專題的中心難點", w=W_P)
y = d.lead(s, "同一個 commit（42da766）裡的 ML-IDS 基線，在兩批資料上的 PR-AUC：",
           y + 0.12, W_P)
y = d.kv(s, [
    ("自有的弱標 Zeek conn.log", [C("0.20 → 0.25", BRICK)]),
    ("外部乾淨資料（HCRL RTPS）", [C("0.98", SAGE)]),
], y + 0.22, w=W_P, header=("資料", "PR-AUC"), kw=0.58, gap=0.400)
y = d.rule(s, y + 0.26, W_P)
d.text(s, L0, y + 0.18, W_P, 1.300,
       [B("⭐ 這是中心難點的第一次量化陳述：模型不是不行，是自有資料的標籤與證據不夠。\n"),
        ("三個月後的每一條主線，都可以回溯到這個 0.25 對 0.98 的落差 —— 而它在 10 月中"
         "被拆成五層並逐層量過（見第 13 頁）。")],
       size=13.5, color=INK, line=1.55)
d.card(s, 10.000, 2.320, "自有資料", "0.25", fill=BRICK)
d.card(s, 10.000, 3.660, "外部資料", "0.98", fill=SAGE)
d.card(s, 10.000, 5.000, "落差的真因", "觀測層", fill=STONE, vsize=18.8)
d.footer(s, "[Sources] 42da766 commit body；文件/七月初到現在做了什麼_2026-10-19.md §1.1")

# ── P4 規模 ──────────────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "SCALE  ·  107 DAYS LATER")
y = d.title(s, "程式長 6.9 倍，而防守端的 src/ 只長 1.2 倍", w=W_P)
y = d.lead(s, "git diff --shortstat fa6b58c HEAD ⇒ 976 files changed, "
              "342,406 insertions(+), 1,500 deletions(-)", y + 0.12, W_P)
y = d.kv(s, [
    ("文件/", "14 → 567　　40.5×"),
    ("tests/", "2 → 105　　52.5×"),
    ("工具腳本/", "3 → 90　　30.0×"),
    ([B("firewall_lab/")], [B("0 → 84　　（無中生有）")]),
    ("紅隊測試/PoC腳本/", "25 → 35　　1.4×"),
    ([B("src/")], [B("37 → 45　　1.2×")]),
    ("全 repo", "150 → 1,035　　6.9×"),
], y + 0.20, w=W_P, header=("目錄", "2026-07-04 → 2026-10-19"), kw=0.42, gap=0.318)
d.band_note(s, y + 0.24,
            [B("⭐ 最說明問題的兩列是 src/ 只長 1.2 倍而 tests/ 長 52 倍：\n"),
             ("　防守端的程式幾乎沒有變，變的是「怎麼證明它有效」。")],
            w=W_P, h=0.720)
d.card(s, 10.000, 2.320, "刪除行數", "1,500", fill=STONE)
d.card(s, 10.000, 3.660, "測試（獨立收集）", "24 → 1,767", fill=STONE, vsize=16.5)
d.card(s, 10.000, 5.000, "commit 累計", "35 → 354", fill=STONE, vsize=18.8)
d.footer(s, "[Sources] git diff --shortstat；git ls-tree -r --name-only；"
            "pytest 獨立收集 1,767（grep 只數到 1,410，低估是 parametrize 造成的）")

# ── P5 六個階段 ──────────────────────────────────────────────────────
s = page(RAIL)
d.eyebrow(s, "TIMELINE  ·  SIX PHASES")
y = d.title(s, "時間軸：六個階段，而每一段空窗都對得上一件事")
y = d.lead(s, "commit 直方圖：07 月 5 個　·　08 月 131 個　·　09 月 103 個　·　10 月 80 個。"
              "單日峰值是 08-18 的 27 個。", y + 0.10, W_R)
y = d.kv(s, [
    ("階段 0　07-04 → 08-05", "起點與一個月的空窗　·　5 個 commit，然後零"),
    ("階段 1　08-06 → 08-21", "資料工廠　·　33 個 commit　·　1,100 場 campaign"),
    ("階段 2　08-25 → 09-04", "證據治理與跨主機　·　69 個 commit"),
    ("階段 3　09-15 → 09-27", "模型選型與量測工具　·　49 個 commit"),
    ("階段 4　10-02 → 10-11", "工程問題與跨主機鏈　·　40 個 commit"),
    ("階段 5　10-15 → 10-19", "驗收與理解　·　27 個 commit"),
], y + 0.24, w=W_R, header=("階段", "內容"), kw=0.26, gap=0.372)
d.band_note(s, y + 0.26,
            [B("⭐ 空窗是資料在跑，不是停工。"),
             ("　07-05 → 08-05 的 32 天是在想「0.25 對 0.98 要怎麼辦」，"
              "而答案是不要再調模型，去把資料做對；\n　其餘五段空窗（6／10／4／4／3 天）"
              "全部對得上一次 campaign 在跑或跑完後的沉澱。")],
            w=W_R, h=0.760)
d.footer(s, "[Sources] git log --format=%ad --date=short 逐日計數；"
            "⚠️ 「空窗對得上什麼」是從 commit 主旨與 campaign 日誌推的，不是工時紀錄")

# ── P6 階段 1 ────────────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "PHASE 1  ·  THE DATA FACTORY")
y = d.title(s, "資料工廠：1,100 場，以及兩個把防禦偽裝成有效的缺陷", w=W_P)
y = d.kv(s, [
    ("08-06", "M1 多模態管線第一次端到端跑通（loopback）"),
    ("08-13／14", "1,100 場正式 campaign，0 errors、19,204 個 artifact、0 hash 失配"),
    ("08-17", "跨模式可分離度 0.9451（門檻 0.70）⇒ 必須分模式訓練"),
    ([B("08-18")], [B("單日 27 個 commit（全期峰值）—— 查出兩個 collector bug")]),
    ("08-21", "300 場受控重跑，三個事前預測全部成立"),
], y + 0.26, w=W_P, header=("日期", "事件"), kw=0.20, gap=0.330)
y = d.band_note(s, y + 0.24,
                [B("parameter_call_rate"), (" 的 hook 掛在 rcl 的 read-only 拒絕"),
                 B("之下"), ("（攻擊流量到不了那一層）；\n"),
                 B("replay"), (" 的 N1 心跳重放是 BEST_EFFORT 對 RELIABLE ⇒ "),
                 B("DDS 直接不投遞"),
                 ("　50／50 場都有 incompatible QoS 日誌，而 9,502 筆 HMAC 全是 accepted。")],
                w=W_P, h=0.900)
d.text(s, L0, y + 0.18, W_P, 0.620,
       [B("⇒ ReplayCache 這條主防線，在正式資料裡一次都沒有被走過。")],
       size=13.5, color=BRICK, line=1.45)
d.card(s, 10.000, 2.320, "重跑後 replay", "0.375 → 1.000", fill=SAGE, vsize=15.0)
d.card(s, 10.000, 3.660, "parameter_tamper", "0.429 → 1.000", fill=SAGE, vsize=15.0)
d.card(s, 10.000, 5.000, "沒被修的那兩類", "沒有改善", fill=STONE, vsize=16.5)
d.footer(s, "[Sources] CLAUDE.md C2C-013／024；validation 數字，不是 test")

# ── P7 階段 2 ────────────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "PHASE 2  ·  EVIDENCE & THE SECOND HOST")
y = d.title(s, "證據治理與跨主機，以及最大的一次自我否證", w=W_P)
y = d.kv(s, [
    ("08-25", "Codex 的 P0／P1／P2：版本治理、family-LOO、RTPS 身份契約"),
    ("08-26／27", "第一次拿到 DDS 層的遠端認證證據（C++ sidecar observer）"),
    ("08-29", "跨主機身份歸因第一次成立；source_ip_attribution 第一次是 true"),
    ("08-30", "79／80，8 小時無人值守、79 個相異 GUID、陰性對照零誤判"),
    ([B("08-31")], [B("發現 1,400 場的 Zeek 全部沒帶 -C")]),
    ("09-03", "640 場全新資料重收；第一次真正獨立的 final test"),
], y + 0.22, w=W_P, header=("日期", "事件"), kw=0.20, gap=0.318)
y = d.band_note(s, y + 0.22,
                [("checksum offload 讓封包被整批丟棄，位元組／封包／duration 全部未設定，"),
                 B("conn_count 虛增 7.96 倍"),
                 ("；而「按 conn.log 流起點分窗」也是錯的 —— 一筆 conn 代表整條流，"
                  "實測流量跨度 46 秒而流起點全擠在前 9 秒。")],
                w=W_P, h=0.980)
d.text(s, L0, y + 0.16, W_P, 0.620,
       [B("⇒ 任何引用網路特徵數值的既有結論都要重做。")],
       size=13.5, color=BRICK, line=1.45)
d.card(s, 10.000, 2.320, "conn_count", "虛增 7.96×", fill=BRICK, vsize=16.5)
d.card(s, 10.000, 3.660, "修法", "逐封包分窗", fill=STONE, vsize=16.5)
d.card(s, 10.000, 5.000, "跨主機 soak", "79 / 80", fill=SAGE)
d.footer(s, "[Sources] CLAUDE.md C2C-050／051／052；文件/網路特徵四個缺陷與修正_2026-08-31.md")

# ── P8 階段 3 ────────────────────────────────────────────────────────
s = page(RAIL)
d.eyebrow(s, "PHASE 3  ·  MODEL SELECTION")
y = d.title(s, "模型選型：瓶頸不在學習器，而量測工具自己壞了一次")
y = d.kv(s, [
    ("解析度", "validation 每類只有 3 場 ⇒「3 場全錯」顯示成 0.000；"
               "改 CV（每類 17 場）之後 Enforce 真正恆零的只有 1 類不是 5 類"),
    ("序列模型不成立", "TCN／GRU 在六次比較裡沒有一次贏過同條件的樹模型"),
    ("換表述有效", "per_window_pooled → session_aggregate，Enforce +0.093"),
    ("學習器不是瓶頸", "24 個學習法的完整比較，前七名寬度只有 0.02"),
    ([B("折本身有缺陷")], [B("GroupKFold 不洗牌也不吃 seed ⇒ 兩輪排名建立在同一個偏的分割上")]),
    ("Enforce 的未知攻擊", "3 個評分器 × 8 種池化 = 24 格全部是 0.0000"),
], y + 0.30, w=W_R, header=("發現", "內容"), kw=0.20, gap=0.372)
d.band_note(s, y + 0.26,
            [("⚠️ 那個 GroupKFold 的缺陷是第 "), B("13"),
             (" 次「量測工具的缺陷偽裝成被量對象的性質」\n"
              "　—— 修好折之後排名整個重排，先前推薦的第 1 名掉到第 4。")],
            w=W_R, h=0.680)
d.footer(s, "[Sources] CLAUDE.md C2C-064／065／066／068／088；全部是 CV，不是 held-out test")

# ── P9 階段 4 ────────────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "PHASE 4  ·  THE CHAIN RUNS")
y = d.title(s, "三個根因都不是模型問題；而跨主機鏈第一次連著跑完", w=W_P)
y = d.kv(s, [
    ("readiness 三層窗反轉", "stack 起得來，是被 fail-closed 刻意停掉的；"
                             "內層 120 秒先到期，外層 200 秒永遠用不到"),
    ("94 個 talker 孤兒", "campaign 自己的 runner 留下的；"
                          "而兜底清除的 16 項 pattern 全是防守端"),
    ("記憶體", "沒有 memory= 上限時 WSL 拿主機 50% 並且不還"),
], y + 0.24, w=W_P, header=("根因", "真相"), kw=0.30, gap=0.560)
y = d.band_note(s, y + 0.22,
                [B("⭐ 10-08 跨主機鏈第一次連著跑完：歸因 → 票 → 真核心封鎖 → 撤銷，九項全過。\n"),
                 ("　票的 evidence_id 就是歸因報告自己的 SHA-256 ⇒ "
                  "「是這份證據授權了這次封鎖」在密碼學上可以事後證明。\n"),
                 ("　同日 Jesse 親手輸入核准片語重跑一次，九項再全過。")],
                w=W_P, h=1.000)
d.text(s, L0, y + 0.16, W_P, 0.560,
       [("⚠️ 而兩次產物的 authorization 區塊"), B("逐字相同"),
        (" ⇒ 程式分不出誰按下去。")],
       size=12.0, color=MUTED, line=1.45)
d.card(s, 10.000, 2.320, "10-11 campaign", "pending 0", fill=SAGE, vsize=18.8)
d.card(s, 10.000, 3.660, "合格場次", "3,553", fill=STONE)
d.card(s, 10.000, 5.000, "ETA 誤差", "1 分 23 秒", fill=STONE, vsize=16.5)
d.footer(s, "[Sources] CLAUDE.md C2C-103／106／107／113；文件/跨主機鏈_2026-10-07/")

# ── P10 階段 5 ───────────────────────────────────────────────────────
s = page(RAIL)
d.eyebrow(s, "PHASE 5  ·  ACCEPTANCE")
y = d.title(s, "驗收與理解：這個專案第一次有可事後驗證的一次性數字")
y = d.kv(s, [
    ("10-15", "四階段 runbook 整條跑完；四份 holdout 封印；"
              "independent_final_test 第一次 True"),
    ("10-16", "查明「那個 1.0000 是單批次上限」（見第 14 頁）"),
    ("10-16 → 10-19", "八份單獨提交的事前註冊；文件四項全部補上"),
], y + 0.30, w=W_R, header=("日期", "事件"), kw=0.20, gap=0.470)
y = d.rule(s, y + 0.24, W_R)
d.text(s, L0, y + 0.20, W_R, 1.500,
       [B("independent_final_test: True"),
        (" 的意思是三件事都可以事後驗證：\n"),
        ("　設定在資料"), B("存在之前"), ("凍結並雜湊　·　"
         "封印在"), B("擬合之前"), ("綁住場次清單　·　開封"), B("一次性"), ("。\n\n"),
        ("而第一次量到的數字是：識別 "), C("0.4655／0.4228", BRICK),
        ("（門檻 0.80）、open-set "), C("0.1645", BRICK), ("（門檻 0.70）。")],
       size=13.5, color=INK, line=1.55)
d.footer(s, "[Sources] CLAUDE.md C2C-114／115／116；文件/重訓_識別_{permissive,enforce}.json")

# ── P11 計分板 ───────────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "SCORECARD  ·  7 月初 → 現在")
y = d.title(s, "九個組件：七月初沒有這張表，計分本身是 8 月才建立的", w=W_P, size=25.0)
y = d.kv(s, [
    ("資料集", "無（弱標 conn.log）　→　95%"),
    ("攻擊偵測（二元）", "PR-AUC 0.20–0.25　→　95%"),
    ([B("攻擊識別（多類）")], [B("無　→　60%")]),
    ([B("未知攻擊")], [B("無　→　55%")]),
    ("回應／執行", "無　→　95%"),
    ("本機防禦驗證", "無　→　89%（8／9）"),
    ("跨主機／硬體", "無　→　95%"),
    ("攻擊面覆蓋", "9 類　→　87%（20／23）"),
    ("文件／簡報", "14 份　→　100%"),
], y + 0.16, w=W_P, header=("組件", "2026-07-04　→　2026-10-19"), kw=0.42, gap=0.318)
y = d.rule(s, y + 0.18, W_P)
d.text(s, L0, y + 0.16, 5.400, 0.420,
       [("整體　"), B("85.67%"), ("　（771／9）")], size=18.8, color=INK)
d.card(s, 10.000, 2.320, "門檻改過嗎", "一個字未改", fill=STONE, vsize=15.0)
d.card(s, 10.000, 3.660, "holdout 讀取", "0", fill=STONE)
d.card(s, 10.000, 5.000, "部署資格", "FALSE", fill=BRICK)
d.footer(s, "[Sources] CLAUDE.md 進度百分比表（活狀態表，每輪更新）")

# ── P12 三次下修 ─────────────────────────────────────────────────────
s = page(RAIL)
d.eyebrow(s, "THE THREE DOWNGRADES")
y = d.title(s, "三次往下，而三次的理由都不是「做壞了」")
y = d.lead(s, "55% → 68% → 70% → 76% → 78% → 76% → 79% → 83% → 85% → 87.33% "
              "→ 84.56% → 85.67%", y + 0.10, W_R, size=12.0)
y = d.kv(s, [
    ("2026-08-28　71% → 70%", "新增一列「本機防禦驗證」。先前七列沒有任何一列代表"
                              "九項本機 outcome ⇒ 5／9 → 6／9 在百分比上完全看不見"),
    ("2026-09-02　78% → 76%", "新增一列「攻擊面覆蓋」。那正是部署 gate "
                              "all_policy_classes_present 量的東西"),
    ([B("2026-10-15　87.33% → 84.56%")],
     [B("第一次有處女 holdout 的數字，而它遠低於門檻")]),
], y + 0.24, w=W_R, header=("下修", "理由"), kw=0.26, gap=0.560)
d.band_note(s, y + 0.24,
            [B("⭐ 前兩次的原則逐字寫在狀態表裡：「把一直存在但沒被計分的軸攤開，"
               "不應該讓總分變好看，會降低才是對的。」\n"),
             B("⭐ 第三次的原則是：證據等級提高而數字變差，要反映出來。"),
             ("　那兩列的 100% 定義一個字未改 ⇒ 不是放寬或收緊標準，是讓百分比跟上證據。")],
            w=W_R, h=0.880)
d.footer(s, "[Sources] CLAUDE.md C2C-045／053／115 與進度百分比表的逐次註記")

# ── P13 五層 ─────────────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "THE ANSWER  ·  FIVE LAYERS")
y = d.title(s, "0.25 對 0.98 的答案：那個落差被拆成五層並逐層量過", w=W_P, size=25.0)
y = d.kv(s, [
    ("標籤與證據", "08-18 的兩個 collector bug ⇒ 兩類攻擊的定義性特徵全程為 0"),
    ("網路通道", "08-31 的 Zeek 沒帶 -C ⇒ conn_count 虛增 7.96 倍"),
    ("證據排他性", "認不出來的類別，是沒有專屬證據通道的那些"),
    ("SROS2 生效的代價", "Enforce 下攻擊者在 handshake 就被擋 ⇒ "
                         "整個遙測層對識別的資訊量是 0.0009"),
    ("批次背景", "單一批次內可以完美分開，跨批次就不行"),
], y + 0.18, w=W_P, header=("層", "發現"), kw=0.32, gap=0.470)
y = d.band_note(s, y + 0.20,
                [B("⇒「偵測得到但識別不出」不是模型容量問題，是觀測層的性質。\n"),
                 ("　而那個不對稱現在在同一批一次性資料上兩邊都量到了。")],
                w=W_P, h=0.700)
d.card(s, 10.000, 2.320, "二元（封印 holdout）", "1.0000 / 0.9151", fill=SAGE, vsize=14.2)
d.card(s, 10.000, 3.660, "識別（同一批）", "0.4655 / 0.4228", fill=BRICK, vsize=14.2)
d.card(s, 10.000, 5.000, "遙測層對識別", "0.0009", fill=STONE, vsize=18.8)
d.footer(s, "[Sources] CLAUDE.md C2C-119／121／122；⚠️ 二元那個 1.0000 不是 PR-AUC，"
            "是 18×18 混淆矩陣的粗化")

# ── P14 單批次上限 ───────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "2026-10-16  ·  THE SINGLE-BATCH CEILING")
y = d.title(s, "先前的高分，從來沒有度量過它宣稱的東西", w=W_P)
y = d.lead(s, "refresh 640 上 permissive 的場次層級 CV 是 1.0000，"
              "而同一組設定在 dataset_mega 上是 0.5124、封印 holdout 上 0.4655。",
           y + 0.12, W_P)
y = d.kv(s, [
    ("CV → holdout", [C("Δ −0.047　轉移得很好", SAGE)]),
    ("資料集之間", [C("Δ −0.49　掉的是這一步", BRICK)]),
], y + 0.20, w=W_P, header=("哪一步掉的", "幅度"), kw=0.42, gap=0.380)
y = d.kv(s, [
    ("refresh 640（單批次）", "類間／類內 2.141　·　1-NN 0.9490"),
    ("mega 全部（18.2 天）", "類間／類內 0.588　·　1-NN 0.4670"),
    ([B("mega 的單一 3h 窗")], [B("類間／類內 2.177")]),
], y + 0.26, w=W_P, header=("幾何（不經過任何訓練過的模型）", ""), kw=0.42, gap=0.330)
d.band_note(s, y + 0.22,
            [B("⭐ 把 mega 限制在一個批次裡，它的類別幾何就變成 refresh 640 的類別幾何。\n"),
             B("⇒ 那個 1.0000 是單批次上限，不是泛化結果。")],
            w=W_P, h=0.720)
d.card(s, 10.000, 2.320, "真因", "批次的良性背景", fill=STONE, vsize=14.2)
d.card(s, 10.000, 3.660, "09-15／16 的選型", "全在它上面做", fill=BRICK, vsize=14.2)
d.card(s, 10.000, 5.000, "現實的那個數字", "0.4655", fill=STONE)
d.footer(s, "[Sources] CLAUDE.md C2C-116／124；文件/那個1.0000是單批次上限_2026-10-16.md")

# ── P15 驗收機制 ─────────────────────────────────────────────────────
s = page(RAIL)
d.eyebrow(s, "HOW ACCEPTANCE WAS BUILT")
y = d.title(s, "從「跑一次看看」到可事後稽核")
_mech = [
    ("manifest 完整性 gate", "08-17", "訓練前重新核對 evidence hash，fail-closed"),
    ("證據總帳（r3…r9）", "08-25 起", "每個 claim 釘住檔案的 bytes ＋ SHA-256"),
    ("預先註冊", "09-25 起", "設定在資料存在之前凍結並雜湊"),
    ("封印 holdout", "09-26 起", "在讀任何 test 列之前拒絕第二次開封"),
    ("holdout_reads: 0", "10-16 起", "連續 14 輪產出發現而不花掉任何 holdout"),
]
y = d.kv(s, [(a, b + "　　" + c) for a, b, c in _mech],
         y + 0.30, w=W_R, header=("機制", "建立時間　　它保證什麼"), kw=0.26, gap=0.372)
d.band_note(s, y + 0.26,
            [B("⭐ 八份事前註冊，每一份是自己一個 commit，訊息逐字寫著「刻意不含任何結果」\n"),
             ("　⇒ git 歷史自己證明註冊先於量測，不需要相信自述。\n"),
             ("　而真正的檢驗是它抓到了自己的缺陷：C2C-126 的檢查正是為了抓 C2C-123 的平手"
              "而設計的，實測平手 11 → 0、組內變異 50.7% → 1.3%。")],
            w=W_R, h=1.000)
d.footer(s, "[Sources] CLAUDE.md C2C-123／126／127／129；"
            "⚠️ 代價是誠實的：最新那一輪的缺陷還沒有對應的檢查")

# ── P16 31 次 ────────────────────────────────────────────────────────
s = page(PANEL)
d.eyebrow(s, "RULE ONE  ·  SUSPECT THE INSTRUMENT")
y = d.title(s, "先懷疑量測工具：從 8/21 的四個，到現在累計 31 次", w=W_P)
y = d.lead(s, "共同形態是：「防禦沒反應」與「觀測管線壞掉」在資料上長得一模一樣。",
           y + 0.12, W_P)
y = d.kv(s, [
    ("N1 的 QoS 不相容", "「重放被擋下了」（實際是 DDS 根本不投遞）"),
    ("8,192 點的 scan", "「畸形輸入被拒絕了」（實際在傳輸層被丟）"),
    ("FastCDR 版本不一致", "「攻擊者沒有出現」（discovery 靜默失效）"),
    ("wait_for() 函式不存在", "「心跳抑制未被消費」（bash 對未定義函式回 127 然後繼續）"),
    ([B("查錯一層的 manifest 鍵")], [B("「2,053 場全部不是自適應」")]),
    ("探針把訊息切在 90 字元", "「檔案縮了 90%」—— 偽裝成資料損毀"),
], y + 0.22, w=W_P, header=("代表案例", "它偽裝成什麼"), kw=0.38, gap=0.330)
d.band_note(s, y + 0.22,
            [B("⭐ 一個不可能成功的查找，回傳了令人安心的答案。"),
             ("　這條教訓現在是專案的第一守則，而這份回顧的每一個數字都照它重新量過"
              "（包含這份簡報自己的版面守衛）。")],
            w=W_P, h=0.760)
d.card(s, 10.000, 2.320, "8/21 的報告寫", "四個", fill=STONE)
d.card(s, 10.000, 3.660, "現在", "31 次", fill=BRICK)
d.card(s, 10.000, 5.000, "本輪新增", "第 32 次", fill=STONE, vsize=18.8)
d.footer(s, "[Sources] CLAUDE.md 逐則訊息紀錄的編號計數（C2C-002 起）")

# ── P17 被推翻的 ─────────────────────────────────────────────────────
s = page(RAIL)
d.eyebrow(s, "FALSIFIED BY MYSELF")
y = d.title(s, "被自己推翻的結論，而每一次都是同一個形狀")
y = d.lead(s, "判準是「推論還是量測」—— 上一個結論是推論，下一個是量測。",
           y + 0.10, W_R)
y = d.kv(s, [
    ("「vendor fixture 28／28 都命中」", "實際是 27 條，而且只證明 parser 詞彙表"),
    ("「2／2 real runtime denials」", "那兩行是應用層日誌被誤判，真實拒絕數 0"),
    ("「18 項 telemetry 都有 live producer」", "8 項在 1,100 場真實資料上恆為零"),
    ("「Mahalanobis 沒有取捨」", "family-LOO 最差 fold 有 2–6 倍代價"),
    ("「Enforce 不是模型容量問題」", "有一半是模型缺口（場次池化＋時序 +0.24）"),
    ("「至少 4 類做不到」", "兩個獨立的儀器缺陷：一筆都沒送出、擷取開在錯的介面"),
    ("「身份特徵該整合進模型」", "它是盲點製造機 —— 未見持證內鬼 recall −0.2125"),
    ([B("「那個 1.0000 代表模型很好」")], [B("它是單批次上限")]),
], y + 0.24, w=W_R, header=("原本的宣稱", "被什麼推翻"), kw=0.40, gap=0.318)
d.band_note(s, y + 0.22,
            [B("⭐ 最值得寫進報告的一條是「上界不是保證」被犯了兩次：\n"),
             ("　0／80 的三的法則上界 3.7% 被下一批的 5.0% 推翻；"
              "而我引用那個教訓之後，0／154 的上界 1.9% 又被 "), B("7.2%"), (" 推翻。")],
            w=W_R, h=0.760)
d.footer(s, "[Sources] CLAUDE.md C2C-004／005／035／057／059／062／063／105／116")

# ── P18 不可宣稱 ＋ 總結 ─────────────────────────────────────────────
s = page(("full", 9.733, 3.600, SAGE))
d.eyebrow(s, "WHAT STILL CANNOT BE CLAIMED")
y = d.title(s, "仍然不可宣稱", w=W_P)
y = d.kv(s, [
    ("部署資格", "deployment_eligible = false，兩個模式都是；"
                 "executable_classes 是空清單 ⇒ 零個類別被授權執行"),
    ("跨主機鏈", "跑過兩次，但沒有任何模型判定參與 —— 剩下的兩條阻塞"
                 "不是「機制行不行」而是「誰有權觸發」"),
    ("一次不是 soak", "一個目標、一張票、TTL 90 秒、1 個封包被丟、一種攻擊、無正向對照"),
    ("識別與未知攻擊", "0.4655／0.4228 對 0.80；0.1645 對 0.70 —— 都遠低於門檻"),
    ("holdout", "C2C-115 之後沒有任何未花掉的 test holdout"),
    ("本機 8／9", "是這台機器的天花板；剩下那一項拿不到的原因本身就是防禦有效"),
], y + 0.20, w=W_P, header=("項目", "狀態"), kw=0.24, gap=0.470)
d.text(s, 10.000, 1.900, 2.900, 4.200,
       [B("七月初\n"), ("硬化過的系統\n＋\nPR-AUC 0.25\n\n"),
        B("十月中\n"),
        ("能判斷這是攻擊\n（1.0000／0.9151）\n\n判斷不出是哪一種\n（0.4655／0.4228）\n\n"),
        B("而那個不對稱\n有機制上的解釋")],
       size=12.0, color=PAPER, line=1.60)
d.footer(s, "[Sources] 文件/七月初到現在做了什麼_2026-10-19.md §八；"
            "⚠️ 本簡報不產生任何新的量測，九列百分比一個都沒動，holdout_reads: 0")

d.save(OUT)
print("OK  %d pages -> %s" % (len(d.prs.slides), OUT))
