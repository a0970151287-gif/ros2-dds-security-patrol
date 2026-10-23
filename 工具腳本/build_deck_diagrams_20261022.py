# -*- coding: utf-8 -*-
"""三張圖:系統架構圖、物件圖、循序圖。

2026-10-21 口試,老師重複四次「不要用文字描述」,並在 16:56-17:12 指名這三張,
而且給了一條一致性要求（17:26）:「你有這 object 的話,你前面的架構畫出來
這個 object 都會在前面的架構裡面表示」。
⇒ 物件圖的物件必須出現在架構圖裡;循序圖的 lifeline 必須是物件圖的物件。
這份腳本把那條要求寫成 build 期的斷言（見檔尾 CONSISTENCY）。

另一條他特別糾正的（16:35）:「你畫的那些硬體架構……其實還是要架在軟體上面,
然後我們看的是軟體」⇒ 第一張圖以硬體為容器,裡面放軟體元件。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deck_lib import (Deck, L0, INK, PAPER, MUTED, SAGE, BRICK,
                      TAN, STONE, MIST, BLUE)
import deck_diagram as dg

OUT = "文件/SROS2智慧防火牆_系統架構_物件_循序圖_2026-10-22.pptx"
d = Deck()
dg.reset(d)

# 實線 = 已跑過且有證據;虛線 = 機制存在但未啟用。
SOLID, DASH = SAGE, BRICK


# ============================================ 1 系統架構圖
s = d.slide(("rail", SAGE))
d.eyebrow(s, "圖 1 ／ 3　SYSTEM ARCHITECTURE")
y = d.title(s, "系統架構圖｜軟體元件,以及它們跑在哪一台機器上")
y = d.lead(s, "硬體是容器,軟體元件畫在容器裡面。實線是已跑過且有證據的路徑;"
              "虛線是機制存在但尚未啟用的路徑。", y + 0.050)

GT, GH = y + 0.170, 3.260          # 從 lead 的結束位置推,不要手算
dg.group(d, s, 0.670, GT, 2.700, 2.100, MIST)
dg.group(d, s, 3.820, GT, 4.900, GH, STONE)
dg.group(d, s, 9.170, GT, 2.800, 2.100, MIST)

dg.caption(d, s, 0.810, GT + 0.110, 2.420, "攻擊端　桌機 Windows",
           bold=True, color=BRICK)
dg.caption(d, s, 3.960, GT + 0.110, 4.620,
           "防守端　Raspberry Pi 5　Ubuntu 24.04 ＋ ROS 2 Jazzy",
           bold=True, color=INK)
dg.caption(d, s, 9.310, GT + 0.110, 2.520, "實驗工廠　筆電 WSL2",
           bold=True, color=BRICK)

dg.node(d, s, 0.810, 3.080, 2.420, 1.400,
        [("N28 wrong-CA participant\n", None, True),
         ("自己生 CA、自己簽憑證\n沒有防守方的任何秘密\n\n"
          "36 支攻擊 PoC\n出貨 catalog 20 個攻擊類別", MUTED, False)],
        fill=PAPER, size=9.0, outline=TAN, label="攻擊端")

dg.node(d, s, 3.960, 3.080, 4.620, 0.560,
        [("應用層　", TAN, True),
         ("patrol_node ・ mission_manager ・ sensor_hub ・ system_status",
          None, False)],
        fill=PAPER, size=9.0, label="應用層")
dg.node(d, s, 3.960, 3.700, 4.620, 0.560,
        [("防禦層　", TAN, True),
         ("monitor_node（HMAC 簽章）・ intelligent_defense_node"
          "（D1–D6,任 2 個觸發;D1／D4／D5 可單獨發 alert）\n"
          "velocity_guard_node　— /cmd_vel 的唯一合法 publisher", None, False)],
        fill=BLUE, size=9.0, label="防禦層")
dg.node(d, s, 3.960, 4.320, 4.620, 0.560,
        [("觀測層　", TAN, True),
         ("security_observer（C++,直接用 Fast DDS API 記 RTPS 認證事件）\n"
          "dumpcap　— 封包層擷取", None, False)],
        fill=PAPER, size=9.0, label="觀測層")
dg.node(d, s, 3.960, 4.940, 4.620, 0.560,
        [("回應層　", TAN, True),
         ("ResponseAuthorizer → ResponseBackend → 核心 nftables\n"
          "（這三個就是圖 2 展開的物件、圖 3 右邊三條 lifeline）", None, False)],
        fill=PAPER, size=9.0, outline=BRICK, dashed=True, label="回應層")
dg.caption(d, s, 3.960, 5.570, 4.620,
           "SROS2 keystore ＋ 14 個 enclave ・ HMAC 金鑰由 Pi 自己產生,未從筆電複製",
           size=8.0, color=MUTED)

dg.node(d, s, 9.310, 3.080, 2.520, 1.400,
        [("campaign orchestrator\n", None, True),
         ("Gazebo 模擬 ＋ 20 類攻擊排程\nfeatures.py 特徵抽取\n"
          "訓練與封印 holdout\n\n3,841 場・3,553 場合格", MUTED, False)],
        fill=PAPER, size=9.0, outline=TAN, label="實驗工廠")

dg.arrow(d, s, 3.370, 3.560, 3.820, 3.560, color=SOLID)
dg.caption(d, s, 3.370, 3.330, 0.450, "攻擊", size=8.0, color=SOLID, bold=True)
dg.arrow(d, s, 9.170, 3.560, 8.720, 3.560, color=TAN, dash=True)
dg.caption(d, s, 8.720, 3.330, 0.450, "SSH", size=8.0, color=MUTED, bold=True)

d.band_note(s, 6.020, [
    ("實驗網　", None, True),
    ("Wi-Fi・192.168.0.x・RTPS domain 41　— 攻擊流量與 DDS 探索都走這裡。　",
     None, False),
    ("管理網　", None, True),
    ("直連網路線・192.168.137.x　— out-of-band SSH。", None, False),
    ("\n兩者刻意分開:nft 封鎖實驗若把控制通道自己封掉就救不回來"
     "（sudo 的 env_reset 會剝掉 SSH_CONNECTION,讓防鎖死閘變成 no-op）。",
     MUTED, False),
], left=L0, w=11.300, h=0.700)
d.footer(s, [("虛線的回應層　", None, True),
             ("機制九項全過,但 executable_classes 仍為空清單 "
              "⇒ 沒有任何模型判定到得了 backend。", None, False)])
d.pagenum(s, 1)


# ============================================ 2 物件圖
s = d.slide(("rail", BRICK))
d.eyebrow(s, "圖 2 ／ 3　OBJECT DIAGRAM")
y = d.title(s, "物件圖｜從一份歸因證據到一條核心規則")
y = d.lead(s, "圖 1 回應層那一格的展開。實線箭頭是資料流,空心箭頭是繼承;"
              "三個 TimeoutSetAdapter 實作裡,出貨預設是停用的那一個。", y + 0.050)

R1, NH, RGAP = y + 0.110, 0.600, 0.820      # 同上
R2, R3, R4, R5 = (R1 + RGAP * k for k in (1, 2, 3, 4))


def nd(left, top, w, txt, **kw):
    return dg.node(d, s, left, top, w, NH, txt, size=9.4, **kw)


nd(0.670, R1, 2.300, [("AttributionEvidence\n", None, True),
                      ("四條判定的輸出", MUTED, False)], fill=MIST)
nd(3.370, R1, 2.300, [("ResponseContext\n", None, True),
                      ("模式・信心・來源", MUTED, False)], fill=MIST)
nd(6.070, R1, 2.500, [("ResponseAuthorizer\n", None, True),
                      ("兩個訊號・兩個窗・0.95 下限", MUTED, False)], fill=STONE)
nd(8.970, R1, 2.500, [("AuthorizedResponse\n", None, True),
                      ("executable = False（出貨值）", BRICK, False)], fill=STONE)
for x in (2.970, 5.670, 8.570):
    dg.arrow(d, s, x, R1 + NH / 2, x + 0.400, R1 + NH / 2, color=SOLID)

nd(8.970, R2, 2.500, [("Ed25519TicketIssuer\n", None, True),
                      ("evidence_id = sha256(報告)", MUTED, False)],
   fill=PAPER, outline=TAN)
nd(6.870, R2, 1.700, [("ticket\n", None, True),
                      ("簽章字串", MUTED, False)], fill=PAPER, outline=TAN)
nd(3.970, R2, 2.500, [("Ed25519TicketVerifier\n", None, True),
                      ("驗章・防重放・檢查到期", MUTED, False)],
   fill=PAPER, outline=TAN)
nd(0.670, R2, 2.700, [("VerifiedResponseTicket\n", None, True),
                      ("唯一能驅動 backend 的憑據", MUTED, False)],
   fill=PAPER, outline=TAN)
for x in (8.970, 6.870, 3.970):
    dg.arrow(d, s, x, R2 + NH / 2, x - 0.400, R2 + NH / 2, color=SOLID)
dg.arrow(d, s, 10.220, R1 + NH, 10.220, R2, color=SOLID)

nd(4.100, R3, 3.000, [("ResponseBackend\n", None, True),
                      ("套用・對帳・撤銷", MUTED, False)], fill=STONE)
dg.arrow(d, s, 2.020, R2 + NH, 4.100, R3 + NH / 2, color=SOLID)

nd(1.400, R4, 3.200, [("SQLiteResponseState\n", None, True),
                      ("DesiredResponse ／ StagedResponse", MUTED, False)],
   fill=MIST)
nd(6.600, R4, 3.200, [("TimeoutSetAdapter\n", TAN, True),
                      ("«abstract»　到期由核心自己執行", MUTED, False)], fill=MIST)
dg.arrow(d, s, 5.600, R3 + NH, 3.000, R4, color=SOLID)
dg.arrow(d, s, 5.600, R3 + NH, 8.200, R4, color=SOLID)

nd(4.300, R5, 2.600, [("NftablesTimeout…\n", None, True),
                      ("真核心・9／9 通過", MUTED, False)], fill=PAPER, outline=SAGE)
nd(7.100, R5, 2.400, [("InMemoryTimeout…\n", None, True),
                      ("測試用", MUTED, False)], fill=PAPER, outline=TAN)
nd(9.700, R5, 2.400, [("DisabledProduction…\n", None, True),
                      ("出貨預設", BRICK, True)],
   fill=PAPER, outline=BRICK, dashed=True)
for cxx in (5.600, 8.300, 10.900):
    dg.arrow(d, s, cxx, R5, 8.200, R4 + NH, color=TAN, back=True, head=False)

d.footer(s, [("對應圖 1　", None, True),
             ("這一整張是「回應層」那一格的內容;ResponseAuthorizer／"
              "ResponseBackend／nftables 三個物件,就是圖 3 最右邊三條 lifeline。",
              None, False)])
d.pagenum(s, 2)


# ============================================ 3 循序圖
s = d.slide(("rail", SAGE))
d.eyebrow(s, "圖 3 ／ 3　SEQUENCE DIAGRAM")
y = d.title(s, "循序圖｜一次跨主機的攻擊 → 歸因 → 封鎖 → 撤銷")
y = d.lead(s, "2026-10-07 與 10-08 各跑過一次,九項檢查全過。"
              "10-08 那一次的核准片語由本人親手輸入。", y + 0.050)

LANES = [
    ("攻擊端 N28\nwrong-CA\n桌機 .141", BRICK),
    ("security_\nobserver\nPi・C++", SAGE),
    ("dumpcap ＋\nRTPS 解析", SAGE),
    ("crosscheck\n四條判定", SAGE),
    ("人\n（核准）", BRICK),
    ("Response\nAuthorizer", INK),
    ("Response\nBackend", INK),
    ("核心\nnftables", INK),
]
# 起點寫死時,引言會壓住全部 8 條 lane header —— 問 lead 它畫到哪裡。
HT, HH = y + 0.070, 0.720
LL_TOP = HT + HH
y0, dy = LL_TOP + 0.240, 0.255
LL_BOT = y0 + 11 * dy + 0.140
cx = [L0 + 11.330 / 8 * (i + 0.5) for i in range(8)]
for i, (name, col) in enumerate(LANES):
    dg.node(d, s, cx[i] - 0.660, HT, 1.320, HH, name,
            fill=(STONE if col is INK else MIST), size=8.6,
            tcolor=col, bold=True, label="lane%d" % i)
    dg.lifeline(d, s, cx[i], LL_TOP, LL_BOT)

MSGS = [
    (0, 1, "RTPS SPDP ＋ 自簽 CA 憑證"),
    (1, 1, "認證失敗 ⇒ 記 UNAUTHORIZED ＋ GUID（0 bytes 的稽核檔記不到這件事）"),
    (0, 2, "同一批封包進 pcap"),
    (2, 3, "GUID ↔ IP ＋ 來源 MAC"),
    (1, 3, "觀測者的拒絕記錄"),
    (3, 3, "四條判定 ⇒ blockable_ips = [192.168.0.141]（Pi 自己被正確拒絕）"),
    (4, 5, "核准片語（人親手輸入）"),
    (5, 6, "票:evidence_id = sha256(歸因報告)"),
    (6, 7, "add element {IP, timeout 90s}"),
    (7, 7, "counter 0 → 1 ⇒ 封包被丟棄"),
    (6, 7, "revoke_source ⇒ delete element"),
    (7, 7, "之後封包 +0 ⇒ 恢復通過"),
]
for k, (a, b, t) in enumerate(MSGS):
    dg.msg(d, s, cx[a], cx[b], y0 + k * dy, "%d. %s" % (k + 1, t),
           color=(BRICK if a == 4 else SOLID), size=8.0)

d.footer(s, [("仍不可宣稱　", None, True),
             ("沒有任何模型判定參與（票的對象來自證據,權限來自人）・"
              "一次不是 soak・一種攻擊・無正向對照・"
              "第 10、12 項用 ICMP 驗核心的 drop 路徑。", None, False)])
d.pagenum(s, 3)


# ============================================ 一致性斷言（老師 17:26）
labels = {i: {n[4] for n in v} for i, v in dg._NODES.items()}
assert "回應層" in labels[0], "架構圖缺回應層"
assert {"lane5", "lane6", "lane7"} <= labels[2], "循序圖缺回應三條 lifeline"
print("一致性:架構圖的回應層 ↔ 物件圖的展開 ↔ 循序圖的 lane5-7　OK")

d.save(OUT)
print("寫出 %s" % OUT)
print("節點數 %s" % {k + 1: len(v) for k, v in dg._NODES.items()})
