# -*- coding: utf-8 -*-
"""系統架構圖／物件圖／循序圖的畫圖元件,配 deck_lib 的自然色系。

這支檔案存在的理由:2026-10-21 的口試,老師重複四次「不要用文字描述」,
並指名要三張圖(系統架構圖、物件圖、循序圖)。deck_lib 只有表格與色塊,
畫不出圖,所以另開這一支 —— 刻意不改 deck_lib,既有的簡報腳本就不會被動到。

延續 C2C-132／133 的守衛,並補上它們沒有涵蓋的兩類:

1. 越界、壓表格、壓頁碼 —— 沿用 deck_lib 的 Deck._register。
2. 文字溢出 —— node() 自己算文字在框裡需要幾行,放不下就 build 失敗。
   C2C-132 的溢出檢查是事後跑的,這裡提前到畫的當下。
3. **節點互相重疊** —— deck_lib 的守衛只擋「壓住表格」,
   而一張圖裡兩個方框疊在一起,它回報乾淨。
4. **訊息文字互相重疊** —— 循序圖的訊息間距只有 0.255 吋,
   任何一個文字框多吃 0.1 吋就會壓到下一個。而這一類前三道全部看不到:
   它們比的是框與表格、框與頁碼,沒有比文字與文字。
   ⚠️ 這一道刻意用「估計的實際字寬」而不是宣告的框寬 ——
   self 訊息的框宣告 5.6 吋寬而實際字可能只有 3 吋,
   用框寬會對每一個鄰居誤報,而一個會誤報的檢查沒有人會讀。
"""
from pptx.util import Inches, Pt
from pptx.enum.shapes import MSO_SHAPE, MSO_CONNECTOR
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.dml import MSO_LINE_DASH_STYLE
from pptx.oxml.ns import qn

from deck_lib import FONT, INK, MUTED, SAGE, TAN, STONE, MIST
from deck_lib import est_lines, est_width

RIGHT_EDGE = 12.330          # 頁碼的左緣,文字不可越過

_NODES = {}                  # slide_idx -> [(L, T, W, H, label)]
_TEXTS = {}                  # slide_idx -> [(L, T, W, H, text)]


def reset(deck):
    _NODES.clear()
    _TEXTS.clear()


def _idx(deck, s):
    return list(deck.prs.slides).index(s)


def node(deck, s, left, top, w, h, runs, fill=STONE, tcolor=INK, size=10.5,
         bold=False, outline=None, dashed=False, radius=0.10, label=None):
    """圖的方框。文字在框內垂直置中、水平置中。

    runs: str 或 [(text, color|None, bold|None), ...];換行用 \\n。
    """
    sh = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                            Inches(left), Inches(top), Inches(w), Inches(h))
    sh.adjustments[0] = radius
    sh.fill.solid()
    sh.fill.fore_color.rgb = fill
    sh.shadow.inherit = False
    if outline is None:
        sh.line.fill.background()
    else:
        sh.line.color.rgb = outline
        sh.line.width = Pt(1.25)
        if dashed:
            sh.line.dash_style = MSO_LINE_DASH_STYLE.DASH

    tf = sh.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = tf.margin_right = Inches(0.06)
    tf.margin_top = tf.margin_bottom = Inches(0.02)

    if isinstance(runs, str):
        runs = [(runs, None, None)]
    runs = [(r, None, None) if isinstance(r, str) else r for r in runs]
    paras, plain = [[]], []
    for t, c, b in runs:
        plain.append(t)
        for k, part in enumerate(t.split("\n")):
            if k:
                paras.append([])
            if part:
                paras[-1].append((part, c, b))
    for pi, pr in enumerate(paras):
        p = tf.paragraphs[0] if pi == 0 else tf.add_paragraph()
        p.alignment = PP_ALIGN.CENTER
        p.line_spacing = 1.22
        for t, c, b in pr:
            r = p.add_run()
            r.text = t
            r.font.name = FONT
            r.font.size = Pt(size)
            r.font.bold = bold if b is None else b
            r.font.color.rgb = tcolor if c is None else c

    # --- 守衛 2:文字放不下就失敗（而不是讓它默默溢出框外）---
    text = "".join(plain)
    lines = sum(est_lines(seg, w - 0.12, size) for seg in text.split("\n"))
    need = lines * size * 1.22 / 72.0 + 0.04
    if need > h + 1e-6:
        deck.violations.append(
            "p%d 節點文字放不下 需要%.3f 框高%.3f：%s"
            % (_idx(deck, s) + 1, need, h, text.replace("\n", "／")[:40]))

    # --- 守衛 3:節點互相重疊 ---
    i = _idx(deck, s)
    for (ol, ot, ow, oh, olab) in _NODES.get(i, []):
        if (left < ol + ow - 1e-6 and left + w > ol + 1e-6 and
                top < ot + oh - 1e-6 and top + h > ot + 1e-6):
            deck.violations.append(
                "p%d 節點重疊：%s ↔ %s" % (i + 1, label or text[:16], olab))
    _NODES.setdefault(i, []).append((left, top, w, h, label or text[:16]))

    deck._register(s, left, top, w, h, has_text=True)
    return sh


def group(deck, s, left, top, w, h, fill=MIST, outline=None, dashed=False):
    """硬體容器:只有底色,不登記成節點（裡面本來就要放節點）。"""
    sh = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                            Inches(left), Inches(top), Inches(w), Inches(h))
    sh.adjustments[0] = 0.04
    sh.fill.solid()
    sh.fill.fore_color.rgb = fill
    sh.shadow.inherit = False
    if outline is None:
        sh.line.fill.background()
    else:
        sh.line.color.rgb = outline
        sh.line.width = Pt(1.0)
        if dashed:
            sh.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    deck._register(s, left, top, w, h)
    return sh


def arrow(deck, s, x1, y1, x2, y2, color=SAGE, width=1.25, dash=False,
          head=True, back=False):
    conn = s.shapes.add_connector(MSO_CONNECTOR.STRAIGHT,
                                  Inches(x1), Inches(y1), Inches(x2), Inches(y2))
    conn.line.color.rgb = color
    conn.line.width = Pt(width)
    # ⚠️ 順序:dash 要先設,否則 a:prstDash 會被插在 a:tailEnd 之後而違反 schema。
    if dash:
        conn.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    ln = conn.line._get_or_add_ln()
    if head:
        ln.append(ln.makeelement(qn("a:tailEnd"),
                                 {"type": "triangle", "w": "med", "len": "med"}))
    if back:
        ln.insert(0, ln.makeelement(qn("a:headEnd"),
                                    {"type": "triangle", "w": "med", "len": "med"}))
    deck._register(s, min(x1, x2), min(y1, y2), abs(x2 - x1), abs(y2 - y1))
    return conn


def caption(deck, s, left, top, w, text, size=8.4, color=MUTED,
            align=PP_ALIGN.CENTER, bold=False):
    """箭頭旁或節點外的小標。"""
    deck.text(s, left, top, w, 0.200, text, size=size, color=color,
              align=align, bold=bold, line=1.10)


def lifeline(deck, s, x, top, bottom, color=TAN):
    arrow(deck, s, x, top, x, bottom, color=color, width=1.0, dash=True,
          head=False)


def _tracked_text(deck, s, left, top, w, text, size, color, align, bold):
    """畫一行文字,並用估計的實際字寬做守衛 4 的重疊檢查。"""
    deck.text(s, left, top, w, 0.200, text, size=size, color=color,
              align=align, bold=bold, line=1.10)
    aw = min(w, est_width(text, size))
    if align == PP_ALIGN.RIGHT:
        al = left + w - aw
    elif align == PP_ALIGN.CENTER:
        al = left + (w - aw) / 2.0
    else:
        al = left
    i = _idx(deck, s)
    for (ol, ot, ow, oh, otxt) in _TEXTS.get(i, []):
        if (al < ol + ow - 1e-6 and al + aw > ol + 1e-6 and
                top < ot + oh - 1e-6 and top + 0.200 > ot + 1e-6):
            deck.violations.append(
                "p%d 訊息文字重疊：%s ↔ %s" % (i + 1, text[:24], otxt[:24]))
    _TEXTS.setdefault(i, []).append((al, top, aw, 0.200, text))


def msg(deck, s, x1, x2, y, text, color=SAGE, dash=False, size=8.4,
        tcolor=INK, bold=False, tw=5.60):
    """循序圖的訊息。x1 == x2 時畫成 self:lifeline 上一個小方塊。

    ⚠️ 文字一律放在 y-0.215,與箭頭訊息同一條基線 —— self 的文字若垂直置中
    於方塊,它會往下多吃 0.1 吋而壓到下一個訊息（間距只有 0.255）。
    """
    ty = y - 0.215
    if abs(x1 - x2) < 1e-6:
        sh = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x1 - 0.045),
                                Inches(y - 0.065), Inches(0.090), Inches(0.130))
        sh.fill.solid()
        sh.fill.fore_color.rgb = color
        sh.line.fill.background()
        sh.shadow.inherit = False
        deck._register(s, x1 - 0.045, y - 0.065, 0.090, 0.130)
        # 右邊放不下就換到左邊靠右對齊（最右那條 lifeline 一定會遇到）
        if x1 + 0.090 + tw > RIGHT_EDGE:
            _tracked_text(deck, s, x1 - 0.090 - tw, ty, tw, text, size, tcolor,
                          PP_ALIGN.RIGHT, bold)
        else:
            _tracked_text(deck, s, x1 + 0.090, ty, tw, text, size, tcolor,
                          PP_ALIGN.LEFT, bold)
        return
    arrow(deck, s, x1, y, x2, y, color=color, dash=dash, width=1.25)
    lo, hi = min(x1, x2), max(x1, x2)
    # ⚠️ 相鄰兩條 lifeline 只有 1.4 吋,大多數訊息在那個寬度下要兩行,
    # 而框只有一行高。所以讓文字框向兩側長到放得下為止,再夾回版面內。
    mid = (lo + hi) / 2.0
    bw = max(hi - lo, min(est_width(text, size) + 0.08, 5.20))
    bl = max(0.670, min(mid - bw / 2.0, RIGHT_EDGE - bw))
    _tracked_text(deck, s, bl, ty, bw, text, size, tcolor,
                  PP_ALIGN.CENTER, bold)
