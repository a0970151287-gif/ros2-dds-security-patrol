# -*- coding: utf-8 -*-
"""簡報的五項幾何／結構檢查，獨立讀存檔後的 pptx。

與 deck_lib 的 build 期守衛是兩回事：守衛讓 build 失敗，這支驗成品。
兩者刻意分開 —— 一個只檢查自己產生的東西的檢查，證明不了成品是對的。

五項：
  1. 越界            任何形狀超出 13.333 x 7.5
  2. 空白頁          一頁沒有任何非空白文字
  3. 估計溢出        文字的估計高度超過框高（字寬估計，不是 render）
  4. 文字框重疊      兩個有文字的框互相相交
  5. 色塊蓋住文字    後畫的、有實心填色、沒有文字的形狀覆蓋前面的文字框 >= 25%
                     （C2C-132：第 4 項只比有文字的框彼此，所以這一類永遠回報乾淨）

用法：python 工具腳本/qa_deck.py <deck.pptx>
"""
import sys
from pptx import Presentation

EMU = 914400.0
W_IN, H_IN = 13.3333333, 7.5
EPS = 1e-6


def char_w(ch):
    return 0.52 if ord(ch) < 0x2E80 else 1.0


def est_lines(text, box_w_in, pt):
    """估計這段文字要幾行。這是字寬估計不是 render。"""
    total = 0
    for para in text.split(chr(10)):
        if not para.strip():
            total += 1
            continue
        w = sum(char_w(c) for c in para) * pt / 72.0
        total += max(1, int(w / box_w_in) + (1 if w % box_w_in > EPS else 0))
    return total


def need_height(sh, box_w_in):
    """用存檔裡『真正的』字級與行距算需要的高度。

    ⚠️ 不可以在這裡自己猜一個行距常數 —— 那樣兩邊的估計式會分歧，
    而檢查回報的就不是版面對不對，是兩個常數差多少。
    """
    need = 0.0
    for p in sh.text_frame.paragraphs:
        runs = [r for r in p.runs]
        if not runs:
            continue
        pt = max((r.font.size.pt for r in runs if r.font.size), default=0.0)
        if pt <= 0:
            continue
        ls = p.line_spacing if isinstance(p.line_spacing, (int, float)) else 1.2
        txt = "".join(r.text for r in runs)
        need += est_lines(txt, box_w_in, pt) * pt * ls / 72.0
    return need


def rect(sh):
    return (sh.left / EMU, sh.top / EMU, sh.width / EMU, sh.height / EMU)


def inter_area(a, b):
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    ox = max(0.0, min(ax + aw, bx + bw) - max(ax, bx))
    oy = max(0.0, min(ay + ah, by + bh) - max(ay, by))
    return ox * oy


def main(path):
    prs = Presentation(path)
    out_of_bounds, blank, overflow, overlap, covered = [], [], [], [], []

    for i, s in enumerate(prs.slides, 1):
        items = []   # (order, rect, text, need_h, has_fill)
        for k, sh in enumerate(s.shapes):
            r = rect(sh)
            txt = ""
            need = 0.0
            if sh.has_text_frame:
                txt = sh.text_frame.text
                if txt.strip():
                    need = need_height(sh, r[2])
            has_fill = False
            try:
                has_fill = sh.fill.type == 1
            except Exception:
                pass
            items.append((k, r, txt, need, has_fill))

            x, y, w, h = r
            if x < -EPS or y < -EPS or x + w > W_IN + EPS or y + h > H_IN + EPS:
                out_of_bounds.append("p%d #%d L%.3f T%.3f W%.3f H%.3f" % (i, k, x, y, w, h))

        if not any(t.strip() for _, _, t, _, _ in items):
            blank.append("p%d" % i)

        texts = [(k, r, t, nh) for k, r, t, nh, _ in items if t.strip()]

        # 3. 溢出（用存檔裡真正的字級與行距，容差 0.02 吋）
        for k, r, t, need in texts:
            if need > r[3] + 0.02:
                overflow.append("p%d #%d need%.2f have%.2f  %s"
                                % (i, k, need, r[3], t[:24].replace(chr(10), " ")))

        # 4. 文字框彼此重疊
        for a in range(len(texts)):
            for b in range(a + 1, len(texts)):
                if inter_area(texts[a][1], texts[b][1]) > 1e-4:
                    overlap.append("p%d #%d x #%d  %s | %s"
                                   % (i, texts[a][0], texts[b][0],
                                      texts[a][2][:16].replace("\n", " "),
                                      texts[b][2][:16].replace("\n", " ")))

        # 5. 後畫的色塊蓋住前面的文字（C2C-132 漏掉的那一類）
        for k, r, t, nh, fl in items:
            if t.strip() or not fl:
                continue
            if r[2] >= W_IN - EPS and r[3] >= H_IN - EPS:
                continue                      # 整頁底色
            if r[3] >= H_IN - EPS:
                continue                      # 整條側邊色帶
            for tk, tr, tt, _ in texts:
                if tk >= k:
                    continue                  # 只看「後畫的蓋住前畫的」
                area = tr[2] * tr[3]
                if area > 0 and inter_area(r, tr) / area >= 0.25:
                    covered.append("p%d 色塊#%d 蓋住 文字#%d (%.0f%%)  %s"
                                   % (i, k, tk, 100 * inter_area(r, tr) / area,
                                      tt[:20].replace("\n", " ")))

    print("頁數 %d   版面 %.2f x %.2f 吋" % (len(prs.slides),
                                            prs.slide_width / EMU, prs.slide_height / EMU))
    fonts = set()
    for s in prs.slides:
        for sh in s.shapes:
            if sh.has_text_frame:
                for p in sh.text_frame.paragraphs:
                    for r in p.runs:
                        if r.font.name:
                            fonts.add(r.font.name)
    print("字型", sorted(fonts))
    bad = 0
    for name, lst in (("1 越界", out_of_bounds), ("2 空白頁", blank),
                      ("3 估計溢出", overflow), ("4 文字框重疊", overlap),
                      ("5 色塊蓋住文字", covered)):
        print("%-14s %d %s" % (name, len(lst), "OK" if not lst else "FAIL"))
        for x in lst[:12]:
            print("      ", x)
        bad += len(lst)
    print("\n五項全過" if bad == 0 else "\n共 %d 處" % bad)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
