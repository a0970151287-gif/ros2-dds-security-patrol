from pptx import Presentation
import collections
src = "文件/SROS2智慧防火牆_專題成果增補2_自然色系_2026-10-19.pptx"
p = Presentation(src)
print("slides", len(p.slides))
EMU=914400
# dump slide 2 fully (a representative content page)
for idx in (0,1,2):
    s = p.slides[idx]
    print("=== slide", idx+1, "shapes", len(s.shapes))
    for sh in s.shapes:
        txt = sh.text_frame.text.strip()[:30] if sh.has_text_frame else ""
        fill = ""
        try:
            if sh.fill.type == 1: fill = str(sh.fill.fore_color.rgb)
        except Exception: pass
        sz=""
        if sh.has_text_frame:
            ss=[round(r.font.size.pt,1) for pa in sh.text_frame.paragraphs for r in pa.runs if r.font.size]
            sz=str(ss[:3])
        print("  L%.3f T%.3f W%.3f H%.3f fill=%-7s sz=%-14s %s" % (
            sh.left/EMU, sh.top/EMU, sh.width/EMU, sh.height/EMU, fill, sz, ascii(txt)))
