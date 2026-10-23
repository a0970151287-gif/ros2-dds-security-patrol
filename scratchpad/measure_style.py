import sys, collections
from pptx import Presentation
from pptx.util import Emu

src = "文件/SROS2智慧防火牆_專題最終報告_自然色系_2026-08-21.pptx"
p = Presentation(src)
print("slides", len(p.slides))
print("size_in", p.slide_width/914400, p.slide_height/914400)

layouts = collections.Counter()
shapetypes = collections.Counter()
fonts = collections.Counter()
sizes = collections.Counter()
fills = collections.Counter()
colors = collections.Counter()
for s in p.slides:
    layouts[s.slide_layout.name] += 1
    for sh in s.shapes:
        shapetypes[str(sh.shape_type)] += 1
        try:
            if sh.fill.type is not None and sh.fill.type == 1:
                fills[str(sh.fill.fore_color.rgb)] += 1
        except Exception:
            pass
        if sh.has_text_frame:
            for para in sh.text_frame.paragraphs:
                for r in para.runs:
                    if r.font.name: fonts[r.font.name] += 1
                    if r.font.size: sizes[round(r.font.size.pt,1)] += 1
                    try:
                        if r.font.color and r.font.color.type == 1:
                            colors[str(r.font.color.rgb)] += 1
                    except Exception:
                        pass
print("layouts", dict(layouts))
print("shapetypes", dict(shapetypes))
print("fonts", dict(fonts))
print("sizes", sorted(sizes.items(), key=lambda kv:-kv[1])[:14])
print("fills", fills.most_common(12))
print("textcolors", colors.most_common(10))

# page number box position: smallest shape at bottom-right
cands = []
for s in p.slides:
    for sh in s.shapes:
        if sh.has_text_frame and sh.text_frame.text.strip().isdigit():
            cands.append((round(sh.left/914400,3), round(sh.top/914400,3),
                          round(sh.width/914400,3), round(sh.height/914400,3),
                          sh.text_frame.text.strip()))
print("pagenum", collections.Counter([c[:4] for c in cands]).most_common(3))
