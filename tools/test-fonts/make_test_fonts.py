"""Builds the synthetic fonts in test-servers/src/test/resources/documents/fonts (needs fontTools).

diw-test.ttf      TrueType: A (two contours), B (composite of a scaled A and C), C (quadratic curves)
diw-test.otf      OpenType CFF with the same glyph names, cubic curves
diw-test-cid.otf  CID-keyed CFF (ROS, two Font DICTs, FDSelect format 3)
diw-test.ttc      collection of the TrueType and CFF fonts
All map U+0041 to glyph 1, U+4E2D to glyph 2 and U+1F600 to glyph 3 (cmap formats 4 and 12).
Usage: python3 make_test_fonts.py OUTPUT_DIR
"""
import os
import sys

from fontTools.cffLib import FDArrayIndex, FDSelect, FontDict
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.t2CharStringPen import T2CharStringPen
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTCollection, TTFont


def draw_a(pen):
    pen.moveTo((100, 0)); pen.lineTo((500, 0)); pen.lineTo((500, 700)); pen.lineTo((100, 700)); pen.closePath()
    pen.moveTo((200, 100)); pen.lineTo((200, 600)); pen.lineTo((400, 600)); pen.lineTo((400, 100)); pen.closePath()


def draw_c(pen, quad):
    pen.moveTo((300, -100))
    if quad:
        pen.qCurveTo((600, -100), (600, 300)); pen.qCurveTo((600, 800), (300, 800))
        pen.qCurveTo((0, 800), (0, 300)); pen.qCurveTo((0, -100), (300, -100))
    else:
        pen.curveTo((500, -100), (600, 100), (600, 300)); pen.curveTo((600, 600), (450, 800), (300, 800))
        pen.curveTo((100, 800), (0, 600), (0, 300)); pen.curveTo((0, 100), (100, -100), (300, -100))
    pen.closePath()


def finish(fb, order, path):
    fb.setupHorizontalMetrics({n: (600, 0) for n in order})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupNameTable({"familyName": "DiwTest", "styleName": "Regular"})
    fb.setupOS2()
    fb.setupPost()
    fb.save(path)


def truetype(path):
    order = [".notdef", "A", "B", "C"]
    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder(order)
    fb.setupCharacterMap({0x41: "A", 0x4E2D: "B", 0x1F600: "C"})
    g = {".notdef": TTGlyphPen(None).glyph()}
    p = TTGlyphPen(None); draw_a(p); g["A"] = p.glyph()
    p = TTGlyphPen(None); draw_c(p, True); g["C"] = p.glyph()
    p = TTGlyphPen(g); p.addComponent("A", (0.5, 0, 0, 0.5, 50, 100)); p.addComponent("C", (1, 0, 0, 1, 700, 0)); g["B"] = p.glyph()
    fb.setupGlyf(g)
    finish(fb, order, path)


def cff(path, order):
    fb = FontBuilder(1000, isTTF=False)
    fb.setupGlyphOrder(order)
    fb.setupCharacterMap({0x41: order[1], 0x4E2D: order[2], 0x1F600: order[3]})
    cs = {}
    for n in order:
        p = T2CharStringPen(600, None)
        if n == order[1]:
            draw_a(p)
        elif n != ".notdef":
            draw_c(p, False)
        cs[n] = p.getCharString()
    fb.setupCFF("DiwTest", {"FullName": "DiwTest"}, cs, {})
    finish(fb, order, path)


def cid(path):
    order = [".notdef", "cid00001", "cid00002", "cid00003"]
    cff(path, order)
    f = TTFont(path)
    f.getGlyphOrder()
    top = f["CFF "].cff.topDictIndex[0]
    strings = top.CharStrings
    for name in order:
        strings[name]
    top.ROS = ("Adobe", "Identity", 0)
    top.CIDCount = len(order)
    fds = FDArrayIndex()
    for i in range(2):
        fd = FontDict()
        fd.Private = top.Private
        fd.FontName = "DiwTest-FD%d" % i
        fds.append(fd)
    sel = FDSelect()
    sel.format = 3
    sel.gidArray = [0, 1, 1, 0]
    top.FDArray = fds
    top.FDSelect = sel
    strings.fdArray = fds
    strings.fdSelect = sel
    for i, name in enumerate(order):
        strings[name].private = fds[sel[i]].Private
    f.save(path)


def main(out):
    os.makedirs(out, exist_ok=True)
    truetype(os.path.join(out, "diw-test.ttf"))
    cff(os.path.join(out, "diw-test.otf"), [".notdef", "A", "B", "C"])
    cid(os.path.join(out, "diw-test-cid.otf"))
    c = TTCollection()
    c.fonts = [TTFont(os.path.join(out, "diw-test.ttf")), TTFont(os.path.join(out, "diw-test.otf"))]
    c.save(os.path.join(out, "diw-test.ttc"))


if __name__ == "__main__":
    main(sys.argv[1])
