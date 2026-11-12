package diw.wallet.core.document.ofd

import kotlin.math.sqrt

/**
 * The glyph outlines of an embedded font, so OFD text is drawn with the document's own glyph shapes on every
 * platform: TrueType (glyf, simple and composite glyphs), OpenType with CFF outlines, bare CFF (including CID-keyed
 * fonts with FDSelect) and the first font of a collection. Glyphs are found by Unicode through the cmap (formats 0,
 * 4, 6 and 12, symbol fonts too) or given by index (CGTransform). Outlines are in font units, y up.
 */
class FontProgram private constructor(
    val unitsPerEm: Int,
    val glyphCount: Int,
    private val cmap: (Int) -> Int,
    private val outlines: (Int) -> List<OfdPathCommand>,
) {
    private val cache = HashMap<Int, List<OfdPathCommand>>()

    /** The glyph for [codePoint]; 0 (the missing glyph) when the font has none. */
    fun glyphId(codePoint: Int): Int = runCatching { cmap(codePoint) }.getOrDefault(0)

    /** The outline of glyph [id] in font units (y up); empty for a blank glyph or one that cannot be read. */
    fun outline(id: Int): List<OfdPathCommand> {
        if (id < 0 || id >= glyphCount) return emptyList()
        return cache.getOrPut(id) { runCatching { outlines(id) }.getOrDefault(emptyList()) }
    }

    companion object {
        /** The font in [bytes], or null when it is no TrueType, OpenType or CFF font this reader understands. */
        fun parse(bytes: ByteArray): FontProgram? = runCatching {
            val b = Bytes(bytes)
            when {
                bytes.size < 12 -> null
                b.tag(0) == "ttcf" -> sfnt(b, b.u32(12).toInt())
                b.u32(0) == 0x00010000L || b.tag(0) == "true" || b.tag(0) == "OTTO" -> sfnt(b, 0)
                b.u8(0) == 1 && b.u8(2) in 4..32 -> cff(b, 0, bytes.size, null, 1000)
                else -> null
            }
        }.getOrNull()

        private fun sfnt(b: Bytes, base: Int): FontProgram? {
            val count = b.u16(base + 4)
            val tables = HashMap<String, Pair<Int, Int>>()
            for (i in 0 until count) {
                val r = base + 12 + i * 16
                tables[b.tag(r)] = b.u32(r + 8).toInt() to b.u32(r + 12).toInt()
            }
            val head = tables["head"]?.first
            val upem = head?.let { b.u16(it + 18) }?.takeIf { it in 16..16384 } ?: 1000
            val maxp = tables["maxp"]?.first
            val numGlyphs = maxp?.let { b.u16(it + 4) } ?: 0
            val cmap = tables["cmap"]?.let { (off, _) -> cmapLookup(b, off) } ?: { 0 }
            tables["CFF "]?.let { (off, len) -> return cff(b, off, off + len, cmap, upem) }
            val glyf = tables["glyf"] ?: return null
            val loca = tables["loca"] ?: return null
            val longLoca = head?.let { b.s16(it + 50) } == 1
            val n = if (numGlyphs > 0) numGlyphs else (loca.second / (if (longLoca) 4 else 2)) - 1
            fun location(id: Int): Pair<Int, Int> {
                val start = if (longLoca) b.u32(loca.first + id * 4).toInt() else b.u16(loca.first + id * 2) * 2
                val end = if (longLoca) b.u32(loca.first + id * 4 + 4).toInt() else b.u16(loca.first + id * 2 + 2) * 2
                return glyf.first + start to (end - start)
            }
            val glyphs = TrueTypeGlyphs(b, ::location)
            return FontProgram(upem, n, cmap) { glyphs.outline(it) }
        }

        // ------------------------------------------------------------ cmap

        private fun cmapLookup(b: Bytes, off: Int): (Int) -> Int {
            val n = b.u16(off + 2)
            class Sub(val platform: Int, val encoding: Int, val offset: Int, val format: Int)
            val subs = (0 until n).map { i ->
                val r = off + 4 + i * 8
                val o = off + b.u32(r + 4).toInt()
                Sub(b.u16(r), b.u16(r + 2), o, b.u16(o))
            }
            fun rank(s: Sub) = when {
                s.platform == 3 && s.encoding == 10 && s.format == 12 -> 0
                s.platform == 0 && s.format == 12 -> 1
                s.platform == 3 && s.encoding == 1 -> 2
                s.platform == 0 -> 3
                s.platform == 3 && s.encoding == 0 -> 4
                s.platform == 3 -> 5
                s.platform == 1 && s.encoding == 0 -> 6
                else -> 7
            }
            val best = subs.filter { it.format in setOf(0, 4, 6, 12) }.minByOrNull { rank(it) } ?: return { 0 }
            val symbol = best.platform == 3 && best.encoding == 0
            val lookup: (Int) -> Int = when (best.format) {
                0 -> { c -> if (c in 0..255) b.u8(best.offset + 6 + c) else 0 }
                6 -> { c ->
                    val first = b.u16(best.offset + 6)
                    val count = b.u16(best.offset + 8)
                    if (c - first in 0 until count) b.u16(best.offset + 10 + (c - first) * 2) else 0
                }
                12 -> { c ->
                    val groups = b.u32(best.offset + 12).toInt()
                    var lo = 0
                    var hi = groups - 1
                    var g = 0
                    while (lo <= hi) {
                        val mid = (lo + hi) ushr 1
                        val r = best.offset + 16 + mid * 12
                        val start = b.u32(r)
                        val end = b.u32(r + 4)
                        when {
                            c < start -> hi = mid - 1
                            c > end -> lo = mid + 1
                            else -> { g = (b.u32(r + 8) + (c - start)).toInt(); break }
                        }
                    }
                    g
                }
                else -> { c -> format4(b, best.offset, c) }
            }
            return if (symbol) { c -> lookup(c).takeIf { it != 0 } ?: if (c < 0x100) lookup(0xF000 + c) else 0 } else lookup
        }

        private fun format4(b: Bytes, o: Int, c: Int): Int {
            if (c > 0xFFFF) return 0
            val segX2 = b.u16(o + 6)
            val ends = o + 14
            val starts = ends + segX2 + 2
            val deltas = starts + segX2
            val ranges = deltas + segX2
            for (i in 0 until segX2 / 2) {
                val end = b.u16(ends + i * 2)
                if (c > end) continue
                val start = b.u16(starts + i * 2)
                if (c < start) return 0
                val delta = b.s16(deltas + i * 2)
                val rangeOffset = b.u16(ranges + i * 2)
                if (rangeOffset == 0) return (c + delta) and 0xFFFF
                val p = ranges + i * 2 + rangeOffset + (c - start) * 2
                val g = b.u16(p)
                return if (g == 0) 0 else (g + delta) and 0xFFFF
            }
            return 0
        }

        // ------------------------------------------------------------ CFF

        private fun cff(b: Bytes, start: Int, end: Int, cmap: ((Int) -> Int)?, upem: Int): FontProgram? {
            val hdrSize = b.u8(start + 2)
            val names = Index(b, start + hdrSize)
            val topDicts = Index(b, names.end)
            val strings = Index(b, topDicts.end)
            val gsubrs = Index(b, strings.end)
            val top = dict(b, topDicts.offset(0), topDicts.offset(0) + topDicts.length(0))
            val charStrings = Index(b, start + (top[17]?.firstOrNull()?.toInt() ?: return null))
            if ((top[1206]?.firstOrNull()?.toInt() ?: 2) != 2) return null
            val matrix = top[1207]
            val units = if (matrix != null && matrix.size >= 4 && matrix[0] != 0.0) (1.0 / matrix[0]).toInt().coerceIn(16, 16384) else upem
            fun privateOf(d: Map<Int, List<Double>>): Pair<Index?, Double> {
                val p = d[18] ?: return null to 0.0
                if (p.size < 2) return null to 0.0
                val size = p[0].toInt()
                val off = start + p[1].toInt()
                val priv = dict(b, off, off + size)
                val subrs = priv[19]?.firstOrNull()?.toInt()?.let { Index(b, off + it) }
                return subrs to (priv[21]?.firstOrNull() ?: 0.0)
            }
            val fdSelect: ((Int) -> Int)?
            val fdSubrs: List<Index?>
            if (top[1236] != null && top[1237] != null) {
                val fdArray = Index(b, start + top[1236]!!.first().toInt())
                fdSubrs = (0 until fdArray.count).map { i -> privateOf(dict(b, fdArray.offset(i), fdArray.offset(i) + fdArray.length(i))).first }
                val sel = start + top[1237]!!.first().toInt()
                val format = b.u8(sel)
                fdSelect = when (format) {
                    0 -> { g -> b.u8(sel + 1 + g) }
                    3 -> { g ->
                        val n = b.u16(sel + 1)
                        var fd = 0
                        for (i in 0 until n) {
                            val first = b.u16(sel + 3 + i * 3)
                            val next = b.u16(sel + 3 + (i + 1) * 3)
                            if (g >= first && g < next) { fd = b.u8(sel + 3 + i * 3 + 2); break }
                        }
                        fd
                    }
                    else -> { _ -> 0 }
                }
            } else {
                fdSubrs = listOf(privateOf(top).first)
                fdSelect = null
            }
            val glyphCount = charStrings.count
            return FontProgram(units, glyphCount, cmap ?: { 0 }) { id ->
                val subrs = fdSubrs.getOrNull(fdSelect?.invoke(id) ?: 0)
                Type2(b, gsubrs, subrs).run(charStrings.offset(id), charStrings.offset(id) + charStrings.length(id))
            }
        }

        /** A CFF DICT: operator (12 x as 1200 + x) to operands. */
        private fun dict(b: Bytes, start: Int, end: Int): Map<Int, List<Double>> {
            val out = HashMap<Int, List<Double>>()
            val stack = ArrayList<Double>()
            var p = start
            while (p < end) {
                val v = b.u8(p)
                when {
                    v <= 21 -> {
                        val op = if (v == 12) 1200 + b.u8(++p) else v
                        p++
                        out[op] = stack.toList()
                        stack.clear()
                    }
                    v == 28 -> { stack.add(b.s16(p + 1).toDouble()); p += 3 }
                    v == 29 -> { stack.add(b.u32(p + 1).toInt().toDouble()); p += 5 }
                    v == 30 -> {
                        val sb = StringBuilder()
                        p++
                        loop@ while (p < end) {
                            val byte = b.u8(p++)
                            for (nib in intArrayOf(byte shr 4, byte and 15)) when (nib) {
                                in 0..9 -> sb.append(nib)
                                10 -> sb.append('.')
                                11 -> sb.append('E')
                                12 -> sb.append("E-")
                                14 -> sb.append('-')
                                15 -> break@loop
                                else -> {}
                            }
                        }
                        stack.add(sb.toString().toDoubleOrNull() ?: 0.0)
                    }
                    v in 32..246 -> { stack.add((v - 139).toDouble()); p++ }
                    v in 247..250 -> { stack.add(((v - 247) * 256 + b.u8(p + 1) + 108).toDouble()); p += 2 }
                    v in 251..254 -> { stack.add((-(v - 251) * 256 - b.u8(p + 1) - 108).toDouble()); p += 2 }
                    else -> p++
                }
            }
            return out
        }
    }

    /** A CFF INDEX at [start]. */
    private class Index(private val b: Bytes, start: Int) {
        val count = b.u16(start)
        private val offSize = if (count == 0) 0 else b.u8(start + 2)
        private val offsets = start + 3
        private val data = offsets + (count + 1) * offSize - 1
        val end: Int = if (count == 0) start + 2 else data + off(count)

        private fun off(i: Int): Int {
            var v = 0
            for (k in 0 until offSize) v = (v shl 8) or b.u8(offsets + i * offSize + k)
            return v
        }

        fun offset(i: Int) = data + off(i)
        fun length(i: Int) = off(i + 1) - off(i)
    }

    /** A Type 2 charstring interpreter producing the outline. */
    private class Type2(private val b: Bytes, private val gsubrs: Index, private val subrs: Index?) {
        private val out = ArrayList<OfdPathCommand>()
        private val stack = DoubleArray(64)
        private var sp = 0
        private val transient = DoubleArray(32)
        private var x = 0.0
        private var y = 0.0
        private var stems = 0
        private var open = false
        private var haveWidth = false
        private var done = false
        private var depth = 0

        private fun bias(i: Index?) = when { i == null -> 0; i.count < 1240 -> 107; i.count < 33900 -> 1131; else -> 32768 }

        fun run(start: Int, end: Int): List<OfdPathCommand> {
            exec(start, end)
            if (open) out.add(OfdPathCommand.Close)
            return out
        }

        private fun push(v: Double) { if (sp < stack.size) stack[sp++] = v }
        private fun moveTo(dx: Double, dy: Double) {
            if (open) out.add(OfdPathCommand.Close)
            x += dx; y += dy
            out.add(OfdPathCommand.Move(x, y))
            open = true
        }
        private fun lineTo(dx: Double, dy: Double) { x += dx; y += dy; out.add(OfdPathCommand.Line(x, y)) }
        private fun curveTo(d1x: Double, d1y: Double, d2x: Double, d2y: Double, d3x: Double, d3y: Double) {
            val x1 = x + d1x; val y1 = y + d1y
            val x2 = x1 + d2x; val y2 = y1 + d2y
            x = x2 + d3x; y = y2 + d3y
            out.add(OfdPathCommand.Cubic(x1, y1, x2, y2, x, y))
        }

        /** Drops the width a first stack-clearing operator may carry. */
        private fun width(expectedEven: Boolean) {
            if (!haveWidth) {
                haveWidth = true
                if ((sp % 2 == 1) == expectedEven && sp > 0) {
                    for (i in 1 until sp) stack[i - 1] = stack[i]
                    sp--
                }
            }
        }

        private fun exec(start: Int, end: Int) {
            if (++depth > 10) return
            var p = start
            while (p < end && !done) {
                val v = b.u8(p)
                if (v >= 32 || v == 28) {
                    when {
                        v == 28 -> { push(b.s16(p + 1).toDouble()); p += 3 }
                        v <= 246 -> { push((v - 139).toDouble()); p++ }
                        v <= 250 -> { push(((v - 247) * 256 + b.u8(p + 1) + 108).toDouble()); p += 2 }
                        v <= 254 -> { push((-(v - 251) * 256 - b.u8(p + 1) - 108).toDouble()); p += 2 }
                        else -> { push(b.u32(p + 1).toInt() / 65536.0); p += 5 }
                    }
                    continue
                }
                p++
                when (v) {
                    1, 3, 18, 23 -> { width(true); stems += sp / 2; sp = 0 }
                    19, 20 -> {
                        width(true)
                        stems += sp / 2
                        sp = 0
                        p += (stems + 7) / 8
                    }
                    21 -> { width(true); if (sp >= 2) moveTo(stack[sp - 2], stack[sp - 1]); sp = 0 }
                    22 -> { width(false); if (sp >= 1) moveTo(stack[sp - 1], 0.0); sp = 0 }
                    4 -> { width(false); if (sp >= 1) moveTo(0.0, stack[sp - 1]); sp = 0 }
                    5 -> { var i = 0; while (i + 1 < sp) { lineTo(stack[i], stack[i + 1]); i += 2 }; sp = 0 }
                    6, 7 -> {
                        var horizontal = v == 6
                        for (i in 0 until sp) { if (horizontal) lineTo(stack[i], 0.0) else lineTo(0.0, stack[i]); horizontal = !horizontal }
                        sp = 0
                    }
                    8 -> { var i = 0; while (i + 5 < sp) { curveTo(stack[i], stack[i + 1], stack[i + 2], stack[i + 3], stack[i + 4], stack[i + 5]); i += 6 }; sp = 0 }
                    24 -> {
                        var i = 0
                        while (i + 5 < sp - 2) { curveTo(stack[i], stack[i + 1], stack[i + 2], stack[i + 3], stack[i + 4], stack[i + 5]); i += 6 }
                        if (i + 1 < sp) lineTo(stack[i], stack[i + 1])
                        sp = 0
                    }
                    25 -> {
                        var i = 0
                        while (i + 1 < sp - 6) { lineTo(stack[i], stack[i + 1]); i += 2 }
                        if (i + 5 < sp) curveTo(stack[i], stack[i + 1], stack[i + 2], stack[i + 3], stack[i + 4], stack[i + 5])
                        sp = 0
                    }
                    26 -> {
                        var i = 0
                        var dx1 = 0.0
                        if (sp % 2 == 1) { dx1 = stack[0]; i = 1 }
                        while (i + 3 < sp) { curveTo(dx1, stack[i], stack[i + 1], stack[i + 2], 0.0, stack[i + 3]); dx1 = 0.0; i += 4 }
                        sp = 0
                    }
                    27 -> {
                        var i = 0
                        var dy1 = 0.0
                        if (sp % 2 == 1) { dy1 = stack[0]; i = 1 }
                        while (i + 3 < sp) { curveTo(stack[i], dy1, stack[i + 1], stack[i + 2], stack[i + 3], 0.0); dy1 = 0.0; i += 4 }
                        sp = 0
                    }
                    30, 31 -> {
                        var i = 0
                        var vertical = v == 30
                        while (i + 3 < sp) {
                            val last = sp - i == 5
                            if (vertical) curveTo(0.0, stack[i], stack[i + 1], stack[i + 2], stack[i + 3], if (last) stack[i + 4] else 0.0)
                            else curveTo(stack[i], 0.0, stack[i + 1], stack[i + 2], if (last) stack[i + 4] else 0.0, stack[i + 3])
                            i += if (last) 5 else 4
                            vertical = !vertical
                        }
                        sp = 0
                    }
                    10, 29 -> {
                        if (sp < 1) return
                        val idx = if (v == 10) subrs else gsubrs
                        val n = stack[--sp].toInt() + bias(idx)
                        if (idx != null && n in 0 until idx.count) exec(idx.offset(n), idx.offset(n) + idx.length(n))
                    }
                    11 -> { depth--; return }
                    14 -> {
                        width(true)
                        if (open) { out.add(OfdPathCommand.Close); open = false }
                        done = true
                        sp = 0
                    }
                    12 -> {
                        val op = b.u8(p++)
                        escape(op)
                    }
                    else -> sp = 0
                }
            }
            depth--
        }

        private fun escape(op: Int) {
            fun a(i: Int) = stack.getOrElse(i) { 0.0 }
            when (op) {
                35 -> { // flex
                    if (sp >= 12) { curveTo(a(0), a(1), a(2), a(3), a(4), a(5)); curveTo(a(6), a(7), a(8), a(9), a(10), a(11)) }
                    sp = 0
                }
                34 -> { // hflex
                    if (sp >= 7) {
                        val y0 = y
                        curveTo(a(0), 0.0, a(1), a(2), a(3), 0.0)
                        curveTo(a(4), 0.0, a(5), y0 - y, a(6), 0.0)
                    }
                    sp = 0
                }
                36 -> { // hflex1
                    if (sp >= 9) {
                        curveTo(a(0), a(1), a(2), a(3), a(4), 0.0)
                        curveTo(a(5), 0.0, a(6), a(7), a(8), -(a(1) + a(3) + a(7)))
                    }
                    sp = 0
                }
                37 -> { // flex1
                    if (sp >= 11) {
                        val dx = a(0) + a(2) + a(4) + a(6) + a(8)
                        val dy = a(1) + a(3) + a(5) + a(7) + a(9)
                        val horizontal = kotlin.math.abs(dx) > kotlin.math.abs(dy)
                        curveTo(a(0), a(1), a(2), a(3), a(4), a(5))
                        curveTo(a(6), a(7), a(8), a(9), if (horizontal) a(10) else -dx, if (horizontal) -dy else a(10))
                    }
                    sp = 0
                }
                3 -> binary { l, r -> if (l != 0.0 && r != 0.0) 1.0 else 0.0 }
                4 -> binary { l, r -> if (l != 0.0 || r != 0.0) 1.0 else 0.0 }
                5 -> unary { if (it == 0.0) 1.0 else 0.0 }
                9 -> unary { kotlin.math.abs(it) }
                10 -> binary { l, r -> l + r }
                11 -> binary { l, r -> l - r }
                12 -> binary { l, r -> if (r == 0.0) 0.0 else l / r }
                14 -> unary { -it }
                15 -> binary { l, r -> if (l == r) 1.0 else 0.0 }
                18 -> if (sp > 0) sp--
                20 -> if (sp >= 2) { val i = stack[sp - 1].toInt(); val v = stack[sp - 2]; sp -= 2; if (i in transient.indices) transient[i] = v }
                21 -> if (sp >= 1) { val i = stack[sp - 1].toInt(); stack[sp - 1] = transient.getOrElse(i) { 0.0 } }
                22 -> if (sp >= 4) { val v2 = stack[sp - 1]; val v1 = stack[sp - 2]; val s2 = stack[sp - 3]; val s1 = stack[sp - 4]; sp -= 4; push(if (v1 <= v2) s1 else s2) }
                23 -> push(0.5)
                24 -> binary { l, r -> l * r }
                26 -> unary { if (it > 0) sqrt(it) else 0.0 }
                27 -> if (sp >= 1) push(stack[sp - 1])
                28 -> if (sp >= 2) { val t = stack[sp - 1]; stack[sp - 1] = stack[sp - 2]; stack[sp - 2] = t }
                29 -> if (sp >= 1) { var i = stack[sp - 1].toInt(); sp--; if (i < 0) i = 0; if (i < sp) push(stack[sp - 1 - i]) }
                30 -> if (sp >= 2) {
                    val j = stack[sp - 1].toInt(); val n = stack[sp - 2].toInt(); sp -= 2
                    if (n in 1..sp) {
                        val base = sp - n
                        val seg = DoubleArray(n) { stack[base + it] }
                        for (k in 0 until n) stack[base + ((k + j) % n + n) % n] = seg[k]
                    }
                }
                else -> sp = 0
            }
        }

        private inline fun binary(f: (Double, Double) -> Double) {
            if (sp < 2) return
            val r = stack[--sp]
            val l = stack[--sp]
            push(f(l, r))
        }

        private inline fun unary(f: (Double) -> Double) {
            if (sp < 1) return
            stack[sp - 1] = f(stack[sp - 1])
        }
    }

    /** TrueType glyph outlines (glyf) as quadratic paths. */
    private class TrueTypeGlyphs(private val b: Bytes, private val location: (Int) -> Pair<Int, Int>) {
        fun outline(id: Int, depth: Int = 0): List<OfdPathCommand> {
            if (depth > 8) return emptyList()
            val (o, len) = location(id)
            if (len <= 0) return emptyList()
            val contours = b.s16(o)
            return if (contours >= 0) simple(o, contours) else composite(o, depth)
        }

        private fun simple(o: Int, contours: Int): List<OfdPathCommand> {
            if (contours == 0) return emptyList()
            val ends = IntArray(contours) { b.u16(o + 10 + it * 2) }
            val points = ends.last() + 1
            val insLen = b.u16(o + 10 + contours * 2)
            var p = o + 12 + contours * 2 + insLen
            val flags = IntArray(points)
            var i = 0
            while (i < points) {
                val f = b.u8(p++)
                flags[i++] = f
                if (f and 8 != 0) {
                    var repeat = b.u8(p++)
                    while (repeat-- > 0 && i < points) flags[i++] = f
                }
            }
            val xs = IntArray(points)
            val ys = IntArray(points)
            var v = 0
            for (k in 0 until points) {
                val f = flags[k]
                v += when {
                    f and 2 != 0 -> { val d = b.u8(p++); if (f and 16 != 0) d else -d }
                    f and 16 != 0 -> 0
                    else -> { val d = b.s16(p); p += 2; d }
                }
                xs[k] = v
            }
            v = 0
            for (k in 0 until points) {
                val f = flags[k]
                v += when {
                    f and 4 != 0 -> { val d = b.u8(p++); if (f and 32 != 0) d else -d }
                    f and 32 != 0 -> 0
                    else -> { val d = b.s16(p); p += 2; d }
                }
                ys[k] = v
            }
            val out = ArrayList<OfdPathCommand>()
            var start = 0
            for (c in 0 until contours) {
                val end = ends[c]
                contour(out, start, end, xs, ys, flags)
                start = end + 1
            }
            return out
        }

        /** One contour: on-curve points joined by lines, off-curve points as quadratic controls (with implied midpoints). */
        private fun contour(out: MutableList<OfdPathCommand>, s: Int, e: Int, xs: IntArray, ys: IntArray, flags: IntArray) {
            if (e < s) return
            val n = e - s + 1
            fun on(k: Int) = flags[s + (k % n)] and 1 != 0
            fun px(k: Int) = xs[s + (k % n)].toDouble()
            fun py(k: Int) = ys[s + (k % n)].toDouble()
            // Start at an on-curve point, or at the midpoint of the first two off-curve points.
            var first = (0 until n).firstOrNull { on(it) }
            val sx: Double
            val sy: Double
            if (first == null) {
                sx = (px(0) + px(1)) / 2; sy = (py(0) + py(1)) / 2
                first = 0
            } else {
                sx = px(first); sy = py(first)
            }
            out.add(OfdPathCommand.Move(sx, sy))
            var cx: Double? = null
            var cy = 0.0
            for (step in 1..n) {
                val k = first + step
                val x = px(k); val y = py(k)
                if (on(k)) {
                    if (cx != null) out.add(OfdPathCommand.Quad(cx, cy, x, y)) else out.add(OfdPathCommand.Line(x, y))
                    cx = null
                } else {
                    if (cx != null) {
                        val mx = (cx + x) / 2; val my = (cy + y) / 2
                        out.add(OfdPathCommand.Quad(cx, cy, mx, my))
                    }
                    cx = x; cy = y
                }
            }
            if (cx != null) out.add(OfdPathCommand.Quad(cx, cy, sx, sy))
            out.add(OfdPathCommand.Close)
        }

        private fun composite(o: Int, depth: Int): List<OfdPathCommand> {
            val out = ArrayList<OfdPathCommand>()
            var p = o + 10
            while (true) {
                val flags = b.u16(p)
                val glyph = b.u16(p + 2)
                p += 4
                val dx: Double
                val dy: Double
                if (flags and 1 != 0) { dx = b.s16(p).toDouble(); dy = b.s16(p + 2).toDouble(); p += 4 }
                else { dx = b.s8(p).toDouble(); dy = b.s8(p + 1).toDouble(); p += 2 }
                val xy = flags and 2 != 0
                var a = 1.0; var bb = 0.0; var c = 0.0; var d = 1.0
                when {
                    flags and 8 != 0 -> { a = b.f2dot14(p); d = a; p += 2 }
                    flags and 64 != 0 -> { a = b.f2dot14(p); d = b.f2dot14(p + 2); p += 4 }
                    flags and 128 != 0 -> { a = b.f2dot14(p); bb = b.f2dot14(p + 2); c = b.f2dot14(p + 4); d = b.f2dot14(p + 6); p += 8 }
                }
                val ox = if (xy) dx else 0.0
                val oy = if (xy) dy else 0.0
                fun tx(x: Double, y: Double) = a * x + c * y + ox
                fun ty(x: Double, y: Double) = bb * x + d * y + oy
                for (cmd in outline(glyph, depth + 1)) out.add(
                    when (cmd) {
                        is OfdPathCommand.Move -> OfdPathCommand.Move(tx(cmd.x, cmd.y), ty(cmd.x, cmd.y))
                        is OfdPathCommand.Line -> OfdPathCommand.Line(tx(cmd.x, cmd.y), ty(cmd.x, cmd.y))
                        is OfdPathCommand.Quad -> OfdPathCommand.Quad(tx(cmd.x1, cmd.y1), ty(cmd.x1, cmd.y1), tx(cmd.x, cmd.y), ty(cmd.x, cmd.y))
                        is OfdPathCommand.Cubic -> OfdPathCommand.Cubic(
                            tx(cmd.x1, cmd.y1), ty(cmd.x1, cmd.y1), tx(cmd.x2, cmd.y2), ty(cmd.x2, cmd.y2), tx(cmd.x, cmd.y), ty(cmd.x, cmd.y),
                        )
                        OfdPathCommand.Close -> OfdPathCommand.Close
                    },
                )
                if (flags and 32 == 0) break
            }
            return out
        }
    }

    /** Big-endian reads that fail outside the data. */
    private class Bytes(val d: ByteArray) {
        fun u8(p: Int): Int = d[p].toInt() and 0xFF
        fun s8(p: Int): Int = d[p].toInt()
        fun u16(p: Int): Int = (u8(p) shl 8) or u8(p + 1)
        fun s16(p: Int): Int = u16(p).toShort().toInt()
        fun u32(p: Int): Long = (u16(p).toLong() shl 16) or u16(p + 2).toLong()
        fun f2dot14(p: Int): Double = s16(p) / 16384.0
        fun tag(p: Int): String = if (p + 4 <= d.size) (0 until 4).map { d[p + it].toInt().toChar() }.joinToString("") else ""
    }
}
