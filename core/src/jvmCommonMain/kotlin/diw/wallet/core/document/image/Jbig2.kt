package diw.wallet.core.document.image

import diw.wallet.core.i18n.ct

/** A bilevel image: [pixels] holds one byte per pixel, row by row, 1 for black. */
class Jbig2Bitmap(val width: Int, val height: Int, val pixels: ByteArray = ByteArray(width * height)) {
    operator fun get(x: Int, y: Int): Int = pixels[y * width + x].toInt()

    /** As an 8 bit gray image, black on white. */
    fun toRaster(): RasterImage {
        val out = ByteArray(width * height)
        for (i in out.indices) out[i] = if (pixels[i].toInt() != 0) 0 else 0xFF.toByte()
        return RasterImage(width, height, 1, out)
    }
}

/**
 * A JBIG2 decoder (ITU-T T.88) in pure Kotlin, for the bilevel images of OFD documents (MultiMedia format JB2) on
 * every platform. It reads the file format (sequential or random access) and the embedded stream form, and decodes
 * the first page: generic regions (arithmetic with typical prediction and adaptive pixels, or MMR), generic
 * refinement regions (with typical prediction), symbol dictionaries and text regions (arithmetic or Huffman, with
 * refinement and aggregation, standard and custom tables, retained coding contexts), pattern dictionaries and
 * halftone regions (with skipping), intermediate regions, all combination operators and striped pages of unknown
 * height. The arithmetic decoding and region procedures follow pdf.js (Apache License 2.0, Mozilla Foundation);
 * MMR uses the CCITT Group 4 decoder of [TiffDecoder].
 */
object Jbig2 {
    private val FILE_ID = byteArrayOf(0x97.toByte(), 0x4A, 0x42, 0x32, 0x0D, 0x0A, 0x1A, 0x0A)

    /** True when [b] starts with the JBIG2 file header. */
    fun isFile(b: ByteArray) = b.size >= 9 && (0 until 8).all { b[it] == FILE_ID[it] }

    /** The first page of [data] (a JBIG2 file or embedded stream), after the segments of [globals] when given. */
    fun decode(data: ByteArray, globals: ByteArray? = null): Jbig2Bitmap {
        val segments = ArrayList<Segment>()
        globals?.let { segments.addAll(readSegments(it, 0, it.size, false)) }
        if (isFile(data)) {
            val flags = data[8].toInt() and 0xFF
            var pos = 9
            if (flags and 2 == 0) pos += 4
            segments.addAll(readSegments(data, pos, data.size, flags and 1 == 0))
        } else {
            segments.addAll(readSegments(data, 0, data.size, false))
        }
        val visitor = Visitor()
        for (s in segments) {
            if (visitor.done) break
            visitor.process(s)
        }
        return visitor.result() ?: fail("no page")
    }

    internal fun fail(detail: String): Nothing = throw ImageDecodeException(ct("core_jbig2_bad", detail))

    // ---------------------------------------------------------------- bitmaps

    internal class Bits(val width: Int, val height: Int, val data: ByteArray = ByteArray(maxOf(0, width) * maxOf(0, height))) {
        operator fun get(x: Int, y: Int): Int = data[y * width + x].toInt()
        operator fun set(x: Int, y: Int, v: Int) { data[y * width + x] = v.toByte() }

        /** The [w] by [h] area at [x], [y]; pixels outside are 0. */
        fun crop(x: Int, y: Int, w: Int, h: Int): Bits {
            val out = Bits(w, h)
            for (j in 0 until h) {
                val sy = y + j
                if (sy < 0 || sy >= height) continue
                for (i in 0 until w) {
                    val sx = x + i
                    if (sx in 0 until width) out.data[j * w + i] = data[sy * width + sx]
                }
            }
            return out
        }

        fun fill(v: Int) { if (v != 0) data.fill(1) }
    }

    private class Pt(val x: Int, val y: Int)

    /** Combines [v] into [d] with a combination operator: OR, AND, XOR, XNOR, REPLACE. */
    private fun combine(d: Int, v: Int, op: Int): Int = when (op) {
        0 -> d or v
        1 -> d and v
        2 -> d xor v
        3 -> (d xor v) xor 1
        else -> v
    }

    /** Draws [src] into [dst] at [x], [y] with [op], clipped to [dst]. */
    private fun compose(dst: Bits, src: Bits, x: Int, y: Int, op: Int) {
        for (j in 0 until src.height) {
            val dy = y + j
            if (dy < 0 || dy >= dst.height) continue
            val drow = dy * dst.width
            val srow = j * src.width
            for (i in 0 until src.width) {
                val dx = x + i
                if (dx < 0 || dx >= dst.width) continue
                val v = src.data[srow + i].toInt()
                dst.data[drow + dx] = combine(dst.data[drow + dx].toInt(), v, op).toByte()
            }
        }
    }

    // ---------------------------------------------------------------- arithmetic decoding

    private val QE = intArrayOf(
        0x5601, 0x3401, 0x1801, 0x0ac1, 0x0521, 0x0221, 0x5601, 0x5401, 0x4801, 0x3801, 0x3001, 0x2401, 0x1c01, 0x1601,
        0x5601, 0x5401, 0x5101, 0x4801, 0x3801, 0x3401, 0x3001, 0x2801, 0x2401, 0x2201, 0x1c01, 0x1801, 0x1601, 0x1401,
        0x1201, 0x1101, 0x0ac1, 0x09c1, 0x08a1, 0x0521, 0x0441, 0x02a1, 0x0221, 0x0141, 0x0111, 0x0085, 0x0049, 0x0025,
        0x0015, 0x0009, 0x0005, 0x0001, 0x5601,
    )
    private val NMPS = intArrayOf(
        1, 2, 3, 4, 5, 38, 7, 8, 9, 10, 11, 12, 13, 29, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 45, 46,
    )
    private val NLPS = intArrayOf(
        1, 6, 9, 12, 29, 33, 6, 14, 14, 14, 17, 18, 20, 21, 14, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 46,
    )
    private val SWITCH = intArrayOf(1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1)

    /** The MQ arithmetic decoder of T.88 Annex E. */
    private class ArithmeticDecoder(private val data: ByteArray, start: Int, private val end: Int) {
        private var bp = start
        private var chigh: Int
        private var clow = 0
        private var ct = 0
        private var a: Int

        private fun at(i: Int): Int = if (i in 0 until minOf(end, data.size)) data[i].toInt() and 0xFF else -1

        init {
            chigh = at(start).coerceAtLeast(0)
            byteIn()
            chigh = ((chigh shl 7) and 0xffff) or ((clow shr 9) and 0x7f)
            clow = (clow shl 7) and 0xffff
            ct -= 7
            a = 0x8000
        }

        private fun byteIn() {
            if (at(bp) == 0xff) {
                if (at(bp + 1) > 0x8f) {
                    clow += 0xff00
                    ct = 8
                } else {
                    bp++
                    clow += at(bp).coerceAtLeast(0) shl 9
                    ct = 7
                }
            } else {
                bp++
                clow += if (bp < end && bp < data.size) at(bp) shl 8 else 0xff00
                ct = 8
            }
            if (clow > 0xffff) {
                chigh += clow shr 16
                clow = clow and 0xffff
            }
        }

        fun readBit(contexts: ByteArray, pos: Int): Int {
            var index = contexts[pos].toInt() shr 1
            var mps = contexts[pos].toInt() and 1
            val qe = QE[index]
            val d: Int
            var a = this.a - qe
            if (chigh < qe) {
                if (a < qe) {
                    a = qe
                    d = mps
                    index = NMPS[index]
                } else {
                    a = qe
                    d = 1 xor mps
                    if (SWITCH.getOrElse(index) { 0 } == 1) mps = d
                    index = NLPS[index]
                }
            } else {
                chigh -= qe
                if (a and 0x8000 != 0) {
                    this.a = a
                    return mps
                }
                if (a < qe) {
                    d = 1 xor mps
                    if (SWITCH.getOrElse(index) { 0 } == 1) mps = d
                    index = NLPS[index]
                } else {
                    d = mps
                    index = NMPS[index]
                }
            }
            do {
                if (ct == 0) byteIn()
                a = a shl 1
                chigh = ((chigh shl 1) and 0xffff) or ((clow shr 15) and 1)
                clow = (clow shl 1) and 0xffff
                ct--
            } while (a and 0x8000 == 0)
            this.a = a
            contexts[pos] = ((index shl 1) or mps).toByte()
            return d
        }
    }

    /** Arithmetic coding statistics by procedure name. */
    private class ContextCache {
        val map = HashMap<String, ByteArray>()
        fun get(name: String, size: Int = 1 shl 16): ByteArray {
            val have = map[name]
            if (have != null && have.size >= size) return have
            return ByteArray(size).also { n -> have?.copyInto(n); map[name] = n }
        }

        /** A copy of the generic and refinement statistics, for a later dictionary that reuses them. */
        fun bitmapContexts(): Map<String, ByteArray> = map.filterKeys { it == "GB" || it == "GR" }.mapValues { it.value.copyOf() }
    }

    private class DecodingContext(val data: ByteArray, val start: Int, val end: Int, val cache: ContextCache = ContextCache()) {
        val decoder: ArithmeticDecoder by lazy { ArithmeticDecoder(data, start, end) }
    }

    /** The integer decoding procedure (Annex A.2); null for OOB. */
    private fun decodeInteger(cache: ContextCache, procedure: String, decoder: ArithmeticDecoder): Int? {
        val contexts = cache.get(procedure, 512)
        var prev = 1
        fun bits(length: Int): Long {
            var v = 0L
            for (i in 0 until length) {
                val bit = decoder.readBit(contexts, prev)
                prev = if (prev < 256) (prev shl 1) or bit else (((prev shl 1) or bit) and 511) or 256
                v = (v shl 1) or bit.toLong()
            }
            return v
        }
        val sign = bits(1)
        val value = when {
            bits(1) == 0L -> bits(2)
            bits(1) == 0L -> bits(4) + 4
            bits(1) == 0L -> bits(6) + 20
            bits(1) == 0L -> bits(8) + 84
            bits(1) == 0L -> bits(12) + 340
            else -> bits(32) + 4436
        }
        val signed = if (sign == 0L) value else if (value > 0) -value else return null
        return if (signed in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) signed.toInt() else null
    }

    /** The symbol ID decoding procedure (Annex A.3). */
    private fun decodeIaid(cache: ContextCache, decoder: ArithmeticDecoder, codeLength: Int): Int {
        val len = codeLength.coerceIn(0, 30)
        val contexts = cache.get("IAID", 1 shl (len + 1))
        var prev = 1
        for (i in 0 until len) prev = (prev shl 1) or decoder.readBit(contexts, prev)
        return prev and ((1 shl len) - 1)
    }

    private fun log2(x: Int): Int {
        if (x <= 1) return 0
        var n = 0
        while ((1L shl n) < x) n++
        return n
    }

    // ---------------------------------------------------------------- generic regions

    private val CODING_TEMPLATES = arrayOf(
        listOf(Pt(-1, -2), Pt(0, -2), Pt(1, -2), Pt(-2, -1), Pt(-1, -1), Pt(0, -1), Pt(1, -1), Pt(2, -1), Pt(-4, 0), Pt(-3, 0), Pt(-2, 0), Pt(-1, 0)),
        listOf(Pt(-1, -2), Pt(0, -2), Pt(1, -2), Pt(2, -2), Pt(-2, -1), Pt(-1, -1), Pt(0, -1), Pt(1, -1), Pt(2, -1), Pt(-3, 0), Pt(-2, 0), Pt(-1, 0)),
        listOf(Pt(-1, -2), Pt(0, -2), Pt(1, -2), Pt(-2, -1), Pt(-1, -1), Pt(0, -1), Pt(1, -1), Pt(-2, 0), Pt(-1, 0)),
        listOf(Pt(-3, -1), Pt(-2, -1), Pt(-1, -1), Pt(0, -1), Pt(1, -1), Pt(-4, 0), Pt(-3, 0), Pt(-2, 0), Pt(-1, 0)),
    )
    private val REFINEMENT_CODING = arrayOf(
        listOf(Pt(0, -1), Pt(1, -1), Pt(-1, 0)),
        listOf(Pt(-1, -1), Pt(0, -1), Pt(1, -1), Pt(-1, 0)),
    )
    private val REFINEMENT_REFERENCE = arrayOf(
        listOf(Pt(0, -1), Pt(1, -1), Pt(-1, 0), Pt(0, 0), Pt(1, 0), Pt(-1, 1), Pt(0, 1), Pt(1, 1)),
        listOf(Pt(0, -1), Pt(-1, 0), Pt(0, 0), Pt(1, 0), Pt(0, 1), Pt(1, 1)),
    )
    private val REUSED_CONTEXTS = intArrayOf(0x9b25, 0x0795, 0x00e5, 0x0195)
    private val REFINEMENT_REUSED_CONTEXTS = intArrayOf(0x0020, 0x0008)

    /** MMR (T.6) coded bitmap at [start] of [data]; returns it with the position after it (and its EOFB when there is one). */
    private fun mmr(data: ByteArray, start: Int, end: Int, width: Int, height: Int): Pair<Bits, Int> {
        val out = Bits(width, height)
        if (width <= 0 || height <= 0) return out to start
        val slice = data.copyOfRange(start.coerceIn(0, data.size), end.coerceIn(start.coerceIn(0, data.size), data.size))
        val c = Ccitt(slice, width, height, 4, 0, 0)
        val packed = c.decode()
        val rowBytes = (width + 7) / 8
        for (y in 0 until height) for (x in 0 until width) {
            out.data[y * width + x] = ((packed[y * rowBytes + x / 8].toInt() shr (7 - x % 8)) and 1).toByte()
        }
        return out to start + c.bytesUsed()
    }

    private fun decodeBitmap(
        mmr: Boolean, width: Int, height: Int, templateIndex: Int, prediction: Boolean, skip: Bits?, at: List<Pt>, ctx: DecodingContext,
    ): Bits {
        if (mmr) return mmr(ctx.data, ctx.start, ctx.end, width, height).first
        val template = (CODING_TEMPLATES[templateIndex] + at).sortedWith(compareBy<Pt>({ it.y }, { it.x }))
        val n = template.size
        val tx = IntArray(n) { template[it].x }
        val ty = IntArray(n) { template[it].y }
        val changing = ArrayList<Int>()
        var reuseMask = 0
        var minX = 0; var maxX = 0; var minY = 0
        for (k in 0 until n) {
            minX = minOf(minX, tx[k]); maxX = maxOf(maxX, tx[k]); minY = minOf(minY, ty[k])
            if (k < n - 1 && ty[k] == ty[k + 1] && tx[k] == tx[k + 1] - 1) reuseMask = reuseMask or (1 shl (n - 1 - k))
            else changing.add(k)
        }
        val cx = IntArray(changing.size) { tx[changing[it]] }
        val cy = IntArray(changing.size) { ty[changing[it]] }
        val cbit = IntArray(changing.size) { 1 shl (n - 1 - changing[it]) }
        val left = -minX
        val top = -minY
        val right = width - maxX
        val pseudo = REUSED_CONTEXTS[templateIndex]
        val bitmap = Bits(width, height)
        val d = bitmap.data
        val decoder = ctx.decoder
        val contexts = ctx.cache.get("GB")
        var ltp = 0
        var label = 0
        for (i in 0 until height) {
            if (prediction) {
                ltp = ltp xor decoder.readBit(contexts, pseudo)
                if (ltp != 0) {
                    if (i > 0) d.copyInto(d, i * width, (i - 1) * width, i * width)
                    continue
                }
            }
            for (j in 0 until width) {
                if (skip != null && skip[j, i] != 0) { d[i * width + j] = 0; continue }
                if (j >= left && j < right && i >= top) {
                    label = (label shl 1) and reuseMask
                    for (k in cx.indices) {
                        if (d[(i + cy[k]) * width + j + cx[k]].toInt() != 0) label = label or cbit[k]
                    }
                } else {
                    label = 0
                    var shift = n - 1
                    for (k in 0 until n) {
                        val j0 = j + tx[k]
                        val i0 = i + ty[k]
                        if (j0 in 0 until width && i0 >= 0 && d[i0 * width + j0].toInt() != 0) label = label or (1 shl shift)
                        shift--
                    }
                }
                d[i * width + j] = decoder.readBit(contexts, label).toByte()
            }
        }
        return bitmap
    }

    private fun decodeRefinement(
        width: Int, height: Int, templateIndex: Int, reference: Bits, offsetX: Int, offsetY: Int, prediction: Boolean,
        at: List<Pt>?, ctx: DecodingContext,
    ): Bits {
        val coding = if (templateIndex == 0) REFINEMENT_CODING[0] + (at?.getOrNull(0) ?: Pt(-1, -1)) else REFINEMENT_CODING[1]
        val ref = if (templateIndex == 0) REFINEMENT_REFERENCE[0] + (at?.getOrNull(1) ?: Pt(-1, -1)) else REFINEMENT_REFERENCE[1]
        val cX = IntArray(coding.size) { coding[it].x }
        val cY = IntArray(coding.size) { coding[it].y }
        val rX = IntArray(ref.size) { ref[it].x }
        val rY = IntArray(ref.size) { ref[it].y }
        val rw = reference.width
        val rh = reference.height
        fun refAt(x: Int, y: Int) = if (x < 0 || y < 0 || x >= rw || y >= rh) 0 else reference.data[y * rw + x].toInt()
        val pseudo = REFINEMENT_REUSED_CONTEXTS[templateIndex]
        val bitmap = Bits(width, height)
        val d = bitmap.data
        val decoder = ctx.decoder
        val contexts = ctx.cache.get("GR")
        var ltp = 0
        for (i in 0 until height) {
            if (prediction) ltp = ltp xor decoder.readBit(contexts, pseudo)
            for (j in 0 until width) {
                if (ltp != 0) {
                    // Typical prediction: a pixel whose reference neighbourhood is all one colour takes that colour.
                    val x0 = j - offsetX
                    val y0 = i - offsetY
                    val c = refAt(x0, y0)
                    var same = true
                    loop@ for (dy in -1..1) for (dx in -1..1) if (refAt(x0 + dx, y0 + dy) != c) { same = false; break@loop }
                    if (same) { d[i * width + j] = c.toByte(); continue }
                }
                var label = 0
                for (k in cX.indices) {
                    val i0 = i + cY[k]
                    val j0 = j + cX[k]
                    label = if (i0 < 0 || j0 < 0 || j0 >= width) label shl 1 else (label shl 1) or d[i0 * width + j0].toInt()
                }
                for (k in rX.indices) label = (label shl 1) or refAt(j + rX[k] - offsetX, i + rY[k] - offsetY)
                d[i * width + j] = decoder.readBit(contexts, label).toByte()
            }
        }
        return bitmap
    }

    // ---------------------------------------------------------------- symbols and text

    private class TextTables(
        val symbolId: HuffmanTable?,
        val firstS: HuffmanTable,
        val deltaS: HuffmanTable,
        val deltaT: HuffmanTable,
        val rdw: HuffmanTable?,
        val rdh: HuffmanTable?,
        val rdx: HuffmanTable?,
        val rdy: HuffmanTable?,
        val rsize: HuffmanTable?,
    )

    private class DictionaryTables(val deltaHeight: HuffmanTable, val deltaWidth: HuffmanTable, val bitmapSize: HuffmanTable, val aggregate: HuffmanTable)

    /** Tables a text region inside a refined Huffman symbol dictionary uses (6.5.8.2.3). */
    private fun nestedTextTables() = TextTables(
        null, standardTable(6), standardTable(8), standardTable(11),
        standardTable(15), standardTable(15), standardTable(15), standardTable(15), standardTable(1),
    )

    private class SymbolResult(val symbols: List<Bits>, val contexts: Map<String, ByteArray>)

    private fun decodeSymbolDictionary(
        huffman: Boolean, refinement: Boolean, input: List<Bits>, newCount: Int, tables: DictionaryTables?,
        templateIndex: Int, at: List<Pt>, refinementTemplate: Int, refinementAt: List<Pt>?, ctx: DecodingContext, reader: Reader?,
    ): List<Bits> {
        val newSymbols = ArrayList<Bits>()
        var height = 0
        var codeLength = log2(input.size + newCount)
        if (huffman) codeLength = maxOf(codeLength, 1)
        val cache = ctx.cache
        val widths = ArrayList<Int>()
        var emptyClasses = 0
        while (newSymbols.size < newCount) {
            val dh = if (huffman) tables!!.deltaHeight.decode(reader!!) else decodeInteger(cache, "IADH", ctx.decoder)
            height += dh ?: fail("height class")
            if (height < 0) fail("height")
            var width = 0
            var total = 0
            val first = widths.size
            var inClass = 0
            while (true) {
                val dw = if (huffman) tables!!.deltaWidth.decode(reader!!) else decodeInteger(cache, "IADW", ctx.decoder)
                if (dw == null) break
                width += dw
                total += width
                if (width < 0) fail("width")
                inClass++
                if (newSymbols.size + (widths.size - first) >= newCount) fail("symbol count")
                if (refinement) {
                    val instances = if (huffman) tables!!.aggregate.decode(reader!!) ?: fail("aggregate") else decodeInteger(cache, "IAAI", ctx.decoder) ?: fail("aggregate")
                    val all = input + newSymbols
                    val bitmap = if (instances > 1) {
                        decodeTextRegion(
                            huffman, true, width, height, 0, instances, 1, 0, all, codeLength, false, 0, 1, 0,
                            if (huffman) nestedTextTables() else null, refinementTemplate, refinementAt, ctx, reader,
                        )
                    } else if (huffman) {
                        val r = reader!!
                        val id = r.readBits(codeLength).toInt()
                        val rdx = standardTable(15).decode(r) ?: 0
                        val rdy = standardTable(15).decode(r) ?: 0
                        val size = standardTable(1).decode(r) ?: 0
                        r.byteAlign()
                        val start = r.position
                        val sub = DecodingContext(ctx.data, start, start + size, cache)
                        val symbol = all.getOrNull(id) ?: fail("symbol id")
                        val bmp = decodeRefinement(width, height, refinementTemplate, symbol, rdx, rdy, false, refinementAt, sub)
                        r.position = start + size
                        bmp
                    } else {
                        val id = decodeIaid(cache, ctx.decoder, codeLength)
                        val rdx = decodeInteger(cache, "IARDX", ctx.decoder) ?: 0
                        val rdy = decodeInteger(cache, "IARDY", ctx.decoder) ?: 0
                        val symbol = all.getOrNull(id) ?: fail("symbol id")
                        decodeRefinement(width, height, refinementTemplate, symbol, rdx, rdy, false, refinementAt, ctx)
                    }
                    newSymbols.add(bitmap)
                } else if (huffman) {
                    widths.add(width)
                } else {
                    newSymbols.add(decodeBitmap(false, width, height, templateIndex, false, null, at, ctx))
                }
            }
            if (huffman && !refinement) {
                val r = reader!!
                val size = tables!!.bitmapSize.decode(r) ?: 0
                r.byteAlign()
                val collective = if (size == 0) {
                    readUncompressed(r, total, height)
                } else {
                    val start = r.position
                    val bmp = mmr(ctx.data, start, start + size, total, height).first
                    r.position = start + size
                    bmp
                }
                var x = 0
                for (k in first until widths.size) {
                    newSymbols.add(collective.crop(x, 0, widths[k], height))
                    x += widths[k]
                }
            }
            if (inClass == 0 && ++emptyClasses > 4096) fail("empty height classes")
        }
        // Exported symbols: runs of not exported and exported, starting with not exported.
        val total = input.size + newCount
        val flags = ArrayList<Boolean>(total)
        var current = false
        var guard = 0
        while (flags.size < total) {
            val run = if (huffman) standardTable(1).decode(reader!!) ?: fail("export") else decodeInteger(cache, "IAEX", ctx.decoder) ?: fail("export")
            if (run < 0 || flags.size + run > total) fail("export run")
            repeat(run) { flags.add(current) }
            current = !current
            if (++guard > total + 2) fail("export runs")
        }
        val out = ArrayList<Bits>()
        for (i in input.indices) if (flags[i]) out.add(input[i])
        for (j in 0 until newCount) if (flags[input.size + j]) out.add(newSymbols[j])
        return out
    }

    private fun readUncompressed(r: Reader, width: Int, height: Int): Bits {
        val out = Bits(width, height)
        for (y in 0 until height) {
            for (x in 0 until width) out.data[y * width + x] = r.readBit().toByte()
            r.byteAlign()
        }
        return out
    }

    private fun decodeTextRegion(
        huffman: Boolean, refinement: Boolean, width: Int, height: Int, defaultPixel: Int, instances: Int, stripSize: Int,
        logStripSize: Int, symbols: List<Bits>, codeLength: Int, transposed: Boolean, dsOffset: Int, corner: Int, op: Int,
        tables: TextTables?, refinementTemplate: Int, refinementAt: List<Pt>?, ctx: DecodingContext, reader: Reader?,
    ): Bits {
        val bitmap = Bits(width, height)
        bitmap.fill(defaultPixel)
        val cache = ctx.cache
        fun int(name: String, table: HuffmanTable?): Int? = if (huffman) table!!.decode(reader!!) else decodeInteger(cache, name, ctx.decoder)
        var stripT = -(int("IADT", tables?.deltaT) ?: fail("strip"))
        var firstS = 0
        var placed = 0
        while (placed < instances) {
            stripT += int("IADT", tables?.deltaT) ?: fail("strip")
            firstS += int("IAFS", tables?.firstS) ?: fail("first s")
            var currentS = firstS
            while (true) {
                val currentT = if (stripSize > 1) {
                    if (huffman) reader!!.readBits(logStripSize).toInt() else decodeInteger(cache, "IAIT", ctx.decoder) ?: 0
                } else 0
                val t = stripSize * stripT + currentT
                val id = if (huffman) {
                    tables!!.symbolId?.decode(reader!!) ?: reader!!.readBits(codeLength).toInt()
                } else decodeIaid(cache, ctx.decoder, codeLength)
                val refine = refinement && (if (huffman) reader!!.readBit() == 1 else (decodeInteger(cache, "IARI", ctx.decoder) ?: 0) != 0)
                var symbol = symbols.getOrNull(id) ?: fail("symbol $id")
                if (refine) {
                    val rdw: Int; val rdh: Int; val rdx: Int; val rdy: Int
                    if (huffman) {
                        val r = reader!!
                        rdw = tables!!.rdw?.decode(r) ?: 0
                        rdh = tables.rdh?.decode(r) ?: 0
                        rdx = tables.rdx?.decode(r) ?: 0
                        rdy = tables.rdy?.decode(r) ?: 0
                        val size = tables.rsize?.decode(r) ?: 0
                        r.byteAlign()
                        val start = r.position
                        val sub = DecodingContext(ctx.data, start, start + size, cache)
                        symbol = decodeRefinement(symbol.width + rdw, symbol.height + rdh, refinementTemplate, symbol, (rdw shr 1) + rdx, (rdh shr 1) + rdy, false, refinementAt, sub)
                        r.position = start + size
                    } else {
                        rdw = decodeInteger(cache, "IARDW", ctx.decoder) ?: 0
                        rdh = decodeInteger(cache, "IARDH", ctx.decoder) ?: 0
                        rdx = decodeInteger(cache, "IARDX", ctx.decoder) ?: 0
                        rdy = decodeInteger(cache, "IARDY", ctx.decoder) ?: 0
                        symbol = decodeRefinement(symbol.width + rdw, symbol.height + rdh, refinementTemplate, symbol, (rdw shr 1) + rdx, (rdh shr 1) + rdy, false, refinementAt, ctx)
                    }
                }
                val w = symbol.width
                val h = symbol.height
                // Placement by reference corner (0 bottom left, 1 top left, 2 bottom right, 3 top right), as T.88 6.4.5.
                if (!transposed && (corner == 2 || corner == 3)) currentS += w - 1
                else if (transposed && (corner == 0 || corner == 2)) currentS += h - 1
                var x = currentS
                var y = t
                if (transposed) { val swap = x; x = y; y = swap }
                when (corner) {
                    0 -> y -= h - 1
                    2 -> { y -= h - 1; x -= w - 1 }
                    3 -> x -= w - 1
                }
                compose(bitmap, symbol, x, y, op)
                if (!transposed && (corner == 0 || corner == 1)) currentS += w - 1
                else if (transposed && (corner == 1 || corner == 3)) currentS += h - 1
                placed++
                val ds = int("IADS", tables?.deltaS) ?: break
                currentS += ds + dsOffset
            }
        }
        return bitmap
    }

    // ---------------------------------------------------------------- patterns and halftones

    private fun decodePatternDictionary(mmr: Boolean, pw: Int, ph: Int, maxIndex: Int, template: Int, ctx: DecodingContext): List<Bits> {
        val at = ArrayList<Pt>()
        if (!mmr) {
            at.add(Pt(-pw, 0))
            if (template == 0) { at.add(Pt(-3, -1)); at.add(Pt(2, -2)); at.add(Pt(-2, -2)) }
        }
        val collective = decodeBitmap(mmr, (maxIndex + 1) * pw, ph, template, false, null, at, ctx)
        return (0..maxIndex).map { collective.crop(it * pw, 0, pw, ph) }
    }

    private fun decodeHalftoneRegion(
        mmr: Boolean, patterns: List<Bits>, template: Int, regionWidth: Int, regionHeight: Int, defaultPixel: Int,
        enableSkip: Boolean, op: Int, gridWidth: Int, gridHeight: Int, gx: Int, gy: Int, vx: Int, vy: Int, ctx: DecodingContext,
    ): Bits {
        val region = Bits(regionWidth, regionHeight)
        region.fill(defaultPixel)
        if (patterns.isEmpty()) return region
        val pw = patterns[0].width
        val ph = patterns[0].height
        val bitsPerValue = log2(patterns.size)
        fun cellX(m: Int, n: Int) = (gx.toLong() + m.toLong() * vy + n.toLong() * vx).shr(8).toInt()
        fun cellY(m: Int, n: Int) = (gy.toLong() + m.toLong() * vx - n.toLong() * vy).shr(8).toInt()
        val skip = if (enableSkip) Bits(gridWidth, gridHeight).also { s ->
            for (m in 0 until gridHeight) for (n in 0 until gridWidth) {
                val x = cellX(m, n); val y = cellY(m, n)
                if (x + pw <= 0 || x >= regionWidth || y + ph <= 0 || y >= regionHeight) s[n, m] = 1
            }
        } else null
        val at = ArrayList<Pt>()
        if (!mmr) {
            at.add(Pt(if (template <= 1) 3 else 2, -1))
            if (template == 0) { at.add(Pt(-3, -1)); at.add(Pt(2, -2)); at.add(Pt(-2, -2)) }
        }
        val planes = arrayOfNulls<Bits>(bitsPerValue)
        var pos = ctx.start
        for (i in bitsPerValue - 1 downTo 0) {
            planes[i] = if (mmr) {
                val (b, next) = mmr(ctx.data, pos, ctx.end, gridWidth, gridHeight)
                pos = next
                b
            } else decodeBitmap(false, gridWidth, gridHeight, template, false, skip, at, ctx)
        }
        for (m in 0 until gridHeight) for (n in 0 until gridWidth) {
            var bit = 0
            var index = 0
            for (j in bitsPerValue - 1 downTo 0) {
                bit = bit xor planes[j]!![n, m]
                index = index or (bit shl j)
            }
            val pattern = patterns[index.coerceIn(0, patterns.size - 1)]
            compose(region, pattern, cellX(m, n), cellY(m, n), op)
        }
        return region
    }

    // ---------------------------------------------------------------- Huffman tables

    private class HuffmanLine(val rangeLow: Int, val prefixLength: Int, val rangeLength: Int, var prefixCode: Int, val lower: Boolean = false, val oob: Boolean = false)

    private class HuffmanNode(val line: HuffmanLine?) {
        val children = arrayOfNulls<HuffmanNode>(2)

        fun build(l: HuffmanLine, shift: Int) {
            val bit = (l.prefixCode shr shift) and 1
            if (shift <= 0) children[bit] = HuffmanNode(l)
            else {
                val node = children[bit] ?: HuffmanNode(null).also { children[bit] = it }
                node.build(l, shift - 1)
            }
        }
    }

    private class HuffmanTable private constructor(private val root: HuffmanNode) {
        /** The next value from [r]; null for OOB. */
        fun decode(r: Reader): Int? {
            var node = root
            while (node.line == null) node = node.children[r.readBit()] ?: fail("Huffman code")
            val l = node.line
            if (l.oob) return null
            val offset = r.readBits(l.rangeLength)
            val v = if (l.lower) l.rangeLow.toLong() - offset else l.rangeLow.toLong() + offset
            return v.coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()).toInt()
        }

        companion object {
            fun of(lines: List<HuffmanLine>, codesAssigned: Boolean): HuffmanTable {
                if (!codesAssigned) assign(lines)
                val root = HuffmanNode(null)
                for (l in lines) if (l.prefixLength > 0) root.build(l, l.prefixLength - 1)
                return HuffmanTable(root)
            }

            /** Canonical prefix codes from the code lengths (B.3). */
            private fun assign(lines: List<HuffmanLine>) {
                val maxLen = lines.maxOfOrNull { it.prefixLength } ?: 0
                val histogram = IntArray(maxLen + 1)
                for (l in lines) histogram[l.prefixLength]++
                histogram[0] = 0
                var firstCode = 0
                for (len in 1..maxLen) {
                    firstCode = (firstCode + histogram[len - 1]) shl 1
                    var code = firstCode
                    for (l in lines) if (l.prefixLength == len) l.prefixCode = code++
                }
            }
        }
    }

    private val standardTables = HashMap<Int, HuffmanTable>()

    /** The standard Huffman tables B.1 to B.15 (values from T.88 Annex B, as in pdf.js). */
    private fun standardTable(n: Int): HuffmanTable = standardTables.getOrPut(n) {
        val rows: Array<IntArray> = when (n) {
            1 -> arrayOf(intArrayOf(0, 1, 4, 0x0), intArrayOf(16, 2, 8, 0x2), intArrayOf(272, 3, 16, 0x6), intArrayOf(65808, 3, 32, 0x7))
            2 -> arrayOf(intArrayOf(0, 1, 0, 0x0), intArrayOf(1, 2, 0, 0x2), intArrayOf(2, 3, 0, 0x6), intArrayOf(3, 4, 3, 0xe), intArrayOf(11, 5, 6, 0x1e), intArrayOf(75, 6, 32, 0x3e), intArrayOf(6, 0x3f))
            3 -> arrayOf(intArrayOf(-256, 8, 8, 0xfe), intArrayOf(0, 1, 0, 0x0), intArrayOf(1, 2, 0, 0x2), intArrayOf(2, 3, 0, 0x6), intArrayOf(3, 4, 3, 0xe), intArrayOf(11, 5, 6, 0x1e), intArrayOf(-257, 8, 32, 0xff, 1), intArrayOf(75, 7, 32, 0x7e), intArrayOf(6, 0x3e))
            4 -> arrayOf(intArrayOf(1, 1, 0, 0x0), intArrayOf(2, 2, 0, 0x2), intArrayOf(3, 3, 0, 0x6), intArrayOf(4, 4, 3, 0xe), intArrayOf(12, 5, 6, 0x1e), intArrayOf(76, 5, 32, 0x1f))
            5 -> arrayOf(intArrayOf(-255, 7, 8, 0x7e), intArrayOf(1, 1, 0, 0x0), intArrayOf(2, 2, 0, 0x2), intArrayOf(3, 3, 0, 0x6), intArrayOf(4, 4, 3, 0xe), intArrayOf(12, 5, 6, 0x1e), intArrayOf(-256, 7, 32, 0x7f, 1), intArrayOf(76, 6, 32, 0x3e))
            6 -> arrayOf(intArrayOf(-2048, 5, 10, 0x1c), intArrayOf(-1024, 4, 9, 0x8), intArrayOf(-512, 4, 8, 0x9), intArrayOf(-256, 4, 7, 0xa), intArrayOf(-128, 5, 6, 0x1d), intArrayOf(-64, 5, 5, 0x1e), intArrayOf(-32, 4, 5, 0xb), intArrayOf(0, 2, 7, 0x0), intArrayOf(128, 3, 7, 0x2), intArrayOf(256, 3, 8, 0x3), intArrayOf(512, 4, 9, 0xc), intArrayOf(1024, 4, 10, 0xd), intArrayOf(-2049, 6, 32, 0x3e, 1), intArrayOf(2048, 6, 32, 0x3f))
            7 -> arrayOf(intArrayOf(-1024, 4, 9, 0x8), intArrayOf(-512, 3, 8, 0x0), intArrayOf(-256, 4, 7, 0x9), intArrayOf(-128, 5, 6, 0x1a), intArrayOf(-64, 5, 5, 0x1b), intArrayOf(-32, 4, 5, 0xa), intArrayOf(0, 4, 5, 0xb), intArrayOf(32, 5, 5, 0x1c), intArrayOf(64, 5, 6, 0x1d), intArrayOf(128, 4, 7, 0xc), intArrayOf(256, 3, 8, 0x1), intArrayOf(512, 3, 9, 0x2), intArrayOf(1024, 3, 10, 0x3), intArrayOf(-1025, 5, 32, 0x1e, 1), intArrayOf(2048, 5, 32, 0x1f))
            8 -> arrayOf(intArrayOf(-15, 8, 3, 0xfc), intArrayOf(-7, 9, 1, 0x1fc), intArrayOf(-5, 8, 1, 0xfd), intArrayOf(-3, 9, 0, 0x1fd), intArrayOf(-2, 7, 0, 0x7c), intArrayOf(-1, 4, 0, 0xa), intArrayOf(0, 2, 1, 0x0), intArrayOf(2, 5, 0, 0x1a), intArrayOf(3, 6, 0, 0x3a), intArrayOf(4, 3, 4, 0x4), intArrayOf(20, 6, 1, 0x3b), intArrayOf(22, 4, 4, 0xb), intArrayOf(38, 4, 5, 0xc), intArrayOf(70, 5, 6, 0x1b), intArrayOf(134, 5, 7, 0x1c), intArrayOf(262, 6, 7, 0x3c), intArrayOf(390, 7, 8, 0x7d), intArrayOf(646, 6, 10, 0x3d), intArrayOf(-16, 9, 32, 0x1fe, 1), intArrayOf(1670, 9, 32, 0x1ff), intArrayOf(2, 0x1))
            9 -> arrayOf(intArrayOf(-31, 8, 4, 0xfc), intArrayOf(-15, 9, 2, 0x1fc), intArrayOf(-11, 8, 2, 0xfd), intArrayOf(-7, 9, 1, 0x1fd), intArrayOf(-5, 7, 1, 0x7c), intArrayOf(-3, 4, 1, 0xa), intArrayOf(-1, 3, 1, 0x2), intArrayOf(1, 3, 1, 0x3), intArrayOf(3, 5, 1, 0x1a), intArrayOf(5, 6, 1, 0x3a), intArrayOf(7, 3, 5, 0x4), intArrayOf(39, 6, 2, 0x3b), intArrayOf(43, 4, 5, 0xb), intArrayOf(75, 4, 6, 0xc), intArrayOf(139, 5, 7, 0x1b), intArrayOf(267, 5, 8, 0x1c), intArrayOf(523, 6, 8, 0x3c), intArrayOf(779, 7, 9, 0x7d), intArrayOf(1291, 6, 11, 0x3d), intArrayOf(-32, 9, 32, 0x1fe, 1), intArrayOf(3339, 9, 32, 0x1ff), intArrayOf(2, 0x0))
            10 -> arrayOf(intArrayOf(-21, 7, 4, 0x7a), intArrayOf(-5, 8, 0, 0xfc), intArrayOf(-4, 7, 0, 0x7b), intArrayOf(-3, 5, 0, 0x18), intArrayOf(-2, 2, 2, 0x0), intArrayOf(2, 5, 0, 0x19), intArrayOf(3, 6, 0, 0x36), intArrayOf(4, 7, 0, 0x7c), intArrayOf(5, 8, 0, 0xfd), intArrayOf(6, 2, 6, 0x1), intArrayOf(70, 5, 5, 0x1a), intArrayOf(102, 6, 5, 0x37), intArrayOf(134, 6, 6, 0x38), intArrayOf(198, 6, 7, 0x39), intArrayOf(326, 6, 8, 0x3a), intArrayOf(582, 6, 9, 0x3b), intArrayOf(1094, 6, 10, 0x3c), intArrayOf(2118, 7, 11, 0x7d), intArrayOf(-22, 8, 32, 0xfe, 1), intArrayOf(4166, 8, 32, 0xff), intArrayOf(2, 0x2))
            11 -> arrayOf(intArrayOf(1, 1, 0, 0x0), intArrayOf(2, 2, 1, 0x2), intArrayOf(4, 4, 0, 0xc), intArrayOf(5, 4, 1, 0xd), intArrayOf(7, 5, 1, 0x1c), intArrayOf(9, 5, 2, 0x1d), intArrayOf(13, 6, 2, 0x3c), intArrayOf(17, 7, 2, 0x7a), intArrayOf(21, 7, 3, 0x7b), intArrayOf(29, 7, 4, 0x7c), intArrayOf(45, 7, 5, 0x7d), intArrayOf(77, 7, 6, 0x7e), intArrayOf(141, 7, 32, 0x7f))
            12 -> arrayOf(intArrayOf(1, 1, 0, 0x0), intArrayOf(2, 2, 0, 0x2), intArrayOf(3, 3, 1, 0x6), intArrayOf(5, 5, 0, 0x1c), intArrayOf(6, 5, 1, 0x1d), intArrayOf(8, 6, 1, 0x3c), intArrayOf(10, 7, 0, 0x7a), intArrayOf(11, 7, 1, 0x7b), intArrayOf(13, 7, 2, 0x7c), intArrayOf(17, 7, 3, 0x7d), intArrayOf(25, 7, 4, 0x7e), intArrayOf(41, 8, 5, 0xfe), intArrayOf(73, 8, 32, 0xff))
            13 -> arrayOf(intArrayOf(1, 1, 0, 0x0), intArrayOf(2, 3, 0, 0x4), intArrayOf(3, 4, 0, 0xc), intArrayOf(4, 5, 0, 0x1c), intArrayOf(5, 4, 1, 0xd), intArrayOf(7, 3, 3, 0x5), intArrayOf(15, 6, 1, 0x3a), intArrayOf(17, 6, 2, 0x3b), intArrayOf(21, 6, 3, 0x3c), intArrayOf(29, 6, 4, 0x3d), intArrayOf(45, 6, 5, 0x3e), intArrayOf(77, 7, 6, 0x7e), intArrayOf(141, 7, 32, 0x7f))
            14 -> arrayOf(intArrayOf(-2, 3, 0, 0x4), intArrayOf(-1, 3, 0, 0x5), intArrayOf(0, 1, 0, 0x0), intArrayOf(1, 3, 0, 0x6), intArrayOf(2, 3, 0, 0x7))
            15 -> arrayOf(intArrayOf(-24, 7, 4, 0x7c), intArrayOf(-8, 6, 2, 0x3c), intArrayOf(-4, 5, 1, 0x1c), intArrayOf(-2, 4, 0, 0xc), intArrayOf(-1, 3, 0, 0x4), intArrayOf(0, 1, 0, 0x0), intArrayOf(1, 3, 0, 0x5), intArrayOf(2, 4, 0, 0xd), intArrayOf(3, 5, 1, 0x1d), intArrayOf(5, 6, 2, 0x3d), intArrayOf(9, 7, 4, 0x7d), intArrayOf(-25, 7, 32, 0x7e, 1), intArrayOf(25, 7, 32, 0x7f))
            else -> fail("table B.$n")
        }
        HuffmanTable.of(
            rows.map { r -> if (r.size == 2) HuffmanLine(0, r[0], 0, r[1], oob = true) else HuffmanLine(r[0], r[1], r[2], r[3], lower = r.size > 4) },
            true,
        )
    }

    /** A table segment (7.4.13, B.2). */
    private fun tableSegment(data: ByteArray, start: Int, end: Int): HuffmanTable {
        val flags = data[start].toInt() and 0xFF
        val low = readInt32(data, start + 1)
        val high = readInt32(data, start + 5)
        val r = Reader(data, start + 9, end)
        val prefixBits = ((flags shr 1) and 7) + 1
        val rangeBits = ((flags shr 4) and 7) + 1
        val lines = ArrayList<HuffmanLine>()
        var current = low.toLong()
        do {
            val p = r.readBits(prefixBits).toInt()
            val range = r.readBits(rangeBits).toInt()
            lines.add(HuffmanLine(current.toInt(), p, range, 0))
            current += 1L shl range
        } while (current < high && lines.size < 65536)
        lines.add(HuffmanLine(low - 1, r.readBits(prefixBits).toInt(), 32, 0, lower = true))
        lines.add(HuffmanLine(high, r.readBits(prefixBits).toInt(), 32, 0))
        if (flags and 1 != 0) lines.add(HuffmanLine(0, r.readBits(prefixBits).toInt(), 0, 0, oob = true))
        return HuffmanTable.of(lines, false)
    }

    /** Reads bits MSB first between [position] and [end]. */
    private class Reader(val data: ByteArray, start: Int, val end: Int) {
        var position = start
        private var shift = -1
        private var current = 0

        fun readBit(): Int {
            if (shift < 0) {
                if (position >= end || position >= data.size) fail("end of data")
                current = data[position++].toInt() and 0xFF
                shift = 7
            }
            return (current shr shift--) and 1
        }

        fun readBits(n: Int): Long {
            var v = 0L
            for (i in 0 until n) v = (v shl 1) or readBit().toLong()
            return v
        }

        fun byteAlign() { shift = -1 }
    }

    // ---------------------------------------------------------------- segments

    private class Header(
        val number: Int,
        val type: Int,
        val referredTo: List<Int>,
        val page: Int,
        var length: Long,
        val headerEnd: Int,
        var unknownLength: Boolean = false,
    )

    private class Segment(val header: Header, val data: ByteArray, var start: Int = 0, var end: Int = 0)

    private fun u8(d: ByteArray, p: Int) = if (p in d.indices) d[p].toInt() and 0xFF else fail("segment header")
    private fun readUint16(d: ByteArray, p: Int) = (u8(d, p) shl 8) or u8(d, p + 1)
    private fun readUint32(d: ByteArray, p: Int): Long = (u8(d, p).toLong() shl 24) or (u8(d, p + 1).toLong() shl 16) or (u8(d, p + 2).toLong() shl 8) or u8(d, p + 3).toLong()
    private fun readInt32(d: ByteArray, p: Int): Int = readUint32(d, p).toInt()
    private fun readInt8(d: ByteArray, p: Int): Int = d[p].toInt()

    private fun readHeader(data: ByteArray, start: Int): Header {
        val number = readUint32(data, start)
        val flags = u8(data, start + 4)
        val type = flags and 0x3f
        val longPage = flags and 0x40 != 0
        val referredFlags = u8(data, start + 5)
        var count = (referredFlags shr 5) and 7
        var pos = start + 6
        if (count == 7) {
            count = (readUint32(data, start + 5) and 0x1fffffff).toInt()
            pos = start + 9 + (count + 8) / 8
        } else if (count == 5 || count == 6) fail("referred-to flags")
        val size = when { number <= 256 -> 1; number <= 65536 -> 2; else -> 4 }
        val referred = ArrayList<Int>(count)
        repeat(count) {
            referred.add(when (size) { 1 -> u8(data, pos); 2 -> readUint16(data, pos); else -> readInt32(data, pos) })
            pos += size
        }
        val page = if (longPage) readInt32(data, pos).also { pos += 4 } else u8(data, pos++)
        val length = readUint32(data, pos)
        pos += 4
        return Header(number.toInt(), type, referred, page, length, pos)
    }

    /** The data length of an immediate generic region of unknown length (7.2.7): up to its end marker and row count. */
    private fun unknownLength(data: ByteArray, position: Int): Long {
        val flags = u8(data, position + 17)
        val mmr = flags and 1 != 0
        val height = readUint32(data, position + 4)
        val m0 = if (mmr) 0x00 else 0xFF
        val m1 = if (mmr) 0x00 else 0xAC
        var i = position + 18
        while (i + 6 <= data.size) {
            if ((data[i].toInt() and 0xFF) == m0 && (data[i + 1].toInt() and 0xFF) == m1) {
                val rows = readUint32(data, i + 2)
                // The row count ends the data; the height in the region information may be larger (7.4.6.4).
                if (rows in 1L..minOf(height, 1L shl 24)) return (i + 6 - position).toLong()
            }
            i++
        }
        fail("segment end")
    }

    private fun readSegments(data: ByteArray, start: Int, end: Int, randomAccess: Boolean): List<Segment> {
        val out = ArrayList<Segment>()
        var pos = start
        while (pos + 11 <= end) {
            val h = readHeader(data, pos)
            pos = h.headerEnd
            if (h.length == 0xffffffffL) {
                if (h.type == 38 && !randomAccess) { h.length = unknownLength(data, pos); h.unknownLength = true } else fail("segment length")
            }
            val s = Segment(h, data)
            if (!randomAccess) {
                s.start = pos
                pos = (pos + h.length).coerceAtMost(end.toLong()).toInt()
                s.end = pos
            }
            out.add(s)
            if (h.type == 51) break
        }
        if (randomAccess) for (s in out) {
            s.start = pos
            pos = (pos + s.header.length).coerceAtMost(end.toLong()).toInt()
            s.end = pos
        }
        return out
    }

    private class RegionInfo(val width: Int, val height: Int, val x: Int, val y: Int, val op: Int)

    private fun regionInfo(d: ByteArray, p: Int): RegionInfo {
        val h = readUint32(d, p + 4)
        return RegionInfo(readInt32(d, p), if (h == 0xffffffffL) -1 else h.toInt(), readInt32(d, p + 8), readInt32(d, p + 12), u8(d, p + 16) and 7)
    }

    private fun atPixels(d: ByteArray, p: Int, count: Int): List<Pt> = (0 until count).map { Pt(readInt8(d, p + it * 2), readInt8(d, p + it * 2 + 1)) }

    private const val MAX_PIXELS = 1L shl 28

    /** Applies the segments of the first page in order. */
    private class Visitor {
        var done = false
        private var pageNumber = -1
        private var page: Bits? = null
        private var pageDefault = 0
        private var pageUnknownHeight = false
        private var stripeEnd = -1
        private val symbols = HashMap<Int, List<Bits>>()
        private val retained = HashMap<Int, Map<String, ByteArray>>()
        private val patterns = HashMap<Int, List<Bits>>()
        private val tables = HashMap<Int, HuffmanTable>()
        private val intermediate = HashMap<Int, Pair<RegionInfo, Bits>>()

        fun result(): Jbig2Bitmap? {
            val p = page ?: return null
            val h = if (pageUnknownHeight && stripeEnd >= 0) minOf(p.height, stripeEnd + 1) else p.height
            return Jbig2Bitmap(p.width, h, p.data.copyOf(p.width * h))
        }

        private fun check(w: Int, h: Int) {
            if (w < 0 || h < 0 || w.toLong() * h > MAX_PIXELS) Jbig2.fail("size ${w}x$h")
        }

        /** Grows a page of unknown height so rows up to [bottom] exist. */
        private fun ensureHeight(bottom: Int) {
            val p = page ?: return
            if (!pageUnknownHeight || bottom <= p.height) return
            val h = maxOf(bottom, p.height * 2).coerceAtMost((MAX_PIXELS / maxOf(1, p.width)).toInt())
            val grown = Bits(p.width, h)
            grown.fill(pageDefault)
            p.data.copyInto(grown.data)
            page = grown
        }

        private fun draw(info: RegionInfo, bitmap: Bits) {
            ensureHeight(info.y + bitmap.height)
            val p = page ?: return
            compose(p, bitmap, info.x, info.y, info.op)
        }

        private fun custom(index: Int, referred: List<Int>): HuffmanTable {
            var i = 0
            for (r in referred) {
                val t = tables[r] ?: continue
                if (i == index) return t
                i++
            }
            Jbig2.fail("custom table")
        }

        fun process(s: Segment) {
            val h = s.header
            if (h.page != 0) {
                if (pageNumber < 0 && h.type == 48) pageNumber = h.page
                if (h.page != pageNumber) return
            }
            val d = s.data
            var p = s.start
            val end = s.end
            when (h.type) {
                0 -> symbolDictionary(h, d, p, end)
                4, 6, 7 -> {
                    val info = regionInfo(d, p); p += 17
                    check(info.width, info.height)
                    val flags = readUint16(d, p); p += 2
                    val huffman = flags and 1 != 0
                    val refinement = flags and 2 != 0
                    val logStrip = (flags shr 2) and 3
                    val corner = (flags shr 4) and 3
                    val transposed = flags and 64 != 0
                    val op = (flags shr 7) and 3
                    val defaultPixel = (flags shr 9) and 1
                    val dsOffset = (flags shl 17) shr 27
                    val refTemplate = (flags shr 15) and 1
                    var hFlags = 0
                    if (huffman) { hFlags = readUint16(d, p); p += 2 }
                    var refAt: List<Pt>? = null
                    if (refinement && refTemplate == 0) { refAt = atPixels(d, p, 2); p += 4 }
                    val instances = readUint32(d, p).toInt(); p += 4
                    val input = h.referredTo.flatMap { symbols[it].orEmpty() }
                    val codeLength = log2(input.size)
                    var reader: Reader? = null
                    var t: TextTables? = null
                    if (huffman) {
                        reader = Reader(d, p, end)
                        t = textTables(hFlags, refinement, h.referredTo, input.size, reader)
                    }
                    val ctx = DecodingContext(d, p, end)
                    val bitmap = decodeTextRegion(
                        huffman, refinement, info.width, info.height, defaultPixel, instances, 1 shl logStrip, logStrip, input,
                        codeLength, transposed, dsOffset, corner, op, t, refTemplate, refAt, ctx, reader,
                    )
                    if (h.type == 4) intermediate[h.number] = info to bitmap else draw(info, bitmap)
                }
                16 -> {
                    val flags = u8(d, p++)
                    val mmr = flags and 1 != 0
                    val template = (flags shr 1) and 3
                    val pw = u8(d, p++)
                    val ph = u8(d, p++)
                    val maxIndex = readUint32(d, p).toInt(); p += 4
                    check((maxIndex + 1) * pw, ph)
                    patterns[h.number] = decodePatternDictionary(mmr, pw, ph, maxIndex, template, DecodingContext(d, p, end))
                }
                20, 22, 23 -> {
                    val info = regionInfo(d, p); p += 17
                    check(info.width, info.height)
                    val flags = u8(d, p++)
                    val gw = readUint32(d, p).toInt(); p += 4
                    val gh = readUint32(d, p).toInt(); p += 4
                    check(gw, gh)
                    val gx = readInt32(d, p); p += 4
                    val gy = readInt32(d, p); p += 4
                    val vx = readUint16(d, p); p += 2
                    val vy = readUint16(d, p); p += 2
                    val pats = h.referredTo.firstNotNullOfOrNull { patterns[it] } ?: Jbig2.fail("patterns")
                    val bitmap = decodeHalftoneRegion(
                        flags and 1 != 0, pats, (flags shr 1) and 3, info.width, info.height, (flags shr 7) and 1,
                        flags and 8 != 0, (flags shr 4) and 7, gw, gh, gx, gy, vx, vy, DecodingContext(d, p, end),
                    )
                    if (h.type == 20) intermediate[h.number] = info to bitmap else draw(info, bitmap)
                }
                36, 38, 39 -> {
                    val info = regionInfo(d, p); p += 17
                    val flags = u8(d, p++)
                    val mmr = flags and 1 != 0
                    val template = (flags shr 1) and 3
                    val prediction = flags and 8 != 0
                    var at = emptyList<Pt>()
                    if (!mmr) { val n = if (template == 0) 4 else 1; at = atPixels(d, p, n); p += n * 2 }
                    var height = info.height
                    var dataEnd = end
                    if (height < 0 || h.unknownLength) {
                        // Height given after the data, with the end marker (7.4.6.4).
                        if (end - p < 6 || !isEndMarker(d, end - 6, mmr)) Jbig2.fail("region height")
                        height = readUint32(d, end - 4).toInt()
                        dataEnd = end - 6
                    }
                    check(info.width, height)
                    val bitmap = decodeBitmap(mmr, info.width, height, template, prediction, null, at, DecodingContext(d, p, dataEnd))
                    val region = RegionInfo(info.width, height, info.x, info.y, info.op)
                    if (h.type == 36) intermediate[h.number] = region to bitmap else draw(region, bitmap)
                }
                40, 42, 43 -> {
                    val info = regionInfo(d, p); p += 17
                    check(info.width, info.height)
                    val flags = u8(d, p++)
                    val template = flags and 1
                    val prediction = flags and 2 != 0
                    var at: List<Pt>? = null
                    if (template == 0) { at = atPixels(d, p, 2); p += 4 }
                    val referred = h.referredTo.firstNotNullOfOrNull { intermediate[it] }
                    val reference = referred?.second ?: run {
                        ensureHeight(info.y + info.height)
                        (page ?: Jbig2.fail("page")).crop(info.x, info.y, info.width, info.height)
                    }
                    val bitmap = decodeRefinement(info.width, info.height, template, reference, 0, 0, prediction, at, DecodingContext(d, p, end))
                    if (h.type == 40) intermediate[h.number] = info to bitmap else draw(info, bitmap)
                }
                48 -> {
                    val w = readUint32(d, p).toInt()
                    val hh = readUint32(d, p + 4)
                    val flags = u8(d, p + 16)
                    val striping = readUint16(d, p + 17)
                    pageDefault = (flags shr 2) and 1
                    pageUnknownHeight = hh == 0xffffffffL
                    val height = if (pageUnknownHeight) maxOf(1, striping and 0x7fff) else hh.toInt()
                    check(w, height)
                    page = Bits(w, height).also { it.fill(pageDefault) }
                }
                49 -> done = true
                50 -> {
                    stripeEnd = readInt32(d, p)
                    ensureHeight(stripeEnd + 1)
                }
                51 -> done = true
                53 -> tables[h.number] = tableSegment(d, p, end)
                else -> {}
            }
        }

        private fun isEndMarker(d: ByteArray, i: Int, mmr: Boolean): Boolean {
            if (i < 0 || i + 1 >= d.size) return false
            val a = d[i].toInt() and 0xFF
            val b = d[i + 1].toInt() and 0xFF
            return if (mmr) a == 0 && b == 0 else a == 0xFF && b == 0xAC
        }

        private fun symbolDictionary(h: Header, d: ByteArray, start: Int, end: Int) {
            var p = start
            val flags = readUint16(d, p); p += 2
            val huffman = flags and 1 != 0
            val refinement = flags and 2 != 0
            val dhSel = (flags shr 2) and 3
            val dwSel = (flags shr 4) and 3
            val sizeSel = (flags shr 6) and 1
            val aggSel = (flags shr 7) and 1
            val contextUsed = flags and 256 != 0
            val contextRetained = flags and 512 != 0
            val template = (flags shr 10) and 3
            val refTemplate = (flags shr 12) and 1
            var at = emptyList<Pt>()
            if (!huffman) { val n = if (template == 0) 4 else 1; at = atPixels(d, p, n); p += n * 2 }
            var refAt: List<Pt>? = null
            if (refinement && refTemplate == 0) { refAt = atPixels(d, p, 2); p += 4 }
            p += 4 // number of exported symbols, implied by the export flags
            val newCount = readUint32(d, p).toInt(); p += 4
            if (newCount < 0 || newCount > 1 shl 20) Jbig2.fail("symbols")
            val input = h.referredTo.flatMap { symbols[it].orEmpty() }
            var dt: DictionaryTables? = null
            var reader: Reader? = null
            if (huffman) {
                var ci = 0
                val dh = when (dhSel) { 0, 1 -> standardTable(dhSel + 4); 3 -> custom(ci++, h.referredTo); else -> Jbig2.fail("DH") }
                val dw = when (dwSel) { 0, 1 -> standardTable(dwSel + 2); 3 -> custom(ci++, h.referredTo); else -> Jbig2.fail("DW") }
                val bs = if (sizeSel == 1) custom(ci++, h.referredTo) else standardTable(1)
                val ag = if (aggSel == 1) custom(ci, h.referredTo) else standardTable(1)
                dt = DictionaryTables(dh, dw, bs, ag)
                reader = Reader(d, p, end)
            }
            val cache = ContextCache()
            if (contextUsed) {
                h.referredTo.lastOrNull { it in retained }?.let { r -> retained[r]?.forEach { (k, v) -> cache.map[k] = v.copyOf() } }
            }
            val ctx = DecodingContext(d, p, end, cache)
            symbols[h.number] = decodeSymbolDictionary(huffman, refinement, input, newCount, dt, template, at, refTemplate, refAt, ctx, reader)
            if (contextRetained) retained[h.number] = cache.bitmapContexts()
        }

        private fun textTables(hFlags: Int, refinement: Boolean, referred: List<Int>, symbolCount: Int, r: Reader): TextTables {
            // Symbol ID codes: run code lengths, then the code length of every symbol (7.4.3.1.7).
            val runCodes = (0..34).map { HuffmanLine(it, r.readBits(4).toInt(), 0, 0) }
            val runTable = HuffmanTable.of(runCodes, false)
            val lengths = ArrayList<HuffmanLine>()
            var i = 0
            while (i < symbolCount) {
                val code = runTable.decode(r) ?: Jbig2.fail("symbol code")
                when {
                    code < 32 -> { lengths.add(HuffmanLine(i, code, 0, 0)); i++ }
                    else -> {
                        val (repeats, len) = when (code) {
                            32 -> (r.readBits(2).toInt() + 3) to (lengths.lastOrNull()?.prefixLength ?: Jbig2.fail("symbol code"))
                            33 -> (r.readBits(3).toInt() + 3) to 0
                            else -> (r.readBits(7).toInt() + 11) to 0
                        }
                        repeat(repeats) { if (i < symbolCount) { lengths.add(HuffmanLine(i, len, 0, 0)); i++ } }
                    }
                }
            }
            r.byteAlign()
            val idTable = HuffmanTable.of(lengths, false)
            var ci = 0
            fun sel(v: Int, standard: (Int) -> HuffmanTable?): HuffmanTable =
                if (v == 3) custom(ci++, referred) else standard(v) ?: Jbig2.fail("table selector")
            val fs = sel(hFlags and 3) { if (it <= 1) standardTable(it + 6) else null }
            val ds = sel((hFlags shr 2) and 3) { if (it <= 2) standardTable(it + 8) else null }
            val dtT = sel((hFlags shr 4) and 3) { if (it <= 2) standardTable(it + 11) else null }
            if (!refinement) return TextTables(idTable, fs, ds, dtT, null, null, null, null, null)
            val rdw = sel((hFlags shr 6) and 3) { if (it <= 1) standardTable(it + 14) else null }
            val rdh = sel((hFlags shr 8) and 3) { if (it <= 1) standardTable(it + 14) else null }
            val rdx = sel((hFlags shr 10) and 3) { if (it <= 1) standardTable(it + 14) else null }
            val rdy = sel((hFlags shr 12) and 3) { if (it <= 1) standardTable(it + 14) else null }
            val rsize = if (hFlags and 0x4000 != 0) custom(ci, referred) else standardTable(1)
            return TextTables(idTable, fs, ds, dtT, rdw, rdh, rdx, rdy, rsize)
        }
    }
}
