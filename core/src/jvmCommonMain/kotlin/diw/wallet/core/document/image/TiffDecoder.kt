package diw.wallet.core.document.image

import java.io.ByteArrayOutputStream
import java.util.zip.Inflater

/** Decoded pixels: 8 bits per channel, [channels] 1 (gray), 3 (RGB) or 4 (RGBA), rows top to bottom. */
class RasterImage(val width: Int, val height: Int, val channels: Int, val pixels: ByteArray)

class ImageDecodeException(message: String) : Exception(message)

/**
 * A pure Kotlin TIFF reader (TIFF 6.0) for platforms whose image decoder has none, such as Android: page images of
 * official documents (CCITT Group 4 bilevel scans), and the usual strip or tile layouts with no, PackBits, LZW,
 * Deflate or CCITT compression. Bilevel, gray, palette, RGB and CMYK pages with 1 to 16 bits per sample are read;
 * JPEG compressed pages are not.
 */
object TiffDecoder {
    fun isTiff(b: ByteArray): Boolean = b.size > 8 &&
        ((b[0] == 'I'.code.toByte() && b[1] == 'I'.code.toByte() && b[2] == 42.toByte() && b[3] == 0.toByte()) ||
            (b[0] == 'M'.code.toByte() && b[1] == 'M'.code.toByte() && b[2] == 0.toByte() && b[3] == 42.toByte()))

    /** One image file directory: the tags of a page. */
    class Directory internal constructor(private val tags: Map<Int, LongArray>) {
        fun value(tag: Int, default: Long = 0): Long = tags[tag]?.firstOrNull() ?: default
        fun values(tag: Int): LongArray? = tags[tag]
        val width get() = value(256).toInt()
        val height get() = value(257).toInt()
        val compression get() = value(259, 1).toInt()
        val photometric get() = value(262, 1).toInt()

        /** A short description: size, compression and colour model. */
        fun describe(): String {
            val c = when (compression) {
                1 -> "未壓縮"; 2 -> "CCITT RLE"; 3 -> "CCITT Group 3"; 4 -> "CCITT Group 4"; 5 -> "LZW"
                6, 7 -> "JPEG"; 8, 32946 -> "Deflate"; 32773 -> "PackBits"; else -> "壓縮方式 $compression"
            }
            val bits = values(258)?.firstOrNull() ?: 1
            val kind = when (photometric) {
                0, 1 -> if (bits == 1L) "黑白" else "灰階"
                2 -> "彩色（RGB）"; 3 -> "調色盤"; 5 -> "彩色（CMYK）"; 6 -> "彩色（YCbCr）"; else -> "色彩模式 $photometric"
            }
            return "${width} x ${height}，$kind，$c"
        }
    }

    private class Reader(val b: ByteArray) {
        val little = b[0] == 'I'.code.toByte()
        fun u8(p: Int) = b[p].toInt() and 0xFF
        fun u16(p: Int) = if (little) u8(p) or (u8(p + 1) shl 8) else (u8(p) shl 8) or u8(p + 1)
        fun u32(p: Int): Long = if (little) (u16(p).toLong() or (u16(p + 2).toLong() shl 16)) else ((u16(p).toLong() shl 16) or u16(p + 2).toLong())
    }

    /** The directories of every page, in file order. */
    fun directories(b: ByteArray): List<Directory> {
        if (!isTiff(b)) throw ImageDecodeException("不是 TIFF 檔案")
        val r = Reader(b)
        val out = ArrayList<Directory>()
        var offset = r.u32(4)
        val seen = HashSet<Long>()
        while (offset in 8 until b.size - 2 && seen.add(offset) && out.size < 1000) {
            val at = offset.toInt()
            val n = r.u16(at)
            if (at + 2 + n * 12 + 4 > b.size) break
            val tags = HashMap<Int, LongArray>()
            for (i in 0 until n) {
                val e = at + 2 + i * 12
                val tag = r.u16(e)
                val type = r.u16(e + 2)
                val count = r.u32(e + 4)
                val size = when (type) { 1, 2, 6, 7 -> 1; 3, 8 -> 2; 4, 9, 13 -> 4; 5, 10, 12 -> 8; else -> 0 }
                if (size == 0 || count <= 0 || count > 1_000_000) continue
                val total = size * count
                val start = if (total <= 4) e + 8 else r.u32(e + 8).toInt()
                if (start < 0 || start + total > b.size) continue
                tags[tag] = LongArray(count.toInt()) { k ->
                    val p = start + k * size
                    when (type) {
                        1, 6, 7, 2 -> r.u8(p).toLong()
                        3, 8 -> r.u16(p).toLong()
                        5, 10 -> r.u32(p) / maxOf(1L, r.u32(p + 4))
                        else -> r.u32(p)
                    }
                }
            }
            out.add(Directory(tags))
            offset = r.u32(at + 2 + n * 12)
        }
        if (out.isEmpty()) throw ImageDecodeException("TIFF 沒有影像")
        return out
    }

    fun pageCount(b: ByteArray): Int = runCatching { directories(b).size }.getOrDefault(0)

    /** Page [page] of the TIFF in [b]. */
    fun decode(b: ByteArray, page: Int = 0): RasterImage {
        val d = directories(b).getOrNull(page) ?: throw ImageDecodeException("TIFF 沒有第 ${page + 1} 頁")
        val width = d.width
        val height = d.height
        if (width <= 0 || height <= 0 || width.toLong() * height > 100_000_000L) throw ImageDecodeException("TIFF 尺寸不合理（$width x $height）")
        if (d.value(284, 1) != 1L && d.value(277, 1) > 1) throw ImageDecodeException("不支援分平面（planar）的 TIFF")
        val compression = d.compression
        if (compression == 6 || compression == 7) throw ImageDecodeException("不支援 JPEG 壓縮的 TIFF")
        val spp = d.value(277, 1).toInt().coerceIn(1, 8)
        val bps = (d.values(258)?.firstOrNull() ?: 1L).toInt()
        if (bps !in setOf(1, 2, 4, 8, 16)) throw ImageDecodeException("不支援每個樣本 $bps 位元的 TIFF")
        val fillReversed = d.value(266, 1) == 2L
        val little = b[0] == 'I'.code.toByte()
        val photometric = d.photometric
        val tiled = d.values(324) != null || d.values(322) != null
        val blockW = if (tiled) d.value(322).toInt() else width
        val blockH = if (tiled) d.value(323).toInt() else d.value(278, height.toLong()).toInt().coerceIn(1, height)
        val offsets = (if (tiled) d.values(324) else d.values(273)) ?: throw ImageDecodeException("TIFF 沒有影像資料位置")
        val counts = (if (tiled) d.values(325) else d.values(279)) ?: LongArray(offsets.size) { (b.size - offsets[it]).coerceAtLeast(0) }
        if (blockW <= 0 || blockH <= 0) throw ImageDecodeException("TIFF 區塊尺寸不正確")
        val across = (width + blockW - 1) / blockW
        val rowBytes = (blockW * spp * bps + 7) / 8
        // Samples of the whole page, unpacked to one int per sample.
        val samples = IntArray(width * height * spp)
        for ((i, off) in offsets.withIndex()) {
            val x0 = if (tiled) (i % across) * blockW else 0
            val y0 = if (tiled) (i / across) * blockH else i * blockH
            if (y0 >= height || x0 >= width) continue
            val rows = minOf(blockH, if (tiled) blockH else height - y0)
            val start = off.toInt()
            val len = counts.getOrElse(i) { 0L }.toInt()
            if (start < 0 || len < 0 || start + len > b.size) throw ImageDecodeException("TIFF 影像資料超出檔案範圍")
            var raw = b.copyOfRange(start, start + len)
            if (fillReversed) raw = ByteArray(raw.size) { reverse(raw[it]) }
            val data = when (compression) {
                1 -> raw
                2, 3, 4 -> Ccitt(raw, blockW, rows, compression, d.value(292), d.value(293)).decode()
                5 -> lzw(raw, rowBytes * rows)
                8, 32946 -> inflate(raw, rowBytes * rows)
                32773 -> packBits(raw, rowBytes * rows)
                else -> throw ImageDecodeException("不支援這種 TIFF 壓縮方式（$compression）")
            }
            if (d.value(317, 1) == 2L && bps == 8) undoPredictor(data, rowBytes, rows, spp)
            for (y in 0 until rows) {
                val py = y0 + y
                if (py >= height) break
                for (x in 0 until blockW) {
                    val px = x0 + x
                    if (px >= width) break
                    for (s in 0 until spp) {
                        samples[(py * width + px) * spp + s] = sample(data, y * rowBytes, x * spp + s, bps, little)
                    }
                }
            }
        }
        return toRaster(d, width, height, spp, bps, samples, photometric)
    }

    private fun reverse(v: Byte): Byte {
        var x = v.toInt() and 0xFF
        var r = 0
        repeat(8) { r = (r shl 1) or (x and 1); x = x shr 1 }
        return r.toByte()
    }

    /** Sample [index] of a row at [rowStart], scaled to 0..255. */
    private fun sample(data: ByteArray, rowStart: Int, index: Int, bps: Int, little: Boolean): Int {
        val bit = index.toLong() * bps
        val p = rowStart + (bit / 8).toInt()
        if (p >= data.size) return 0
        return when (bps) {
            8 -> data[p].toInt() and 0xFF
            16 -> data[if (little) minOf(p + 1, data.size - 1) else p].toInt() and 0xFF
            else -> {
                val shift = 8 - bps - (bit % 8).toInt()
                val v = ((data[p].toInt() and 0xFF) shr shift) and ((1 shl bps) - 1)
                v * 255 / ((1 shl bps) - 1)
            }
        }
    }

    private fun toRaster(d: Directory, width: Int, height: Int, spp: Int, bps: Int, s: IntArray, photometric: Int): RasterImage {
        val n = width * height
        return when (photometric) {
            0, 1 -> {
                // CCITT decodes black runs to 1 bits, as an uncompressed WhiteIsZero page stores them.
                val invert = photometric == 0
                val alpha = spp >= 2 && d.values(338) != null
                val out = ByteArray(n * if (alpha) 2 else 1)
                if (alpha) {
                    val rgba = ByteArray(n * 4)
                    for (i in 0 until n) {
                        val g = (if (invert) 255 - s[i * spp] else s[i * spp]).toByte()
                        rgba[i * 4] = g; rgba[i * 4 + 1] = g; rgba[i * 4 + 2] = g; rgba[i * 4 + 3] = s[i * spp + 1].toByte()
                    }
                    return RasterImage(width, height, 4, rgba)
                }
                for (i in 0 until n) out[i] = (if (invert) 255 - s[i * spp] else s[i * spp]).toByte()
                RasterImage(width, height, 1, out)
            }
            2 -> {
                val alpha = spp >= 4
                val ch = if (alpha) 4 else 3
                val out = ByteArray(n * ch)
                for (i in 0 until n) for (c in 0 until ch) out[i * ch + c] = s[i * spp + minOf(c, spp - 1)].toByte()
                RasterImage(width, height, ch, out)
            }
            3 -> {
                val map = d.values(320) ?: throw ImageDecodeException("調色盤 TIFF 沒有色彩表")
                val size = 1 shl bps
                if (map.size < size * 3) throw ImageDecodeException("TIFF 色彩表不完整")
                val out = ByteArray(n * 3)
                for (i in 0 until n) {
                    // The sample was scaled to 0..255; the palette index is the raw value.
                    val idx = if (bps == 8 || bps == 16) s[i * spp] else Math.round(s[i * spp] * (size - 1) / 255f)
                    for (c in 0 until 3) out[i * 3 + c] = (map[c * size + idx.coerceIn(0, size - 1)] shr 8).toByte()
                }
                RasterImage(width, height, 3, out)
            }
            5 -> {
                if (spp < 4) throw ImageDecodeException("CMYK TIFF 的樣本數不足")
                val out = ByteArray(n * 3)
                for (i in 0 until n) {
                    val k = s[i * spp + 3]
                    for (c in 0 until 3) out[i * 3 + c] = ((255 - s[i * spp + c]) * (255 - k) / 255).toByte()
                }
                RasterImage(width, height, 3, out)
            }
            else -> throw ImageDecodeException("不支援這種 TIFF 色彩模式（$photometric）")
        }
    }

    private fun undoPredictor(data: ByteArray, rowBytes: Int, rows: Int, spp: Int) {
        for (y in 0 until rows) {
            val base = y * rowBytes
            for (x in spp until rowBytes) {
                val p = base + x
                if (p >= data.size) return
                data[p] = (data[p] + data[p - spp]).toByte()
            }
        }
    }

    private fun inflate(raw: ByteArray, expected: Int): ByteArray {
        val inf = Inflater()
        inf.setInput(raw)
        val out = ByteArrayOutputStream(expected.coerceAtLeast(16))
        val buf = ByteArray(64 * 1024)
        try {
            while (!inf.finished()) {
                val n = inf.inflate(buf)
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break
                out.write(buf, 0, n)
                if (out.size() > expected + 1024 * 1024) break
            }
        } finally {
            inf.end()
        }
        return out.toByteArray()
    }

    private fun packBits(raw: ByteArray, expected: Int): ByteArray {
        val out = ByteArrayOutputStream(expected.coerceAtLeast(16))
        var i = 0
        while (i < raw.size && out.size() < expected) {
            val n = raw[i++].toInt()
            when {
                n >= 0 -> { val end = minOf(raw.size, i + n + 1); out.write(raw, i, end - i); i = end }
                n != -128 -> { if (i < raw.size) { val v = raw[i++].toInt(); repeat(1 - n) { out.write(v) } } }
            }
        }
        return out.toByteArray()
    }

    /** TIFF LZW: codes MSB first from 9 bits, Clear 256, EOI 257, widths grow one code early. */
    private fun lzw(raw: ByteArray, expected: Int): ByteArray {
        val out = ByteArrayOutputStream(expected.coerceAtLeast(16))
        val prefix = IntArray(4096)
        val suffix = ByteArray(4096)
        val length = IntArray(4096)
        for (i in 0 until 256) { suffix[i] = i.toByte(); length[i] = 1; prefix[i] = -1 }
        var next = 258
        var width = 9
        var bitPos = 0L
        val totalBits = raw.size.toLong() * 8
        var old = -1
        val stack = ByteArray(4096)
        fun read(): Int {
            if (bitPos + width > totalBits) return 257
            var v = 0
            for (k in 0 until width) {
                val p = bitPos + k
                v = (v shl 1) or ((raw[(p / 8).toInt()].toInt() shr (7 - (p % 8).toInt())) and 1)
            }
            bitPos += width
            return v
        }
        fun emit(code: Int): Byte {
            var c = code
            var n = 0
            while (c >= 0 && n < 4096) { stack[n++] = suffix[c]; c = prefix[c] }
            for (k in n - 1 downTo 0) out.write(stack[k].toInt())
            return stack[n - 1]
        }
        while (true) {
            val code = read()
            if (code == 257) break
            if (code == 256) {
                next = 258; width = 9; old = -1
                continue
            }
            if (old == -1) {
                if (code > 255) break
                emit(code); old = code
            } else {
                val first: Byte = if (code < next) {
                    emit(code)
                } else {
                    // KwKwK: the code being defined is the previous string plus its own first byte.
                    val f = emit(old)
                    out.write(f.toInt())
                    f
                }
                if (next < 4096) {
                    prefix[next] = old
                    suffix[next] = if (code < next) firstByte(code, prefix, suffix) else first
                    length[next] = length[old] + 1
                    next++
                }
                old = code
            }
            width = when { next + 1 >= 2048 -> 12; next + 1 >= 1024 -> 11; next + 1 >= 512 -> 10; else -> 9 }
            if (out.size() >= expected) break
        }
        return out.toByteArray()
    }

    private fun firstByte(code: Int, prefix: IntArray, suffix: ByteArray): Byte {
        var c = code
        var guard = 0
        while (prefix[c] >= 0 && guard++ < 4096) c = prefix[c]
        return suffix[c]
    }
}

/**
 * CCITT bilevel decoding for TIFF: modified Huffman (compression 2), Group 3 one or two dimensional (3) and Group 4
 * (4), ITU-T T.4 and T.6. The result is one byte row per [rows], 1 bit per pixel, MSB first, 1 meaning black.
 */
internal class Ccitt(
    private val data: ByteArray,
    private val width: Int,
    private val rows: Int,
    private val compression: Int,
    t4Options: Long,
    @Suppress("unused") t6Options: Long,
) {
    private val twoD3 = t4Options and 1L != 0L
    private var pos = 0L
    private val total = data.size.toLong() * 8

    private fun bit(): Int {
        if (pos >= total) throw ImageDecodeException("CCITT 資料提早結束")
        val v = (data[(pos / 8).toInt()].toInt() shr (7 - (pos % 8).toInt())) and 1
        pos++
        return v
    }

    private fun peek(n: Int): Int {
        var v = 0
        for (k in 0 until n) {
            val p = pos + k
            v = (v shl 1) or (if (p < total) (data[(p / 8).toInt()].toInt() shr (7 - (p % 8).toInt())) and 1 else 0)
        }
        return v
    }

    fun decode(): ByteArray {
        val rowBytes = (width + 7) / 8
        val out = ByteArray(rowBytes * rows)
        var ref = intArrayOf(width, width)
        for (y in 0 until rows) {
            if (pos >= total) break
            val changes = when (compression) {
                2 -> { alignByte(); oneD() }
                3 -> {
                    skipEol()
                    if (twoD3) { if (bit() == 1) oneD() else twoD(ref) } else oneD()
                }
                else -> {
                    if (peek(24) == 0x001001) break
                    twoD(ref)
                }
            }
            fill(out, y * rowBytes, changes)
            ref = changes + intArrayOf(width, width)
        }
        return out
    }

    private fun alignByte() { if (pos % 8 != 0L) pos += 8 - pos % 8 }

    /** An EOL (eleven or more zeros, then a one) before a Group 3 row, with any fill bits. */
    private fun skipEol() {
        var p = pos
        while (p < total && bitAt(p) == 0 && p - pos < 4096) p++
        if (p - pos >= 11 && p < total) pos = p + 1
    }

    private fun bitAt(p: Long) = (data[(p / 8).toInt()].toInt() shr (7 - (p % 8).toInt())) and 1

    private fun fill(out: ByteArray, start: Int, changes: IntArray) {
        var black = false
        var x = 0
        for (c in changes + width) {
            val end = c.coerceIn(0, width)
            if (black) for (p in x until end) out[start + p / 8] = (out[start + p / 8].toInt() or (0x80 shr (p % 8))).toByte()
            x = maxOf(x, end)
            black = !black
            if (x >= width) break
        }
    }

    private fun oneD(): IntArray {
        val changes = ArrayList<Int>()
        var a0 = 0
        var white = true
        while (a0 < width) {
            val run = run(white)
            a0 += run
            changes.add(minOf(a0, width))
            white = !white
        }
        return changes.toIntArray()
    }

    private fun twoD(ref: IntArray): IntArray {
        val cur = ArrayList<Int>()
        var a0 = -1
        var white = true
        while (a0 < width) {
            // b1: the first changing element of the reference line right of a0 that changes to the opposite colour.
            var i = 0
            while (i < ref.size && (ref[i] <= a0 || (i % 2 == 0) != white)) i++
            val b1 = if (i < ref.size) ref[i] else width
            val b2 = if (i + 1 < ref.size) ref[i + 1] else width
            when (mode()) {
                Mode.PASS -> a0 = b2
                Mode.HORIZONTAL -> {
                    val start = maxOf(a0, 0)
                    val r1 = run(white)
                    val r2 = run(!white)
                    val a1 = minOf(start + r1, width)
                    val a2 = minOf(a1 + r2, width)
                    cur.add(a1); cur.add(a2)
                    a0 = a2
                }
                Mode.V0 -> { a0 = vertical(cur, b1, 0); white = !white }
                Mode.VR1 -> { a0 = vertical(cur, b1, 1); white = !white }
                Mode.VR2 -> { a0 = vertical(cur, b1, 2); white = !white }
                Mode.VR3 -> { a0 = vertical(cur, b1, 3); white = !white }
                Mode.VL1 -> { a0 = vertical(cur, b1, -1); white = !white }
                Mode.VL2 -> { a0 = vertical(cur, b1, -2); white = !white }
                Mode.VL3 -> { a0 = vertical(cur, b1, -3); white = !white }
            }
        }
        return cur.toIntArray()
    }

    private fun vertical(cur: MutableList<Int>, b1: Int, d: Int): Int {
        val a1 = (b1 + d).coerceIn(0, width)
        cur.add(a1)
        return a1
    }

    private enum class Mode { PASS, HORIZONTAL, V0, VR1, VR2, VR3, VL1, VL2, VL3 }

    private fun mode(): Mode {
        if (bit() == 1) return Mode.V0
        // 0 1 x
        if (bit() == 1) return if (bit() == 1) Mode.VR1 else Mode.VL1
        // 0 0 1: horizontal
        if (bit() == 1) return Mode.HORIZONTAL
        // 0 0 0 1: pass
        if (bit() == 1) return Mode.PASS
        // 0 0 0 0 1 x
        if (bit() == 1) return if (bit() == 1) Mode.VR2 else Mode.VL2
        // 0 0 0 0 0 1 x
        if (bit() == 1) return if (bit() == 1) Mode.VR3 else Mode.VL3
        throw ImageDecodeException("CCITT 二維編碼不正確（位置 ${pos / 8}）")
    }

    /** One run of [white] or black pixels: makeup codes, then the terminating code. */
    private fun run(white: Boolean): Int {
        var total = 0
        while (true) {
            val v = code(if (white) WHITE else BLACK)
            total += v
            if (v < 64) return total
        }
    }

    private fun code(table: Map<Int, Int>): Int {
        var v = 0
        for (len in 1..13) {
            v = (v shl 1) or bit()
            table[(len shl 16) or v]?.let { return it }
        }
        throw ImageDecodeException("CCITT 長度碼不正確（位置 ${pos / 8}）")
    }

    companion object {
        private fun table(codes: String): Map<Int, Int> = codes.trim().split(Regex("\\s+")).chunked(2).associate { (n, c) ->
            ((c.length shl 16) or c.toInt(2)) to n.toInt()
        }

        private const val EXTENDED = """
            1792 00000001000 1856 00000001100 1920 00000001101 1984 000000010010 2048 000000010011 2112 000000010100
            2176 000000010101 2240 000000010110 2304 000000010111 2368 000000011100 2432 000000011101 2496 000000011110
            2560 000000011111
        """

        private val WHITE = table(
            """
            0 00110101 1 000111 2 0111 3 1000 4 1011 5 1100 6 1110 7 1111 8 10011 9 10100 10 00111 11 01000 12 001000
            13 000011 14 110100 15 110101 16 101010 17 101011 18 0100111 19 0001100 20 0001000 21 0010111 22 0000011
            23 0000100 24 0101000 25 0101011 26 0010011 27 0100100 28 0011000 29 00000010 30 00000011 31 00011010
            32 00011011 33 00010010 34 00010011 35 00010100 36 00010101 37 00010110 38 00010111 39 00101000 40 00101001
            41 00101010 42 00101011 43 00101100 44 00101101 45 00000100 46 00000101 47 00001010 48 00001011 49 01010010
            50 01010011 51 01010100 52 01010101 53 00100100 54 00100101 55 01011000 56 01011001 57 01011010 58 01011011
            59 01001010 60 01001011 61 00110010 62 00110011 63 00110100
            64 11011 128 10010 192 010111 256 0110111 320 00110110 384 00110111 448 01100100 512 01100101 576 01101000
            640 01100111 704 011001100 768 011001101 832 011010010 896 011010011 960 011010100 1024 011010101
            1088 011010110 1152 011010111 1216 011011000 1280 011011001 1344 011011010 1408 011011011 1472 010011000
            1536 010011001 1600 010011010 1664 011000 1728 010011011
            """ + EXTENDED
        )

        private val BLACK = table(
            """
            0 0000110111 1 010 2 11 3 10 4 011 5 0011 6 0010 7 00011 8 000101 9 000100 10 0000100 11 0000101
            12 0000111 13 00000100 14 00000111 15 000011000 16 0000010111 17 0000011000 18 0000001000 19 00001100111
            20 00001101000 21 00001101100 22 00000110111 23 00000101000 24 00000010111 25 00000011000 26 000011001010
            27 000011001011 28 000011001100 29 000011001101 30 000001101000 31 000001101001 32 000001101010
            33 000001101011 34 000011010010 35 000011010011 36 000011010100 37 000011010101 38 000011010110
            39 000011010111 40 000001101100 41 000001101101 42 000011011010 43 000011011011 44 000001010100
            45 000001010101 46 000001010110 47 000001010111 48 000001100100 49 000001100101 50 000001010010
            51 000001010011 52 000000100100 53 000000110111 54 000000111000 55 000000100111 56 000000101000
            57 000001011000 58 000001011001 59 000000101011 60 000000101100 61 000001011010 62 000001100110
            63 000001100111
            64 0000001111 128 000011001000 192 000011001001 256 000001011011 320 000000110011 384 000000110100
            448 000000110101 512 0000001101100 576 0000001101101 640 0000001001010 704 0000001001011 768 0000001001100
            832 0000001001101 896 0000001110010 960 0000001110011 1024 0000001110100 1088 0000001110101
            1152 0000001110110 1216 0000001110111 1280 0000001010010 1344 0000001010011 1408 0000001010100
            1472 0000001010101 1536 0000001011010 1600 0000001011011 1664 0000001100100 1728 0000001100101
            """ + EXTENDED
        )
    }
}
