package diw.wallet.core.util

/** A QR Code symbol: [size] x [size] modules, true for dark, row-major. */
class QrMatrix(val size: Int, val version: Int, val mask: Int, private val modules: BooleanArray) {
    operator fun get(x: Int, y: Int): Boolean = modules[y * size + x]
}

/**
 * QR Code model 2 encoder (ISO/IEC 18004) in plain Kotlin, so every platform can show codes without a native or
 * camera library: alphanumeric mode when the text allows it (Base45 frames, BTWVP1), byte mode (UTF-8) otherwise.
 */
object QrEncoder {
    enum class Ecc(val formatBits: Int) { L(1), M(0), Q(3), H(2) }

    private const val ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

    /** Encodes [text] in the smallest version that fits; [forceVersion] and [forceMask] are for tests. */
    fun encode(text: String, ecc: Ecc = Ecc.M, forceVersion: Int? = null, forceMask: Int? = null): QrMatrix {
        val alnum = text.all { it in ALNUM }
        val bytes = text.encodeToByteArray()
        val version = forceVersion ?: (1..40).firstOrNull { v -> bitLength(text.length, bytes.size, alnum, v) <= dataCodewords(v, ecc) * 8 }
            ?: throw IllegalArgumentException("Text too long for a QR Code")
        val capacity = dataCodewords(version, ecc) * 8
        val bits = BitBuffer()
        if (alnum) {
            bits.append(0x2, 4)
            bits.append(text.length, if (version <= 9) 9 else if (version <= 26) 11 else 13)
            var i = 0
            while (i + 1 < text.length) {
                bits.append(ALNUM.indexOf(text[i]) * 45 + ALNUM.indexOf(text[i + 1]), 11)
                i += 2
            }
            if (i < text.length) bits.append(ALNUM.indexOf(text[i]), 6)
        } else {
            bits.append(0x4, 4)
            bits.append(bytes.size, if (version <= 9) 8 else 16)
            bytes.forEach { bits.append(it.toInt() and 0xFF, 8) }
        }
        require(bits.size <= capacity) { "Text does not fit version $version" }
        bits.append(0, minOf(4, capacity - bits.size))
        bits.append(0, (8 - bits.size % 8) % 8)
        var pad = 0xEC
        while (bits.size < capacity) {
            bits.append(pad, 8)
            pad = pad xor 0xEC xor 0x11
        }
        val data = ByteArray(bits.size / 8) { i -> (0 until 8).fold(0) { acc, j -> (acc shl 1) or (if (bits[i * 8 + j]) 1 else 0) }.toByte() }
        return Symbol(version, ecc).build(addEcc(data, version, ecc), forceMask)
    }

    private fun bitLength(chars: Int, bytes: Int, alnum: Boolean, v: Int): Int =
        if (alnum) 4 + (if (v <= 9) 9 else if (v <= 26) 11 else 13) + chars / 2 * 11 + chars % 2 * 6
        else 4 + (if (v <= 9) 8 else 16) + bytes * 8

    private class BitBuffer {
        private val bits = ArrayList<Boolean>()
        val size get() = bits.size
        operator fun get(i: Int) = bits[i]
        fun append(value: Int, length: Int) {
            for (i in length - 1 downTo 0) bits += (value ushr i) and 1 == 1
        }
    }

    private class Symbol(val version: Int, val ecc: Ecc) {
        val size = version * 4 + 17
        val modules = Array(size) { BooleanArray(size) }
        val function = Array(size) { BooleanArray(size) }

        fun build(codewords: ByteArray, forceMask: Int?): QrMatrix {
            drawFunctionPatterns()
            drawCodewords(codewords)
            val mask = forceMask ?: (0 until 8).minBy { m ->
                applyMask(m); drawFormatBits(m)
                penalty().also { applyMask(m) }
            }
            applyMask(mask)
            drawFormatBits(mask)
            val flat = BooleanArray(size * size) { modules[it / size][it % size] }
            return QrMatrix(size, version, mask, flat)
        }

        private fun set(x: Int, y: Int, dark: Boolean) {
            modules[y][x] = dark
            function[y][x] = true
        }

        private fun drawFunctionPatterns() {
            for (i in 0 until size) {
                set(6, i, i % 2 == 0)
                set(i, 6, i % 2 == 0)
            }
            finder(3, 3); finder(size - 4, 3); finder(3, size - 4)
            val pos = alignmentPositions()
            val n = pos.size
            for (i in 0 until n) for (j in 0 until n) {
                if ((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)) continue
                for (dy in -2..2) for (dx in -2..2) set(pos[i] + dx, pos[j] + dy, maxOf(kotlin.math.abs(dx), kotlin.math.abs(dy)) != 1)
            }
            drawFormatBits(0)
            drawVersion()
        }

        private fun finder(x: Int, y: Int) {
            for (dy in -4..4) for (dx in -4..4) {
                val xx = x + dx
                val yy = y + dy
                if (xx in 0 until size && yy in 0 until size) {
                    val d = maxOf(kotlin.math.abs(dx), kotlin.math.abs(dy))
                    set(xx, yy, d != 2 && d != 4)
                }
            }
        }

        private fun alignmentPositions(): IntArray {
            if (version == 1) return IntArray(0)
            val n = version / 7 + 2
            val step = (version * 8 + n * 3 + 5) / (n * 4 - 4) * 2
            val out = IntArray(n)
            out[0] = 6
            var p = size - 7
            for (i in n - 1 downTo 1) {
                out[i] = p
                p -= step
            }
            return out
        }

        private fun drawFormatBits(mask: Int) {
            val data = ecc.formatBits shl 3 or mask
            var rem = data
            repeat(10) { rem = (rem shl 1) xor ((rem ushr 9) * 0x537) }
            val bits = (data shl 10 or rem) xor 0x5412
            fun bit(i: Int) = (bits ushr i) and 1 == 1
            for (i in 0..5) set(8, i, bit(i))
            set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8))
            for (i in 9 until 15) set(14 - i, 8, bit(i))
            for (i in 0 until 8) set(size - 1 - i, 8, bit(i))
            for (i in 8 until 15) set(8, size - 15 + i, bit(i))
            set(8, size - 8, true)
        }

        private fun drawVersion() {
            if (version < 7) return
            var rem = version
            repeat(12) { rem = (rem shl 1) xor ((rem ushr 11) * 0x1F25) }
            val bits = version shl 12 or rem
            for (i in 0 until 18) {
                val b = (bits ushr i) and 1 == 1
                val a = size - 11 + i % 3
                val c = i / 3
                set(a, c, b); set(c, a, b)
            }
        }

        private fun drawCodewords(data: ByteArray) {
            var i = 0
            var right = size - 1
            while (right >= 1) {
                if (right == 6) right = 5
                for (vert in 0 until size) for (j in 0..1) {
                    val x = right - j
                    val upward = (right + 1) and 2 == 0
                    val y = if (upward) size - 1 - vert else vert
                    if (!function[y][x] && i < data.size * 8) {
                        modules[y][x] = (data[i ushr 3].toInt() ushr (7 - (i and 7))) and 1 == 1
                        i++
                    }
                }
                right -= 2
            }
        }

        private fun applyMask(m: Int) {
            for (y in 0 until size) for (x in 0 until size) {
                val invert = when (m) {
                    0 -> (x + y) % 2 == 0
                    1 -> y % 2 == 0
                    2 -> x % 3 == 0
                    3 -> (x + y) % 3 == 0
                    4 -> (x / 3 + y / 2) % 2 == 0
                    5 -> x * y % 2 + x * y % 3 == 0
                    6 -> (x * y % 2 + x * y % 3) % 2 == 0
                    else -> ((x + y) % 2 + x * y % 3) % 2 == 0
                }
                if (invert && !function[y][x]) modules[y][x] = !modules[y][x]
            }
        }

        /** ISO/IEC 18004 mask penalty (runs, 2x2 blocks, finder-like patterns, dark balance). */
        private fun penalty(): Int {
            var p = 0
            fun line(get: (Int) -> Boolean) {
                var run = 1
                for (i in 1 until size) {
                    if (get(i) == get(i - 1)) {
                        run++
                        if (i == size - 1 && run >= 5) p += run - 2
                    } else {
                        if (run >= 5) p += run - 2
                        run = 1
                    }
                }
                val pattern = booleanArrayOf(true, false, true, true, true, false, true)
                for (i in 0..size - 7) {
                    if ((0 until 7).all { get(i + it) == pattern[it] }) {
                        val before = (1..4).all { i - it < 0 || !get(i - it) }
                        val after = (1..4).all { i + 6 + it >= size || !get(i + 6 + it) }
                        if (before || after) p += 40
                    }
                }
            }
            for (y in 0 until size) line { modules[y][it] }
            for (x in 0 until size) line { modules[it][x] }
            for (y in 0 until size - 1) for (x in 0 until size - 1) {
                val c = modules[y][x]
                if (c == modules[y][x + 1] && c == modules[y + 1][x] && c == modules[y + 1][x + 1]) p += 3
            }
            val dark = modules.sumOf { r -> r.count { it } }
            val total = size * size
            p += ((kotlin.math.abs(dark * 20 - total * 10) + total - 1) / total - 1).coerceAtLeast(0) * 10
            return p
        }
    }

    private fun rawModules(v: Int): Int {
        var r = (16 * v + 128) * v + 64
        if (v >= 2) {
            val n = v / 7 + 2
            r -= (25 * n - 10) * n - 55
            if (v >= 7) r -= 36
        }
        return r
    }

    private fun dataCodewords(v: Int, ecc: Ecc): Int = rawModules(v) / 8 - ECC_PER_BLOCK[ecc.ordinal][v] * BLOCKS[ecc.ordinal][v]

    private fun addEcc(data: ByteArray, v: Int, ecc: Ecc): ByteArray {
        val numBlocks = BLOCKS[ecc.ordinal][v]
        val eccLen = ECC_PER_BLOCK[ecc.ordinal][v]
        val raw = rawModules(v) / 8
        val numShort = numBlocks - raw % numBlocks
        val shortLen = raw / numBlocks
        val divisor = rsDivisor(eccLen)
        val blocks = ArrayList<ByteArray>()
        var k = 0
        for (i in 0 until numBlocks) {
            val datLen = shortLen - eccLen + if (i < numShort) 0 else 1
            val dat = data.copyOfRange(k, k + datLen)
            k += datLen
            val block = dat.copyOf(shortLen + 1)
            rsRemainder(dat, divisor).copyInto(block, block.size - eccLen)
            blocks += block
        }
        val out = ArrayList<Byte>(raw)
        for (i in blocks[0].indices) for (j in blocks.indices) {
            if (i != shortLen - eccLen || j >= numShort) out += blocks[j][i]
        }
        return out.toByteArray()
    }

    private fun gfMul(x: Int, y: Int): Int {
        var z = 0
        for (i in 7 downTo 0) {
            z = (z shl 1) xor ((z ushr 7) * 0x11D)
            z = z xor (((y ushr i) and 1) * x)
        }
        return z
    }

    private fun rsDivisor(degree: Int): IntArray {
        val r = IntArray(degree)
        r[degree - 1] = 1
        var root = 1
        repeat(degree) {
            for (j in r.indices) {
                r[j] = gfMul(r[j], root)
                if (j + 1 < r.size) r[j] = r[j] xor r[j + 1]
            }
            root = gfMul(root, 2)
        }
        return r
    }

    private fun rsRemainder(data: ByteArray, divisor: IntArray): ByteArray {
        val r = IntArray(divisor.size)
        for (b in data) {
            val factor = (b.toInt() and 0xFF) xor r[0]
            for (i in 0 until r.size - 1) r[i] = r[i + 1]
            r[r.size - 1] = 0
            for (i in r.indices) r[i] = r[i] xor gfMul(divisor[i], factor)
        }
        return ByteArray(r.size) { r[it].toByte() }
    }

    private val ECC_PER_BLOCK = arrayOf(
        intArrayOf(-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
        intArrayOf(-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
        intArrayOf(-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
        intArrayOf(-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    )

    private val BLOCKS = arrayOf(
        intArrayOf(-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
        intArrayOf(-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
        intArrayOf(-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
        intArrayOf(-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81),
    )
}
