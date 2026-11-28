package diw.wallet.core.document.c2pa

/** Brotli (RFC 7932) for compressed manifests (C2PA 11.2.4, the brob box). */
internal expect object C2paBrotli {
    /** The bytes [data] decompresses to; throws when it is not a valid stream or would exceed [limit] bytes. */
    fun decode(data: ByteArray, limit: Int): ByteArray
}

/**
 * A Brotli encoder (RFC 7932) in pure Kotlin for writing compressed manifests: LZ77 matches found with hash chains in
 * a 64 KiB window (WBITS 16), one meta-block of up to 16 MiB at a time with a single block type per category, and
 * prefix codes built from the block's own symbol counts. It never uses the static dictionary, so every stream it
 * writes is plain RFC 7932 that any decoder reads.
 */
object BrotliEncoder {
    private const val WINDOW = (1 shl 16) - 16
    private const val MAX_BLOCK = 1 shl 24
    private const val MIN_MATCH = 4
    private const val MAX_MATCH = 65535
    private const val HASH_BITS = 15
    private const val CHAIN = 48

    private class Bits {
        private var buf = ByteArray(1024)
        private var size = 0
        private var acc = 0L
        private var n = 0

        fun write(value: Long, bits: Int) {
            if (bits == 0) return
            acc = acc or ((value and ((1L shl bits) - 1)) shl n)
            n += bits
            while (n >= 8) {
                if (size == buf.size) buf = buf.copyOf(buf.size * 2)
                buf[size++] = acc.toByte()
                acc = acc ushr 8
                n -= 8
            }
        }

        fun write(value: Int, bits: Int) = write(value.toLong(), bits)

        fun finish(): ByteArray {
            if (n > 0) write(0, 8 - n)
            return buf.copyOf(size)
        }
    }

    private class Command(val insert: Int, val copy: Int, val distance: Int)

    fun encode(data: ByteArray): ByteArray {
        val out = Bits()
        out.write(0, 1) // WBITS = 16
        if (data.isEmpty()) {
            out.write(1, 1); out.write(1, 1) // ISLAST, ISLASTEMPTY
            return out.finish()
        }
        val head = IntArray(1 shl HASH_BITS) { -1 }
        val prev = IntArray(data.size)
        var start = 0
        var pos = 0
        while (start < data.size) {
            val end = minOf(data.size, start + MAX_BLOCK)
            val commands = ArrayList<Command>()
            var literalStart = pos
            fun insertHash(i: Int) {
                if (i + MIN_MATCH > data.size) return
                val h = hash(data, i)
                prev[i] = head[h]
                head[h] = i
            }
            while (pos < end) {
                var bestLen = 0
                var bestDist = 0
                if (pos + MIN_MATCH <= end) {
                    var cand = head[hash(data, pos)]
                    var tries = CHAIN
                    while (cand >= 0 && pos - cand <= WINDOW && tries-- > 0) {
                        if (data[cand + bestLen] == data[pos + bestLen]) {
                            var l = 0
                            val limit = minOf(MAX_MATCH, end - pos)
                            while (l < limit && data[cand + l] == data[pos + l]) l++
                            if (l > bestLen) { bestLen = l; bestDist = pos - cand; if (l == limit) break }
                        }
                        cand = prev[cand]
                    }
                }
                if (bestLen >= MIN_MATCH) {
                    commands.add(Command(pos - literalStart, bestLen, bestDist))
                    for (i in pos until pos + bestLen) insertHash(i)
                    pos += bestLen
                    literalStart = pos
                } else {
                    insertHash(pos)
                    pos++
                }
            }
            // The last literals: a command whose copy is never read, as the meta-block ends after its literals.
            if (literalStart < end) commands.add(Command(end - literalStart, 0, 0))
            metaBlock(out, data, start, end, commands, end == data.size)
            start = end
        }
        return out.finish()
    }

    private fun hash(b: ByteArray, i: Int): Int {
        val v = (b[i].toInt() and 0xFF) or ((b[i + 1].toInt() and 0xFF) shl 8) or ((b[i + 2].toInt() and 0xFF) shl 16) or ((b[i + 3].toInt() and 0xFF) shl 24)
        return (v * 0x1E35A7BD) ushr (32 - HASH_BITS)
    }

    // ---------------------------------------------------------------- lengths and distances (RFC 7932 5 and 4)

    private val INSERT_BASE = intArrayOf(0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594)
    private val INSERT_EXTRA = intArrayOf(0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24)
    private val COPY_BASE = intArrayOf(2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118)
    private val COPY_EXTRA = intArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24)

    private fun code(base: IntArray, value: Int): Int {
        var c = base.size - 1
        while (base[c] > value) c--
        return c
    }

    /** The insert-and-copy symbol of cells that read an explicit distance (128 and above). */
    private fun commandSymbol(ins: Int, copy: Int): Int {
        val cell = when {
            ins < 8 && copy < 8 -> 128
            ins < 8 && copy < 16 -> 192
            ins < 16 && copy < 8 -> 256
            ins < 16 && copy < 16 -> 320
            ins < 8 -> 384
            ins >= 16 && copy < 8 -> 448
            ins < 16 -> 512
            copy < 16 -> 576
            else -> 640
        }
        return cell + ((ins and 7) shl 3) + (copy and 7)
    }

    /** Distance symbol, extra bit count and extra bits for NPOSTFIX 0 and NDIRECT 0. */
    private fun distanceCode(d: Int): Triple<Int, Int, Int> {
        val x = d + 3
        val log = 31 - x.countLeadingZeroBits()
        val nbits = log - 1
        val hcode = ((nbits - 1) shl 1) or ((x ushr nbits) and 1)
        val extra = x - ((2 + (hcode and 1)) shl nbits)
        return Triple(16 + hcode, nbits, extra)
    }

    // ---------------------------------------------------------------- meta-block

    private fun metaBlock(out: Bits, data: ByteArray, start: Int, end: Int, commands: List<Command>, last: Boolean) {
        val literals = IntArray(256)
        val symbols = IntArray(704)
        val distances = IntArray(64)
        var p = start
        for (c in commands) {
            for (i in p until p + c.insert) literals[data[i].toInt() and 0xFF]++
            symbols[commandSymbol(code(INSERT_BASE, c.insert), code(COPY_BASE, maxOf(2, c.copy)))]++
            if (c.copy > 0) distances[distanceCode(c.distance).first]++
            p += c.insert + c.copy
        }
        val len = end - start
        out.write(if (last) 1 else 0, 1)
        if (last) out.write(0, 1) // ISLASTEMPTY
        val nibbles = when { len - 1 < (1 shl 16) -> 4; len - 1 < (1 shl 20) -> 5; else -> 6 }
        out.write(nibbles - 4, 2)
        out.write(len - 1, nibbles * 4)
        if (!last) out.write(0, 1) // ISUNCOMPRESSED
        out.write(0, 1); out.write(0, 1); out.write(0, 1) // one block type each for literals, commands, distances
        out.write(0, 2); out.write(0, 4) // NPOSTFIX, NDIRECT
        out.write(0, 2) // context mode of the literal block type
        out.write(0, 1); out.write(0, 1) // one literal tree, one distance tree
        val litCodes = prefixCode(out, literals, 8)
        val cmdCodes = prefixCode(out, symbols, 10)
        val distCodes = prefixCode(out, distances, 6)
        p = start
        for (c in commands) {
            val ic = code(INSERT_BASE, c.insert)
            val cc = code(COPY_BASE, maxOf(2, c.copy))
            emit(out, cmdCodes, commandSymbol(ic, cc))
            out.write(c.insert - INSERT_BASE[ic], INSERT_EXTRA[ic])
            out.write(maxOf(2, c.copy) - COPY_BASE[cc], COPY_EXTRA[cc])
            for (i in p until p + c.insert) emit(out, litCodes, data[i].toInt() and 0xFF)
            if (c.copy > 0) {
                val (sym, nbits, extra) = distanceCode(c.distance)
                emit(out, distCodes, sym)
                out.write(extra, nbits)
            }
            p += c.insert + c.copy
        }
    }

    /** Canonical code (length, code bits in stream order) per symbol. */
    private class Codes(val lengths: IntArray, val bits: IntArray)

    private fun emit(out: Bits, c: Codes, symbol: Int) = out.write(c.bits[symbol], c.lengths[symbol])

    /**
     * Writes the prefix code of an alphabet with the counts [counts] (RFC 7932 3.4 and 3.5) and returns it. One used
     * symbol (or none) takes a simple prefix code with a zero-length code; more take a complex prefix code.
     */
    private fun prefixCode(out: Bits, counts: IntArray, alphabetBits: Int): Codes {
        val used = counts.indices.filter { counts[it] > 0 }
        if (used.size <= 1) {
            out.write(1, 2) // HSKIP 1: simple prefix code
            out.write(0, 2) // NSYM - 1
            out.write(used.firstOrNull() ?: 0, alphabetBits)
            return Codes(IntArray(counts.size), IntArray(counts.size))
        }
        val lengths = huffmanLengths(counts, 15)
        // Code lengths with runs of zeros as symbol 17 (3 to 10), never two 17s in a row.
        val seq = ArrayList<IntArray>()
        val lastUsed = lengths.indices.last { lengths[it] > 0 }
        var i = 0
        var lastWasRun = false
        while (i <= lastUsed) {
            if (lengths[i] == 0) {
                var run = 0
                while (i + run <= lastUsed && lengths[i + run] == 0) run++
                if (run >= 3 && !lastWasRun) {
                    val n = minOf(run, 10)
                    seq.add(intArrayOf(17, n - 3)); i += n; lastWasRun = true
                    continue
                }
                seq.add(intArrayOf(0, 0)); i++; lastWasRun = false
            } else {
                seq.add(intArrayOf(lengths[i], 0)); i++; lastWasRun = false
            }
        }
        val clCounts = IntArray(18)
        for (x in seq) clCounts[x[0]]++
        val clUsed = clCounts.indices.count { clCounts[it] > 0 }
        val clLengths = if (clUsed == 1) IntArray(18).also { it[clCounts.indices.first { k -> clCounts[k] > 0 }] = 1 } else huffmanLengths(clCounts, 5)
        out.write(0, 2) // HSKIP 0
        var space = 32
        for (sym in CL_ORDER) {
            val l = clLengths[sym]
            out.write(STATIC_BITS[l], STATIC_LENGTHS[l])
            if (l != 0) { space -= 32 shr l; if (space <= 0 && clUsed > 1) break }
        }
        val clCodes = canonical(clLengths)
        for (x in seq) {
            // A code length code with one used symbol takes no bits.
            if (clUsed > 1) emit(out, clCodes, x[0])
            if (x[0] == 17) out.write(x[1], 3)
        }
        return canonical(lengths)
    }

    private val CL_ORDER = intArrayOf(1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15)

    /** The static code of code length code lengths 0 to 5 (RFC 7932 3.5), as bits in stream order. */
    private val STATIC_BITS = intArrayOf(0, 7, 3, 2, 1, 15)
    private val STATIC_LENGTHS = intArrayOf(2, 4, 3, 2, 2, 4)

    /** Huffman code lengths of at most [limit] bits for [counts] (two used symbols at least). */
    private fun huffmanLengths(counts: IntArray, limit: Int): IntArray {
        var floor = 1L
        while (true) {
            val parent = IntArray(counts.size * 2) { -1 }
            var next = counts.size
            // (weight, node), merged two lightest at a time; ties broken by node so the result is deterministic.
            val nodes = counts.indices.filter { counts[it] > 0 }.map { longArrayOf(maxOf(counts[it].toLong(), floor), it.toLong()) }.toMutableList()
            val order = compareBy<LongArray>({ it[0] }, { it[1] })
            while (nodes.size > 1) {
                nodes.sortWith(order)
                val a = nodes.removeAt(0)
                val b = nodes.removeAt(0)
                val id = next++
                parent[a[1].toInt()] = id
                parent[b[1].toInt()] = id
                nodes.add(longArrayOf(a[0] + b[0], id.toLong()))
            }
            val lengths = IntArray(counts.size)
            var ok = true
            for (s in counts.indices) if (counts[s] > 0) {
                var d = 0
                var n = s
                while (parent[n] >= 0) { n = parent[n]; d++ }
                lengths[s] = d
                if (d > limit) ok = false
            }
            if (ok) return lengths
            floor *= 2
        }
    }

    /** Canonical codes (RFC 7932 3.2) with the bits reversed for the LSB-first stream. */
    private fun canonical(lengths: IntArray): Codes {
        val max = lengths.maxOrNull() ?: 0
        val count = IntArray(max + 1)
        for (l in lengths) if (l > 0) count[l]++
        val nextCode = IntArray(max + 2)
        var c = 0
        for (bits in 1..max) { c = (c + count[bits - 1]) shl 1; nextCode[bits] = c }
        val out = IntArray(lengths.size)
        for (s in lengths.indices) {
            val l = lengths[s]
            if (l == 0) continue
            val v = nextCode[l]++
            var r = 0
            for (k in 0 until l) if (v and (1 shl k) != 0) r = r or (1 shl (l - 1 - k))
            out[s] = r
        }
        return Codes(lengths, out)
    }
}
