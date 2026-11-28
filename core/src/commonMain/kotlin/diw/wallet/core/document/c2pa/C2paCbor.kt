package diw.wallet.core.document.c2pa

/**
 * A small CBOR encoder with exact control over map key order and lengths, for the C2PA and CAWG structures whose
 * bytes are hashed or signed as written. Integers and lengths use the shortest form (RFC 8949 4.2.1).
 */
object C2paCbor {
    fun head(major: Int, n: Long): ByteArray {
        val m = major shl 5
        return when {
            n < 24 -> byteArrayOf((m or n.toInt()).toByte())
            n < 0x100 -> byteArrayOf((m or 24).toByte(), n.toByte())
            n < 0x10000 -> byteArrayOf((m or 25).toByte(), (n shr 8).toByte(), n.toByte())
            n < 0x100000000L -> byteArrayOf((m or 26).toByte(), (n shr 24).toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
            else -> byteArrayOf((m or 27).toByte()) + ByteArray(8) { (n shr (56 - 8 * it)).toByte() }
        }
    }

    fun int(n: Long): ByteArray = if (n >= 0) head(0, n) else head(1, -1 - n)
    fun int(n: Int): ByteArray = int(n.toLong())
    fun bstr(b: ByteArray): ByteArray = head(2, b.size.toLong()) + b
    fun tstr(s: String): ByteArray = s.encodeToByteArray().let { head(3, it.size.toLong()) + it }
    fun array(items: List<ByteArray>): ByteArray = concat(listOf(head(4, items.size.toLong())) + items)
    fun tag(t: Long, item: ByteArray): ByteArray = head(6, t) + item
    val NULL: ByteArray = byteArrayOf(0xF6.toByte())

    /** A map with text keys, in the order given. */
    fun map(entries: List<Pair<String, ByteArray>>): ByteArray = rawMap(entries.map { tstr(it.first) to it.second })

    /** A map whose keys are already encoded (integer keys of COSE headers), in the order given. */
    fun rawMap(entries: List<Pair<ByteArray, ByteArray>>): ByteArray =
        concat(listOf(head(5, entries.size.toLong())) + entries.flatMap { listOf(it.first, it.second) })

    /** A map in core deterministic order (RFC 8949 4.2.1): keys sorted by their encoded bytes. */
    fun deterministicMap(entries: List<Pair<String, ByteArray>>): ByteArray =
        rawMap(entries.map { tstr(it.first) to it.second }.sortedWith { a, b -> compareBytes(a.first, b.first) })

    /** Encoded length of a byte string of [n] bytes. */
    fun bstrSize(n: Int): Int = head(2, n.toLong()).size + n

    /** The byte string length whose encoding takes exactly [size] bytes, or null when no length does. */
    fun bstrLengthFor(size: Int): Int? {
        for (h in listOf(1, 2, 3, 5)) {
            val n = size - h
            if (n >= 0 && bstrSize(n) == size) return n
        }
        return null
    }

    /** The encoded length of the CBOR item at [off] of [b] (definite lengths only). */
    fun itemLength(b: ByteArray, off: Int, depth: Int = 0): Int {
        if (depth > 64 || off >= b.size) throw IllegalArgumentException("CBOR item")
        val ib = b[off].toInt() and 0xFF
        val major = ib ushr 5
        val info = ib and 0x1F
        var p = off + 1
        val n: Long = when {
            info < 24 -> info.toLong()
            info in 24..27 -> {
                val w = 1 shl (info - 24)
                if (p + w > b.size) throw IllegalArgumentException("CBOR item")
                var v = 0L
                repeat(w) { v = (v shl 8) or (b[p++].toLong() and 0xFF) }
                v
            }
            else -> throw IllegalArgumentException("CBOR indefinite or reserved length")
        }
        return when (major) {
            0, 1 -> p - off
            2, 3 -> { if (n < 0 || p + n > b.size) throw IllegalArgumentException("CBOR item"); (p + n - off).toInt() }
            4, 5 -> {
                var q = p
                val items = if (major == 5) n * 2 else n
                if (items < 0 || items > b.size) throw IllegalArgumentException("CBOR item")
                repeat(items.toInt()) { q += itemLength(b, q, depth + 1) }
                q - off
            }
            6 -> p - off + itemLength(b, p, depth + 1)
            else -> p - off
        }
    }

    fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    fun concat(parts: List<ByteArray>): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var o = 0
        for (p in parts) { p.copyInto(out, o); o += p.size }
        return out
    }
}
