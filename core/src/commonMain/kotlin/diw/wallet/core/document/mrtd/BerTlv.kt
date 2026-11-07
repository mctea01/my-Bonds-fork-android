package diw.wallet.core.document.mrtd

/** BER-TLV as the LDS and the card protocols use it: tags of up to three bytes, definite lengths up to four bytes. */
object BerTlv {
    class Tlv(val tag: Int, val value: ByteArray, val start: Int, val end: Int) {
        val constructed: Boolean get() = (if (tag > 0xFFFF) tag shr 16 else if (tag > 0xFF) tag shr 8 else tag) and 0x20 != 0
    }

    fun read(b: ByteArray, off: Int): Tlv? {
        var p = off
        if (p >= b.size) return null
        var tag = b[p++].toInt() and 0xFF
        if (tag and 0x1F == 0x1F) {
            do {
                if (p >= b.size) return null
                val next = b[p++].toInt() and 0xFF
                tag = (tag shl 8) or next
                if (tag > 0xFFFFFF) return null
            } while (next and 0x80 != 0)
        }
        if (p >= b.size) return null
        var len = b[p++].toInt() and 0xFF
        if (len and 0x80 != 0) {
            val n = len and 0x7F
            if (n == 0 || n > 4 || p + n > b.size) return null
            len = 0
            repeat(n) { len = (len shl 8) or (b[p++].toInt() and 0xFF) }
            if (len < 0) return null
        }
        if (p + len > b.size) return null
        return Tlv(tag, b.copyOfRange(p, p + len), off, p + len)
    }

    fun children(b: ByteArray): List<Tlv> {
        val out = ArrayList<Tlv>()
        var off = 0
        while (off < b.size) {
            if (b[off] == 0.toByte() || b[off] == 0xFF.toByte()) { off++; continue }
            val t = read(b, off) ?: break
            out.add(t)
            off = t.end
        }
        return out
    }

    /** The value of the first direct child with [tag]. */
    fun find(b: ByteArray, tag: Int): ByteArray? = children(b).firstOrNull { it.tag == tag }?.value

    /** The value of the first element with [tag] anywhere in [b], searching constructed elements depth first. */
    fun findDeep(b: ByteArray, tag: Int): ByteArray? {
        for (t in children(b)) {
            if (t.tag == tag) return t.value
            if (t.constructed) findDeep(t.value, tag)?.let { return it }
        }
        return null
    }

    /** The length of the whole TLV at the start of [b] from its header alone, or null when the header is incomplete. */
    fun totalLength(b: ByteArray): Int? {
        var p = 0
        if (b.isEmpty()) return null
        if (b[p++].toInt() and 0x1F == 0x1F) {
            do { if (p >= b.size) return null } while (b[p++].toInt() and 0x80 != 0)
        }
        if (p >= b.size) return null
        var len = b[p++].toInt() and 0xFF
        if (len and 0x80 != 0) {
            val n = len and 0x7F
            if (n == 0 || n > 4 || p + n > b.size) return null
            len = 0
            repeat(n) { len = (len shl 8) or (b[p++].toInt() and 0xFF) }
        }
        return p + len
    }

    fun length(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n <= 0xFF -> byteArrayOf(0x81.toByte(), n.toByte())
        n <= 0xFFFF -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
    }

    fun encode(tag: Int, value: ByteArray): ByteArray {
        val t = when {
            tag > 0xFFFF -> byteArrayOf((tag shr 16).toByte(), (tag shr 8).toByte(), tag.toByte())
            tag > 0xFF -> byteArrayOf((tag shr 8).toByte(), tag.toByte())
            else -> byteArrayOf(tag.toByte())
        }
        return t + length(value.size) + value
    }

    /** An unsigned big-endian integer of up to four bytes. */
    fun uint(v: ByteArray): Int = v.takeLast(4).fold(0) { a, x -> (a shl 8) or (x.toInt() and 0xFF) }

    /** DER encoding of an OBJECT IDENTIFIER value (without tag and length) from its dotted form. */
    fun oidValue(dotted: String): ByteArray {
        val parts = dotted.split('.').map { it.toLong() }
        val out = ArrayList<Byte>()
        fun base128(v: Long) {
            val tmp = ArrayList<Byte>()
            var x = v
            tmp.add((x and 0x7F).toByte())
            x = x shr 7
            while (x > 0) { tmp.add(((x and 0x7F) or 0x80).toByte()); x = x shr 7 }
            out.addAll(tmp.reversed())
        }
        base128(parts[0] * 40 + parts[1])
        for (p in parts.drop(2)) base128(p)
        return out.toByteArray()
    }

    /** The dotted form of an OBJECT IDENTIFIER value. */
    fun oidString(v: ByteArray): String {
        val parts = ArrayList<Long>()
        var acc = 0L
        for (b in v) {
            acc = (acc shl 7) or (b.toLong() and 0x7F)
            if (b.toInt() and 0x80 == 0) { parts.add(acc); acc = 0 }
        }
        if (parts.isEmpty()) return ""
        val first = parts[0]
        val head = when {
            first < 40 -> listOf(0L, first)
            first < 80 -> listOf(1L, first - 40)
            else -> listOf(2L, first - 80)
        }
        return (head + parts.drop(1)).joinToString(".")
    }
}
