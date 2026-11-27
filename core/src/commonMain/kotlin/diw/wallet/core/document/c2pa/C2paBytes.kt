package diw.wallet.core.document.c2pa

/** Byte access shared by the C2PA container readers and writers: integers in both byte orders, ASCII, search. */
internal object C2paBytes {
    fun u8(b: ByteArray, o: Int): Int = b[o].toInt() and 0xFF
    fun u16(b: ByteArray, o: Int): Int = (u8(b, o) shl 8) or u8(b, o + 1)
    fun u24(b: ByteArray, o: Int): Int = (u8(b, o) shl 16) or (u8(b, o + 1) shl 8) or u8(b, o + 2)
    fun u32(b: ByteArray, o: Int): Long = (0 until 4).fold(0L) { acc, i -> (acc shl 8) or (b[o + i].toLong() and 0xFF) }
    fun u64(b: ByteArray, o: Int): Long = (0 until 8).fold(0L) { acc, i -> (acc shl 8) or (b[o + i].toLong() and 0xFF) }
    fun le16(b: ByteArray, o: Int): Int = u8(b, o) or (u8(b, o + 1) shl 8)
    fun le32(b: ByteArray, o: Int): Long = le16(b, o).toLong() or (le16(b, o + 2).toLong() shl 16)
    fun le64(b: ByteArray, o: Int): Long = le32(b, o) or (le32(b, o + 4) shl 32)

    fun be16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
    fun be32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    fun be64(v: Long) = ByteArray(8) { (v ushr (56 - 8 * it)).toByte() }
    fun le16b(v: Int) = byteArrayOf(v.toByte(), (v ushr 8).toByte())
    fun le32b(v: Long) = byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte())

    fun put32(b: ByteArray, o: Int, v: Long) { for (i in 0 until 4) b[o + i] = (v ushr (24 - 8 * i)).toByte() }
    fun put64(b: ByteArray, o: Int, v: Long) { for (i in 0 until 8) b[o + i] = (v ushr (56 - 8 * i)).toByte() }
    fun putLe32(b: ByteArray, o: Int, v: Long) { for (i in 0 until 4) b[o + i] = (v ushr (8 * i)).toByte() }

    /** A big-endian unsigned integer of [n] bytes (0, 4 or 8 in BMFF fields). */
    fun uN(b: ByteArray, o: Int, n: Int): Long = (0 until n).fold(0L) { acc, i -> (acc shl 8) or (b[o + i].toLong() and 0xFF) }
    fun putN(b: ByteArray, o: Int, n: Int, v: Long) { for (i in 0 until n) b[o + i] = (v ushr (8 * (n - 1 - i))).toByte() }

    fun ascii(b: ByteArray, off: Int, n: Int): String =
        if (off < 0 || off + n > b.size) "" else CharArray(n) { (b[off + it].toInt() and 0xFF).toChar() }.concatToString()

    fun at(b: ByteArray, off: Int, text: String): Boolean = ascii(b, off, text.length) == text

    fun indexOf(b: ByteArray, needle: ByteArray, from: Int = 0, to: Int = b.size): Int {
        if (needle.isEmpty()) return from
        var i = maxOf(0, from)
        val last = minOf(b.size, to) - needle.size
        while (i <= last) {
            var k = 0
            while (k < needle.size && b[i + k] == needle[k]) k++
            if (k == needle.size) return i
            i++
        }
        return -1
    }

    fun concat(vararg parts: ByteArray): ByteArray = C2paCbor.concat(parts.toList())

    /** [b] with [length] bytes at [start] replaced by [insert]. */
    fun splice(b: ByteArray, start: Int, length: Int, insert: ByteArray): ByteArray =
        concat(b.copyOfRange(0, start), insert, b.copyOfRange(start + length, b.size))

    /** ID3v2 synchsafe integer: 4 bytes of 7 bits each. */
    fun synchsafe(b: ByteArray, o: Int): Int = (u8(b, o) and 0x7F shl 21) or (u8(b, o + 1) and 0x7F shl 14) or (u8(b, o + 2) and 0x7F shl 7) or (u8(b, o + 3) and 0x7F)
    fun synchsafeBytes(v: Int) = byteArrayOf((v ushr 21 and 0x7F).toByte(), (v ushr 14 and 0x7F).toByte(), (v ushr 7 and 0x7F).toByte(), (v and 0x7F).toByte())
}

/** A byte range of a file: where it starts and how many bytes it has. */
data class C2paRange(val start: Long, val length: Long) {
    val end: Long get() = start + length
}
