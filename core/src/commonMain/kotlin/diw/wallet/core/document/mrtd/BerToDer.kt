package diw.wallet.core.document.mrtd

/**
 * Rewrites the parts of a BER encoding that strict DER readers refuse: indefinite lengths become definite and
 * constructed OCTET STRINGs become primitive. Elements without either are copied byte for byte, so signed encodings
 * (a certificate's TBS, signed attributes) keep their exact bytes. Some passports encode EF.SOD this way.
 */
object BerToDer {
    private const val MAX_DEPTH = 64

    private class Node(
        val start: Int,
        val tagEnd: Int,
        val constructed: Boolean,
        val indefinite: Boolean,
        val end: Int,
        val children: List<Node>,
    )

    /** [bytes] in DER where it matters, or null when it is not a BER encoding. */
    fun convert(bytes: ByteArray): ByteArray? = runCatching {
        val root = parse(bytes, 0, bytes.size, 0)
        if (root.end != bytes.size) return null
        emit(bytes, root)
    }.getOrNull()

    /** The CMS ContentInfo of EF.SOD in DER where it matters, without the 0x77 wrapper; [sod] itself when unreadable. */
    fun sod(sod: ByteArray): ByteArray {
        val der = convert(sod) ?: return sod
        if (der.isEmpty() || der[0] != 0x77.toByte()) return der
        val inner = runCatching { parse(der, 0, der.size, 0) }.getOrNull() ?: return der
        val first = inner.children.firstOrNull() ?: return der
        return der.copyOfRange(first.start, first.end)
    }

    private fun parse(b: ByteArray, off: Int, limit: Int, depth: Int): Node {
        require(depth < MAX_DEPTH && off < limit)
        val first = b[off].toInt() and 0xFF
        var i = off + 1
        if (first and 0x1F == 0x1F) {
            while (i < limit && b[i].toInt() and 0x80 != 0) i++
            i++
        }
        require(i < limit)
        val tagEnd = i
        val constructed = first and 0x20 != 0
        val l = b[i++].toInt() and 0xFF
        if (l == 0x80) {
            require(constructed)
            val children = ArrayList<Node>()
            var p = i
            while (true) {
                require(p + 1 < limit)
                if (b[p].toInt() == 0 && b[p + 1].toInt() == 0) break
                val c = parse(b, p, limit, depth + 1)
                children.add(c)
                p = c.end
            }
            return Node(off, tagEnd, true, true, p + 2, children)
        }
        var len = l
        if (l > 0x80) {
            val n = l and 0x7F
            require(n <= 4 && i + n <= limit)
            len = 0
            repeat(n) { len = (len shl 8) or (b[i++].toInt() and 0xFF) }
            require(len >= 0)
        }
        val end = i + len
        require(end <= limit)
        val children = ArrayList<Node>()
        if (constructed) {
            var p = i
            while (p < end) {
                val c = parse(b, p, end, depth + 1)
                children.add(c)
                p = c.end
            }
        }
        return Node(off, tagEnd, constructed, false, end, children)
    }

    /** A constructed OCTET STRING (universal tag 4 with the constructed bit). */
    private fun octetChunks(b: ByteArray, n: Node) = (b[n.start].toInt() and 0xFF) == 0x24

    private fun changed(b: ByteArray, n: Node): Boolean = n.indefinite || octetChunks(b, n) || n.children.any { changed(b, it) }

    private fun emit(b: ByteArray, n: Node): ByteArray {
        if (!changed(b, n)) return b.copyOfRange(n.start, n.end)
        if (octetChunks(b, n)) return BerTlv.encode(0x04, octets(b, n))
        val content = n.children.fold(ByteArray(0)) { acc, c -> acc + emit(b, c) }
        return b.copyOfRange(n.start, n.tagEnd) + BerTlv.length(content.size) + content
    }

    /** The concatenated contents of a constructed OCTET STRING. */
    private fun octets(b: ByteArray, n: Node): ByteArray =
        if (!n.constructed) b.copyOfRange(n.end - contentLength(b, n), n.end)
        else n.children.fold(ByteArray(0)) { acc, c -> acc + octets(b, c) }

    private fun contentLength(b: ByteArray, n: Node): Int {
        val l = b[n.tagEnd].toInt() and 0xFF
        if (l < 0x80) return l
        var len = 0
        for (k in 1..(l and 0x7F)) len = (len shl 8) or (b[n.tagEnd + k].toInt() and 0xFF)
        return len
    }
}
