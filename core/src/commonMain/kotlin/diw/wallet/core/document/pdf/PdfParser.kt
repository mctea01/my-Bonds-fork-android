package diw.wallet.core.document.pdf

/**
 * Tokenizer and object parser over the bytes of a PDF file (ISO 32000-1 section 7.2 and 7.3). Indirect references
 * are returned as [PdfRef]; resolving them is up to [PdfFile]. Streams are read with [streamLength], which resolves
 * an indirect /Length.
 */
class PdfParser(val bytes: ByteArray, var pos: Int = 0, private val streamLength: (PdfDict) -> Int? = { (it["Length"] as? PdfNumber)?.int }) {

    /** Optional source capture; normal document parsing does not copy source strings. */
    var retainStringSource: Boolean = false

    /** Raw encoded extent of the last parsed stream, before any decryption or filters. */
    var lastStreamExtent: IntRange? = null
        private set

    fun skipWhitespace() {
        while (pos < bytes.size) {
            val c = bytes[pos].toInt() and 0xFF
            when {
                isWhite(c) -> pos++
                c == '%'.code -> while (pos < bytes.size && bytes[pos] != '\n'.code.toByte() && bytes[pos] != '\r'.code.toByte()) pos++
                else -> return
            }
        }
    }

    fun atEnd(): Boolean {
        skipWhitespace()
        return pos >= bytes.size
    }

    private fun peek(offset: Int = 0): Int = if (pos + offset < bytes.size) bytes[pos + offset].toInt() and 0xFF else -1

    /** Reads a bare keyword or number token (regular characters up to a delimiter or whitespace). */
    fun readToken(): String {
        skipWhitespace()
        val start = pos
        while (pos < bytes.size && isRegular(bytes[pos].toInt() and 0xFF)) pos++
        return bytes.decodeToString(start, pos)
    }

    fun expectKeyword(k: String) {
        val t = readToken()
        if (t != k) throw PdfException("Expected '$k' at ${pos - t.length}, found '$t'")
    }

    fun parseObject(): PdfObject {
        skipWhitespace()
        if (pos >= bytes.size) throw PdfException("Unexpected end of file")
        val c = peek()
        return when {
            c == '/'.code -> parseName()
            c == '('.code -> parseLiteralString()
            c == '<'.code && peek(1) == '<'.code -> parseDictOrStream()
            c == '<'.code -> parseHexString()
            c == '['.code -> parseArray()
            c == '+'.code || c == '-'.code || c == '.'.code || c in '0'.code..'9'.code -> parseNumberOrRef()
            else -> {
                val t = readToken()
                when (t) {
                    "true" -> PdfBool(true)
                    "false" -> PdfBool(false)
                    "null" -> PdfNull
                    "" -> throw PdfException("Unexpected character '${c.toChar()}' at $pos")
                    else -> throw PdfException("Unexpected keyword '$t' at ${pos - t.length}")
                }
            }
        }
    }

    private fun parseNumberOrRef(): PdfObject {
        val first = readToken()
        if (!isNumber(first)) throw PdfException("Malformed number '$first' at $pos")
        if (!first.all { it.isDigit() }) return PdfNumber(normalize(first))
        val save = pos
        skipWhitespace()
        val second = readToken()
        if (second.isNotEmpty() && second.all { it.isDigit() }) {
            skipWhitespace()
            if (peek() == 'R'.code && (pos + 1 >= bytes.size || !isRegular(peek(1)))) {
                pos++
                return PdfRef(first.toInt(), second.toInt())
            }
        }
        pos = save
        return PdfNumber(first)
    }

    private fun normalize(n: String): String {
        // "--5", "+.5" and similar forms occur in the wild; keep one sign.
        val neg = n.startsWith("-")
        val body = n.trimStart('+', '-')
        val fixed = if (body.startsWith(".")) "0$body" else body
        return if (neg) "-$fixed" else fixed
    }

    private fun parseName(): PdfName {
        pos++ // '/'
        val out = StringBuilder()
        val raw = ArrayList<Byte>()
        while (pos < bytes.size && isRegular(bytes[pos].toInt() and 0xFF)) {
            val b = bytes[pos]
            if (b == '#'.code.toByte() && pos + 2 < bytes.size && hexVal(bytes[pos + 1].toInt()) >= 0 && hexVal(bytes[pos + 2].toInt()) >= 0) {
                raw.add(((hexVal(bytes[pos + 1].toInt()) shl 4) or hexVal(bytes[pos + 2].toInt())).toByte())
                pos += 3
            } else {
                raw.add(b)
                pos++
            }
        }
        out.append(raw.toByteArray().decodeToString())
        return PdfName(out.toString())
    }

    private fun parseLiteralString(): PdfString {
        pos++ // '('
        val sourceStart = pos
        val out = ByteBuilder()
        var depth = 1
        while (pos < bytes.size) {
            val c = bytes[pos].toInt() and 0xFF
            pos++
            when (c) {
                '('.code -> { depth++; out.add(c) }
                ')'.code -> {
                    depth--
                    if (depth == 0) return PdfString(out.toByteArray()).also {
                        if (retainStringSource) it.sourceBytes = bytes.copyOfRange(sourceStart, pos - 1)
                    }
                    out.add(c)
                }
                '\\'.code -> {
                    if (pos >= bytes.size) break
                    val e = bytes[pos].toInt() and 0xFF
                    pos++
                    when (e) {
                        'n'.code -> out.add(10)
                        'r'.code -> out.add(13)
                        't'.code -> out.add(9)
                        'b'.code -> out.add(8)
                        'f'.code -> out.add(12)
                        '('.code, ')'.code, '\\'.code -> out.add(e)
                        '\r'.code -> if (peek() == '\n'.code) pos++
                        '\n'.code -> {}
                        in '0'.code..'7'.code -> {
                            var v = e - '0'.code
                            var n = 1
                            while (n < 3 && peek() in '0'.code..'7'.code) {
                                v = v * 8 + (peek() - '0'.code)
                                pos++; n++
                            }
                            out.add(v and 0xFF)
                        }
                        else -> out.add(e)
                    }
                }
                '\r'.code -> {
                    // An end-of-line in a string is a single line feed.
                    if (peek() == '\n'.code) pos++
                    out.add(10)
                }
                else -> out.add(c)
            }
        }
        throw PdfException("Unterminated string")
    }

    private fun parseHexString(): PdfString {
        pos++ // '<'
        val sourceStart = pos
        val out = ByteBuilder()
        var hi = -1
        while (pos < bytes.size) {
            val c = bytes[pos].toInt() and 0xFF
            pos++
            if (c == '>'.code) {
                if (hi >= 0) out.add(hi shl 4)
                return PdfString(out.toByteArray(), hex = true).also {
                    if (retainStringSource) it.sourceBytes = bytes.copyOfRange(sourceStart, pos - 1)
                }
            }
            if (isWhite(c)) continue
            val v = hexVal(c)
            if (v < 0) throw PdfException("Bad hex string character at ${pos - 1}")
            if (hi < 0) hi = v else { out.add((hi shl 4) or v); hi = -1 }
        }
        throw PdfException("Unterminated hex string")
    }

    private fun parseArray(): PdfArray {
        pos++ // '['
        val items = ArrayList<PdfObject>()
        while (true) {
            skipWhitespace()
            if (pos >= bytes.size) throw PdfException("Unterminated array")
            if (peek() == ']'.code) { pos++; return PdfArray(items) }
            items.add(parseObject())
        }
    }

    private fun parseDictOrStream(): PdfObject {
        pos += 2 // '<<'
        val map = LinkedHashMap<String, PdfObject>()
        while (true) {
            skipWhitespace()
            if (pos >= bytes.size) throw PdfException("Unterminated dictionary")
            if (peek() == '>'.code && peek(1) == '>'.code) { pos += 2; break }
            val key = parseObject() as? PdfName ?: throw PdfException("Dictionary key is not a name at $pos")
            skipWhitespace()
            if (peek() == '>'.code && peek(1) == '>'.code) { map[key.name] = PdfNull; pos += 2; break }
            map[key.name] = parseObject()
        }
        val dict = PdfDict(map)
        // A stream follows its dictionary with the keyword "stream" and one end-of-line.
        val save = pos
        skipWhitespace()
        if (startsWith("stream")) {
            pos += 6
            if (peek() == '\r'.code) pos++
            if (peek() == '\n'.code) pos++
            val start = pos
            val declared = streamLength(dict)
            val end = if (declared != null && declared >= 0 && start + declared <= bytes.size && endstreamFollows(start + declared)) {
                start + declared
            } else {
                // Wrong or missing /Length: up to the next "endstream" without its preceding end-of-line.
                val k = indexOf(ENDSTREAM, start)
                if (k < 0) throw PdfException("Stream without endstream")
                var e = k
                if (e > start && bytes[e - 1] == '\n'.code.toByte()) e--
                if (e > start && bytes[e - 1] == '\r'.code.toByte()) e--
                e
            }
            pos = end
            skipWhitespace()
            if (startsWith("endstream")) pos += 9
            lastStreamExtent = start until end
            return PdfStream(dict, bytes.copyOfRange(start, end))
        }
        pos = save
        return dict
    }

    private fun endstreamFollows(at: Int): Boolean {
        var p = at
        while (p < bytes.size && isWhite(bytes[p].toInt() and 0xFF)) p++
        return regionMatches(p, ENDSTREAM)
    }

    fun startsWith(k: String): Boolean = regionMatches(pos, k.encodeToByteArray())

    private fun regionMatches(at: Int, k: ByteArray): Boolean {
        if (at < 0 || at + k.size > bytes.size) return false
        for (i in k.indices) if (bytes[at + i] != k[i]) return false
        return true
    }

    fun indexOf(k: ByteArray, from: Int): Int = indexOf(bytes, k, from)

    /** Parses "num gen obj <object> endobj" at [pos]. */
    fun parseIndirect(): Triple<Int, Int, PdfObject> {
        val num = readToken().toIntOrNull() ?: throw PdfException("Expected object number at $pos")
        val gen = readToken().toIntOrNull() ?: throw PdfException("Expected generation at $pos")
        expectKeyword("obj")
        val obj = parseObject()
        return Triple(num, gen, obj)
    }

    private class ByteBuilder {
        private var buf = ByteArray(64)
        private var n = 0
        fun add(b: Int) {
            if (n == buf.size) buf = buf.copyOf(buf.size * 2)
            buf[n++] = b.toByte()
        }
        fun toByteArray() = buf.copyOf(n)
    }

    companion object {
        private val ENDSTREAM = "endstream".encodeToByteArray()

        fun isWhite(c: Int) = c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32
        fun isDelimiter(c: Int) = c == '('.code || c == ')'.code || c == '<'.code || c == '>'.code || c == '['.code ||
            c == ']'.code || c == '{'.code || c == '}'.code || c == '/'.code || c == '%'.code
        fun isRegular(c: Int) = c >= 0 && !isWhite(c) && !isDelimiter(c)

        fun hexVal(c: Int): Int = when (c) {
            in '0'.code..'9'.code -> c - '0'.code
            in 'a'.code..'f'.code -> c - 'a'.code + 10
            in 'A'.code..'F'.code -> c - 'A'.code + 10
            else -> -1
        }

        private fun isNumber(s: String): Boolean =
            s.isNotEmpty() && s.all { it.isDigit() || it == '.' || it == '-' || it == '+' } && s.any { it.isDigit() }

        fun indexOf(bytes: ByteArray, k: ByteArray, from: Int): Int {
            if (k.isEmpty()) return from
            var i = maxOf(0, from)
            val last = bytes.size - k.size
            outer@ while (i <= last) {
                if (bytes[i] == k[0]) {
                    for (j in 1 until k.size) if (bytes[i + j] != k[j]) { i++; continue@outer }
                    return i
                }
                i++
            }
            return -1
        }

        fun lastIndexOf(bytes: ByteArray, k: ByteArray, before: Int = bytes.size): Int {
            var i = minOf(before, bytes.size) - k.size
            outer@ while (i >= 0) {
                for (j in k.indices) if (bytes[i + j] != k[j]) { i--; continue@outer }
                return i
            }
            return -1
        }
    }
}
