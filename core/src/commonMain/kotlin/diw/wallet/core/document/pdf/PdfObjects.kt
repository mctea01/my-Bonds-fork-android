package diw.wallet.core.document.pdf

/** Thrown when a PDF cannot be read: broken syntax, a missing object, or an unsupported construct. */
open class PdfException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Thrown when an encrypted PDF needs a user password other than the one given. */
class PdfPasswordException(message: String) : PdfException(message)

/** PDF objects (ISO 32000-1 section 7.3). Strings keep their raw bytes; text decoding is up to the caller. */
sealed class PdfObject

object PdfNull : PdfObject() {
    override fun toString() = "null"
}

data class PdfBool(val value: Boolean) : PdfObject()

/** A number as written; integer and real access do not round silently. */
data class PdfNumber(val text: String) : PdfObject() {
    val isInteger: Boolean get() = text.none { it == '.' }
    val long: Long get() = text.toLongOrNull() ?: text.toDouble().toLong()
    val int: Int get() = long.toInt()
    val double: Double get() = text.toDouble()

    companion object {
        fun of(v: Long) = PdfNumber(v.toString())
        fun of(v: Int) = PdfNumber(v.toString())
    }
}

class PdfString(val bytes: ByteArray, val hex: Boolean = false) : PdfObject() {
    /** Populated only when a parser explicitly retains source spelling for zkPDF. */
    internal var sourceBytes: ByteArray? = null
    /** Text string (ISO 32000-1 7.9.2.2): UTF-16BE with BOM, UTF-8 with BOM (PDF 2.0), else PDFDocEncoding. */
    fun text(): String = PdfText.decode(bytes)

    override fun equals(other: Any?) = other is PdfString && other.bytes.contentEquals(bytes)
    override fun hashCode() = bytes.contentHashCode()
    override fun toString() = if (hex) "<hex ${bytes.size}>" else "(${text()})"
}

data class PdfName(val name: String) : PdfObject() {
    override fun toString() = "/$name"
}

class PdfArray(val items: List<PdfObject>) : PdfObject(), List<PdfObject> by items {
    override fun equals(other: Any?) = other is PdfArray && other.items == items
    override fun hashCode() = items.hashCode()
    override fun toString() = items.joinToString(" ", "[", "]")
}

class PdfDict(val entries: Map<String, PdfObject>) : PdfObject() {
    operator fun get(key: String): PdfObject? = entries[key]
    fun name(key: String): String? = (entries[key] as? PdfName)?.name
    fun has(key: String) = key in entries
    val keys: Set<String> get() = entries.keys

    fun with(key: String, value: PdfObject?): PdfDict =
        PdfDict(LinkedHashMap(entries).apply { if (value == null) remove(key) else put(key, value) })

    override fun equals(other: Any?) = other is PdfDict && other.entries == entries
    override fun hashCode() = entries.hashCode()
    override fun toString() = entries.entries.joinToString(" ", "<<", ">>") { "/${it.key} ${it.value}" }

    companion object {
        fun of(vararg pairs: Pair<String, PdfObject>) = PdfDict(linkedMapOf(*pairs))
    }
}

data class PdfRef(val num: Int, val gen: Int) : PdfObject() {
    override fun toString() = "$num $gen R"
}

/**
 * A stream: its dictionary and where its raw (still encoded) data lies. [data] is the raw slice; [decoded] applies
 * the filters this reader supports (FlateDecode with PNG or TIFF predictors, ASCIIHexDecode, ASCII85Decode).
 */
class PdfStream(val dict: PdfDict, val data: ByteArray) : PdfObject() {
    override fun toString() = "stream(${dict}, ${data.size} bytes)"
}

/** Text string decoding for PDF strings. */
object PdfText {
    fun decode(b: ByteArray): String = when {
        b.size >= 2 && b[0] == 0xFE.toByte() && b[1] == 0xFF.toByte() -> utf16be(b, 2)
        b.size >= 3 && b[0] == 0xEF.toByte() && b[1] == 0xBB.toByte() && b[2] == 0xBF.toByte() -> b.copyOfRange(3, b.size).decodeToString()
        else -> buildString { for (x in b) append(PDF_DOC[x.toInt() and 0xFF]) }
    }

    fun utf16be(b: ByteArray, from: Int = 0): String = buildString {
        var i = from
        while (i + 1 < b.size) {
            append(((b[i].toInt() and 0xFF) shl 8 or (b[i + 1].toInt() and 0xFF)).toChar())
            i += 2
        }
    }

    /** UTF-16BE with BOM, which any reader decodes; ASCII-only text stays one byte per character. */
    fun encode(s: String): ByteArray {
        if (s.all { it.code in 0x20..0x7E }) return s.encodeToByteArray()
        val out = ByteArray(2 + s.length * 2)
        out[0] = 0xFE.toByte(); out[1] = 0xFF.toByte()
        s.forEachIndexed { i, c ->
            out[2 + i * 2] = (c.code shr 8).toByte()
            out[3 + i * 2] = c.code.toByte()
        }
        return out
    }

    /** PDFDocEncoding: Latin-1 except 0x18-0x1F and 0x80-0xA0. */
    private val PDF_DOC: CharArray = CharArray(256) { it.toChar() }.also { t ->
        val low = "˘ˇˆ˙˝˛˚˜"
        for (i in 0 until 8) t[0x18 + i] = low[i]
        val high = "•†‡…—–ƒ⁄‹›−‰„“”‘" +
            "’‚™ﬁﬂŁŒŠŸŽıłœšž�€"
        for (i in high.indices) t[0x80 + i] = high[i]
    }
}
