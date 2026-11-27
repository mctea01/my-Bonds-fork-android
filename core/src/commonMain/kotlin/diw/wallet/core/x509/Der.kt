package diw.wallet.core.x509

import kotlin.time.Instant

/** A DER encoding the certificate reader could not follow. */
class DerException(message: String) : Exception(message)

/**
 * One DER element (X.690) read over a shared buffer: its tag class, constructed flag and tag number, and where its
 * content lies. Definite lengths only, as DER requires; indefinite lengths and lengths that run past their parent are
 * refused.
 */
class Der private constructor(
    val tagClass: Int,
    val constructed: Boolean,
    val tag: Int,
    private val src: ByteArray,
    private val start: Int,
    private val contentStart: Int,
    private val end: Int,
) {
    val content: ByteArray get() = src.copyOfRange(contentStart, end)
    val encoded: ByteArray get() = src.copyOfRange(start, end)
    val contentLength: Int get() = end - contentStart

    val universal: Boolean get() = tagClass == UNIVERSAL
    fun isUniversal(t: Int): Boolean = tagClass == UNIVERSAL && tag == t
    fun isContext(t: Int): Boolean = tagClass == CONTEXT && tag == t

    /** The elements inside a constructed element, or a primitive element's content read as elements. */
    fun children(): List<Der> = readAll(src, contentStart, end)

    /** The content of an explicitly tagged or wrapped element (an OCTET STRING or BIT STRING holding DER) read as one element. */
    fun inner(): Der = when {
        isUniversal(BIT_STRING) -> parse(bitStringBytes())
        constructed -> children().singleOrNull() ?: throw DerException("Expected one element inside tag $tag")
        else -> parse(content)
    }

    fun oid(): String {
        if (!isUniversal(OID)) throw DerException("Expected an OBJECT IDENTIFIER, found tag $tag")
        return decodeOid(src, contentStart, end)
    }

    fun bool(): Boolean {
        if (!isUniversal(BOOLEAN) || contentLength != 1) throw DerException("Expected a BOOLEAN")
        return src[contentStart].toInt() != 0
    }

    /** A small INTEGER (or ENUMERATED) value. */
    fun long(): Long {
        if (contentLength == 0 || contentLength > 8) throw DerException("INTEGER out of range")
        var v = src[contentStart].toLong()
        for (i in contentStart + 1 until end) v = (v shl 8) or (src[i].toLong() and 0xFF)
        return v
    }

    /** The bytes of a BIT STRING, without the unused-bits octet. */
    fun bitStringBytes(): ByteArray {
        if (contentLength == 0) throw DerException("Empty BIT STRING")
        return src.copyOfRange(contentStart + 1, end)
    }

    /** The number of unused bits in the last octet of a BIT STRING. */
    fun unusedBits(): Int = if (contentLength == 0) 0 else src[contentStart].toInt() and 0xFF

    /** Whether bit [n] (0 is the most significant bit of the first octet) of a BIT STRING is set. */
    fun bit(n: Int): Boolean {
        val bytes = bitStringBytes()
        val i = n / 8
        return i < bytes.size && (bytes[i].toInt() shr (7 - n % 8)) and 1 == 1
    }

    /** The text of a string element of any ASN.1 string type. */
    fun string(): String {
        val c = content
        if (!isString) throw DerException("Expected a string, found tag $tag")
        return when (tag) {
            BMP_STRING -> buildString { for (i in 0 until c.size / 2) append(((c[2 * i].toInt() and 0xFF shl 8) or (c[2 * i + 1].toInt() and 0xFF)).toChar()) }
            UNIVERSAL_STRING -> buildString {
                for (i in 0 until c.size / 4) {
                    val cp = (c[4 * i].toInt() and 0xFF shl 24) or (c[4 * i + 1].toInt() and 0xFF shl 16) or
                        (c[4 * i + 2].toInt() and 0xFF shl 8) or (c[4 * i + 3].toInt() and 0xFF)
                    if (cp < 0x10000) append(cp.toChar()) else {
                        val v = cp - 0x10000
                        append((0xD800 + (v shr 10)).toChar()); append((0xDC00 + (v and 0x3FF)).toChar())
                    }
                }
            }
            // TeletexString is used by some CAs for UTF-8 text; it is read as UTF-8 when it is valid UTF-8.
            UTF8_STRING -> c.decodeToString()
            else -> runCatching { c.decodeToString(throwOnInvalidSequence = true) }.getOrElse { CharArray(c.size) { (c[it].toInt() and 0xFF).toChar() }.concatToString() }
        }
    }

    val isString: Boolean get() = universal && tag in STRING_TAGS

    /** UTCTime or GeneralizedTime. */
    fun time(): Instant {
        val s = content.decodeToString()
        val (year, rest) = when (tag) {
            UTC_TIME -> {
                if (s.length < 11) throw DerException("Bad UTCTime")
                val yy = s.substring(0, 2).toInt()
                (if (yy >= 50) 1900 + yy else 2000 + yy) to s.substring(2)
            }
            GENERALIZED_TIME -> {
                if (s.length < 13) throw DerException("Bad GeneralizedTime")
                s.substring(0, 4).toInt() to s.substring(4)
            }
            else -> throw DerException("Expected a time, found tag $tag")
        }
        val month = rest.substring(0, 2)
        val day = rest.substring(2, 4)
        val hour = rest.substring(4, 6)
        val minute = rest.substring(6, 8)
        var i = 8
        val second = if (rest.length >= 10 && rest[8].isDigit()) rest.substring(8, 10).also { i = 10 } else "00"
        var fraction = ""
        if (i < rest.length && (rest[i] == '.' || rest[i] == ',')) {
            val j = rest.indexOfFirst { it == 'Z' || it == '+' || it == '-' }.takeIf { it > i } ?: rest.length
            fraction = rest.substring(i, j).replace(',', '.')
            i = j
        }
        val zone = rest.substring(i).let { z ->
            when {
                z.isEmpty() || z == "Z" -> "Z"
                z.length == 5 -> z.substring(0, 3) + ":" + z.substring(3)
                else -> throw DerException("Bad time zone in $s")
            }
        }
        return Instant.parse("${year.toString().padStart(4, '0')}-$month-${day}T$hour:$minute:$second$fraction$zone")
    }

    companion object {
        const val UNIVERSAL = 0
        const val APPLICATION = 1
        const val CONTEXT = 2
        const val PRIVATE = 3

        const val BOOLEAN = 1
        const val INTEGER = 2
        const val BIT_STRING = 3
        const val OCTET_STRING = 4
        const val NULL = 5
        const val OID = 6
        const val ENUMERATED = 10
        const val UTF8_STRING = 12
        const val SEQUENCE = 16
        const val SET = 17
        const val NUMERIC_STRING = 18
        const val PRINTABLE_STRING = 19
        const val TELETEX_STRING = 20
        const val IA5_STRING = 22
        const val UTC_TIME = 23
        const val GENERALIZED_TIME = 24
        const val VISIBLE_STRING = 26
        const val UNIVERSAL_STRING = 28
        const val BMP_STRING = 30
        private val STRING_TAGS = setOf(UTF8_STRING, NUMERIC_STRING, PRINTABLE_STRING, TELETEX_STRING, 21, IA5_STRING, 25, VISIBLE_STRING, 27, UNIVERSAL_STRING, BMP_STRING)

        private const val MAX_DEPTH_TEXT = 12

        /** The single element encoded in [bytes]; trailing bytes are refused. */
        fun parse(bytes: ByteArray): Der {
            val all = readAll(bytes, 0, bytes.size)
            return all.singleOrNull() ?: throw DerException(if (all.isEmpty()) "No DER element" else "Trailing data after the DER element")
        }

        fun readAll(src: ByteArray, from: Int, to: Int): List<Der> {
            val out = mutableListOf<Der>()
            var pos = from
            while (pos < to) {
                val e = readOne(src, pos, to)
                out.add(e)
                pos = e.end
            }
            return out
        }

        private fun readOne(src: ByteArray, at: Int, limit: Int): Der {
            var pos = at
            if (pos >= limit) throw DerException("Truncated DER")
            val first = src[pos++].toInt() and 0xFF
            val cls = first shr 6
            val constructed = first and 0x20 != 0
            var tag = first and 0x1F
            if (tag == 0x1F) {
                tag = 0
                var n = 0
                while (true) {
                    if (pos >= limit || ++n > 4) throw DerException("Bad high tag number")
                    val b = src[pos++].toInt() and 0xFF
                    tag = (tag shl 7) or (b and 0x7F)
                    if (b and 0x80 == 0) break
                }
            }
            if (pos >= limit) throw DerException("Truncated DER length")
            val l0 = src[pos++].toInt() and 0xFF
            val length = when {
                l0 < 0x80 -> l0
                l0 == 0x80 -> throw DerException("Indefinite length is not DER")
                else -> {
                    val n = l0 and 0x7F
                    if (n > 4 || pos + n > limit) throw DerException("Bad DER length")
                    var v = 0L
                    repeat(n) { v = (v shl 8) or (src[pos++].toLong() and 0xFF) }
                    if (v > Int.MAX_VALUE) throw DerException("DER length too large")
                    v.toInt()
                }
            }
            if (length < 0 || pos + length > limit) throw DerException("DER element runs past its end")
            return Der(cls, constructed, tag, src, at, pos, pos + length)
        }

        fun decodeOid(bytes: ByteArray, from: Int = 0, to: Int = bytes.size): String {
            if (to <= from) throw DerException("Empty OBJECT IDENTIFIER")
            val parts = mutableListOf<String>()
            var v = 0L
            var first = true
            for (i in from until to) {
                val b = bytes[i].toInt() and 0xFF
                v = (v shl 7) or (b and 0x7F).toLong()
                if (v < 0) throw DerException("OBJECT IDENTIFIER arc too large")
                if (b and 0x80 == 0) {
                    if (first) {
                        val a = if (v < 40) 0 else if (v < 80) 1 else 2
                        parts.add(a.toString()); parts.add((v - 40L * a).toString())
                        first = false
                    } else parts.add(v.toString())
                    v = 0
                }
            }
            return parts.joinToString(".")
        }

        fun hex(b: ByteArray): String = b.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

        /** Hex in colon-separated upper-case pairs, as certificate viewers show identifiers. */
        fun colonHex(b: ByteArray): String = b.joinToString(":") { (it.toInt() and 0xFF).toString(16).padStart(2, '0').uppercase() }
    }

    /**
     * A one-line outline of this element and what it holds (types, OIDs with their names, strings, small integers,
     * the length of binary values), for extensions the reader does not know.
     */
    fun outline(depth: Int = 0): String {
        if (depth > MAX_DEPTH_TEXT) return "..."
        val name = when {
            tagClass == CONTEXT -> "[$tag]"
            tagClass == APPLICATION -> "[APPLICATION $tag]"
            tagClass == PRIVATE -> "[PRIVATE $tag]"
            else -> when (tag) {
                BOOLEAN -> "BOOLEAN"; INTEGER -> "INTEGER"; BIT_STRING -> "BIT STRING"; OCTET_STRING -> "OCTET STRING"
                NULL -> "NULL"; OID -> "OID"; ENUMERATED -> "ENUMERATED"; SEQUENCE -> "SEQUENCE"; SET -> "SET"
                UTC_TIME -> "UTCTime"; GENERALIZED_TIME -> "GeneralizedTime"
                else -> if (isString) "String" else "tag $tag"
            }
        }
        val value = runCatching {
            when {
                constructed -> "{ " + children().joinToString(", ") { it.outline(depth + 1) } + " }"
                universal && tag == OID -> oid().let { o -> X509Names.oid(o)?.let { "$o ($it)" } ?: o }
                universal && tag == BOOLEAN -> bool().toString().uppercase()
                universal && (tag == INTEGER || tag == ENUMERATED) -> if (contentLength <= 8) long().toString() else "0x" + hex(content)
                universal && tag == NULL -> ""
                isString -> "\"" + string() + "\""
                universal && (tag == UTC_TIME || tag == GENERALIZED_TIME) -> time().toString()
                universal && tag == OCTET_STRING -> nested() ?: "${contentLength} bytes 0x${hex(content.take(32).toByteArray())}${if (contentLength > 32) "..." else ""}"
                universal && tag == BIT_STRING -> "${(contentLength - 1) * 8 - unusedBits()} bits 0x${hex(bitStringBytes().take(32).toByteArray())}${if (contentLength > 33) "..." else ""}"
                tagClass == CONTEXT && contentLength in 1..256 && content.all { it in 0x20..0x7E } -> "\"" + content.decodeToString() + "\""
                else -> "${contentLength} bytes 0x${hex(content.take(32).toByteArray())}${if (contentLength > 32) "..." else ""}"
            }
        }.getOrElse { "${contentLength} bytes" }
        return if (value.isEmpty()) name else "$name $value"
    }

    /** An OCTET STRING whose content is itself one DER element, outlined; null otherwise. */
    private fun nested(): String? = runCatching { parse(content).takeIf { it.constructed }?.outline(1) }.getOrNull()
}
