package diw.wallet.core.util

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.Charset
import java.nio.charset.CodingErrorAction

/**
 * Text whose encoding is not declared: ZIP entry names without the UTF-8 flag (Windows in Taiwan writes Big5, in
 * mainland China GBK), download names a server sent as raw bytes, and percent-encoded names. Strict decoding is tried
 * first, so text that is already right is never changed.
 */
object TextEncodings {
    /** Legacy encodings tried in order when the bytes are not UTF-8; Big5 first, as most files come from Taiwan. */
    private val LEGACY = listOf("x-windows-950", "Big5-HKSCS", "Big5", "GB18030", "GBK", "Shift_JIS", "EUC-KR")
        .mapNotNull { runCatching { Charset.forName(it) }.getOrNull() }

    private fun strict(bytes: ByteArray, cs: Charset): String? = try {
        cs.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: CharacterCodingException) {
        null
    }

    /** Characters a file name in Chinese plausibly has: ASCII, common CJK ideographs and CJK or full-width punctuation. */
    private fun oddCharacters(s: String): Int = s.count { c ->
        !(c.code < 0x80 || c in '\u4E00'..'\u9FFF' || c in '\u3000'..'\u303F' || c in '\uFF00'..'\uFFEF' || c in '\u2010'..'\u2027')
    }

    /**
     * [bytes] as text: UTF-8 when [utf8] says so or the bytes are valid UTF-8, else the legacy encoding that reads
     * them with the fewest unusual characters (Big5 wins a tie), else ISO-8859-1 so nothing is lost.
     */
    fun decode(bytes: ByteArray, utf8: Boolean = false): String {
        if (utf8) return bytes.toString(Charsets.UTF_8)
        if (bytes.all { it >= 0 }) return bytes.toString(Charsets.US_ASCII)
        strict(bytes, Charsets.UTF_8)?.let { return it }
        val candidates = LEGACY.mapNotNull { cs -> strict(bytes, cs) }
        return candidates.minByOrNull { oddCharacters(it) } ?: bytes.toString(Charsets.ISO_8859_1)
    }

    /**
     * A name that went through the wrong decoder: UTF-8 or Big5 bytes read as ISO-8859-1 ("çè­.pdf"),
     * or still percent-encoded ("%E7%8D%8E.pdf"). Names that are fine are returned unchanged.
     */
    fun repairName(name: String): String {
        var s = name
        if (Regex("%[0-9A-Fa-f]{2}").containsMatchIn(s)) {
            percentDecode(s)?.let { s = it }
        }
        if (s.any { it.code in 0x80..0xFF } && s.all { it.code <= 0xFF }) {
            val bytes = s.toByteArray(Charsets.ISO_8859_1)
            val fixed = decode(bytes)
            if (oddCharacters(fixed) < oddCharacters(s)) s = fixed
        }
        return s
    }

    /** Percent-decoding to UTF-8 (or a legacy encoding); null when the result would not be text. */
    fun percentDecode(s: String): String? {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 3 <= s.length) {
                val v = s.substring(i + 1, i + 3).toIntOrNull(16)
                if (v != null) { out.write(v); i += 3; continue }
            }
            out.write(c.toString().toByteArray(Charsets.UTF_8))
            i++
        }
        return decode(out.toByteArray()).takeIf { it.none { ch -> ch == '\uFFFD' } }
    }

    /**
     * The file name a Content-Disposition header gives: filename* (RFC 6266 and 5987, with its charset) before
     * filename, repaired when a server sent raw bytes; null when the header names no file.
     */
    fun contentDispositionName(header: String?): String? {
        if (header.isNullOrBlank()) return null
        Regex("filename\\*\\s*=\\s*([^']*)'[^']*'([^;]+)", RegexOption.IGNORE_CASE).find(header)?.let { m ->
            val cs = runCatching { Charset.forName(m.groupValues[1].trim().ifEmpty { "UTF-8" }) }.getOrDefault(Charsets.UTF_8)
            val raw = m.groupValues[2].trim().trim('"')
            val out = java.io.ByteArrayOutputStream()
            var i = 0
            while (i < raw.length) {
                if (raw[i] == '%' && i + 3 <= raw.length) {
                    val v = raw.substring(i + 1, i + 3).toIntOrNull(16)
                    if (v != null) { out.write(v); i += 3; continue }
                }
                out.write(raw[i].code and 0xFF); i++
            }
            return out.toByteArray().toString(cs).takeIf { it.isNotBlank() }?.let(::baseName)
        }
        val m = Regex("filename\\s*=\\s*(\"([^\"]*)\"|([^;]+))", RegexOption.IGNORE_CASE).find(header) ?: return null
        val raw = (m.groupValues[2].ifEmpty { m.groupValues[3] }).trim()
        return raw.takeIf { it.isNotBlank() }?.let { baseName(repairName(it)) }
    }

    private fun baseName(s: String) = s.replace('\\', '/').substringAfterLast('/')
}
