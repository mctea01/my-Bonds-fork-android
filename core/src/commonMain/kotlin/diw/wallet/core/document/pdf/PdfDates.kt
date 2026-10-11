package diw.wallet.core.document.pdf

import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.UtcOffset
import kotlinx.datetime.toInstant
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Instant

/** PDF date strings (ISO 32000-1 7.9.4): D:YYYYMMDDHHmmSSOHH'mm'. */
object PdfDates {
    /** Epoch seconds of a PDF date, or null when it cannot be read. A missing offset is read as UTC. */
    fun parse(text: String?): Long? {
        if (text == null) return null
        val s = text.trim().removePrefix("D:")
        if (s.length < 4 || !s.take(4).all { it.isDigit() }) return null
        fun num(from: Int, len: Int, default: Int): Int =
            if (s.length >= from + len && s.substring(from, from + len).all { it.isDigit() }) s.substring(from, from + len).toInt() else default
        val year = num(0, 4, 0)
        val month = num(4, 2, 1).coerceIn(1, 12)
        val day = num(6, 2, 1).coerceIn(1, 31)
        val hour = num(8, 2, 0).coerceIn(0, 23)
        val minute = num(10, 2, 0).coerceIn(0, 59)
        val second = num(12, 2, 0).coerceIn(0, 59)
        var offsetSeconds = 0
        var i = 4
        while (i < s.length && s[i].isDigit()) i++
        if (i < s.length && (s[i] == '+' || s[i] == '-')) {
            val sign = if (s[i] == '-') -1 else 1
            val rest = s.substring(i + 1).filter { it.isDigit() }
            val oh = rest.take(2).toIntOrNull() ?: 0
            val om = rest.drop(2).take(2).toIntOrNull() ?: 0
            offsetSeconds = sign * (oh * 3600 + om * 60)
        }
        return runCatching {
            LocalDateTime(year, month, day, hour, minute, second).toInstant(UtcOffset(seconds = offsetSeconds)).epochSeconds
        }.getOrNull()
    }

    /** A PDF date for [at] in UTC. */
    fun format(at: Instant): String {
        val t = at.toLocalDateTime(TimeZone.UTC)
        fun p(v: Int, n: Int = 2) = v.toString().padStart(n, '0')
        return "D:" + p(t.year, 4) + p(t.month.ordinal + 1) + p(t.day) + p(t.hour) + p(t.minute) + p(t.second) + "Z"
    }
}
