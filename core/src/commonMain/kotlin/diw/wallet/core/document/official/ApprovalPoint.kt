package diw.wallet.core.document.official

import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * One signing point (簽核點定義) the wallet adds to an online approval file (.si, 文書處理手冊 104_sign DTD): who signs
 * (the name comes from the signing certificate), the action (異動別) and the opinion (簽核意見).
 */
data class ApprovalPoint(
    /** 異動別: 呈核, 核閱, 會辦, 核稿, 簽核, 決行... */
    val action: String = "簽核",
    val opinion: String? = null,
    /** 單位 */
    val unit: String? = null,
    /** 職稱 */
    val title: String? = null,
    /** 角色 */
    val role: String? = null,
    /** 帳號 */
    val account: String? = null,
    val time: Instant = Clock.System.now(),
) {
    companion object {
        /** Actions (異動別) the official document handbook uses for a signing point. */
        val ACTIONS = listOf("簽核", "呈核", "核閱", "核稿", "會辦", "決行", "代決", "陳閱")

        private val taipei by lazy { runCatching { TimeZone.of("Asia/Taipei") }.getOrDefault(TimeZone.UTC) }

        /** "11510161230": ROC year (three digits), month, day, hour and minute in Taipei time, as 簽章時間 is written. */
        fun rocTime(time: Instant): String {
            val t = time.toLocalDateTime(taipei)
            fun two(n: Int) = n.toString().padStart(2, '0')
            return (t.year - 1911).toString().padStart(3, '0') + two(t.month.ordinal + 1) + two(t.day) + two(t.hour) + two(t.minute)
        }

        /** The instant of a 簽章時間 or 產生時間 value (ROC year, month, day, hour, minute, seconds optional); null when unreadable. */
        fun parseRocTime(raw: String?): Instant? {
            val m = Regex("^(\\d{2,3})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?$").find(raw?.trim() ?: return null) ?: return null
            val g = m.groupValues
            return runCatching {
                LocalDateTime(g[1].toInt() + 1911, g[2].toInt(), g[3].toInt(), g[4].toInt(), g[5].toInt(), g[6].ifEmpty { "0" }.toInt()).toInstant(taipei)
            }.getOrNull()
        }

        /** 檔案格式 of a file in an approval's file list, from its extension. */
        fun fileFormat(name: String): String = when (val ext = name.substringAfterLast('.', "").lowercase()) {
            "doc", "docx" -> "WORD"
            "xls", "xlsx" -> "EXCEL"
            "ppt", "pptx" -> "POWERPOINT"
            "tif", "tiff" -> "TIFF"
            "jpg", "jpeg" -> "JPG"
            "odt", "ods", "odp" -> "ODF"
            "" -> "OTHER"
            else -> ext.uppercase()
        }
    }
}
