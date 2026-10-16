package diw.wallet.core.document.official

import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * One signing point (簽核點定義) the wallet adds to an online approval file (.si, 104_sign_utf8 of the 文書及檔案管理電腦化
 * 作業規範): who signs (the name comes from the signing certificate), the action (異動別) and the opinion (簽核意見).
 * 簽核人員 is (機關?, 單位, 職稱, 姓名, 帳號, 角色?); 單位, 職稱 and 帳號 are written empty when not given.
 */
data class ApprovalPoint(
    /** 異動別, free text of up to 10 characters: 擬辦, 陳核, 會辦, 核定, 決行... */
    val action: String = "陳核",
    val opinion: String? = null,
    /** 單位 */
    val unit: String? = null,
    /** 職稱 */
    val title: String? = null,
    /** 角色 */
    val role: String? = null,
    /** 帳號 */
    val account: String? = null,
    /** 機關 */
    val organization: String? = null,
    /** 退文: this point returns the case to an earlier signer. */
    val returned: Boolean = false,
    val time: Instant = Clock.System.now(),
) {
    companion object {
        /**
         * Actions (異動別) for a signing point. The specification's examples are 擬辦, 陳核, 核定 (簽核流程) and 分文,
         * 送會 (異動資訊); the rest are the steps of the 文書處理手冊 (會辦, 核稿, 決行, 代決, 繕校). The field is free text.
         */
        val ACTIONS = listOf("擬辦", "陳核", "會辦", "核稿", "核定", "決行", "代決", "繕校", "送會", "分文")

        /** Longest 異動別 the specification allows (X(10)). */
        const val ACTION_MAX = 10

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
