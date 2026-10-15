package diw.wallet.core.document.derived

import diw.wallet.core.profile.bonds.MyDataText
import kotlinx.datetime.LocalDate

/** One trip of an entry and exit record: its item number, exit date and entry date (null when not given). */
data class EntryExitTrip(val item: Int, val exit: LocalDate?, val entry: LocalDate?)

/**
 * The certificate of entry and exit dates of the National Immigration Agency (入出國日期證明書), read from its text
 * layer: the person, the certificate itself and the table of trips. The table prints two halves side by side, so a
 * text line carries two numbered rows; rows are read by their item number (item 1 is the latest trip).
 */
data class EntryExitCertificate(
    val name: String?,
    val englishName: String?,
    val nationality: String?,
    val gender: String?,
    val idNumber: String?,
    val birthDate: LocalDate?,
    val serialNumber: String?,
    /** Date and time of issue as printed (the English line carries the time). */
    val issuedAt: String?,
    val issueDate: LocalDate?,
    val pages: Int?,
    override val periodFrom: LocalDate?,
    val periodTo: LocalDate?,
    val issuer: String?,
    val trips: List<EntryExitTrip>,
) : MovementRecord {
    override val inside: String get() = "境內"
    override val dayClaimPrefix: String get() = "inTaiwanOn"

    val latestExit: LocalDate? get() = trips.mapNotNull { it.exit }.maxOrNull()
    val latestEntry: LocalDate? get() = trips.mapNotNull { it.entry }.maxOrNull()

    /** Whether the latest departure was followed by a return; null without any departure. */
    val returnedFromLatestTrip: Boolean?
        get() {
            val exit = latestExit ?: return null
            val entry = latestEntry ?: return false
            return entry >= exit
        }

    /** The last day the record speaks for: the end of the queried period, else the date of issue. */
    override val coveredUntil: LocalDate? get() = periodTo ?: issueDate

    /**
     * Whether the person was in Taiwan at the end of [date], from the movements up to that day; null when [date] lies
     * outside the queried period or the record has no movements to tell from. With no movement before [date], the
     * first movement after it decides: an exit means the person was still in Taiwan, an entry that they were abroad.
     */
    fun inTaiwanOn(date: LocalDate): Boolean? {
        if (periodFrom != null && date < periodFrom) return null
        val end = coveredUntil
        if (end != null && date > end) return null
        // A departure and a return on the same day: the departure comes first.
        val events = trips.flatMap { t -> listOfNotNull(t.exit?.let { it to false }, t.entry?.let { it to true }) }
            .sortedWith(compareBy({ it.first }, { if (it.second) 1 else 0 }))
        return MovementRecord.insideOn(events, date)
    }

    override fun insideOn(date: LocalDate): Boolean? = inTaiwanOn(date)

    /** Whether the person was in Taiwan on the last day the record covers. */
    val inTaiwanAtEnd: Boolean? get() = coveredUntil?.let { inTaiwanOn(it) }

    companion object {
        private const val DATE = "(\\d{4}/\\d{1,2}/\\d{1,2})"
        private val row = Regex("(?<![0-9/])(\\d{1,3})\\s+(\\d{4}/\\d{1,2}/\\d{1,2}|-{3,})\\s+(\\d{4}/\\d{1,2}/\\d{1,2}|-{3,})")

        /** True when [text] is the text layer of an entry and exit record. */
        fun recognize(text: String): Boolean {
            val t = MyDataText.halfWidth(text)
            val title = "入出國日期證明書" in t || "CERTIFICATE OF ENTRY AND EXIT DATES" in t.uppercase()
            val table = ("出境日期" in t && "入境日期" in t) || ("Exit Dates" in t && "Entry Dates" in t)
            return table && (title || row.containsMatchIn(t))
        }

        fun parse(text: String): EntryExitCertificate? {
            if (!recognize(text)) return null
            val t = MyDataText.halfWidth(text)
            fun field(label: String, value: String = "(.+?)"): String? =
                Regex("(?<![A-Za-z])$label\\s*:\\s*$value(?=\\s+[^\\s:]{1,40}:|\\s{2,}|\\n|$)").find(t)?.groupValues?.get(1)?.trim()?.takeIf { it.isNotEmpty() }
            val trips = row.findAll(t).mapNotNull { m ->
                val exit = date(m.groupValues[2])
                val entry = date(m.groupValues[3])
                if (exit == null && entry == null) null else EntryExitTrip(m.groupValues[1].toInt(), exit, entry)
            }.distinctBy { it.item }.sortedBy { it.item }.toList()
            val period = Regex("之\\s*$DATE\\s*至\\s*$DATE").find(t) ?: Regex("from\\s+$DATE\\s+to\\s+$DATE", RegexOption.IGNORE_CASE).find(t)
            val issuedTime = Regex("Date of Issue\\s*:\\s*($DATE(?:\\s+\\d{1,2}:\\d{2}(?::\\d{2})?)?)", RegexOption.IGNORE_CASE).find(t)?.groupValues?.get(1)
            val issued = field("發證時間", DATE) ?: issuedTime?.substringBefore(' ')
            return EntryExitCertificate(
                name = field("姓名"),
                englishName = field("Name"),
                nationality = field("國籍"),
                gender = field("性別"),
                idNumber = field("(?:護照號碼或統一證號|統一證號|身分證統一編號)", "([A-Z0-9]{6,20})"),
                birthDate = field("出生日期(?:<年/月/日>)?", DATE)?.let { date(it) },
                serialNumber = Regex("證明書序號\\s*(?:\\(Serial Number\\))?\\s*:\\s*(\\d+)").find(t)?.groupValues?.get(1),
                issuedAt = issuedTime ?: issued,
                issueDate = issued?.let { date(it) },
                pages = Regex("本證明書共\\s*(\\d+)\\s*頁").find(t)?.groupValues?.get(1)?.toIntOrNull(),
                periodFrom = period?.groupValues?.get(1)?.let { date(it) },
                periodTo = period?.groupValues?.get(2)?.let { date(it) },
                issuer = if ("內政部移民署" in t) "內政部移民署" else null,
                trips = trips,
            )
        }

        private fun date(v: String): LocalDate? {
            val p = v.trim().split('/')
            if (p.size != 3) return null
            return runCatching { LocalDate(p[0].toInt(), p[1].toInt(), p[2].toInt()) }.getOrNull()
        }
    }
}
