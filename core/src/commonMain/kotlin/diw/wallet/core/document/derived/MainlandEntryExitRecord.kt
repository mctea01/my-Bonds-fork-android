package diw.wallet.core.document.derived

import diw.wallet.core.profile.bonds.MyDataText
import kotlinx.datetime.LocalDate

/**
 * A record of border crossings read from a document: the period it speaks for and whether the person was inside on
 * a day of it. Implemented by the Taiwan certificate of entry and exit dates and the mainland China record.
 */
sealed interface MovementRecord {
    /** The territory the record is about, as the holder reads it ("境內" for Taiwan, "中國大陸境內"). */
    val inside: String

    /** The claim name prefix of the answer for a day ("inTaiwanOn", "inMainlandOn"). */
    val dayClaimPrefix: String
    val periodFrom: LocalDate?
    val coveredUntil: LocalDate?

    /** Whether the person was inside at the end of [date]; null outside the queried period or without movements. */
    fun insideOn(date: LocalDate): Boolean?

    companion object {
        /** The record [text] holds, of either kind; null for other documents. */
        fun parse(text: String): MovementRecord? = EntryExitCertificate.parse(text) ?: MainlandEntryExitRecord.parse(text)

        /**
         * Inside or not at the end of [date] from [events] (date, true for an arrival, in the order they happened):
         * the last movement up to that day decides; with none before it, the first one after it does (a departure
         * means the person was inside).
         */
        internal fun insideOn(events: List<Pair<LocalDate, Boolean>>, date: LocalDate): Boolean? {
            if (events.isEmpty()) return null
            events.lastOrNull { it.first <= date }?.let { return it.second }
            return !events.first().second
        }
    }
}

/** One crossing of a mainland China entry and exit record (出入境记录): leaving (出境) or arriving (入境). */
data class MainlandMovement(
    /** The row number; 1 is the latest movement. */
    val item: Int,
    val arrival: Boolean,
    val date: LocalDate,
    val documentName: String?,
    val documentNumber: String?,
    val port: String?,
    val flight: String?,
)

/**
 * The entry and exit record the mainland China National Immigration Administration issues as a signed PDF
 * (出入境记录查询结果（电子文件）), read from its text layer: the person, the record itself and every movement of the
 * queried period, oldest included. Each row prints the document name on the lines around it ("台湾居民来往大陆" before,
 * "通行证" after); the flight number is missing for crossings by land or sea, and older rows may lack more.
 */
data class MainlandEntryExitRecord(
    val number: String?,
    val queryDate: LocalDate?,
    val name: String?,
    val gender: String?,
    val birthDate: LocalDate?,
    /** The document the record was queried with ("台湾居民来往大陆通行证") and its number. */
    val documentLabel: String?,
    val documentNumber: String?,
    override val periodFrom: LocalDate?,
    val periodTo: LocalDate?,
    /** Date and time the file was made, as printed. */
    val madeAt: String?,
    val pages: Int?,
    val issuer: String,
    /** Latest first, as printed. */
    val movements: List<MainlandMovement>,
) : MovementRecord {
    override val inside: String get() = "中國大陸境內"
    override val dayClaimPrefix: String get() = "inMainlandOn"
    override val coveredUntil: LocalDate? get() = periodTo ?: queryDate

    val latestArrival: LocalDate? get() = movements.filter { it.arrival }.maxOfOrNull { it.date }
    val latestDeparture: LocalDate? get() = movements.filter { !it.arrival }.maxOfOrNull { it.date }

    /** Whether the person was in mainland China on the last day the record covers. */
    val insideAtEnd: Boolean? get() = coveredUntil?.let { insideOn(it) }

    override fun insideOn(date: LocalDate): Boolean? {
        if (periodFrom != null && date < periodFrom) return null
        val end = coveredUntil
        if (end != null && date > end) return null
        // Rows are numbered latest first, which also orders two crossings on the same day.
        val events = movements.sortedWith(compareBy({ it.date }, { -it.item })).map { it.date to it.arrival }
        return MovementRecord.insideOn(events, date)
    }

    companion object {
        private const val ISSUER = "中华人民共和国出入境管理局"
        private val row = Regex("^\\s*(\\d{1,3})\\s+(出境|入境)\\s+(\\d{4})-(\\d{1,2})-(\\d{1,2})(?:\\s+(.*))?$")
        private val flight = Regex("^[A-Z0-9]{2}\\d{1,5}[A-Z]?$")
        private val number = Regex("^[A-Za-z]{0,2}\\d[A-Za-z0-9]{4,19}$")
        private const val DATE = "(\\d{4})\\s*年\\s*(\\d{1,2})\\s*月\\s*(\\d{1,2})\\s*日"

        /** True when [text] is the text layer of a mainland China entry and exit record. */
        fun recognize(text: String): Boolean {
            val t = MyDataText.halfWidth(text)
            return ("出入境记录查询结果" in t || "出入境記錄查詢結果" in t) && t.lines().any { row.matches(it) || "出入境记录" in it }
        }

        fun parse(text: String): MainlandEntryExitRecord? {
            if (!recognize(text)) return null
            val t = MyDataText.halfWidth(text)
            val lines = t.lines().map { it.trim() }
            fun field(label: String, value: String = "([^,，\\s][^,，]*?)"): String? =
                Regex("$label\\s*:\\s*$value\\s*(?=[,，]|\\s{2,}|$)", RegexOption.MULTILINE).find(t)?.groupValues?.get(1)?.trim()?.takeIf { it.isNotEmpty() }
            fun dateOf(m: MatchResult?, from: Int = 1): LocalDate? = m?.let {
                runCatching { LocalDate(it.groupValues[from].toInt(), it.groupValues[from + 1].toInt(), it.groupValues[from + 2].toInt()) }.getOrNull()
            }
            val document = Regex("([\\u4e00-\\u9fff]{2,20}?)(?:号码|號碼)\\s*:\\s*([A-Za-z0-9]{5,20})").find(t)
            val period = Regex("在\\s*$DATE\\s*至\\s*$DATE\\s*期间").find(t)
            return MainlandEntryExitRecord(
                number = Regex("编号\\s*:\\s*([A-Za-z0-9]{4,40})").find(t)?.groupValues?.get(1),
                queryDate = dateOf(Regex("查询日期\\s*:\\s*$DATE").find(t)),
                name = field("查询人姓名"),
                gender = field("性别"),
                birthDate = dateOf(Regex("出生日期\\s*:\\s*$DATE").find(t)),
                documentLabel = document?.groupValues?.get(1),
                documentNumber = document?.groupValues?.get(2),
                periodFrom = dateOf(period),
                periodTo = dateOf(period, 4),
                madeAt = Regex("制作日期\\s*:\\s*(\\d{4}年\\d{1,2}月\\d{1,2}日(?:\\d{1,2}时\\d{1,2}分)?)").find(t)?.groupValues?.get(1),
                pages = Regex("共\\s*(\\d+)\\s*页").find(t)?.groupValues?.get(1)?.toIntOrNull(),
                issuer = ISSUER,
                movements = movements(lines),
            )
        }

        /** The rows, with the document name gathered from the short lines between rows. */
        private fun movements(lines: List<String>): List<MainlandMovement> {
            val rows = lines.indices.filter { row.matches(lines[it]) }
            if (rows.isEmpty()) return emptyList()
            // A line of a wrapped document name: short, no digits, no label or punctuation of the notes.
            fun namePart(l: String) = l.isNotEmpty() && l.length <= 20 && l.none { it.isDigit() } && ':' !in l && '。' !in l &&
                "序号" !in l && "出入境" !in l
            val before = HashMap<Int, MutableList<String>>()
            val after = HashMap<Int, MutableList<String>>()
            rows.forEachIndexed { k, r ->
                val start = if (k == 0) (r - 1 downTo 0).takeWhile { namePart(lines[it]) }.lastOrNull() ?: r else rows[k - 1] + 1
                val parts = (start until r).map { lines[it] }.filter { namePart(it) }
                if (k == 0) {
                    before.getOrPut(r) { mutableListOf() }.addAll(parts)
                } else {
                    // The lines between two rows: the end of the previous row's wrapped name (when it has a start
                    // before its row), then the start of this one's.
                    val prev = rows[k - 1]
                    val split = if (parts.size >= 2 && !before[prev].isNullOrEmpty()) 1 else 0
                    after.getOrPut(prev) { mutableListOf() }.addAll(parts.take(split))
                    before.getOrPut(r) { mutableListOf() }.addAll(parts.drop(split))
                }
            }
            val last = rows.last()
            if (!before[last].isNullOrEmpty()) {
                lines.drop(last + 1).firstOrNull()?.takeIf { namePart(it) }?.let { after.getOrPut(last) { mutableListOf() }.add(it) }
            }
            return rows.mapNotNull { r ->
                val m = row.matchEntire(lines[r]) ?: return@mapNotNull null
                val date = runCatching { LocalDate(m.groupValues[3].toInt(), m.groupValues[4].toInt(), m.groupValues[5].toInt()) }.getOrNull()
                    ?: return@mapNotNull null
                val rest = m.groupValues[6].trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.toMutableList()
                val docNumber = rest.firstOrNull()?.takeIf { number.matches(it) }?.also { rest.removeAt(0) }
                val flightNo = rest.lastOrNull()?.takeIf { flight.matches(it) && it.any { c -> c.isLetter() } }
                    ?.also { rest.removeAt(rest.lastIndex) }
                val name = (before[r].orEmpty() + after[r].orEmpty()).joinToString("").ifEmpty { null }
                MainlandMovement(
                    item = m.groupValues[1].toInt(),
                    arrival = m.groupValues[2] == "入境",
                    date = date,
                    documentName = name,
                    documentNumber = docNumber,
                    port = rest.joinToString(" ").ifEmpty { null },
                    flight = flightNo,
                )
            }.distinctBy { it.item }.sortedBy { it.item }
        }
    }
}
