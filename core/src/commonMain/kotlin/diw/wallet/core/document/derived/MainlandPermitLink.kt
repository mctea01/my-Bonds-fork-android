package diw.wallet.core.document.derived

import diw.wallet.core.profile.bonds.MyDataText
import kotlinx.datetime.DatePeriod
import kotlinx.datetime.LocalDate
import kotlinx.datetime.plus

/** A document the holder holds or has held, as a mainland China permit association lists it. */
data class LinkedPermit(val name: String, val number: String, val validUntil: LocalDate?)

/**
 * The association of a Taiwan resident's mainland travel permit and residence permit that the mainland China
 * National Immigration Administration issues as a signed PDF (台湾居民来往大陆通行证与居住证关联查询结果): the person,
 * every document they hold or have held (the travel permit with its expiry, the residence permit), the date of the
 * query and how long the file is valid from it (note 5: "从查询日期起，30天内有效"). Values are padded with spaces and
 * the paragraph wraps inside words, so it is read joined.
 */
data class MainlandPermitLink(
    val number: String?,
    val name: String?,
    val gender: String?,
    val birthDate: LocalDate?,
    /** "台湾" in "经系统核验，台湾居民". */
    val residentOf: String?,
    val permits: List<LinkedPermit>,
    val queryDate: LocalDate?,
    /** Days the file is valid from the query date, as its notes state. */
    val validDays: Int?,
    val pages: Int?,
    val issuer: String,
) : ParsedCertificate {
    /** The last day the file is valid: the query date plus [validDays] less one (the query day counts). */
    val validUntil: LocalDate? get() = if (queryDate != null && validDays != null) queryDate.plus(DatePeriod(days = validDays - 1)) else null

    val travelPermit: LinkedPermit? get() = permits.firstOrNull { "通行证" in it.name || "通行證" in it.name }
    val residencePermit: LinkedPermit? get() = permits.firstOrNull { "居住证" in it.name || "居住證" in it.name }

    override fun claims(): List<DerivedClaim> = buildList {
        name?.let { add(DerivedClaim("name", it, "姓名")) }
        gender?.let { add(DerivedClaim("gender", it, "性別")) }
        birthDate?.let { add(DerivedClaim("birthDate", it.toString(), "出生日期")) }
        travelPermit?.let { p ->
            add(DerivedClaim("travelPermitNumber", p.number, "台灣居民來往大陸通行證號碼"))
            p.validUntil?.let { add(DerivedClaim("travelPermitValidUntil", it.toString(), "通行證有效期至")) }
        }
        residencePermit?.let { p ->
            add(DerivedClaim("residencePermitNumber", p.number, "台灣居民居住證號碼"))
            p.validUntil?.let { add(DerivedClaim("residencePermitValidUntil", it.toString(), "居住證有效期至")) }
        }
        permits.filter { it !== travelPermit && it !== residencePermit }.forEachIndexed { i, p ->
            add(DerivedClaim("linkedDocument${i + 1}", p.name + " " + p.number + (p.validUntil?.let { "（有效期至 $it）" } ?: ""), "關聯證件 ${i + 1}"))
        }
        add(DerivedClaim("permitsLinked", if (travelPermit != null && residencePermit != null) "true" else "false", "通行證與居住證屬同一人"))
        number?.let { add(DerivedClaim("recordNumber", it, "編號")) }
        queryDate?.let { add(DerivedClaim("queryDate", it.toString(), "查詢日期")) }
        validUntil?.let { add(DerivedClaim("recordValidUntil", it.toString(), "文件有效期至")) }
    }

    companion object {
        private const val ISSUER = "中华人民共和国出入境管理局"
        private const val DATE = "(\\d{4})年(\\d{1,2})月(\\d{1,2})日"

        fun recognize(text: String): Boolean {
            val compact = MyDataText.halfWidth(text).replace(Regex("\\s+"), "")
            return ("通行证与居住证关联查询结果" in compact || "通行證與居住證關聯查詢結果" in compact) && "号码" in compact
        }

        fun parse(text: String): MainlandPermitLink? {
            if (!recognize(text)) return null
            val t = MyDataText.halfWidth(text)
            val lines = t.lines().map { it.trim() }.filter { it.isNotEmpty() }
            val zh = lines.joinToString("").replace(Regex("\\s+"), "")
            fun field(label: String) = Regex("(?:$label):([^,;。]+?)(?=[,;。]|$)").find(zh)?.groupValues?.get(1)?.ifEmpty { null }
            fun date(m: MatchResult?, from: Int = 1) = m?.let {
                runCatching { LocalDate(it.groupValues[from].toInt(), it.groupValues[from + 1].toInt(), it.groupValues[from + 2].toInt()) }.getOrNull()
            }
            // Each document: "<name>号码:<number>[,有效期至:<date>];" after "下列证件:".
            val list = zh.substringAfter("下列证件:", zh.substringAfter("下列證件:", ""))
            val permits = Regex("([\\u4e00-\\u9fff]{4,30}?)(?:号码|號碼):([A-Za-z0-9]{5,24})(?:,(?:有效期至|有效期限至|有效期):$DATE)?")
                .findAll(list).map { m -> LinkedPermit(m.groupValues[1], m.groupValues[2], date(m, 3)) }.toList()
            // The query date is the date line after the notes, near the page footer.
            val queryDate = lines.lastOrNull { Regex("^$DATE$").matches(it.replace(" ", "")) }?.let { date(Regex(DATE).find(it.replace(" ", ""))) }
            return MainlandPermitLink(
                number = Regex("(?:编号|編號):\\s*([A-Za-z0-9]{4,40})").find(t)?.groupValues?.get(1),
                name = field("姓名"),
                gender = field("性别|性別"),
                birthDate = date(Regex("出生日期:$DATE").find(zh)),
                residentOf = Regex("经系统核验,([\\u4e00-\\u9fff]{2,6}?)居民").find(zh)?.groupValues?.get(1),
                permits = permits,
                queryDate = queryDate,
                validDays = Regex("从查询日期起,(\\d{1,3})(?:天|日)内有效").find(zh)?.groupValues?.get(1)?.toIntOrNull(),
                pages = Regex("共\\s*(\\d+)\\s*页").find(t)?.groupValues?.get(1)?.toIntOrNull(),
                issuer = ISSUER,
            )
        }
    }
}
