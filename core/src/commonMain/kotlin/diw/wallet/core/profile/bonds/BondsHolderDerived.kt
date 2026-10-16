package diw.wallet.core.profile.bonds

import diw.wallet.core.did.DidKeys
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.w3c.SdJwtDisclosures
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * A verifier's question for a holder-derived credential (bonds_rule in the signed request object): a rule id and
 * string parameters. The same rule is signed into the credential, so the verifier can check that the answer is to the
 * question it asked.
 */
data class DerivedRule(val id: String, val params: Map<String, String>) {
    /** Why the wallet refuses the rule, or null when it is one this wallet computes with exactly the expected parameters. */
    fun problem(): String? {
        val required = REQUIRED[id] ?: return "本錢包不會回答這種問題（$id）"
        required.firstOrNull { params[it].isNullOrBlank() }?.let { return "查驗方的問題缺少參數 $it" }
        val allowed = required + OPTIONAL[id].orEmpty()
        params.keys.firstOrNull { it !in allowed }?.let { return "查驗方的問題帶有不允許的參數 $it" }
        return null
    }

    /** The question as the holder reads it on the consent screen. */
    val question: String
        get() = when (id) {
            INCOME -> "${params["tax_year"]} 年的所得是否不超過新臺幣 ${grouped(params["ceiling_twd"].orEmpty())} 元？"
            INSURANCE -> "${params["on_date"]} 當天是否有勞保？"
            HOUSEHOLD -> params["min_months"]?.takeIf { it.isNotBlank() }
                ?.let { "戶籍是否設在${params["city"]}滿 $it 個月？" } ?: "戶籍是否設在${params["city"]}？"
            else -> id
        }

    fun toJson(): JsonObject = buildJsonObject {
        put("id", id)
        putJsonObject("params") { params.toSortedMap().forEach { (k, v) -> put(k, v) } }
    }

    companion object {
        const val INCOME = "income-ceiling/v1"
        const val INSURANCE = "insurance-active/v1"
        const val HOUSEHOLD = "household-city/v1"

        /** Parameters each rule needs; anything else is refused, so a verifier cannot have other fields echoed under the holder's signature. */
        private val REQUIRED = mapOf(INCOME to listOf("tax_year", "ceiling_twd"), INSURANCE to listOf("on_date"), HOUSEHOLD to listOf("city"))
        private val OPTIONAL = mapOf(HOUSEHOLD to listOf("min_months"))

        fun parse(e: JsonElement?): DerivedRule? {
            val o = e as? JsonObject ?: return null
            val id = o.str("id")?.takeIf { it.isNotEmpty() } ?: return null
            val raw = o.obj("params") ?: return null
            val params = raw.mapValues { (_, v) -> (v as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null }
            return DerivedRule(id, params)
        }

        private fun grouped(digits: String): String = digits.toLongOrNull()?.let { n ->
            n.toString().reversed().chunked(3).joinToString(",").reversed()
        } ?: digits
    }
}

/**
 * A credential type a MyData document derives into, as Bonds and its verifier define it: the vct (Type Metadata
 * published under bonds-tw.github.io), the SRI integrity of that metadata pinned by the verifier, the claims, which of
 * them are predicates, and the rules the type answers.
 */
data class HolderDerivedType(
    val vct: String,
    val integrity: String,
    val documentType: String,
    val title: String,
    val claims: List<String>,
    val rules: List<String>,
    val claimLabels: Map<String, String>,
)

object HolderDerivedTypes {
    const val VCT_BASE = "https://bonds-tw.github.io/vct/"
    const val INCOME = "mydata-income"
    const val LABOR_INSURANCE = "mydata-labor-insurance"
    const val HOUSEHOLD = "mydata-household"

    val income = HolderDerivedType(
        VCT_BASE + "mydata-income/v1.json", "sha256-UWf/U6jOpKCHfZxeIMTh0snMIglSOjDdxy76cI/BENA=", INCOME, "個人所得資料",
        listOf("tax_year", "payer_count", "income_within_ceiling"), listOf(DerivedRule.INCOME),
        mapOf("tax_year" to "所得年度", "payer_count" to "扣繳單位數", "income_within_ceiling" to "所得在門檻內"),
    )
    val laborInsurance = HolderDerivedType(
        VCT_BASE + "mydata-labor-insurance/v1.json", "sha256-qtCc76IWmYLsuHXKYGXmHL00MI4vjKWvSwuzjWKEXPs=", LABOR_INSURANCE, "被保險人投保資料",
        listOf("on_date", "insured_on_date"), listOf(DerivedRule.INSURANCE),
        mapOf("on_date" to "查詢日期", "insured_on_date" to "當天有勞保"),
    )
    val household = HolderDerivedType(
        VCT_BASE + "mydata-household/v1.json", "sha256-d8lnX7PMXJyryDSHYcHYPEa9TlKEZX9DUgRWJ9jSEk0=", HOUSEHOLD, "現戶全戶戶籍資料",
        listOf("registered_in_city", "registered_at_least_months"), listOf(DerivedRule.HOUSEHOLD),
        mapOf("registered_in_city" to "設籍於指定縣市", "registered_at_least_months" to "設籍滿指定月數"),
    )

    val all = listOf(income, laborInsurance, household)

    fun byVct(vct: String?): HolderDerivedType? = all.firstOrNull { it.vct == vct }
    fun byDocumentType(type: String?): HolderDerivedType? = all.firstOrNull { it.documentType == type }
}

/** One insured period, ISO dates; [end] null means still in force when the document was produced. */
data class CoveragePeriod(val start: String, val end: String?)

/** What a parser read from a document: string fields and, for tables, dated periods. */
data class ParsedSource(val documentType: String, val parser: String, val fields: Map<String, String>, val periods: List<CoveragePeriod> = emptyList())

/** The document cannot answer: not this document, a field missing, or the rule and the document do not meet. */
class HolderDerivedException(message: String) : Exception(message)

/** Text helpers for MyData documents (Bonds MyDataTextField). */
object MyDataText {
    private fun isColon(c: Char) = c == '：' || c == ':'

    /** The value after "[label]：" (either colon width) on the first line that has one. */
    fun value(label: String, text: String): String? {
        for (line in text.lines()) {
            val at = line.indexOf(label)
            if (at < 0) continue
            val rest = line.substring(at + label.length)
            val colon = rest.indexOfFirst { isColon(it) }
            if (colon < 0) continue
            var value = rest.substring(colon + 1).trim()
            // A line can carry two fields: "所得年度：113  所得人：王小明".
            val gap = listOf(value.indexOf("  "), value.indexOf('\t'), value.indexOf('　')).filter { it >= 0 }.minOrNull()
            if (gap != null) value = value.substring(0, gap)
            val space = value.indexOf(' ')
            if (space >= 0 && value.substring(space + 1).any { isColon(it) }) value = value.substring(0, space)
            if (value.isNotEmpty()) return value
        }
        return null
    }

    private fun isIdeograph(c: Char) = c in '\u3400'..'\u9FFF' || c in '\uF900'..'\uFAFF'

    /**
     * The value of the field named exactly [label] on [line]: the label must start the line or follow a character
     * that is not a CJK ideograph, and only spaces may stand between it and the colon. "姓名" therefore never reads
     * "姓名羅馬拼音：" or "父姓名：". Null when the line has no such field or its value is empty.
     */
    fun labelled(label: String, line: String): String? {
        var from = 0
        while (true) {
            val at = line.indexOf(label, from)
            if (at < 0) return null
            from = at + 1
            if (at > 0 && isIdeograph(line[at - 1])) continue
            val rest = line.substring(at + label.length)
            val colon = rest.indexOfFirst { isColon(it) }
            if (colon < 0 || rest.substring(0, colon).isNotBlank()) continue
            return value(label, line.substring(at))
        }
    }

    private val PAGE_NUMBER = Regex("第\\s*\\d+\\s*(/\\s*\\d+\\s*)?頁|共\\s*\\d+\\s*頁|(?i)page\\s*\\d+\\s*(of|/)\\s*\\d+")
    private val CLOCK = Regex("\\d{1,4}[-/.]\\d{1,2}[-/.]\\d{1,2}|\\d{1,2}:\\d{2}(:\\d{2})?")

    /**
     * A running header or footer line: a page number ("第 1/4頁", "共 4 頁"), alone or with the print time
     * ("2026-10-15 21:23:08 第 1/4頁"), and no field of its own.
     */
    fun isPageFurniture(line: String): Boolean {
        val t = halfWidth(line).trim()
        if (t.isEmpty() || t.length > 60 || !PAGE_NUMBER.containsMatchIn(t)) return false
        val rest = PAGE_NUMBER.replace(CLOCK.replace(t, ""), "")
        return rest.none { isColon(it) }
    }

    /** [text] without its running headers and footers. */
    fun withoutPageFurniture(text: String): String = text.lines().filterNot { isPageFurniture(it) }.joinToString("\n")

    /** "1,234,567" / "NT$1,234" / "1234567 元" to "1234567"; null without a digit. */
    fun digits(raw: String): String? {
        val d = raw.filter { it in '0'..'9' }
        return if (d.isEmpty()) null else (d.trimStart('0').ifEmpty { "0" })
    }

    private val DATE_PATTERNS = listOf(
        Regex("^(\\d{2,4})[/.\\-年](\\d{1,2})[/.\\-月](\\d{1,2})日?$"),
        Regex("^(\\d{3})(\\d{2})(\\d{2})$"),
        Regex("^(\\d{4})(\\d{2})(\\d{2})$"),
    )

    /** A Republic of China or Gregorian date (113/02/01, 113年2月1日, 民國113年02月01日, 1130201, 2024-02-01) as yyyy-MM-dd. */
    fun isoDate(raw: String): String? {
        val text = halfWidth(raw).replace("民國", "").replace(" ", "").trim()
        for (p in DATE_PATTERNS) {
            val m = p.matchEntire(text) ?: continue
            val y = m.groupValues[1].toInt()
            val mo = m.groupValues[2].toInt()
            val d = m.groupValues[3].toInt()
            if (mo !in 1..12 || d !in 1..31) return null
            val year = if (y < 1000) y + 1911 else y
            return year.toString().padStart(4, '0') + "-" + mo.toString().padStart(2, '0') + "-" + d.toString().padStart(2, '0')
        }
        return null
    }

    private val DATE_TOKEN = Regex("(民國)?\\s*\\d{2,4}\\s*[/.\\-年]\\s*\\d{1,2}\\s*[/.\\-月]\\s*\\d{1,2}日?|(?<!\\d)\\d{7}(?!\\d)|(?<!\\d)\\d{8}(?!\\d)")

    /** Every date in [line], in order, as yyyy-MM-dd. */
    fun isoDates(line: String): List<String> = DATE_TOKEN.findAll(halfWidth(line)).mapNotNull { isoDate(it.value) }.toList()

    /** "113", "113年度" or "2024" as the Gregorian year. */
    fun gregorianYear(raw: String): String? = digits(raw)?.toIntOrNull()?.let { (if (it < 1000) it + 1911 else it).toString() }

    /** Full-width forms to ASCII. */
    fun halfWidth(text: String): String = buildString(text.length) {
        for (c in text) append(
            when (c) {
                in '！'..'～' -> (c.code - 0xFEE0).toChar()
                '　' -> ' '
                else -> c
            }
        )
    }

    /** 台 to 臺 and full-width to ASCII, so city names compare equal however they were typed. */
    fun normalised(text: String): String = halfWidth(text.replace('台', '臺')).trim()
}

/** The MyData document parsers Bonds ships, by document type; the version travels in the credential (source.parser). */
object MyDataParsers {
    const val INCOME_PARSER = "income-pdf/v1"
    const val LABOR_INSURANCE_PARSER = "labor-insurance-pdf/v1"
    const val HOUSEHOLD_PARSER = "household-pdf/v1"

    const val TAX_YEAR = "tax_year"
    const val INCOME_TOTAL = "income_total_twd"
    const val PAYER_COUNT = "payer_count"
    const val PERIOD_COUNT = "period_count"
    const val LATEST_START = "latest_start"
    const val CITY = "household_city"
    const val DISTRICT = "household_district"
    const val REGISTERED_SINCE = "registered_since"
    const val MEMBER_COUNT = "member_count"
    const val HOLDER_MATCHED = "holder_matched"

    private val CITIES = listOf(
        "臺北市", "新北市", "桃園市", "臺中市", "臺南市", "高雄市", "基隆市", "新竹市", "嘉義市", "新竹縣", "苗栗縣", "彰化縣",
        "南投縣", "雲林縣", "嘉義縣", "屏東縣", "宜蘭縣", "花蓮縣", "臺東縣", "澎湖縣", "金門縣", "連江縣",
    )

    fun parse(documentType: String, text: String, holders: List<HolderHint> = emptyList()): ParsedSource = when (documentType) {
        HolderDerivedTypes.INCOME -> income(text)
        HolderDerivedTypes.LABOR_INSURANCE -> laborInsurance(text)
        HolderDerivedTypes.HOUSEHOLD -> household(text, holders)
        else -> throw HolderDerivedException("本錢包不會解析這種文件")
    }

    /** The document type a page's own text names, for a file whose name says nothing. */
    fun recognize(text: String): String? = when {
        "個人所得資料" in text || ("所得年度" in text && "給付總額" in text) -> HolderDerivedTypes.INCOME
        "被保險人投保資料" in text || ("投保單位" in text && "加保" in text) -> HolderDerivedTypes.LABOR_INSURANCE
        "戶籍資料" in text || ("戶長" in text && "戶號" in text) -> HolderDerivedTypes.HOUSEHOLD
        else -> null
    }

    /** The tax year and the sum of 給付總額: a 合計 line, else the per-row amounts; never zero by default. */
    fun income(text: String): ParsedSource {
        if (listOf("所得資料", "給付總額", "所得年度").none { it in text }) throw HolderDerivedException("這份文件不是個人所得資料")
        val year = MyDataText.value("所得年度", text)?.let { MyDataText.gregorianYear(it) }
            ?: Regex("(\\d{2,4})\\s*年度").find(text)?.let { MyDataText.gregorianYear(it.groupValues[1]) }
            ?: throw HolderDerivedException("所得資料讀不到所得年度")
        val lines = text.lines()
        // The summary puts several totals on one line (給付總額合計, 扣繳稅額合計, 所得額合計); only the amount right after
        // 給付總額(收入)合計 counts. The first such total includes separately taxed income, as the list prints it first.
        val total = GROSS_TOTAL.find(MyDataText.halfWidth(text))?.let { MyDataText.digits(it.groupValues[1])?.toLongOrNull() }
            ?: lines.filter { "給付總額" in it && "合計" !in it }
                .mapNotNull { MyDataText.value("給付總額", it)?.let { v -> MyDataText.digits(v)?.toLongOrNull() } }
                .takeIf { it.isNotEmpty() }?.sum()
            ?: throw HolderDerivedException("所得資料讀不到給付總額")
        val payers = lines.count { l ->
            val label = if ("扣繳單位" in l) "扣繳單位" else if ("給付單位" in l) "給付單位" else null
            label != null && MyDataText.value(label, l) != null
        }
        return ParsedSource(HolderDerivedTypes.INCOME, INCOME_PARSER, mapOf(TAX_YEAR to year, INCOME_TOTAL to total.toString(), PAYER_COUNT to payers.toString()))
    }

    /** 給付總額(收入)合計： 2,134 in half-width text; the amount stops at the first character that is not a digit or comma. */
    private val GROSS_TOTAL = Regex("給付總額\\s*(?:\\(\\s*收入\\s*\\))?\\s*合計\\s*[：:]\\s*([0-9][0-9,]*)")

    /** Insured periods, one per row with a date: the first date enrols, a second (or a 退保日期) withdraws. The salary is never read. */
    fun laborInsurance(text: String): ParsedSource {
        if (listOf("投保資料", "加保", "投保單位").none { it in text }) throw HolderDerivedException("這份文件不是被保險人投保資料")
        val periods = text.lines().mapNotNull { line ->
            val dates = MyDataText.isoDates(line)
            val start = dates.firstOrNull() ?: return@mapNotNull null
            val end = MyDataText.value("退保日期", line)?.let { MyDataText.isoDate(it) } ?: dates.getOrNull(1)
            CoveragePeriod(start, end)
        }
        if (periods.isEmpty()) throw HolderDerivedException("投保資料讀不到加保日期")
        return ParsedSource(
            HolderDerivedTypes.LABOR_INSURANCE, LABOR_INSURANCE_PARSER,
            mapOf(PERIOD_COUNT to periods.size.toString(), LATEST_START to periods.maxOf { it.start }), periods,
        )
    }

    private val SINCE_LABELS = listOf("遷入日期", "初設戶籍日期", "設籍日期", "遷入登記日期")
    private val NAME_LABELS = listOf("姓名")
    private val ID_LABELS = listOf("統一編號", "身分證統一編號", "身分證字號", "統號")
    private val ID_NUMBER = Regex("[A-Z][0-9A-Z*＊Xx]{9}")
    private val FULL_ID_NUMBER = Regex("[A-Z][0-9A-Z][0-9]{8}")

    /**
     * The household's city and district (the address is the household's, shared by every member) and the holder's
     * own registration date. A whole-household record lists several people, each with their own 遷入日期; the holder
     * is picked by ID number or name from [holders], so a parent's or child's date never answers for the holder.
     * The record is refused unless the holder is found on it, also when it lists a single person: a record shared by
     * someone else must not answer for the holder.
     */
    fun household(source: String, holders: List<HolderHint> = emptyList()): ParsedSource {
        val text = MyDataText.withoutPageFurniture(source)
        if (listOf("戶籍", "戶長", "戶號").none { it in text }) throw HolderDerivedException("這份文件不是戶籍資料")
        val raw = MyDataText.value("戶籍地址", text) ?: MyDataText.value("住址", text) ?: throw HolderDerivedException("戶籍資料讀不到戶籍地址")
        val address = MyDataText.normalised(raw)
        val city = CITIES.firstOrNull { address.startsWith(it) } ?: throw HolderDerivedException("戶籍資料讀不到縣市")
        val rest = address.substring(city.length)
        val end = rest.indexOfFirst { it in "區鄉鎮市" }
        val fields = linkedMapOf(CITY to city, DISTRICT to if (end >= 0) rest.substring(0, end + 1) else "")
        val members = householdMembers(text)
        fields[MEMBER_COUNT] = members.size.toString()
        if (holders.isEmpty()) throw HolderDerivedException("需要先製作身分證卡或在設定填入身分證統一編號，才能確認這份戶籍資料是持有人本人的")
        val since: String? = when {
            members.isEmpty() -> {
                // No person could be told apart: the holder's full ID number must appear on the record, and a
                // registration date is used only when the page carries exactly one.
                val flat = MyDataText.halfWidth(text).uppercase()
                if (holders.none { h -> h.idNumber?.trim()?.uppercase()?.let { FULL_ID_NUMBER.matches(it) && it in flat } == true }) {
                    throw HolderDerivedException("戶籍資料中找不到持有人的身分證統一編號，無法確認是持有人本人的戶籍")
                }
                val dates = text.lines().flatMap { line -> SINCE_LABELS.mapNotNull { MyDataText.value(it, line)?.let { v -> MyDataText.isoDate(v) } } }.distinct()
                dates.singleOrNull()
            }
            else -> {
                val holder = holderOf(members, holders)
                    ?: throw HolderDerivedException(
                        if (members.size == 1) "戶籍資料的住戶不是持有人（以身分證卡或設定的身分證統一編號與姓名比對）"
                        else "戶籍資料的 ${members.size} 位住戶中找不到持有人（以身分證卡或設定的身分證統一編號與姓名比對）"
                    )
                holder.since
            }
        }
        fields[HOLDER_MATCHED] = "true"
        since?.let { fields[REGISTERED_SINCE] = it }
        return ParsedSource(HolderDerivedTypes.HOUSEHOLD, HOUSEHOLD_PARSER, fields)
    }

    /** One person on a household record. */
    data class HouseholdMember(val name: String?, val idNumber: String?, val since: String?)

    /** One person's block of a household record in the labelled layout: the person and the lines of the block. */
    data class HouseholdBlock(val member: HouseholdMember, val lines: List<String>)

    /** A household record split into the household's own lines (before the first person) and one block per person. */
    data class HouseholdLayout(val header: List<String>, val blocks: List<HouseholdBlock>)

    /** Labels that open a person's block when they stand on the line just before its 姓名 field. */
    private val BLOCK_LEADS = listOf("稱謂", "與戶長關係", "序號")

    /**
     * The labelled layout: each person's block starts at its own 姓名 field (exactly that label, so 姓名羅馬拼音
     * and 父姓名 do not start one), or at the 稱謂 line right above it, and runs to the next block. Running headers
     * and footers are dropped first, and a line repeating the household part (the header printed again on each page)
     * is left out of the blocks.
     */
    fun householdLayout(source: String): HouseholdLayout {
        val lines = MyDataText.withoutPageFurniture(source).lines()
        val starts = ArrayList<Int>()
        lines.forEachIndexed { i, line ->
            if (NAME_LABELS.none { MyDataText.labelled(it, MyDataText.halfWidth(line)) != null }) return@forEachIndexed
            val lead = i > 0 && BLOCK_LEADS.any { MyDataText.labelled(it, MyDataText.halfWidth(lines[i - 1])) != null } &&
                NAME_LABELS.none { MyDataText.labelled(it, MyDataText.halfWidth(lines[i - 1])) != null }
            val start = if (lead) i - 1 else i
            if (starts.lastOrNull() != start) starts += start
        }
        if (starts.isEmpty()) return HouseholdLayout(lines, emptyList())
        val header = lines.subList(0, starts.first())
        val repeated = header.map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val blocks = starts.mapIndexed { n, start ->
            val end = starts.getOrNull(n + 1) ?: lines.size
            val block = lines.subList(start, end).filter { it.trim() !in repeated }
            HouseholdBlock(member(block), block)
        }.filter { it.member.name != null || it.member.idNumber != null }
        return HouseholdLayout(header, blocks)
    }

    private fun member(block: List<String>): HouseholdMember {
        var name: String? = null
        var id: String? = null
        var since: String? = null
        for (raw in block) {
            val line = MyDataText.halfWidth(raw)
            if (name == null) name = NAME_LABELS.firstNotNullOfOrNull { MyDataText.labelled(it, line) }?.trim()
            if (id == null) id = ID_LABELS.firstNotNullOfOrNull { MyDataText.labelled(it, line) }?.let { ID_NUMBER.find(it.uppercase())?.value }
            if (since == null) since = SINCE_LABELS.firstNotNullOfOrNull { MyDataText.labelled(it, line)?.let { v -> MyDataText.isoDate(v) } }
        }
        return HouseholdMember(name, id, since ?: sinceFromNotes(block.joinToString("")))
    }

    /** "民國100年05月02日 ... 遷入登記" in a person's 記事 (the text may wrap, so the lines are joined first). */
    private val NOTE_EVENT = Regex("(?:民國)?\\s*(\\d{2,3})\\s*年\\s*(\\d{1,2})\\s*月\\s*(\\d{1,2})\\s*日[^年。；]{0,40}?(遷入|初設戶籍|出生登記)")

    /**
     * The registration date from a person's 記事 when the record has no 遷入日期 field: the latest move-in, else the
     * first registration (birth or first household registration) when the person never moved in from elsewhere.
     */
    fun sinceFromNotes(text: String): String? {
        val events = NOTE_EVENT.findAll(MyDataText.halfWidth(text).replace(" ", "")).mapNotNull { m ->
            val date = MyDataText.isoDate(m.groupValues[1] + "年" + m.groupValues[2] + "月" + m.groupValues[3] + "日") ?: return@mapNotNull null
            date to m.groupValues[4]
        }.toList()
        return events.filter { it.second == "遷入" }.maxOfOrNull { it.first } ?: events.minOfOrNull { it.first }
    }

    /**
     * The holder among [members]: the one member [holders] identify; null when there are no hints or they match none
     * or several. A single-person record still has to match, so another person's record never stands for the holder.
     */
    fun <T> holderOf(members: List<T>, holders: List<HolderHint>, person: (T) -> HouseholdMember): T? =
        members.filter { m -> holders.any { it.matches(person(m)) } }.singleOrNull()

    fun holderOf(members: List<HouseholdMember>, holders: List<HolderHint>): HouseholdMember? = holderOf(members, holders) { it }

    /**
     * The people on a household record, in either layout: labelled blocks ([householdLayout]), or a table whose
     * header names the columns and whose rows carry an ID number.
     */
    fun householdMembers(text: String): List<HouseholdMember> {
        val lines = MyDataText.withoutPageFurniture(text).lines().map { MyDataText.halfWidth(it) }
        tableMembers(lines).takeIf { it.isNotEmpty() }?.let { return it }
        return householdLayout(text).blocks.map { it.member }
    }

    private fun tableMembers(lines: List<String>): List<HouseholdMember> {
        val headerAt = lines.indexOfFirst { l -> "姓名" in l && SINCE_LABELS.any { it in l } && ':' !in l && '：' !in l }
        if (headerAt < 0) return emptyList()
        val header = lines[headerAt].trim().split(Regex("\\s+"))
        val nameCol = header.indexOfFirst { it == "姓名" }
        val sinceCol = header.indexOfFirst { it in SINCE_LABELS }
        val idCol = header.indexOfFirst { it in ID_LABELS }
        return lines.drop(headerAt + 1).mapNotNull { row ->
            val cells = row.trim().split(Regex("\\s+"))
            val id = (cells.getOrNull(idCol)?.takeIf { idCol >= 0 } ?: row).let { ID_NUMBER.find(it.uppercase())?.value } ?: return@mapNotNull null
            HouseholdMember(
                cells.getOrNull(nameCol)?.takeIf { nameCol >= 0 && it.isNotBlank() },
                id,
                cells.getOrNull(sinceCol)?.takeIf { sinceCol >= 0 }?.let { MyDataText.isoDate(it) },
            )
        }
    }
}

/**
 * Who the holder is, for picking their row on a household record: the ID number and name on the holder's national ID
 * card, or the ID number saved for MyData. A masked digit (* or X) on the record matches any digit.
 */
data class HolderHint(val idNumber: String?, val name: String?) {
    fun matches(m: MyDataParsers.HouseholdMember): Boolean {
        val id = idNumber?.trim()?.uppercase()
        val other = m.idNumber?.uppercase()
        if (id != null && other != null && id.length == other.length) {
            val same = id.indices.all { i -> other[i] == id[i] || other[i] in "*＊X" }
            val masked = other.count { it in "*＊X" }
            // A masked number alone is not enough when it hides most digits; then the name must agree too.
            return same && (masked <= 3 || (name != null && m.name?.trim() == name.trim()))
        }
        return name != null && m.name?.trim() == name.trim()
    }
}

/** A vault document a holder-derived credential can be computed from; [text] is read only for the chosen one. */
class HolderDerivedSource(
    val id: String,
    val name: String,
    /** The document type when the vault knows it (from the MyData item), else null and the text decides. */
    val documentType: String?,
    /** SHA-256 of the stored bytes, hex. */
    val sha256Hex: String,
    val text: suspend () -> String,
)

/** The answer computed for one request, shown on the consent screen before anything is signed. */
class HolderDerivedPlan(
    val queryId: String,
    val type: HolderDerivedType,
    val rule: DerivedRule,
    val source: HolderDerivedSource,
    val parsed: ParsedSource,
    /** Every claim of the type the rule produced, by name ("true" / "false" for predicates). */
    val answers: Map<String, String>,
    /** The claims the verifier asked for, all present in [answers]; only these travel. */
    val requested: List<String>,
)

/**
 * Bonds holder-derived credentials (twdiw-vp-verifier-lite holderDerived): the verifier asks in DCQL for a dc+sd-jwt
 * credential of a Bonds MyData type and puts its question beside it as bonds_rule. The wallet reads the original kept
 * in the vault, computes the answer, and mints at that moment an IETF SD-JWT VC whose iss and cnf are one fresh
 * in-memory P-256 key (did:key jwk_jcs), with the rule, the source fingerprint, the parser version, assurance
 * "holder-derived" and the pinned vct#integrity in clear. The credential exists only in the response, valid ten
 * minutes, so two presentations share nothing to correlate on. The vp_token is a JSON object keyed by the DCQL
 * credential query id.
 */
object BondsHolderDerived {
    const val ASSURANCE = "holder-derived"
    const val SOURCE_KIND = "mydata-downloaded-document"
    const val RULE_PARAM = "bonds_rule"
    const val VALID_SECONDS = 600L

    private val TAIPEI = TimeZone.of("Asia/Taipei")

    private fun derivedQuery(request: ValidatedAuthorizationRequest): JsonObject? =
        request.dcqlQuery.arr("credentials")?.filterIsInstance<JsonObject>()?.firstOrNull { it.str("format") == "dc+sd-jwt" }

    /** True for a request with a bonds_rule and a dc+sd-jwt DCQL query: it is answered from the vault, never with a held card. */
    fun wants(request: ValidatedAuthorizationRequest): Boolean =
        request.raw.params[RULE_PARAM] is JsonObject && derivedQuery(request) != null

    /**
     * Finds the original of the requested type among [sources] (by its known type, else by what an untyped document's
     * own text says), parses it and computes the answer; [holders] pick the holder's own row on a household record.
     * Throws access_denied with the reason the holder reads.
     */
    suspend fun prepare(
        request: ValidatedAuthorizationRequest,
        sources: List<HolderDerivedSource>,
        holders: List<HolderHint> = emptyList(),
        now: Instant = Clock.System.now(),
    ): HolderDerivedPlan {
        val query = derivedQuery(request) ?: throw ProtocolException("invalid_request", "No dc+sd-jwt credential query")
        val queryId = query.str("id") ?: throw ProtocolException("invalid_request", "DCQL credential query without id")
        val vct = query.obj("meta")?.arr("vct_values")?.firstNotNullOfOrNull { (it as? JsonPrimitive)?.content }
        val type = HolderDerivedTypes.byVct(vct) ?: throw ProtocolException("access_denied", "查驗方要的衍生憑證類型（$vct）本錢包不支援")
        val rule = DerivedRule.parse(request.raw.params[RULE_PARAM]) ?: throw ProtocolException("invalid_request", "查驗方沒有寫明問題（bonds_rule）")
        rule.problem()?.let { throw ProtocolException("access_denied", it) }
        if (rule.id !in type.rules) throw ProtocolException("access_denied", "${type.title}不能回答這個問題（${rule.id}）")
        val requested = query.arr("claims").orEmpty().filterIsInstance<JsonObject>().mapNotNull { c ->
            c.arr("path")?.singleOrNull()?.let { (it as? JsonPrimitive)?.content }
        }.distinct()
        requested.firstOrNull { it !in type.claims }?.let { throw ProtocolException("access_denied", "查驗方要的欄位 $it 不在${type.title}的衍生憑證內") }

        // Every original of the type is tried, newest first as the vault lists them, so files of several years (or
        // several household records) live side by side and the one that answers this rule is used.
        val typed = sources.filter { it.documentType == type.documentType }
        val untyped = sources.filter { it.documentType == null }
        val candidates = typed.map { it to null as String? } + untyped.mapNotNull { s ->
            val t = runCatching { s.text() }.getOrNull() ?: return@mapNotNull null
            if (MyDataParsers.recognize(t) == type.documentType) s to t else null
        }
        if (candidates.isEmpty()) throw ProtocolException("access_denied", "文件分頁沒有${type.title}，請先從 MyData 下載")
        val problems = ArrayList<String>()
        val years = ArrayList<String>()
        for ((source, text) in candidates) {
            val parsed = try {
                MyDataParsers.parse(type.documentType, text ?: source.text(), holders)
            } catch (e: HolderDerivedException) {
                problems.add("${source.name}：${e.message}")
                continue
            }
            parsed.fields[MyDataParsers.TAX_YEAR]?.let { years.add(it) }
            val answers = try {
                derive(type, parsed, rule, now)
            } catch (e: HolderDerivedException) {
                problems.add(e.message ?: "文件無法回答這個問題")
                continue
            }
            val missing = requested.firstOrNull { it !in answers }
            if (missing != null) {
                problems.add("${source.name}無法回答「${type.claimLabels[missing] ?: missing}」")
                continue
            }
            return HolderDerivedPlan(queryId, type, rule, source, parsed, answers, requested)
        }
        if (rule.id == DerivedRule.INCOME && years.isNotEmpty() && rule.params["tax_year"] !in years) {
            throw ProtocolException("access_denied",
                "文件分頁的所得資料是 ${years.distinct().sorted().joinToString("、")} 年，查驗方問的是 ${rule.params["tax_year"]} 年，請先從 MyData 下載該年度的資料")
        }
        throw ProtocolException("access_denied", problems.first())
    }

    /**
     * Every claim of [type] computed from [parsed] and [rule]. A rule that does not meet the document (an income rule
     * for another year) is refused rather than answered "false", which would be a statement about the wrong year.
     */
    fun derive(type: HolderDerivedType, parsed: ParsedSource, rule: DerivedRule, now: Instant = Clock.System.now()): Map<String, String> {
        if (parsed.documentType != type.documentType) throw HolderDerivedException("文件類型與問題不符")
        rule.problem()?.let { throw HolderDerivedException(it) }
        return when (rule.id) {
            DerivedRule.INCOME -> {
                val year = parsed.fields[MyDataParsers.TAX_YEAR]
                val total = parsed.fields[MyDataParsers.INCOME_TOTAL]?.toLongOrNull()
                val ceiling = rule.params["ceiling_twd"]?.toLongOrNull()
                if (year == null || total == null || ceiling == null) throw HolderDerivedException("所得資料無法回答所得門檻")
                if (year != rule.params["tax_year"]) throw HolderDerivedException("所得資料是 $year 年，查驗方問的是 ${rule.params["tax_year"]} 年")
                mapOf("tax_year" to year, "payer_count" to (parsed.fields[MyDataParsers.PAYER_COUNT] ?: "0"), "income_within_ceiling" to (total <= ceiling).toString())
            }
            DerivedRule.INSURANCE -> {
                val on = rule.params["on_date"]?.let { MyDataText.isoDate(it) } ?: throw HolderDerivedException("查驗方的日期無法讀取")
                val active = parsed.periods.any { it.start <= on && (it.end == null || it.end >= on) }
                mapOf("on_date" to on, "insured_on_date" to active.toString())
            }
            DerivedRule.HOUSEHOLD -> {
                val city = parsed.fields[MyDataParsers.CITY] ?: throw HolderDerivedException("戶籍資料讀不到縣市")
                val asked = MyDataText.normalised(rule.params["city"].orEmpty())
                val claims = linkedMapOf("registered_in_city" to (city == asked).toString())
                val months = rule.params["min_months"]?.toIntOrNull()
                val since = parsed.fields[MyDataParsers.REGISTERED_SINCE]
                if (months != null) {
                    // Asked but unreadable is refused: leaving the answer out would read as if the question was not asked.
                    if (since == null) throw HolderDerivedException("戶籍資料讀不到持有人的遷入日期，無法回答是否設籍滿 $months 個月")
                    claims["registered_at_least_months"] = (monthsBetween(since, now) >= months && city == asked).toString()
                }
                claims
            }
            else -> throw HolderDerivedException("本錢包不會回答這種問題（${rule.id}）")
        }
    }

    /** Whole months from [iso] to [now] in Taipei, never negative. */
    fun monthsBetween(iso: String, now: Instant): Int {
        val since = runCatching { LocalDate.parse(iso) }.getOrNull() ?: return 0
        val today = now.toLocalDateTime(TAIPEI).date
        val months = (today.year - since.year) * 12 + (today.monthNumber - since.monthNumber) - if (today.dayOfMonth < since.dayOfMonth) 1 else 0
        return maxOf(0, months)
    }

    /**
     * Mints the credential for [plan] with a fresh key and presents it to [request]: the requested disclosures and a
     * KB-JWT (aud the client id, the request nonce, sd_hash). Returns the presentation (issuer JWT~disclosures~KB-JWT).
     */
    suspend fun present(request: ValidatedAuthorizationRequest, plan: HolderDerivedPlan, now: Instant = Clock.System.now()): String {
        val private = Crypto.createEcPrivateKey(EcCurve.P256)
        val key = AsymmetricKey.AnonymousExplicit(private, Algorithm.ES256)
        val iss = DidKeys.didKeyJwkJcs(private.publicKey)
        val jwk = private.publicKey.toJwk()
        val claims = plan.type.claims.mapNotNull { name -> plan.answers[name]?.let { name to it } }
        val disclosures = claims.associate { (name, value) ->
            name to JsonArray(listOf(JsonPrimitive(PlatformCrypto.randomBytes(16).toBase64Url()), JsonPrimitive(name), JsonPrimitive(value)))
                .toString().encodeToByteArray().toBase64Url()
        }
        val payload = buildJsonObject {
            putJsonObject("source") {
                put("kind", SOURCE_KIND)
                put("sha256", plan.source.sha256Hex.lowercase())
                put("document_type", plan.type.documentType)
                put("parser", plan.parsed.parser)
            }
            put("rule", plan.rule.toJson())
            put("assurance", ASSURANCE)
            put("vct#integrity", plan.type.integrity)
            put("iss", iss)
            put("iat", now.epochSeconds)
            put("exp", now.epochSeconds + VALID_SECONDS)
            put("vct", plan.type.vct)
            putJsonObject("cnf") { put("jwk", jwk) }
            putJsonArray("_sd") { disclosures.values.map { SdJwtDisclosures.digest(it) }.sorted().forEach { add(JsonPrimitive(it)) } }
            put("_sd_alg", "sha-256")
        }
        val jwt = signJws(buildJsonObject { put("alg", "ES256"); put("typ", "dc+sd-jwt") }, payload, key)
        val presented = (listOf(jwt) + plan.requested.mapNotNull { disclosures[it] }).joinToString("~") + "~"
        val kb = signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "kb+jwt") },
            buildJsonObject {
                put("iat", now.epochSeconds)
                put("aud", request.verifier.effectiveClientId)
                put("nonce", request.nonce)
                put("sd_hash", PlatformCrypto.sha256(presented.encodeToByteArray()).toBase64Url())
            },
            key,
        )
        return presented + kb
    }

    /** Form parameters of the response: a DCQL vp_token keyed by the credential query id, and the state. */
    suspend fun response(request: ValidatedAuthorizationRequest, plan: HolderDerivedPlan, now: Instant = Clock.System.now()): JsonObject {
        val presentation = present(request, plan, now)
        return buildJsonObject {
            putJsonObject("vp_token") { putJsonArray(plan.queryId) { add(JsonPrimitive(presentation)) } }
            request.state?.let { put("state", it) }
        }
    }
}
