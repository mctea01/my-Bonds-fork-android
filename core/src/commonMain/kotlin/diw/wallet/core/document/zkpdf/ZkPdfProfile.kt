package diw.wallet.core.document.zkpdf

import kotlinx.serialization.json.*

/**
 * A zkPDF document template (p4-circuits.md 3.11): which page streams stay private, which public labels delimit each
 * field, and how a field's decoded text is normalized. Templates come from the signed template pack (templates/zkpdf)
 * or, for tests, from code; both sides of a proof must use the same template version, named by [id].
 */
class ZkPdfProfile(
    /** Template identifier and version, for example cn.fzu.student-status/1. */
    val id: String,
    val title: String,
    /** Image XObject resource names on page 1 whose stream data stays private (for example a QR code). */
    val opaqueImages: List<String>,
    val fields: List<ZkPdfFieldRule>,
    /** Present only in test packs; production templates never set it. */
    val test: Boolean = false,
) {
    init {
        require(Regex("[a-z0-9.-]{1,64}/[0-9]{1,4}").matches(id)) { "Invalid zkPDF template identifier" }
        require(fields.isNotEmpty() && fields.size <= MAX_SLOTS) { "A zkPDF template has 1 to $MAX_SLOTS fields" }
        require(fields.map { it.claim }.toSet().size == fields.size) { "Duplicate zkPDF field" }
        require(opaqueImages.size <= 1) { "At most one private image" }
        require(fields.flatMap { it.before + it.after }.toSet().size <= MAX_ANCHORS) { "Too many zkPDF anchors" }
    }

    fun field(claim: String): ZkPdfFieldRule? = fields.firstOrNull { it.claim == claim }

    fun toJson(): JsonObject = buildJsonObject {
        put("id", id)
        put("title", title)
        putJsonArray("opaqueImages") { opaqueImages.forEach { add(it) } }
        putJsonArray("fields") { fields.forEach { add(it.toJson()) } }
        if (test) put("test", true)
    }

    companion object {
        const val MAX_SLOTS = 12
        const val MAX_ANCHORS = 16

        fun parse(o: JsonObject): ZkPdfProfile {
            fun bad(what: String): Nothing = throw IllegalArgumentException("Invalid zkPDF template: $what")
            fun JsonObject.str(key: String) = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
            fun JsonObject.strings(key: String) = (this[key] as? JsonArray ?: JsonArray(emptyList()))
                .map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: bad(key) }
            val fields = (o["fields"] as? JsonArray ?: bad("fields")).map { element ->
                val f = element as? JsonObject ?: bad("field")
                ZkPdfFieldRule(
                    claim = f.str("claim") ?: bad("claim"),
                    label = f.str("label") ?: bad("label"),
                    before = f.strings("before"),
                    after = f.strings("after"),
                    normalize = ZkPdfNormalize.entries.firstOrNull { it.code == f.str("normalize") } ?: bad("normalize"),
                )
            }
            return ZkPdfProfile(o.str("id") ?: bad("id"), o.str("title") ?: bad("title"), o.strings("opaqueImages"), fields,
                (o["test"] as? JsonPrimitive)?.booleanOrNull == true)
        }
    }
}

/**
 * One field: the decoded text of every text operator strictly between an operator whose decoded text is one of
 * [before] and the next operator whose decoded text is one of [after].
 */
class ZkPdfFieldRule(
    /** Claim name in the derived credential; the same name as the P3 document fields where the meaning matches. */
    val claim: String,
    /** Label shown to people. */
    val label: String,
    val before: List<String>,
    val after: List<String>,
    val normalize: ZkPdfNormalize,
) {
    init {
        require(Regex("[A-Za-z][A-Za-z0-9_]{0,31}").matches(claim)) { "Invalid zkPDF claim name" }
        require(before.isNotEmpty() && after.isNotEmpty()) { "A zkPDF field needs labels on both sides" }
    }

    fun toJson(): JsonObject = buildJsonObject {
        put("claim", claim)
        put("label", label)
        putJsonArray("before") { before.forEach { add(it) } }
        putJsonArray("after") { after.forEach { add(it) } }
        put("normalize", normalize.code)
    }
}

/** How a field's decoded text becomes the disclosed value; part of the template version. */
enum class ZkPdfNormalize(val code: String) {
    /** Leading and trailing white space removed, inner runs of white space collapsed to one space. */
    TEXT("text"),
    /** All white space removed (identifiers). */
    COMPACT("compact"),
    /**
     * A value cut out of running prose: as [TEXT], then the separators that a sentence puts around it (commas,
     * colons, semicolons, the ideographic comma and full stop, in full and half width) removed from both ends.
     */
    CLAUSE("clause"),
    /** A year and month written as a 4-digit year and a 1–2 digit month separated by non-digits, as YYYY-MM. */
    MONTH("month"),
    /**
     * A Gregorian date written as a 4-digit year, a 1–2 digit month and a 1–2 digit day separated by non-digits
     * (date format 0 of the predicate circuit), disclosed as YYYY-MM-DD.
     */
    DATE("date");

    private companion object {
        const val CLAUSE_SEPARATORS = ",，、;；:：。"
    }

    fun apply(text: String): String? = when (this) {
        TEXT -> text.trim().replace(Regex("\\s+"), " ").takeIf { it.isNotEmpty() }
        COMPACT -> text.replace(Regex("\\s+"), "").takeIf { it.isNotEmpty() }
        CLAUSE -> TEXT.apply(text)?.trim { it.isWhitespace() || it in CLAUSE_SEPARATORS }?.takeIf { it.isNotEmpty() }
        MONTH -> Regex("[0-9]+").findAll(text).map { it.value }.toList().takeIf { g ->
            g.size == 2 && g[0].length == 4 && g[1].length in 1..2 && g[1].toInt() in 1..12
        }?.let { (y, m) -> y + "-" + m.padStart(2, '0') }
        DATE -> ZkPdfDates.parse(text)?.let { (y, m, d) ->
            y.toString().padStart(4, '0') + "-" + m.toString().padStart(2, '0') + "-" + d.toString().padStart(2, '0')
        }
    }
}

/** The date reading of the predicate circuit (format 0), so a disclosed date and a proven date agree. */
object ZkPdfDates {
    fun parse(text: String): Triple<Int, Int, Int>? {
        val groups = Regex("[0-9]+").findAll(text).map { it.value }.toList()
        if (groups.size != 3 || groups[0].length != 4 || groups[1].length !in 1..2 || groups[2].length !in 1..2) return null
        val (y, m, d) = groups.map { it.toInt() }
        if (m !in 1..12 || d < 1 || d > daysIn(y, m)) return null
        return Triple(y, m, d)
    }

    fun yyyymmdd(text: String): Int? = parse(text)?.let { (y, m, d) -> y * 10000 + m * 100 + d }

    private fun daysIn(y: Int, m: Int) = when (m) {
        2 -> if ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) 29 else 28
        4, 6, 9, 11 -> 30
        else -> 31
    }
}
