package diw.wallet.core.document.zkpdf

import kotlinx.serialization.json.*

/** An image XObject whose stream data stays private: its resource name on a page (1-based) the template proves. */
class ZkPdfImageRef(val page: Int, val name: String) {
    init {
        require(page in 1..ZkPdfProfile.MAX_PAGE) { "Invalid zkPDF page" }
        require(name.isNotEmpty()) { "Invalid zkPDF image name" }
    }

    override fun equals(other: Any?) = other is ZkPdfImageRef && other.page == page && other.name == name
    override fun hashCode() = page * 31 + name.hashCode()
}

/**
 * A zkPDF document template (p4-circuits.md 3.11): which pages are proven (the pages its fields are on), which
 * images of those pages stay private, which public labels delimit each field, and how a field's decoded text is
 * normalized. Every page without a field of the template stays private as a whole. Templates come from the signed
 * template pack (templates/zkpdf) or, for tests, from code; both sides of a proof must use the same template
 * version, named by [id].
 */
class ZkPdfProfile(
    /** Template identifier and version, for example cn.fzu.student-status/1. */
    val id: String,
    val title: String,
    /** Image XObjects of proven pages whose stream data stays private (for example a QR code). */
    val opaqueImages: List<ZkPdfImageRef>,
    val fields: List<ZkPdfFieldRule>,
    /** Present only in test packs; production templates never set it. */
    val test: Boolean = false,
) {
    /** The proven pages, 1-based and ascending. */
    val pages: List<Int> get() = fields.map { it.page }.distinct().sorted()

    init {
        require(Regex("[a-z0-9.-]{1,64}/[0-9]{1,4}").matches(id)) { "Invalid zkPDF template identifier" }
        require(fields.isNotEmpty() && fields.size <= MAX_FIELDS) { "A zkPDF template has 1 to $MAX_FIELDS fields" }
        require(fields.map { it.claim }.toSet().size == fields.size) { "Duplicate zkPDF field" }
        require(pages.size <= MAX_PAGES) { "A zkPDF template proves at most $MAX_PAGES pages" }
        require(opaqueImages.size <= MAX_IMAGES && opaqueImages.toSet().size == opaqueImages.size) { "At most $MAX_IMAGES private images" }
        require(opaqueImages.all { it.page in pages }) { "A private image must be on a proven page" }
        for (page in pages) {
            val onPage = fields.filter { it.page == page }
            require(onPage.size <= MAX_SLOTS) { "At most $MAX_SLOTS zkPDF fields on a page" }
            require(onPage.flatMap { it.before + it.after }.toSet().size <= MAX_ANCHORS) { "Too many zkPDF anchors" }
        }
    }

    fun field(claim: String): ZkPdfFieldRule? = fields.firstOrNull { it.claim == claim }

    fun toJson(): JsonObject = buildJsonObject {
        put("id", id)
        put("title", title)
        putJsonArray("opaqueImages") {
            opaqueImages.forEach { if (it.page == 1) add(it.name) else addJsonObject { put("page", it.page); put("name", it.name) } }
        }
        putJsonArray("fields") { fields.forEach { add(it.toJson()) } }
        if (test) put("test", true)
    }

    companion object {
        /** Fields of one proven page: the slots of the claim circuit. */
        const val MAX_SLOTS = 12
        const val MAX_ANCHORS = 16
        /** Proven pages of a template: each is a separate chain of segment proofs. */
        const val MAX_PAGES = 4
        const val MAX_FIELDS = MAX_SLOTS * MAX_PAGES
        const val MAX_IMAGES = 4
        /** Highest page number a template may name. */
        const val MAX_PAGE = 999

        fun parse(o: JsonObject): ZkPdfProfile {
            fun bad(what: String): Nothing = throw IllegalArgumentException("Invalid zkPDF template: $what")
            fun JsonObject.str(key: String) = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
            fun JsonObject.page() = when (val p = this["page"]) {
                null -> 1
                else -> (p as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull?.takeIf { it in 1..MAX_PAGE } ?: bad("page")
            }
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
                    page = f.page(),
                )
            }
            // An image is its resource name on page 1, or {"page": n, "name": ...} on another proven page.
            val images = (o["opaqueImages"] as? JsonArray ?: JsonArray(emptyList())).map { e ->
                when (e) {
                    is JsonPrimitive -> ZkPdfImageRef(1, e.takeIf { it.isString }?.content ?: bad("opaqueImages"))
                    is JsonObject -> ZkPdfImageRef(e.page(), e.str("name") ?: bad("opaqueImages"))
                    else -> bad("opaqueImages")
                }
            }
            return ZkPdfProfile(o.str("id") ?: bad("id"), o.str("title") ?: bad("title"), images, fields,
                (o["test"] as? JsonPrimitive)?.booleanOrNull == true)
        }
    }
}

/**
 * One field: the decoded text of every text operator strictly between an operator whose decoded text is one of
 * [before] and the next operator whose decoded text is one of [after], on the content stream of [page].
 */
class ZkPdfFieldRule(
    /** Claim name in the derived credential; the same name as the P3 document fields where the meaning matches. */
    val claim: String,
    /** Label shown to people. */
    val label: String,
    val before: List<String>,
    val after: List<String>,
    val normalize: ZkPdfNormalize,
    /** The page (1-based) whose content stream holds the field and its labels. */
    val page: Int = 1,
) {
    init {
        require(Regex("[A-Za-z][A-Za-z0-9_]{0,31}").matches(claim)) { "Invalid zkPDF claim name" }
        require(before.isNotEmpty() && after.isNotEmpty()) { "A zkPDF field needs labels on both sides" }
        require(page in 1..ZkPdfProfile.MAX_PAGE) { "Invalid zkPDF page" }
    }

    fun toJson(): JsonObject = buildJsonObject {
        put("claim", claim)
        put("label", label)
        putJsonArray("before") { before.forEach { add(it) } }
        putJsonArray("after") { after.forEach { add(it) } }
        put("normalize", normalize.code)
        if (page != 1) put("page", page)
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
