package diw.wallet.core.profile.bonds

/** One person of a household transcript: who it is, the labelled fields in print order, and whether it is the holder. */
data class HouseholdPerson(
    val member: MyDataParsers.HouseholdMember,
    val fields: List<Pair<String, String>>,
    val holder: Boolean,
)

/**
 * A household registration transcript (戶籍謄本 現戶部分 or 現戶全戶, from the Department of Household Registration or
 * MyData) read for a structured preview: the household's own fields, then each person, the holder first when the
 * holder can be told apart.
 */
data class HouseholdTranscript(
    val title: String?,
    val household: List<Pair<String, String>>,
    val people: List<HouseholdPerson>,
) {
    val holderFound: Boolean get() = people.any { it.holder }
}

object HouseholdTranscripts {
    private val TITLE = Regex("戶籍謄本|戶籍資料|現戶部分|現戶全戶")

    /** A field label: CJK, Latin letters, brackets or a slash, up to 12 characters, before a colon of either width. */
    private val LABEL = Regex("(?:^|(?<=\\s))([\\u4e00-\\u9fffA-Za-z()（）/]{1,12})\\s*[：:]")

    /**
     * The transcript in [text] (the PDF's text layer), or null when it is not a household record or lists nobody.
     * [holders] pick the holder's own entry, as for the holder-derived answers.
     */
    fun parse(text: String, holders: List<HolderHint> = emptyList()): HouseholdTranscript? {
        val clean = MyDataText.withoutPageFurniture(text)
        if (listOf("戶號", "戶長", "戶籍").count { it in clean } < 2) return null
        val title = clean.lines().map { it.trim() }.firstOrNull { it.isNotEmpty() && TITLE.containsMatchIn(it) && !it.any { c -> c == ':' || c == '：' } }
        // Other records name the household address too (the national ID data): a transcript has its title or 戶號.
        if (title == null && "戶號" !in clean) return null
        val layout = MyDataParsers.householdLayout(clean)
        val people: List<HouseholdPerson>
        val household: List<Pair<String, String>>
        if (layout.blocks.isNotEmpty()) {
            household = fields(layout.header.filter { it.trim() != title })
            people = layout.blocks.map { HouseholdPerson(it.member, fields(it.lines), false) }
        } else {
            val table = table(clean.lines()) ?: return null
            household = fields(clean.lines().subList(0, table.first).filter { it.trim() != title })
            people = table.second
        }
        if (people.isEmpty()) return null
        val holder = MyDataParsers.holderOf(people, holders) { it.member }
        val ordered = if (holder == null) people else listOf(holder.copy(holder = true)) + people.filter { it !== holder }
        return HouseholdTranscript(title, household, ordered)
    }

    /**
     * "標籤：值" fields of [lines] in print order; a line can hold several fields, and a line without a label carries
     * on the value before it (a 記事 that wraps).
     */
    fun fields(lines: List<String>): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        for (raw in lines) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            val labels = LABEL.findAll(line).toList()
            if (labels.isEmpty() || labels.first().range.first > 0) {
                val lead = if (labels.isEmpty()) line else line.substring(0, labels.first().range.first).trim()
                if (out.isNotEmpty()) out[out.lastIndex] = out.last().let { (k, v) -> k to (if (v.isEmpty()) lead else "$v\n$lead") }
                else out.add("" to lead)
            }
            labels.forEachIndexed { i, m ->
                val end = labels.getOrNull(i + 1)?.range?.first ?: line.length
                out.add(m.groupValues[1] to line.substring(m.range.last + 1, end).trim())
            }
        }
        return out.filter { (k, v) -> k.isNotEmpty() || v.isNotEmpty() }
    }

    /** The table layout: a header row naming the columns (姓名 among them, no colon) and one row per person. */
    private fun table(lines: List<String>): Pair<Int, List<HouseholdPerson>>? {
        val at = lines.indexOfFirst { l -> "姓名" in l && l.none { it == ':' || it == '：' } && l.trim().split(Regex("\\s+")).size >= 3 }
        if (at < 0) return null
        val header = lines[at].trim().split(Regex("\\s+"))
        val members = MyDataParsers.householdMembers(lines.joinToString("\n"))
        val rows = lines.drop(at + 1).map { it.trim() }.filter { it.isNotEmpty() }
        val people = members.map { m ->
            val row = rows.firstOrNull { r -> m.idNumber != null && r.uppercase().contains(m.idNumber) }
            val cells = row?.split(Regex("\\s+")).orEmpty()
            val fields = if (cells.size == header.size) header.zip(cells) else listOfNotNull(row?.let { "" to it })
            HouseholdPerson(m, fields, false)
        }
        return at to people
    }
}
