package diw.wallet.core.document.derived

import diw.wallet.core.document.OpenCertInfo

/**
 * Claims read from a document's content, so that a derived credential carries what the document says instead of
 * values the holder types: OpenCerts data, the fields of an official letter (函) and "label: value" lines of a PDF's
 * text layer (as MyData, household and certificate PDFs print them).
 */
object DocumentFields {
    /** At most this many claims come from one document's content. */
    const val MAX_FIELDS = 30

    private const val MAX_VALUE = 200

    /** Well known OpenAttestation paths, with the claim name and label they become. */
    private val openCertNames = linkedMapOf(
        "recipient.name" to ("recipientName" to "受領人"),
        "id" to ("documentId" to "證書編號"),
        "issuedOn" to ("issuedOn" to "發證日期"),
        "description" to ("description" to "說明"),
        "admissionDate" to ("admissionDate" to "入學日期"),
        "graduationDate" to ("graduationDate" to "畢業日期"),
        "attainmentDate" to ("attainmentDate" to "取得日期"),
        "validFrom" to ("validFrom" to "生效日期"),
        "expiresOn" to ("expiresOn" to "到期日期"),
        "recipient.studentId" to ("recipientStudentId" to "學號"),
        "recipient.nric" to ("recipientNric" to "受領人身分證號"),
        "recipient.email" to ("recipientEmail" to "受領人電子郵件"),
        "recipient.course" to ("recipientCourse" to "課程"),
        "recipient.programme" to ("recipientProgramme" to "學程"),
    )

    /** Paths that describe the template, the issuer's publication or attachments rather than the holder's document. */
    private val openCertSkipped = Regex("^(\\\$template|issuers|transcript|attachments|additionalData|logo|signature|qrCode|privacy)(\\.|$)")

    /** OpenCerts data: the well known fields first, then the other scalar fields by their path. */
    fun fromOpenCert(info: OpenCertInfo): List<DerivedClaim> {
        val out = ArrayList<DerivedClaim>()
        for ((path, nl) in openCertNames) info.fields[path]?.let { v -> value(v)?.let { out.add(DerivedClaim(nl.first, it, nl.second)) } }
        info.issuers.takeIf { it.isNotEmpty() }?.let { out.add(DerivedClaim("documentIssuer", it.joinToString("、"), "發證機構")) }
        for ((path, v) in info.fields) {
            if (path in openCertNames || path == "name" || openCertSkipped.containsMatchIn(path)) continue
            val text = value(v) ?: continue
            out.add(DerivedClaim(path, text, path))
        }
        return unique(out)
    }

    private val letterFields = listOf(
        Triple("letterSender", "發文機關", Regex("<發文機關>.*?<全銜>(.*?)</全銜>", RegexOption.DOT_MATCHES_ALL)),
        Triple("letterRecipient", "受文者", Regex("<受文者>.*?<全銜>(.*?)</全銜>", RegexOption.DOT_MATCHES_ALL)),
        Triple("letterDate", "發文日期", Regex("<發文日期>.*?<年月日>(.*?)</年月日>", RegexOption.DOT_MATCHES_ALL)),
        Triple("letterSubject", "主旨", Regex("<主旨>.*?<文字>(.*?)</文字>", RegexOption.DOT_MATCHES_ALL)),
    )

    /** An official letter (函, DTD 104_2) in XML: sender, recipient, date, number and subject. */
    fun fromOfficialLetter(xml: String): List<DerivedClaim> {
        if (!xml.contains("<函")) return emptyList()
        val out = ArrayList<DerivedClaim>()
        for ((name, label, re) in letterFields) re.find(xml)?.let { m -> value(unescape(m.groupValues[1]))?.let { out.add(DerivedClaim(name, it, label)) } }
        Regex("<發文字號>.*?<字>(.*?)</字>.*?<年度>(.*?)</年度>.*?<流水號>(.*?)</流水號>", RegexOption.DOT_MATCHES_ALL).find(xml)?.let { m ->
            val (word, year, serial) = m.destructured
            value(unescape(word) + "字第" + year + serial + "號")?.let { out.add(DerivedClaim("letterNumber", it, "發文字號")) }
        }
        return out
    }

    /**
     * A label right before a full or half width colon: CJK characters (with brackets or a slash, no spaces, so that
     * the value of an earlier label on the same line is not taken in), or up to four Latin words.
     */
    private val labelRe = Regex("([\\u3400-\\u9FFF\\uF900-\\uFAFF][\\u3400-\\u9FFF\\uF900-\\uFAFF（）()／/、A-Za-z]{0,14}|[A-Za-z]+(?: [A-Za-z]+){0,3})\\s*[：:]")

    private val notLabels = setOf("http", "https", "mailto", "ftp", "file", "data", "urn", "did")

    /**
     * "label: value" pairs of a text layer, several per line when the line holds several labels; the first value of a
     * label wins. Values that are empty, longer than [MAX_VALUE] characters or only punctuation are left out.
     */
    fun fromText(text: String): List<DerivedClaim> {
        val out = ArrayList<DerivedClaim>()
        for (line in text.lines()) {
            val matches = labelRe.findAll(line).filter { m ->
                val label = m.groupValues[1].trim()
                label.lowercase() !in notLabels && !(m.range.last + 1 < line.length && line[m.range.last + 1] == '/')
            }.toList()
            matches.forEachIndexed { i, m ->
                val end = if (i + 1 < matches.size) matches[i + 1].range.first else line.length
                val label = m.groupValues[1].trim().replace(Regex("\\s+"), "")
                val v = line.substring(m.range.last + 1, end).trim()
                if (label.length >= 2 && v.any { it.isLetterOrDigit() }) value(v)?.let { out.add(DerivedClaim(label, it, label)) }
            }
        }
        return unique(out)
    }

    /** The first line of a text layer that reads like a title: short, with letters and not a "label: value" line. */
    fun titleFromText(text: String): String? = text.lines().map { it.trim() }.firstOrNull { l ->
        l.length in 2..40 && l.count { it.isLetter() } >= 2 && !labelRe.containsMatchIn(l)
    }

    private fun value(v: String): String? = v.trim().replace(Regex("\\s+"), " ").takeIf { it.isNotEmpty() && it.length <= MAX_VALUE }

    private fun unique(list: List<DerivedClaim>): List<DerivedClaim> {
        val seen = HashSet<String>()
        return list.filter { seen.add(it.name) }.take(MAX_FIELDS)
    }

    private fun unescape(s: String) = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}
