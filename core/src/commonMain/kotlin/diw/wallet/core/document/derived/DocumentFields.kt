package diw.wallet.core.document.derived

import diw.wallet.core.document.OpenCertInfo
import diw.wallet.core.document.official.OfficialDocument
import diw.wallet.core.document.official.OfficialEntry

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
        "credentialSubject.name" to ("recipientName" to "受領人"),
        "id" to ("documentId" to "證書編號"),
        "issuedOn" to ("issuedOn" to "發證日期"),
        "issuanceDate" to ("issuedOn" to "發證日期"),
        "expirationDate" to ("expiresOn" to "到期日期"),
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
    private val openCertSkipped = Regex("^(\\\$template|issuers|issuer|transcript|attachments|additionalData|logo|signature|qrCode|privacy|openAttestationMetadata|@context|type|version|schema|credentialSubject\\.id)(\\.|$)")

    /** OpenCerts data: the well known fields first, then the other scalar fields by their path. */
    fun fromOpenCert(info: OpenCertInfo): List<DerivedClaim> {
        val out = ArrayList<DerivedClaim>()
        for ((path, nl) in openCertNames) info.fields[path]?.let { v -> value(v)?.let { out.add(DerivedClaim(nl.first, it, nl.second)) } }
        info.issuers.takeIf { it.isNotEmpty() }?.let { out.add(DerivedClaim("documentIssuer", it.joinToString("、"), "發證機構")) }
        for ((path, v) in info.fields) {
            if (path in openCertNames || path == "name" || openCertSkipped.containsMatchIn(path)) continue
            val text = value(v) ?: continue
            out.add(DerivedClaim(path, text, openCertLabel(path)))
        }
        return unique(out)
    }

    /** "recipient.courseCode" reads "Recipient / Course Code"; array indexes are dropped. */
    private fun openCertLabel(path: String): String =
        path.split('.').filter { it.toIntOrNull() == null }.takeLast(2).joinToString(" / ") { k ->
            k.replace(Regex("([a-z0-9])([A-Z])"), "$1 $2").replace('_', ' ').trim().replaceFirstChar { it.uppercase() }
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

    /** Labels [fromOfficialLetter] already gives a letter under its own claim names. */
    private val letterLabels = setOf("發文機關", "受文者", "發文日期", "主旨", "發文字號")

    /**
     * The fields of any official document (簽, 令, 便簽, 會勘通知單, forms): the labelled values of its main part, its
     * subject, and for an online approval file who made the final decision (決行) and when. A letter's sender,
     * recipient, date, number and subject come from [fromOfficialLetter] instead.
     */
    fun fromOfficial(doc: OfficialDocument): List<DerivedClaim> {
        val out = ArrayList<DerivedClaim>()
        val letter = doc.kind == "函"
        out.add(DerivedClaim("officialKind", doc.category?.takeIf { it != doc.kind }?.let { "${doc.kind}（$it）" } ?: doc.kind, "公文類別"))
        if (!letter) doc.subject?.let { value(it) }?.let { out.add(DerivedClaim("officialSubject", it, "主旨")) }
        doc.sections.firstOrNull { it.title == null }?.entries?.forEach { e ->
            if (e is OfficialEntry.Field && !(letter && e.label in letterLabels)) value(e.value)?.let { out.add(DerivedClaim(e.label, it, e.label)) }
        }
        doc.steps.lastOrNull { it.action == "決行" }?.let { s ->
            s.signer?.let { value(it) }?.let { out.add(DerivedClaim("officialDecidedBy", it, "決行者")) }
            s.time?.let { out.add(DerivedClaim("officialDecidedAt", it, "決行時間")) }
        }
        return unique(out)
    }

    private const val CJK = "\\u3400-\\u9FFF\\uF900-\\uFAFF"

    /**
     * A label right before a full or half width colon: CJK characters (with brackets or a slash, no spaces, so that
     * the value of an earlier label on the same line is not taken in) or up to four Latin words (hyphens allowed, as
     * in E-mail), either optionally followed by a bracketed translation ("邮编(Zip Code)") and a "/English" part
     * ("打印日期/Date").
     */
    private val labelRe = Regex(
        "((?:[$CJK][$CJK（）()／/、]{0,14}|(?<![A-Za-z])[A-Za-z][A-Za-z-]*(?: [A-Za-z][A-Za-z-]*){0,3})" +
            "(?:\\s?[（(][^（()）：:]{1,30}[)）])?(?:/[A-Za-z][A-Za-z ]{0,20})?)\\s*[：:]",
    )

    private val notLabels = setOf("http", "https", "mailto", "ftp", "file", "data", "urn", "did")

    /** A value ends at sentence punctuation or at a wide gap (the next column of the line). */
    private val valueEnd = Regex("[，。；;]|\\s{4,}")

    private val trailing = Regex("[，,。；;、\\s]+$")

    /** A document number printed on its own line: "NO.202610088168". */
    private val numberLine = Regex("^(?:NO|No|no)\\.?\\s*([A-Za-z0-9][A-Za-z0-9-]{3,})$")

    private fun labels(line: String): List<MatchResult> = labelRe.findAll(line).filter { m ->
        val label = m.groupValues[1].trim()
        label.lowercase() !in notLabels && !(m.range.last + 1 < line.length && line[m.range.last + 1] == '/')
    }.toList()

    private fun cut(raw: String): String = raw.let { r -> valueEnd.find(r)?.let { r.substring(0, it.range.first) } ?: r }.replace(trailing, "").trim()

    /**
     * "label: value" pairs of a text layer, several per line when the line holds several labels; the first value of a
     * label wins. A value stops at the next label, at sentence punctuation (so "学生：甲，性别：男，出生于..." gives
     * two short values rather than the sentence) or at a wide gap; a label ending its line takes the start of the
     * next line. Values that are empty, longer than [MAX_VALUE] characters or only punctuation are left out.
     */
    fun fromText(text: String): List<DerivedClaim> {
        val out = ArrayList<DerivedClaim>()
        val lines = text.lines()
        lines.forEachIndexed { n, line ->
            numberLine.matchEntire(line.trim())?.let { m -> out.add(DerivedClaim("documentNumber", m.groupValues[1], "文件編號")) }
            val matches = labels(line)
            matches.forEachIndexed { i, m ->
                val end = if (i + 1 < matches.size) matches[i + 1].range.first else line.length
                val label = m.groupValues[1].trim().replace(Regex("\\s+(?=[（(])"), "")
                var v = cut(line.substring(m.range.last + 1, end))
                if (v.isEmpty() && i == matches.lastIndex && n + 1 < lines.size) {
                    val next = lines[n + 1]
                    if (labels(next).firstOrNull()?.range?.first != 0) v = cut(next.substring(0, labels(next).firstOrNull()?.range?.first ?: next.length))
                }
                if (label.length >= 2 && v.any { it.isLetterOrDigit() }) value(v)?.let { out.add(DerivedClaim(label, it, label)) }
            }
        }
        val joined = lines.joinToString("") { it.trim() }
        for ((name, re) in prose) re.find(joined)?.let { m -> value(m.groupValues[1])?.let { out.add(DerivedClaim(name, it, name)) } }
        return unique(out)
    }

    private const val DATE = "(\\d{4}\\s*年\\s*\\d{1,2}\\s*月\\s*\\d{1,2}\\s*日|民國\\s*\\d{2,3}\\s*年\\s*\\d{1,2}\\s*月\\s*\\d{1,2}\\s*日)"

    /** Facts certificates state in a sentence rather than as "label: value" (学籍证明: "出生于 2007 年 02 月 16 日"). */
    private val prose = listOf(
        "出生日期" to Regex("出生(?:于|於)\\s*$DATE"),
        "入學年月" to Regex("(?:于|於)\\s*(\\d{4}\\s*年\\s*\\d{1,2}\\s*月)\\s*(?:入学|入學)"),
    )

    private val titleWords = listOf("證明", "证明", "證書", "证书", "謄本", "誊本", "資料", "资料", "通知", "公告", "執照", "执照", "Certificate", "Proof", "Transcript")

    /**
     * The title of a text layer: the first short line naming a kind of document (證明, 證書, 謄本...), else the first
     * short line with letters that is not a "label: value" line.
     */
    fun titleFromText(text: String): String? {
        val candidates = text.lines().map { it.trim() }.filter { l -> l.length in 2..40 && l.count { it.isLetter() } >= 2 && !labelRe.containsMatchIn(l) }
        return candidates.firstOrNull { l -> titleWords.any { l.contains(it, ignoreCase = true) } } ?: candidates.firstOrNull()
    }

    private fun value(v: String): String? = v.trim().replace(Regex("\\s+"), " ").takeIf { it.isNotEmpty() && it.length <= MAX_VALUE }

    private fun unique(list: List<DerivedClaim>): List<DerivedClaim> {
        val seen = HashSet<String>()
        return list.filter { seen.add(it.name) }.take(MAX_FIELDS)
    }

    private fun unescape(s: String) = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}
