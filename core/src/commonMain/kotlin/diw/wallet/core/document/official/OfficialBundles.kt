package diw.wallet.core.document.official

import diw.wallet.core.document.XmlElement
import diw.wallet.core.document.XmlTree

/** One reason for or against putting a file in an official document's container, as the holder reads it. */
data class BundleEvidence(val text: String, val supports: Boolean)

/** How well a file fits the container of an official document. */
data class BundleMatch(val evidence: List<BundleEvidence>) {
    val supported: Boolean get() = evidence.any { it.supports }
    val contradicted: Boolean get() = evidence.any { !it.supports }

    /** Suggested for the container: something points to the document and nothing against it. */
    val suggested: Boolean get() = supported && !contradicted
}

/**
 * An official document travels with related files: the exchange form (.sw) listing whom it is sent to, the online
 * approval file (.si), message forms (.dm) and attachments. Nothing in the files names the document they belong to
 * for sure, so the wallet collects the hints (same file name, receivers that match the document's 受文者, 正本 and 副本,
 * the attachment field naming the file) and the holder confirms before files are put together.
 */
object OfficialBundles {
    /** Root elements of the forms that accompany a document rather than being one. */
    val FORMS = setOf("交換表單", "文書訊息表單", "線上簽核", "跨機關陳核會稿交換表單")

    /** True when [bytes] named [name] is an official document that can hold related files (a .di and the like). */
    fun isMain(name: String, bytes: ByteArray): Boolean {
        val ext = name.substringAfterLast('.', "").lowercase()
        if (ext in setOf("sw", "si", "dm", "co")) return false
        val root = XmlTree.parse(bytes)?.root ?: return false
        return root.name in OfficialDocuments.KINDS && root.name !in FORMS
    }

    /** True when [name] is a file of the official document exchange (.di, .sw, .si, .dm, .co). */
    fun isExchangeFile(name: String): Boolean = name.substringAfterLast('.', "").lowercase() in OfficialDocuments.EXTENSIONS

    /** Evidence that [candidate] (named [candidateName]) belongs with the document [main] (named [mainName]). */
    fun match(mainName: String, main: ByteArray, candidateName: String, candidate: ByteArray): BundleMatch {
        val evidence = ArrayList<BundleEvidence>()
        val base = mainName.substringBeforeLast('.')
        val otherBase = candidateName.substringBeforeLast('.')
        if (base.isNotBlank() && base == otherBase) evidence.add(BundleEvidence("檔名相同（$base）", true))
        val doc = XmlTree.parse(main)?.root
        val other = XmlTree.parse(candidate)?.root
        if (doc != null && other != null) {
            when (other.name) {
                "交換表單" -> receivers(doc, other)?.let { evidence.add(it) }
                "線上簽核" -> {
                    val listed = other.descendants("檔案").map { it.text.trim() } + other.descendants("文稿").map { it.text.trim() } +
                        other.descendants("附件").map { it.deepText() }
                    if (listed.any { it.isNotBlank() && (it.contains(mainName) || (base.isNotBlank() && it.contains(base))) }) {
                        evidence.add(BundleEvidence("簽核檔列出這份公文", true))
                    }
                }
            }
            if (other.name == doc.name && other != doc && other.name !in FORMS) {
                evidence.add(BundleEvidence("這也是一份「${other.name}」，通常是另一份公文", false))
            }
        }
        if (doc != null && other == null) {
            // Attachments are named in the document's 附件 field.
            val attachments = doc.descendants("附件").joinToString(" ") { it.deepText() } + " " + doc.descendants("附件檔名").joinToString(" ") { it.deepText() }
            if (candidateName.isNotBlank() && attachments.contains(candidateName.substringBeforeLast('.'))) {
                evidence.add(BundleEvidence("公文的附件欄列出這個檔名", true))
            }
        }
        return BundleMatch(evidence)
    }

    /** The exchange form's receivers against the document's 受文者, 正本 and 副本, by full name or agency code. */
    private fun receivers(doc: XmlElement, form: XmlElement): BundleEvidence? {
        val names = HashSet<String>()
        val codes = HashSet<String>()
        for (part in listOf("受文者", "正本", "副本")) {
            for (e in doc.descendants(part)) {
                e.descendants("全銜").forEach { names.add(norm(it.text)) }
                if (e.children.isEmpty()) e.text.split('、', '，', ',').forEach { names.add(norm(it)) }
                e.descendants("機關代碼").forEach { codes.add(norm(it.text)) }
            }
        }
        names.removeAll { it.isEmpty() }
        codes.removeAll { it.isEmpty() || it.all { c -> c == '○' } }
        val listed = form.descendants("全銜").map { norm(it.text) }.filter { it.isNotEmpty() }.distinct()
        val formCodes = form.descendants("機關代碼").map { norm(it.text) }.filter { it.isNotEmpty() && !it.all { c -> c == '○' } }
        if (listed.isEmpty() || (names.isEmpty() && codes.isEmpty())) return null
        val hits = listed.count { it in names } + formCodes.distinct().count { it in codes }
        return if (hits > 0) BundleEvidence("交換表單的 ${listed.size} 個發送對象中，有 $hits 個與公文的受文者、正本或副本相符", true)
        else BundleEvidence("交換表單的發送對象與公文的受文者、正本、副本都不相同", false)
    }

    private fun norm(s: String): String = s.replace(Regex("\\s+"), "").replace('（', '(').replace('）', ')')

    /**
     * An entry name of a ZIP made by tools that write non-ASCII names as "#Uxxxx" escapes (獎懲令.di arrives as
     * "#U734e#U61f2#U4ee4.di"), decoded; other names stay as they are.
     */
    fun decodeZipName(name: String): String =
        Regex("#U([0-9A-Fa-f]{4})").replace(name) { it.groupValues[1].toInt(16).toChar().toString() }
}
