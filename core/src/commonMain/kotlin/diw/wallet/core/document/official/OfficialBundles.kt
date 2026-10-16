package diw.wallet.core.document.official

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.XmlElement
import diw.wallet.core.document.XmlTree
import org.multipaz.util.fromBase64

/** One reason for or against putting a file in an official document's container, as the holder reads it. */
data class BundleEvidence(val text: String, val supports: Boolean)

/** A file an online approval (.si) signed: its name (the XMLDSig Reference URI) and digest. */
data class ApprovalReference(val uri: String, val algorithm: String, val digest: ByteArray) {
    /** True when [bytes] have this digest. */
    fun matches(bytes: ByteArray): Boolean = runCatching { DocCrypto.digest(algorithm, bytes).contentEquals(digest) }.getOrDefault(false)

    override fun equals(other: Any?) = other is ApprovalReference && other.uri == uri && other.algorithm == algorithm && other.digest.contentEquals(digest)
    override fun hashCode() = uri.hashCode() * 31 + digest.contentHashCode()
}

/** An online approval file (.si) and the files its signatures cover. */
class ApprovalFile(val name: String, val references: List<ApprovalReference>) {
    /** True: [fileName] is listed with the digest of [bytes]; false: listed with other content; null: not listed. */
    fun lists(fileName: String, bytes: ByteArray): Boolean? {
        val refs = references.filter { it.uri == fileName }
        if (refs.isEmpty()) return null
        return refs.any { it.matches(bytes) }
    }

    /** Names of the files listed, in the order they first appear. */
    val names: List<String> get() = references.map { it.uri }.distinct()

    companion object {
        /** The approval in [bytes] named [name], or null when it is not an online approval listing files. */
        fun of(name: String, bytes: ByteArray): ApprovalFile? =
            OfficialBundles.approvalReferences(bytes).takeIf { it.isNotEmpty() }?.let { ApprovalFile(name, it) }
    }
}

/**
 * One signing point (簽核點定義) of an online approval: who signed, the action and time it states, and the files its
 * own signature covers ([references], in SignedInfo order).
 */
class ApprovalPointFiles(
    val index: Int,
    val signer: String?,
    val action: String?,
    val time: String?,
    val references: List<ApprovalReference>,
    /** The point holds an XMLDSig Signature (a point approved without a certificate has none). */
    val signed: Boolean = true,
) {
    val names: List<String> get() = references.map { it.uri }.distinct()
}

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

    /**
     * The files the signatures of an online approval (.si, root 線上簽核) cover: each XMLDSig Reference to a file
     * (not to an element of the approval itself) with its digest. Empty when [bytes] is not such an approval.
     */
    fun approvalReferences(bytes: ByteArray): List<ApprovalReference> {
        val root = XmlTree.parse(bytes)?.root ?: return emptyList()
        if (root.name != "線上簽核") return emptyList()
        return fileReferences(root).distinct()
    }

    /**
     * The signing points of the online approval in [bytes], in document order, each with the files its own signature
     * covers. A file signed again unchanged at a later point is listed there too. Empty for any other file.
     */
    fun approvalPoints(bytes: ByteArray): List<ApprovalPointFiles> {
        val root = XmlTree.parse(bytes)?.root ?: return emptyList()
        if (root.name != "線上簽核") return emptyList()
        return root.descendants("簽核點定義").mapIndexed { i, point ->
            val info = point.descendants("異動資訊").firstOrNull()
            val signature = point.children.firstOrNull { it.name == "Signature" }
            ApprovalPointFiles(
                index = i,
                signer = info?.child("簽核人員")?.child("姓名")?.deepText()?.ifBlank { null },
                action = info?.child("異動別")?.deepText()?.ifBlank { null },
                time = info?.child("簽章時間")?.deepText()?.ifBlank { null },
                references = signature?.let { fileReferences(it).distinct() }.orEmpty(),
                signed = signature != null,
            )
        }
    }

    /** XMLDSig References under [e] that point to a file (not to an element), with their digests. */
    private fun fileReferences(e: XmlElement): List<ApprovalReference> = e.descendants("Reference").mapNotNull { ref ->
        val uri = ref.attributes["URI"]?.trim()?.takeIf { it.isNotEmpty() && !it.startsWith("#") } ?: return@mapNotNull null
        val algorithm = digestAlgorithm(ref.descendants("DigestMethod").firstOrNull()?.attributes?.get("Algorithm")) ?: return@mapNotNull null
        val digest = ref.descendants("DigestValue").firstOrNull()?.text?.replace(Regex("\\s+"), "")
            ?.let { runCatching { it.fromBase64() }.getOrNull() } ?: return@mapNotNull null
        ApprovalReference(uri, algorithm, digest)
    }

    private fun digestAlgorithm(uri: String?): String? = when (uri?.substringAfterLast('#')) {
        "sha1" -> "SHA-1"
        "sha256" -> "SHA-256"
        "sha384" -> "SHA-384"
        "sha512" -> "SHA-512"
        else -> null
    }

    /**
     * Evidence that [candidate] (named [candidateName]) belongs with the document [main] (named [mainName]).
     * [approvals] are the online approval files that came with them: one that signed both files with their current
     * content is the strongest hint, since the approval names each file and its digest.
     */
    fun match(
        mainName: String, main: ByteArray, candidateName: String, candidate: ByteArray,
        approvals: List<ApprovalFile> = emptyList(),
    ): BundleMatch {
        val evidence = ArrayList<BundleEvidence>()
        val base = mainName.substringBeforeLast('.')
        val otherBase = candidateName.substringBeforeLast('.')
        if (base.isNotBlank() && base == otherBase) evidence.add(BundleEvidence("檔名相同（$base）", true))
        var approved = false
        for (a in approvals) {
            if (a.name == candidateName || a.name == mainName) continue
            val mainListed = a.lists(mainName, main)
            val listed = a.lists(candidateName, candidate)
            when {
                mainListed == true && listed == true -> {
                    evidence.add(BundleEvidence("簽核檔「${a.name}」列出公文與這個檔案，內容雜湊相符", true)); approved = true
                }
                mainListed == true && listed == false ->
                    evidence.add(BundleEvidence("簽核檔「${a.name}」列出同名檔案，但內容不同", false))
            }
        }
        val doc = XmlTree.parse(main)?.root
        val other = if (candidateName.substringAfterLast('.', "").lowercase() in BINARY_EXTENSIONS) null else XmlTree.parse(candidate)?.root
        if (doc != null && other != null) {
            when (other.name) {
                "交換表單" -> receivers(doc, other)?.let { evidence.add(it) }
                "線上簽核" -> {
                    when (ApprovalFile.of(candidateName, candidate)?.lists(mainName, main)) {
                        true -> { evidence.add(BundleEvidence("簽核檔列出這份公文，內容雜湊相符", true)); approved = true }
                        false -> evidence.add(BundleEvidence("簽核檔列出同名的公文，但內容不同（可能是另一個版本）", false))
                        null -> {
                            val listed = other.descendants("檔案").map { it.text.trim() } + other.descendants("文稿").map { it.text.trim() } +
                                other.descendants("附件").map { it.deepText() }
                            if (listed.any { it.isNotBlank() && (it.contains(mainName) || (base.isNotBlank() && it.contains(base))) }) {
                                evidence.add(BundleEvidence("簽核檔列出這份公文", true))
                            }
                        }
                    }
                }
            }
            // Drafts and versions of one case are all documents; an approval that signed both settles it.
            if (!approved && other.name == doc.name && other != doc && other.name !in FORMS) {
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

    /** Extensions of files that are never XML (attachments and page images), so they are not parsed as such. */
    private val BINARY_EXTENSIONS = setOf("doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "pdf", "tif", "tiff", "png", "jpg", "jpeg", "gif", "zip")

    private fun norm(s: String): String = s.replace(Regex("\\s+"), "").replace('（', '(').replace('）', ')')

    /**
     * An entry name of a ZIP made by tools that write non-ASCII names as "#Uxxxx" escapes (獎懲令.di arrives as
     * "#U734e#U61f2#U4ee4.di"), decoded; other names stay as they are.
     */
    fun decodeZipName(name: String): String =
        Regex("#U([0-9A-Fa-f]{4})").replace(name) { it.groupValues[1].toInt(16).toChar().toString() }
}
