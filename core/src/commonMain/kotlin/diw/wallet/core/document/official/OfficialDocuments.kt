package diw.wallet.core.document.official

import diw.wallet.core.document.XmlElement
import diw.wallet.core.document.XmlTree
import kotlinx.io.bytestring.ByteString
import org.multipaz.asn1.OID
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64

/** One line of an official document: a labelled value, or a paragraph (主旨, 說明 with its numbered items). */
sealed class OfficialEntry {
    data class Field(val label: String, val value: String) : OfficialEntry()

    data class Paragraph(val heading: String?, val text: String?, val items: List<OfficialItem>) : OfficialEntry()
}

/** A numbered item of a paragraph (條列), such as "一、" with its own sub items. */
data class OfficialItem(val number: String?, val text: String?, val items: List<OfficialItem>)

/** A part of the document: the main body, or a nested part such as one co-signing agency (會辦機關). */
data class OfficialSection(val title: String?, val entries: List<OfficialEntry>)

/** A node of the planned approval flow (線上簽核流程), [depth] 0 for the main line, deeper for parallel branches. */
data class OfficialFlowNode(val name: String, val action: String?, val depth: Int)

/** One signing point of an online approval file (簽核點定義): who acted, how, when, what they wrote and on which files. */
data class OfficialStep(
    val point: String?,
    val action: String?,
    val signer: String?,
    val role: String?,
    val time: String?,
    val opinions: List<String>,
    val next: List<String>,
    /** Subject common name of the certificate in the signing point's XMLDSig KeyInfo. */
    val certificate: String?,
    val drafts: List<String>,
    val files: List<String>,
)

/**
 * A Taiwanese official document in XML (文書處理檔案管理手冊 DTD 104 series): 函, 書函, 令, 公告, 簽, 稿, 便簽,
 * 開會通知單, 會勘通知單, 會銜公文會辦單, the online approval file 線上簽核 (.si), the message form 文書訊息表單 (.dm),
 * the exchange form 交換表單 (.sw) and the cross-agency consultation form 跨機關陳核會稿交換表單 (.co).
 */
data class OfficialDocument(
    /** The root element, such as 函. */
    val kind: String,
    /** The category code the document states (函類別 書函, 令類別 獎懲令), else null. */
    val category: String?,
    /** What a reader sees on top: the issuing agency and the document type. */
    val title: String,
    /** The subject (主旨 or 事由), when there is one. */
    val subject: String?,
    val sections: List<OfficialSection>,
    val flow: List<OfficialFlowNode> = emptyList(),
    val steps: List<OfficialStep> = emptyList(),
)

/** Reads official documents from XML into what a person reads, never showing the XML itself. */
object OfficialDocuments {
    /** Root elements of the DTD 104 series and the forms that travel with them. */
    val KINDS = setOf(
        "函", "書函", "令", "公告", "簽", "稿", "便簽", "開會通知單", "會勘通知單", "會銜公文會辦單", "公文會辦單",
        "線上簽核", "文書訊息表單", "交換表單", "跨機關陳核會稿交換表單",
    )

    private val dtd = Regex("(^|/)104_[A-Za-z0-9]+(_utf8)?\\.dtd$", RegexOption.IGNORE_CASE)

    /** File name extensions the official document exchange uses. */
    val EXTENSIONS = setOf("di", "si", "sw", "co", "dm")

    /** The document in [bytes], or null when it is not XML or not an official document. */
    fun parse(bytes: ByteArray): OfficialDocument? {
        val doc = XmlTree.parse(bytes) ?: return null
        val known = doc.root.name in KINDS || doc.systemId?.let { dtd.containsMatchIn(it.trim()) } == true
        return if (known) read(doc.root) else null
    }

    /** The document whose root element is [root]. */
    fun read(root: XmlElement): OfficialDocument {
        if (root.name == "線上簽核") return approval(root)
        if (root.name == "交換表單") return roster(root)
        val category = root.children.firstOrNull { it.name.endsWith("類別") }?.let { code(it) }
        val agency = root.all("發文機關").mapNotNull { it.child("全銜")?.text?.ifBlank { null } }
            .ifEmpty { listOfNotNull(root.child("全銜")?.text?.ifBlank { null }) }
        val kindName = category?.takeIf { it != root.name && it.isNotBlank() } ?: root.name
        val title = (agency.joinToString("、") + " " + kindName).trim()
        val subject = (root.child("主旨") ?: root.children.firstOrNull { it.name.endsWith("事由") })?.let { paragraphText(it) }
        val sections = ArrayList<OfficialSection>()
        val main = ArrayList<OfficialEntry>()
        // An XAdES or XMLDSig signature added to the document is checked and shown as a signature, not as content.
        readInto(root, main, sections, skip = { it.name.endsWith("類別") || it.name == "Signature" })
        sections.add(0, OfficialSection(null, main))
        return OfficialDocument(root.name, category, title, subject, sections.filter { it.entries.isNotEmpty() })
    }

    // ---------------------------------------------------------------- general documents

    private fun readInto(e: XmlElement, out: MutableList<OfficialEntry>, sections: MutableList<OfficialSection>, skip: (XmlElement) -> Boolean = { false }) {
        for (c in e.children) {
            if (skip(c)) continue
            entry(c, out, sections)
        }
    }

    private val partyLeaves = setOf("全銜", "機關代碼", "單位代碼")
    private val personLeaves = setOf("姓名", "職稱", "電話", "單位", "單位名")

    private fun entry(c: XmlElement, out: MutableList<OfficialEntry>, sections: MutableList<OfficialSection>) {
        val names = c.children.map { it.name }.toSet()
        when {
            c.name == "段落" -> paragraph(c)?.let(out::add)
            c.name == "條列" -> item(c).let { out.add(OfficialEntry.Paragraph(null, null, listOf(it))) }
            c.name == "主旨" || c.name.endsWith("事由") ->
                paragraphText(c)?.let { out.add(OfficialEntry.Paragraph(c.name + "：", it, items(c))) }
            names.isNotEmpty() && names.all { it == "段落" } -> c.children.mapNotNull { paragraph(it) }.forEach(out::add)
            "年月日" in names || "時分" in names -> dateText(c)?.let { field(out, c.name, it) }
            c.name.endsWith("字號") || c.name == "文號" || "文號" in names -> numberText(c)?.let { field(out, label(c.name), it) }
            c.name == "密等及解密條件或保密期限" -> c.children.mapNotNull { it.deepText().ifBlank { null } ?: code(it) }
                .takeIf { it.isNotEmpty() }?.let { field(out, "密等", it.joinToString("，")) }
            c.name == "聯絡方式" -> contact(c.text)?.let { (l, v) -> field(out, l, v) }
            names.isNotEmpty() && names.all { it in partyLeaves } -> {
                val parties = c.all("全銜").mapNotNull { it.text.ifBlank { null } }
                if (parties.isNotEmpty()) field(out, label(c.name), parties.joinToString("、"))
                else c.child("機關代碼")?.text?.ifBlank { null }?.let { field(out, label(c.name) + "代碼", it) }
            }
            names.isNotEmpty() && names.all { it in personLeaves } -> person(c)?.let { field(out, label(c.name), it) }
            names == setOf("文字") -> paragraphText(c)?.let { field(out, label(c.name), it) }
            names.isEmpty() -> {
                val v = c.text.ifBlank { null } ?: code(c)?.let { codeText(c.name, it) }
                v?.let { field(out, label(c.name), it) }
            }
            names.size == 1 && c.children.size == 1 && c.children[0].children.isEmpty() -> {
                val inner = c.children[0]
                (inner.text.ifBlank { null } ?: code(inner)?.let { codeText(inner.name, it) })?.let { field(out, label(c.name), it) }
            }
            else -> {
                val title = c.child("全銜")?.text?.ifBlank { null }?.let { "${label(c.name)}：$it" } ?: label(c.name)
                val inner = ArrayList<OfficialEntry>()
                readInto(c, inner, sections, skip = { it.name == "全銜" && c.child("全銜") === it })
                if (inner.isNotEmpty()) sections.add(OfficialSection(title, inner))
            }
        }
    }

    private fun field(out: MutableList<OfficialEntry>, label: String, value: String) {
        val v = value.trim()
        if (v.isNotEmpty()) out.add(OfficialEntry.Field(label, v))
    }

    private val labels = mapOf(
        "年月日" to "日期",
        "全銜" to "機關",
        "決行" to "決行人",
        "審核" to "審核人",
        "承辦" to "承辦人",
        "會辦" to "會辦人",
        "聯絡人及電話" to "聯絡人",
        "收發處理本別" to "本別",
        "文書訊息代碼" to "訊息代碼",
    )

    private fun label(name: String): String = labels[name] ?: name

    private fun code(e: XmlElement): String? = e.attributes["代碼"]?.trim()?.ifEmpty { null }

    /** Codes whose meaning the DTD fixes; others are shown as written. */
    private fun codeText(name: String, code: String): String = when (name) {
        "會陳狀態" -> when (code) {
            "1" -> "外陳"
            "2" -> "外會"
            "3" -> "回文"
            "4" -> "退文"
            else -> code
        }
        "文書訊息代碼" -> "代碼 $code"
        else -> code
    }

    private fun contact(text: String): Pair<String, String>? {
        val t = text.trim()
        val i = t.indexOfFirst { it == '：' || it == ':' }
        if (i <= 0) return t.ifEmpty { null }?.let { "聯絡方式" to it }
        val v = t.substring(i + 1).trim()
        return if (v.isEmpty()) null else t.substring(0, i).trim() to v
    }

    private fun person(e: XmlElement): String? {
        val parts = listOf("單位", "單位名", "職稱", "姓名").mapNotNull { e.child(it)?.text?.ifBlank { null } }
        val phone = e.child("電話")?.text?.ifBlank { null }
        val base = parts.joinToString(" ")
        return when {
            base.isEmpty() && phone == null -> null
            phone == null -> base
            base.isEmpty() -> phone
            else -> "$base（$phone）"
        }
    }

    private fun dateText(e: XmlElement): String? {
        val date = e.child("年月日")?.text?.ifBlank { null }
        val week = e.child("星期")?.text?.ifBlank { null }?.let { "（星期$it）" }
        val time = e.child("時分")?.text?.ifBlank { null }
        val text = listOfNotNull(date?.let { it + (week ?: "") } ?: week, time).joinToString(" ")
        return text.ifBlank { null }
    }

    /** "檔管字第1100000001號"; a number of a 簽 without its word is "1100000001". */
    private fun numberText(e: XmlElement): String? {
        val n = if (e.name == "文號") e else e.child("文號") ?: e.descendants("文號").firstOrNull()
        val year = n?.child("年度")?.text.orEmpty()
        val serial = n?.child("流水號")?.text.orEmpty()
        val branch = n?.child("支號")?.text.orEmpty()
        val word = e.child("字")?.text.orEmpty()
        if (year.isBlank() && serial.isBlank()) return null
        val number = year + serial + if (branch.isNotBlank()) "-$branch" else ""
        return if (word.isBlank()) number else "${word}字第${number}號"
    }

    private fun paragraphText(e: XmlElement): String? =
        e.all("文字").map { it.deepText() }.filter { it.isNotBlank() }.joinToString("\n").ifBlank { null }
            ?: e.text.ifBlank { null }

    private fun items(e: XmlElement): List<OfficialItem> = e.all("條列").map(::item)

    private fun item(e: XmlElement): OfficialItem =
        OfficialItem(e.attributes["序號"]?.ifBlank { null }, paragraphText(e), items(e))

    private fun paragraph(e: XmlElement): OfficialEntry.Paragraph? {
        val heading = e.attributes["段名"]?.takeIf { it.isNotBlank() && it.any { ch -> ch != '　' && !ch.isWhitespace() } }
        val text = paragraphText(e)
        val items = items(e).filter { hasContent(it) }
        if (text == null && items.isEmpty()) return null
        return OfficialEntry.Paragraph(heading, text, items)
    }

    private fun hasContent(i: OfficialItem): Boolean = i.text != null || i.items.any(::hasContent)

    // ---------------------------------------------------------------- 交換表單 (.sw)

    /** The exchange form lists receivers one after another (全銜, 機關代碼, 單位代碼, 本別); one line per receiver. */
    private fun roster(root: XmlElement): OfficialDocument {
        val rows = ArrayList<OfficialEntry>()
        var name: String? = null
        var codes = ArrayList<String>()
        var copy: String? = null
        fun flush() {
            val n = name ?: return
            val code = codes.filter { it.isNotBlank() }.joinToString(" ")
            rows.add(OfficialEntry.Field(copy ?: "受文者", if (code.isEmpty()) n else "$n（$code）"))
            name = null; codes = ArrayList(); copy = null
        }
        for (c in root.children) {
            when (c.name) {
                "全銜" -> { flush(); name = c.text.ifBlank { null } }
                "機關代碼", "單位代碼" -> codes.add(c.text)
                "本別" -> copy = c.children.firstNotNullOfOrNull { code(it) } ?: c.deepText().ifBlank { null }
                else -> { flush(); entry(c, rows, ArrayList()) }
            }
        }
        flush()
        return OfficialDocument(root.name, null, "交換表單", null, listOf(OfficialSection("發送對象", rows)))
    }

    // ---------------------------------------------------------------- 線上簽核 (.si)

    private fun approval(root: XmlElement): OfficialDocument {
        val flow = ArrayList<OfficialFlowNode>()
        fun walk(e: XmlElement, depth: Int) {
            for (c in e.children) {
                when (c.name) {
                    "簽核流程" -> {
                        flow.add(OfficialFlowNode(flowName(c.attributes["Id"]), c.attributes["異動別"], depth))
                        walk(c, depth + 1)
                    }
                    "分會點" -> walk(c, depth)
                }
            }
        }
        root.child("線上簽核流程")?.let { walk(it, 0) }
        val steps = root.descendants("簽核點定義").map(::step)
        val files = LinkedHashSet<String>()
        steps.forEach { files.addAll(it.files) }
        val entries = ArrayList<OfficialEntry>()
        root.attributes["Id"]?.let { entries.add(OfficialEntry.Field("簽核編號", it.removePrefix("sign_"))) }
        entries.add(OfficialEntry.Field("簽核點", steps.size.toString()))
        if (files.isNotEmpty()) entries.add(OfficialEntry.Field("簽核檔案", files.joinToString("\n")))
        val subject = steps.firstNotNullOfOrNull { s -> s.opinions.firstOrNull() }
        return OfficialDocument(root.name, null, "線上簽核", subject, listOf(OfficialSection(null, entries)), flow, steps)
    }

    private fun flowName(id: String?): String = id?.replace(Regex("^(FLOW_)+"), "")?.ifBlank { null } ?: "簽核點"

    private fun step(point: XmlElement): OfficialStep {
        val info = point.descendants("異動資訊").firstOrNull()
        val signer = info?.child("簽核人員")
        val opinions = info?.all("簽核意見")?.mapNotNull { it.deepText().ifBlank { null } }.orEmpty()
        val next = info?.child("次位簽核人員")?.all("簽核人員")?.mapNotNull { person(it) }.orEmpty()
        val cert = point.descendants("X509Certificate").firstOrNull()?.text?.let(::certificateName)
        val folder = point.descendants("簽核文件夾").lastOrNull()
        val drafts = folder?.descendants("文稿")?.mapNotNull { d ->
            val name = d.child("名稱")?.text?.ifBlank { null }
            val type = d.child("文稿類型")?.text?.ifBlank { null } ?: d.attributes["類型"]
            listOfNotNull(name, type?.let { "（$it）" }).joinToString("").ifBlank { null }
        }.orEmpty()
        val files = folder?.descendants("電子檔案資訊")?.mapNotNull { f ->
            val name = f.child("檔案名稱")?.text?.ifBlank { null } ?: return@mapNotNull null
            val size = f.child("檔案大小")?.text?.toLongOrNull()
            if (size != null) "$name（$size 位元組）" else name
        }.orEmpty()
        return OfficialStep(
            point = point.attributes["Id"]?.removePrefix("Sign_")?.replace(Regex("^(FLOW_)+"), ""),
            action = info?.child("異動別")?.text?.ifBlank { null },
            signer = signer?.let { person(it) },
            role = signer?.child("角色")?.text?.ifBlank { null },
            time = info?.child("簽章時間")?.text?.let(::rocTime),
            opinions = opinions,
            next = next,
            certificate = cert,
            drafts = drafts,
            files = files,
        )
    }

    /** "10406111823" (ROC year, month, day, hour, minute; seconds optional) reads "民國104年06月11日 18:23". */
    fun rocTime(raw: String): String {
        val t = raw.trim()
        val m = Regex("^(\\d{2,3})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?$").find(t) ?: return t
        val g = m.groupValues
        val seconds = if (g[6].isNotEmpty()) ":" + g[6] else ""
        return "民國${g[1].trimStart('0')}年${g[2]}月${g[3]}日 ${g[4]}:${g[5]}$seconds"
    }

    private fun certificateName(b64: String): String? = runCatching {
        val der = b64.filterNot { it.isWhitespace() }.fromBase64()
        val cert = X509Cert(ByteString(der))
        cert.subject.components[OID.COMMON_NAME.oid]?.value ?: cert.subject.name
    }.getOrNull()
}
