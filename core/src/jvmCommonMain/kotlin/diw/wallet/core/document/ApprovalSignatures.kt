package diw.wallet.core.document

import diw.wallet.core.document.official.ApprovalPoint
import diw.wallet.core.document.official.OfficialDocuments
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import org.w3c.dom.Document
import org.w3c.dom.Element
import java.util.Base64
import kotlin.time.Instant

/**
 * Signatures of Taiwan's online approval files (線上簽核, .si, DTD 104_sign_utf8 of the 文書及檔案管理電腦化作業規範,
 * appendix 3 table 3-5 and appendix 4; see docs/research/official-document-files.md). These are not XAdES: each signing
 * point (簽核點定義) holds an XMLDSig Signature written without the XMLDSig namespace, followed by an Object with the
 * signer, action and opinion (異動資訊) and the files of the case (簽核資訊). The SignedInfo (Canonical XML 1.0,
 * RSA-SHA256) refers to every file of the case by its file name (detached, digest of the file bytes, written with
 * the "xmldsig-more#sha256" URI), to the point's own Object and to the previous signing point, so the points form a
 * chain. The case files themselves (.di, attachments, page images) stay unchanged.
 */
internal object ApprovalSignatures {
    const val ROOT = "線上簽核"
    const val POINT = "簽核點定義"
    const val DIGEST = "http://www.w3.org/2001/04/xmldsig-more#sha256"

    /** True when [doc] is an online approval file. */
    fun isApproval(doc: Document): Boolean = doc.documentElement?.let { (it.localName ?: it.nodeName) == ROOT } == true

    /** The namespace-less Signature of each signing point, in document order. */
    private fun points(doc: Document): List<Pair<Element, Element>> =
        XmlParsing.descendants(doc, null, POINT).mapNotNull { p ->
            XmlParsing.children(p).firstOrNull { it.localName == "Signature" && it.namespaceURI == null }?.let { p to it }
        }

    /**
     * Verifies every signing point of the approval in [bytes]. [related] holds the case files by name; a point whose
     * files are missing is reported as not fully checked, never as failed.
     */
    suspend fun verify(bytes: ByteArray, checks: CmsChecks, now: Instant, related: Map<String, ByteArray>): List<SignatureInfo> {
        val doc = XmlParsing.parse(bytes)
        val list = points(doc)
        return list.mapIndexed { i, (point, sig) ->
            val info = XmlParsing.child(point, null, "Object")?.let { XmlParsing.descendants(it, null, "異動資訊").firstOrNull() }
            val person = info?.let { XmlParsing.child(it, null, "簽核人員") }
            val name = person?.let { XmlParsing.text(XmlParsing.child(it, null, "姓名")) }?.ifBlank { null }
            val action = info?.let { XmlParsing.text(XmlParsing.child(it, null, "異動別")) }?.ifBlank { null }
            val label = "簽核點 ${i + 1}" + (name?.let { "：$it" } ?: "") + (action?.let { "（$it）" } ?: "")
            val checked = XmlDsig.integrity(doc, sig, { related[it] }, ns = null)
            val notes = checked.notes.map { n ->
                n.replace(Regex("參照的檔案「(.*)」不在檔案內，無法檢查"), "簽核的檔案「$1」不在錢包內，無法比對；把同一案件的檔案匯入或放入公文容器後會重新檢查")
            }.toMutableList()
            val problems = checked.problems.map { it.replace("的內容在簽署後被修改", "與簽核時的內容不同") }.toMutableList()
            val refs = XmlParsing.childrenNamed(XmlParsing.child(sig, null, "SignedInfo")!!, null, "Reference").mapNotNull { it.getAttribute("URI").ifEmpty { null } }
            val fileRefs = refs.filter { !it.startsWith("#") }
            val listed = XmlParsing.child(point, null, "Object")?.let { o ->
                XmlParsing.descendants(o, null, "電子檔案資訊").mapNotNull { XmlParsing.text(XmlParsing.child(it, null, "檔案名稱"))?.ifBlank { null } }
            }.orEmpty()
            val objectId = XmlParsing.child(point, null, "Object")?.getAttribute("Id")
            if (objectId.isNullOrEmpty() || "#$objectId" !in refs) problems.add("簽章沒有涵蓋這個簽核點的異動資訊（簽核人員、意見）")
            listed.filter { it !in fileRefs }.forEach { notes.add("檔案清單列出「$it」，但簽章沒有涵蓋") }
            val previous = list.getOrNull(i - 1)?.first?.getAttribute("Id")
            if (previous != null && previous.isNotEmpty() && "#$previous" !in refs) notes.add("這個簽核點沒有涵蓋前一個簽核點")
            notes.add(0, "涵蓋 ${fileRefs.size} 個檔案" + (if (previous != null && "#$previous" in refs) "與前一個簽核點" else ""))
            notes.addAll(conformance(doc, point, sig, checked.method, related))
            val alg = XmlDsig.signatureName(checked.method)
            val claimed = info?.let { XmlParsing.text(XmlParsing.child(it, null, "簽章時間")) }?.let { ApprovalPoint.parseRocTime(it)?.epochSeconds }
            checks.evaluate(
                format = SignatureFormat.OFFICIAL_APPROVAL,
                label = label,
                algorithm = alg?.first?.replace("with", " ")?.replace("SHA", "SHA-"),
                signer = checked.signer,
                pool = checked.certificates,
                integrity = checked.integrity,
                claimed = claimed,
                timestamp = null,
                ocsps = emptyList(),
                crls = emptyList(),
                now = now,
                problems = problems,
                notes = notes,
                coversWhole = null,
            ).copy(signerName = name, reason = listOfNotNull(action?.let { if (info?.getAttribute("退文") == "Y") "$it（退文）" else it }, info?.let { XmlParsing.text(XmlParsing.child(it, null, "簽核意見")) }?.ifBlank { null }).joinToString("：").ifEmpty { null })
        }
    }

    /**
     * Where a signing point departs from the specification (文書及檔案管理電腦化作業規範 第十點、附錄 3 表 3-5、附錄 4):
     * RSA-SHA256 over Canonical XML 1.0, a 簽核流程 the point names, and a temporary card (借卡) confirmed by a
     * later signature with the person's own certificate (補簽追認) before filing.
     */
    private fun conformance(doc: Document, point: Element, sig: Element, method: String?, related: Map<String, ByteArray>): List<String> {
        val out = ArrayList<String>()
        if (method != null && method != XmlDsig.RSA_SHA256) {
            out.add("規範指定的簽章演算法是 RSA-SHA256，這個簽核點使用 ${XmlDsig.signatureName(method)?.first ?: method}，機關的公文系統可能不接受")
        }
        val c14n = XmlParsing.child(sig, null, "SignedInfo")?.let { XmlParsing.child(it, null, "CanonicalizationMethod") }?.getAttribute("Algorithm")
        if (!c14n.isNullOrEmpty() && c14n != XmlC14n.C14N) out.add("規範指定 Canonical XML 1.0，這個簽核點使用 $c14n")
        val flowIds = XmlParsing.descendants(doc, null, "簽核流程").mapNotNull { it.getAttribute("Id").ifEmpty { null } }.toSet()
        val flow = point.getAttribute("URI").removePrefix("#")
        when {
            flow.isEmpty() -> out.add("簽核點沒有以 URI 指向線上簽核流程的簽核流程")
            flow !in flowIds -> out.add("簽核點指向的簽核流程「$flow」不在線上簽核流程內")
        }
        val info = XmlParsing.child(point, null, "Object")?.let { XmlParsing.descendants(it, null, "異動資訊").firstOrNull() }
        val borrowed = info?.getAttribute("借卡") == "Y" || (info?.let { XmlParsing.child(it, null, "借卡") } != null)
        if (borrowed) {
            val id = point.getAttribute("Id")
            // A confirmation counts only when its own signature holds; an unsigned 補簽人員 added later proves nothing.
            val checks = XmlParsing.descendants(doc, null, "補簽人員").filter { it.getAttribute("URI").removePrefix("#") == id }.map { c ->
                val sig2 = XmlParsing.child(c, null, "簽章資料")?.let { d -> XmlParsing.children(d).firstOrNull { it.localName == "Signature" && it.namespaceURI == null } }
                sig2?.let { XmlDsig.integrity(doc, it, { name -> related[name] }, ns = null) }
            }
            out.add(when {
                checks.isEmpty() -> "以臨時憑證（借卡）簽核，尚未補簽追認；規範要求歸檔前以本人的正式憑證補簽"
                checks.any { it?.integrity == Check.PASS } -> {
                    val who = checks.first { it?.integrity == Check.PASS }!!.signer?.let { runCatching { Bc.cn(it) }.getOrNull() }
                    "以臨時憑證（借卡）簽核，已有補簽追認" + (who?.let { "（補簽者 $it）" } ?: "")
                }
                checks.any { it?.integrity == Check.NOT_CHECKED } -> "以臨時憑證（借卡）簽核，補簽追認的簽章涵蓋不在錢包內的檔案，無法確認"
                else -> "以臨時憑證（借卡）簽核，補簽追認沒有簽章或簽章不成立，不算完成追認"
            })
        }
        return out
    }

    /**
     * Adds a signing point to [approval] (or makes a new approval file for the case when null) signed by [signer]:
     * the point refers to every file in [files] (name and bytes, the official document first), to the previous point
     * and to its own Object. The rest of the file is kept byte for byte, so earlier points stay valid.
     */
    suspend fun sign(approval: ByteArray?, files: List<Pair<String, ByteArray>>, signer: DocumentSigner, point: ApprovalPoint): ByteArray {
        require(files.isNotEmpty()) { "沒有要簽核的檔案" }
        val bom = approval?.decodeToString()?.startsWith("\uFEFF") == true
        val text0 = approval?.decodeToString()?.removePrefix("\uFEFF") ?: newApproval(files.first().first, point)
        val declared = Regex("<\\?xml[^>]*encoding=[\"']([^\"']+)[\"']").find(text0.take(200))?.groupValues?.get(1)
        if (declared != null && !declared.equals("UTF-8", true) && !declared.equals("UTF8", true)) throw IllegalArgumentException("只能在 UTF-8 編碼的線上簽核檔加簽（此檔案為 $declared）")
        val doc0 = XmlParsing.parse(text0.toByteArray(Charsets.UTF_8))
        if (!isApproval(doc0)) throw IllegalArgumentException("這個檔案不是線上簽核檔（.si）")
        val existing = points(doc0)
        val ids = HashSet<String>()
        fun walkIds(n: org.w3c.dom.Node) {
            var c = n.firstChild
            while (c != null) { if (c is Element) { c.getAttribute("Id").takeIf { it.isNotEmpty() }?.let { ids.add(it) }; walkIds(c) }; c = c.nextSibling }
        }
        walkIds(doc0)
        var n = existing.size
        while ("Sign_P$n" in ids || "Sign_info_$n" in ids || "ds_user_$n" in ids || "FLOW_P$n" in ids || "DOC_P$n" in ids) n++
        val pointId = "Sign_P$n"
        val infoId = "Sign_info_$n"
        val previous = existing.lastOrNull()?.first?.getAttribute("Id")?.takeIf { it.isNotEmpty() }

        // The flow gets a node for this point; the flow is not covered by any signature.
        val text = insertBefore(text0, "</線上簽核流程>") { indent -> "$indent  <簽核流程 Id=\"FLOW_P$n\" 異動別=\"${esc(point.action.take(ApprovalPoint.ACTION_MAX))}\" />\n" }
        val infoEnd = text.indexOf("</線上簽核資訊>")
        if (infoEnd < 0) throw IllegalArgumentException("線上簽核檔沒有簽核資訊（線上簽核資訊）")
        val pad = lineIndent(text, infoEnd) + "  "
        val chain = signer.certificateChain
        val method = if (signer.keyType == SignerKeyType.RSA) XmlDsig.RSA_SHA256 else XmlDsig.ECDSA_SHA256
        val b64 = Base64.getEncoder()
        val signerName = runCatching { Bc.cn(Bc.holder(chain.first())!!) }.getOrNull()?.ifBlank { null } ?: "簽核人員"
        val time = ApprovalPoint.rocTime(point.time)
        // 簽核文稿清單: the .di files are the drafts (the first file when there is none); other case files except the
        // exchange forms are attachments of the first draft. 原始檔序號 is the file's place in 檔案清單, from 1.
        val entries = files.mapIndexed { i, (name, bytes) -> CaseFile(i + 1, name, bytes) }
        val drafts = entries.filter { it.ext == "di" }.ifEmpty { entries.take(1) }.map { f ->
            val official = runCatching { OfficialDocuments.parse(f.bytes) }.getOrNull()
            Draft(f.serial, f.name.substringBeforeLast('.'), official?.kind ?: ApprovalPoint.fileFormat(f.name))
        }
        val attachments = entries.filter { e -> drafts.none { it.serial == e.serial } && e.ext !in FORMS }
            .map { Attachment(it.serial, it.name, ApprovalPoint.fileFormat(it.name)) }
        val fileDigests = files.map { (name, bytes) -> name to b64.encodeToString(DocCrypto.digest("SHA-256", bytes)) }

        fun pointXml(infoDigest: String, previousDigest: String, value: String) = buildString {
            val p = pad
            append(p).append("<簽核點定義 URI=\"#FLOW_P$n\" Id=\"$pointId\">\n")
            append(p).append("  <Signature Id=\"ds_user_$n\">\n")
            append(p).append("    <SignedInfo>\n")
            append(p).append("      <CanonicalizationMethod Algorithm=\"${XmlC14n.C14N}\"></CanonicalizationMethod>\n")
            append(p).append("      <SignatureMethod Algorithm=\"$method\"></SignatureMethod>\n")
            fun ref(uri: String, digest: String) {
                append(p).append("      <Reference URI=\"${esc(uri)}\">\n")
                append(p).append("        <DigestMethod Algorithm=\"$DIGEST\"></DigestMethod>\n")
                append(p).append("        <DigestValue>$digest</DigestValue>\n")
                append(p).append("      </Reference>\n")
            }
            fileDigests.forEach { (name, d) -> ref(name, d) }
            if (previous != null) ref("#$previous", previousDigest)
            ref("#$infoId", infoDigest)
            append(p).append("    </SignedInfo>\n")
            append(p).append("    <SignatureValue>$value</SignatureValue>\n")
            append(p).append("    <KeyInfo>\n")
            append(p).append("      <X509Data>\n")
            chain.forEach { append(p).append("        <X509Certificate>").append(b64.encodeToString(it)).append("</X509Certificate>\n") }
            append(p).append("      </X509Data>\n")
            append(p).append("    </KeyInfo>\n")
            append(p).append("  </Signature>\n")
            append(p).append("  <Object Id=\"$infoId\">\n")
            append(p).append("    <異動資訊" + (if (point.returned) " 退文=\"Y\"" else "") + ">\n")
            append(p).append("      <簽核人員>\n")
            point.organization?.ifBlank { null }?.let { append(p).append("        <機關>${esc(it)}</機關>\n") }
            append(p).append("        <單位>${esc(point.unit.orEmpty())}</單位>\n")
            append(p).append("        <職稱>${esc(point.title.orEmpty())}</職稱>\n")
            append(p).append("        <姓名>${esc(signerName)}</姓名>\n")
            append(p).append("        <帳號>${esc(point.account.orEmpty())}</帳號>\n")
            point.role?.ifBlank { null }?.let { append(p).append("        <角色>${esc(it)}</角色>\n") }
            append(p).append("      </簽核人員>\n")
            append(p).append("      <異動別>${esc(point.action.take(ApprovalPoint.ACTION_MAX))}</異動別>\n")
            point.opinion?.ifBlank { null }?.let { append(p).append("      <簽核意見>${esc(it)}</簽核意見>\n") }
            append(p).append("      <簽章時間>$time</簽章時間>\n")
            append(p).append("    </異動資訊>\n")
            append(p).append("    <簽核資訊>\n")
            append(p).append("      <簽核文件夾 Id=\"DOC_P$n\" 產生時間=\"$time\">\n")
            append(p).append("        <簽核文稿清單 文稿數=\"${drafts.size}\">\n")
            drafts.forEachIndexed { j, d ->
                append(p).append("          <文稿 原始檔序號=\"${d.serial}\" 序號=\"${j + 1}\" 產生時間=\"$time\">\n")
                append(p).append("            <名稱>${esc(d.name)}</名稱>\n")
                append(p).append("            <文稿類型>${esc(d.kind)}</文稿類型>\n")
                if (j == 0 && attachments.isNotEmpty()) {
                    append(p).append("            <附件清單 附件數=\"${attachments.size}\">\n")
                    attachments.forEachIndexed { k, a ->
                        val pages = a.kind == "TIFF"
                        append(p).append("              <附件 格式=\"${if (pages) "一般頁面檔格式附件" else "電子檔格式附件"}\" 序號=\"${k + 1}\" 產生時間=\"$time\">\n")
                        append(p).append("                <名稱>${esc(a.name)}</名稱>\n")
                        append(p).append("                <附件類型>${a.kind}</附件類型>\n")
                        if (pages) {
                            append(p).append("                <一般頁面檔格式附件 頁面數=\"1\">\n")
                            append(p).append("                  <頁面 原始檔序號=\"${a.serial}\" 序號=\"1\" 產生時間=\"$time\" />\n")
                            append(p).append("                </一般頁面檔格式附件>\n")
                        } else {
                            append(p).append("                <電子檔格式附件 原始檔序號=\"${a.serial}\" />\n")
                        }
                        append(p).append("              </附件>\n")
                    }
                    append(p).append("            </附件清單>\n")
                }
                append(p).append("          </文稿>\n")
            }
            append(p).append("        </簽核文稿清單>\n")
            append(p).append("        <檔案清單 檔案數=\"${files.size}\">\n")
            files.forEachIndexed { i, (name, bytes) ->
                append(p).append("          <電子檔案資訊 原始檔序號=\"${i + 1}\" 序號=\"${i + 1}\" 產生時間=\"$time\">\n")
                append(p).append("            <檔案名稱>${esc(name)}</檔案名稱>\n")
                append(p).append("            <檔案大小>${bytes.size}</檔案大小>\n")
                append(p).append("            <檔案格式>${ApprovalPoint.fileFormat(name)}</檔案格式>\n")
                append(p).append("          </電子檔案資訊>\n")
            }
            append(p).append("        </檔案清單>\n")
            append(p).append("      </簽核文件夾>\n")
            append(p).append("    </簽核資訊>\n")
            append(p).append("  </Object>\n")
            append(p).append("</簽核點定義>\n")
        }
        val base = text
        fun assemble(xml: String) = insertBefore(base, "</線上簽核資訊>") { xml }

        // Digests of the point's Object and of the previous point, then the signature over the canonical SignedInfo.
        val draft = XmlParsing.parse(assemble(pointXml("", "", "")).toByteArray(Charsets.UTF_8))
        val infoDigest = b64.encodeToString(DocCrypto.digest("SHA-256", XmlC14n.canonicalize(XmlParsing.byId(draft, infoId)!!, XmlC14n.C14N)))
        val previousDigest = previous?.let { b64.encodeToString(DocCrypto.digest("SHA-256", XmlC14n.canonicalize(XmlParsing.byId(draft, it)!!, XmlC14n.C14N))) } ?: ""
        val withDigests = XmlParsing.parse(assemble(pointXml(infoDigest, previousDigest, "")).toByteArray(Charsets.UTF_8))
        val signedInfo = XmlParsing.byId(withDigests, pointId)!!.let { XmlParsing.child(it, null, "Signature")!! }.let { XmlParsing.child(it, null, "SignedInfo")!! }
        val raw = signer.sign(XmlC14n.canonicalize(signedInfo, XmlC14n.C14N))
        val value = b64.encodeToString(if (signer.keyType == SignerKeyType.EC_P256) XmlDsig.derToRaw(raw) else raw)
        val out = ((if (bom) "\uFEFF" else "") + assemble(pointXml(infoDigest, previousDigest, value))).toByteArray(Charsets.UTF_8)

        // The new point must verify against the files it names before it is returned.
        val doc = XmlParsing.parse(out)
        val sig = XmlParsing.child(XmlParsing.byId(doc, pointId)!!, null, "Signature")!!
        val related = files.toMap()
        val check = XmlDsig.integrity(doc, sig, { related[it] }, ns = null)
        if (check.integrity != Check.PASS) throw IllegalStateException("簽核點簽章檢查失敗：" + check.problems.joinToString("；"))
        return out
    }

    /** A new approval file for the case of [mainName]: an empty flow and no signing point yet. */
    private fun newApproval(mainName: String, point: ApprovalPoint): String {
        val case = mainName.substringBeforeLast('.').filter { it.isLetterOrDigit() }.ifEmpty { ApprovalPoint.rocTime(point.time) }
        return buildString {
            append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
            append("<!DOCTYPE 線上簽核 SYSTEM \"104_sign_utf8.dtd\"[]>\n")
            append("<線上簽核 Id=\"sign_${esc(case)}\">\n")
            append("  <線上簽核流程 Id=\"FlowInfo\">\n")
            append("  </線上簽核流程>\n")
            append("  <線上簽核資訊 Id=\"signInfo\">\n")
            append("  </線上簽核資訊>\n")
            append("</線上簽核>\n")
        }
    }

    /**
     * [text] with the lines [block] makes (given the indent of [closing]'s line) inserted before the first [closing]
     * tag: on their own lines when the tag starts its line, else after a line break.
     */
    private fun insertBefore(text: String, closing: String, block: (String) -> String): String {
        val at = text.indexOf(closing)
        if (at < 0) return text
        val lineStart = text.lastIndexOf('\n', at - 1) + 1
        val indent = lineIndent(text, at)
        return if (text.substring(lineStart, at).isBlank()) text.substring(0, lineStart) + block(indent) + text.substring(lineStart)
        else text.substring(0, at) + "\n" + block(indent) + indent + text.substring(at)
    }

    /** The whitespace that starts the line holding [index]. */
    private fun lineIndent(text: String, index: Int): String {
        val start = text.lastIndexOf('\n', index - 1) + 1
        return text.substring(start, index).takeWhile { it == ' ' || it == '\t' }
    }

    /** Exchange forms (交換表單, 文書訊息, 會稿交換表單, 信封) travel with a case but are not drafts or attachments. */
    private val FORMS = setOf("sw", "esw", "dm", "co", "en", "si")

    private class CaseFile(val serial: Int, val name: String, val bytes: ByteArray) {
        val ext = name.substringAfterLast('.', "").lowercase()
    }

    private class Draft(val serial: Int, val name: String, val kind: String)

    private class Attachment(val serial: Int, val name: String, val kind: String)

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
}
