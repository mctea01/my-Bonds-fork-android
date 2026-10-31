package diw.wallet.core.document.official

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.XmlElement
import org.multipaz.util.fromBase64

/** A file an envelope (.en) lists: its name, the stated hash and algorithm, its role, and whether it needs a signature. */
data class EnvelopeFile(val name: String, val algorithm: String, val hash: String, val role: String, val needsSignature: Boolean, val note: String?) {
    /**
     * True when the stated hash is the digest of [bytes] (hex or base64), false when it is something else, null when
     * the value cannot be read. The specification calls it the hash used to verify the file, so the content is
     * compared first and the file name second.
     */
    fun matches(fileName: String, bytes: ByteArray): Boolean? {
        val stated = decode(hash) ?: return null
        val alg = when (algorithm.lowercase()) { "sha384" -> "SHA-384"; "sha512" -> "SHA-512"; else -> "SHA-256" }
        return runCatching {
            DocCrypto.digest(alg, bytes).contentEquals(stated) || DocCrypto.digest(alg, fileName.encodeToByteArray()).contentEquals(stated)
        }.getOrNull()
    }

    private fun decode(v: String): ByteArray? {
        val s = v.trim()
        if (s.length % 2 == 0 && s.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            return ByteArray(s.length / 2) { i -> s.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        }
        return runCatching { s.fromBase64() }.getOrNull()
    }
}

/** A party of the exchange (object): agency code, unit code, full name and the optional note. */
data class ExchangeParty(val orgId: String?, val unitId: String?, val name: String?, val note: String?) {
    val display: String get() = listOfNotNull(name, listOfNotNull(orgId, unitId).joinToString(" ").ifBlank { null }?.let { "（$it）" }).joinToString("")
}

/** One receiver of an encrypted exchange form (.esw) with the certificate cards its key was encrypted to. */
data class EncryptedReceiver(val orgId: String?, val unitId: String?, val cards: List<EncryptedCard>)

/** A receiving certificate card: its type (GCA, MOEACA, XCA, MOICA), card number and the encrypted key size. */
data class EncryptedCard(val type: String, val cardNumber: String?, val method: String, val cipherBytes: Int?)

/**
 * The electronic document exchange files of 文書及檔案管理電腦化作業規範 (appendix 5, 二(二) 4 to 6, DTD
 * 104_g2b2c_envelope, 104_g2b2c_encrypt-list and 104_msg): the envelope (信封檔, EN) naming sender, receivers and the
 * files it carries, the encrypted exchange form (加密交換表單檔, ESW) holding the content key encrypted for each
 * receiving agency's certificate card, and the exchange confirmation message (交換確認訊息檔). These are produced by
 * the agencies' exchange systems with agency certificates; the wallet reads and links them, it does not make them.
 */
object ExchangeFiles {
    const val ENVELOPE = "g2b2c-envelope"
    const val ENCRYPT_LIST = "g2b2c-encrypt-list"
    const val MESSAGE = "g2b2c-msg"
    val ROOTS = setOf(ENVELOPE, ENCRYPT_LIST, MESSAGE)

    fun party(o: XmlElement?): ExchangeParty? = o?.let {
        ExchangeParty(
            it.child("orgid")?.text?.trim()?.ifEmpty { null },
            it.child("unitid")?.text?.trim()?.ifEmpty { null },
            it.child("orgname")?.text?.trim()?.ifEmpty { null },
            it.child("note")?.let(::noteText),
        )
    }

    /** The note: free text (文字), or the document's type, date, number and priority. */
    fun noteText(n: XmlElement): String? {
        n.child("文字")?.deepText()?.ifBlank { null }?.let { return it }
        val parts = listOfNotNull(
            n.child("doctype")?.text?.trim()?.ifEmpty { null },
            n.child("docdate")?.text?.trim()?.ifEmpty { null }?.let { "發文日期 $it" },
            n.child("docword")?.text?.trim()?.ifEmpty { null }?.let { "發文字號 $it" },
            n.child("docpriority")?.text?.trim()?.ifEmpty { null }?.let { "速別 $it" },
        )
        return parts.joinToString("，").ifEmpty { n.deepText().ifBlank { null } }
    }

    /** The files an envelope lists, in order: the presentation file, the extension file, then the others. */
    fun envelopeFiles(root: XmlElement): List<EnvelopeFile> {
        if (root.name != ENVELOPE) return emptyList()
        val list = root.child("filelist") ?: return emptyList()
        fun files(role: String, e: XmlElement?) = e?.all("file").orEmpty().mapNotNull { f ->
            val name = f.child("filename")?.text?.trim()?.ifEmpty { null } ?: return@mapNotNull null
            val hash = f.child("hash")
            EnvelopeFile(
                name, hash?.attributes?.get("algorithm") ?: "sha256", hash?.text?.trim().orEmpty(), role,
                f.attributes["needsig"] == "true", f.child("note")?.let(::noteText),
            )
        }
        return files("呈現檔", list.child("print")) + files("延伸檔", list.child("description")) + files("其他檔案", list.child("others"))
    }

    fun receivers(root: XmlElement): List<EncryptedReceiver> {
        if (root.name != ENCRYPT_LIST) return emptyList()
        return root.descendants("receiverobject").map { r ->
            EncryptedReceiver(
                r.child("orgid")?.text?.trim()?.ifEmpty { null },
                r.child("unitid")?.text?.trim()?.ifEmpty { null },
                r.all("cardlist").map { c ->
                    val data = c.child("EncryptedData")
                    val cipher = data?.child("CipherData")?.text?.replace(Regex("\\s+"), "")
                    EncryptedCard(
                        c.attributes["type"] ?: "GCA",
                        c.child("cardnum")?.text?.trim()?.ifEmpty { null },
                        data?.attributes?.get("Method") ?: "RSA",
                        cipher?.let { runCatching { it.fromBase64().size }.getOrNull() },
                    )
                },
            )
        }
    }

    /** The exchange file as a person reads it. */
    fun read(root: XmlElement): OfficialDocument = when (root.name) {
        ENVELOPE -> envelope(root)
        ENCRYPT_LIST -> encryptList(root)
        else -> message(root)
    }

    private fun f(label: String, v: String?) = v?.trim()?.ifEmpty { null }?.let { OfficialEntry.Field(label, it) }

    private fun envelope(root: XmlElement): OfficialDocument {
        val sender = party(root.child("senderinfo")?.child("object"))
        val receivers = root.child("receiverlist")?.all("object").orEmpty().mapNotNull(::party)
        val info = listOfNotNull(
            f("表單註冊號碼", root.child("serviceid")?.text),
            f("發文端流水號", root.child("applicationid")?.text),
            f("交換最終期限", root.child("expiredate")?.text),
            f("聯絡資訊", root.child("contactinfo")?.text),
            sender?.note?.let { OfficialEntry.Field("公文資訊", it) },
        )
        val files = envelopeFiles(root).map { e ->
            OfficialEntry.Field(e.role, e.name + (if (e.needsSignature) "（需簽章）" else "") + (e.note?.let { "，$it" } ?: "") +
                "，${e.algorithm.uppercase()} " + e.hash.take(16) + if (e.hash.length > 16) "…" else "")
        }
        return OfficialDocument(
            ENVELOPE, null, "信封檔", root.child("subject")?.deepText()?.ifBlank { null },
            listOf(
                OfficialSection("發文單位", listOfNotNull(sender?.let { OfficialEntry.Field("發文單位", it.display) })),
                OfficialSection("受文單位", receivers.map { OfficialEntry.Field("受文單位", it.display + (it.note?.let { n -> "，$n" } ?: "")) }),
                OfficialSection("交換資訊", info),
                OfficialSection("封裝檔案", files),
            ).filter { it.entries.isNotEmpty() },
        )
    }

    private fun encryptList(root: XmlElement): OfficialDocument {
        val sections = receivers(root).map { r ->
            OfficialSection(
                "收文機關 " + listOfNotNull(r.orgId, r.unitId).joinToString(" "),
                r.cards.map { c ->
                    OfficialEntry.Field("${c.type} 憑證卡", (c.cardNumber ?: "未列卡號") + "，以 ${c.method} 加密的內容金鑰" + (c.cipherBytes?.let { "（$it 位元組）" } ?: ""))
                },
            )
        } + OfficialSection(null, listOf(OfficialEntry.Paragraph("說明：",
            "信封檔外部的檔案以內容金鑰加密，內容金鑰再以每個收文機關憑證卡的公鑰加密。只有持有該憑證卡私鑰的收文機關公文交換系統能解密；錢包只顯示收文對象，不解密。",
            emptyList())))
        return OfficialDocument(ENCRYPT_LIST, null, "加密交換表單檔", null, sections)
    }

    private fun message(root: XmlElement): OfficialDocument {
        val code = root.child("msgcode")?.text?.trim()
        val entries = listOfNotNull(
            party(root.child("senderinfo")?.child("object"))?.let { OfficialEntry.Field("回復單位", it.display) },
            root.child("receiverlist")?.all("object").orEmpty().mapNotNull(::party).takeIf { it.isNotEmpty() }
                ?.let { l -> OfficialEntry.Field("原發文單位", l.joinToString("、") { it.display }) },
            f("交換序號", root.child("exchangeid")?.text),
            f("處理序號", root.child("processid")?.text),
            f("發文端流水號", root.child("applicationid")?.text),
            f("回復時間", root.child("msgtime")?.text),
            f("訊息代碼", code?.let { if (it == "0") "0（使用者確認收文）" else it }),
            f("訊息說明", root.child("msgnote")?.deepText()),
        )
        return OfficialDocument(MESSAGE, null, "交換確認訊息檔", null, listOf(OfficialSection(null, entries)))
    }
}
