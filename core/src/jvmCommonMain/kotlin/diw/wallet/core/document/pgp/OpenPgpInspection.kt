package diw.wallet.core.document.pgp

import diw.wallet.core.document.CertInfo
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.SignatureFormat
import diw.wallet.core.document.SignatureInfo
import diw.wallet.core.document.TrustSummary
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPMarker
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.io.ByteArrayInputStream
import kotlin.time.Instant

/**
 * Checks OpenPGP files for [diw.wallet.core.document.DocumentInspector]: detached signatures (with the content the
 * user linked), cleartext signed and signed messages, certificates, and encrypted messages (recipients only). A
 * signature is checked against the certificates in the wallet's OpenPGP list; its trust is the user's trust in that
 * certificate, raised from unverified to verified by a certification from a key the user made an introducer.
 */
internal object OpenPgpInspection {
    private val EXTENSIONS = setOf("asc", "sig", "gpg", "pgp")

    /** Whether [b] is OpenPGP data: an armor header, or a binary packet sequence that parses as one. */
    fun detect(b: ByteArray, name: String?): Boolean {
        if (b.isEmpty()) return false
        val head = b.copyOfRange(0, minOf(b.size, 4096)).decodeToString()
        if (head.trimStart().startsWith("-----BEGIN PGP ")) return true
        val h = b[0].toInt() and 0xFF
        if (h and 0x80 == 0) return false
        val tag = if (h and 0x40 != 0) h and 0x3F else (h shr 2) and 0x0F
        if (tag !in setOf(1, 2, 3, 4, 5, 6, 8, 10, 11, 18)) return false
        val ext = name?.substringAfterLast('.', "")?.lowercase()
        val first = runCatching { BcPGPObjectFactory(ByteArrayInputStream(b)).nextObject() }.getOrNull() ?: return false
        return when (first) {
            is PGPSignatureList -> first.size() > 0
            is PGPPublicKeyRing, is PGPSecretKeyRing, is PGPEncryptedDataList, is PGPOnePassSignatureList -> true
            is PGPCompressedData, is PGPLiteralData, is PGPMarker -> ext in EXTENSIONS
            else -> false
        }
    }

    private class Keyring(val entries: List<Entry>) {
        class Entry(val ring: PGPPublicKeyRing, val key: OpenPgpTrustedKey)

        /** The ring and key named by the signature's issuer fingerprint, else by its key ID. */
        fun find(sig: PGPSignature): Pair<Entry, PGPPublicKey>? {
            val ids = sig.keyIdentifiers
            val fprs = ids.mapNotNull { it.fingerprint }
            for (e in entries) for (k in e.ring.publicKeys) {
                val hit = if (fprs.isNotEmpty()) fprs.any { it.contentEquals(k.fingerprint) } else ids.any { it.keyId == k.keyID }
                if (hit) return e to k
            }
            return null
        }
    }

    suspend fun inspect(data: ByteArray, detached: ByteArray?, base: DocumentReport, trust: DocumentTrustSource, now: Instant): DocumentReport {
        val keyring = Keyring(trust.openPgpKeys().mapNotNull { k ->
            runCatching { Keyring.Entry(PGPPublicKeyRing(k.certificate, OpenPgp.calculator), k) }.getOrNull()
        })
        val text = runCatching { data.decodeToString(throwOnInvalidSequence = true) }.getOrNull()
        if (text != null && text.trimStart().startsWith("-----BEGIN PGP SIGNED MESSAGE-----")) return cleartext(text, base, keyring, now)
        val report = base.copy(format = DocumentFormat.OPENPGP)
        val sigs = ArrayList<PGPSignature>()
        val keys = ArrayList<OpenPgpKeyInfo>()
        var secret = false
        var literal: ByteArray? = null
        var literalName: String? = null
        var encrypted: PGPEncryptedDataList? = null
        var onePass = false
        fun walk(f: BcPGPObjectFactory, depth: Int) {
            if (depth > 4) return
            while (true) {
                when (val o = f.nextObject() ?: return) {
                    is PGPSignatureList -> sigs.addAll(o.asSequence())
                    is PGPOnePassSignatureList -> onePass = true
                    is PGPCompressedData -> walk(BcPGPObjectFactory(o.dataStream), depth + 1)
                    is PGPLiteralData -> {
                        literalName = o.fileName.takeIf { it.isNotBlank() && it != PGPLiteralData.CONSOLE }
                        literal = OpenPgp.readCapped(o.inputStream)
                    }
                    is PGPPublicKeyRing -> keys.add(OpenPgp.describe(o, false))
                    is PGPSecretKeyRing -> {
                        secret = true
                        keys.add(OpenPgp.describe(PGPPublicKeyRing(o.publicKeys.asSequence().toList()), true))
                    }
                    is PGPEncryptedDataList -> { encrypted = o; return }
                    else -> {}
                }
            }
        }
        for (block in OpenPgp.blocks(data)) walk(BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(block))), 0)

        encrypted?.let { list -> return encryptedReport(list, report) }
        if (keys.isNotEmpty() && sigs.isEmpty() && literal == null) {
            return report.copy(
                openPgp = OpenPgpReport(if (secret) OpenPgpKind.SECRET_KEYS else OpenPgpKind.PUBLIC_KEYS, keys = keys),
                notes = listOf(
                    if (secret) "檔案含有 OpenPGP 私鑰。錢包不保存私鑰，加入清單時只保留公開部分；請妥善保管或刪除這個檔案。"
                    else "OpenPGP 公開金鑰：可加入 OpenPGP 公開金鑰清單，用來檢查這把金鑰的簽章與加密給對方。",
                ),
            )
        }
        val content = literal
        if (content != null) {
            val infos = sigs.mapIndexed { i, s -> verify(s, content, keyring, label(i, sigs.size, "簽章訊息"), now) }
            return report.copy(
                signatures = infos,
                openPgp = OpenPgpReport(
                    if (sigs.isEmpty() && !onePass) OpenPgpKind.LITERAL else OpenPgpKind.SIGNED_MESSAGE,
                    literalName = literalName, literalSize = content.size.toLong(), signers = signers(sigs),
                ),
                notes = listOf("內容（" + (literalName ?: "未命名") + "，${content.size} 位元組）包在 OpenPGP 訊息內，可另存成檔案。"),
            )
        }
        if (sigs.isEmpty()) return report.copy(problems = listOf("看起來是 OpenPGP 資料，但沒有簽章、金鑰或內容"))
        val infos = sigs.mapIndexed { i, s ->
            if (detached == null) missingContent(s, label(i, sigs.size, "分離式簽章"))
            else verify(s, detached, keyring, label(i, sigs.size, "分離式簽章"), now)
        }
        return report.copy(
            signatures = infos,
            openPgp = OpenPgpReport(OpenPgpKind.DETACHED_SIGNATURE, signers = signers(sigs)),
            notes = if (detached == null) listOf("分離式簽章：請選擇被簽署的原檔才能檢查") else emptyList(),
        )
    }

    private fun label(i: Int, n: Int, what: String) = if (n > 1) "$what ${i + 1}" else what

    private fun signers(sigs: List<PGPSignature>): List<String> = sigs.mapNotNull { s ->
        s.keyIdentifiers.firstNotNullOfOrNull { it.fingerprint }?.let { OpenPgp.hex(it) }
            ?: s.keyIdentifiers.firstOrNull()?.keyId?.takeIf { it != 0L }?.let { java.lang.Long.toHexString(it).uppercase().padStart(16, '0') }
    }.distinct()

    /** A cleartext signed message (RFC 9580 7): dash-escaping removed, trailing whitespace dropped, CRLF lines. */
    private fun cleartext(text: String, base: DocumentReport, keyring: Keyring, now: Instant): DocumentReport {
        val lines = text.trimStart().split("\n").map { it.removeSuffix("\r") }
        var i = 1
        while (i < lines.size && lines[i].isNotEmpty()) i++
        i++
        val body = ArrayList<String>()
        while (i < lines.size && lines[i] != "-----BEGIN PGP SIGNATURE-----") {
            body.add(lines[i].let { if (it.startsWith("- ")) it.substring(2) else it }.trimEnd(' ', '\t'))
            i++
        }
        if (i >= lines.size) return base.copy(format = DocumentFormat.OPENPGP, problems = listOf("明文簽章訊息缺少簽章區塊"))
        val signed = body.joinToString("\r\n")
        val armored = lines.subList(i, lines.size).joinToString("\n").encodeToByteArray()
        val sigs = (BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(armored))).nextObject() as? PGPSignatureList)?.asSequence()?.toList().orEmpty()
        val infos = sigs.mapIndexed { n, s -> verify(s, signed.encodeToByteArray(), keyring, label(n, sigs.size, "明文簽章"), now) }
        return base.copy(
            format = DocumentFormat.OPENPGP,
            signatures = infos,
            openPgp = OpenPgpReport(OpenPgpKind.CLEARTEXT_SIGNED, clearText = body.joinToString("\n"), signers = signers(sigs)),
            problems = if (sigs.isEmpty()) listOf("明文簽章訊息的簽章區塊無法讀取") else emptyList(),
        )
    }

    private fun encryptedReport(list: PGPEncryptedDataList, report: DocumentReport): DocumentReport {
        val recipients = list.encryptedDataObjects.asSequence().mapNotNull { d ->
            when (d) {
                is PGPPublicKeyEncryptedData -> OpenPgpRecipient(
                    d.keyIdentifier.fingerprint?.let { OpenPgp.hex(it) }
                        ?: java.lang.Long.toHexString(d.keyID).uppercase().padStart(16, '0'),
                    OpenPgp.publicKeyAlgorithmName(d.algorithm),
                )
                is PGPPBEEncryptedData -> OpenPgpRecipient("密碼", "以密碼加密（SKESK v${d.version}）")
                else -> null
            }
        }.toList()
        val protection = when {
            list.isEmpty -> null
            list[0].isAEAD -> "AEAD（SEIPD v2 或 OCB）"
            list.isIntegrityProtected -> "SEIPD v1，含 MDC 完整性檢查"
            else -> "舊式 SED，沒有完整性保護"
        }
        return report.copy(
            encrypted = true,
            openPgp = OpenPgpReport(OpenPgpKind.ENCRYPTED, recipients = recipients, encryption = protection),
            notes = listOf("OpenPGP 加密訊息：寄給 ${recipients.size} 位收件人。收件人是你的 OpenPGP 卡時，可以用卡片解密。"),
            problems = if (protection?.startsWith("舊式") == true) listOf("沒有完整性保護，錢包不會解密這份訊息") else emptyList(),
        )
    }

    private fun missingContent(s: PGPSignature, label: String) = SignatureInfo(
        format = SignatureFormat.OPENPGP,
        label = label,
        algorithm = OpenPgp.publicKeyAlgorithmName(s.keyAlgorithm) + " / " + OpenPgp.hashName(s.hashAlgorithm),
        signer = null,
        chain = emptyList(),
        integrity = Check.NOT_CHECKED,
        coversWholeDocument = null,
        claimedTime = s.creationTime.time / 1000,
        trust = null,
        certificateValidity = Check.NOT_CHECKED,
        problems = listOf("分離式簽章需要原檔才能檢查"),
    )

    /** Verifies [s] over [content] with the list's certificates and judges the key's validity at the signing time. */
    private fun verify(s: PGPSignature, content: ByteArray, keyring: Keyring, label: String, now: Instant): SignatureInfo {
        val created = s.creationTime.time / 1000
        val algorithm = OpenPgp.publicKeyAlgorithmName(s.keyAlgorithm) + " / " + OpenPgp.hashName(s.hashAlgorithm)
        val type = when (s.signatureType) {
            PGPSignature.BINARY_DOCUMENT -> "二進位文件（0x00）"
            PGPSignature.CANONICAL_TEXT_DOCUMENT -> "正規化文字（0x01）"
            else -> "類型 0x" + s.signatureType.toString(16)
        }
        val found = keyring.find(s) ?: return SignatureInfo(
            format = SignatureFormat.OPENPGP,
            label = label,
            algorithm = algorithm,
            signer = null,
            chain = emptyList(),
            integrity = Check.NOT_CHECKED,
            coversWholeDocument = true,
            claimedTime = created,
            trust = null,
            certificateValidity = Check.NOT_CHECKED,
            problems = listOf(
                "OpenPGP 公開金鑰清單中沒有簽署者的金鑰（" + (signers(listOf(s)).firstOrNull() ?: "未標示") +
                    "），無法檢查。可匯入對方的公開金鑰，或從 keys.openpgp.org 查詢。",
            ),
            notes = listOf("簽章類型：$type"),
        )
        val (entry, key) = found
        val master = entry.ring.publicKey
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        notes += "簽章類型：$type"
        notes += "簽署金鑰：" + OpenPgpPackets.fingerprintText(key.fingerprint) + "（" + OpenPgp.algorithmName(key) + "）"
        if (!key.isMasterKey) notes += "主金鑰：" + OpenPgpPackets.fingerprintText(master.fingerprint)

        val integrity = runCatching {
            s.init(BcPGPContentVerifierBuilderProvider(), key)
            s.update(content)
            s.verify()
        }.getOrElse { problems += "簽章無法驗證：" + (it.message ?: it.javaClass.simpleName); false }
        var integrityCheck = if (integrity) Check.PASS else Check.FAIL
        if (integrity && s.hashAlgorithm in setOf(1, 2, 3)) {
            integrityCheck = Check.WARN
            problems += "簽章使用 " + OpenPgp.hashName(s.hashAlgorithm) + "，已不安全，無法排除偽造"
        }
        if (!integrity) problems += "簽章值與內容不符：文件在簽署後被修改，或簽章不是這份文件的"

        var validity = Check.PASS
        val keyCreated = key.creationTime.time / 1000
        if (created < keyCreated) { validity = Check.FAIL; problems += "簽章時間早於簽署金鑰的建立時間" }
        if (key.validSeconds > 0 && created > keyCreated + key.validSeconds) { validity = Check.FAIL; problems += "簽署時金鑰已過期" }
        if (s.hashedSubPackets?.signatureExpirationTime?.let { it > 0 && now.epochSeconds > created + it } == true) {
            validity = Check.FAIL
            problems += "簽章本身已過期（簽章到期時間）"
        }
        val bare = entry.ring.publicKeys.asSequence().none { it.signatures.hasNext() }
        if (!key.isMasterKey && !bare) {
            val binding = OpenPgp.validBinding(master, key)
            if (binding == null) { validity = Check.FAIL; problems += "子金鑰沒有有效的綁定簽章，不能代表主金鑰" }
            else {
                val flags = binding.hashedSubPackets?.keyFlags ?: 0
                if (flags != 0 && flags and KeyFlags.SIGN_DATA == 0) { validity = Check.FAIL; problems += "子金鑰的金鑰旗標不允許簽署資料" }
            }
        }
        for (k in listOfNotNull(master, key.takeIf { !it.isMasterKey })) {
            val rev = OpenPgp.revocation(k, master) ?: continue
            val reason = rev.hashedSubPackets?.revocationReason?.revocationReason?.toInt()
            val soft = reason == RevocationReasonTags.KEY_SUPERSEDED.toInt() || reason == RevocationReasonTags.KEY_RETIRED.toInt() ||
                reason == RevocationReasonTags.USER_NO_LONGER_VALID.toInt()
            val revokedAt = rev.creationTime.time / 1000
            if (!soft || created >= revokedAt) {
                validity = Check.FAIL
                problems += (if (k.isMasterKey) "主金鑰" else "子金鑰") + "已撤銷" + (if (soft) "（撤銷後才簽署）" else "（金鑰可能外洩，撤銷前的簽章也不可信）")
            } else notes += (if (k.isMasterKey) "主金鑰" else "子金鑰") + "在簽署後才停用，這個簽章仍有效"
        }

        val (tier, anchor) = tierOf(entry, keyring)
        if (entry.key.trust == OpenPgpTrust.DISTRUSTED) problems += "你已將這把金鑰設為不信任"
        if (tier == "T3") problems += "尚未核對這把金鑰的指紋：簽章屬於這把金鑰，但無法確認金鑰屬於誰"
        val uid = master.userIDs.asSequence().firstOrNull()
        val expires = key.validSeconds.takeIf { it > 0 }?.let { keyCreated + it } ?: 253402300799L
        val signer = CertInfo(
            subject = uid ?: entry.key.name,
            issuer = "OpenPGP（" + entry.key.trust.title + "）",
            commonName = uid ?: entry.key.name,
            serialHex = OpenPgp.hex(key.fingerprint),
            notBefore = keyCreated,
            notAfter = expires,
            der = "",
            publicKey = OpenPgp.algorithmName(key),
        )
        return SignatureInfo(
            format = SignatureFormat.OPENPGP,
            label = label,
            algorithm = algorithm,
            signer = signer,
            chain = listOf(signer),
            integrity = integrityCheck,
            coversWholeDocument = true,
            claimedTime = created,
            trust = TrustSummary(tier, null, false, anchor, if (tier == "T4") listOf("UNKNOWN_ANCHOR") else listOf("USER_ANCHOR")),
            certificateValidity = validity,
            signerName = uid,
            problems = problems,
            notes = notes,
        )
    }

    /**
     * The tier of a signature by [entry]: the user's own trust, raised from unverified to T2 when a user ID carries a
     * valid certification by a key the user verified and made an introducer.
     */
    private fun tierOf(entry: Keyring.Entry, keyring: Keyring): Pair<String, String> = when (entry.key.trust) {
        OpenPgpTrust.OWN_CARD, OpenPgpTrust.VERIFIED -> "T2" to entry.key.name + "（" + entry.key.trust.title + "）"
        OpenPgpTrust.DISTRUSTED -> "T4" to entry.key.name + "（不信任）"
        OpenPgpTrust.UNVERIFIED -> {
            val introducer = introducerOf(entry, keyring)
            if (introducer != null) "T2" to entry.key.name + "（由「" + introducer + "」認證）"
            else "T3" to entry.key.name + "（未核對指紋）"
        }
    }

    private fun introducerOf(entry: Keyring.Entry, keyring: Keyring): String? {
        val master = entry.ring.publicKey
        val introducers = keyring.entries.filter { it.key.introducer && (it.key.trust == OpenPgpTrust.VERIFIED || it.key.trust == OpenPgpTrust.OWN_CARD) && it !== entry }
        if (introducers.isEmpty()) return null
        for (uid in master.userIDs.asSequence()) for (cert in master.getSignaturesForID(uid).asSequence()) {
            if (!cert.isCertification || cert.signatureType == PGPSignature.CERTIFICATION_REVOCATION) continue
            for (intro in introducers) {
                val signerKey = intro.ring.publicKeys.asSequence().firstOrNull { k ->
                    cert.keyIdentifiers.any { id -> id.fingerprint?.contentEquals(k.fingerprint) ?: (id.keyId == k.keyID) }
                } ?: continue
                val ok = runCatching {
                    cert.init(BcPGPContentVerifierBuilderProvider(), signerKey)
                    cert.verifyCertification(uid, master)
                }.getOrDefault(false)
                if (ok) return intro.key.name
            }
        }
        return null
    }
}
