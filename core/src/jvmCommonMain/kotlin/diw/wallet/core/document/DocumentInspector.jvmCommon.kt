package diw.wallet.core.document

import diw.wallet.core.document.pdf.PdfDates
import diw.wallet.core.document.pdf.PdfException
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfSignatureField
import diw.wallet.core.document.pdf.PdfSignatures
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.EnvelopedData
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo
import org.bouncycastle.asn1.cms.RecipientInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.tsp.TimeStampRequestGenerator
import org.bouncycastle.tsp.TimeStampResponse
import java.math.BigInteger
import java.security.Signature
import java.util.Base64
import kotlin.time.Instant

actual object DocumentInspector {
    private const val SIGNED_DATA = "1.2.840.113549.1.7.2"
    private const val ENVELOPED_DATA = "1.2.840.113549.1.7.3"
    private const val TST_INFO = "1.2.840.113549.1.9.16.1.4"

    actual suspend fun inspect(
        bytes: ByteArray,
        fileName: String?,
        trust: DocumentTrustSource,
        detachedContent: ByteArray?,
        now: Instant,
    ): DocumentReport {
        val checks = CmsChecks(PkiSupport(trust))
        val base = DocumentReport(DocumentFormat.OTHER, DocCryptoUtil.hex(DocCrypto.digest("SHA-256", bytes)), bytes.size.toLong(), checkedAt = now.epochSeconds)
        val (data, decodedNote) = unwrapText(bytes)
        return try {
            val report = when (val format = sniff(data, fileName)) {
                DocumentFormat.PDF -> pdf(data, base, checks, now)
                DocumentFormat.CMS_SIGNED -> cms(data, detachedContent, fileName, base, checks, now)
                DocumentFormat.CMS_ENVELOPED -> enveloped(data, fileName, base)
                DocumentFormat.TIMESTAMP -> timestampFile(data, detachedContent, base, checks)
                DocumentFormat.XML -> xml(data, fileName, base, checks, now)
                DocumentFormat.OFD, DocumentFormat.ASIC_E, DocumentFormat.ZIP -> container(data, base, checks, now)
                DocumentFormat.OPENCERTS -> openCerts(data, base)
                else -> base.copy(format = format, notes = listOfNotNull(certificateNote(data)))
            }
            if (decodedNote != null) report.copy(notes = listOf(decodedNote) + report.notes) else report
        } catch (e: Exception) {
            base.copy(format = sniff(data, fileName), problems = listOf("無法讀取檔案：" + (e.message ?: e.javaClass.simpleName)))
        }
    }

    /** Base64 or PEM text wrapping binary data (such as the .asdt transcript token): the decoded bytes. */
    private fun unwrapText(bytes: ByteArray): Pair<ByteArray, String?> {
        if (bytes.size > 8 * 1024 * 1024 || bytes.isEmpty()) return bytes to null
        val text = runCatching { bytes.decodeToString(throwOnInvalidSequence = true) }.getOrNull()?.trim() ?: return bytes to null
        val pem = Regex("-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\\s]+)-----END \\1-----").find(text)
        if (pem != null && pem.groupValues[1] in setOf("PKCS7", "CMS", "PKCS #7 SIGNED DATA")) {
            return Base64.getMimeDecoder().decode(pem.groupValues[2]) to "檔案是 PEM 文字，已解碼"
        }
        if (text.length >= 64 && text.all { it.isLetterOrDigit() || it in "+/=\r\n " }) {
            val decoded = runCatching { Base64.getMimeDecoder().decode(text) }.getOrNull()
            if (decoded != null && decoded.isNotEmpty() && decoded[0] == 0x30.toByte()) return decoded to "檔案是 base64 文字，已解碼"
        }
        return bytes to null
    }

    fun sniff(b: ByteArray, name: String?): DocumentFormat {
        val ext = name?.substringAfterLast('.', "")?.lowercase()
        if (PdfFile.isPdf(b)) return DocumentFormat.PDF
        if (Zip.isZip(b)) {
            val files = runCatching { Zip.read(b) }.getOrNull() ?: return DocumentFormat.ZIP
            return when {
                "OFD.xml" in files -> DocumentFormat.OFD
                Asic.isAsic(files) -> DocumentFormat.ASIC_E
                else -> DocumentFormat.ZIP
            }
        }
        if (b.isNotEmpty() && b[0] == 0x30.toByte()) {
            val oid = runCatching { ASN1ObjectIdentifier.getInstance(ASN1Sequence.getInstance(Bc.parse(b)).getObjectAt(0)).id }.getOrNull()
            when (oid) {
                SIGNED_DATA -> return if (runCatching { CMSSignedData(b).signedContentTypeOID == TST_INFO }.getOrDefault(false)) DocumentFormat.TIMESTAMP else DocumentFormat.CMS_SIGNED
                GmSignedData.GM_SIGNED_DATA -> return DocumentFormat.CMS_SIGNED
                ENVELOPED_DATA -> return DocumentFormat.CMS_ENVELOPED
            }
            if (runCatching { TimeStampResponse(b) }.isSuccess) return DocumentFormat.TIMESTAMP
            return DocumentFormat.OTHER
        }
        val head = b.copyOfRange(0, minOf(b.size, 512)).decodeToString().removePrefix("﻿").trimStart()
        return when {
            head.startsWith("<") -> DocumentFormat.XML
            head.startsWith("{") -> {
                val o = OpenCerts.parse(b)
                if (o != null && OpenCerts.looksLike(o)) DocumentFormat.OPENCERTS else DocumentFormat.JSON
            }
            b.size > 8 && b[0] == 0x89.toByte() && b[1] == 'P'.code.toByte() -> DocumentFormat.IMAGE
            b.size > 3 && b[0] == 0xFF.toByte() && b[1] == 0xD8.toByte() -> DocumentFormat.IMAGE
            ext in setOf("txt", "csv", "md") -> DocumentFormat.TEXT
            else -> DocumentFormat.OTHER
        }
    }

    private fun certificateNote(b: ByteArray): String? =
        Bc.holder(b)?.let { "這是一張 X.509 憑證（${it.subject}），可在設定的信任錨點匯入" }

    // ---- PDF ----

    private suspend fun pdf(bytes: ByteArray, base: DocumentReport, checks: CmsChecks, now: Instant): DocumentReport {
        val pdf = try { PdfFile(bytes) } catch (e: PdfException) {
            return base.copy(format = DocumentFormat.PDF, problems = listOf("PDF 結構無法讀取：" + e.message))
        }
        val sigs = PdfSignatures(pdf)
        val notes = ArrayList<String>()
        val problems = ArrayList<String>()
        if (pdf.reconstructed) notes.add("PDF 的交互參照表損壞，已以掃描方式讀取")
        if (pdf.encrypted) {
            if (pdf.encryptionProblem != null) problems.add("PDF 已加密且需要開啟密碼（${pdf.encryptionProblem}）；仍會檢查簽章")
            else notes.add("PDF 有加密（開啟密碼為空，只限制複製或修改）")
        }
        val dss = sigs.dss()
        val fields = sigs.fields().sortedBy { it.signedLength }
        val fileEnd = significantEnd(bytes)
        val results = ArrayList<Pair<PdfSignatureField, SignatureInfo>>()
        for ((i, f) in fields.withIndex()) {
            val label = f.fieldName ?: "簽章 ${i + 1}"
            val info = pdfSignature(f, bytes, label, dss, checks, now)
            val whole = f.signedLength >= fileEnd
            val (changes, changeProblems) = if (whole) LaterChanges.NONE to emptyList() else sigs.changesAfter(f.signedLength)
            val p = info.problems.toMutableList()
            val n = info.notes.toMutableList()
            var integrity = info.integrity
            if (!f.gapIsContentsOnly) { p.add("簽章範圍（ByteRange）沒有涵蓋簽章值以外的全部內容"); integrity = Check.FAIL }
            p.addAll(changeProblems)
            if (f.docMdpPermission == 1 && changes != LaterChanges.NONE) p.add("此認證簽章不允許任何修改，但之後仍有更新")
            if (f.docMdpPermission != null) n.add("認證簽章（DocMDP P=${f.docMdpPermission}）")
            if (!whole && changes == LaterChanges.SIGNATURES_ONLY) n.add("簽署後只加入簽章、時戳或驗證資料")
            results.add(f to info.copy(
                integrity = integrity,
                coversWholeDocument = whole,
                laterChanges = changes,
                claimedTime = info.claimedTime ?: PdfDates.parse(f.claimedTime),
                reason = f.reason,
                location = f.location,
                signerName = f.name?.takeIf { it.isNotBlank() } ?: info.signerName,
                problems = p,
                notes = n,
            ))
        }
        // A trusted document time stamp added later proves the earlier signatures existed at its time (PAdES-LTA).
        val docStamps = results.filter { it.first.subFilter == "ETSI.RFC3161" && it.second.timestamp?.trusted == true }
        val upgraded = results.map { (f, info) ->
            if (info.certificateValidity == Check.PASS || info.timestamp?.trusted == true || info.signer == null) return@map f to info
            val later = docStamps.filter { it.first.signedLength > f.signedLength }.minByOrNull { it.first.signedLength } ?: return@map f to info
            val t = later.second.timestamp!!.time
            if (t in info.signer.notBefore..info.signer.notAfter && info.problems.none { it.contains("撤銷") }) {
                f to info.copy(
                    certificateValidity = Check.PASS,
                    problems = info.problems.filterNot { it == "簽署憑證不在有效期間內" },
                    notes = info.notes.filterNot { it.startsWith("簽署憑證已過期") } + "簽署憑證在之後的文件時戳時間仍有效，簽章可長期驗證",
                )
            } else f to info
        }
        val level = padesLevel(upgraded.map { it.first to it.second }, dss)
        if (level != null) notes.add(level)
        if (dss != null) notes.add("文件含長期驗證資料（DSS）：${dss.certificates.size} 張憑證、${dss.ocsps.size} 份 OCSP、${dss.crls.size} 份 CRL")
        return base.copy(
            format = DocumentFormat.PDF,
            title = sigs.title(),
            pages = sigs.pageCount(),
            encrypted = pdf.encrypted,
            signatures = upgraded.map { it.second },
            notes = notes,
            problems = problems,
        )
    }

    /** Last byte that is not trailing whitespace or NUL, plus one. */
    private fun significantEnd(b: ByteArray): Long {
        var e = b.size
        while (e > 0 && (b[e - 1].toInt() and 0xFF).let { it == 0 || it == 0x20 || it == 0x0A || it == 0x0D || it == 0x09 || it == 0x0C }) e--
        return e.toLong()
    }

    private fun padesLevel(sigs: List<Pair<PdfSignatureField, SignatureInfo>>, dss: diw.wallet.core.document.pdf.PdfDss?): String? {
        val pades = sigs.filter { it.first.subFilter == "ETSI.CAdES.detached" }
        if (pades.isEmpty()) return null
        val first = pades.first()
        val ownTs = first.second.timestamp != null
        val docTsAfter = sigs.count { it.first.subFilter == "ETSI.RFC3161" && it.first.signedLength > first.first.signedLength }
        val hasLt = (dss != null && (dss.ocsps.isNotEmpty() || dss.crls.isNotEmpty())) || first.second.revocationData
        val level = when {
            hasLt && docTsAfter >= 1 && (ownTs || docTsAfter >= 2) -> "B-LTA"
            hasLt && (ownTs || docTsAfter >= 1) -> "B-LT"
            ownTs || docTsAfter >= 1 -> "B-T"
            else -> "B-B"
        }
        return "PAdES 等級：$level"
    }

    private suspend fun pdfSignature(f: PdfSignatureField, bytes: ByteArray, label: String, dss: diw.wallet.core.document.pdf.PdfDss?, checks: CmsChecks, now: Instant): SignatureInfo {
        val signed = try { f.signedData(bytes) } catch (e: PdfException) {
            return checks.failed(SignatureFormat.PADES, label, "簽章範圍無效：" + e.message)
        }
        val contents = trimDer(f.contents)
        val dssCerts = dss?.certificates.orEmpty()
        val dssOcsps = dss?.ocsps.orEmpty()
        val dssCrls = dss?.crls.orEmpty()
        return when (f.subFilter) {
            "ETSI.RFC3161" -> {
                val ts = checks.timestamp(contents, signed)
                timestampSignature(ts, SignatureFormat.PDF_DOC_TIMESTAMP, label, checks, contents)
            }
            "adbe.pkcs7.sha1" -> {
                val r = checks.verify(contents, null, SignatureFormat.PDF_PKCS7_SHA1, label, now, dssCerts, dssOcsps, dssCrls).first()
                val inner = runCatching { CMSSignedData(contents).signedContent?.content as? ByteArray }.getOrNull()
                if (inner == null || !inner.contentEquals(DocCrypto.digest("SHA-1", signed))) {
                    r.copy(integrity = Check.FAIL, problems = r.problems + "SHA-1 摘要與文件內容不符")
                } else r.copy(notes = r.notes + "使用較弱的 SHA-1（adbe.pkcs7.sha1）")
            }
            "adbe.x509.rsa_sha1" -> x509RsaSha1(f, signed, contents, label, checks, now)
            "ETSI.CAdES.detached" -> checks.verify(contents, signed, SignatureFormat.PADES, label, now, dssCerts, dssOcsps, dssCrls).first()
            else -> checks.verify(contents, signed, SignatureFormat.PDF_PKCS7, label, now, dssCerts, dssOcsps, dssCrls).first()
        }
    }

    /** The DER object at the start of a zero-padded /Contents (BER with indefinite lengths is kept whole). */
    private fun trimDer(b: ByteArray): ByteArray {
        if (b.size < 2 || b[0] != 0x30.toByte()) return b
        val l0 = b[1].toInt() and 0xFF
        if (l0 == 0x80) return b
        val (len, hdr) = when {
            l0 < 0x80 -> l0 to 2
            else -> {
                val n = l0 and 0x7F
                if (n > 4 || b.size < 2 + n) return b
                var v = 0
                for (i in 0 until n) v = (v shl 8) or (b[2 + i].toInt() and 0xFF)
                v to 2 + n
            }
        }
        return if (hdr + len <= b.size) b.copyOfRange(0, hdr + len) else b
    }

    private suspend fun x509RsaSha1(f: PdfSignatureField, signed: ByteArray, contents: ByteArray, label: String, checks: CmsChecks, now: Instant): SignatureInfo {
        val certs = f.certificates.mapNotNull { Bc.holder(it) }
        val signer = certs.firstOrNull()
        val value = runCatching { ASN1OctetString.getInstance(Bc.parse(contents)).octets }.getOrDefault(contents)
        val problems = ArrayList<String>()
        val integrity = if (signer == null) { problems.add("簽章沒有附上憑證"); Check.NOT_CHECKED } else {
            val ok = runCatching {
                val key = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(Bc.provider).getCertificate(signer).publicKey
                Signature.getInstance("SHA1withRSA", Bc.provider).run { initVerify(key); update(signed); verify(value) }
            }.getOrDefault(false)
            if (ok) Check.PASS else { problems.add("簽章值不符"); Check.FAIL }
        }
        return checks.evaluate(SignatureFormat.PDF_X509, label, "RSA SHA-1", signer, certs, integrity, null, null, emptyList(), emptyList(), now,
            problems, mutableListOf("使用較弱的 SHA-1（adbe.x509.rsa_sha1）"))
    }

    private fun timestampSignature(ts: TimestampInfo, format: SignatureFormat, label: String, checks: CmsChecks, token: ByteArray): SignatureInfo {
        val integrity = when {
            ts.imprint == Check.FAIL || ts.signature == Check.FAIL -> Check.FAIL
            ts.imprint == Check.PASS && ts.signature == Check.PASS -> Check.PASS
            else -> Check.NOT_CHECKED
        }
        val signerInfo = ts.chain.firstOrNull()
        val validity = when {
            signerInfo == null -> Check.NOT_CHECKED
            ts.time in signerInfo.notBefore..signerInfo.notAfter -> Check.PASS
            else -> Check.FAIL
        }
        return SignatureInfo(
            format = format,
            label = label,
            algorithm = ts.hashAlgorithm,
            signer = signerInfo,
            chain = ts.chain,
            integrity = integrity,
            coversWholeDocument = null,
            claimedTime = ts.time,
            timestamp = ts,
            trust = ts.trust,
            certificateValidity = validity,
            signerName = ts.tsa,
            problems = ts.problems,
            notes = listOf("時戳機構：${ts.tsa ?: "未知"}"),
        )
    }

    // ---- CMS ----

    private suspend fun cms(bytes: ByteArray, detached: ByteArray?, fileName: String?, base: DocumentReport, checks: CmsChecks, now: Instant): DocumentReport {
        val notes = ArrayList<String>()
        if (GmSignedData.isGm(bytes)) {
            val gm = GmSignedData.parse(bytes)
            val content = gm.content ?: detached
            val sigs = gm.signers.mapIndexed { i, s ->
                val cert = gm.signerCertificate(s)
                val problems = ArrayList<String>()
                val integrity = when {
                    cert == null -> { problems.add("簽章沒有附上簽署者憑證"); Check.NOT_CHECKED }
                    content == null -> Check.NOT_CHECKED
                    else -> gm.verify(s, cert, content).also { if (it == Check.FAIL) problems.add("簽章值不符") }
                }
                val n = if (content == null) mutableListOf("分離式簽章：需要原始內容檔才能檢查內容是否被修改") else mutableListOf()
                checks.evaluate(SignatureFormat.CADES, fileName ?: "簽署者 ${i + 1}", AlgorithmNames.signature(s.signatureOid, s.digestOid), cert,
                    gm.certificates, integrity, null, null, emptyList(), emptyList(), now, problems, n, coversWhole = content != null)
            }
            return base.copy(format = DocumentFormat.CMS_SIGNED, signatures = sigs, notes = listOf("國密 SignedData（GM/T 0010）"))
        }
        val sd = CMSSignedData(bytes)
        val encapsulated = sd.signedContent?.content as? ByteArray
        if (sd.signerInfos.size() == 0) {
            val n = sd.certificates.getMatches(null).size
            return base.copy(format = DocumentFormat.CMS_SIGNED, notes = listOf("只含 $n 張憑證的 PKCS#7 檔（.p7b），沒有簽章"))
        }
        val content = encapsulated ?: detached
        if (encapsulated != null) notes.add("內含原始內容（${encapsulated.size} 位元組），可另存原檔")
        else if (detached != null) notes.add("已以選擇的原始檔檢查分離式簽章")
        val sigs = checks.verify(bytes, if (encapsulated == null) detached else null, SignatureFormat.CADES, fileName ?: "CMS 簽章", now)
            .map { it.copy(coversWholeDocument = content != null) }
        val inner = encapsulated?.let { sniff(it, null) }
        if (inner != null && inner != DocumentFormat.OTHER) notes.add("內含的檔案是 ${inner.name}")
        return base.copy(format = DocumentFormat.CMS_SIGNED, signatures = sigs, notes = notes)
    }

    private fun enveloped(bytes: ByteArray, fileName: String?, base: DocumentReport): DocumentReport {
        val ci = ContentInfo.getInstance(Bc.parse(bytes))
        val env = EnvelopedData.getInstance(ci.content)
        val recipients = ArrayList<String>()
        val keyAlgs = ArrayList<String>()
        for (r in env.recipientInfos) {
            val ri = RecipientInfo.getInstance(r).info
            if (ri is KeyTransRecipientInfo) {
                val iss = runCatching { org.bouncycastle.asn1.cms.IssuerAndSerialNumber.getInstance(ri.recipientIdentifier.id) }.getOrNull()
                recipients.add(if (iss != null) "${iss.name}（序號 ${iss.serialNumber.value.toString(16)}）" else "以金鑰識別碼指定的收件者")
                keyAlgs.add(algName(ri.keyEncryptionAlgorithm))
            } else recipients.add("其他類型的收件者")
        }
        val eci = env.encryptedContentInfo
        val info = EnvelopeInfo(recipients, algName(eci.contentEncryptionAlgorithm), keyAlgs.distinct(), eci.encryptedContent?.octets?.size ?: 0)
        val notes = ArrayList<String>()
        notes.add("這是加密信封（CMS EnvelopedData），只有收件者能解開，沒有簽章可以在本機驗證")
        val asdt = fileName?.lowercase()?.endsWith(".asdt") == true || recipients.any { it.contains("www.ris.gov.tw") }
        if (asdt) notes.add("電子戶籍謄本檔（.asdt）：加密給內政部戶政司，請到戶政司網站上傳查驗；錢包保存原檔與時戳")
        return base.copy(format = DocumentFormat.CMS_ENVELOPED, envelope = info, notes = notes)
    }

    private fun algName(a: AlgorithmIdentifier): String = when (a.algorithm.id) {
        "1.2.840.113549.1.1.1" -> "RSA"
        "1.2.840.113549.1.1.7" -> "RSA-OAEP"
        "1.2.840.113549.3.7" -> "3DES-CBC"
        "2.16.840.1.101.3.4.1.2" -> "AES-128-CBC"
        "2.16.840.1.101.3.4.1.22" -> "AES-192-CBC"
        "2.16.840.1.101.3.4.1.42" -> "AES-256-CBC"
        "1.2.156.10197.1.104" -> "SM4-CBC"
        else -> a.algorithm.id
    }

    private suspend fun timestampFile(bytes: ByteArray, detached: ByteArray?, base: DocumentReport, checks: CmsChecks): DocumentReport {
        val token = CmsChecks.tokenOf(bytes)
        val ts = checks.timestamp(token, detached ?: ByteArray(0))
        val info = if (detached == null) ts.copy(imprint = Check.NOT_CHECKED, problems = ts.problems.filterNot { it == "時戳涵蓋的資料與文件不符" }) else ts
        val sig = timestampSignature(info, SignatureFormat.RFC3161, "時戳", checks, token)
        val notes = if (detached == null) listOf("需要被時戳的原始檔才能確認時戳涵蓋的內容") else emptyList()
        return base.copy(format = DocumentFormat.TIMESTAMP, signatures = listOf(sig.copy(coversWholeDocument = detached != null)), notes = notes)
    }

    // ---- XML, containers, OpenCerts ----

    private suspend fun xml(bytes: ByteArray, fileName: String?, base: DocumentReport, checks: CmsChecks, now: Instant): DocumentReport {
        val doc = runCatching { XmlParsing.parse(bytes) }.getOrElse {
            return base.copy(format = DocumentFormat.XML, problems = listOf("XML 格式錯誤：" + (it.message ?: "")))
        }
        val root = doc.documentElement
        val notes = ArrayList<String>()
        val title = when (root?.localName ?: root?.nodeName) {
            "函", "書函", "公告", "令", "開會通知單", "簽", "稿" -> {
                notes.add("台灣電子公文（${root.nodeName}）")
                XmlParsing.descendants(root, null, "主旨").firstOrNull()?.textContent?.trim()?.take(80)
            }
            else -> null
        }
        val sigs = XmlDsig.verify(bytes, fileName ?: "XML 簽章", checks, now)
        return base.copy(format = DocumentFormat.XML, title = title, signatures = sigs, notes = notes)
    }

    private suspend fun container(bytes: ByteArray, base: DocumentReport, checks: CmsChecks, now: Instant): DocumentReport {
        val files = Zip.read(bytes)
        val entries = files.keys.toList()
        return when {
            "OFD.xml" in files -> {
                val ofd = OfdSignatures(files, checks)
                base.copy(format = DocumentFormat.OFD, title = ofd.title(), pages = ofd.pageCount(), signatures = ofd.verify(now), entries = entries)
            }
            Asic.isAsic(files) -> base.copy(format = DocumentFormat.ASIC_E, signatures = Asic.verify(files, checks, now), entries = entries.filter { !it.startsWith("META-INF/") && it != "mimetype" })
            else -> base.copy(format = DocumentFormat.ZIP, entries = entries, notes = listOf("壓縮檔內有 ${entries.size} 個檔案，可逐一解出保存與檢查"))
        }
    }

    private fun openCerts(bytes: ByteArray, base: DocumentReport): DocumentReport {
        val o = OpenCerts.parse(bytes) ?: return base.copy(format = DocumentFormat.JSON)
        val info = OpenCerts.inspect(o)
        val notes = listOf("OpenCerts 只匯入保存：已檢查內容與 Merkle 證明是否一致，發行端是否確實發行需在 opencerts.io 查驗")
        return base.copy(format = DocumentFormat.OPENCERTS, title = info.name, openCert = info, notes = notes)
    }

    // ---- RFC 3161 ----

    actual suspend fun verifyTimestamp(token: ByteArray, data: ByteArray, trust: DocumentTrustSource): TimestampInfo =
        CmsChecks(PkiSupport(trust)).timestamp(CmsChecks.tokenOf(token), data)

    actual fun timestampRequest(data: ByteArray): ByteArray = timestampRequestForDigest(DocCrypto.digest("SHA-256", data))

    /** A TimeStampReq over an already computed SHA-256 [digest]. */
    fun timestampRequestForDigest(digest: ByteArray): ByteArray {
        val gen = TimeStampRequestGenerator()
        gen.setCertReq(true)
        return gen.generate(CmsChecks.SHA256.algorithm, digest, BigInteger(1, DocCrypto.randomBytes(8))).encoded
    }

    actual fun timestampToken(response: ByteArray): ByteArray {
        val resp = TimeStampResponse(response)
        val token = resp.timeStampToken
        if (token == null) throw IllegalStateException("時戳機構拒絕：" + (resp.statusString ?: "狀態 ${resp.status}"))
        return token.encoded
    }

    actual fun encapsulatedContent(cms: ByteArray): ByteArray? = runCatching {
        if (GmSignedData.isGm(cms)) GmSignedData.parse(cms).content else CMSSignedData(cms).signedContent?.content as? ByteArray
    }.getOrNull()
}
