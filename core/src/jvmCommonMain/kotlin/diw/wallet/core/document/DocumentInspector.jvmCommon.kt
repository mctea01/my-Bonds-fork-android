package diw.wallet.core.document

import diw.wallet.core.i18n.ct
import diw.wallet.core.i18n.CoreText
import diw.wallet.core.document.c2pa.C2paManifests
import diw.wallet.core.document.image.ImageKind
import diw.wallet.core.document.image.TiffDecoder
import diw.wallet.core.document.official.OfficialDocuments
import diw.wallet.core.document.opencerts.OpenAttestationDocument
import diw.wallet.core.document.pdf.PdfDates
import diw.wallet.core.document.pdf.PdfException
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfSignatureField
import diw.wallet.core.document.pdf.PdfSignatures
import diw.wallet.core.document.pgp.OpenPgpInspection
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
        related: Map<String, ByteArray>,
    ): DocumentReport {
        val pki = PkiSupport(trust)
        val checks = CmsChecks(pki)
        val base = DocumentReport(DocumentFormat.OTHER, DocCryptoUtil.hex(DocCrypto.digest("SHA-256", bytes)), bytes.size.toLong(), checkedAt = now.epochSeconds)
        val (data, decodedNote) = unwrapText(bytes)
        return try {
            val report = when (val format = sniff(data, fileName)) {
                DocumentFormat.PDF -> pdf(data, base, checks, now)
                DocumentFormat.CMS_SIGNED -> cms(data, detachedContent, fileName, base, checks, now)
                DocumentFormat.CMS_ENVELOPED -> enveloped(data, fileName, base)
                DocumentFormat.TIMESTAMP -> timestampFile(data, detachedContent, base, checks)
                DocumentFormat.XML -> xml(data, fileName, base, checks, now, related)
                DocumentFormat.OFD, DocumentFormat.ASIC_E, DocumentFormat.ZIP -> container(data, base, checks, now)
                DocumentFormat.OPENCERTS -> openCerts(data, base)
                DocumentFormat.OPENPGP -> OpenPgpInspection.inspect(data, detachedContent, base, trust, now)
                DocumentFormat.OFFICE -> base.copy(format = DocumentFormat.OFFICE, notes = officeNotes(data, fileName))
                DocumentFormat.IMAGE -> contentCredentials(data, base.copy(format = DocumentFormat.IMAGE, notes = listOfNotNull(imageNote(data))), pki, checks, now)
                else -> if (C2paManifests.isSidecar(data)) contentCredentials(data, base.copy(format = format), pki, checks, now)
                    else base.copy(format = format, notes = listOfNotNull(certificateNote(data)))
            }
            if (decodedNote != null) report.copy(notes = listOf(decodedNote) + report.notes) else report
        } catch (e: Exception) {
            base.copy(format = sniff(data, fileName), problems = listOf(ct("core_file_unreadable") + (e.message ?: e.javaClass.simpleName)))
        }
    }

    /** Base64 or PEM text wrapping binary data (such as the .asdt transcript token): the decoded bytes. */
    private fun unwrapText(bytes: ByteArray): Pair<ByteArray, String?> {
        if (bytes.size > 8 * 1024 * 1024 || bytes.isEmpty()) return bytes to null
        val text = runCatching { bytes.decodeToString(throwOnInvalidSequence = true) }.getOrNull()?.trim() ?: return bytes to null
        val pem = Regex("-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\\s]+)-----END \\1-----").find(text)
        if (pem != null && pem.groupValues[1] in setOf("PKCS7", "CMS", "PKCS #7 SIGNED DATA")) {
            return Base64.getMimeDecoder().decode(pem.groupValues[2]) to ct("core_file_pem_decoded")
        }
        if (text.length >= 64 && text.all { it.isLetterOrDigit() || it in "+/=\r\n " }) {
            val decoded = runCatching { Base64.getMimeDecoder().decode(text) }.getOrNull()
            if (decoded != null && decoded.isNotEmpty() && decoded[0] == 0x30.toByte()) return decoded to ct("core_file_base64_decoded")
        }
        return bytes to null
    }

    fun sniff(b: ByteArray, name: String?): DocumentFormat {
        val ext = name?.substringAfterLast('.', "")?.lowercase()
        // A CMS/DER container must be recognised before the PDF magic-byte scan. An opaque PKCS#7 SignedData that
        // encapsulates a PDF (an S/MIME-signed .pdf.p7m, as SSL.com sends) carries "%PDF-" only a few dozen header
        // bytes in, so isPdf would otherwise classify the whole signed file as a plain (unsigned) PDF and the CMS
        // signature would never be checked. No PDF, ZIP, CFB or image starts with a DER SEQUENCE (0x30), so testing
        // the DER container types first is safe for every other format.
        if (b.isNotEmpty() && b[0] == 0x30.toByte()) {
            val oid = runCatching { ASN1ObjectIdentifier.getInstance(ASN1Sequence.getInstance(Bc.parse(b)).getObjectAt(0)).id }.getOrNull()
            when (oid) {
                SIGNED_DATA -> return if (runCatching { CmsChecks.signedData(b, null).signedContentTypeOID == TST_INFO }.getOrDefault(false)) DocumentFormat.TIMESTAMP else DocumentFormat.CMS_SIGNED
                GmSignedData.GM_SIGNED_DATA -> return DocumentFormat.CMS_SIGNED
                ENVELOPED_DATA -> return DocumentFormat.CMS_ENVELOPED
            }
            if (runCatching { TimeStampResponse(b) }.isSuccess) return DocumentFormat.TIMESTAMP
            return DocumentFormat.OTHER
        }
        // OpenPGP armor is text and binary OpenPGP starts with a packet tag (high bit set), never a PDF or ZIP header.
        if (OpenPgpInspection.detect(b, name)) return DocumentFormat.OPENPGP
        if (PdfFile.isPdf(b)) return DocumentFormat.PDF
        if (Zip.isZip(b)) {
            val files = runCatching { Zip.read(b) }.getOrNull() ?: return DocumentFormat.ZIP
            return when {
                "OFD.xml" in files -> DocumentFormat.OFD
                Asic.isAsic(files) -> DocumentFormat.ASIC_E
                officePackage(files) != null -> DocumentFormat.OFFICE
                else -> DocumentFormat.ZIP
            }
        }
        if (b.size > 8 && b.copyOfRange(0, 8).contentEquals(CFB_MAGIC)) return DocumentFormat.OFFICE
        ImageKind.of(b)?.let { kind -> if (kind != ImageKind.BMP && kind != ImageKind.ICO || ImageKind.ofExtension(name ?: "") == kind) return DocumentFormat.IMAGE }
        val head = b.copyOfRange(0, minOf(b.size, 512)).decodeToString().removePrefix("﻿").trimStart()
        return when {
            head.startsWith("<") -> DocumentFormat.XML
            head.startsWith("{") -> {
                if (OpenAttestationDocument.parse(b) != null) DocumentFormat.OPENCERTS else DocumentFormat.JSON
            }
            ext in setOf("txt", "csv", "md") -> DocumentFormat.TEXT
            else -> DocumentFormat.OTHER
        }
    }

    /** The OLE compound file signature (MS-CFB 2.2): Word 97-2003 and other older Office files. */
    private val CFB_MAGIC = byteArrayOf(0xD0.toByte(), 0xCF.toByte(), 0x11, 0xE0.toByte(), 0xA1.toByte(), 0xB1.toByte(), 0x1A, 0xE1.toByte())

    /** The kind of Office package [files] are (OOXML with [Content_Types].xml, or ODF by its mimetype), or null. */
    private fun officePackage(files: Map<String, ByteArray>): String? {
        files["[Content_Types].xml"]?.decodeToString()?.let { types ->
            return when {
                "wordprocessingml" in types -> ct("core_office_word")
                "spreadsheetml" in types -> ct("core_office_excel")
                "presentationml" in types -> ct("core_office_powerpoint")
                else -> ct("core_office_ooxml")
            }
        }
        val mime = files["mimetype"]?.decodeToString()?.trim() ?: return null
        if (!mime.startsWith("application/vnd.oasis.opendocument")) return null
        return when {
            mime.endsWith(".text") -> ct("core_odf_text")
            mime.endsWith(".spreadsheet") -> ct("core_odf_spreadsheet")
            mime.endsWith(".presentation") -> ct("core_odf_presentation")
            else -> ct("core_odf_document")
        }
    }

    /** What an Office file is, and whether it carries Office's own signatures (kept with the file, not verified). */
    private fun officeNotes(b: ByteArray, name: String?): List<String> {
        val ext = name?.substringAfterLast('.', "")?.lowercase()
        if (!Zip.isZip(b)) {
            val kind = when (ext) {
                "xls" -> ct("core_office_excel_97")
                "ppt" -> ct("core_office_powerpoint_97")
                else -> ct("core_office_word_97")
            }
            return listOf(ct("core_office_ole_kept", kind))
        }
        val files = runCatching { Zip.read(b) }.getOrNull() ?: return listOf(ct("core_office_document"))
        val kind = officePackage(files) ?: ct("core_office_document")
        val notes = mutableListOf(ct("core_office_kept", kind))
        if ((ext == "doc" || ext == "xls" || ext == "ppt") && files.containsKey("[Content_Types].xml")) {
            notes.add(ct("core_office_ext_mismatch", ext))
        }
        if (files.keys.any { it.startsWith("_xmlsignatures/") } || files.containsKey("META-INF/documentsignatures.xml")) {
            notes.add(ct("core_office_signature_unchecked"))
        }
        return notes
    }

    /** The kind of picture, and for a TIFF its pages and coding (page images of official documents are CCITT G4 scans). */
    private fun imageNote(b: ByteArray): String? {
        val kind = ImageKind.of(b) ?: return null
        if (kind != ImageKind.TIFF) return ct("core_image_kind", kind.title)
        val pages = runCatching { TiffDecoder.directories(b) }.getOrNull() ?: return ct("core_tiff_unreadable")
        return ct("core_tiff_pages", pages.size, pages.first().describe())
    }

    /** Adds the C2PA manifest store of a picture (or a sidecar .c2pa file), when it has one. */
    private suspend fun contentCredentials(b: ByteArray, report: DocumentReport, pki: PkiSupport, checks: CmsChecks, now: Instant): DocumentReport {
        val store = runCatching { C2paManifests.read(b) }.getOrNull() ?: return report
        val (info, signature) = C2paSignatures(pki, checks).inspect(store, now)
        val note = ct("core_c2pa_present", info.manifests.size, store.container)
        return report.copy(c2pa = info, signatures = listOfNotNull(signature), title = report.title ?: info.manifests.firstOrNull()?.title, notes = report.notes + note)
    }

    private fun certificateNote(b: ByteArray): String? =
        Bc.holder(b)?.let { ct("core_x509_file", it.subject) }

    // ---- PDF ----

    actual suspend fun inspectWithheldPdf(
        bytes: ByteArray,
        byteRange: IntArray,
        sha256: ByteArray,
        trust: DocumentTrustSource,
        now: Instant,
    ): DocumentReport {
        require(sha256.size == 32)
        val range = byteRange.map { it.toLong() }
        val checks = CmsChecks(PkiSupport(trust))
        val base = DocumentReport(DocumentFormat.PDF, "", bytes.size.toLong(), checkedAt = now.epochSeconds)
        // Labels as pdf() assigns them; signatures over other ranges read withheld bytes and cannot be checked here.
        val fields = PdfSignatures(PdfFile(bytes)).fields().sortedBy { it.signedLength }
        val index = fields.indexOfFirst { it.byteRange == range }
        val report = pdf(bytes, base, checks, now, range to sha256)
        if (index < 0) return report.copy(signatures = emptyList(), problems = report.problems + ct("core_attested_sig_missing"))
        val label = fields[index].fieldName ?: ct("core_signature_n", index + 1)
        return report.copy(signatures = report.signatures.filter { it.label == label })
    }

    private suspend fun pdf(bytes: ByteArray, base: DocumentReport, checks: CmsChecks, now: Instant,
        withheld: Pair<List<Long>, ByteArray>? = null): DocumentReport {
        val pdf = try { PdfFile(bytes) } catch (e: PdfException) {
            return base.copy(format = DocumentFormat.PDF, problems = listOf(ct("core_pdf_unreadable") + e.message))
        }
        val sigs = PdfSignatures(pdf)
        val notes = ArrayList<String>()
        val problems = ArrayList<String>()
        if (pdf.reconstructed) notes.add(ct("core_pdf_xref_repaired"))
        if (pdf.encrypted) {
            if (pdf.encryptionProblem != null) problems.add(ct("core_pdf_encrypted_password", pdf.encryptionProblem))
            else notes.add(ct("core_pdf_encrypted_empty"))
        }
        val dss = sigs.dss()
        val fields = sigs.fields().sortedBy { it.signedLength }
        val fileEnd = significantEnd(bytes)
        val results = ArrayList<Pair<PdfSignatureField, SignatureInfo>>()
        for ((i, f) in fields.withIndex()) {
            val label = f.fieldName ?: ct("core_signature_n", i + 1)
            val info = pdfSignature(f, bytes, label, dss, checks, now, withheld?.takeIf { it.first == f.byteRange }?.second)
            val whole = f.signedLength >= fileEnd
            val (changes, changeProblems) = if (whole) LaterChanges.NONE to emptyList() else sigs.changesAfter(f.signedLength)
            val p = info.problems.toMutableList()
            val n = info.notes.toMutableList()
            var integrity = info.integrity
            if (!f.gapIsContentsOnly) { p.add(ct("core_pdf_byterange_gap")); integrity = Check.FAIL }
            p.addAll(changeProblems)
            // ISO 32000-2 12.8.2.2: a DSS and document time stamps may follow any certification, P=1 included.
            val laterSignature = fields.any { it.signedLength > f.signedLength && it.subFilter != "ETSI.RFC3161" }
            if (f.docMdpPermission == 1 && changes != LaterChanges.NONE && (changes != LaterChanges.SIGNATURES_ONLY || laterSignature)) {
                p.add(ct("core_pdf_docmdp_violated"))
            }
            if (f.docMdpPermission != null) n.add(ct("core_pdf_docmdp", f.docMdpPermission))
            if (!whole && changes == LaterChanges.SIGNATURES_ONLY) n.add(ct("core_pdf_only_sig_updates"))
            results.add(f to info.copy(
                integrity = integrity,
                coversWholeDocument = whole,
                laterChanges = changes,
                claimedTime = info.claimedTime ?: PdfDates.parse(f.claimedTime),
                reason = f.reason,
                location = f.location,
                signerName = f.name?.takeIf { it.isNotBlank() } ?: info.signerName,
                docMdp = f.docMdpPermission,
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
            if (t in info.signer.notBefore..info.signer.notAfter && info.problems.none { it.startsWith(CoreText.prefix("core_cms_cert_revoked")) }) {
                f to info.copy(
                    certificateValidity = Check.PASS,
                    problems = info.problems.filterNot { it == ct("core_cms_cert_not_valid") },
                    notes = info.notes.filterNot { it.startsWith(ct("core_cert_expired_prefix")) } + ct("core_cert_valid_at_doc_tst"),
                )
            } else f to info
        }
        val level = padesLevel(upgraded.map { it.first to it.second }, dss)
        if (level != null) notes.add(level)
        // Where each signature sits on its page, matched to the SignatureInfo label by field name.
        val labels = upgraded.map { it.second.label }.toSet()
        val placements = sigs.placements().filter { it.fieldName != null && it.fieldName in labels }.map {
            SignaturePlacementInfo(it.fieldName!!, it.page, it.x0, it.y0, it.x1, it.y1, it.visible)
        }
        if (dss != null) notes.add(ct("core_pdf_dss", dss.certificates.size, dss.ocsps.size, dss.crls.size))
        return base.copy(
            format = DocumentFormat.PDF,
            title = sigs.title(),
            pages = sigs.pageCount(),
            encrypted = pdf.encrypted,
            signatures = upgraded.map { it.second },
            signaturePlacements = placements,
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
        return ct("core_pades_level", level)
    }

    private suspend fun pdfSignature(f: PdfSignatureField, bytes: ByteArray, label: String, dss: diw.wallet.core.document.pdf.PdfDss?, checks: CmsChecks, now: Instant,
        withheldSha256: ByteArray? = null): SignatureInfo {
        if (withheldSha256 != null) {
            // Parts of the signed bytes are withheld (zkPDF): the proven SHA-256 stands for them. Only SHA-256 CMS.
            if (f.subFilter !in setOf("ETSI.CAdES.detached", "adbe.pkcs7.detached")) {
                return checks.failed(SignatureFormat.PADES, label, ct("core_zk_format_unsupported"))
            }
            val format = if (f.subFilter == "ETSI.CAdES.detached") SignatureFormat.PADES else SignatureFormat.PDF_PKCS7
            return checks.verify(trimDer(f.contents), null, format, label, now, dss?.certificates.orEmpty(), dss?.ocsps.orEmpty(),
                dss?.crls.orEmpty(), fallbackClaimed = PdfDates.parse(f.claimedTime), contentSha256 = withheldSha256).first()
        }
        val signed = try { f.signedData(bytes) } catch (e: PdfException) {
            return checks.failed(SignatureFormat.PADES, label, ct("core_sig_range_invalid") + e.message)
        }
        val contents = trimDer(f.contents)
        val dssCerts = dss?.certificates.orEmpty()
        val dssOcsps = dss?.ocsps.orEmpty()
        val dssCrls = dss?.crls.orEmpty()
        // The /M entry stands for the claimed signing time when the CMS has no signingTime attribute (PDF PKCS#7).
        val m = PdfDates.parse(f.claimedTime)
        return when (f.subFilter) {
            "ETSI.RFC3161" -> {
                val ts = checks.timestamp(contents, signed)
                timestampSignature(ts, SignatureFormat.PDF_DOC_TIMESTAMP, label, checks, contents)
            }
            "adbe.pkcs7.sha1" -> {
                val r = checks.verify(contents, null, SignatureFormat.PDF_PKCS7_SHA1, label, now, dssCerts, dssOcsps, dssCrls, fallbackClaimed = m).first()
                val inner = runCatching { CmsChecks.signedData(contents, null).signedContent?.content as? ByteArray }.getOrNull()
                if (inner == null || !inner.contentEquals(DocCrypto.digest("SHA-1", signed))) {
                    r.copy(integrity = Check.FAIL, problems = r.problems + ct("core_sha1_digest_mismatch"))
                } else r.copy(notes = r.notes + ct("core_weak_sha1_pkcs7"))
            }
            "adbe.x509.rsa_sha1" -> x509RsaSha1(f, signed, contents, label, checks, now)
            "ETSI.CAdES.detached" -> checks.verify(contents, signed, SignatureFormat.PADES, label, now, dssCerts, dssOcsps, dssCrls, fallbackClaimed = m).first()
            else -> checks.verify(contents, signed, SignatureFormat.PDF_PKCS7, label, now, dssCerts, dssOcsps, dssCrls, fallbackClaimed = m).first()
        }
    }

    /** The DER object at the start of a zero-padded /Contents (BER with indefinite lengths is kept whole). */
    internal fun trimDer(b: ByteArray): ByteArray {
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
        val integrity = if (signer == null) { problems.add(ct("core_sig_no_cert")); Check.NOT_CHECKED } else {
            val ok = runCatching {
                val key = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(Bc.provider).getCertificate(signer).publicKey
                Signature.getInstance("SHA1withRSA", Bc.provider).run { initVerify(key); update(signed); verify(value) }
            }.getOrDefault(false)
            if (ok) Check.PASS else { problems.add(ct("core_sig_value_mismatch")); Check.FAIL }
        }
        return checks.evaluate(SignatureFormat.PDF_X509, label, "RSA SHA-1", signer, certs, integrity, null, null, emptyList(), emptyList(), now,
            problems, mutableListOf(ct("core_weak_sha1_x509")))
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
            notes = listOf(ct("core_tsa_line", ts.tsa ?: ct("core_unknown"))),
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
                    cert == null -> { problems.add(ct("core_sig_no_signer_cert")); Check.NOT_CHECKED }
                    content == null -> Check.NOT_CHECKED
                    else -> gm.verify(s, cert, content).also { if (it == Check.FAIL) problems.add(ct("core_sig_value_mismatch")) }
                }
                val n = if (content == null) mutableListOf(ct("core_sig_detached_needs_content")) else mutableListOf()
                checks.evaluate(SignatureFormat.CADES, fileName ?: ct("core_signer_n", i + 1), AlgorithmNames.signature(s.signatureOid, s.digestOid), cert,
                    gm.certificates, integrity, null, null, emptyList(), emptyList(), now, problems, n, coversWhole = content != null)
            }
            return base.copy(format = DocumentFormat.CMS_SIGNED, signatures = sigs, notes = listOf(ct("core_gm_signed_data")))
        }
        val sd = CmsChecks.signedData(bytes, null)
        val encapsulated = sd.signedContent?.content as? ByteArray
        if (sd.signerInfos.size() == 0) {
            val n = sd.certificates.getMatches(null).size
            return base.copy(format = DocumentFormat.CMS_SIGNED, notes = listOf(ct("core_p7b_only", n)))
        }
        val content = encapsulated ?: detached
        if (encapsulated != null) notes.add(ct("core_encapsulated_content", encapsulated.size))
        else if (detached != null) notes.add(ct("core_detached_checked"))
        val sigs = checks.verify(bytes, if (encapsulated == null) detached else null, SignatureFormat.CADES, fileName ?: ct("core_cms_signature"), now)
            .map { it.copy(coversWholeDocument = content != null) }
        val inner = encapsulated?.let { sniff(it, null) }
        if (inner != null && inner != DocumentFormat.OTHER) notes.add(ct("core_inner_file", inner.name))
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
                recipients.add(if (iss != null) ct("core_recipient_issuer", iss.name, iss.serialNumber.value.toString(16)) else ct("core_recipient_key_id"))
                keyAlgs.add(algName(ri.keyEncryptionAlgorithm))
            } else recipients.add(ct("core_recipient_other"))
        }
        val eci = env.encryptedContentInfo
        val info = EnvelopeInfo(recipients, algName(eci.contentEncryptionAlgorithm), keyAlgs.distinct(), eci.encryptedContent?.octets?.size ?: 0)
        val notes = ArrayList<String>()
        notes.add(ct("core_enveloped_only"))
        val asdt = fileName?.lowercase()?.endsWith(".asdt") == true || recipients.any { it.contains("www.ris.gov.tw") }
        if (asdt) notes.add(ct("core_asdt_note"))
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
        val info = if (detached == null) ts.copy(imprint = Check.NOT_CHECKED, problems = ts.problems.filterNot { it == ct("core_tst_data_mismatch") }) else ts
        val sig = timestampSignature(info, SignatureFormat.RFC3161, ct("core_time_stamp"), checks, token)
        val notes = if (detached == null) listOf(ct("core_tst_needs_content")) else emptyList()
        return base.copy(format = DocumentFormat.TIMESTAMP, signatures = listOf(sig.copy(coversWholeDocument = detached != null)), notes = notes)
    }

    // ---- XML, containers, OpenCerts ----

    private suspend fun xml(bytes: ByteArray, fileName: String?, base: DocumentReport, checks: CmsChecks, now: Instant, related: Map<String, ByteArray>): DocumentReport {
        val doc = runCatching { XmlParsing.parse(bytes) }.getOrElse {
            return base.copy(format = DocumentFormat.XML, problems = listOf(ct("core_xml_malformed") + (it.message ?: "")))
        }
        val notes = ArrayList<String>()
        val official = if (doc.documentElement != null) OfficialDocuments.parse(bytes) else null
        val title = official?.let { o ->
            notes.add(ct("core_official_note", o.category?.takeIf { it != o.kind }?.let { c -> ct("core_pair_comma", o.kind, c) } ?: o.kind))
            if (o.kind == "線上簽核") {
                notes.add(ct("core_approval_not_xades"))
            }
            if (o.kind == "線上簽核") ct("core_approval_title", o.steps.size) else (o.subject ?: o.title).take(80)
        }
        val sigs = XmlDsig.verify(bytes, fileName ?: ct("core_xml_signature"), checks, now) +
            if (ApprovalSignatures.isApproval(doc)) ApprovalSignatures.verify(bytes, checks, now, related) else emptyList()
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
            else -> base.copy(format = DocumentFormat.ZIP, entries = entries, notes = listOf(ct("core_zip_entries", entries.size)))
        }
    }

    private fun openCerts(bytes: ByteArray, base: DocumentReport): DocumentReport {
        val doc = OpenAttestationDocument.parse(bytes) ?: return base.copy(format = DocumentFormat.JSON)
        val info = OpenCertInfo(
            version = doc.version,
            name = doc.name,
            issuers = doc.issuers.mapNotNull { it.name },
            identityProofs = doc.issuers.mapNotNull { i -> i.identityType?.let { t -> t + (i.identityLocation?.let { ct("core_colon_value", it) } ?: "") } },
            fields = doc.fields(),
            integrity = doc.integrity,
            issuerVerified = Check.NOT_CHECKED,
        )
        val notes = listOf(ct("core_opencerts_checked"))
        return base.copy(format = DocumentFormat.OPENCERTS, title = info.name, openCert = info, notes = notes)
    }

    // ---- RFC 3161 ----

    actual suspend fun verifyTimestamp(token: ByteArray, data: ByteArray, trust: DocumentTrustSource): TimestampInfo =
        CmsChecks(PkiSupport(trust)).timestamp(CmsChecks.tokenOf(token), data)

    actual suspend fun verifyTimestampDigest(token: ByteArray, sha256: ByteArray, trust: DocumentTrustSource): TimestampInfo =
        CmsChecks(PkiSupport(trust)).timestamp(CmsChecks.tokenOf(token), ByteArray(0), sha256)

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
        if (token == null) throw IllegalStateException(ct("core_tsa_refused") + (resp.statusString ?: ct("core_status_n", resp.status)))
        return token.encoded
    }

    actual fun encapsulatedContent(cms: ByteArray): ByteArray? = runCatching {
        if (GmSignedData.isGm(cms)) GmSignedData.parse(cms).content else CmsChecks.signedData(cms, null).signedContent?.content as? ByteArray
    }.getOrNull()
}
