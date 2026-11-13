package diw.wallet.core.document

import diw.wallet.core.document.ofd.OfdBox
import diw.wallet.core.document.ofd.OfdStamp
import diw.wallet.core.i18n.ct
import org.bouncycastle.asn1.ASN1BitString
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1GeneralizedTime
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.cert.X509CertificateHolder
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.UtcOffset
import kotlinx.datetime.toInstant
import java.util.Base64
import kotlin.time.Instant

/**
 * OFD (GB/T 33190) signatures: electronic seals (GB/T 38540 SES_Signature, version 4 and the GM/T 0031 version
 * 1) and digital signatures (GB/T 35275 SignedData). The signature covers Signature.xml, whose References hold the
 * SM3 (or other) digest of every protected file in the container.
 */
internal class OfdSignatures(private val files: Map<String, ByteArray>, private val checker: CmsChecks? = null) {
    /** Checks need trust; reading the stamps does not. */
    private val checks: CmsChecks get() = checker ?: error("OfdSignatures without CmsChecks cannot verify")

    private fun file(path: String, base: String): ByteArray? {
        val p = if (path.startsWith("/")) path.removePrefix("/") else (if (base.isEmpty()) path else "$base/$path")
        return files[normalize(p)]
    }

    private fun normalize(p: String): String {
        val out = ArrayList<String>()
        for (part in p.replace('\\', '/').split('/')) when (part) {
            "", "." -> {}
            ".." -> if (out.isNotEmpty()) out.removeAt(out.size - 1)
            else -> out.add(part)
        }
        return out.joinToString("/")
    }

    private fun dir(path: String) = normalize(path).substringBeforeLast('/', "")

    /** Title of the first document (DocInfo/Title) when present. */
    fun title(): String? = runCatching {
        val ofd = XmlParsing.parse(files["OFD.xml"]!!)
        XmlParsing.descendants(ofd, null, "Title").firstOrNull()?.textContent?.trim()?.ifEmpty { null }
    }.getOrNull()

    fun pageCount(): Int? = runCatching {
        val ofd = XmlParsing.parse(files["OFD.xml"]!!)
        val root = XmlParsing.descendants(ofd, null, "DocRoot").first().textContent.trim()
        val doc = XmlParsing.parse(file(root, "")!!)
        XmlParsing.descendants(doc, null, "Page").size
    }.getOrNull()

    /** One signature listed in a Signatures.xml: its descriptor, type (Seal or Sign), ID and report label. */
    private class Entry(val path: String, val seal: Boolean, val id: String) {
        val label: String get() = (if (seal) ct("core_ofd_seal") else ct("core_ofd_signature")) + if (id.isNotEmpty()) " $id" else ""
    }

    private fun entries(): List<Entry> {
        val ofd = XmlParsing.parse(files["OFD.xml"] ?: return emptyList())
        val out = ArrayList<Entry>()
        for (sigsRef in XmlParsing.descendants(ofd, null, "Signatures")) {
            val path = sigsRef.textContent.trim().ifEmpty { continue }
            val sigsBytes = file(path, "") ?: continue
            val base = dir(path.removePrefix("/"))
            val sigs = runCatching { XmlParsing.parse(sigsBytes) }.getOrNull() ?: continue
            for (s in XmlParsing.descendants(sigs, null, "Signature")) {
                val loc = s.getAttribute("BaseLoc").ifEmpty { continue }
                val type = s.getAttribute("Type").ifEmpty { "Seal" }
                val sigPath = if (loc.startsWith("/")) normalize(loc) else normalize("$base/$loc")
                out.add(Entry(sigPath, type.equals("Seal", true), s.getAttribute("ID")))
            }
        }
        return out
    }

    suspend fun verify(now: Instant): List<SignatureInfo> = entries().map { verifyOne(it.path, it.seal, it.label, now) }

    /**
     * Where each signature's seal shows (its StampAnnot elements) with the seal picture: from the electronic seal
     * inside the signature value (Seal type) or the seal file the descriptor names (Seal/BaseLoc).
     */
    fun stamps(): List<OfdStamp> = entries().flatMap { e ->
        runCatching {
            val xml = files[e.path] ?: return@runCatching emptyList()
            val doc = XmlParsing.parse(xml)
            val base = dir(e.path)
            val annots = XmlParsing.descendants(doc, null, "StampAnnot")
            if (annots.isEmpty()) return@runCatching emptyList()
            val sealBytes = XmlParsing.descendants(doc, null, "Seal").firstOrNull()?.let { s ->
                XmlParsing.descendants(s, null, "BaseLoc").firstOrNull()?.textContent?.trim()?.let { file(it, base) }
            }
            val value = XmlParsing.descendants(doc, null, "SignedValue").firstOrNull()?.textContent?.trim()?.let { file(it, base) }
            val eseal = value?.let { v -> runCatching { sesSeal(v) }.getOrNull() } ?: sealBytes
            val picture = eseal?.let { runCatching { sealPicture(it) }.getOrNull() }
            annots.mapNotNull { a ->
                val box = OfdBox.parse(a.getAttribute("Boundary")) ?: return@mapNotNull null
                OfdStamp(e.label, a.getAttribute("PageRef"), box, OfdBox.parse(a.getAttribute("Clip")), picture?.first, picture?.second, e.path)
            }
        }.getOrDefault(emptyList())
    }

    /** The DER of the electronic seal (SESeal) inside an SES_Signature, or null for another value. */
    private fun sesSeal(der: ByteArray): ByteArray? {
        val ses = ASN1Sequence.getInstance(Bc.parse(der))
        val toSign = ses.getObjectAt(0) as? ASN1Sequence ?: return null
        return (toSign.getObjectAt(1) as? ASN1Sequence)?.encoded
    }

    /** Type and data of the picture of an electronic seal (SES_ESPictrueInfo in SES_SealInfo, v1 to v5). */
    private fun sealPicture(eseal: ByteArray): Pair<String, ByteArray>? {
        val seal = ASN1Sequence.getInstance(Bc.parse(eseal))
        val info = ASN1Sequence.getInstance(seal.getObjectAt(0))
        val pic = info.firstOrNull { e ->
            e is ASN1Sequence && e.size() >= 2 && e.getObjectAt(0) is ASN1String && e.getObjectAt(1) is ASN1OctetString
        } as? ASN1Sequence ?: return null
        return (pic.getObjectAt(0) as ASN1String).string.lowercase() to ASN1OctetString.getInstance(pic.getObjectAt(1)).octets
    }

    private suspend fun verifyOne(sigPath: String, seal: Boolean, label: String, now: Instant): SignatureInfo {
        val format = if (seal) SignatureFormat.OFD_SEAL else SignatureFormat.OFD_SIGN
        val sigXml = files[sigPath] ?: return checks.failed(format, label, ct("core_ofd_no_descriptor", sigPath))
        val base = dir(sigPath)
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        val doc = XmlParsing.parse(sigXml)
        val signedInfo = XmlParsing.descendants(doc, null, "SignedInfo").firstOrNull() ?: return checks.failed(format, label, ct("core_ofd_no_signed_info"))

        // Protected files.
        var integrity = Check.PASS
        val refs = XmlParsing.descendants(signedInfo, null, "References").firstOrNull()
        val method = refs?.getAttribute("CheckMethod").orEmpty()
        val digestAlg = when (method.uppercase()) {
            "", "SM3", "1.2.156.10197.1.401" -> "SM3"
            "SHA1", "SHA-1", "1.3.14.3.2.26" -> "SHA-1"
            "SHA256", "SHA-256", "2.16.840.1.101.3.4.2.1" -> "SHA-256"
            "MD5", "1.2.840.113549.2.5" -> "MD5"
            else -> null
        }
        val covered = HashSet<String>()
        if (digestAlg == null) { problems.add(ct("core_digest_unsupported", method)); integrity = Check.NOT_CHECKED }
        else for (r in XmlParsing.descendants(signedInfo, null, "Reference")) {
            val ref = r.getAttribute("FileRef")
            val p = if (ref.startsWith("/")) normalize(ref) else normalize("$base/$ref")
            covered.add(p)
            val data = files[p]
            val expected = runCatching { Base64.getMimeDecoder().decode(XmlParsing.text(XmlParsing.descendants(r, null, "CheckValue").firstOrNull()).orEmpty()) }.getOrNull()
            when {
                data == null -> { problems.add(ct("core_ofd_protected_missing", p)); integrity = Check.FAIL }
                expected == null || !DocCrypto.digest(digestAlg, data).contentEquals(expected) -> { problems.add(ct("core_ofd_file_modified", p)); integrity = Check.FAIL }
            }
        }
        // Content outside the signature: anything not protected, other than signature data added later.
        val unprotected = files.keys.filter { it !in covered && it != sigPath && !it.contains("/Signs/") && !it.startsWith("Signs/") && !it.endsWith("Signatures.xml") }
        if (unprotected.isNotEmpty()) notes.add(ct("core_ofd_uncovered") + unprotected.take(5).joinToString(ct("core_sep_list")) + if (unprotected.size > 5) ct("core_ofd_uncovered_more", unprotected.size) else "")

        val valuePath = XmlParsing.descendants(doc, null, "SignedValue").firstOrNull()?.textContent?.trim()
        val value = valuePath?.let { file(it, base) } ?: return checks.failed(format, label, ct("core_ofd_no_signed_value"))
        val claimed0 = XmlParsing.descendants(signedInfo, null, "SignatureDateTime").firstOrNull()?.textContent?.trim()?.let { parseOfdTime(it) }

        var signer: X509CertificateHolder? = null
        var pool = emptyList<X509CertificateHolder>()
        var claimed = claimed0
        var timestamp: TimestampInfo? = null
        var algorithm: String? = "SM2 SM3"
        if (seal || runCatching { ASN1Sequence.getInstance(Bc.parse(value)).getObjectAt(0) is ASN1Sequence }.getOrDefault(false)) {
            val r = sesSignature(value, sigXml, files.entries.firstOrNull { it.key.endsWith(".esl") && it.key in covered }?.value, problems, notes)
            if (r == null) return checks.failed(format, label, problems.firstOrNull() ?: ct("core_ofd_ses_unparsable"))
            signer = r.signer
            pool = listOfNotNull(r.signer, r.sealCert)
            if (r.integrity != Check.PASS) integrity = if (r.integrity == Check.FAIL) Check.FAIL else if (integrity == Check.PASS) r.integrity else integrity
            claimed = r.time ?: claimed
            algorithm = r.algorithm
            timestamp = r.timestampToken?.let { checks.timestamp(it, r.signatureValue) }
            r.sealName?.let { notes.add(0, ct("core_ofd_seal_name", it)) }
        } else {
            val gm = runCatching { GmSignedData.parse(value) }.getOrNull() ?: return checks.failed(format, label, ct("core_ofd_sig_unparsable"))
            val s = gm.signers.firstOrNull() ?: return checks.failed(format, label, ct("core_ofd_no_signer"))
            signer = gm.signerCertificate(s)
            pool = gm.certificates
            algorithm = AlgorithmNames.signature(s.signatureOid, s.digestOid)
            val content = gm.content ?: sigXml
            if (gm.content != null && !gm.content.contentEquals(sigXml)) { problems.add(ct("core_ofd_content_mismatch")); integrity = Check.FAIL }
            if (signer == null) { problems.add(ct("core_sig_no_signer_cert")); integrity = if (integrity == Check.FAIL) Check.FAIL else Check.NOT_CHECKED }
            else if (gm.verify(s, signer, content) != Check.PASS) { problems.add(ct("core_sig_value_mismatch")); integrity = Check.FAIL }
            if (gm.isGmOids) notes.add(ct("core_ofd_gbt35275")) else notes.add(ct("core_ofd_pkcs7_sign"))
            timestamp = s.timestampToken?.let { checks.timestamp(it, s.signature) }
        }
        return checks.evaluate(
            format = format, label = label, algorithm = algorithm, signer = signer, pool = pool, integrity = integrity,
            claimed = claimed, timestamp = timestamp, ocsps = emptyList(), crls = emptyList(), now = now,
            problems = problems, notes = notes, coversWhole = unprotected.isEmpty(),
        )
    }

    private class SesResult(
        val signer: X509CertificateHolder?,
        val sealCert: X509CertificateHolder?,
        val integrity: Check,
        val time: Long?,
        val algorithm: String,
        val signatureValue: ByteArray,
        val timestampToken: ByteArray?,
        val sealName: String?,
    )

    /** GB/T 38540 (v4) or GM/T 0031 (v1) SES_Signature over the Signature.xml bytes. */
    private fun sesSignature(der: ByteArray, signed: ByteArray, sealFile: ByteArray?, problems: MutableList<String>, notes: MutableList<String>): SesResult? {
        val ses = runCatching { ASN1Sequence.getInstance(Bc.parse(der)) }.getOrNull() ?: run { problems.add(ct("core_ofd_ses_unparsable_named")); return null }
        val toSign = ASN1Sequence.getInstance(ses.getObjectAt(0))
        val v4 = ses.size() >= 4 && ses.getObjectAt(1) is ASN1OctetString
        val certDer: ByteArray
        val sigOid: String
        val signature: ByteArray
        var token: ByteArray? = null
        val timeEl = toSign.getObjectAt(2)
        val time: Long?
        if (v4) {
            certDer = ASN1OctetString.getInstance(ses.getObjectAt(1)).octets
            sigOid = ASN1ObjectIdentifier.getInstance(ses.getObjectAt(2)).id
            signature = ASN1BitString.getInstance(ses.getObjectAt(3)).octets
            if (ses.size() > 4) (ses.getObjectAt(4) as? ASN1TaggedObject)?.let { t ->
                token = runCatching { ASN1BitString.getInstance(t.baseObject.toASN1Primitive()).octets }.getOrNull()
                    ?: runCatching { ASN1OctetString.getInstance(t.baseObject.toASN1Primitive()).octets }.getOrNull()
            }
            time = runCatching { ASN1GeneralizedTime.getInstance(timeEl).date.time / 1000 }.getOrNull()
        } else {
            certDer = ASN1OctetString.getInstance(toSign.getObjectAt(5)).octets
            sigOid = ASN1ObjectIdentifier.getInstance(toSign.getObjectAt(6)).id
            signature = ASN1BitString.getInstance(ses.getObjectAt(1)).octets
            time = runCatching { parseOfdTime(String(ASN1BitString.getInstance(timeEl).octets)) }.getOrNull()
                ?: runCatching { ASN1GeneralizedTime.getInstance(timeEl).date.time / 1000 }.getOrNull()
        }
        val signer = Bc.holder(certDer)
        var integrity = Check.PASS
        version(ses, v4)?.let { notes.add(it) }
        val dataHash = runCatching { ASN1BitString.getInstance(toSign.getObjectAt(3)).octets }.getOrNull()
        if (dataHash == null || !DocCrypto.digest("SM3", signed).contentEquals(dataHash) && !DocCrypto.digest("SHA-256", signed).contentEquals(dataHash)) {
            problems.add(ct("core_ofd_ses_data_mismatch")); integrity = Check.FAIL
        }
        if (signer == null) { problems.add(ct("core_ofd_ses_no_cert")); integrity = Check.NOT_CHECKED }
        else if (!GmSignedData.verifySignature(signer, sigOid, null, toSign.encoded, signature)) { problems.add(ct("core_ofd_ses_value_mismatch")); integrity = Check.FAIL }

        // The seal (SESeal): made and signed by the seal maker; its picture, validity and authorised signers.
        val eseal = ASN1Sequence.getInstance(toSign.getObjectAt(1))
        if (sealFile != null && !sealFile.contentEquals(eseal.encoded)) notes.add(ct("core_ofd_seal_differs"))
        val sealInfo = ASN1Sequence.getInstance(eseal.getObjectAt(0))
        val sealCertDer: ByteArray?
        val sealSigOid: String?
        val sealSig: ByteArray?
        if (eseal.size() >= 4) {
            sealCertDer = runCatching { ASN1OctetString.getInstance(eseal.getObjectAt(1)).octets }.getOrNull()
            sealSigOid = runCatching { ASN1ObjectIdentifier.getInstance(eseal.getObjectAt(2)).id }.getOrNull()
            sealSig = runCatching { ASN1BitString.getInstance(eseal.getObjectAt(3)).octets }.getOrNull()
        } else {
            val signInfo = ASN1Sequence.getInstance(eseal.getObjectAt(1))
            sealCertDer = runCatching { ASN1OctetString.getInstance(signInfo.getObjectAt(0)).octets }.getOrNull()
            sealSigOid = runCatching { ASN1ObjectIdentifier.getInstance(signInfo.getObjectAt(1)).id }.getOrNull()
            sealSig = runCatching { ASN1BitString.getInstance(signInfo.getObjectAt(2)).octets }.getOrNull()
        }
        val sealCert = sealCertDer?.let { Bc.holder(it) }
        if (sealCert == null || sealSigOid == null || sealSig == null || !GmSignedData.verifySignature(sealCert, sealSigOid, null, sealInfo.encoded, sealSig)) {
            problems.add(ct("core_ofd_seal_maker_invalid")); integrity = Check.FAIL
        } else notes.add(ct("core_ofd_seal_maker", checksCn(sealCert)))
        val property = runCatching { ASN1Sequence.getInstance(sealInfo.getObjectAt(2)) }.getOrNull()
        val name = property?.let { runCatching { (it.getObjectAt(1) as ASN1String).string }.getOrNull() }
        if (property != null) {
            val times = property.mapNotNull { e -> runCatching { ASN1GeneralizedTime.getInstance(e).date.time / 1000 }.getOrNull() }
            if (times.size >= 3 && time != null && (time < times[times.size - 2] || time > times[times.size - 1])) {
                problems.add(ct("core_ofd_time_outside_seal")); integrity = Check.FAIL
            }
            // Authorised signer certificates (type 1: certificates; type 2: digests).
            if (signer != null) {
                val list = property.firstOrNull { it is ASN1Sequence || it is ASN1TaggedObject }?.let { certList(it) }
                if (list != null && list.isNotEmpty()) {
                    val ok = list.any { it.contentEquals(signer.encoded) || it.contentEquals(DocCrypto.digest("SM3", signer.encoded)) || it.contentEquals(DocCrypto.digest("SHA-256", signer.encoded)) }
                    if (!ok) { problems.add(ct("core_ofd_signer_not_authorized")); integrity = Check.FAIL }
                }
            }
        }
        return SesResult(signer, sealCert, integrity, time, AlgorithmNames.signature(sigOid, "1.2.156.10197.1.401"), signature, token, name)
    }

    /**
     * The version the seal header states (SES_Header: ID "ES", version, vendor ID): 1 is GM/T 0031-2014, 4 is
     * GB/T 38540-2020, 5 is GM/T 0031-2025 (same structure as 4). Read from the seal inside the signature.
     */
    private fun version(ses: ASN1Sequence, v4: Boolean): String? = runCatching {
        val toSign = ASN1Sequence.getInstance(ses.getObjectAt(0))
        val header = ASN1Sequence.getInstance(ASN1Sequence.getInstance(ASN1Sequence.getInstance(toSign.getObjectAt(1)).getObjectAt(0)).getObjectAt(0))
        val n = org.bouncycastle.asn1.ASN1Integer.getInstance(header.getObjectAt(1)).value.toInt()
        val standard = when (n) { 1, 2, 3 -> "GM/T 0031-2014"; 4 -> "GB/T 38540-2020"; 5 -> "GM/T 0031-2025"; else -> null }
        ct("core_ofd_ses_version", n, standard ?: if (v4) "GB/T 38540" else "GM/T 0031")
    }.getOrNull()

    private fun certList(e: ASN1Encodable): List<ByteArray> = runCatching {
        val seq = if (e is ASN1TaggedObject) ASN1Sequence.getInstance(e.baseObject.toASN1Primitive()) else ASN1Sequence.getInstance(e)
        seq.flatMap { item ->
            when (item) {
                is ASN1OctetString -> listOf(item.octets)
                is ASN1Sequence -> item.mapNotNull { (it as? ASN1OctetString)?.octets }
                else -> emptyList()
            }
        }
    }.getOrDefault(emptyList())

    private fun checksCn(h: X509CertificateHolder) = h.subject.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN).firstOrNull()?.first?.value?.toString() ?: h.subject.toString()

    companion object {
        /** OFD times: "yyyy-MM-dd HH:mm:ss" (local China time), ISO 8601, or GeneralizedTime digits. */
        fun parseOfdTime(s: String): Long? {
            val t = s.trim()
            runCatching { return Instant.parse(t).epochSeconds }
            val m = Regex("(\\d{4})-?(\\d{2})-?(\\d{2})[ T]?(\\d{2}):?(\\d{2}):?(\\d{2})").find(t) ?: return null
            val (y, mo, d, h, mi, se) = m.destructured
            return runCatching {
                LocalDateTime(y.toInt(), mo.toInt(), d.toInt(), h.toInt(), mi.toInt(), se.toInt())
                    .toInstant(UtcOffset(hours = if (t.endsWith("Z")) 0 else 8)).epochSeconds
            }.getOrNull()
        }
    }
}
