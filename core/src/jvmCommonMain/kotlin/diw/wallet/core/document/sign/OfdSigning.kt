package diw.wallet.core.document.sign

import diw.wallet.core.document.Bc
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.GmSignedData
import diw.wallet.core.document.Zip
import diw.wallet.core.document.ofd.OfdPackage
import diw.wallet.core.document.pdf.PdfSignatureAppearance
import diw.wallet.core.i18n.ct
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * OFD signatures (GB/T 33190-2016 section 18): digital signatures (Type "Sign") and electronic seals (Type "Seal",
 * GB/T 38540). The package keeps every file it has; the first signature adds a Signatures.xml (and its reference in
 * OFD.xml), each signature adds Sign_N/ with Signature.xml and SignedValue.dat (and Seal.esl for a seal).
 * References cover every file of the package except Signatures.xml, which later signatures extend, so earlier
 * signatures stay valid. The signed data is the Signature.xml file itself.
 */
internal object OfdSigning {
    private const val NS = "http://www.ofdspec.org/2016"
    private const val SM3 = "1.2.156.10197.1.401"
    private const val SM2_SIGN = "1.2.156.10197.1.301.1"
    private const val SM3_WITH_SM2 = "1.2.156.10197.1.501"
    private const val SHA256 = "2.16.840.1.101.3.4.2.1"
    private const val RSA_SHA256 = "1.2.840.113549.1.1.11"
    private const val ECDSA_SHA256 = "1.2.840.10045.4.3.2"
    private const val PKCS7_SIGNED = "1.2.840.113549.1.7.2"
    private const val PKCS7_DATA = "1.2.840.113549.1.7.1"
    private const val TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
    private const val DEFAULT_SEAL_MM = 40.0
    private val TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")

    suspend fun sign(ofd: ByteArray, signer: DocumentSigner, timestamper: Timestamper?, nowMillis: Long = System.currentTimeMillis(), seal: OfdSealOptions? = null): ByteArray {
        val files = LinkedHashMap(Zip.read(ofd))
        val pkg = OfdPackage.read(files) ?: throw SigningException(ct("core_ofd_sign_not_ofd"))
        val doc = pkg.documents.firstOrNull() ?: throw SigningException(ct("core_ofd_sign_no_document"))
        val stamp = seal?.let { stampOf(it, doc, signer, nowMillis / 1000) }
        val docDir = doc.root.substringBeforeLast('/', "")
        val signsDir = (if (docDir.isEmpty()) "" else "$docDir/") + "Signs"

        // Signatures.xml: the existing list, or a new one referenced from OFD.xml.
        val sigsPath = doc.signatures ?: "$signsDir/Signatures.xml"
        val existing = files[sigsPath]?.decodeToString()?.removePrefix("﻿")
        if (existing == null) files["OFD.xml"] = withSignaturesRef(files["OFD.xml"]!!.decodeToString().removePrefix("﻿"), "/$sigsPath").encodeToByteArray()
        val sigsDir = sigsPath.substringBeforeLast('/', "")
        var n = 0
        while (files.keys.any { it.startsWith("$sigsDir/Sign_$n/") }) n++
        val signDir = "$sigsDir/Sign_$n"
        val sigXmlPath = "$signDir/Signature.xml"
        val valuePath = "$signDir/SignedValue.dat"
        val ids = existing?.let { Regex("<(?:\\w+:)?Signature\\b[^>]*\\bID=\"[^\"]*?(\\d+)\"").findAll(it).mapNotNull { m -> m.groupValues[1].toIntOrNull() }.toList() }.orEmpty()
        val max = existing?.let { Regex("<(?:\\w+:)?MaxSignId>\\s*[^<]*?(\\d+)\\s*<").find(it)?.groupValues?.get(1)?.toIntOrNull() } ?: 0
        val next = maxOf(max, ids.maxOrNull() ?: 0) + 1
        val id = "s" + next.toString().padStart(3, '0')
        files[sigsPath] = signatures(existing, next, id, "/$sigXmlPath", if (stamp != null) "Seal" else "Sign").encodeToByteArray()
        val sealPath = "$signDir/Seal.esl"
        if (stamp != null) files[sealPath] = stamp.seal.der

        // Every file is protected except the signature list and the new signature's own files.
        val sm2 = signer.keyType == SignerKeyType.SM2
        val digestAlg = if (sm2) "SM3" else "SHA-256"
        val refs = files.keys.filter { it != sigsPath && it != sigXmlPath && it != valuePath }
        val time = ZonedDateTime.ofInstant(java.time.Instant.ofEpochMilli(nowMillis), ZoneOffset.UTC).format(TIME)
        val signatureXml = buildString {
            append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
            append("<ofd:Signature xmlns:ofd=\"$NS\"><ofd:SignedInfo>")
            append("<ofd:Provider ProviderName=\"DIW MY WALLET\" Company=\"DIW MY WALLET\" Version=\"1.0\"/>")
            append("<ofd:SignatureMethod>").append(if (stamp != null) OfdSeals.SM3_WITH_SM2 else signatureMethod(signer.keyType)).append("</ofd:SignatureMethod>")
            append("<ofd:SignatureDateTime>").append(time).append("</ofd:SignatureDateTime>")
            append("<ofd:References CheckMethod=\"").append(if (sm2) SM3 else SHA256).append("\">")
            for (r in refs) {
                append("<ofd:Reference FileRef=\"/").append(xmlAttr(r)).append("\"><ofd:CheckValue>")
                append(Base64.getEncoder().encodeToString(DocCrypto.digest(digestAlg, files[r]!!)))
                append("</ofd:CheckValue></ofd:Reference>")
            }
            append("</ofd:References>")
            if (stamp != null) {
                append("<ofd:StampAnnot ID=\"1\" PageRef=\"").append(xmlAttr(stamp.pageId)).append("\" Boundary=\"").append(stamp.boundary).append("\"/>")
                append("<ofd:Seal><ofd:BaseLoc>/").append(xmlAttr(sealPath)).append("</ofd:BaseLoc></ofd:Seal>")
            }
            append("</ofd:SignedInfo>")
            append("<ofd:SignedValue>/").append(valuePath).append("</ofd:SignedValue></ofd:Signature>")
        }.encodeToByteArray()
        files[sigXmlPath] = signatureXml

        if (stamp != null) {
            files[valuePath] = OfdSeals.signature(stamp.seal, signer, signatureXml, "/$sigXmlPath", nowMillis / 1000, timestamper) { tokenOf(it) }
            return Zip.write(files.entries.map { it.key to it.value })
        }

        val chain = signer.certificateChain.ifEmpty { throw SigningException(ct("core_key_no_certificate")) }
        val signatureValue = signer.sign(signatureXml)
        val cert = Bc.holder(chain.first()) ?: throw SigningException(ct("core_key_no_certificate"))
        if (!GmSignedData.verifySignature(cert, signatureOid(signer.keyType), digestOid(sm2), signatureXml, signatureValue)) {
            throw SigningException(ct("core_jds_mismatch"))
        }
        val token = timestamper?.timestamp(signatureValue)?.let { tokenOf(it) }
        val signedData = signedData(chain, cert, signer.keyType, signatureValue, token)
        files[valuePath] = signedData

        // The result must verify as the inspector reads it.
        val check = GmSignedData.parse(signedData)
        val s = check.signers.single()
        if (check.verify(s, cert, signatureXml) != Check.PASS) throw SigningException(ct("core_jds_mismatch"))
        return Zip.write(files.entries.map { it.key to it.value })
    }

    /** The seal to stamp with and where: the page's ID and the box in millimetres. */
    private class Stamp(val seal: OfdSeals.Parsed, val pageId: String, val boundary: String)

    /**
     * The seal of [o] (the issued one, or one made for the signer's key) checked against the signer and the time,
     * and its box on the chosen page: [OfdSealOptions.widthMm] wide (else the seal's own size, else 40 mm), as high
     * as the picture's proportions say, at the preset position or the given page fractions, kept on the page.
     */
    private suspend fun stampOf(o: OfdSealOptions, doc: diw.wallet.core.document.ofd.OfdDocument, signer: DocumentSigner, now: Long): Stamp {
        if (signer.keyType != SignerKeyType.SM2) throw SigningException(ct("core_ofd_seal_sm2_only"))
        val cert = signer.certificateChain.firstOrNull() ?: throw SigningException(ct("core_key_no_certificate"))
        val pages = doc.pages
        val index = if (o.page < 0) pages.size + o.page else o.page
        val page = pages.getOrNull(index) ?: throw SigningException(ct("core_ofd_seal_no_page", index + 1))
        val box = page.box
        val seal = if (o.sealFile != null) {
            OfdSeals.parse(o.sealFile) ?: throw SigningException(ct("core_ofd_seal_bad"))
        } else {
            val picture = o.picture ?: throw SigningException(ct("core_ofd_seal_no_picture"))
            val (pw, ph) = OfdSeals.pngSize(picture) ?: throw SigningException(ct("core_ofd_seal_no_picture"))
            val w = (o.widthMm ?: DEFAULT_SEAL_MM).coerceIn(5.0, minOf(box.w, box.h))
            val name = o.name.ifBlank { Bc.holder(cert)?.subject?.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN)?.firstOrNull()?.first?.value?.toString().orEmpty() }
            OfdSeals.parse(OfdSeals.make(signer, name, o.personal, picture, w.toInt().coerceAtLeast(1), (w * ph / pw).toInt().coerceAtLeast(1), now))
                ?: throw SigningException(ct("core_ofd_seal_bad"))
        }
        if (!OfdSeals.allows(seal, cert)) throw SigningException(ct("core_ofd_seal_not_holder", seal.info.name))
        val from = seal.info.validFrom
        val to = seal.info.validTo
        if ((from != null && now < from) || (to != null && now > to)) {
            fun day(t: Long?) = t?.let { java.time.Instant.ofEpochSecond(it).atOffset(ZoneOffset.ofHours(8)).toLocalDate().toString() } ?: "-"
            throw SigningException(ct("core_ofd_seal_outside_validity", day(from), day(to)))
        }
        // The size: as asked, else the seal's own, else the default; the height keeps the picture's proportions.
        val own = seal.info.widthMm.takeIf { it > 0 && seal.info.heightMm > 0 }
        val ratio = when {
            own != null -> seal.info.heightMm / seal.info.widthMm
            else -> OfdSeals.pngSize(seal.info.picture)?.let { it.second.toDouble() / it.first } ?: 1.0
        }
        var w = o.widthMm ?: own ?: DEFAULT_SEAL_MM
        var h = w * ratio
        val fit = minOf(1.0, box.w / w, box.h / h)
        w *= fit; h *= fit
        val m = 0.04
        val (fx, fy) = o.at ?: when (o.position) {
            PdfSignatureAppearance.Position.TOP_LEFT -> m to m
            PdfSignatureAppearance.Position.TOP_RIGHT -> (1 - m - w / box.w) to m
            PdfSignatureAppearance.Position.BOTTOM_LEFT -> m to (1 - m - h / box.h)
            PdfSignatureAppearance.Position.BOTTOM_CENTER -> ((1 - w / box.w) / 2) to (1 - m - h / box.h)
            PdfSignatureAppearance.Position.BOTTOM_RIGHT -> (1 - m - w / box.w) to (1 - m - h / box.h)
        }
        val x = box.x + (fx * box.w).coerceIn(0.0, box.w - w)
        val y = box.y + (fy * box.h).coerceIn(0.0, box.h - h)
        fun mm(v: Double) = String.format(java.util.Locale.ROOT, "%.3f", v)
        return Stamp(seal, page.id, "${mm(x)} ${mm(y)} ${mm(w)} ${mm(h)}")
    }

    private fun signatureMethod(type: SignerKeyType) = when (type) {
        SignerKeyType.SM2 -> SM3_WITH_SM2
        SignerKeyType.RSA -> RSA_SHA256
        SignerKeyType.EC_P256 -> ECDSA_SHA256
    }

    /** The signature algorithm of the SignerInfo: sm2sign (GB/T 35276), else the PKCS#1 or X9.62 OIDs. */
    private fun signatureOid(type: SignerKeyType) = when (type) {
        SignerKeyType.SM2 -> SM2_SIGN
        SignerKeyType.RSA -> RSA_SHA256
        SignerKeyType.EC_P256 -> ECDSA_SHA256
    }

    private fun digestOid(sm2: Boolean) = if (sm2) SM3 else SHA256

    /** The token of a TimeStampResp or the token itself (a ContentInfo). */
    private fun tokenOf(der: ByteArray): ASN1Primitive {
        val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der))
        // A TimeStampResp is SEQUENCE { PKIStatusInfo SEQUENCE, token ContentInfo }; a token starts with its OID.
        return if (seq.getObjectAt(0) is ASN1ObjectIdentifier) seq else seq.getObjectAt(1).toASN1Primitive()
    }

    /**
     * SignedData with the signature over the detached content (no signed attributes, as GB/T 35275 permits):
     * national OIDs for SM2, PKCS#7 otherwise; the chain in certificates; the time stamp as an unsigned attribute.
     */
    private fun signedData(chain: List<ByteArray>, cert: org.bouncycastle.cert.X509CertificateHolder, type: SignerKeyType, signature: ByteArray, token: ASN1Primitive?): ByteArray {
        val sm2 = type == SignerKeyType.SM2
        val digestAlg = if (sm2) AlgorithmIdentifier(ASN1ObjectIdentifier(SM3)) else AlgorithmIdentifier(ASN1ObjectIdentifier(SHA256), DERNull.INSTANCE)
        val sigAlg = when (type) {
            SignerKeyType.RSA -> AlgorithmIdentifier(ASN1ObjectIdentifier(RSA_SHA256), DERNull.INSTANCE)
            else -> AlgorithmIdentifier(ASN1ObjectIdentifier(signatureOid(type)))
        }
        val signerInfo = ASN1EncodableVector().apply {
            add(ASN1Integer(1))
            add(IssuerAndSerialNumber(cert.issuer, cert.serialNumber))
            add(digestAlg)
            add(sigAlg)
            add(DEROctetString(signature))
            if (token != null) add(DERTaggedObject(false, 1, DERSet(Attribute(ASN1ObjectIdentifier(TIMESTAMP_TOKEN), DERSet(token)))))
        }
        val certs = ASN1EncodableVector().apply { chain.forEach { add(ASN1Primitive.fromByteArray(it)) } }
        val sd = ASN1EncodableVector().apply {
            add(ASN1Integer(1))
            add(DERSet(digestAlg))
            add(DERSequence(ASN1ObjectIdentifier(if (sm2) GmSignedData.GM_DATA else PKCS7_DATA)))
            add(DERTaggedObject(false, 0, DERSet(certs)))
            add(DERSet(DERSequence(signerInfo)))
        }
        val ci = ASN1EncodableVector().apply {
            add(ASN1ObjectIdentifier(if (sm2) GmSignedData.GM_SIGNED_DATA else PKCS7_SIGNED))
            add(DERTaggedObject(true, 0, DERSequence(sd)))
        }
        return DERSequence(ci).encoded
    }

    /** OFD.xml with a Signatures reference in its first DocBody (after DocRoot), using the file's own prefix. */
    private fun withSignaturesRef(ofd: String, path: String): String {
        val m = Regex("</(\\w+:)?DocRoot>").find(ofd) ?: throw SigningException(ct("core_ofd_sign_not_ofd"))
        val prefix = m.groupValues[1]
        return ofd.substring(0, m.range.last + 1) + "<${prefix}Signatures>$path</${prefix}Signatures>" + ofd.substring(m.range.last + 1)
    }

    /** Signatures.xml with the new entry: a new list, or the existing one with its MaxSignId raised. */
    private fun signatures(existing: String?, next: Int, id: String, baseLoc: String, type: String): String {
        if (existing == null) {
            return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ofd:Signatures xmlns:ofd=\"$NS\"><ofd:MaxSignId>$next</ofd:MaxSignId>" +
                "<ofd:Signature ID=\"$id\" Type=\"$type\" BaseLoc=\"$baseLoc\"/></ofd:Signatures>"
        }
        val close = Regex("</(\\w+:)?Signatures>\\s*$").find(existing) ?: throw SigningException(ct("core_ofd_sign_not_ofd"))
        val prefix = close.groupValues[1]
        var out = existing.substring(0, close.range.first) + "<${prefix}Signature ID=\"$id\" Type=\"$type\" BaseLoc=\"$baseLoc\"/>" + existing.substring(close.range.first)
        val maxRe = Regex("(<(?:\\w+:)?MaxSignId>)[^<]*(</(?:\\w+:)?MaxSignId>)")
        out = if (maxRe.containsMatchIn(out)) maxRe.replace(out) { it.groupValues[1] + next + it.groupValues[2] }
        else Regex("(<(?:\\w+:)?Signatures\\b[^>]*>)").replaceFirst(out, "$1<${prefix}MaxSignId>$next</${prefix}MaxSignId>")
        return out
    }

    private fun xmlAttr(s: String) = s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;")

    /** True when [spki] (SubjectPublicKeyInfo DER) is a key on the SM2 curve. */
    fun isSm2Key(spki: ByteArray): Boolean = runCatching {
        val info = SubjectPublicKeyInfo.getInstance(spki)
        info.algorithm.parameters?.toASN1Primitive() == ASN1ObjectIdentifier("1.2.156.10197.1.301")
    }.getOrDefault(false)
}
