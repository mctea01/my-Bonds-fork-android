package diw.wallet.core.document.sign

import diw.wallet.core.document.Bc
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.GmSignedData
import diw.wallet.core.document.Zip
import diw.wallet.core.document.ofd.OfdPackage
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
 * OFD digital signatures (GB/T 33190-2016 section 18, Signature Type "Sign"). The package keeps every file it has;
 * the first signature adds a Signatures.xml (and its reference in OFD.xml), each signature adds Sign_N/ with
 * Signature.xml and SignedValue.dat. References cover every file of the package except Signatures.xml, which later
 * signatures extend, so earlier signatures stay valid. The signed data is the Signature.xml file itself.
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
    private val TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")

    suspend fun sign(ofd: ByteArray, signer: DocumentSigner, timestamper: Timestamper?, nowMillis: Long = System.currentTimeMillis()): ByteArray {
        val files = LinkedHashMap(Zip.read(ofd))
        val pkg = OfdPackage.read(files) ?: throw SigningException(ct("core_ofd_sign_not_ofd"))
        val doc = pkg.documents.firstOrNull() ?: throw SigningException(ct("core_ofd_sign_no_document"))
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
        files[sigsPath] = signatures(existing, next, id, "/$sigXmlPath").encodeToByteArray()

        // Every file is protected except the signature list and the new signature's own files.
        val sm2 = signer.keyType == SignerKeyType.SM2
        val digestAlg = if (sm2) "SM3" else "SHA-256"
        val refs = files.keys.filter { it != sigsPath && it != sigXmlPath && it != valuePath }
        val time = ZonedDateTime.ofInstant(java.time.Instant.ofEpochMilli(nowMillis), ZoneOffset.UTC).format(TIME)
        val signatureXml = buildString {
            append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
            append("<ofd:Signature xmlns:ofd=\"$NS\"><ofd:SignedInfo>")
            append("<ofd:Provider ProviderName=\"DIW MY WALLET\" Company=\"DIW MY WALLET\" Version=\"1.0\"/>")
            append("<ofd:SignatureMethod>").append(signatureMethod(signer.keyType)).append("</ofd:SignatureMethod>")
            append("<ofd:SignatureDateTime>").append(time).append("</ofd:SignatureDateTime>")
            append("<ofd:References CheckMethod=\"").append(if (sm2) SM3 else SHA256).append("\">")
            for (r in refs) {
                append("<ofd:Reference FileRef=\"/").append(xmlAttr(r)).append("\"><ofd:CheckValue>")
                append(Base64.getEncoder().encodeToString(DocCrypto.digest(digestAlg, files[r]!!)))
                append("</ofd:CheckValue></ofd:Reference>")
            }
            append("</ofd:References></ofd:SignedInfo>")
            append("<ofd:SignedValue>/").append(valuePath).append("</ofd:SignedValue></ofd:Signature>")
        }.encodeToByteArray()
        files[sigXmlPath] = signatureXml

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
    private fun signatures(existing: String?, next: Int, id: String, baseLoc: String): String {
        if (existing == null) {
            return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ofd:Signatures xmlns:ofd=\"$NS\"><ofd:MaxSignId>$next</ofd:MaxSignId>" +
                "<ofd:Signature ID=\"$id\" Type=\"Sign\" BaseLoc=\"$baseLoc\"/></ofd:Signatures>"
        }
        val close = Regex("</(\\w+:)?Signatures>\\s*$").find(existing) ?: throw SigningException(ct("core_ofd_sign_not_ofd"))
        val prefix = close.groupValues[1]
        var out = existing.substring(0, close.range.first) + "<${prefix}Signature ID=\"$id\" Type=\"Sign\" BaseLoc=\"$baseLoc\"/>" + existing.substring(close.range.first)
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
