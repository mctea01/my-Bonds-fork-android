package diw.wallet.core.document

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber
import org.bouncycastle.cert.X509CertificateHolder
import java.security.Signature

/**
 * SignedData under the Chinese national OIDs (GM/T 0010, used by GB/T 35275 and OFD digital signatures):
 * 1.2.156.10197.6.1.4.2.2 instead of 1.2.840.113549.1.7.2, SM2 with SM3, with or without signed attributes.
 * BouncyCastle's CMS classes do not map these OIDs, so the structure is read directly.
 */
internal class GmSignedData private constructor(
    val certificates: List<X509CertificateHolder>,
    val signers: List<Signer>,
    val content: ByteArray?,
) {
    class Signer(
        val issuerAndSerial: IssuerAndSerialNumber?,
        val digestOid: String,
        val signatureOid: String,
        val signedAttributes: ASN1Set?,
        val signature: ByteArray,
    )

    /** Verifies [signer] over [data] (the detached or encapsulated content) with [cert]. */
    fun verify(signer: Signer, cert: X509CertificateHolder, data: ByteArray): Check {
        val attrs = signer.signedAttributes
        val toVerify = if (attrs != null) {
            val md = attrs.firstOrNull { Attribute.getInstance(it).attrType == CMSAttributes.messageDigest }
                ?.let { ASN1OctetString.getInstance(Attribute.getInstance(it).attrValues.getObjectAt(0)).octets }
                ?: return Check.FAIL
            val expected = DocCrypto.digest(AlgorithmNames.jcaDigest(signer.digestOid), data)
            if (!md.contentEquals(expected)) return Check.FAIL
            attrs.encoded
        } else data
        return if (verifySignature(cert, signer.signatureOid, signer.digestOid, toVerify, signer.signature)) Check.PASS else Check.FAIL
    }

    fun signerCertificate(signer: Signer): X509CertificateHolder? = certificates.firstOrNull { c ->
        signer.issuerAndSerial == null || (c.issuer == signer.issuerAndSerial.name && c.serialNumber == signer.issuerAndSerial.serialNumber.value)
    }

    companion object {
        const val GM_SIGNED_DATA = "1.2.156.10197.6.1.4.2.2"
        const val GM_DATA = "1.2.156.10197.6.1.4.2.1"

        fun isGm(der: ByteArray): Boolean = runCatching {
            ASN1ObjectIdentifier.getInstance(ASN1Sequence.getInstance(Bc.parse(der)).getObjectAt(0)).id == GM_SIGNED_DATA
        }.getOrDefault(false)

        /** Parses a ContentInfo holding SignedData (GM or PKCS#7 OIDs). */
        fun parse(der: ByteArray): GmSignedData {
            val ci = ASN1Sequence.getInstance(Bc.parse(der))
            val sd = ASN1Sequence.getInstance((ci.getObjectAt(1) as ASN1TaggedObject).baseObject.toASN1Primitive())
            var certs = emptyList<X509CertificateHolder>()
            var signerInfos: ASN1Set? = null
            var content: ByteArray? = null
            for (e in sd) {
                when {
                    e is ASN1TaggedObject && e.tagNo == 0 -> certs = ASN1Set.getInstance(e, false).mapNotNull { Bc.holder(it.toASN1Primitive().encoded) }
                    e is ASN1TaggedObject -> {}
                    e is ASN1Sequence && e.size() >= 1 && e.getObjectAt(0) is ASN1ObjectIdentifier -> {
                        content = (e.takeIf { it.size() > 1 }?.getObjectAt(1) as? ASN1TaggedObject)?.let { t ->
                            runCatching { ASN1OctetString.getInstance(t.baseObject.toASN1Primitive()).octets }.getOrNull()
                        }
                    }
                    e is ASN1Set -> signerInfos = e
                }
            }
            val signers = signerInfos?.map { parseSigner(ASN1Sequence.getInstance(it)) }.orEmpty()
            return GmSignedData(certs, signers, content)
        }

        private fun parseSigner(s: ASN1Sequence): Signer {
            var i = 1
            val sid = runCatching { IssuerAndSerialNumber.getInstance(s.getObjectAt(i)) }.getOrNull()
            i++
            val digestOid = algOid(s.getObjectAt(i++))
            var attrs: ASN1Set? = null
            val next = s.getObjectAt(i)
            if (next is ASN1TaggedObject && next.tagNo == 0) {
                attrs = ASN1Set.getInstance(next, false)
                i++
            }
            val sigOid = algOid(s.getObjectAt(i++))
            val value = ASN1OctetString.getInstance(s.getObjectAt(i)).octets
            return Signer(sid, digestOid, sigOid, attrs, value)
        }

        private fun algOid(e: ASN1Encodable): String = ASN1ObjectIdentifier.getInstance(ASN1Sequence.getInstance(e).getObjectAt(0)).id

        /** Verifies a raw signature (SM2 with SM3, RSA, ECDSA) over [data] with [cert]. */
        fun verifySignature(cert: X509CertificateHolder, signatureOid: String, digestOid: String?, data: ByteArray, signature: ByteArray): Boolean = runCatching {
            val key = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(Bc.provider).getCertificate(cert).publicKey
            val digest = digestOid?.let { AlgorithmNames.digest(it).replace("-", "") } ?: "SHA256"
            val name = when (signatureOid) {
                "1.2.156.10197.1.501", "1.2.156.10197.1.301.1", "1.2.156.10197.1.301" -> "SM3withSM2"
                "1.2.840.113549.1.1.11" -> "SHA256withRSA"
                "1.2.840.113549.1.1.12" -> "SHA384withRSA"
                "1.2.840.113549.1.1.13" -> "SHA512withRSA"
                "1.2.840.113549.1.1.5" -> "SHA1withRSA"
                "1.2.840.113549.1.1.1" -> digest + "withRSA"
                "1.2.840.10045.4.3.2" -> "SHA256withECDSA"
                "1.2.840.10045.4.3.3" -> "SHA384withECDSA"
                "1.2.840.10045.4.3.4" -> "SHA512withECDSA"
                "1.2.840.10045.2.1" -> digest + "withECDSA"
                else -> return false
            }
            val sig = Signature.getInstance(name, Bc.provider)
            sig.initVerify(key)
            sig.update(data)
            sig.verify(signature)
        }.getOrDefault(false)
    }
}
