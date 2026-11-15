package diw.wallet.core.zkpassport

import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * What an Android key attestation certificate states about its key and the app holding it, read the way this
 * project's key attestation circuits read it (native/circuits-zkpassport, keyattest.nr): the two security levels
 * (0 software, 1 TEE, 2 StrongBox) and the first package and signing certificate digest of the application id.
 */
class KeyAttestationInfo(
    val attestationLevel: Int,
    val keyLevel: Int,
    val packageName: String?,
    /** SHA-256 of the app's signing certificate, lowercase hex. */
    val signerDigest: String?,
) {
    /** The circuits take the key: attested and held in a TEE or StrongBox, with a signing certificate digest. */
    val provable: Boolean get() = attestationLevel in 1..2 && keyLevel in 1..2 && signerDigest != null

    companion object {
        private const val EXTENSION = "1.3.6.1.4.1.11129.2.1.17"
        private const val APPLICATION_ID = 709

        /** Reads the attestation extension of [certificate] (DER); null when it has none or it does not parse. */
        fun read(certificate: ByteArray): KeyAttestationInfo? = runCatching {
            val parsed = CertificateFactory.getInstance("X.509").generateCertificate(certificate.inputStream()) as X509Certificate
            val extension = parsed.getExtensionValue(EXTENSION) ?: return null
            val description = ASN1Sequence.getInstance(ASN1OctetString.getInstance(extension).octets)
            val software = ASN1Sequence.getInstance(description.getObjectAt(6))
            val application = software.asSequence().filterIsInstance<ASN1TaggedObject>().firstOrNull { it.tagNo == APPLICATION_ID }
                ?.let { ASN1Sequence.getInstance(ASN1OctetString.getInstance(it.baseObject).octets) }
            val packageName = application?.let { ASN1Set.getInstance(it.getObjectAt(0)) }?.firstOrNull()
                ?.let { ASN1OctetString.getInstance(ASN1Sequence.getInstance(it).getObjectAt(0)).octets.decodeToString() }
            val digest = application?.let { ASN1Set.getInstance(it.getObjectAt(1)) }?.firstOrNull()
                ?.let { ASN1OctetString.getInstance(it).octets }?.takeIf { it.size == 32 }
            KeyAttestationInfo(
                ASN1Enumerated.getInstance(description.getObjectAt(1)).value.toInt(),
                ASN1Enumerated.getInstance(description.getObjectAt(3)).value.toInt(),
                packageName,
                digest?.joinToString("") { "%02x".format(it) },
            )
        }.getOrNull()
    }
}
