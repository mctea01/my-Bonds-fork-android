package diw.wallet.core.document

import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AccessDescription
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.CRLReason
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.cert.ocsp.RevokedStatus
import org.bouncycastle.cert.ocsp.UnknownStatus
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.multipaz.crypto.X509Cert
import java.security.Provider
import java.util.Base64
import java.util.Date
import kotlin.time.Instant

/** BouncyCastle as an instance (never registered), for every algorithm including SM2 and SM3. */
internal object Bc {
    val provider: Provider by lazy { BouncyCastleProvider() }

    fun contentVerifier(holder: X509CertificateHolder) = JcaContentVerifierProviderBuilder().setProvider(provider).build(holder)
    fun digestProvider() = JcaDigestCalculatorProviderBuilder().setProvider(provider).build()

    fun parse(der: ByteArray): ASN1Primitive = ASN1InputStream(der).use { it.readObject() }

    fun holder(der: ByteArray): X509CertificateHolder? = runCatching { X509CertificateHolder(der) }.getOrNull()

    /** The http(s) caIssuers URLs of [h]'s Authority Information Access extension. */
    fun caIssuers(h: X509CertificateHolder): List<String> = runCatching {
        val aia = AuthorityInformationAccess.fromExtensions(h.extensions) ?: return emptyList()
        aia.accessDescriptions.filter { it.accessMethod == AccessDescription.id_ad_caIssuers }
            .mapNotNull { d -> d.accessLocation.takeIf { it.tagNo == GeneralName.uniformResourceIdentifier }?.name?.toString() }
            .filter { it.startsWith("http://") || it.startsWith("https://") }
    }.getOrDefault(emptyList())

    private fun rdn(h: X509CertificateHolder, oid: ASN1ObjectIdentifier): String? =
        h.subject.getRDNs(oid).firstOrNull()?.first?.value?.toString()

    fun cn(h: X509CertificateHolder): String? = rdn(h, BCStyle.CN)
    fun org(h: X509CertificateHolder): String? = rdn(h, BCStyle.O)
    fun country(h: X509CertificateHolder): String? = rdn(h, BCStyle.C)

    /** DER certificates of a certificate, a PKCS#7 certs-only bundle, or PEM text. */
    fun certificates(data: ByteArray): List<ByteArray> {
        val text = runCatching { data.decodeToString() }.getOrNull()
        if (text != null && "-----BEGIN CERTIFICATE-----" in text) {
            return Regex("-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\\s]+)-----END CERTIFICATE-----").findAll(text)
                .mapNotNull { runCatching { Base64.getMimeDecoder().decode(it.groupValues[1]) }.getOrNull() }.toList()
        }
        holder(data)?.let { return listOf(it.encoded) }
        return runCatching {
            val ci = ContentInfo.getInstance(parse(data))
            val sd = SignedData.getInstance(ci.content)
            sd.certificates?.map { it.toASN1Primitive().encoded }.orEmpty()
        }.getOrDefault(emptyList())
    }
}

/** Where a certificate came from, the chain built from it, and the evaluation the inspector shows. */
internal class PkiSupport(private val trust: DocumentTrustSource) {
    private val fetched = HashMap<String, List<ByteArray>>()
    private var known: List<X509CertificateHolder>? = null

    private suspend fun known(): List<X509CertificateHolder> = known
        ?: runCatching { trust.knownCertificates() }.getOrDefault(emptyList()).mapNotNull { Bc.holder(it) }.also { known = it }

    fun certInfo(h: X509CertificateHolder): CertInfo = CertInfo(
        subject = h.subject.toString(),
        issuer = h.issuer.toString(),
        commonName = cn(h.subject),
        serialHex = h.serialNumber.toString(16),
        notBefore = h.notBefore.time / 1000,
        notAfter = h.notAfter.time / 1000,
        der = Base64.getEncoder().encodeToString(h.encoded),
        publicKey = keyDescription(h),
    )

    fun cn(name: X500Name): String? = name.getRDNs(BCStyle.CN).firstOrNull()?.first?.value?.toString()

    fun keyDescription(h: X509CertificateHolder): String {
        val alg = h.subjectPublicKeyInfo.algorithm
        return when (alg.algorithm.id) {
            "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10" -> "RSA " + rsaBits(h) + " 位元"
            "1.2.840.10045.2.1" -> when (alg.parameters?.toString()) {
                "1.2.840.10045.3.1.7" -> "ECDSA P-256"
                "1.3.132.0.34" -> "ECDSA P-384"
                "1.3.132.0.35" -> "ECDSA P-521"
                "1.2.156.10197.1.301" -> "SM2"
                else -> "ECDSA"
            }
            "1.2.156.10197.1.301" -> "SM2"
            "1.3.101.112" -> "Ed25519"
            else -> alg.algorithm.id
        }
    }

    fun rsaBits(h: X509CertificateHolder): Int = runCatching {
        org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(h.subjectPublicKeyInfo.parsePublicKey()).modulus.bitLength()
    }.getOrDefault(0)

    fun issued(child: X509CertificateHolder, issuer: X509CertificateHolder): Boolean =
        child.issuer == issuer.subject && runCatching { child.isSignatureValid(Bc.contentVerifier(issuer)) }.getOrDefault(false)

    fun selfSigned(h: X509CertificateHolder) = h.subject == h.issuer && issued(h, h)

    /**
     * The chain from [leaf] towards a root: issuers from [pool] first, then the known intermediates and importable
     * roots of the trust source, then AIA caIssuers links (at most three downloads per chain).
     */
    suspend fun buildChain(leaf: X509CertificateHolder, pool: List<X509CertificateHolder>): List<X509CertificateHolder> {
        val known = known()
        val chain = arrayListOf(leaf)
        var downloads = 0
        while (chain.size < 10) {
            val cur = chain.last()
            if (selfSigned(cur)) break
            var next = pool.firstOrNull { it != cur && it !in chain && issued(cur, it) }
                ?: known.firstOrNull { it != cur && it !in chain && issued(cur, it) }
            if (next == null && downloads < 3) {
                for (url in caIssuers(cur)) {
                    downloads++
                    val certs = fetched.getOrPut(url) { runCatching { trust.fetchIssuerCertificates(url) }.getOrDefault(emptyList()).flatMap { Bc.certificates(it) } }
                    next = certs.mapNotNull { Bc.holder(it) }.firstOrNull { it !in chain && issued(cur, it) }
                    if (next != null) break
                }
            }
            if (next == null) break
            chain.add(next)
        }
        return chain
    }

    fun caIssuers(h: X509CertificateHolder): List<String> = Bc.caIssuers(h)

    suspend fun decide(role: TrustRole, chain: List<X509CertificateHolder>, at: Instant): TrustDecision =
        trust.decide(role, chain.map { X509Cert(ByteString(it.encoded)) }, at)

    /** Embedded revocation data for [cert] (issued by [issuer]): revoked (with when) or good, from OCSP or a CRL. */
    fun revocation(cert: X509CertificateHolder, issuer: X509CertificateHolder?, ocsps: List<ByteArray>, crls: List<ByteArray>): Revocation? {
        if (issuer == null) return null
        for (raw in ocsps) {
            val basic = runCatching {
                val resp = runCatching { OCSPResp(raw) }.getOrNull()
                if (resp != null) resp.responseObject as? BasicOCSPResp else BasicOCSPResp(org.bouncycastle.asn1.ocsp.BasicOCSPResponse.getInstance(Bc.parse(raw)))
            }.getOrNull() ?: continue
            val id = runCatching { CertificateID(Bc.digestProvider().get(CertificateID.HASH_SHA1), issuer, cert.serialNumber) }.getOrNull() ?: continue
            val single = basic.responses.firstOrNull { it.certID.serialNumber == cert.serialNumber && runCatching { it.certID.matchesIssuer(issuer, Bc.digestProvider()) }.getOrDefault(false) }
                ?: basic.responses.firstOrNull { it.certID == id } ?: continue
            // The response must be signed by the issuer or by a responder it delegated to.
            val signers = listOf(issuer) + basic.certs.filter { issued(it, issuer) }
            if (signers.none { s -> runCatching { basic.isSignatureValid(Bc.contentVerifier(s)) }.getOrDefault(false) }) continue
            return when (val st = single.certStatus) {
                null -> Revocation(false, null, "OCSP", basic.producedAt.time / 1000)
                is RevokedStatus -> Revocation(true, st.revocationTime.time / 1000, "OCSP", basic.producedAt.time / 1000, reason(st))
                is UnknownStatus -> null
                else -> null
            }
        }
        for (raw in crls) {
            val crl = runCatching { X509CRLHolder(raw) }.getOrNull() ?: continue
            if (crl.issuer != issuer.subject) continue
            if (!runCatching { crl.isSignatureValid(Bc.contentVerifier(issuer)) }.getOrDefault(false)) continue
            val entry = crl.getRevokedCertificate(cert.serialNumber)
            return if (entry != null) Revocation(true, entry.revocationDate.time / 1000, "CRL", crl.thisUpdate.time / 1000)
            else Revocation(false, null, "CRL", crl.thisUpdate.time / 1000)
        }
        return null
    }

    private fun reason(st: RevokedStatus): String? = runCatching {
        if (!st.hasRevocationReason()) null else when (st.revocationReason) {
            CRLReason.keyCompromise -> "金鑰洩漏"
            CRLReason.cACompromise -> "憑證機構金鑰洩漏"
            CRLReason.affiliationChanged -> "隸屬變更"
            CRLReason.superseded -> "已被取代"
            CRLReason.cessationOfOperation -> "停止使用"
            CRLReason.certificateHold -> "暫時停用"
            else -> null
        }
    }.getOrNull()

    /** OCSP responses and CRLs carried by a CMS SignedData (crls and otherRevocationInfo). */
    fun cmsRevocation(sd: org.bouncycastle.cms.CMSSignedData): Pair<List<ByteArray>, List<ByteArray>> {
        val crls = runCatching { sd.crLs.getMatches(null).map { (it as X509CRLHolder).encoded } }.getOrDefault(emptyList())
        val ocsps = runCatching {
            sd.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_response).getMatches(null).map { (it as org.bouncycastle.asn1.ASN1Encodable).toASN1Primitive().encoded }
        }.getOrDefault(emptyList())
        return ocsps to crls
    }

    /**
     * Adobe revocationInfoArchival (1.2.840.113583.1.1.8), a signed attribute holding CRLs [0] and OCSP responses
     * [1] that the signer collected at signing time.
     */
    fun adobeRevocation(value: org.bouncycastle.asn1.ASN1Encodable): Pair<List<ByteArray>, List<ByteArray>> {
        val ocsps = ArrayList<ByteArray>()
        val crls = ArrayList<ByteArray>()
        runCatching {
            val seq = ASN1Sequence.getInstance(value)
            for (e in seq) {
                val t = e as? ASN1TaggedObject ?: continue
                val inner = ASN1Sequence.getInstance(t.baseObject.toASN1Primitive())
                when (t.tagNo) {
                    0 -> inner.forEach { crls.add(it.toASN1Primitive().encoded) }
                    1 -> inner.forEach { ocsps.add(it.toASN1Primitive().encoded) }
                }
            }
        }
        return ocsps to crls
    }

    class Revocation(val revoked: Boolean, val at: Long?, val source: String, val producedAt: Long, val reason: String? = null)

    companion object {
        val ADOBE_REVOCATION = ASN1ObjectIdentifier("1.2.840.113583.1.1.8")

        fun validAt(h: X509CertificateHolder, at: Instant): Boolean = h.isValidOn(Date(at.toEpochMilliseconds()))

        fun summary(d: TrustDecision): TrustSummary = TrustSummary.of(d)

        /** A chain that reaches no enabled anchor is reported with the UNKNOWN_ANCHOR label (tier T3, unidentified). */
        fun unknownAnchor(d: TrustDecision) = TrustLabel.UNKNOWN_ANCHOR in d.labels || d.tier == TrustTier.T4
    }
}

/** Display names of signature and digest algorithms by OID. */
internal object AlgorithmNames {
    fun digest(oid: String): String = when (oid) {
        "1.3.14.3.2.26" -> "SHA-1"
        "2.16.840.1.101.3.4.2.1" -> "SHA-256"
        "2.16.840.1.101.3.4.2.2" -> "SHA-384"
        "2.16.840.1.101.3.4.2.3" -> "SHA-512"
        "2.16.840.1.101.3.4.2.4" -> "SHA-224"
        "1.2.840.113549.2.5" -> "MD5"
        "1.2.156.10197.1.401" -> "SM3"
        else -> oid
    }

    fun signature(encOid: String, digestOid: String): String {
        val d = digest(digestOid)
        return when (encOid) {
            "1.2.840.113549.1.1.1" -> "RSA $d"
            "1.2.840.113549.1.1.5" -> "RSA SHA-1"
            "1.2.840.113549.1.1.11" -> "RSA SHA-256"
            "1.2.840.113549.1.1.12" -> "RSA SHA-384"
            "1.2.840.113549.1.1.13" -> "RSA SHA-512"
            "1.2.840.113549.1.1.10" -> "RSA-PSS $d"
            "1.2.840.10045.2.1" -> "ECDSA $d"
            "1.2.840.10045.4.3.2" -> "ECDSA SHA-256"
            "1.2.840.10045.4.3.3" -> "ECDSA SHA-384"
            "1.2.840.10045.4.3.4" -> "ECDSA SHA-512"
            "1.2.156.10197.1.501" -> "SM2 SM3"
            "1.2.156.10197.1.301.1", "1.2.156.10197.1.301" -> "SM2 $d"
            else -> "$encOid $d"
        }
    }

    /** Weak algorithms the report warns about. */
    fun weak(digestOid: String): Boolean = digest(digestOid) in setOf("SHA-1", "MD5")

    fun jcaDigest(oid: String): String = when (val d = digest(oid)) {
        "SM3" -> "SM3"
        else -> d
    }
}

internal fun X509CertificateHolder.toCertificate(): Certificate = toASN1Structure()
