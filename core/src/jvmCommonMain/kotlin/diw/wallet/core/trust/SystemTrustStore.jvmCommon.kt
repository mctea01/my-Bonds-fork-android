package diw.wallet.core.trust

import kotlinx.io.bytestring.ByteString
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.multipaz.crypto.X509Cert
import java.security.KeyStore
import java.security.Provider
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.time.Instant

actual object SystemTrustStore {
    /**
     * The default trust manager's issuers (Android: AndroidCAStore; JVM: cacerts), plus the operating system's root
     * store on Windows (Windows-ROOT) and macOS (KeychainStore), which the JDK does not read by default.
     */
    private val roots: List<X509Cert> by lazy {
        val fromDefault = runCatching {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            tmf.trustManagers.filterIsInstance<X509TrustManager>().flatMap { it.acceptedIssuers.toList() }
        }.getOrDefault(emptyList())
        val os = System.getProperty("os.name").orEmpty().lowercase()
        val osStore = when {
            "windows" in os -> "Windows-ROOT"
            "mac" in os -> "KeychainStore"
            else -> null
        }
        val fromOs = osStore?.let { type ->
            runCatching {
                val ks = KeyStore.getInstance(type)
                ks.load(null, null)
                ks.aliases().toList().mapNotNull { ks.getCertificate(it) as? X509Certificate }
            }.getOrDefault(emptyList())
        }.orEmpty()
        (fromDefault + fromOs).map { X509Cert(ByteString(it.encoded)) }.distinct()
    }

    actual fun anchors(): List<X509Cert> = roots

    actual fun anchorOf(chain: List<X509Cert>, at: Instant): X509Cert? = Pkix.anchorOf(chain, roots, at)
}

actual object Pkix {
    private val factory: CertificateFactory by lazy { CertificateFactory.getInstance("X.509") }

    /**
     * BouncyCastle, for the Chinese national algorithms (SM2 keys, SM3withSM2 signatures) that the platform providers
     * lack. It is used as an instance and never registered, so it does not change any other algorithm lookup.
     */
    private val bc: Provider by lazy { BouncyCastleProvider() }
    private val bcFactory: CertificateFactory by lazy { CertificateFactory.getInstance("X.509", bc) }

    actual fun anchorOf(chain: List<X509Cert>, anchors: List<X509Cert>, at: Instant): X509Cert? {
        if (chain.isEmpty() || anchors.isEmpty()) return null
        val first = chain.first()
        if (first in anchors) return first.takeIf { at in it.validityNotBefore..it.validityNotAfter }
        // The path ends below its anchor: certificates of the chain that are anchors themselves are left out.
        val path = chain.takeWhile { it !in anchors }
        // Shorter paths too: a bundle may carry a cross-signed copy of a root (DigiCert Trusted Root G4 signed by
        // Assured ID Root CA), whose own issuer is not an anchor while the self-signed root with the same key is.
        val national = (path + anchors).any { isNational(it) }
        for (n in path.size downTo 1) {
            val p = path.subList(0, n)
            // The platform providers first; SM2 chains, or anchors that are SM2 roots, need BouncyCastle.
            validate(p, anchors, at, null)?.let { return it }
            if (national) validate(p, anchors, at, bc)?.let { return it }
        }
        return null
    }

    private fun validate(path: List<X509Cert>, anchors: List<X509Cert>, at: Instant, provider: Provider?): X509Cert? {
        val f = if (provider == null) factory else bcFactory
        fun jca(c: X509Cert) = f.generateCertificate(c.encoded.toByteArray().inputStream()) as X509Certificate
        return runCatching {
            val params = PKIXParameters(anchors.map { TrustAnchor(jca(it), null) }.toSet()).apply {
                isRevocationEnabled = false
                date = Date(at.toEpochMilliseconds())
            }
            val validator = if (provider == null) CertPathValidator.getInstance("PKIX") else CertPathValidator.getInstance("PKIX", provider)
            val result = validator.validate(f.generateCertPath(path.map { jca(it) }), params) as PKIXCertPathValidatorResult
            X509Cert(ByteString(result.trustAnchor.trustedCert.encoded))
        }.getOrNull()
    }

    /** Signed with SM3withSM2 or holding an SM2 key: the OIDs under 1.2.156.10197 (GM/T 0006). */
    private fun isNational(c: X509Cert): Boolean =
        runCatching { c.signatureAlgorithmOid.startsWith(SM_ARC) }.getOrDefault(false) || containsOid(c.encoded.toByteArray(), SM2_CURVE_DER)

    private fun containsOid(der: ByteArray, oid: ByteArray): Boolean {
        outer@ for (i in 0..der.size - oid.size) {
            for (j in oid.indices) if (der[i + j] != oid[j]) continue@outer
            return true
        }
        return false
    }

    private const val SM_ARC = "1.2.156.10197."
    /** DER of OID 1.2.156.10197.1.301 (the SM2 curve). */
    private val SM2_CURVE_DER = byteArrayOf(0x06, 0x08, 0x2A, 0x81.toByte(), 0x1C, 0xCF.toByte(), 0x55, 0x01, 0x82.toByte(), 0x2D)
}
