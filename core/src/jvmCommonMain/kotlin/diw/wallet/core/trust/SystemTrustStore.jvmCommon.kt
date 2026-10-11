package diw.wallet.core.trust

import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import java.security.KeyStore
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

    private fun jca(c: X509Cert): X509Certificate = factory.generateCertificate(c.encoded.toByteArray().inputStream()) as X509Certificate

    actual fun anchorOf(chain: List<X509Cert>, anchors: List<X509Cert>, at: Instant): X509Cert? {
        if (chain.isEmpty() || anchors.isEmpty()) return null
        val first = chain.first()
        if (first in anchors) return first.takeIf { at in it.validityNotBefore..it.validityNotAfter }
        // The path ends below its anchor: certificates of the chain that are anchors themselves are left out.
        val path = chain.takeWhile { it !in anchors }.map { jca(it) }
        val params = PKIXParameters(anchors.map { TrustAnchor(jca(it), null) }.toSet()).apply {
            isRevocationEnabled = false
            date = Date(at.toEpochMilliseconds())
        }
        val result = runCatching {
            CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(path), params) as PKIXCertPathValidatorResult
        }.getOrNull() ?: return null
        return X509Cert(ByteString(result.trustAnchor.trustedCert.encoded))
    }
}
