package diw.wallet.core.trust

import diw.wallet.core.x509.displaySubject
import org.multipaz.asn1.OID
import org.multipaz.crypto.X509Cert
import kotlin.time.Instant

/**
 * Public certification authorities the wallet accepts as T3 (a public CA verified a domain or organisation, not an
 * official list): the platform's certificate store with the roots of common services built in beside it, and the
 * built-in mainland China CAs, each group switched on by the user.
 */
object PublicRoots {
    /** The anchor a chain led to, and how it is shown. */
    class Found(val certificate: X509Cert, val label: String, val source: String, val region: String?)

    /**
     * The public root [chain] (leaf first) validates to at [at]: the mainland China CAs first when [mainlandChina]
     * is on, so that their chains are named as such, then the platform store and the built-in service roots when
     * [platform] is on, and for a time-stamp authority ([timestamping]) the built-in time stamping roots.
     */
    fun anchorOf(chain: List<X509Cert>, at: Instant, platform: Boolean, mainlandChina: Boolean, timestamping: Boolean = false): Found? {
        if (mainlandChina) {
            val roots = BuiltInPublicRoots.mainlandChina.validAt(at)
            Pkix.anchorOf(chain, roots.map { it.certificate }, at)?.let { a ->
                val r = roots.first { it.certificate == a }
                return Found(a, "中國大陸憑證機構：${r.name}", BuiltInPublicRoots.MAINLAND_SOURCE, "CN")
            }
        }
        if (platform) {
            SystemTrustStore.anchorOf(chain, at)?.let { a -> return Found(a, "系統憑證庫：" + commonName(a), "system", null) }
            val services = BuiltInPublicRoots.services.validAt(at)
            Pkix.anchorOf(chain, services.map { it.certificate }, at)?.let { a ->
                val r = services.first { it.certificate == a }
                return Found(a, "常用服務憑證機構：${r.name}", BuiltInPublicRoots.SERVICE_SOURCE, null)
            }
            if (timestamping) {
                val tsa = BuiltInPublicRoots.timestamping.validAt(at)
                Pkix.anchorOf(chain, tsa.map { it.certificate }, at)?.let { a ->
                    val r = tsa.first { it.certificate == a }
                    return Found(a, "時間戳記憑證機構：${r.name}", BuiltInPublicRoots.TIMESTAMPING_SOURCE, null)
                }
            }
        }
        return null
    }

    /** A built-in root that has expired (or is not yet valid) is no longer an anchor, until a release replaces it. */
    private fun List<BuiltInPublicRoots.Root>.validAt(at: Instant) =
        filter { it.certificate.validityNotBefore <= at && at <= it.certificate.validityNotAfter }

    private fun commonName(c: X509Cert): String = c.subject.components[OID.COMMON_NAME.oid]?.value ?: c.displaySubject()
}
