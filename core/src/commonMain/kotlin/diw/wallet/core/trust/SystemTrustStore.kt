package diw.wallet.core.trust

import org.multipaz.crypto.X509Cert
import kotlin.time.Instant

/**
 * The platform's own certificate store: on Android the system CAs (and CAs the user installed in the system
 * settings), on desktop the JDK store together with the Windows or macOS store. These are web PKI authorities: a
 * chain to them proves that a public CA verified a domain or organisation, not that the party is on an official list.
 */
expect object SystemTrustStore {
    /** The CA certificates of the store; empty where the platform has none. */
    fun anchors(): List<X509Cert>

    /** The store anchor [chain] validates to at [at] (see [Pkix.anchorOf]), or null. */
    fun anchorOf(chain: List<X509Cert>, at: Instant): X509Cert?
}

/**
 * RFC 5280 path validation (PKIX) for any key type. Multipaz's trust manager only handles EC keys; RSA chains, such
 * as the Taiwan GPKI and most of the web PKI, are validated here.
 */
expect object Pkix {
    /**
     * The anchor among [anchors] that [chain] (leaf first) validates to at [at], or null. A chain that ends with an
     * anchor may include it; a chain that is an anchor itself matches it. Revocation is not checked.
     */
    fun anchorOf(chain: List<X509Cert>, anchors: List<X509Cert>, at: Instant): X509Cert?
}
