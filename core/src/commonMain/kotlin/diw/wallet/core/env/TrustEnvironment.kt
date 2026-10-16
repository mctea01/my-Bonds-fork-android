package diw.wallet.core.env

/**
 * PKI environment partition. Every trust anchor, credential and verification result carries one of these.
 * PRODUCTION anchors are official lists and production roots; TEST anchors are sandboxes, conformance suites
 * and reference implementations; USER anchors were imported by the user.
 */
enum class TrustEnvironment(val id: String) {
    PRODUCTION("production"),
    TEST("test"),
    USER("user"),

    /**
     * Public CAs: the platform's own certificate store (Android system CAs, the JDK and OS stores on desktop), the
     * roots of common services built into the wallet, and the built-in mainland China CAs.
     */
    SYSTEM("system");

    companion object {
        fun fromId(id: String?): TrustEnvironment? = entries.firstOrNull { it.id == id }
    }
}

/**
 * Runtime environment policy. Test anchors are always consulted: a match is marked TEST (T3, never official), so
 * trusting them needs no switch. [testEnvironmentEnabled] only enables the custom test server addresses (the DIW
 * test server, a TWDIW front end other than production, a remote wallet provider); [allowInsecureLoopbackHttp]
 * permits http://localhost style endpoints and is only honoured together with it.
 */
data class EnvironmentPolicy(
    val testEnvironmentEnabled: Boolean = false,
    val allowInsecureLoopbackHttp: Boolean = false,
    val userAnchorsEnabled: Boolean = true,
    /** Accept chains to the platform's certificate store, as T2 (a trust root: the public CA verified a domain, not an official list). */
    val systemStoreEnabled: Boolean = false,
    /** Accept chains to the built-in mainland China CAs (including SM2 roots), as T2 like the platform store. */
    val mainlandChinaRootsEnabled: Boolean = false,
) {
    val insecureLoopbackAllowed: Boolean get() = testEnvironmentEnabled && allowInsecureLoopbackHttp

    fun enabledEnvironments(): List<TrustEnvironment> = buildList {
        add(TrustEnvironment.PRODUCTION)
        if (userAnchorsEnabled) add(TrustEnvironment.USER)
        if (systemStoreEnabled || mainlandChinaRootsEnabled) add(TrustEnvironment.SYSTEM)
        add(TrustEnvironment.TEST)
    }
}
