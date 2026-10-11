package diw.wallet.core.env

/**
 * PKI environment partition. Every trust anchor, credential and verification result carries one of these.
 * PRODUCTION anchors are official lists and production roots; TEST anchors are sandboxes, conformance suites
 * and reference implementations; USER anchors were imported by the user.
 */
enum class TrustEnvironment(val id: String) {
    PRODUCTION("production"),
    TEST("test"),
    USER("user");

    companion object {
        fun fromId(id: String?): TrustEnvironment? = entries.firstOrNull { it.id == id }
    }
}

/**
 * Runtime environment policy. Test anchors are only consulted when [testEnvironmentEnabled] is set
 * (developer settings). [allowInsecureLoopbackHttp] permits http://localhost style endpoints and is only
 * honoured together with the test environment.
 */
data class EnvironmentPolicy(
    val testEnvironmentEnabled: Boolean = false,
    val allowInsecureLoopbackHttp: Boolean = false,
    val userAnchorsEnabled: Boolean = true,
) {
    val insecureLoopbackAllowed: Boolean get() = testEnvironmentEnabled && allowInsecureLoopbackHttp

    fun enabledEnvironments(): List<TrustEnvironment> = buildList {
        add(TrustEnvironment.PRODUCTION)
        if (userAnchorsEnabled) add(TrustEnvironment.USER)
        if (testEnvironmentEnabled) add(TrustEnvironment.TEST)
    }
}
