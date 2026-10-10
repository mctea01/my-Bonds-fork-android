package diw.wallet.core.trust

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.Storage
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustMetadata
import org.multipaz.trustmanagement.TrustEntryAlreadyExistsException
import kotlin.time.Clock
import kotlin.time.Instant

/** What a trust anchor is used for. Anchors are never shared across roles. */
enum class TrustRole(val id: String) {
    ISSUER("issuer"),
    VERIFIER("verifier"),
    WALLET_PROVIDER("wallet-provider"),
    STATUS_LIST("status-list"),
    TSA("tsa"),
}

/** Metadata extension keys stored in [TrustMetadata.extensions]. */
object TrustMetadataKeys {
    const val ENVIRONMENT = "diw.environment"
    const val OFFICIAL = "diw.official"
    const val SOURCE = "diw.source"
}

fun trustMetadata(
    displayName: String,
    environment: TrustEnvironment,
    official: Boolean,
    source: String,
    privacyPolicyUrl: String? = null,
): TrustMetadata = TrustMetadata(
    displayName = displayName,
    privacyPolicyUrl = privacyPolicyUrl,
    testOnly = environment == TrustEnvironment.TEST,
    extensions = mapOf(
        TrustMetadataKeys.ENVIRONMENT to environment.id,
        TrustMetadataKeys.OFFICIAL to official.toString(),
        TrustMetadataKeys.SOURCE to source,
    )
)

/** Result of a chain lookup in one role across enabled environments. */
data class AnchorMatch(
    val environment: TrustEnvironment,
    val metadata: TrustMetadata,
    val official: Boolean,
    val anchor: X509Cert,
)

/**
 * Holds one Multipaz [TrustManager] per (role, environment). Lookups only consult the environments
 * enabled by the current [EnvironmentPolicy], in the order PRODUCTION, USER, TEST.
 */
class TrustRegistry(
    private val storage: Storage,
    var policy: EnvironmentPolicy,
) {
    private val managers = mutableMapOf<Pair<TrustRole, TrustEnvironment>, TrustManager>()

    fun manager(role: TrustRole, environment: TrustEnvironment): TrustManager =
        managers.getOrPut(role to environment) {
            TrustManager(storage, identifier = "${role.id}-${environment.id}")
        }

    suspend fun addAnchor(
        role: TrustRole,
        environment: TrustEnvironment,
        certificate: X509Cert,
        displayName: String,
        official: Boolean,
        source: String,
    ): Boolean = try {
        manager(role, environment).addX509Cert(
            certificate,
            trustMetadata(displayName, environment, official, source)
        )
        true
    } catch (_: TrustEntryAlreadyExistsException) {
        false
    }

    suspend fun anchors(role: TrustRole, environment: TrustEnvironment): List<Pair<X509Cert, TrustMetadata>> =
        manager(role, environment).getTrustPoints().map { it.certificate to it.metadata }

    /**
     * Finds a trusted anchor for [chain] (leaf first, root may be omitted).
     * Returns null when no enabled environment trusts the chain.
     */
    suspend fun match(
        role: TrustRole,
        chain: List<X509Cert>,
        atTime: Instant = Clock.System.now(),
        docType: String? = null,
    ): AnchorMatch? {
        if (chain.isEmpty()) return null
        for (env in policy.enabledEnvironments()) {
            val result = manager(role, env).verify(chain, atTime, validateCaValidity = true, docType = docType)
            if (result.isTrusted) {
                val point = result.trustPoints.first()
                val official = point.metadata.extensions[TrustMetadataKeys.OFFICIAL] == "true" &&
                    env == TrustEnvironment.PRODUCTION
                return AnchorMatch(env, point.metadata, official, point.certificate)
            }
        }
        return null
    }

    /** Evaluates a chain whose signature binding has already been verified by the caller. */
    suspend fun decide(role: TrustRole, chain: List<X509Cert>, atTime: Instant = Clock.System.now()): TrustDecision {
        val m = match(role, chain, atTime)
        if (m == null) {
            return TrustDecision(
                tier = TrustTier.T3,
                environment = null,
                official = false,
                anchorName = null,
                labels = setOf(TrustLabel.UNKNOWN_ANCHOR),
                reasons = listOf("Certificate chain does not lead to an enabled trust anchor")
            )
        }
        val labels = buildSet {
            if (m.environment == TrustEnvironment.TEST) add(TrustLabel.TEST_ANCHOR)
            if (m.environment == TrustEnvironment.USER) add(TrustLabel.USER_ANCHOR)
        }
        return TrustDecision(
            tier = tierFor(m.environment, m.official, cryptographicallyVerified = true),
            environment = m.environment,
            official = m.official,
            anchorName = m.metadata.displayName,
            labels = labels,
        )
    }
}
