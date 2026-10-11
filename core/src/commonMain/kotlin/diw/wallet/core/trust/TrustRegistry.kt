package diw.wallet.core.trust

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.Storage
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustMetadata
import org.multipaz.trustmanagement.TrustEntryAlreadyExistsException
import org.multipaz.trustmanagement.TrustEntryX509Cert
import diw.wallet.core.x509.displaySubject
import kotlin.time.Clock
import kotlin.time.Instant

/** What a trust anchor is used for. Anchors are never shared across roles. */
enum class TrustRole(val id: String) {
    ISSUER("issuer"),
    VERIFIER("verifier"),
    WALLET_PROVIDER("wallet-provider"),
    STATUS_LIST("status-list"),
    TSA("tsa"),
    /** Signers of documents (PDF, CMS, XML, OFD signatures and seals). */
    DOCUMENT("document"),
}

/** Metadata extension keys stored in [TrustMetadata.extensions]. */
object TrustMetadataKeys {
    const val ENVIRONMENT = "diw.environment"
    const val OFFICIAL = "diw.official"
    const val SOURCE = "diw.source"
    /** "true": the anchor certifies the identity of the parties below it (T2), not that they are listed (T1). */
    const val IDENTITY = "diw.identity"
    /** Region of a built-in public CA ("CN" for mainland China). */
    const val REGION = "diw.region"
}

fun trustMetadata(
    displayName: String,
    environment: TrustEnvironment,
    official: Boolean,
    source: String,
    privacyPolicyUrl: String? = null,
    identity: Boolean = false,
    region: String? = null,
): TrustMetadata = TrustMetadata(
    displayName = displayName,
    privacyPolicyUrl = privacyPolicyUrl,
    testOnly = environment == TrustEnvironment.TEST,
    extensions = buildMap {
        put(TrustMetadataKeys.ENVIRONMENT, environment.id)
        put(TrustMetadataKeys.OFFICIAL, official.toString())
        put(TrustMetadataKeys.SOURCE, source)
        if (identity) put(TrustMetadataKeys.IDENTITY, "true")
        region?.let { put(TrustMetadataKeys.REGION, it) }
    }
)

/** Result of a chain lookup in one role across enabled environments. */
data class AnchorMatch(
    val environment: TrustEnvironment,
    val metadata: TrustMetadata,
    val official: Boolean,
    val anchor: X509Cert,
)

/** An X.509 anchor as stored: the role and environment it applies to, and its metadata. */
data class StoredAnchor(
    val role: TrustRole,
    val environment: TrustEnvironment,
    val certificate: X509Cert,
    val metadata: TrustMetadata,
    val identifier: String,
) {
    val official: Boolean get() = metadata.extensions[TrustMetadataKeys.OFFICIAL] == "true" && environment == TrustEnvironment.PRODUCTION
    val source: String? get() = metadata.extensions[TrustMetadataKeys.SOURCE]
}

/**
 * Holds one Multipaz [TrustManager] per (role, environment). Lookups only consult the environments
 * enabled by the current [EnvironmentPolicy], in the order PRODUCTION, USER, TEST.
 */
class TrustRegistry(
    private val storage: Storage,
    var policy: EnvironmentPolicy,
) {
    private companion object {
        /**
         * The system store holds web PKI CAs: they may identify issuers, verifiers, status list signers, document
         * signers and time-stamp authorities, nothing else (never a wallet provider).
         */
        val SYSTEM_ROLES = setOf(TrustRole.ISSUER, TrustRole.VERIFIER, TrustRole.STATUS_LIST, TrustRole.DOCUMENT, TrustRole.TSA)

        /** Roles whose chains are validated with PKIX only (RFC 5280), not with the mdoc trust profile. */
        val PKIX_ROLES = setOf(TrustRole.DOCUMENT, TrustRole.TSA)
    }

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
        identity: Boolean = false,
    ): Boolean = try {
        manager(role, environment).addX509Cert(
            certificate,
            trustMetadata(displayName, environment, official, source, identity = identity)
        )
        true
    } catch (_: TrustEntryAlreadyExistsException) {
        false
    }

    /**
     * Adds the [BuiltInAnchors] (Taiwan GPKI) as PRODUCTION identity anchors for their roles; anchors already stored
     * are left as they are. Returns how many were added.
     */
    suspend fun seedBuiltInAnchors(): Int {
        var added = 0
        for (a in BuiltInAnchors.all) for (role in a.roles) {
            if (addAnchor(role, TrustEnvironment.PRODUCTION, a.certificate, a.name, official = false, source = BuiltInAnchors.SOURCE, identity = true)) added++
        }
        return added
    }

    suspend fun anchors(role: TrustRole, environment: TrustEnvironment): List<Pair<X509Cert, TrustMetadata>> =
        manager(role, environment).getTrustPoints().map { it.certificate to it.metadata }

    /** Every stored X.509 anchor of every role and environment, enabled or not (the system store is not stored here). */
    suspend fun allAnchors(): List<StoredAnchor> = TrustEnvironment.entries.filter { it != TrustEnvironment.SYSTEM }.flatMap { env ->
        TrustRole.entries.flatMap { role ->
            manager(role, env).getEntries().filterIsInstance<TrustEntryX509Cert>()
                .map { StoredAnchor(role, env, it.certificate, it.metadata, it.identifier) }
        }
    }

    /** Removes [anchor]; false when it was not stored. */
    suspend fun removeAnchor(anchor: StoredAnchor): Boolean {
        val m = manager(anchor.role, anchor.environment)
        val entry = m.getEntries().firstOrNull { it.identifier == anchor.identifier } ?: return false
        return m.deleteEntry(entry)
    }

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
            if (env == TrustEnvironment.SYSTEM) {
                if (role !in SYSTEM_ROLES) continue
                val found = runCatching {
                    PublicRoots.anchorOf(chain, atTime, platform = policy.systemStoreEnabled, mainlandChina = policy.mainlandChinaRootsEnabled)
                }.getOrNull() ?: continue
                val metadata = trustMetadata(found.label, env, official = false, source = found.source, region = found.region)
                return AnchorMatch(env, metadata, false, found.certificate)
            }
            val m = manager(role, env)
            // Multipaz handles EC chains; an RSA chain (GPKI, web PKI) makes it throw and is validated with PKIX.
            // Document signers and time-stamp authorities are plain PKIX chains: Multipaz's mdoc profile checks
            // (signing key usage of the leaf) do not apply to them.
            val result = if (role in PKIX_ROLES) null else runCatching { m.verify(chain, atTime, validateCaValidity = true, docType = docType) }.getOrNull()
            // Only when Multipaz could not evaluate the chain: an EC chain it found untrusted stays untrusted.
            val point = if (result != null) result.trustPoints.firstOrNull()?.takeIf { result.isTrusted } else {
                val points = m.getTrustPoints()
                Pkix.anchorOf(chain, points.map { it.certificate }, atTime)?.let { a -> points.first { it.certificate == a } }
            }
            if (point != null) {
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
        val identity = m.environment == TrustEnvironment.PRODUCTION && m.metadata.extensions[TrustMetadataKeys.IDENTITY] == "true"
        val labels = buildSet {
            if (m.environment == TrustEnvironment.TEST) add(TrustLabel.TEST_ANCHOR)
            if (m.environment == TrustEnvironment.USER) add(TrustLabel.USER_ANCHOR)
            if (m.environment == TrustEnvironment.SYSTEM) add(TrustLabel.SYSTEM_ANCHOR)
            if (m.metadata.extensions[TrustMetadataKeys.REGION] == "CN") add(TrustLabel.MAINLAND_CHINA_CA)
            if (identity && !m.official) add(TrustLabel.IDENTITY_VERIFIED)
        }
        return TrustDecision(
            tier = if (identity && !m.official) TrustTier.T2 else tierFor(m.environment, m.official, cryptographicallyVerified = true),
            environment = m.environment,
            official = m.official,
            anchorName = m.metadata.displayName,
            labels = labels,
        )
    }
}
