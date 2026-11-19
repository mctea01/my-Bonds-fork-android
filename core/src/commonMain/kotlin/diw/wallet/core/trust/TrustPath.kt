package diw.wallet.core.trust

import diw.wallet.core.env.TrustEnvironment
import org.multipaz.crypto.X509Cert

/** Where a certificate of a [TrustPath] came from. */
enum class PathSource {
    /** Sent with the signature, credential, request or document. */
    PRESENTED,

    /** One of the intermediate CA certificates built into the wallet. */
    BUILT_IN_INTERMEDIATE,

    /** An intermediate CA certificate the user imported. */
    USER_INTERMEDIATE,

    /** A trust anchor or a root the wallet knows (stored, built in, or in the platform store). */
    TRUST_SOURCE,

    /** Downloaded from the AIA caIssuers link of the certificate below it. */
    AIA,
}

/** One certificate of a [TrustPath]. */
data class PathStep(
    val certificate: X509Cert,
    val source: PathSource,
    /**
     * The certificate above this one verifies its signature; for the top certificate, its own key verifies it when it
     * is self-issued. Null when there is nothing to check against (the issuer could not be found).
     */
    val signatureValid: Boolean?,
    /** This certificate is the anchor the chain was evaluated against for the role asked. */
    val anchor: Boolean,
)

/** A place among the wallet's trust sources that holds a root (or the top certificate of a path). */
data class RootListing(
    val kind: Kind,
    val name: String,
    val role: TrustRole? = null,
    val environment: TrustEnvironment? = null,
    val official: Boolean = false,
) {
    enum class Kind {
        /** A stored anchor (built-in production anchor, user anchor or test anchor) for [role] in [environment]. */
        STORED_ANCHOR,

        /** A country signing CA of the built-in master list (travel documents only). */
        BUILT_IN_CSCA,

        /** A built-in public root (mainland China CAs, common services, time stamping, C2PA). */
        BUILT_IN_PUBLIC,

        /** The platform's certificate store. */
        PLATFORM_STORE,

        /** A built-in root that is offered for import and is not trusted until the user imports it. */
        IMPORTABLE,

        /** A trust service of an enabled trust list (AATL, EUTL), as found for the role asked. */
        TRUST_LIST,
    }
}

/**
 * A certificate chain completed up to its root for display: the leaf first, then each issuer found among the
 * certificates sent with it, the built-in and user intermediates, the anchors and known roots, and AIA links. The
 * trust tier still comes only from the anchor the chain leads to ([decision]); finding a root here does not make it
 * trusted.
 *
 * @property extras certificates sent with the chain that are not part of the path from the leaf.
 * @property decision the evaluation for the role asked, as [TrustRegistry.decide] reports it; null without a role.
 * @property rootListings where the top certificate is held among the wallet's trust sources.
 */
data class TrustPath(
    val steps: List<PathStep>,
    val extras: List<X509Cert>,
    val decision: TrustDecision?,
    val rootListings: List<RootListing>,
) {
    val top: X509Cert? get() = steps.lastOrNull()?.certificate

    /** The path ends in a self-issued certificate whose own signature verifies. */
    val rootReached: Boolean get() = steps.lastOrNull()?.let { s -> s.certificate.subject == s.certificate.issuer && s.signatureValid == true } ?: false

    /** The top certificate is an anchor or a known root for some role (not necessarily the one asked). */
    val rootKnown: Boolean get() = rootListings.any { it.kind != RootListing.Kind.IMPORTABLE }

    /** The top certificate is stored as an anchor for [role] in an environment the user can rely on (production or user). */
    fun anchoredFor(role: TrustRole): Boolean = rootListings.any {
        it.kind == RootListing.Kind.STORED_ANCHOR && it.role == role &&
            (it.environment == TrustEnvironment.PRODUCTION || it.environment == TrustEnvironment.USER)
    } || (role == TrustRole.TRAVEL_DOCUMENT && rootListings.any { it.kind == RootListing.Kind.BUILT_IN_CSCA })
}
