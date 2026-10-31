package diw.wallet.core.trust

import diw.wallet.core.env.TrustEnvironment

/**
 * Prompt levels shown to the user for verifiers, issuers and document signers.
 * T1: verified beyond the trust root, in an official list (TWDIW listed and matching its on-chain registration, or an
 * anchor flagged official); T2: the chain or key leads to a trust root (built-in GPKI, platform store and built-in
 * public roots, user-imported roots, user-trusted DIDs, verified Linked Domains) or a listed party could not be fully
 * checked; T1 and T2 count as highly trusted. T3: cryptographically verifiable but not led to any trust root, and every
 * test anchor; T4: verification failed, unsigned or anonymous. Intermediate certificates never set the tier: only the
 * root a chain leads to does.
 */
enum class TrustTier { T1, T2, T3, T4 }

/** Independent labels displayed next to the tier. */
enum class TrustLabel {
    TEST_ANCHOR,
    USER_ANCHOR,
    UNKNOWN_ANCHOR,
    UNSIGNED_REQUEST,
    VIA_INTERMEDIARY,
    RETAINS_DATA,
    HAS_TRANSACTION_DATA,
    SOFTWARE_KEY,
    TIME_NOT_VERIFIED,
    UNSIGNED_METADATA,
    KEY_NOT_ATTESTED,

    /**
     * The party's DID is linked to its domain per DIF Well Known DID Configuration, the root of trust of Microsoft
     * Entra Verified ID (shown as a verified domain, as Microsoft Authenticator does).
     */
    LINKED_DOMAIN,

    /** The chain leads to the platform's certificate store (public web PKI). */
    SYSTEM_ANCHOR,

    /** A built-in anchor certifies who the party is (Taiwan GPKI), not that it is a listed issuer: T2. */
    IDENTITY_VERIFIED,

    /**
     * The chain leads to a built-in mainland China certification authority (public CAs in the Mozilla or Microsoft
     * programs, and SM2 roots of licensed CAs): a public CA verified a domain or organisation, as for [SYSTEM_ANCHOR].
     */
    MAINLAND_CHINA_CA,

    /** The chain leads to a root on the Adobe Approved Trust List (document signatures and time stamps). */
    AATL,

    /** The chain leads to a trust service of an EU member state's trusted list (eIDAS), granted at the time checked. */
    EUTL,

    /** The EU trusted list names the service as qualified (a qualified certificate or a qualified time stamp). */
    EU_QUALIFIED,

    /**
     * Issued by this wallet's own key (a credential derived from a stored document): it vouches that the content was
     * read from that document, not for whoever issued the document.
     */
    SELF_ISSUED,

    /** The party's metadata comes from an OpenID Federation trust chain to a configured Trust Anchor. */
    OPENID_FEDERATION,
}

/**
 * Result of evaluating an entity (verifier or issuer) against the trust registry.
 *
 * @property environment environment of the matched anchor, or null when no anchor matched.
 * @property official whether the matched anchor is flagged as an official source.
 * @property anchorName display name of the matched anchor.
 */
data class TrustDecision(
    val tier: TrustTier,
    val environment: TrustEnvironment?,
    val official: Boolean,
    val anchorName: String?,
    val labels: Set<TrustLabel>,
    val reasons: List<String> = emptyList(),
) {
    /** Test results must never look like a passing production result. */
    val mayShowAsVerified: Boolean get() = tier == TrustTier.T1 && environment == TrustEnvironment.PRODUCTION

    companion object {
        fun unknown(vararg reasons: String, labels: Set<TrustLabel> = emptySet()) = TrustDecision(
            tier = TrustTier.T4,
            environment = null,
            official = false,
            anchorName = null,
            labels = labels,
            reasons = reasons.toList()
        )
    }
}

/**
 * Applies the environment rules: an official production anchor is T1, any other production, user or platform trust
 * root is T2, and test anchors never rise above T3.
 */
fun tierFor(environment: TrustEnvironment?, official: Boolean, cryptographicallyVerified: Boolean): TrustTier = when {
    !cryptographicallyVerified -> TrustTier.T4
    environment == TrustEnvironment.PRODUCTION && official -> TrustTier.T1
    environment == null || environment == TrustEnvironment.TEST -> TrustTier.T3
    else -> TrustTier.T2
}

/** T1 and T2: led to a trust root, or verified beyond one; the wallet treats these parties as highly trusted. */
val TrustTier.highlyTrusted: Boolean get() = this == TrustTier.T1 || this == TrustTier.T2
