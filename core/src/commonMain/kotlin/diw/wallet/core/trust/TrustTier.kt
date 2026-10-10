package diw.wallet.core.trust

import diw.wallet.core.env.TrustEnvironment

/**
 * Prompt levels shown to the user for verifiers and issuers.
 * T1: official or meets security requirements; T2: identity verified but purpose not registered or request
 * exceeds registration; T3: cryptographically verifiable but not anchored in an official list; T4: unknown,
 * unsigned or anonymous.
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

/** Applies the environment rules: test anchors can never reach T1 or T2. */
fun tierFor(environment: TrustEnvironment?, official: Boolean, cryptographicallyVerified: Boolean): TrustTier = when {
    !cryptographicallyVerified -> TrustTier.T4
    environment == TrustEnvironment.PRODUCTION && official -> TrustTier.T1
    else -> TrustTier.T3
}
