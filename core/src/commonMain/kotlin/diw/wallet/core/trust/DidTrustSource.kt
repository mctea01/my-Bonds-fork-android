package diw.wallet.core.trust

/**
 * Trust for issuers and verifiers identified by a DID instead of an X.509 chain: a national DID registry
 * (TWDIW trust list), or a domain linkage (DIF Well Known DID Configuration). Returns null when the source
 * knows nothing about the DID, so the next source, or the default tier, applies.
 */
interface DidTrustSource {
    suspend fun decide(did: String, role: TrustRole): TrustDecision?

    /** True when this source ties [host] to [did], so a key published there (a jku) speaks for the DID. */
    suspend fun bindsHost(did: String, host: String): Boolean = false
}

/** Asks sources in order; the first answer wins. */
class DidTrust(private val sources: List<DidTrustSource>) {
    suspend fun decide(did: String, role: TrustRole): TrustDecision? {
        for (s in sources) {
            val d = runCatching { s.decide(did, role) }.getOrNull()
            if (d != null) return d
        }
        return null
    }

    /** True when any source ties [host] to [did]. */
    suspend fun bindsHost(did: String, host: String): Boolean = sources.any { runCatching { it.bindsHost(did, host) }.getOrDefault(false) }

    /** The decision for a DID, or T3 (verifiable but not anchored) when no source knows it. */
    suspend fun decideOrDefault(did: String, role: TrustRole, reason: String): TrustDecision =
        decide(did, role) ?: TrustDecision(
            tier = TrustTier.T3, environment = null, official = false, anchorName = null,
            labels = setOf(TrustLabel.UNKNOWN_ANCHOR),
            reasons = listOf(reason),
        )

    companion object {
        val NONE = DidTrust(emptyList())
    }
}
