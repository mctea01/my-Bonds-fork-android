package diw.wallet.core.oid4vp

import diw.wallet.core.jose.VerificationKey

/** A Verifier registered with the wallet out of band (client_id without prefix). */
data class PreRegisteredVerifier(
    val clientId: String,
    val displayName: String,
    val responseUris: List<String>,
    val keys: List<VerificationKey>,
    val official: Boolean,
)

/**
 * Presentation policy for the standard OpenID4VP 1.0 profile. Defaults follow HAIP where the wallet can
 * enforce it without breaking the plain 1.0 profile; HAIP-only rules are switched on with [haip].
 */
data class PresentationPolicy(
    /** HAIP: signed requests, x509_hash client ids, encrypted responses (direct_post.jwt / dc_api.jwt). */
    val haip: Boolean = false,
    /** Accept requests whose x509 chain does not reach an enabled anchor (shown as T3 with a warning). */
    val allowUnanchoredX509: Boolean = true,
    /** Accept decentralized_identifier clients (always T3 unless anchored by a later profile). */
    val allowDecentralizedIdentifier: Boolean = true,
    /** Accept unsigned redirect_uri clients (always T4). */
    val allowRedirectUriClients: Boolean = true,
    /** Require typ=oauth-authz-req+jwt on signed request objects. */
    val requireRequestObjectTyp: Boolean = true,
    /** Maximum accepted size of a fetched request object in bytes. */
    val maxRequestObjectBytes: Int = 256 * 1024,
    val preRegistered: List<PreRegisteredVerifier> = emptyList(),
)

/** wallet_metadata sent with request_uri_method=post (OpenID4VP 1.0 section 10). */
object WalletMetadata {
    val vpFormatsSupported = mapOf(
        "mso_mdoc" to mapOf(
            "issuerauth_alg_values" to listOf(-7, -9, -35, -36, -8),
            "deviceauth_alg_values" to listOf(-7, -9, -35, -36, -8)
        ),
        "dc+sd-jwt" to mapOf(
            "sd-jwt_alg_values" to listOf("ES256", "ES384", "ES512", "EdDSA", "RS256", "PS256"),
            "kb-jwt_alg_values" to listOf("ES256", "ES384", "ES512", "EdDSA")
        )
    )
    val clientIdPrefixesSupported = listOf(
        "redirect_uri", "x509_san_dns", "x509_hash", "decentralized_identifier", "verifier_attestation"
    )
    val responseModesSupported = listOf("direct_post", "direct_post.jwt", "dc_api", "dc_api.jwt")
    val responseTypesSupported = listOf("vp_token")
    val requestObjectSigningAlgs = listOf("ES256", "ES384", "ES512", "EdDSA", "RS256", "PS256")
}
