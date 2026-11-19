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
    /**
     * DIW extension (docs/design/p5-verifier.md section 6.2): accept a request_uri and response_uri over plain http on
     * a private IPv4 address under [LanEndpoints.PATH_PREFIX], when the request is signed, the response encrypted
     * (direct_post.jwt) and both URLs name the same host. Another wallet acting as verifier on the same network.
     */
    val allowLanEndpoints: Boolean = false,
)

/** The local network endpoints of a wallet acting as verifier (DIW extension). */
object LanEndpoints {
    const val PATH_PREFIX = "/diw-oid4vp/"

    /** The host of a plain http URL on a private IPv4 address under [PATH_PREFIX]; null for anything else. */
    fun host(url: String): String? {
        val u = runCatching { io.ktor.http.Url(url) }.getOrNull() ?: return null
        if (u.protocol != io.ktor.http.URLProtocol.HTTP || u.user != null || u.password != null || '#' in url) return null
        if (!u.encodedPath.startsWith(PATH_PREFIX) || u.host == "localhost" || ':' in u.host) return null
        return u.host.takeIf { diw.wallet.core.util.isLocalTestHost(it) }
    }
}

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
