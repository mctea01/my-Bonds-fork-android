package diw.wallet.core.compat

import diw.wallet.core.oid4vci.AuthServerMetadata

/**
 * EUDI reference issuer (issuer.eudiw.dev): its authorization server metadata names the issuer
 * https://issuer.eudiw.dev, but authorization responses carry iss https://issuer.eudiw.dev/oidc,
 * the path its endpoints live under.
 */
class EudiDialect : IssuanceDialect {
    override val id = "eudi"
    override val spec = "EUDI 參考實作"

    /**
     * Accepts an iss below the published issuer identifier when the token endpoint is below that iss too: the code
     * then still goes to the server that issued it, which is what the RFC 9207 mix-up check protects.
     */
    override fun acceptsAuthorizationResponseIssuer(authServer: AuthServerMetadata, iss: String): Boolean {
        val base = iss.trimEnd('/')
        return base.startsWith(authServer.issuer.trimEnd('/') + "/") && authServer.tokenEndpoint.startsWith("$base/")
    }
}
