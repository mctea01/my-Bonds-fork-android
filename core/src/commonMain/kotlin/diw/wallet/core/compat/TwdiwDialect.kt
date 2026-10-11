package diw.wallet.core.compat

import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.hostOf
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.obj
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.EcPublicKey

/**
 * Taiwan digital wallet (TWDIW) profile and issuers built on it: W3C credentials wrapped in SD-JWT without vct,
 * typed by credential_definition.type, with the issuer key set referenced by jku.
 */
class TwdiwDialect(
    private val httpClient: HttpClient,
    private val allowInsecureLoopback: Boolean,
) : IssuanceDialect {
    override val id = "twdiw"
    override val spec = "TWDIW"

    override fun storageType(config: CredentialConfiguration): String? =
        config.raw.obj("credential_definition")?.strList("type")?.lastOrNull { it != "VerifiableCredential" }

    /**
     * Key lookup through the JWS jku header. The credential arrived over TLS from the credential issuer, so a key set
     * on the same host, or a sibling host under the same organisation domain (at least three labels, e.g.
     * wallet.gov.tw), is accepted; anything else could let a third party vouch for the credential.
     */
    override suspend fun sdJwtIssuerKey(context: SdJwtKeyContext): DialectIssuerKey? {
        val jku = context.header.str("jku") ?: return null
        val kid = context.header.str("kid")
        if (!isAcceptableEndpoint(jku, allowInsecureLoopback)) throw ProtocolException("invalid_credential", "jku must be https")
        val keyHost = hostOf(jku).lowercase()
        val issuerHost = hostOf(context.credentialIssuer).lowercase()
        val parent = issuerHost.substringAfter('.', "")
        val sameOrg = keyHost == issuerHost || (parent.count { it == '.' } >= 2 && keyHost.substringAfter('.', "") == parent)
        if (!sameOrg) throw ProtocolException("invalid_credential", "jku host $keyHost is not on the credential issuer's domain")
        val resp = httpClient.get(jku)
        if (!resp.status.isSuccess()) throw ProtocolException("invalid_credential", "jku key set not available (${resp.status.value})")
        val keys = parseJsonObject(resp.bodyAsText(), "invalid_credential").arr("keys").orEmpty().filterIsInstance<JsonObject>()
        val jwk = (if (kid != null) keys.firstOrNull { it.str("kid") == kid } else null)
            ?: keys.singleOrNull() ?: throw ProtocolException("invalid_credential", "No key in jku matches kid '$kid'")
        return DialectIssuerKey(EcPublicKey.fromJwk(jwk), "Issuer key comes from jku on the credential issuer's domain, not from an X.509 anchor", "JWS jku (RFC 7515)")
    }
}
