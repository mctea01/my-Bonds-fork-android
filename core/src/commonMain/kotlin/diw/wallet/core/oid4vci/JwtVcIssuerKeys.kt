package diw.wallet.core.oid4vci

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.obj
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.str
import diw.wallet.core.util.wellKnownUrl
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.EcPublicKey

/**
 * The signing key of an SD-JWT VC issuer named by an https iss without x5c: SD-JWT VC JWT VC Issuer Metadata
 * (/.well-known/jwt-vc-issuer), whose keys are inline (jwks) or behind an https jwks_uri.
 */
class JwtVcIssuerKeys(private val httpClient: HttpClient, private val allowInsecureLoopback: Boolean) {
    suspend fun resolve(issuer: String, kid: String?): EcPublicKey {
        if (!isAcceptableEndpoint(issuer, allowInsecureLoopback)) {
            throw ProtocolException("invalid_credential", "SD-JWT VC without x5c and with non-https iss")
        }
        val resp = httpClient.get(wellKnownUrl(issuer, "jwt-vc-issuer"))
        if (!resp.status.isSuccess()) throw ProtocolException("invalid_credential", "jwt-vc-issuer metadata not available")
        val meta = parseJsonObject(resp.bodyAsText(), "invalid_credential")
        if (meta.str("issuer") != issuer) throw ProtocolException("invalid_credential", "jwt-vc-issuer metadata issuer mismatch")
        val jwks = meta.obj("jwks") ?: meta.str("jwks_uri")?.let { uri ->
            if (!isAcceptableEndpoint(uri, allowInsecureLoopback)) throw ProtocolException("invalid_credential", "jwks_uri must be https")
            parseJsonObject(httpClient.get(uri).bodyAsText(), "invalid_credential")
        } ?: throw ProtocolException("invalid_credential", "jwt-vc-issuer metadata has no keys")
        val keys = jwks.arr("keys").orEmpty().filterIsInstance<JsonObject>()
        val jwk = (if (kid != null) keys.firstOrNull { it.str("kid") == kid } else keys.singleOrNull())
            ?: throw ProtocolException("invalid_credential", "No issuer key matches kid '$kid'")
        return EcPublicKey.fromJwk(jwk)
    }
}
