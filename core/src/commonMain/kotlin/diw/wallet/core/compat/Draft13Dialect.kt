package diw.wallet.core.compat

import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.oid4vci.IssuerMetadata
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

/**
 * OpenID4VCI draft 13 and earlier SD-JWT VC drafts, still deployed by many issuers (walt.id, TWDIW-based ones):
 * c_nonce in the token and error responses, format-based credential requests with a single proof, a single
 * credential in the response, vct inside credential_definition, and issuer keys from a DID in iss.
 */
class Draft13Dialect(
    private val httpClient: HttpClient,
    private val allowInsecureLoopback: Boolean,
) : IssuanceDialect {
    override val id = "draft13"
    override val spec = "OpenID4VCI draft 13"

    override fun nonceWithoutEndpoint(tokenResponse: JsonObject): String? = tokenResponse.str("c_nonce")

    override fun nonceFromError(error: JsonObject): String? = error.str("c_nonce")

    override fun alternativeCredentialRequest(
        issuer: IssuerMetadata,
        config: CredentialConfiguration,
        credentialIdentifier: String?,
        proofs: JsonObject?,
        status: HttpStatusCode,
        error: JsonObject,
    ): JsonObject? {
        // Only issuers without a nonce endpoint can be draft era; invalid_nonce is handled by the standard retry.
        if (status != HttpStatusCode.BadRequest || issuer.nonceEndpoint != null || error.str("error") == "invalid_nonce") return null
        return buildJsonObject {
            if (credentialIdentifier != null) {
                put("credential_identifier", credentialIdentifier)
            } else {
                put("format", config.raw.str("format") ?: config.format.wire)
                config.docType?.let { put("doctype", it) }
                config.raw.str("vct")?.let { put("vct", it) }
                config.raw.obj("credential_definition")?.let { put("credential_definition", it) }
            }
            val jwt = proofs?.arr("jwt")?.firstOrNull()
            val attestation = proofs?.arr("attestation")?.firstOrNull()
            if (jwt != null) {
                putJsonObject("proof") { put("proof_type", "jwt"); put("jwt", jwt) }
            } else if (attestation != null) {
                putJsonObject("proof") { put("proof_type", "attestation"); put("attestation", attestation) }
            }
        }
    }

    override fun credentialsFromResponse(response: JsonObject): List<String>? = response.str("credential")?.let { listOf(it) }

    override fun storageType(config: CredentialConfiguration): String? = config.raw.obj("credential_definition")?.str("vct")

    override suspend fun sdJwtIssuerKey(context: SdJwtKeyContext): DialectIssuerKey? {
        val iss = context.payload.str("iss") ?: return null
        if (listOf("did:key:", "did:jwk:", "did:web:").none { iss.startsWith(it) }) return null
        val doc = DidResolver(httpClient, allowInsecureLoopback).resolve(iss)
        // did:key and did:jwk have one method; the kid fragment varies between issuers (#0, #<multibase>).
        val kid = context.header.str("kid")
        val method = doc.methods.singleOrNull() ?: kid?.let { doc.find(it) }
            ?: throw ProtocolException("invalid_credential", "No verification method in $iss matches kid '$kid'")
        val key = (method.key as? VerificationKey.Ec)?.key ?: throw ProtocolException("invalid_credential", "Issuer DID key is not an EC key")
        return DialectIssuerKey(key, "Issuer key comes from the issuer DID $iss, not from an X.509 anchor", "DID " + iss.split(':').take(2).joinToString(":"))
    }
}
