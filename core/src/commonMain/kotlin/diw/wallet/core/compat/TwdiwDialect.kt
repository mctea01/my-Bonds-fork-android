package diw.wallet.core.compat

import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vci.AuthServerMetadata
import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.oid4vci.IssuerMetadata
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.hostOf
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.client.HttpClient
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Taiwan digital wallet (TWDIW, 數位憑證皮夾) issuance as the official wallet and Bonds perform it:
 *
 * - no authorization server metadata; the token endpoint is {credential_issuer}token;
 * - the token request carries client_id (moda_dw), authorization_details and an empty tx_code when none is asked;
 * - c_nonce comes in the token response;
 * - the proof JWT has kid set to the holder did:key (jwk_jcs-pub) without a fragment, no jwk, and iss = client_id;
 * - the credential request is credential_identifier + proofs, the response a single credential;
 * - credentials announced as jwt_vc_json are SD-JWTs (typ vc+sd-jwt) with the W3C credential under vc and no vct;
 * - the issuer key is the issuer DID in iss (did:key); jku is never followed;
 * - every card is bound to one wallet-level holder key, so cards can be presented together.
 *
 * The dialect owns sessions for issuers under wallet.gov.tw or reached through the modadigitalwallet scheme, and
 * sessions where the issuer has no authorization server metadata and no token_endpoint.
 */
class TwdiwDialect(
    private val httpClient: HttpClient,
    private val allowInsecureLoopback: Boolean,
    /** client_id sent to TWDIW issuers; moda_dw is the official wallet's and what TWDIW issuers accept. */
    private val clientId: () -> String = { DEFAULT_CLIENT_ID },
) : IssuanceDialect {
    override val id = ID
    override val spec = "TWDIW"

    override fun claimsIssuer(credentialIssuer: String, entryHint: String?): Boolean =
        entryHint == ENTRY_HINT || runCatching { isTwdiwHost(hostOf(credentialIssuer)) }.getOrDefault(false)

    override fun holderProfile(issuer: IssuerMetadata): HolderProfile = HolderProfile(HolderIdentities.TWDIW, HolderKey.DID_KEY_JWK_JCS)

    override fun authorizationServerFallback(issuer: IssuerMetadata): AuthServerMetadata? {
        if (issuer.authorizationServers.isNotEmpty() || issuer.raw.str("token_endpoint") != null) return null
        val base = if (issuer.credentialIssuer.endsWith("/")) issuer.credentialIssuer else issuer.credentialIssuer + "/"
        return AuthServerMetadata(
            issuer = issuer.credentialIssuer,
            authorizationEndpoint = null,
            tokenEndpoint = base + "token",
            parEndpoint = null,
            requirePar = false,
            dpopAlgorithms = emptyList(),
            codeChallengeMethods = emptyList(),
            tokenEndpointAuthMethods = emptyList(),
            challengeEndpoint = null,
            preAuthorizedAnonymousAccess = false,
            responseIssParameterSupported = false,
            raw = JsonObject(emptyMap()),
        )
    }

    override fun tokenParameters(context: TokenContext): Map<String, String> = buildMap {
        put("client_id", clientId())
        put("authorization_details", buildJsonArray {
            for (id in context.configurationIds) addJsonObject {
                put("type", "openid_credential")
                put("credential_configuration_id", id)
            }
        }.toString())
        // The TWDIW token endpoint expects the parameter even when the offer asks for no transaction code.
        put("tx_code", context.txCode.orEmpty())
    }

    override fun nonceWithoutEndpoint(tokenResponse: JsonObject): String? = tokenResponse.str("c_nonce")

    override fun nonceFromError(error: JsonObject): String? = error.str("c_nonce")

    override fun proofStyle(issuer: IssuerMetadata, config: CredentialConfiguration): ProofStyle = ProofStyle(ProofKid.BARE_DID, clientId())

    override fun credentialRequest(issuer: IssuerMetadata, config: CredentialConfiguration, credentialIdentifier: String?, proofs: JsonObject?): JsonObject =
        buildJsonObject {
            put("credential_identifier", credentialIdentifier ?: config.id)
            proofs?.let { put("proofs", it) }
        }

    override fun credentialsFromResponse(response: JsonObject): List<String>? =
        (response["credential"] as? JsonPrimitive)?.takeIf { it.isString }?.let { listOf(it.content) }

    override fun storageType(config: CredentialConfiguration): String? =
        config.raw.obj("credential_definition")?.strList("type")?.lastOrNull { it != "VerifiableCredential" }

    override fun w3cDeliveredAsSdJwt(config: CredentialConfiguration): Boolean = config.format.isW3c

    /** Issuer key from the issuer DID in iss. The kid and jku headers point at a key set this wallet does not trust. */
    override suspend fun sdJwtIssuerKey(context: SdJwtKeyContext): DialectIssuerKey? {
        val iss = context.payload.str("iss") ?: return null
        if (!iss.startsWith("did:key:") && !iss.startsWith("did:jwk:")) return null
        val method = DidResolver(httpClient, allowInsecureLoopback).resolve(iss).methods.singleOrNull()
            ?: throw ProtocolException("invalid_credential", "Issuer DID $iss has no single key")
        val key = (method.key as? VerificationKey.Ec)?.key ?: throw ProtocolException("invalid_credential", "Issuer DID key is not an EC key")
        return DialectIssuerKey(key, "Issuer key comes from the issuer DID $iss (TWDIW)", "TWDIW")
    }

    companion object {
        const val ID = "twdiw"
        const val ENTRY_HINT = "twdiw"
        const val DEFAULT_CLIENT_ID = "moda_dw"

        /** Hosts of the TWDIW platform and its issuers and verifiers (wallet.gov.tw and subdomains). */
        fun isTwdiwHost(host: String): Boolean {
            val h = host.lowercase().trimEnd('.')
            return h == "wallet.gov.tw" || h.endsWith(".wallet.gov.tw")
        }
    }
}
