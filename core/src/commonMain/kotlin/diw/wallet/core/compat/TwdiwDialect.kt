package diw.wallet.core.compat

import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vci.AuthServerMetadata
import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.oid4vci.IssuerMetadata
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.highlyTrusted
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.hostOf
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlin.time.Clock
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
 * - the metadata may name the issuer without the offer's trailing slash (the live telecom card issuer does); the
 *   identifier keeps the slash, so the token endpoint and the proof aud are what the issuer expects;
 * - the token request carries client_id (moda_dw), authorization_details and an empty tx_code when none is asked;
 * - c_nonce comes in the token response; an issuer that publishes a nonce_endpoint (moda) wants the endpoint's value;
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
    /**
     * Issuer hosts whose credential endpoint requires the TWDIW ecosystem signature (the official partner-card
     * platform). An empty set disables the signature, which is the behaviour for every other TWDIW issuer (the
     * telecom cards and the lite test issuers do not use it).
     */
    private val ecosystemSignatureHosts: () -> Set<String> = { setOf("moda.wallet.gov.tw") },
    /**
     * This wallet's own ecosystem application identity, used to sign credential requests to the hosts above. These
     * are DIW's own values, not the official app's; the official app's embedded application key is never used.
     */
    private val appIdentity: () -> TwdiwAppIdentity = { TwdiwAppIdentity.DEFAULT },
    /** Base URL of the ecosystem nonce endpoint for an issuer; the issuer's own origin by default. */
    private val ecosystemBase: (IssuerMetadata) -> String = { defaultEcosystemBase(it.credentialIssuer) },
    /**
     * The TWDIW trust list's decision for an organisation registered for a credential issuer URL (its host and the
     * organisation ID in the path); null when no listed organisation is registered for it.
     */
    private val registeredIssuerTrust: suspend (credentialIssuer: String) -> TrustDecision? = { null },
) : IssuanceDialect {
    override val id = ID
    override val spec = "TWDIW"

    override fun claimsIssuer(credentialIssuer: String, entryHint: String?): Boolean =
        entryHint == ENTRY_HINT || runCatching { isTwdiwHost(hostOf(credentialIssuer)) }.getOrDefault(false)

    override fun holderProfile(issuer: IssuerMetadata): HolderProfile = HolderProfile(HolderIdentities.TWDIW, HolderKey.DID_KEY_JWK_JCS)

    /** A trailing slash is the only difference accepted; the identifier is used with the slash, as Bonds does. */
    override fun issuerIdentifier(given: String, inMetadata: String): String? =
        if (given.trimEnd('/') == inMetadata.trimEnd('/')) given.trimEnd('/') + "/" else null

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

    /**
     * TWDIW issuers publish unsigned metadata, so before issuance the issuer would rest on TLS alone (T3). The trust
     * list registers the platform issuer URL for each organisation, so its decision for that organisation applies;
     * the unsigned metadata label stays. The credential's own issuer DID is checked again after issuance.
     */
    override suspend fun issuerTrust(issuer: IssuerMetadata): TrustDecision? {
        if (issuer.trust.tier.highlyTrusted) return null
        val listed = registeredIssuerTrust(issuer.credentialIssuer) ?: return null
        val unsigned = issuer.trust.labels.filter { it == TrustLabel.UNSIGNED_METADATA }
        return listed.copy(labels = listed.labels + unsigned)
    }

    override fun nonceFromError(error: JsonObject): String? = error.str("c_nonce")

    /**
     * TWDIW answers with {resp_code, resp_message} instead of an OAuth error_description. Keep these details without
     * inferring which validation checks passed: the deployed handler and downstream service can differ from the
     * older public implementation, including application authentication separate from the holder's proof.
     */
    override fun errorDetail(error: JsonObject): String? {
        val code = (error["resp_code"] as? JsonPrimitive)?.content?.takeIf { it.isNotBlank() } ?: return null
        val message = error.str("resp_message")?.trim()?.takeIf { it.isNotEmpty() && it != "null" }
        return "TWDIW resp_code $code" + (message?.let { " ($it)" } ?: "")
    }

    override fun proofStyle(issuer: IssuerMetadata, config: CredentialConfiguration): ProofStyle = ProofStyle(ProofKid.BARE_DID, clientId())

    override fun credentialRequest(issuer: IssuerMetadata, config: CredentialConfiguration, credentialIdentifier: String?, proofs: JsonObject?): JsonObject =
        buildJsonObject {
            put("credential_identifier", credentialIdentifier ?: config.id)
            proofs?.let { put("proofs", it) }
        }

    /**
     * TWDIW's ecosystem signature, as the official wallet adds it on the official partner-card platform: the
     * credential POST also carries a Twdiw-Signature header, an ES256 JWT over the SHA-256 of the exact outgoing
     * request bytes, bound to a one-time ecosystem nonce. The signature is produced with this wallet's own holder
     * key and this wallet's own application identity; this is interoperability with the published protocol shape,
     * not a copy of the official application's embedded key, which the wallet never has. Issuers outside
     * [ecosystemSignatureHosts] get no header, and a missing or failing ecosystem nonce endpoint leaves the request
     * unsigned rather than blocking issuance.
     */
    override suspend fun outboundCredentialHeaders(context: OutboundCredentialContext): Map<String, String>? {
        val host = runCatching { hostOf(context.issuer.credentialIssuer) }.getOrNull() ?: return null
        if (host !in ecosystemSignatureHosts()) return null
        val nonce = fetchEcosystemNonce(ecosystemBase(context.issuer)) ?: return null
        val identity = appIdentity()
        val jwt = signJws(
            buildJsonObject { put("typ", "JWT"); put("alg", "ES256"); put("kid", context.keyId) },
            buildJsonObject {
                put("bodyHash", DocCryptoUtil.hex(PlatformCrypto.sha256(context.requestBytes)))
                put("nonce", nonce)
                put("appHash", DocCryptoUtil.hex(PlatformCrypto.sha256(identity.appId.encodeToByteArray())))
                put("appVersion", identity.appVersion)
                put("appPlatform", identity.appPlatform)
                put("timestamp", Clock.System.now().toEpochMilliseconds().toString())
                put("keyId", context.keyId)
            },
            context.signingKey,
        )
        return mapOf(ECOSYSTEM_SIGNATURE_HEADER to jwt)
    }

    /** A fresh ecosystem nonce, or null when the endpoint is absent or does not answer with one. */
    private suspend fun fetchEcosystemNonce(base: String): String? = runCatching {
        val resp = httpClient.get(base.trimEnd('/') + "/api/ext/nonce/generate?type=ecosyst") {
            header(HttpHeaders.Accept, "application/json")
        }
        if (!resp.status.isSuccess()) return null
        val body = DiwJson.parseToJsonElement(resp.bodyAsText()) as? JsonObject ?: return null
        (body.obj("data") ?: body).str("nonce")?.takeIf { it.isNotBlank() }
    }.getOrNull()

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
        // Only the TWDIW shape (W3C credential under vc, no vct) is labelled TWDIW; an IETF SD-JWT VC whose iss is a
        // DID (walt.id and others) uses the same key lookup but follows no TWDIW specification.
        val twdiwShape = context.payload["vc"] != null && context.payload["vct"] == null
        return if (twdiwShape) DialectIssuerKey(key, "Issuer key comes from the issuer DID $iss (TWDIW)", "TWDIW")
        else DialectIssuerKey(key, "Issuer key comes from the issuer DID $iss", "")
    }

    companion object {
        const val ID = "twdiw"
        const val ENTRY_HINT = "twdiw"
        const val DEFAULT_CLIENT_ID = "moda_dw"
        const val ECOSYSTEM_SIGNATURE_HEADER = "Twdiw-Signature"

        /** Hosts of the TWDIW platform and its issuers and verifiers (wallet.gov.tw and subdomains). */
        fun isTwdiwHost(host: String): Boolean {
            val h = host.lowercase().trimEnd('.')
            return h == "wallet.gov.tw" || h.endsWith(".wallet.gov.tw")
        }

        /** The issuer's own scheme and authority, where the ecosystem nonce endpoint lives by default. */
        fun defaultEcosystemBase(credentialIssuer: String): String {
            val scheme = credentialIssuer.substringBefore("://", "https")
            val authority = credentialIssuer.substringAfter("://", credentialIssuer).substringBefore('/')
            return "$scheme://$authority"
        }
    }
}

/**
 * This wallet's own TWDIW ecosystem application identity. [appHash] in the signed payload is derived from [appId],
 * so these describe DIW, not the official application; no official-app key or identity is embedded.
 */
data class TwdiwAppIdentity(val appId: String, val appVersion: String, val appPlatform: String) {
    companion object {
        val DEFAULT = TwdiwAppIdentity(appId = "diw", appVersion = "0.1", appPlatform = "android")
    }
}
