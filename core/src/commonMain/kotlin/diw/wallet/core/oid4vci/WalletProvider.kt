package diw.wallet.core.oid4vci

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.long
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.reqStr
import io.ktor.client.HttpClient
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.securearea.KeyAttestation
import org.multipaz.util.toBase64
import org.multipaz.util.toBase64Url
import org.multipaz.webtoken.buildJwt
import kotlin.time.Clock

/** A wallet instance attestation (oauth-client-attestation+jwt) and the key it is bound to (cnf). */
data class WalletAttestation(val jwt: String, val instanceKey: AsymmetricKey) {
    val expiresAt: Long? get() = runCatching { Jws.unverifiedPayload(jwt).long("exp") }.getOrNull()
}

/**
 * Wallet provider back end. Issuers that require wallet or key attestation trust the provider,
 * and the provider vouches for this wallet instance and its keys.
 */
interface WalletProvider {
    val clientId: String

    /** Returns a fresh-enough wallet attestation, or null when this wallet has none (public client). */
    suspend fun walletAttestation(): WalletAttestation?

    /**
     * Returns a key-attestation+jwt covering [keys], or null when unavailable.
     * [nonce] is the issuer c_nonce; [userAuthentication] states whether the keys require user verification.
     */
    suspend fun keyAttestation(keys: List<KeyAttestation>, nonce: String?, userAuthentication: Boolean): String?
}

/** No back end: a plain public client. Works with issuers that need neither wallet nor key attestation. */
class PublicClientWalletProvider(override val clientId: String) : WalletProvider {
    override suspend fun walletAttestation(): WalletAttestation? = null
    override suspend fun keyAttestation(keys: List<KeyAttestation>, nonce: String?, userAuthentication: Boolean): String? = null
}

/**
 * Talks to a DIW wallet provider service:
 * POST {base}/wallet-attestation {client_id, jwk, x5c?} -> {wallet_attestation}
 * POST {base}/key-attestation {nonce?, user_authentication, keys:[{jwk, x5c?}]} -> {key_attestation}
 * x5c carries the platform key attestation chain (Android Keystore) when the platform has one.
 */
class RemoteWalletProvider(
    private val httpClient: HttpClient,
    private val baseUrl: String,
    override val clientId: String,
    private val instanceKey: AsymmetricKey,
    private val instanceKeyAttestation: KeyAttestation?,
    allowInsecureLoopback: Boolean,
) : WalletProvider {
    private var cached: WalletAttestation? = null

    init {
        require(isAcceptableEndpoint(baseUrl, allowInsecureLoopback)) { "Wallet provider URL must be https" }
    }

    override suspend fun walletAttestation(): WalletAttestation {
        cached?.let { c ->
            val exp = c.expiresAt
            if (exp == null || exp - 60 > Clock.System.now().epochSeconds) return c
        }
        val jwk = instanceKey.publicKey.toJwk()
        val body = buildJsonObject {
            put("client_id", clientId)
            put("jwk", jwk)
            instanceKeyAttestation?.certChain?.let { chain ->
                putJsonArray("x5c") { chain.certificates.forEach { add(it.encoded.toByteArray().toBase64()) } }
            }
        }
        val resp = postJson("$baseUrl/wallet-attestation", body)
        return WalletAttestation(resp.reqStr("wallet_attestation"), instanceKey).also { cached = it }
    }

    override suspend fun keyAttestation(keys: List<KeyAttestation>, nonce: String?, userAuthentication: Boolean): String {
        val jwks = keys.map { it.publicKey.toJwk() }
        val body = buildJsonObject {
            nonce?.let { put("nonce", it) }
            put("user_authentication", userAuthentication)
            putJsonArray("keys") {
                for ((k, jwk) in keys.zip(jwks)) addJsonObject {
                    put("jwk", jwk)
                    k.certChain?.let { chain ->
                        putJsonArray("x5c") { chain.certificates.forEach { add(it.encoded.toByteArray().toBase64()) } }
                    }
                }
            }
        }
        return postJson("$baseUrl/key-attestation", body).reqStr("key_attestation")
    }

    private suspend fun postJson(url: String, body: JsonObject): JsonObject {
        val resp = httpClient.post(url) {
            contentType(ContentType.Application.Json)
            setBody(body.toString())
        }
        val text = resp.bodyAsText()
        if (!resp.status.isSuccess()) {
            throw ProtocolException("wallet_provider_error", "Wallet provider returned ${resp.status.value}: $text")
        }
        return parseJsonObject(text, "wallet_provider_error")
    }
}

/** Builds OAuth-Client-Attestation-PoP (draft-ietf-oauth-attestation-based-client-auth). */
suspend fun clientAttestationPop(attestation: WalletAttestation, clientId: String, audience: String, challenge: String?): String =
    buildJwt(type = "oauth-client-attestation-pop+jwt", key = attestation.instanceKey) {
        put("iss", clientId)
        put("aud", audience)
        put("jti", PlatformCrypto.randomBytes(16).toBase64Url())
        challenge?.let { put("challenge", it) }
    }
