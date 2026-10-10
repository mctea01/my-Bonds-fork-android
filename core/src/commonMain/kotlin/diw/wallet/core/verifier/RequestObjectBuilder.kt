package diw.wallet.core.verifier

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.webtoken.buildJwt

/** Parameters of an OpenID4VP 1.0 authorization request created by a Verifier. */
data class VerifierRequestSpec(
    val clientId: String,
    val responseMode: String,
    val nonce: String,
    val dcqlQuery: JsonObject,
    val responseUri: String? = null,
    val state: String? = null,
    val encryptionKey: EcPrivateKey? = null,
    val encryptionKid: String = "enc-1",
    val encValues: List<String> = listOf("A128GCM", "A256GCM"),
    val expectedOrigins: List<String> = emptyList(),
    val verifierInfo: JsonArray? = null,
    val transactionData: List<String> = emptyList(),
    val walletNonce: String? = null,
    val audience: String? = "https://self-issued.me/v2",
    val extra: Map<String, JsonElement> = emptyMap(),
)

/** Creates request parameters and signed request objects (oauth-authz-req+jwt). Shared by the test Verifier and the wallet's verifier mode. */
object RequestObjectBuilder {
    suspend fun claims(spec: VerifierRequestSpec): JsonObject {
        val encJwk = spec.encryptionKey?.publicKey?.toJwk(buildJsonObject {
            put("kid", spec.encryptionKid)
            put("use", "enc")
            put("alg", "ECDH-ES")
        })
        return buildJsonObject {
        put("response_type", "vp_token")
        put("client_id", spec.clientId)
        put("response_mode", spec.responseMode)
        spec.responseUri?.let { put("response_uri", it) }
        put("nonce", spec.nonce)
        spec.state?.let { put("state", it) }
        put("dcql_query", spec.dcqlQuery)
        spec.audience?.let { put("aud", it) }
        spec.walletNonce?.let { put("wallet_nonce", it) }
        if (spec.expectedOrigins.isNotEmpty()) putJsonArray("expected_origins") { spec.expectedOrigins.forEach { add(it) } }
        if (spec.transactionData.isNotEmpty()) putJsonArray("transaction_data") { spec.transactionData.forEach { add(it) } }
        spec.verifierInfo?.let { put("verifier_info", it) }
        putJsonObject("client_metadata") {
            putJsonObject("vp_formats_supported") {
                putJsonObject("mso_mdoc") {
                    putJsonArray("issuerauth_alg_values") { add(-7); add(-9) }
                    putJsonArray("deviceauth_alg_values") { add(-7); add(-9) }
                }
                putJsonObject("dc+sd-jwt") {
                    putJsonArray("sd-jwt_alg_values") { add("ES256") }
                    putJsonArray("kb-jwt_alg_values") { add("ES256") }
                }
            }
            encJwk?.let { jwk ->
                putJsonObject("jwks") {
                    putJsonArray("keys") { add(jwk) }
                }
                putJsonArray("encrypted_response_enc_values_supported") { spec.encValues.forEach { add(it) } }
            }
        }
        for ((k, v) in spec.extra) put(k, v)
        }
    }

    /** Signs the request with [key]: X.509 keys produce an x5c header, named keys a kid header. */
    suspend fun sign(spec: VerifierRequestSpec, key: AsymmetricKey, extraHeader: Map<String, JsonElement> = emptyMap()): String {
        val claims = claims(spec)
        return buildJwt(
            type = "oauth-authz-req+jwt",
            key = key,
            header = { for ((k, v) in extraHeader) put(k, v) },
        ) {
            for ((k, v) in claims) put(k, v)
        }
    }
}
