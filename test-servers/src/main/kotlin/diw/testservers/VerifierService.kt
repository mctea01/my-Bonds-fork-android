package diw.testservers

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.verifier.CheckStatus
import diw.wallet.core.verifier.PresentationVerification
import diw.wallet.core.verifier.PresentationVerifier
import diw.wallet.core.verifier.RequestObjectBuilder
import diw.wallet.core.verifier.VerifierRequestSpec
import diw.wallet.core.verifier.VerifierSession
import diw.wallet.core.x509.x509Hash
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.util.toBase64Url
import org.multipaz.webtoken.buildJwt
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.days

/** What a test session should exercise. */
data class VerifierSessionRequest(
    val clientIdPrefix: String = "x509_san_dns",
    val responseMode: String = "direct_post.jwt",
    val requestUriMethod: String = "get",
    val dcql: JsonObject = VerifierService.DEFAULT_DCQL,
    /** Test knobs that deliberately break the request, to exercise wallet rejections. */
    val tamper: String? = null,
)

class StoredVerifierSession(
    val id: String,
    val session: VerifierSession,
    val spec: VerifierRequestSpec,
    val prefix: String,
    val requestUriMethod: String,
    val tamper: String?,
    @Volatile var result: PresentationVerification? = null,
)

/**
 * Multi-prefix OpenID4VP 1.0 test Verifier (profile std-haip). Requests are served by reference;
 * responses are verified with the same core verifier the wallet uses in verifier mode.
 */
class VerifierService(
    private val baseUrl: String,
    private val pki: TestPki,
    private val verifier: PresentationVerifier,
) {
    private val sessions = ConcurrentHashMap<String, StoredVerifierSession>()
    private val host = Url(baseUrl).host
    private val didKey = kotlinx.coroutines.runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val attestedKey = kotlinx.coroutines.runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }

    fun session(id: String): StoredVerifierSession? = sessions[id]

    /** Creates a session and returns the wallet invocation URI. */
    suspend fun create(req: VerifierSessionRequest): Pair<StoredVerifierSession, String> {
        val id = PlatformCrypto.randomBytes(12).toBase64Url()
        val responseUri = "$baseUrl/verifier/responses/$id"
        val encKey = if (req.responseMode.endsWith(".jwt")) Crypto.createEcPrivateKey(EcCurve.P256) else null
        val clientId = clientIdFor(req.clientIdPrefix, responseUri)
        val spec = VerifierRequestSpec(
            clientId = clientId,
            responseMode = req.responseMode,
            nonce = PlatformCrypto.randomBytes(24).toBase64Url(),
            dcqlQuery = req.dcql,
            responseUri = when (req.tamper) {
                "foreign_response_uri" -> "https://attacker.example/responses/$id"
                else -> responseUri
            },
            state = PlatformCrypto.randomBytes(12).toBase64Url(),
            encryptionKey = encKey,
        )
        val stored = StoredVerifierSession(
            id = id,
            session = VerifierSession(spec.nonce, clientId, spec.responseMode, spec.dcqlQuery, responseUri, spec.state, encKey),
            spec = spec,
            prefix = req.clientIdPrefix,
            requestUriMethod = req.requestUriMethod,
            tamper = req.tamper,
        )
        sessions[id] = stored
        val outerClientId = if (req.tamper == "outer_client_id_mismatch") "x509_san_dns:evil.example" else clientId
        val uri = if (req.clientIdPrefix == "redirect_uri") {
            URLBuilder("openid4vp://").apply {
                for ((k, v) in RequestObjectBuilder.claims(spec.copy(audience = null))) {
                    parameters.append(k, if (v is JsonPrimitive && v.isString) v.content else v.toString())
                }
            }.buildString()
        } else {
            URLBuilder("openid4vp://").apply {
                parameters.append("client_id", outerClientId)
                parameters.append("request_uri", "$baseUrl/verifier/requests/$id")
                if (req.requestUriMethod == "post") parameters.append("request_uri_method", "post")
            }.buildString()
        }
        return stored to uri
    }

    private suspend fun clientIdFor(prefix: String, responseUri: String): String = when (prefix) {
        "x509_san_dns" -> "x509_san_dns:$host"
        "x509_hash" -> "x509_hash:" + pki.readerKey(host).certChain.certificates.first().x509Hash()
        "redirect_uri" -> "redirect_uri:$responseUri"
        "decentralized_identifier" -> "decentralized_identifier:" + didJwk()
        "verifier_attestation" -> "verifier_attestation:diw-test-verifier"
        else -> throw IllegalArgumentException("Unsupported prefix $prefix")
    }

    private suspend fun didJwk(): String =
        "did:jwk:" + didKey.publicKey.toJwk().toString().encodeToByteArray().toBase64Url()

    /** Signed request object for request_uri (GET, or POST with wallet_nonce). */
    suspend fun requestObject(id: String, walletNonce: String?): String {
        val s = sessions[id] ?: throw NoSuchElementException(id)
        val spec = s.spec.copy(walletNonce = walletNonce)
        return when (s.prefix) {
            "x509_san_dns", "x509_hash" -> {
                val key = when (s.tamper) {
                    "san_mismatch" -> pki.readerKey("evil.example")
                    else -> pki.readerKey(host)
                }
                val signed = RequestObjectBuilder.sign(spec, key)
                if (s.tamper == "bad_signature") signed.dropLast(4) + "AAAA" else signed
            }
            "decentralized_identifier" -> {
                val did = didJwk()
                RequestObjectBuilder.sign(spec, AsymmetricKey.NamedExplicit("$did#0", didKey))
            }
            "verifier_attestation" -> {
                val attIssuer = pki.readerKey("attestation.$host")
                val attJwk = attestedKey.publicKey.toJwk()
                val att = buildJwt(type = "verifier-attestation+jwt", key = attIssuer, expiresIn = 1.days) {
                    put("iss", "DIW Test Verifier Attestation Issuer")
                    put("sub", "diw-test-verifier")
                    put("name", "DIW Test Verifier (attested)")
                    putJsonObject("cnf") { put("jwk", attJwk) }
                    putJsonArray("redirect_uris") { add(s.session.responseUri) }
                }
                RequestObjectBuilder.sign(spec, AsymmetricKey.anonymous(attestedKey), mapOf("jwt" to JsonPrimitive(att)))
            }
            else -> throw IllegalStateException("No request object for ${s.prefix}")
        }
    }

    suspend fun receive(id: String, form: Map<String, String>): PresentationVerification {
        val s = sessions[id] ?: throw NoSuchElementException(id)
        val r = verifier.verifyDirectPost(form, s.session)
        s.result = r
        return r
    }

    /** DC API request (data member) for [origin]; signed requests carry expected_origins. */
    suspend fun createDcApi(origin: String, signed: Boolean, encrypted: Boolean, dcql: JsonObject = DEFAULT_DCQL): Triple<StoredVerifierSession, String, JsonObject> {
        val id = PlatformCrypto.randomBytes(12).toBase64Url()
        val encKey = if (encrypted) Crypto.createEcPrivateKey(EcCurve.P256) else null
        val clientId = "x509_san_dns:$host"
        val spec = VerifierRequestSpec(
            clientId = clientId,
            responseMode = if (encrypted) "dc_api.jwt" else "dc_api",
            nonce = PlatformCrypto.randomBytes(24).toBase64Url(),
            dcqlQuery = dcql,
            encryptionKey = encKey,
            expectedOrigins = listOf(origin),
            audience = null,
        )
        val stored = StoredVerifierSession(id, VerifierSession(spec.nonce, clientId, spec.responseMode, dcql, null, null, encKey, origin), spec, "x509_san_dns", "dc_api", null)
        sessions[id] = stored
        return if (signed) {
            Triple(stored, "openid4vp-v1-signed", buildJsonObject { put("request", RequestObjectBuilder.sign(spec, pki.readerKey(host))) })
        } else {
            val claims = RequestObjectBuilder.claims(spec)
            Triple(stored, "openid4vp-v1-unsigned", JsonObject(claims.filterKeys { it != "client_id" && it != "expected_origins" }))
        }
    }

    suspend fun receiveDcApi(id: String, data: JsonObject, origin: String): PresentationVerification {
        val s = sessions[id] ?: throw NoSuchElementException(id)
        val r = verifier.verifyDcApi(data, s.session, origin)
        s.result = r
        return r
    }

    companion object {
        val DEFAULT_DCQL: JsonObject = DiwJson.parseToJsonElement(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
              "claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}
            """.trimIndent()
        ) as JsonObject

        fun resultJson(r: PresentationVerification?): JsonObject = buildJsonObject {
            if (r == null) { put("status", "pending"); return@buildJsonObject }
            put("status", if (r.passed) "passed" else if (r.error != null) "error" else "not_passed")
            put("test_environment", r.testEnvironmentOnly)
            r.error?.let { put("error", it) }
            r.errorDescription?.let { put("error_description", it) }
            put("session_checks", buildJsonArray {
                r.sessionChecks.forEach { c -> add(buildJsonObject { put("name", c.name); put("status", c.status.name); put("detail", c.detail) }) }
            })
            put("credentials", buildJsonArray {
                r.credentials.forEach { c ->
                    add(buildJsonObject {
                        put("id", c.queryId); put("format", c.format); put("type", c.typeName); put("passed", c.passed)
                        put("issuer_trust_tier", c.issuerTrust.tier.name)
                        put("issuer_environment", c.issuerTrust.environment?.id)
                        putJsonObject("claims") { c.claims.forEach { (k, v) -> put(k, v) } }
                        put("checks", JsonArray(c.checks.map { ch ->
                            buildJsonObject { put("name", ch.name); put("status", ch.status.name); put("detail", ch.detail) }
                        }))
                    })
                }
            })
        }

        fun CheckStatus.isOk() = this == CheckStatus.PASS
    }
}
