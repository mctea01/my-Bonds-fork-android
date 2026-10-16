package diw.testservers

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.jwkThumbprint
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.arr
import diw.wallet.core.util.long
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.URLBuilder
import io.ktor.http.parseQueryString
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.RawCbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import org.multipaz.revocation.RevocationStatus
import org.multipaz.revocation.StatusList
import org.multipaz.sdjwt.SdJwt
import org.multipaz.util.toBase64Url
import org.multipaz.util.truncateToWholeSeconds
import org.multipaz.webtoken.buildJwt
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

/** Behaviour switches for the test issuer, so tests can exercise each protocol branch. */
data class IssuerOptions(
    val dpopNonce: Boolean = true,
    val requireClientAttestation: Boolean = false,
    val requireClientAssertion: Boolean = false,
    val encryption: Boolean = true,
    val encryptionRequired: Boolean = false,
    val signedMetadata: Boolean = false,
    val batchSize: Int = 3,
    val requirePar: Boolean = true,
    /** Encrypts deferred responses to the key of the original credential request, as issuer.eudiw.dev does. */
    val deferredToOriginalKey: Boolean = false,
)

/** Error that maps to an OAuth error response. */
class IssuerError(
    val status: HttpStatusCode,
    val error: String,
    val description: String,
    val headers: Map<String, String> = emptyMap(),
) : Exception(description)

/** Server reply: status, body (JSON text, JWT or JWE) and extra headers. */
data class IssuerReply(
    val status: HttpStatusCode,
    val body: String,
    val contentType: String = "application/json",
    val headers: Map<String, String> = emptyMap(),
)

/**
 * OpenID4VCI 1.0 test Credential Issuer with a co-located authorization server (TEST environment).
 * Supports pre-authorized code (tx_code), authorization code with PKCE and PAR, DPoP with server nonces,
 * attestation-based client authentication, nonce endpoint, jwt proofs (with key_attestation) and attestation
 * proofs, batch issuance, request/response encryption, deferred issuance, notifications and Token Status List.
 */
class IssuerService(
    private val baseUrl: String,
    private val pki: TestPki,
    private val trust: TrustRegistry,
    val options: IssuerOptions = IssuerOptions(),
) {
    val issuerId = "$baseUrl/issuer"
    private val encKey = kotlinx.coroutines.runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val encKid = "enc-1"
    private val w3cKey = kotlinx.coroutines.runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val w3cKid = "w3c-1"
    @Volatile private var dpopNonce = PlatformCrypto.randomBytes(16).toBase64Url()

    private class PreAuth(val configIds: List<String>, val txCode: String?)
    private class ParRequest(val params: Parameters, val expires: Long)
    private class AuthCode(val clientId: String, val redirectUri: String, val challenge: String, val configIds: List<String>)
    private class TokenInfo(val configIds: List<String>, val jkt: String?, val identifiers: Map<String, String>, val expires: Long)
    private class DeferredTx(val credentials: JsonArray, var pollsLeft: Int, val encryption: JsonObject?)
    private class StatusListState(val bits: Int, val statuses: MutableMap<Int, Int> = ConcurrentHashMap(), var next: Int = 0)

    private val offers = ConcurrentHashMap<String, JsonObject>()
    private val preAuth = ConcurrentHashMap<String, PreAuth>()
    private val par = ConcurrentHashMap<String, ParRequest>()
    private val codes = ConcurrentHashMap<String, AuthCode>()
    private val tokens = ConcurrentHashMap<String, TokenInfo>()
    private val cNonces = ConcurrentHashMap<String, Long>()
    private val deferred = ConcurrentHashMap<String, DeferredTx>()
    private val statusLists = mapOf("sdjwt" to StatusListState(2), "mdoc" to StatusListState(1))
    private val usedJti = ConcurrentHashMap.newKeySet<String>()

    /** Notification events received, for assertions. */
    val notifications = java.util.Collections.synchronizedList(mutableListOf<JsonObject>())
    /** Status list index per issued credential (last issued first), for revocation tests. */
    val issuedStatus = java.util.Collections.synchronizedList(mutableListOf<Pair<String, Int>>())

    // ---------------------------------------------------------------- metadata

    private val acceptedStorage = listOf("iso_18045_basic", "iso_18045_moderate", "iso_18045_high")

    private fun jwtProof(attested: Boolean) = buildJsonObject {
        putJsonObject("jwt") {
            putJsonArray("proof_signing_alg_values_supported") { add("ES256") }
            if (attested) putJsonObject("key_attestations_required") {
                putJsonArray("key_storage") { acceptedStorage.forEach { add(it) } }
            }
        }
    }

    private fun sdJwtConfig(scope: String, name: String, proofs: JsonObject?) = buildJsonObject {
        put("format", "dc+sd-jwt")
        put("vct", EUPersonalID.EUPID_VCT)
        put("scope", scope)
        if (proofs != null) {
            putJsonArray("cryptographic_binding_methods_supported") { add("jwk") }
            putJsonArray("credential_signing_alg_values_supported") { add("ES256") }
            put("proof_types_supported", proofs)
        }
        putJsonObject("credential_metadata") {
            putJsonArray("display") {
                addJsonObject { put("name", name); put("locale", "zh-TW") }
                addJsonObject { put("name", "$name (test)"); put("locale", "en") }
            }
        }
    }

    val configurations: JsonObject = buildJsonObject {
        put("pid_sd_jwt", sdJwtConfig("pid", "測試身分憑證", jwtProof(false)))
        put("pid_sd_jwt_attested", sdJwtConfig("pid_attested", "測試身分憑證（金鑰證明）", jwtProof(true)))
        put("pid_sd_jwt_attestation_proof", sdJwtConfig("pid_attestation", "測試身分憑證（證明型）", buildJsonObject {
            putJsonObject("attestation") {
                putJsonArray("proof_signing_alg_values_supported") { add("ES256") }
                putJsonObject("key_attestations_required") { putJsonArray("key_storage") { acceptedStorage.forEach { add(it) } } }
            }
        }))
        put("pid_sd_jwt_deferred", sdJwtConfig("pid_deferred", "測試身分憑證（延遲）", jwtProof(false)))
        put("pid_sd_jwt_keyless", sdJwtConfig("pid_keyless", "測試身分憑證（無金鑰）", null))
        // Draft-era / W3C-style configuration (as TWDIW publishes): legacy media type, no vct, type list instead.
        put("w3c_sd_jwt_legacy", buildJsonObject {
            put("format", "vc+sd-jwt")
            put("scope", "w3c_legacy")
            putJsonObject("credential_definition") { putJsonArray("type") { add("VerifiableCredential"); add("TestCard") } }
            putJsonArray("cryptographic_binding_methods_supported") { add("jwk") }
            putJsonArray("credential_signing_alg_values_supported") { add("ES256") }
            put("proof_types_supported", jwtProof(false))
            putJsonArray("display") { addJsonObject { put("name", "測試卡（W3C 舊式）"); put("locale", "zh-TW") } }
        })
        // A format this wallet does not implement; wallets must list it as unsupported, not fail on the whole metadata.
        put("w3c_ldp_vc", buildJsonObject {
            put("format", "ldp_vc")
            putJsonObject("credential_definition") { putJsonArray("type") { add("VerifiableCredential"); add("TestCard") } }
        })
        put("mdl_mdoc", buildJsonObject {
            put("format", "mso_mdoc")
            put("doctype", DrivingLicense.MDL_DOCTYPE)
            put("scope", "mdl")
            putJsonArray("cryptographic_binding_methods_supported") { add("cose_key") }
            putJsonArray("credential_signing_alg_values_supported") { add(-7) }
            put("proof_types_supported", jwtProof(false))
            putJsonObject("credential_metadata") {
                putJsonArray("display") { addJsonObject { put("name", "測試行動駕照"); put("locale", "zh-TW") } }
            }
        })
    }

    suspend fun issuerMetadata(): JsonObject {
        val encJwk = encKey.publicKey.toJwk()
        return buildJsonObject {
            put("credential_issuer", issuerId)
            put("credential_endpoint", "$issuerId/credential")
            put("nonce_endpoint", "$issuerId/nonce")
            put("deferred_credential_endpoint", "$issuerId/deferred")
            put("notification_endpoint", "$issuerId/notification")
            putJsonObject("batch_credential_issuance") { put("batch_size", options.batchSize) }
            if (options.encryption) {
                putJsonObject("credential_request_encryption") {
                    putJsonObject("jwks") {
                        putJsonArray("keys") {
                            add(JsonObject(encJwk + mapOf("kid" to JsonPrimitive(encKid), "alg" to JsonPrimitive("ECDH-ES"), "use" to JsonPrimitive("enc"))))
                        }
                    }
                    putJsonArray("enc_values_supported") { add("A128GCM"); add("A256GCM") }
                    put("encryption_required", options.encryptionRequired)
                }
                putJsonObject("credential_response_encryption") {
                    putJsonArray("alg_values_supported") { add("ECDH-ES") }
                    putJsonArray("enc_values_supported") { add("A128GCM"); add("A256GCM") }
                    put("encryption_required", options.encryptionRequired)
                }
            }
            putJsonArray("display") { addJsonObject { put("name", "DIW 測試發行端"); put("locale", "zh-TW") } }
            put("credential_configurations_supported", configurations)
        }
    }

    suspend fun signedIssuerMetadata(): String? {
        if (!options.signedMetadata) return null
        val claims = issuerMetadata()
        return buildJwt(type = "openidvci-issuer-metadata+jwt", key = pki.documentSigner) {
            put("sub", issuerId)
            claims.forEach { (k, v) -> put(k, v) }
        }
    }

    fun authServerMetadata(): JsonObject = buildJsonObject {
        put("issuer", issuerId)
        put("authorization_endpoint", "$issuerId/authorize")
        put("token_endpoint", "$issuerId/token")
        put("pushed_authorization_request_endpoint", "$issuerId/par")
        put("require_pushed_authorization_requests", options.requirePar)
        putJsonArray("dpop_signing_alg_values_supported") { add("ES256") }
        putJsonArray("code_challenge_methods_supported") { add("S256") }
        putJsonArray("response_types_supported") { add("code") }
        putJsonArray("grant_types_supported") { add("authorization_code"); add("urn:ietf:params:oauth:grant-type:pre-authorized_code") }
        putJsonArray("token_endpoint_auth_methods_supported") {
            if (options.requireClientAssertion) add("private_key_jwt") else {
                add("attest_jwt_client_auth")
                if (!options.requireClientAttestation) add("none")
            }
        }
        put("pre-authorized_grant_anonymous_access_supported", !options.requireClientAttestation && !options.requireClientAssertion)
        put("authorization_response_iss_parameter_supported", true)
    }

    // ---------------------------------------------------------------- offers (test helper)

    fun createOffer(configIds: List<String>, grant: String, txCode: String?, byReference: Boolean): String {
        val unknown = configIds.filter { configurations[it] == null }
        require(unknown.isEmpty()) { "Unknown configurations $unknown" }
        val offer = buildJsonObject {
            put("credential_issuer", issuerId)
            putJsonArray("credential_configuration_ids") { configIds.forEach { add(it) } }
            putJsonObject("grants") {
                if (grant == "pre-authorized") {
                    val code = PlatformCrypto.randomBytes(16).toBase64Url()
                    preAuth[code] = PreAuth(configIds, txCode)
                    putJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code") {
                        put("pre-authorized_code", code)
                        if (txCode != null) putJsonObject("tx_code") {
                            put("input_mode", "numeric"); put("length", txCode.length); put("description", "請輸入簡訊中的驗證碼")
                        }
                    }
                } else {
                    putJsonObject("authorization_code") { put("issuer_state", PlatformCrypto.randomBytes(8).toBase64Url()) }
                }
            }
        }
        val b = URLBuilder("openid-credential-offer://")
        if (byReference) {
            val id = PlatformCrypto.randomBytes(12).toBase64Url()
            offers[id] = offer
            b.parameters.append("credential_offer_uri", "$issuerId/offers/$id")
        } else {
            b.parameters.append("credential_offer", offer.toString())
        }
        return b.buildString()
    }

    fun offer(id: String): JsonObject? = offers[id]

    // ---------------------------------------------------------------- authorization server

    private fun nonceHeaders() = mapOf("DPoP-Nonce" to dpopNonce, "Cache-Control" to "no-store")

    /** Verifies a DPoP proof and returns the JWK thumbprint. Throws [IssuerError] with use_dpop_nonce when needed. */
    private suspend fun verifyDpop(proof: String, method: String, url: String, accessToken: String?, resource: Boolean): String {
        val jws = try { Jws.parse(proof) } catch (e: Exception) { throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "Malformed DPoP") }
        if (jws.typ != "dpop+jwt") throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "typ")
        val jwk = jws.jwk ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "jwk missing")
        if (jwk.containsKey("d")) throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "private key in jwk")
        try { jws.verify(VerificationKey.fromJwk(jwk)) } catch (e: Exception) {
            throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "signature")
        }
        val p = jws.payload
        if (p.str("htm") != method || p.str("htu") != url) throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "htm/htu")
        val iat = p.long("iat") ?: 0
        if (kotlin.math.abs(Clock.System.now().epochSeconds - iat) > 300) throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "iat")
        val jti = p.str("jti") ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "jti")
        if (options.dpopNonce && p.str("nonce") != dpopNonce) {
            val status = if (resource) HttpStatusCode.Unauthorized else HttpStatusCode.BadRequest
            throw IssuerError(status, "use_dpop_nonce", "DPoP nonce required", mapOf(
                "DPoP-Nonce" to dpopNonce,
                "WWW-Authenticate" to "DPoP error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce in DPoP proof\"",
            ))
        }
        if (!usedJti.add(jti)) throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "jti replay")
        if (accessToken != null && p.str("ath") != PlatformCrypto.sha256(accessToken.encodeToByteArray()).toBase64Url()) {
            throw IssuerError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "ath")
        }
        return jwkThumbprint(jwk)
    }

    /** Attestation-based client authentication; returns the authenticated client_id or null when absent. */
    private suspend fun verifyClientAttestation(attestation: String?, pop: String?, clientId: String?): String? {
        if (attestation == null || pop == null) {
            if (options.requireClientAttestation) throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Client attestation required")
            return null
        }
        val att = Jws.parse(attestation)
        if (att.typ != "oauth-client-attestation+jwt") throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "attestation typ")
        val chain = att.x5c?.certificates ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "attestation x5c")
        trust.match(TrustRole.WALLET_PROVIDER, chain) ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "untrusted wallet provider")
        try { att.verify(VerificationKey.fromCertificate(chain.first())) } catch (e: Exception) {
            throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "attestation signature")
        }
        val claims = att.payload
        if ((claims.long("exp") ?: 0) < Clock.System.now().epochSeconds) throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "attestation expired")
        val sub = claims.str("sub")
        if (clientId != null && sub != clientId) throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "client_id mismatch")
        val cnf = claims.obj("cnf")?.obj("jwk") ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "cnf")
        val popJws = Jws.parse(pop)
        if (popJws.typ != "oauth-client-attestation-pop+jwt") throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "pop typ")
        try { popJws.verify(VerificationKey.fromJwk(cnf)) } catch (e: Exception) {
            throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "pop signature")
        }
        if (popJws.payload.str("aud") != issuerId) throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "pop aud")
        return sub
    }

    private suspend fun verifyClientAssertion(form: Parameters): String? {
        val assertion = form["client_assertion"]
        if (assertion == null) {
            if (options.requireClientAssertion) throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Client assertion required")
            return null
        }
        if (form["client_assertion_type"] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Invalid assertion type")
        val jwt = try { Jws.parse(assertion) } catch (e: Exception) {
            throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Invalid assertion JWT")
        }
        val chain = jwt.x5c?.certificates ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Certificate required")
        trust.match(TrustRole.WALLET_PROVIDER, chain)
            ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Untrusted assertion signer")
        try { jwt.verify(VerificationKey.fromCertificate(chain.first())) } catch (e: Exception) {
            throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Invalid assertion signature")
        }
        val claims = jwt.payload
        val id = form["client_id"]
        if (id == null || claims.str("iss") != id || claims.str("sub") != id ||
            claims.str("aud") != issuerId || (claims.long("exp") ?: 0) <= Clock.System.now().epochSeconds)
            throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Invalid assertion claims")
        val jti = claims.str("jti")
            ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Missing assertion jti")
        if (!usedJti.add("assertion:$jti"))
            throw IssuerError(HttpStatusCode.Unauthorized, "invalid_client", "Replayed assertion")
        return id
    }

    suspend fun pushedAuthorization(form: Parameters, headers: Map<String, String?>): IssuerReply {
        headers["DPoP"]?.let { verifyDpop(it, "POST", "$issuerId/par", null, resource = false) }
        verifyClientAttestation(headers["OAuth-Client-Attestation"], headers["OAuth-Client-Attestation-PoP"], form["client_id"])
        verifyClientAssertion(form)
        if (form["response_type"] != "code") throw IssuerError(HttpStatusCode.BadRequest, "invalid_request", "response_type")
        if (form["code_challenge_method"] != "S256" || form["code_challenge"] == null) {
            throw IssuerError(HttpStatusCode.BadRequest, "invalid_request", "PKCE S256 required")
        }
        if (form["redirect_uri"] == null || form["client_id"] == null) throw IssuerError(HttpStatusCode.BadRequest, "invalid_request", "client_id and redirect_uri required")
        val uri = "urn:ietf:params:oauth:request_uri:" + PlatformCrypto.randomBytes(16).toBase64Url()
        par[uri] = ParRequest(form, Clock.System.now().epochSeconds + 90)
        return IssuerReply(HttpStatusCode.Created, buildJsonObject { put("request_uri", uri); put("expires_in", 90) }.toString(), headers = nonceHeaders())
    }

    /** The test user approves immediately; returns the redirect Location. */
    fun authorize(query: Parameters): String {
        val params = query["request_uri"]?.let { ru ->
            val p = par.remove(ru) ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_request_uri", "Unknown or used request_uri")
            if (p.expires < Clock.System.now().epochSeconds) throw IssuerError(HttpStatusCode.BadRequest, "invalid_request_uri", "expired")
            if (p.params["client_id"] != query["client_id"]) throw IssuerError(HttpStatusCode.BadRequest, "invalid_request", "client_id mismatch")
            p.params
        } ?: if (options.requirePar) throw IssuerError(HttpStatusCode.BadRequest, "invalid_request", "PAR required") else query
        val configIds = requestedConfigurations(params)
        if (configIds.isEmpty()) throw IssuerError(HttpStatusCode.BadRequest, "invalid_scope", "No credential requested")
        val code = PlatformCrypto.randomBytes(16).toBase64Url()
        codes[code] = AuthCode(params["client_id"]!!, params["redirect_uri"]!!, params["code_challenge"]!!, configIds)
        return URLBuilder(params["redirect_uri"]!!).apply {
            parameters.append("code", code)
            params["state"]?.let { parameters.append("state", it) }
            parameters.append("iss", issuerId)
        }.buildString()
    }

    private fun requestedConfigurations(params: Parameters): List<String> {
        val fromDetails = params["authorization_details"]?.let { d ->
            (diw.wallet.core.util.DiwJson.parseToJsonElement(d) as JsonArray).filterIsInstance<JsonObject>()
                .filter { it.str("type") == "openid_credential" }.mapNotNull { it.str("credential_configuration_id") }
        }.orEmpty()
        val scopes = params["scope"]?.split(' ').orEmpty()
        val fromScope = configurations.filter { (_, v) -> (v as JsonObject).str("scope") in scopes }.keys
        return (fromDetails + fromScope).distinct().filter { configurations[it] != null }
    }

    suspend fun token(form: Parameters, headers: Map<String, String?>): IssuerReply {
        val jkt = headers["DPoP"]?.let { verifyDpop(it, "POST", "$issuerId/token", null, resource = false) }
        val authClient = verifyClientAssertion(form) ?: verifyClientAttestation(headers["OAuth-Client-Attestation"], headers["OAuth-Client-Attestation-PoP"], form["client_id"])
        val (configIds, identifiers) = when (form["grant_type"]) {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" -> {
                val code = form["pre-authorized_code"] ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_request", "pre-authorized_code")
                val g = preAuth[code] ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_grant", "Unknown pre-authorized_code")
                if (g.txCode != null && form["tx_code"] != g.txCode) throw IssuerError(HttpStatusCode.BadRequest, "invalid_grant", "Wrong tx_code")
                preAuth.remove(code)
                g.configIds to emptyMap<String, String>()
            }
            "authorization_code" -> {
                val c = codes.remove(form["code"] ?: "") ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_grant", "Unknown code")
                if (form["client_id"] != c.clientId || (authClient != null && authClient != c.clientId)) {
                    throw IssuerError(HttpStatusCode.BadRequest, "invalid_grant", "client mismatch")
                }
                if (form["redirect_uri"] != c.redirectUri) throw IssuerError(HttpStatusCode.BadRequest, "invalid_grant", "redirect_uri mismatch")
                val verifier = form["code_verifier"] ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_grant", "code_verifier")
                if (PlatformCrypto.sha256(verifier.encodeToByteArray()).toBase64Url() != c.challenge) {
                    throw IssuerError(HttpStatusCode.BadRequest, "invalid_grant", "PKCE verification failed")
                }
                c.configIds to c.configIds.associateBy { "$it#1" }
            }
            else -> throw IssuerError(HttpStatusCode.BadRequest, "unsupported_grant_type", "grant_type")
        }
        val token = PlatformCrypto.randomBytes(24).toBase64Url()
        tokens[token] = TokenInfo(configIds, jkt, identifiers, Clock.System.now().epochSeconds + 3600)
        val body = buildJsonObject {
            put("access_token", token)
            put("token_type", if (jkt != null) "DPoP" else "Bearer")
            put("expires_in", 3600)
            if (identifiers.isNotEmpty()) putJsonArray("authorization_details") {
                for (id in configIds) addJsonObject {
                    put("type", "openid_credential")
                    put("credential_configuration_id", id)
                    putJsonArray("credential_identifiers") { add("$id#1") }
                }
            }
        }
        return IssuerReply(HttpStatusCode.OK, body.toString(), headers = nonceHeaders())
    }

    // ---------------------------------------------------------------- credential endpoints

    fun nonce(): IssuerReply {
        val n = PlatformCrypto.randomBytes(18).toBase64Url()
        cNonces[n] = Clock.System.now().epochSeconds + 300
        return IssuerReply(HttpStatusCode.OK, buildJsonObject { put("c_nonce", n) }.toString(), headers = nonceHeaders())
    }

    private suspend fun authorizeResource(headers: Map<String, String?>, url: String): TokenInfo {
        val auth = headers["Authorization"] ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_token", "No access token")
        val scheme = auth.substringBefore(' ')
        val token = auth.substringAfter(' ')
        val info = tokens[token]?.takeIf { it.expires > Clock.System.now().epochSeconds }
            ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_token", "Unknown or expired token")
        if (info.jkt != null) {
            if (!scheme.equals("DPoP", true)) throw IssuerError(HttpStatusCode.Unauthorized, "invalid_token", "DPoP-bound token used as bearer")
            val proof = headers["DPoP"] ?: throw IssuerError(HttpStatusCode.Unauthorized, "invalid_dpop_proof", "DPoP proof missing")
            if (verifyDpop(proof, "POST", url, token, resource = true) != info.jkt) {
                throw IssuerError(HttpStatusCode.Unauthorized, "invalid_dpop_proof", "DPoP key does not match token binding")
            }
        }
        return info
    }

    private suspend fun readBody(body: String, contentType: String?): JsonObject {
        val isJwe = contentType?.startsWith("application/jwt") == true
        if (options.encryptionRequired && !isJwe) {
            throw IssuerError(HttpStatusCode.BadRequest, "invalid_encryption_parameters", "Encrypted request required")
        }
        return if (isJwe) {
            try {
                JsonWebEncryption.decrypt(body.trim(), AsymmetricKey.AnonymousExplicit(encKey, Algorithm.ECDH_P256))
            } catch (e: Exception) {
                throw IssuerError(HttpStatusCode.BadRequest, "invalid_encryption_parameters", "Cannot decrypt request")
            }
        } else diw.wallet.core.util.parseJsonObject(body)
    }

    private suspend fun reply(status: HttpStatusCode, json: JsonObject, request: JsonObject): IssuerReply {
        val enc = request.obj("credential_response_encryption")
        if (enc == null) {
            if (options.encryptionRequired) throw IssuerError(HttpStatusCode.BadRequest, "invalid_encryption_parameters", "Response encryption required")
            return IssuerReply(status, json.toString(), headers = nonceHeaders())
        }
        val jwk = enc.obj("jwk") ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_encryption_parameters", "jwk")
        val encAlg = Algorithm.fromJoseAlgorithmIdentifier(enc.str("enc") ?: "A128GCM")
        val jwe = JsonWebEncryption.encrypt(
            claimsSet = json,
            recipientPublicKey = EcPublicKey.fromJwk(jwk),
            encAlg = encAlg,
            apu = ByteString(PlatformCrypto.randomBytes(8)),
            apv = ByteString(PlatformCrypto.randomBytes(8)),
            kid = jwk.str("kid"),
        )
        return IssuerReply(status, jwe, "application/jwt", nonceHeaders())
    }

    suspend fun credential(body: String, contentType: String?, headers: Map<String, String?>): IssuerReply {
        val info = authorizeResource(headers, "$issuerId/credential")
        val req = readBody(body, contentType)
        val configId = req.str("credential_identifier")?.let { info.identifiers[it] ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_credential_request", "Unknown credential_identifier") }
            ?: req.str("credential_configuration_id")?.also {
                if (info.identifiers.isNotEmpty()) throw IssuerError(HttpStatusCode.BadRequest, "invalid_credential_request", "credential_identifier must be used")
            }
            ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_credential_request", "No credential requested")
        if (configId !in info.configIds) throw IssuerError(HttpStatusCode.BadRequest, "invalid_credential_request", "Not authorized for $configId")
        val config = configurations[configId] as JsonObject
        val keys = if (config.obj("proof_types_supported") == null) listOf(null) else holderKeys(config, req.obj("proofs"))
        if (keys.size > options.batchSize) throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "Batch size exceeded")
        val minted = keys.map { issueOne(config, it) }
        val credentials = buildJsonArray { minted.forEach { c -> addJsonObject { put("credential", c) } } }
        if (configId.endsWith("_deferred")) {
            val tx = PlatformCrypto.randomBytes(12).toBase64Url()
            deferred[tx] = DeferredTx(credentials, 1, req.obj("credential_response_encryption"))
            return reply(HttpStatusCode.Accepted, buildJsonObject { put("transaction_id", tx); put("interval", 1) }, req)
        }
        return reply(HttpStatusCode.OK, buildJsonObject {
            put("credentials", credentials)
            put("notification_id", PlatformCrypto.randomBytes(10).toBase64Url())
        }, req)
    }

    suspend fun deferredCredential(body: String, contentType: String?, headers: Map<String, String?>): IssuerReply {
        authorizeResource(headers, "$issuerId/deferred")
        val received = readBody(body, contentType)
        val tx = deferred[received.str("transaction_id") ?: ""]
            ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_transaction_id", "Unknown transaction_id")
        val req = if (options.deferredToOriginalKey && tx.encryption != null) {
            JsonObject(received + ("credential_response_encryption" to tx.encryption))
        } else received
        if (tx.pollsLeft > 0) {
            tx.pollsLeft--
            return reply(HttpStatusCode.Accepted, buildJsonObject { put("interval", 1) }, req)
        }
        deferred.remove(req.str("transaction_id"))
        return reply(HttpStatusCode.OK, buildJsonObject {
            put("credentials", tx.credentials)
            put("notification_id", PlatformCrypto.randomBytes(10).toBase64Url())
        }, req)
    }

    suspend fun notification(body: String, headers: Map<String, String?>): IssuerReply {
        authorizeResource(headers, "$issuerId/notification")
        val json = diw.wallet.core.util.parseJsonObject(body)
        if (json.str("notification_id") == null || json.str("event") !in setOf("credential_accepted", "credential_failure", "credential_deleted")) {
            throw IssuerError(HttpStatusCode.BadRequest, "invalid_notification_request", "notification_id and event required")
        }
        notifications += json
        return IssuerReply(HttpStatusCode.NoContent, "")
    }

    /** Verifies the proofs object and returns the holder keys to issue to. */
    private suspend fun holderKeys(config: JsonObject, proofs: JsonObject?): List<EcPublicKey> {
        if (proofs == null || proofs.size != 1) throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "Exactly one proof type is required")
        val types = config.obj("proof_types_supported")!!
        val result = mutableListOf<EcPublicKey>()
        val usedNonces = mutableSetOf<String>()
        proofs.arr("jwt")?.let { jwts ->
            val info = types.obj("jwt") ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "jwt proofs not accepted")
            val attestationRequired = info.obj("key_attestations_required") != null
            for (j in jwts) {
                val jws = Jws.parse((j as JsonPrimitive).content)
                if (jws.typ != "openid4vci-proof+jwt") throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "typ")
                val p = jws.payload
                if (p.str("aud") != issuerId) throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "aud")
                val nonce = p.str("nonce")
                if (nonce == null || (cNonces[nonce] ?: 0) < Clock.System.now().epochSeconds) {
                    throw IssuerError(HttpStatusCode.BadRequest, "invalid_nonce", "c_nonce missing or expired")
                }
                usedNonces += nonce
                val ka = jws.header.str("key_attestation")
                val keys = if (ka != null) verifyKeyAttestation(ka, null, info) else {
                    if (attestationRequired) throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "key_attestation required")
                    listOf(EcPublicKey.fromJwk(jws.jwk ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "jwk")))
                }
                val signer = keys.firstOrNull { k ->
                    runCatching { jws.verify(VerificationKey.Ec(k)); true }.getOrDefault(false)
                } ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "Proof signature does not match a presented key")
                result += if (ka != null) keys else listOf(signer)
            }
        } ?: proofs.arr("attestation")?.let { arr ->
            val info = types.obj("attestation") ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "attestation proofs not accepted")
            if (arr.size != 1) throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "One attestation expected")
            val ka = (arr.first() as JsonPrimitive).content
            val n = Jws.unverifiedPayload(ka).str("nonce")
            if (n == null || (cNonces[n] ?: 0) < Clock.System.now().epochSeconds) throw IssuerError(HttpStatusCode.BadRequest, "invalid_nonce", "nonce")
            usedNonces += n
            result += verifyKeyAttestation(ka, n, info)
        } ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "Unsupported proof type")
        usedNonces.forEach { cNonces.remove(it) }
        return result.distinct()
    }

    private suspend fun verifyKeyAttestation(jwt: String, nonce: String?, proofInfo: JsonObject): List<EcPublicKey> {
        val jws = Jws.parse(jwt)
        if (jws.typ != "key-attestation+jwt") throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "key attestation typ")
        val chain = jws.x5c?.certificates ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "key attestation x5c")
        trust.match(TrustRole.WALLET_PROVIDER, chain) ?: throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "untrusted wallet provider")
        try { jws.verify(VerificationKey.fromCertificate(chain.first())) } catch (e: Exception) {
            throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "key attestation signature")
        }
        val p = jws.payload
        if ((p.long("exp") ?: Long.MAX_VALUE) < Clock.System.now().epochSeconds) throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "key attestation expired")
        if (nonce != null && p.str("nonce") != nonce) throw IssuerError(HttpStatusCode.BadRequest, "invalid_nonce", "key attestation nonce")
        val accepted = proofInfo.obj("key_attestations_required")?.strList("key_storage").orEmpty()
        if (accepted.isNotEmpty() && p.strList("key_storage").none { it in accepted }) {
            throw IssuerError(HttpStatusCode.BadRequest, "invalid_proof", "key storage level not accepted")
        }
        return p.arr("attested_keys").orEmpty().map { EcPublicKey.fromJwk(it as JsonObject) }
    }

    // ---------------------------------------------------------------- credential minting and status

    private fun allocateStatus(list: String): Int {
        val s = statusLists.getValue(list)
        synchronized(s) { return s.next++ }
    }

    fun setStatus(list: String, idx: Int, status: Int) {
        statusLists.getValue(list).statuses[idx] = status
    }

    fun statusListUri(list: String) = "$issuerId/status/$list"

    suspend fun statusListJwt(list: String): String? {
        val s = statusLists[list] ?: return null
        val b = StatusList.Builder(s.bits)
        val size = maxOf(s.next, 16)
        for (i in 0 until size) b.addStatus(i, s.statuses[i] ?: 0)
        return b.build().compress(10.minutes).serializeAsJwt(pki.documentSigner, statusListUri(list))
    }

    /** Key set referenced by jku in W3C-style credentials. */
    suspend fun w3cKeys(): JsonObject {
        val jwk = JsonObject(w3cKey.publicKey.toJwk() + mapOf("kid" to JsonPrimitive(w3cKid)))
        return buildJsonObject { putJsonArray("keys") { add(jwk) } }
    }

    /** TWDIW-style SD-JWT: typ vc+sd-jwt, key via kid + jku, DID issuer, no vct, disclosures under vc.credentialSubject. */
    private suspend fun mintW3cSdJwt(holder: EcPublicKey): String {
        val now = Clock.System.now().epochSeconds
        val disclosures = listOf("name" to "林哲全", "cardNumber" to "A123").map { (k, v) ->
            buildJsonArray { add(PlatformCrypto.randomBytes(16).toBase64Url()); add(k); add(v) }.toString().encodeToByteArray().toBase64Url()
        }
        val digests = disclosures.map { Crypto.digest(Algorithm.SHA256, it.encodeToByteArray()).toBase64Url() }
        val holderJwk = holder.toJwk()
        val jwt = buildJwt(
            type = "vc+sd-jwt",
            key = AsymmetricKey.AnonymousExplicit(w3cKey, Algorithm.ES256),
            header = { put("kid", w3cKid); put("jku", "$issuerId/keys") },
        ) {
            put("iss", "did:example:diw-test-issuer")
            put("nbf", now)
            put("exp", now + 365L * 86400)
            putJsonObject("cnf") { put("jwk", holderJwk) }
            put("_sd_alg", "sha-256")
            putJsonObject("vc") {
                putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1") }
                putJsonArray("type") { add("VerifiableCredential"); add("TestCard") }
                putJsonObject("credentialSubject") {
                    putJsonArray("_sd") { digests.forEach { add(it) } }
                }
            }
        }
        return jwt + disclosures.joinToString("") { "~$it" } + "~"
    }

    private suspend fun issueOne(config: JsonObject, holder: EcPublicKey?): String {
        val now = Clock.System.now()
        if (config.str("scope") == "w3c_legacy") return mintW3cSdJwt(holder!!)
        return if (config.str("format") == "mso_mdoc") {
            val idx = allocateStatus("mdoc")
            issuedStatus.add(0, "mdoc" to idx)
            mintMdoc(holder!!, idx)
        } else {
            val idx = allocateStatus("sdjwt")
            issuedStatus.add(0, "sdjwt" to idx)
            SdJwt.create(
                issuerKey = pki.documentSigner,
                kbKey = holder,
                claims = buildJsonObject {
                    put("given_name", "哲全"); put("family_name", "林"); put("birthdate", "1990-01-01"); put("nationality", "TW")
                },
                nonSdClaims = buildJsonObject {
                    put("iss", issuerId)
                    put("vct", config.str("vct"))
                    put("iat", now.epochSeconds)
                    put("exp", (now + 365.days).epochSeconds)
                    putJsonObject("status") {
                        putJsonObject("status_list") { put("idx", idx); put("uri", statusListUri("sdjwt")) }
                    }
                },
            ).compactSerialization
        }
    }

    private suspend fun mintMdoc(holder: EcPublicKey, statusIdx: Int): String {
        val now = Clock.System.now().truncateToWholeSeconds()
        val ns = buildIssuerNamespaces {
            addNamespace(DrivingLicense.MDL_NAMESPACE) {
                addDataElement("given_name", Tstr("Che-Chuan"))
                addDataElement("family_name", Tstr("Lin"))
                addDataElement("age_over_18", Simple.TRUE)
                addDataElement("issuing_country", Tstr("TW"))
            }
        }
        val mso = MobileSecurityObject(
            version = "1.0", docType = DrivingLicense.MDL_DOCTYPE,
            signedAt = now, validFrom = now, validUntil = now + 365.days, expectedUpdate = null,
            digestAlgorithm = Algorithm.SHA256, valueDigests = ns.getValueDigests(Algorithm.SHA256),
            deviceKey = holder,
            revocationStatus = RevocationStatus.StatusList(statusIdx, statusListUri("mdoc"), null),
        )
        val tagged = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(mso.toDataItem()))))
        val prot = mapOf<CoseLabel, DataItem>(CoseNumberLabel(Cose.COSE_LABEL_ALG) to Algorithm.ES256.coseAlgorithmIdentifier!!.toDataItem())
        val unprot = mapOf<CoseLabel, DataItem>(CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN) to pki.documentSigner.certChain.toDataItem())
        val issuerAuth = Cbor.encode(Cose.coseSign1Sign(pki.documentSigner, tagged, true, prot, unprot).toDataItem())
        return Cbor.encode(buildCborMap {
            put("nameSpaces", ns.toDataItem())
            put("issuerAuth", RawCbor(issuerAuth))
        }).toBase64Url()
    }

    companion object {
        fun parseForm(text: String): Parameters = parseQueryString(text)
    }
}
