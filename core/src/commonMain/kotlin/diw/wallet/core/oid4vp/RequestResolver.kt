package diw.wallet.core.oid4vp

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.queryParameters
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.util.toBase64Url
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.JsonWebEncryption

/** Entry hint of Microsoft Verified ID requests (openid-vc), matching MsVerifiedIdPresentationDialect.ENTRY_HINT. */
private const val MS_VERIFIED_ID_ENTRY = "msvid"

/**
 * Turns an OpenID4VP invocation (URI or DC API payload) into a [RawAuthorizationRequest].
 * It fetches request_uri, but performs no trust decisions; that is [RequestValidator]'s job.
 */
class RequestResolver(
    private val httpClient: HttpClient,
    private val policy: PresentationPolicy,
    private val allowInsecureLoopback: Boolean,
    /** Wallet-controlled, locally held ECDH-ES request-object keys (never verifier-supplied JWKs). */
    private val decryptionKeys: suspend () -> List<AsymmetricKey> = { emptyList() },
) {
    /** Schemes the wallet registers for OpenID4VP invocation. */
    val supportedSchemes = setOf("openid4vp", "haip-vp", "eudi-openid4vp", "mdoc-openid4vp", "https", "openid-vc", "openid", "siopv2")

    /** Parameters whose values are JSON in a request passed by value. */
    private val jsonParameters = setOf("dcql_query", "client_metadata", "presentation_definition", "claims", "registration")

    /** Resolves a URI invocation; [entryHint] names the profile whose entry point delivered it (twdiw). */
    suspend fun fromUri(uri: String, entryHint: String? = null): RawAuthorizationRequest {
        val scheme = uri.substringBefore(':', "").lowercase()
        if (scheme !in supportedSchemes) {
            throw RequestValidationException("invalid_request", "Unsupported invocation scheme '$scheme'")
        }
        @Suppress("NAME_SHADOWING")
        val entryHint = entryHint ?: if (scheme == "openid-vc") MS_VERIFIED_ID_ENTRY else null
        val q = queryParameters(uri)
        val outer = q.names().associateWith { q[it]!! }
        val clientId = outer["client_id"]
        val requestValue = outer["request"]
        val requestUri = outer["request_uri"]
        if (requestValue != null && requestUri != null) {
            throw RequestValidationException("invalid_request", "Both request and request_uri are present")
        }
        return when {
            requestUri != null -> {
                // OpenID4VP 1.0 and JAR need client_id beside request_uri. Microsoft Verified ID (openid-vc) sends only
                // request_uri; its client_id is in the signed request object, which the legacy validator requires.
                if (clientId == null && entryHint != MS_VERIFIED_ID_ENTRY) {
                    throw RequestValidationException("invalid_request", "client_id is required with request_uri")
                }
                val method = outer["request_uri_method"] ?: "get"
                val (jwt, walletNonce) = fetchRequestObject(requestUri, method)
                if (clientId == null && jwt.startsWith("{")) {
                    throw RequestValidationException("invalid_request", "client_id is required with an unsigned request_uri object")
                }
                // Some pre-1.0 verifiers serve the request as a plain JSON object rather than a JWT.
                if (jwt.startsWith("{")) {
                    RawAuthorizationRequest(RequestChannel.URI, outer, null, parseJsonObject(jwt, "invalid_request_uri"), null, walletNonce, entryHint = entryHint)
                } else {
                    val (jws, claims) = parseRequestObjectOrDecrypt(jwt)
                    RawAuthorizationRequest(RequestChannel.URI, outer, jws, claims, null, walletNonce, entryHint = entryHint)
                }
            }
            requestValue != null -> {
                if (clientId == null) throw RequestValidationException("invalid_request", "client_id is required with request")
                val (jws, claims) = parseRequestObjectOrDecrypt(requestValue)
                RawAuthorizationRequest(RequestChannel.URI, outer, jws, claims, null, null, entryHint = entryHint)
            }
            else -> {
                val params = buildJsonObject {
                    for ((k, v) in outer) {
                        val parsed: JsonElement = when (k) {
                            in jsonParameters -> try {
                                DiwJson.parseToJsonElement(v)
                            } catch (e: Exception) {
                                throw RequestValidationException("invalid_request", "$k is not valid JSON", cause = e)
                            }
                            "transaction_data", "verifier_info" -> try {
                                DiwJson.parseToJsonElement(v)
                            } catch (_: Exception) {
                                JsonPrimitive(v)
                            }
                            else -> JsonPrimitive(v)
                        }
                        put(k, parsed)
                    }
                }
                RawAuthorizationRequest(RequestChannel.URI, outer, null, params, null, null, entryHint = entryHint)
            }
        }
    }

    /**
     * Builds a request from a W3C Digital Credentials API invocation.
     * @param protocol e.g. openid4vp-v1-unsigned, openid4vp-v1-signed
     * @param data the request data member
     * @param callerOrigin the caller origin provided by the platform; a trailing slash is dropped (an origin has no path)
     */
    suspend fun fromDcApi(protocol: String, data: JsonObject, callerOrigin: String): RawAuthorizationRequest {
        if (protocol !in setOf("openid4vp-v1-unsigned", "openid4vp-v1-signed", "openid4vp-v1-multisigned")) {
            throw RequestValidationException("invalid_request", "Unsupported DC API protocol '$protocol'")
        }
        val origin = callerOrigin.removeSuffix("/")
        val request = data["request"]
        return when (protocol) {
            "openid4vp-v1-unsigned" -> {
                if (request != null || "payload" in data || "signatures" in data) {
                    throw RequestValidationException("invalid_request", "Unsigned DC API protocol cannot carry a signed request")
                }
                RawAuthorizationRequest(RequestChannel.DC_API, emptyMap(), null, data, origin, null, protocol)
            }
            "openid4vp-v1-signed" -> {
                val compact = (request as? JsonPrimitive)?.content
                    ?: throw RequestValidationException("invalid_request", "Signed DC API requires a compact JWS request")
                val jws = parseRequestObject(compact)
                RawAuthorizationRequest(RequestChannel.DC_API, emptyMap(), jws, jws.payload, origin, null, protocol)
            }
            else -> {
                val envelope = (request ?: data) as? JsonObject
                    ?: throw RequestValidationException("invalid_request", "Multi-signed request must use JWS JSON Serialization")
                if (envelope.keys.any { it !in setOf("payload", "signatures") }) {
                    throw RequestValidationException("invalid_request_object", "Unexpected members in a multi-signed request")
                }
                val payload = (envelope["payload"] as? JsonPrimitive)?.content
                    ?: throw RequestValidationException("invalid_request_object", "Missing JWS JSON payload")
                val signatures = envelope["signatures"] as? JsonArray
                    ?: throw RequestValidationException("invalid_request_object", "Missing JWS JSON signatures")
                if (signatures.isEmpty() || signatures.size > 8 ||
                    payload.length > policy.maxRequestObjectBytes
                ) throw RequestValidationException("invalid_request_object", "Multi-signed request exceeds supported bounds")
                val alternatives = signatures.map { entry ->
                    val signature = entry as? JsonObject
                        ?: throw RequestValidationException("invalid_request_object", "Invalid multi-signed signature")
                    if (signature.keys.any { it !in setOf("protected", "signature") }) {
                        throw RequestValidationException("invalid_request_object", "Unprotected JWS headers are not accepted")
                    }
                    val protected = (signature["protected"] as? JsonPrimitive)?.content
                        ?: throw RequestValidationException("invalid_request_object", "Missing protected JWS header")
                    val signatureValue = (signature["signature"] as? JsonPrimitive)?.content
                        ?: throw RequestValidationException("invalid_request_object", "Missing JWS signature")
                    val jws = parseRequestObject("$protected.$payload.$signatureValue")
                    val clientId = jws.header.str("client_id")
                        ?: throw RequestValidationException("invalid_request_object", "Each signature requires a protected client_id")
                    if ("client_id" in jws.payload || "verifier_info" in jws.payload) {
                        throw RequestValidationException("invalid_request_object", "Verifier identity must be in protected headers")
                    }
                    val claims = buildJsonObject {
                        jws.payload.forEach { (name, value) -> put(name, value) }
                        put("client_id", clientId)
                        jws.header["verifier_info"]?.let { put("verifier_info", it) }
                    }
                    RawAuthorizationRequest(RequestChannel.DC_API, emptyMap(), jws, claims, origin, null, protocol)
                }
                // Validator authenticates every candidate separately. Never treat the envelope as unsigned.
                alternatives.first().copy(multiSignedCandidates = alternatives)
            }
        }
    }

    /**
     * ECDH-ES decryption proves confidentiality to this wallet key, not the Verifier's identity.
     * Signed client prefixes must still authenticate with a JWS after request resolution.
     */
    private suspend fun parseRequestObjectOrDecrypt(input: String): Pair<Jws?, JsonObject> {
        if (input.count { it == '.' } != 4) {
            val jws = parseRequestObject(input)
            return jws to jws.payload
        }
        if (input.length > policy.maxRequestObjectBytes * 4) {
            throw RequestValidationException("invalid_request_object", "Encrypted request object is too large")
        }
        val keys = decryptionKeys()
        if (keys.isEmpty()) throw RequestValidationException(
            "invalid_request_object", "Encrypted Request Object requires a wallet-controlled registered decryption key"
        )
        for (key in keys.take(4)) {
            try {
                return null to JsonWebEncryption.decrypt(input, key)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                // Try another locally owned key. Never use a decryption key provided by the request.
            }
        }
        throw RequestValidationException("invalid_request_object", "Unable to decrypt request with registered wallet keys")
    }

    private fun parseRequestObject(jwt: String): Jws {
        if (jwt.count { it == '.' } == 4) {
            throw RequestValidationException("invalid_request_object", "Encrypted request objects are not supported")
        }
        val jws = try {
            Jws.parse(jwt)
        } catch (e: Exception) {
            throw RequestValidationException("invalid_request_object", "Request object is not a signed JWT: ${e.message}", cause = e)
        }
        return jws
    }

    private suspend fun fetchRequestObject(requestUri: String, method: String): Pair<String, String?> {
        if (!isAcceptableEndpoint(requestUri, allowInsecureLoopback)) {
            throw RequestValidationException("invalid_request_uri", "request_uri must use https")
        }
        // The request object type first; verifiers that serve the request as plain JSON (walt.id with the
        // redirect_uri prefix) answer 406 unless JSON is acceptable too.
        val accept = "application/oauth-authz-req+jwt, application/jwt;q=0.9, application/json;q=0.8, */*;q=0.1"
        var walletNonce: String? = null
        val resp: HttpResponse = when (method) {
            "get" -> httpClient.get(requestUri) { header(HttpHeaders.Accept, accept) }
            "post" -> {
                walletNonce = PlatformCrypto.randomBytes(16).toBase64Url()
                val nonce = walletNonce
                httpClient.submitForm(
                    url = requestUri,
                    formParameters = parameters {
                        append("wallet_metadata", walletMetadataJson().toString())
                        append("wallet_nonce", nonce)
                    }
                ) { header(HttpHeaders.Accept, accept) }
            }
            else -> throw RequestValidationException("invalid_request_uri_method", "Unsupported request_uri_method '$method'")
        }
        if (!resp.status.isSuccess()) {
            throw RequestValidationException("invalid_request_uri", "request_uri returned HTTP ${resp.status.value}")
        }
        val bytes = resp.bodyAsBytes()
        if (bytes.size > policy.maxRequestObjectBytes) {
            throw RequestValidationException("invalid_request_uri", "Request object too large (${bytes.size} bytes)")
        }
        val ct = resp.contentType()
        // Pre-1.0 verifiers serve request objects as application/jwt, text/plain or JSON; only HTML is certainly wrong.
        if (ct != null && ct.match(ContentType.Text.Html)) {
            throw RequestValidationException("invalid_request_uri", "Unexpected request object content type $ct")
        }
        return bytes.decodeToString().trim() to walletNonce
    }

    fun walletMetadataJson(): JsonObject = buildJsonObject {
        putJsonObject("vp_formats_supported") {
            for ((fmt, params) in WalletMetadata.vpFormatsSupported) {
                putJsonObject(fmt) {
                    for ((k, values) in params) {
                        putJsonArray(k) {
                            values.forEach { v -> if (v is Int) add(v) else add(v.toString()) }
                        }
                    }
                }
            }
        }
        putJsonArray("client_id_prefixes_supported") { WalletMetadata.clientIdPrefixesSupported.forEach { add(it) } }
        putJsonArray("response_modes_supported") { WalletMetadata.responseModesSupported.forEach { add(it) } }
        putJsonArray("response_types_supported") { WalletMetadata.responseTypesSupported.forEach { add(it) } }
        putJsonArray("request_object_signing_alg_values_supported") { WalletMetadata.requestObjectSigningAlgs.forEach { add(it) } }
        putJsonArray("authorization_encryption_alg_values_supported") { add("ECDH-ES") }
        putJsonArray("authorization_encryption_enc_values_supported") { add("A128GCM"); add("A256GCM") }
    }
}

internal fun JsonObject.verifierInfoEntries(): List<VerifierInfoEntry> {
    val arr = this["verifier_info"] as? JsonArray ?: return emptyList()
    return arr.mapNotNull { e ->
        val o = e as? JsonObject ?: return@mapNotNull null
        val format = o.str("format") ?: return@mapNotNull null
        val data = o["data"] ?: return@mapNotNull null
        val ids = (o["credential_ids"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content } ?: emptyList()
        VerifierInfoEntry(format, data, ids)
    }
}
