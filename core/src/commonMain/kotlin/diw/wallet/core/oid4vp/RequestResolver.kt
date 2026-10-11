package diw.wallet.core.oid4vp

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.parseJsonObject
import diw.wallet.core.util.queryParameters
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.ContentType
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
                    val jws = parseRequestObject(jwt)
                    RawAuthorizationRequest(RequestChannel.URI, outer, jws, jws.payload, null, walletNonce, entryHint = entryHint)
                }
            }
            requestValue != null -> {
                if (clientId == null) throw RequestValidationException("invalid_request", "client_id is required with request")
                val jws = parseRequestObject(requestValue)
                RawAuthorizationRequest(RequestChannel.URI, outer, jws, jws.payload, null, null, entryHint = entryHint)
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
    fun fromDcApi(protocol: String, data: JsonObject, callerOrigin: String): RawAuthorizationRequest {
        if (protocol !in setOf("openid4vp-v1-unsigned", "openid4vp-v1-signed", "openid4vp-v1-multisigned")) {
            throw RequestValidationException("invalid_request", "Unsupported DC API protocol '$protocol'")
        }
        val origin = callerOrigin.removeSuffix("/")
        val signed = data["request"]
        return if (signed != null) {
            val jwt = (signed as? JsonPrimitive)?.content
                ?: throw RequestValidationException("invalid_request", "DC API request member is not a string")
            val jws = parseRequestObject(jwt)
            RawAuthorizationRequest(RequestChannel.DC_API, emptyMap(), jws, jws.payload, origin, null, protocol)
        } else {
            if (protocol == "openid4vp-v1-signed") {
                throw RequestValidationException("invalid_request", "Signed DC API protocol without request object")
            }
            if (protocol == "openid4vp-v1-multisigned") {
                throw RequestValidationException("invalid_request", "Multi-signed DC API requests are not supported")
            }
            RawAuthorizationRequest(RequestChannel.DC_API, emptyMap(), null, data, origin, null, protocol)
        }
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
        val reqObjType = ContentType("application", "oauth-authz-req+jwt")
        var walletNonce: String? = null
        val resp: HttpResponse = when (method) {
            "get" -> httpClient.get(requestUri) { accept(reqObjType) }
            "post" -> {
                walletNonce = PlatformCrypto.randomBytes(16).toBase64Url()
                val nonce = walletNonce
                httpClient.submitForm(
                    url = requestUri,
                    formParameters = parameters {
                        append("wallet_metadata", walletMetadataJson().toString())
                        append("wallet_nonce", nonce)
                    }
                ) { accept(reqObjType) }
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
