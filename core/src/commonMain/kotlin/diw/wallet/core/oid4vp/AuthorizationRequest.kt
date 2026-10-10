package diw.wallet.core.oid4vp

import diw.wallet.core.jose.Jws
import diw.wallet.core.trust.TrustDecision
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.X509CertChain

/** How the request reached the wallet. */
enum class RequestChannel {
    /** Same-device or cross-device URI (QR code, deep link, pasted link). */
    URI,
    /** W3C Digital Credentials API (Android Credential Manager). */
    DC_API,
}

enum class ResponseMode(val wire: String, val encrypted: Boolean, val dcApi: Boolean) {
    DIRECT_POST("direct_post", false, false),
    DIRECT_POST_JWT("direct_post.jwt", true, false),
    DC_API("dc_api", false, true),
    DC_API_JWT("dc_api.jwt", true, true);

    companion object {
        fun fromWire(w: String?): ResponseMode? = entries.firstOrNull { it.wire == w }
    }
}

/** Raw request as obtained from the transport, before any validation. */
data class RawAuthorizationRequest(
    val channel: RequestChannel,
    /** Parameters outside the request object (URI query or DC API data members). */
    val outer: Map<String, String>,
    /** Signed request object, when the request was passed by value or reference as a JWT. */
    val requestObject: Jws?,
    /** Effective request parameters: request object claims for signed requests, outer parameters otherwise. */
    val params: JsonObject,
    /** Origin of the caller for DC API requests (web origin or android:apk-key-hash:...). */
    val origin: String?,
    /** wallet_nonce sent with request_uri_method=post, to be matched against the request object. */
    val walletNonce: String?,
    /** The DC API protocol identifier, e.g. openid4vp-v1-signed. */
    val dcApiProtocol: String? = null,
)

/** Identity of the Verifier as established by the request validation layer. */
data class VerifierIdentityInfo(
    val clientId: ClientId,
    /** client_id the response must be bound to (KB-JWT aud, mdoc handover). */
    val effectiveClientId: String,
    val displayName: String,
    val certificateChain: X509CertChain?,
    val dnsNames: List<String>,
    val did: String?,
    val trust: TrustDecision,
)

/** One verifier_info entry (OpenID4VP 1.0 section 5.11), kept verbatim for the verifier transparency layer. */
data class VerifierInfoEntry(val format: String, val data: kotlinx.serialization.json.JsonElement, val credentialIds: List<String>)

/** A request that passed the wallet's request validation layer. */
data class ValidatedAuthorizationRequest(
    val raw: RawAuthorizationRequest,
    val verifier: VerifierIdentityInfo,
    val responseMode: ResponseMode,
    val responseUri: String?,
    val nonce: String,
    val state: String?,
    val dcqlQuery: JsonObject,
    val transactionData: List<String>,
    val clientMetadata: JsonObject?,
    val verifierInfo: List<VerifierInfoEntry>,
    val expectedOrigins: List<String>,
    val warnings: List<String>,
) {
    val origin: String? get() = raw.origin
}

/** Validation failure. [canNotifyVerifier] is true only when the Verifier was authenticated, so an error response is safe to send. */
class RequestValidationException(
    code: String,
    message: String,
    val canNotifyVerifier: Boolean = false,
    val responseUri: String? = null,
    val state: String? = null,
    cause: Throwable? = null,
) : diw.wallet.core.util.ProtocolException(code, message, cause)

internal fun JsonObject.transactionDataStrings(): List<String> =
    (this["transaction_data"] as? JsonArray)?.map {
        (it as? kotlinx.serialization.json.JsonPrimitive)?.content
            ?: throw RequestValidationException("invalid_request", "transaction_data entries must be strings")
    } ?: emptyList()
