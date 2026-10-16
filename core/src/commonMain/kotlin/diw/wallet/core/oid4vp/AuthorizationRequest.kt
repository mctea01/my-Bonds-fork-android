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

enum class ResponseMode(val wire: String, val encrypted: Boolean, val dcApi: Boolean, val standard: Boolean = true) {
    DIRECT_POST("direct_post", false, false),
    DIRECT_POST_JWT("direct_post.jwt", true, false),
    DC_API("dc_api", false, true),
    DC_API_JWT("dc_api.jwt", true, true),
    /** OAuth 2.0 response modes used by pre-1.0 drafts and SIOPv2: parameters in the redirect_uri fragment or query. */
    FRAGMENT("fragment", false, false, standard = false),
    QUERY("query", false, false, standard = false),
    /** Form post to redirect_uri (OAuth form_post; Microsoft Verified ID sends "post"). */
    FORM_POST("form_post", false, false, standard = false),
    POST("post", false, false, standard = false);

    /** True for modes that deliver to the Verifier by an HTTP POST from the wallet. */
    val posted: Boolean get() = this == DIRECT_POST || this == DIRECT_POST_JWT || this == FORM_POST || this == POST

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
    /** Profile whose entry point delivered the request (twdiw for the modadigitalwallet scheme). */
    val entryHint: String? = null,
    /** Verified separately: JWS JSON Serialization offers alternative verifier identities. */
    val multiSignedCandidates: List<RawAuthorizationRequest> = emptyList(),
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
    /** Presentation Exchange definition of a pre-1.0 request (instead of [dcqlQuery], which is then empty). */
    val presentationDefinition: JsonObject? = null,
    /** response_type values; vp_token for OpenID4VP 1.0, id_token or both for SIOPv2 and pre-1.0 drafts. */
    val responseTypes: Set<String> = setOf("vp_token"),
    /** redirect_uri for fragment, query and post response modes. */
    val redirectUri: String? = null,
    /** Profile that owns the request (twdiw, msvid) or the legacy draft it follows (legacy); null for OpenID4VP 1.0. */
    val profile: String? = null,
    /** Specifications followed besides OpenID4VP 1.0, shown with the consent screen. */
    val specs: List<String> = emptyList(),
) {
    val origin: String? get() = raw.origin

    /** True when the request needs the wallet's own engine (pre-1.0, SIOP, profile requests). */
    val isLegacy: Boolean get() = profile != null || presentationDefinition != null || responseTypes != setOf("vp_token") || !responseMode.standard

    /** Where the response goes: response_uri for direct_post, redirect_uri otherwise. */
    val target: String? get() = responseUri ?: redirectUri
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
