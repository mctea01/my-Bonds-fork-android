package diw.wallet.core.oid4vp.compat

import diw.wallet.core.holder.HolderKey
import diw.wallet.core.oid4vp.ConsentTerms
import diw.wallet.core.oid4vp.RawAuthorizationRequest
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.ext.WalletCredential
import diw.wallet.core.trust.TrustDecision
import kotlinx.serialization.json.JsonObject

/** Credentials going into one verifiable presentation, all bound to [holder]. */
data class VpInput(
    val request: ValidatedAuthorizationRequest,
    val holder: HolderKey,
    /** Each credential as it will be embedded (SD-JWTs already reduced to the chosen disclosures). */
    val credentials: List<Pair<WalletCredential, String>>,
)

/**
 * Presentation behaviour of a profile outside OpenID4VP 1.0 (TWDIW, Microsoft Verified ID). Like issuance dialects,
 * a presentation dialect is always on, never changes requests it does not own, and every response built through it
 * records the specification it followed.
 */
interface PresentationDialect {
    val id: String
    val spec: String

    /** True when this profile owns the request ([params] are the effective request parameters). */
    fun owns(raw: RawAuthorizationRequest, params: JsonObject): Boolean

    /** Extra verifier checks or trust for an owned request whose client is the DID [did]; null keeps the generic decision. */
    suspend fun verifierTrust(did: String, request: ValidatedAuthorizationRequest): TrustDecision? = null

    /** Warnings for an owned request (e.g. response_uri outside the verifier's registered service). */
    suspend fun warnings(request: ValidatedAuthorizationRequest): List<String> = emptyList()

    /** The JWT VP for an owned request, replacing the generic jwt_vp; null keeps the generic one. */
    suspend fun jwtVp(input: VpInput): String? = null

    /** path_nested format of a credential inside a jwt_vp (jwt_vc for TWDIW, vc+moica for Bonds self-issued cards). */
    fun nestedFormat(credential: WalletCredential): String? = null

    /**
     * path_nested path of the [index]th credential inside a jwt_vp; null keeps the JWT claim path
     * $.vp.verifiableCredential[index]. Microsoft Verified ID resolves it inside the vp claim.
     */
    fun nestedPath(index: Int): String? = null

    /** Parameters added to the response (TWDIW custom_data). */
    suspend fun extraResponseParameters(request: ValidatedAuthorizationRequest, holder: HolderKey?): Map<String, String> = emptyMap()

    /** The id_token of an owned request that asks for one (Microsoft Verified ID carries _vp_token in it). */
    suspend fun idToken(request: ValidatedAuthorizationRequest, holder: HolderKey, submission: JsonObject?): String? = null

    /** Holder identity profile used for SIOP and presentations of an owned request. */
    val holderProfile: String? get() = null

    /** Whether the verifier accepted the response, for verifiers that answer HTTP 200 with an error body; null uses the HTTP status. */
    fun accepted(status: Int, body: String): Boolean? = null

    /** Recipient, occasion, purpose and terms of an owned request; null keeps the Presentation Exchange purpose. */
    fun consentTerms(request: ValidatedAuthorizationRequest): ConsentTerms? = null
}
