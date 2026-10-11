package diw.wallet.core.oid4vp.compat

import diw.wallet.core.did.DidKeys
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.RawAuthorizationRequest
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.ext.ExtendedPresenter
import diw.wallet.core.oid4vp.ext.WalletCredential
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Clock

/**
 * Microsoft Entra Verified ID presentation (openid-vc:// requests, as the Microsoft Authenticator and the
 * Verified ID wallet library answer them): response_type id_token with claims.vp_token.presentation_definition,
 * response_mode post to redirect_uri, an id_token from https://self-issued.me/v2/openid-vc carrying the
 * presentation_submission in _vp_token, and a vp_token signed by the wallet's Verified ID holder DID.
 *
 * The submission follows the wallet library's PresentationResponseFormatter: format jwt_vp at "$", and path_nested
 * format jwt_vc at "$.verifiableCredential[i]", resolved inside the vp claim. A JWT claim path
 * ($.vp.verifiableCredential[i]) finds nothing there, and the verifier answers 401 "The presentation does not
 * include any verifiable credentials".
 */
class MsVerifiedIdPresentationDialect : PresentationDialect {
    override val id = ID
    override val spec = "Microsoft Entra Verified ID"
    override val holderProfile: String = HolderIdentities.MS_VERIFIED_ID

    override fun owns(raw: RawAuthorizationRequest, params: JsonObject): Boolean =
        raw.entryHint == ENTRY_HINT ||
            (params.obj("claims")?.obj("vp_token") != null && (params.str("response_type") ?: "").contains("id_token"))

    override suspend fun idToken(request: ValidatedAuthorizationRequest, holder: HolderKey, submission: JsonObject?): String {
        val did = holder.did ?: HolderKey.didFor(holder.publicKey, "did:jwk")
        val now = Clock.System.now().epochSeconds
        return signJws(
            buildJsonObject { put("alg", ExtendedPresenter.joseAlg(holder.publicKey)); put("typ", "JWT"); put("kid", DidKeys.verificationMethod(did)) },
            buildJsonObject {
                put("sub", did)
                put("aud", request.verifier.effectiveClientId)
                put("nonce", request.nonce)
                put("iat", now)
                put("exp", now + 3600)
                put("jti", ExtendedPresenter.uuid())
                put("iss", SELF_ISSUED)
                submission?.let { putJsonObject("_vp_token") { put("presentation_submission", it) } }
            },
            holder.signingKey(ExtendedPresenter.joseAlg(holder.publicKey)),
        )
    }

    override fun nestedFormat(credential: WalletCredential): String = "jwt_vc"

    override fun nestedPath(index: Int): String = "\$.verifiableCredential[$index]"

    override suspend fun jwtVp(input: VpInput): String {
        val holder = input.holder
        val did = holder.did ?: HolderKey.didFor(holder.publicKey, "did:jwk")
        val now = Clock.System.now().epochSeconds
        return signJws(
            buildJsonObject { put("alg", ExtendedPresenter.joseAlg(holder.publicKey)); put("typ", "JWT"); put("kid", DidKeys.verificationMethod(did)) },
            buildJsonObject {
                put("jti", ExtendedPresenter.uuid())
                putJsonObject("vp") {
                    putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
                    putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
                    putJsonArray("verifiableCredential") { input.credentials.forEach { add(JsonPrimitive(it.second)) } }
                }
                put("iss", did)
                put("iat", now)
                put("exp", now + 3600)
                put("nbf", now)
                put("aud", input.request.verifier.effectiveClientId)
                put("nonce", input.request.nonce)
            },
            holder.signingKey(ExtendedPresenter.joseAlg(holder.publicKey)),
        )
    }

    companion object {
        const val ID = "msvid"
        const val ENTRY_HINT = "msvid"
        const val SELF_ISSUED = "https://self-issued.me/v2/openid-vc"
    }
}
