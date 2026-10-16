package diw.wallet.core.oid4vp.compat

import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.ConsentTerms
import diw.wallet.core.oid4vp.RawAuthorizationRequest
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.ext.CredentialFamily
import diw.wallet.core.oid4vp.ext.ExtendedPresenter
import diw.wallet.core.oid4vp.ext.WalletCredential
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.hostOf
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Clock

/** A custom field a TWDIW static verifier asks the holder to fill in (custom.fields of the static QR service). */
data class TwdiwCustomField(val cname: String, val ename: String, val description: String?, val regex: String?, val value: String = "")

/**
 * TWDIW presentation as the official wallet and Bonds perform it:
 * - the client_id is the verifier's bare DID and the request object is signed by it (no aud check);
 * - Presentation Exchange 2.0 with vc+sd-jwt descriptors;
 * - one jwt_vp signed by the wallet holder key, header {typ, alg, jwk}, payload with sub/iss = holder DID, aud = client_id,
 *   nbf, exp, nonce, jti and vp.context / type / verifiableCredential (each card an SD-JWT with the chosen disclosures);
 * - presentation_submission with format jwt_vp, path $, path_nested jwt_vc at $.vp.verifiableCredential[i];
 * - custom_data for static verifiers with custom fields, signed like the VP;
 * - presentation_definition.purpose is a JSON string {client, scenario, purpose, terms_uri}: the recipient, the
 *   occasion, the purpose and the 知情同意書 page the official wallet links before sending;
 * - success is a JSON body with code 0.
 */
class TwdiwPresentationDialect(
    /** True when [host] is a registered service host of the verifier DID in the TWDIW trust list; null when unknown. */
    private val responseHostRegistered: suspend (did: String, host: String) -> Boolean? = { _, _ -> null },
) : PresentationDialect {
    override val id = ID
    override val spec = "TWDIW"
    override val holderProfile: String = HolderIdentities.TWDIW

    private val customData = mutableMapOf<String, List<TwdiwCustomField>>()

    /** Values the holder entered for a static verifier's custom fields, sent with the presentation for [nonce]. */
    fun attachCustomData(nonce: String, fields: List<TwdiwCustomField>) {
        customData[nonce] = fields
    }

    override fun owns(raw: RawAuthorizationRequest, params: JsonObject): Boolean {
        if (raw.entryHint == TwdiwDialect.ENTRY_HINT) return true
        val target = params.str("response_uri") ?: params.str("redirect_uri")
        if (target != null && runCatching { TwdiwDialect.isTwdiwHost(hostOf(target)) }.getOrDefault(false)) return true
        val clientId = params.str("client_id") ?: raw.outer["client_id"] ?: return false
        val descriptors = params.obj("presentation_definition")?.arr("input_descriptors")?.filterIsInstance<JsonObject>().orEmpty()
        // TWDIW-based verifiers (official, Bonds, twdiw-vc-issuer-lite) use a bare did:key client and Presentation Exchange,
        // with vc+sd-jwt / vc+moica descriptor formats, or no descriptor format and jwt_vp / jwt_vc in client_metadata.vp_formats.
        if (!clientId.startsWith("did:key:") || descriptors.isEmpty()) return false
        if (descriptors.all { d -> d.obj("format")?.keys?.any { it in DESCRIPTOR_FORMATS } == true }) return true
        val vpFormats = (params.obj("client_metadata") ?: params.obj("registration"))?.obj("vp_formats")?.keys.orEmpty()
        return descriptors.none { it.obj("format") != null } && vpFormats.isNotEmpty() && vpFormats.all { it in VP_FORMATS }
    }

    override suspend fun warnings(request: ValidatedAuthorizationRequest): List<String> {
        val did = request.verifier.did ?: return emptyList()
        val host = request.target?.let { runCatching { hostOf(it) }.getOrNull() } ?: return emptyList()
        return if (responseHostRegistered(did, host) == false) listOf("Response host $host is not a service registered for $did in the TWDIW trust list") else emptyList()
    }

    override suspend fun jwtVp(input: VpInput): String {
        val holder = input.holder
        val did = input.credentials.firstNotNullOfOrNull { (c, _) -> (c.credential as? diw.wallet.core.w3c.W3cVcCredential)?.holderDid }
            ?: holder.did ?: HolderKey.didFor(holder.publicKey, HolderKey.DID_KEY_JWK_JCS)
        val now = Clock.System.now().epochSeconds
        return signJws(
            header(holder),
            buildJsonObject {
                put("sub", did)
                put("aud", input.request.verifier.effectiveClientId)
                put("iss", did)
                put("nbf", now)
                putJsonObject("vp") {
                    putJsonArray("context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
                    putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
                    putJsonArray("verifiableCredential") { input.credentials.forEach { add(JsonPrimitive(it.second)) } }
                }
                put("exp", now + VP_LIFETIME_SECONDS)
                put("nonce", input.request.nonce)
                put("jti", "urn:uuid:" + ExtendedPresenter.uuid())
            },
            holder.signingKey("ES256"),
        )
    }

    override fun nestedFormat(credential: WalletCredential): String? = when (credential.family) {
        CredentialFamily.W3C_SD_JWT, CredentialFamily.W3C_JWT -> "jwt_vc"
        else -> null
    }

    override suspend fun extraResponseParameters(request: ValidatedAuthorizationRequest, holder: HolderKey?): Map<String, String> {
        val fields = customData.remove(request.nonce)?.takeIf { it.isNotEmpty() } ?: return emptyMap()
        val key = holder ?: return emptyMap()
        val jwt = signJws(header(key), buildJsonObject {
            putJsonArray("customData") {
                for (f in fields) addJsonObject { put("cname", f.cname); put("ename", f.ename); put("value", f.value) }
            }
        }, key.signingKey("ES256"))
        return mapOf("custom_data" to jwt)
    }

    override fun consentTerms(request: ValidatedAuthorizationRequest): ConsentTerms? = terms(request.presentationDefinition?.str("purpose"))

    override fun accepted(status: Int, body: String): Boolean? {
        val json = runCatching { DiwJson.parseToJsonElement(body) as JsonObject }.getOrNull() ?: return null
        val code = (json["code"] as? JsonPrimitive)?.content ?: return null
        return status in 200..299 && code == "0"
    }

    private suspend fun header(holder: HolderKey): JsonObject {
        val jwk = holder.publicKey.toJwk()
        return buildJsonObject {
            put("typ", "JWT")
            put("alg", "ES256")
            put("jwk", jwk)
        }
    }

    companion object {
        const val ID = "twdiw"

        /** Parses the official verifier's purpose JSON; a plain text purpose is kept as it is. */
        fun terms(purpose: String?): ConsentTerms? {
            val text = purpose?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            val json = runCatching { DiwJson.parseToJsonElement(text) as? JsonObject }.getOrNull() ?: return ConsentTerms(purpose = text)
            fun field(name: String) = (json[name] as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()?.takeIf { it.isNotEmpty() }
            return ConsentTerms(
                recipient = field("client"),
                scenario = field("scenario"),
                purpose = field("purpose"),
                termsUri = ConsentTerms.httpsOnly(field("terms_uri")),
            ).takeIf { !it.isEmpty }
        }
        /** The official wallet and Bonds give the VP a 30 day lifetime. */
        const val VP_LIFETIME_SECONDS = 60L * 60 * 24 * 30
        private val DESCRIPTOR_FORMATS = setOf("vc+sd-jwt", "vc+moica")
        private val VP_FORMATS = setOf("jwt_vp", "jwt_vc", "jwt_vp_json", "jwt_vc_json", "vc+sd-jwt")
    }
}
