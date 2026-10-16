package diw.wallet.core.profile.bonds

import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.ext.ExtendedPresenter
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Clock

/** A vc+moica card the wallet keeps outside the document store (national ID card, derived document card). */
class HeldMoicaCard(val id: String, val name: String, val card: MoicaSignedCredential)

/** A card chosen for an input descriptor, with the claims it discloses. */
class MoicaMatch(val card: HeldMoicaCard, val descriptorId: String, val claims: List<String>)

/**
 * Bonds self-issued cards over OpenID4VP (Bonds OID4VPResponse.selfIssuedMaterial): a TWDIW-shaped request whose
 * Presentation Exchange descriptors name the vc+moica format. The answer is a jwt_vp signed by the card's holder key
 * (header jwk, did:key jwk_jcs subject, 30 days) carrying the envelope reduced to the requested disclosures; the
 * submission nests vc+moica at $.vp.verifiableCredential[i]. A vc+moica request never falls back to other cards.
 */
object BondsMoicaOnline {
    const val FORMAT = "vc+moica"

    private class Descriptor(val id: String, val group: List<String>, val type: String?, val claims: List<Pair<String, Boolean>>)

    /** True when every input descriptor of the request names the vc+moica format. */
    fun wants(request: ValidatedAuthorizationRequest): Boolean {
        val ds = request.presentationDefinition?.arr("input_descriptors")?.filterIsInstance<JsonObject>().orEmpty()
        return ds.isNotEmpty() && ds.all { d -> d.obj("format")?.containsKey(FORMAT) == true }
    }

    private fun descriptors(request: ValidatedAuthorizationRequest): List<Descriptor> =
        request.presentationDefinition?.arr("input_descriptors")?.filterIsInstance<JsonObject>().orEmpty().map { d ->
            var type: String? = null
            val claims = ArrayList<Pair<String, Boolean>>()
            for (f in d.obj("constraints")?.arr("fields").orEmpty().filterIsInstance<JsonObject>()) {
                val optional = (f["optional"] as? JsonPrimitive)?.booleanOrNull == true
                for (p in f.arr("path").orEmpty().mapNotNull { (it as? JsonPrimitive)?.content }) {
                    val path = p.removePrefix("$.vc.").let { if (it == p) p.removePrefix("$.") else it }
                    when {
                        path == "type" -> type = f.obj("filter")?.let { flt -> flt.obj("contains")?.str("const") ?: flt.str("const") }
                        path.startsWith("credentialSubject.") -> path.removePrefix("credentialSubject.").takeIf { '.' !in it }?.let { claims += it to optional }
                    }
                }
            }
            Descriptor(
                d.str("id") ?: throw ProtocolException("invalid_request", "Input descriptor without id"),
                d.arr("group").orEmpty().mapNotNull { (it as? JsonPrimitive)?.content }, type, claims,
            )
        }

    /** Claims [card] can disclose: its disclosures, or the clear subject of a legacy card without commitments. */
    fun available(card: MoicaSignedCredential): Set<String> {
        val c = card.credential()
        return if (c["_sd"] != null) BondsOfflinePresentation.disclosableClaims(card).map { it.first }.toSet()
        else (c.obj("credentialSubject") ?: JsonObject(emptyMap())).keys - "id"
    }

    private fun answer(d: Descriptor, cards: List<HeldMoicaCard>): MoicaMatch? = cards.firstNotNullOfOrNull { held ->
        val types = held.card.credential().arr("type").orEmpty().mapNotNull { (it as? JsonPrimitive)?.content }
        if (d.type != null && d.type !in types) return@firstNotNullOfOrNull null
        val have = available(held.card)
        if (d.claims.any { (name, optional) -> !optional && name !in have }) return@firstNotNullOfOrNull null
        MoicaMatch(held, d.id, d.claims.map { it.first }.filter { it in have }.distinct())
    }

    /**
     * The cards answering the request: one per descriptor, or one per group named by submission_requirements (pick).
     * Throws access_denied when a needed descriptor has no card.
     */
    fun match(request: ValidatedAuthorizationRequest, cards: List<HeldMoicaCard>): List<MoicaMatch> {
        val ds = descriptors(request)
        val requirements = request.presentationDefinition?.arr("submission_requirements")?.filterIsInstance<JsonObject>().orEmpty()
        val unavailable = ProtocolException("access_denied", "No stored credential satisfies the request: a Bonds self-issued card (vc+moica) is needed")
        if (requirements.isEmpty()) return ds.map { answer(it, cards) ?: throw unavailable }
        return requirements.flatMap { r ->
            val from = r.str("from") ?: throw ProtocolException("invalid_request", "Nested submission requirements are not supported for vc+moica")
            val inGroup = ds.filter { from in it.group }
            val found = inGroup.mapNotNull { answer(it, cards) }
            val need = (r["count"] as? JsonPrimitive)?.content?.toIntOrNull() ?: (r["min"] as? JsonPrimitive)?.content?.toIntOrNull() ?: if (r.str("rule") == "all") inGroup.size else 1
            if (found.size < need) throw unavailable
            found.take(maxOf(need, 1))
        }
    }

    /** Form parameters of the response: vp_token, presentation_submission and state. */
    suspend fun response(request: ValidatedAuthorizationRequest, matches: List<MoicaMatch>, holder: HolderKey): JsonObject {
        val holderDid = HolderKey.didFor(holder.publicKey, HolderKey.DID_KEY_JWK_JCS)
        val subjectKeys = setOfNotNull(holder.did, holderDid, runCatching { HolderKey.didFor(holder.publicKey, "did:key") }.getOrNull())
        val presented = matches.map { m ->
            val subject = m.card.card.credential().obj("credentialSubject")?.str("id")
            if (subject != null && subject !in subjectKeys) throw ProtocolException("invalid_key", "The card is about another holder")
            val c = m.card.card
            (if (c.credential()["_sd"] != null) c.withDisclosures(m.claims.toSet(), always = emptySet()) else c).serialized()
        }
        val now = Clock.System.now().epochSeconds
        val vp = signJws(
            buildJsonObject {
                put("typ", "JWT")
                put("alg", "ES256")
                put("jwk", holder.publicKey.toJwk())
            },
            buildJsonObject {
                put("sub", holderDid)
                put("aud", request.verifier.effectiveClientId)
                put("iss", holderDid)
                put("nbf", now)
                putJsonObject("vp") {
                    putJsonArray("context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
                    putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
                    putJsonArray("verifiableCredential") { presented.forEach { add(JsonPrimitive(it)) } }
                }
                put("exp", now + VP_LIFETIME_SECONDS)
                put("nonce", request.nonce)
                put("jti", "urn:uuid:" + ExtendedPresenter.uuid())
            },
            holder.signingKey("ES256"),
        )
        val definitionId = request.presentationDefinition?.str("id") ?: throw ProtocolException("invalid_request", "presentation_definition.id missing")
        val submission = buildJsonObject {
            put("id", ExtendedPresenter.uuid())
            put("definition_id", definitionId)
            putJsonArray("descriptor_map") {
                matches.forEachIndexed { i, m ->
                    addJsonObject {
                        put("id", m.descriptorId)
                        put("format", "jwt_vp")
                        put("path", "$")
                        putJsonObject("path_nested") {
                            put("id", m.descriptorId)
                            put("format", FORMAT)
                            put("path", "\$.vp.verifiableCredential[$i]")
                        }
                    }
                }
            }
        }
        return buildJsonObject {
            put("vp_token", vp)
            put("presentation_submission", submission)
            request.state?.let { put("state", it) }
        }
    }

    /** The official wallet and Bonds give the VP a 30 day lifetime. */
    private const val VP_LIFETIME_SECONDS = 60L * 60 * 24 * 30
}
