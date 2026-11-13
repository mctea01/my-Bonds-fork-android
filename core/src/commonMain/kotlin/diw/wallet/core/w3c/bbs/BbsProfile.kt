package diw.wallet.core.w3c.bbs

import diw.wallet.core.util.Jcs
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.strList
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url

/**
 * How this wallet uses bbs-2023 with OpenID4VCI and OpenID4VP where the specifications leave it open.
 *
 * Issuance of the optional features is a DIW extension (no standard carries the holder's commitment yet): a credential
 * configuration lists the features in [METADATA], and the credential request carries [REQUEST] with the feature and
 * the base64url commitment_with_proof. Issuers that do not list [METADATA] are sent plain requests and issue baseline
 * credentials.
 *
 * Presentation: the BBS presentation header binds a derived proof to one request (JCS of {"aud", "nonce"}), and the
 * pseudonym nym_domain is the audience (the client_id, or "origin:<origin>" over the DC API), so a pseudonym is stable
 * per verifier and unrelated across verifiers. The presentation header is opaque to bbs-2023 itself.
 */
object BbsProfile {
    const val METADATA = "diw_bbs_features"
    const val REQUEST = "diw_bbs_commitment"

    /** Order this wallet picks an optional feature in: anonymous holder binding links nothing across presentations. */
    private val PREFERENCE = listOf(BbsFeature.ANONYMOUS_HOLDER_BINDING, BbsFeature.HOLDER_BINDING_PSEUDONYM, BbsFeature.PSEUDONYM)

    fun offered(configuration: JsonObject): List<BbsFeature> =
        configuration.strList(METADATA).mapNotNull { BbsFeature.of(it) }.filter { it != BbsFeature.BASELINE }

    fun choose(configuration: JsonObject): BbsFeature? {
        val offered = offered(configuration)
        if (offered.isEmpty() || !Bbs.available()) return null
        return PREFERENCE.firstOrNull { it in offered }
    }

    fun requestMember(feature: BbsFeature, commitmentWithProof: ByteArray): JsonObject = buildJsonObject {
        put("feature", feature.id)
        put("commitment_with_proof", commitmentWithProof.toBase64Url())
    }

    /** Issuer side: the feature and commitment of a credential request, or null for a plain request. */
    fun parseRequest(request: JsonObject): Pair<BbsFeature, ByteArray>? {
        val member = request[REQUEST] as? JsonObject ?: return null
        val feature = (member["feature"] as? JsonPrimitive)?.content?.let { BbsFeature.of(it) }?.takeIf { it != BbsFeature.BASELINE }
            ?: throw ProtocolException("invalid_credential_request", "Unknown bbs-2023 feature")
        val commitment = (member["commitment_with_proof"] as? JsonPrimitive)?.content?.let { runCatching { it.fromBase64Url() }.getOrNull() }
            ?: throw ProtocolException("invalid_credential_request", "bbs-2023 commitment_with_proof missing")
        return feature to commitment
    }

    fun presentationHeader(audience: String, nonce: String): ByteArray =
        Jcs.canonicalBytes(buildJsonObject { put("aud", audience); put("nonce", nonce) })

    /**
     * JSON pointers for the claims a request asked for: [memberPaths] are member names from the credential root (an
     * empty path asks for the whole credential). The issuer's mandatory pointers are always disclosed as well.
     */
    fun pointers(document: JsonObject, memberPaths: List<List<String>>, includeSubjectId: Boolean): List<String> {
        val skip = setOf("@context", "proof")
        val out = linkedSetOf<String>()
        for (path in memberPaths) {
            if (path.isEmpty()) document.keys.filter { it !in skip }.forEach { out += "/" + escape(it) }
            else out += path.joinToString("") { "/" + escape(it) }
        }
        if ("issuer" in document) out += "/issuer"
        if (includeSubjectId && (document["credentialSubject"] as? JsonObject)?.containsKey("id") == true) out += "/credentialSubject/id"
        // A pointer inside another selected one adds nothing.
        return out.filter { p -> out.none { q -> q != p && p.startsWith("$q/") } }
    }

    private fun escape(s: String) = s.replace("~", "~0").replace("/", "~1")
}
