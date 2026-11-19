package diw.wallet.core.verifier.declaration

import diw.wallet.core.oid4vp.ClientId
import diw.wallet.core.oid4vp.VerifierIdentityInfo
import diw.wallet.core.oid4vp.VerifierInfoEntry
import diw.wallet.core.trust.TrustDecision
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Tstr
import org.multipaz.crypto.X509CertChain

/**
 * A verifier declaration in an ISO/IEC 18013-5 session (docs/design/p5-verifier.md section 7): it travels in the
 * requestInfo of the reader's DocRequest under [VerifierDeclaration.REQUEST_INFO_KEY], with an optional EUDI
 * registration certificate under [VerifierDeclaration.REQUEST_INFO_WRPRC]. It is signed by the reader authentication
 * key, its client_id is the x509_hash of the reader certificate and its nonce is
 * [VerifierDeclaration.proximityNonce] of the SessionTranscript. Readers and wallets that do not know these keys
 * ignore them, as ISO/IEC 18013-5 requires for unknown requestInfo keys.
 */
object ProximityDeclaration {
    /** The requestInfo entries that carry [declaration] and, when given, the registration certificate [registration]. */
    fun requestInfo(declaration: String, registration: String? = null): Map<String, DataItem> = buildMap {
        put(VerifierDeclaration.REQUEST_INFO_KEY, Tstr(declaration))
        registration?.let { put(VerifierDeclaration.REQUEST_INFO_WRPRC, Tstr(it)) }
    }

    /** The verifier_info entries a DocRequest's requestInfo carries (text or UTF-8 bytes); empty when it carries none. */
    fun entries(info: Map<String, DataItem>): List<VerifierInfoEntry> = buildList {
        info[VerifierDeclaration.REQUEST_INFO_WRPRC]?.let(::text)?.let { add(VerifierInfoEntry("jwt", JsonPrimitive(it), emptyList())) }
        info[VerifierDeclaration.REQUEST_INFO_KEY]?.let(::text)?.let { add(VerifierInfoEntry(VerifierDeclaration.FORMAT, JsonPrimitive(it), emptyList())) }
    }

    private fun text(item: DataItem): String? = when (item) {
        is Tstr -> item.value
        is Bstr -> runCatching { item.value.decodeToString() }.getOrNull()
        else -> null
    }.takeIf { !it.isNullOrBlank() }

    /** The reader as a verifier: its certificate is the request key and names the client_id x509_hash. */
    fun verifier(chain: X509CertChain, trust: TrustDecision, name: String): VerifierIdentityInfo {
        val clientId = clientId(chain)
        return VerifierIdentityInfo(ClientId.parse(clientId), clientId, name, chain, emptyList(), null, trust)
    }

    fun clientId(chain: X509CertChain): String = x509HashClientId(chain.certificates.first().encoded.toByteArray())

    /** One mdoc request written as a DCQL credential query, to compare with what a declaration lists. */
    fun query(id: String, docType: String, elements: Map<String, List<String>>): JsonObject = buildJsonObject {
        put("id", id)
        put("format", "mso_mdoc")
        put("meta", buildJsonObject { put("doctype_value", docType) })
        putJsonArray("claims") {
            elements.forEach { (ns, names) -> names.forEach { e -> add(buildJsonObject { put("path", buildJsonArray { add(ns); add(e) }) }) } }
        }
    }

    /** The DCQL query of a whole DeviceRequest: one credential query per DocRequest. */
    fun dcql(requests: List<Pair<String, Map<String, List<String>>>>): JsonObject = buildJsonObject {
        putJsonArray("credentials") { requests.forEachIndexed { i, (docType, elements) -> add(query("d$i", docType, elements)) } }
    }
}
