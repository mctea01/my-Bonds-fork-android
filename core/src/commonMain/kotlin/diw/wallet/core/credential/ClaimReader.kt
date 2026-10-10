package diw.wallet.core.credential

import diw.wallet.core.util.DiwJson
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.claim.Claim
import org.multipaz.claim.JsonClaim
import org.multipaz.claim.MdocClaim
import org.multipaz.credential.Credential
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.fromBase64Url

/** One claim for display: claim path, the credential type's name for it (or the path) and the rendered value. */
data class DisplayClaim(val label: String, val value: String, val path: List<String> = label.split('.'))

/**
 * Claims of a stored credential for display. Multipaz only reads SD-JWTs signed with an X.509 chain, so SD-JWTs
 * whose issuer key came from a DID, jku or issuer metadata are decoded here from the issued token instead.
 */
object ClaimReader {
    private val technical = setOf("iss", "sub", "iat", "nbf", "exp", "jti", "cnf", "vct", "status", "_sd", "_sd_alg", "@context", "type", "credentialStatus")
    /** W3C VC data model envelope fields under "vc"; the claims themselves are under vc.credentialSubject. */
    private val w3cEnvelope = setOf("id", "issuer", "issuanceDate", "expirationDate", "validFrom", "validUntil", "credentialSchema", "proof")

    suspend fun read(credential: Credential, types: DocumentTypeRepository): List<DisplayClaim> {
        val multipaz = runCatching { credential.getClaims(types) }.getOrNull()
        // Registered JWT claims (iss, iat, cnf, status, ...) are shown in the details view, not as credential data.
        if (multipaz != null) return multipaz.map { DisplayClaim(it.displayName, it.render(), pathOf(it)) }
            .filterNot { it.path.size == 1 && it.path[0] in technical }
        if (credential !is SdJwtVcCredential) return emptyList()
        return fromCompact(credential.issuerProvidedData.decodeToString())
    }

    /** Claim path: namespace and element for mdoc, the JSON path for SD-JWT VC. */
    fun pathOf(claim: Claim): List<String> = when (claim) {
        is MdocClaim -> listOf(claim.namespaceName, claim.dataElementName)
        is JsonClaim -> claim.claimPath.map { (it as? JsonPrimitive)?.content ?: it.toString() }
        else -> listOf(claim.displayName)
    }

    /** Disclosed and plain claims of a compact SD-JWT (issuer part only; a key binding JWT is ignored). */
    fun fromCompact(compact: String): List<DisplayClaim> {
        val parts = compact.split('~')
        val payload = DiwJson.parseToJsonElement(parts[0].split('.')[1].fromBase64Url().decodeToString()) as JsonObject
        val out = mutableListOf<DisplayClaim>()
        // Plain claims, nested objects flattened with dotted names; selectively disclosed ones come from disclosures.
        plain(payload, "", out)
        for (d in parts.drop(1).filter { it.isNotEmpty() && '.' !in it }) {
            val arr = runCatching { DiwJson.parseToJsonElement(d.fromBase64Url().decodeToString()) as JsonArray }.getOrNull() ?: continue
            if (arr.size == 3) {
                val name = (arr[1] as? JsonPrimitive)?.content ?: continue
                if (name !in technical) out += DisplayClaim(name, render(arr[2]))
            }
        }
        return out
    }

    private fun plain(o: JsonObject, prefix: String, out: MutableList<DisplayClaim>) {
        for ((k, v) in o) {
            if (k in technical || (prefix == "vc." && k in w3cEnvelope)) continue
            when (v) {
                is JsonObject -> plain(v, "$prefix$k.", out)
                else -> out += DisplayClaim((prefix + k).removePrefix("vc.credentialSubject."), render(v))
            }
        }
    }

    private fun render(v: JsonElement): String = when (v) {
        is JsonPrimitive -> v.content
        is JsonArray -> v.joinToString(", ") { render(it) }
        is JsonObject -> v.entries.joinToString(", ") { (k, x) -> "$k: ${render(x)}" }
    }
}
