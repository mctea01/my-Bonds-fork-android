package diw.wallet.core.credential

import diw.wallet.core.util.DiwJson
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.credential.Credential
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.fromBase64Url

/** One claim for display: label and rendered value. */
data class DisplayClaim(val label: String, val value: String)

/**
 * Claims of a stored credential for display. Multipaz only reads SD-JWTs signed with an X.509 chain, so SD-JWTs
 * whose issuer key came from a DID, jku or issuer metadata are decoded here from the issued token instead.
 */
object ClaimReader {
    private val technical = setOf("iss", "sub", "iat", "nbf", "exp", "jti", "cnf", "vct", "status", "_sd", "_sd_alg", "@context", "type", "credentialStatus")

    suspend fun read(credential: Credential, types: DocumentTypeRepository): List<DisplayClaim> {
        val multipaz = runCatching { credential.getClaims(types) }.getOrNull()
        if (multipaz != null) return multipaz.map { DisplayClaim(it.displayName, it.render()) }
        if (credential !is SdJwtVcCredential) return emptyList()
        return fromCompact(credential.issuerProvidedData.decodeToString())
    }

    /** Disclosed and plain claims of a compact SD-JWT (issuer part only; a key binding JWT is ignored). */
    fun fromCompact(compact: String): List<DisplayClaim> {
        val parts = compact.split('~')
        val payload = DiwJson.parseToJsonElement(parts[0].split('.')[1].fromBase64Url().decodeToString()) as JsonObject
        val out = mutableListOf<DisplayClaim>()
        // W3C-style tokens keep the subject claims under vc.credentialSubject.
        val subject = ((payload["vc"] as? JsonObject)?.get("credentialSubject") as? JsonObject)
        plain(subject ?: payload, "", out)
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
            if (k in technical || k == "vc") continue
            when (v) {
                is JsonObject -> plain(v, "$prefix$k.", out)
                else -> out += DisplayClaim(prefix + k, render(v))
            }
        }
    }

    private fun render(v: JsonElement): String = when (v) {
        is JsonPrimitive -> v.content
        is JsonArray -> v.joinToString(", ") { render(it) }
        is JsonObject -> v.entries.joinToString(", ") { (k, x) -> "$k: ${render(x)}" }
    }
}
