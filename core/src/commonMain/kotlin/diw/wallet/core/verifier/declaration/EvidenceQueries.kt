package diw.wallet.core.verifier.declaration

import diw.wallet.core.credential.ClaimReader
import diw.wallet.core.credential.DisplayClaim
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.credential.Credential
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.sdjwt.credential.SdJwtVcCredential

/** A claim the verifier may disclose as evidence; [identifying] claims name who it is and are chosen by default. */
data class EvidenceClaim(val path: List<String>, val label: String, val value: String, val identifying: Boolean)

/**
 * The DCQL query of an evidence presentation (docs/design/p5-verifier.md section 4.1): the verifier's own credential,
 * disclosing by default only the claims that name who it is (names, and an organisation's identifier). The user may
 * choose other claims instead.
 */
object EvidenceQueries {
    private val WANTED = VerifierDeclarationCheck.NAME_CLAIMS + VerifierDeclarationCheck.GIVEN_CLAIMS +
        VerifierDeclarationCheck.FAMILY_CLAIMS + VerifierDeclarationCheck.ID_CLAIMS

    /** Whether [credential] can be evidence: an mdoc or an SD-JWT VC. */
    fun supported(credential: Credential): Boolean = credential is MdocCredential || credential is SdJwtVcCredential

    /** Every claim of [credential] that can be disclosed, identifying ones first; empty for other formats. */
    suspend fun claims(credential: Credential, types: DocumentTypeRepository): List<EvidenceClaim> {
        if (!supported(credential)) return emptyList()
        return ClaimReader.read(credential, types).filter { it.path.isNotEmpty() }.distinctBy { it.path }
            .map { EvidenceClaim(it.path, it.label, display(it), it.path.lastOrNull() in WANTED) }
            .sortedBy { if (it.identifying) 0 else 1 }
    }

    private fun display(c: DisplayClaim): String = if (c.picture != null) "[image]" else c.value.take(80)

    /**
     * The query for [credential] under [id]: [chosen] paths when given (those the credential has), else its identifying
     * claims. Null when it is neither an mdoc nor an SD-JWT VC, or nothing would be disclosed.
     */
    suspend fun forCredential(id: String, credential: Credential, types: DocumentTypeRepository, chosen: List<List<String>>? = null): JsonObject? {
        val format: String
        val meta: JsonObject
        when (credential) {
            is MdocCredential -> {
                format = "mso_mdoc"
                meta = buildJsonObject { put("doctype_value", credential.docType) }
            }
            is SdJwtVcCredential -> {
                format = "dc+sd-jwt"
                meta = buildJsonObject { putJsonArray("vct_values") { add(credential.vct) } }
            }
            else -> return null
        }
        val all = ClaimReader.read(credential, types).map { it.path }.filter { it.isNotEmpty() }.distinct()
        val paths = if (chosen != null) all.filter { it in chosen } else all.filter { it.lastOrNull() in WANTED }
        if (paths.isEmpty()) return null
        return buildJsonObject {
            put("id", id)
            put("format", format)
            put("meta", meta)
            putJsonArray("claims") {
                paths.forEach { p -> add(buildJsonObject { put("path", buildJsonArray { p.forEach { add(it) } }) }) }
            }
        }
    }
}
