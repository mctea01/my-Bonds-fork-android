package diw.wallet.core.verifier.declaration

import diw.wallet.core.credential.ClaimReader
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

/**
 * The DCQL query of an evidence presentation (docs/design/p5-verifier.md section 4.1): the verifier's own credential,
 * disclosing only the claims that name who it is (names, and an organisation's identifier), never the rest.
 */
object EvidenceQueries {
    /**
     * The query for [credential] under [id]; null when it is neither an mdoc nor an SD-JWT VC (other formats cannot be
     * evidence) or it carries no claim that names a person or organisation.
     */
    suspend fun forCredential(id: String, credential: Credential, types: DocumentTypeRepository): JsonObject? {
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
        val wanted = VerifierDeclarationCheck.NAME_CLAIMS + VerifierDeclarationCheck.GIVEN_CLAIMS +
            VerifierDeclarationCheck.FAMILY_CLAIMS + VerifierDeclarationCheck.ID_CLAIMS
        val paths = ClaimReader.read(credential, types).map { it.path }.filter { it.lastOrNull() in wanted }.distinct()
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
