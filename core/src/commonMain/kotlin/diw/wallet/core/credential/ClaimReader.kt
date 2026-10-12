package diw.wallet.core.credential

import diw.wallet.core.util.DiwJson
import diw.wallet.core.w3c.W3cEncoding
import diw.wallet.core.w3c.W3cVcCredential
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Tstr
import org.multipaz.claim.Claim
import org.multipaz.claim.JsonClaim
import org.multipaz.claim.MdocClaim
import org.multipaz.credential.Credential
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.fromBase64Url

/**
 * One claim for display: claim path, the credential type's name for it (or the path) and the rendered value;
 * [picture] holds the image bytes of a portrait or other picture claim (JPEG, PNG, GIF, WebP).
 */
data class DisplayClaim(val label: String, val value: String, val path: List<String> = label.split('.'), val picture: ByteArray? = null) {
    override fun equals(other: Any?) = other is DisplayClaim && other.label == label && other.value == value && other.path == path &&
        other.picture.contentEquals(picture)

    override fun hashCode() = (label.hashCode() * 31 + value.hashCode()) * 31 + path.hashCode()
}

/** Image claims: mdoc byte strings and data: URLs or base64 text of an image in JSON credentials. */
object ClaimPictures {
    private val dataUrl = Regex("^data:image/(png|jpe?g|gif|webp);base64,(.+)$", RegexOption.IGNORE_CASE)

    /** True when [b] starts like a JPEG, PNG, GIF or WebP file. */
    fun isImage(b: ByteArray): Boolean = b.size > 12 && (
        (b[0] == 0xFF.toByte() && b[1] == 0xD8.toByte() && b[2] == 0xFF.toByte()) ||
            (b[0] == 0x89.toByte() && b[1] == 'P'.code.toByte() && b[2] == 'N'.code.toByte() && b[3] == 'G'.code.toByte()) ||
            (b[0] == 'G'.code.toByte() && b[1] == 'I'.code.toByte() && b[2] == 'F'.code.toByte()) ||
            (b[0] == 'R'.code.toByte() && b[1] == 'I'.code.toByte() && b[8] == 'W'.code.toByte() && b[9] == 'E'.code.toByte())
        )

    /** The image in a text value: a data: URL, or base64 / base64url of at least 100 bytes that decodes to an image. */
    fun fromText(v: String): ByteArray? {
        val t = v.trim()
        dataUrl.matchEntire(t)?.let { m -> return decode(m.groupValues[2])?.takeIf { isImage(it) } }
        if (t.length < 136 || t.any { it.isWhitespace() }) return null
        if (!(t.startsWith("/9j/") || t.startsWith("_9j_") || t.startsWith("iVBOR") || t.startsWith("R0lGOD") || t.startsWith("UklGR"))) return null
        return decode(t)?.takeIf { isImage(it) }
    }

    private fun decode(s: String): ByteArray? = runCatching {
        s.trimEnd('=').replace('+', '-').replace('/', '_').fromBase64Url()
    }.getOrNull()

    /** What a picture claim shows as text. */
    fun describe(b: ByteArray): String = "圖片（${(b.size + 1023) / 1024} KB）"
}

/**
 * Claims of a stored credential for display. Multipaz only reads SD-JWTs signed with an X.509 chain, so SD-JWTs
 * whose issuer key came from a DID, jku or issuer metadata are decoded here from the issued token instead.
 */
object ClaimReader {
    private val technical = setOf("iss", "sub", "iat", "nbf", "exp", "jti", "cnf", "vct", "status", "_sd", "_sd_alg", "@context", "type", "credentialStatus")
    /** W3C VC data model envelope fields under "vc"; the claims themselves are under vc.credentialSubject. */
    private val w3cEnvelope = setOf("id", "issuer", "issuanceDate", "expirationDate", "validFrom", "validUntil", "credentialSchema", "proof")

    suspend fun read(credential: Credential, types: DocumentTypeRepository): List<DisplayClaim> {
        if (credential is W3cVcCredential) return fromW3c(credential)
        val multipaz = runCatching { credential.getClaims(types) }.getOrNull()
        // Registered JWT claims (iss, iat, cnf, status, ...) are shown in the details view, not as credential data.
        if (multipaz != null) return multipaz.map { c ->
            val picture = when (c) {
                is MdocClaim -> (c.value as? Bstr)?.value?.takeIf { ClaimPictures.isImage(it) }
                is JsonClaim -> (c.value as? JsonPrimitive)?.takeIf { it.isString }?.let { ClaimPictures.fromText(it.content) }
                else -> null
            }
            DisplayClaim(c.displayName, picture?.let { ClaimPictures.describe(it) } ?: valueOf(c), pathOf(c), picture)
        }
            .filterNot { it.path.size == 1 && it.path[0] in technical }
        if (credential !is SdJwtVcCredential) return emptyList()
        return fromCompact(credential.issuerProvidedData.decodeToString())
    }

    /**
     * Rendered value, except country codes: the credential's own ISO 3166 code is shown instead of the type's
     * option name, which may not be the name the holder uses for their country.
     */
    private fun valueOf(claim: Claim): String {
        val name = pathOf(claim).lastOrNull().orEmpty()
        if ("country" in name || "nationalit" in name) {
            when (claim) {
                is MdocClaim -> (claim.value as? Tstr)?.let { return it.value }
                is JsonClaim -> return render(claim.value)
                else -> {}
            }
        }
        return claim.render()
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
                if (name !in technical) out += display(name, arr[2])
            }
        }
        return out
    }

    /** W3C credentials: disclosures of an SD-JWT, otherwise the credentialSubject claims (without its id). */
    fun fromW3c(credential: W3cVcCredential): List<DisplayClaim> = runCatching {
        if (credential.encoding == W3cEncoding.SD_JWT) return@runCatching fromCompact(credential.raw)
        val out = mutableListOf<DisplayClaim>()
        val subjects = when (val s = credential.credentialJson()["credentialSubject"]) {
            is JsonObject -> listOf(s)
            is JsonArray -> s.filterIsInstance<JsonObject>()
            else -> emptyList()
        }
        subjects.forEach { plain(JsonObject(it - "id"), "", out) }
        out
    }.getOrDefault(emptyList())

    private fun plain(o: JsonObject, prefix: String, out: MutableList<DisplayClaim>) {
        for ((k, v) in o) {
            if (k in technical || (prefix == "vc." && k in w3cEnvelope)) continue
            when (v) {
                is JsonObject -> plain(v, "$prefix$k.", out)
                else -> out += display((prefix + k).removePrefix("vc.credentialSubject."), v)
            }
        }
    }

    private fun display(label: String, v: JsonElement): DisplayClaim {
        val picture = (v as? JsonPrimitive)?.takeIf { it.isString }?.let { ClaimPictures.fromText(it.content) }
        return DisplayClaim(label, picture?.let { ClaimPictures.describe(it) } ?: render(v), label.split('.'), picture)
    }

    private fun render(v: JsonElement): String = when (v) {
        is JsonPrimitive -> v.content
        is JsonArray -> v.joinToString(", ") { render(it) }
        is JsonObject -> v.entries.joinToString(", ") { (k, x) -> "$k: ${render(x)}" }
    }
}
