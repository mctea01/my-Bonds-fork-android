package diw.wallet.core.credential

import diw.wallet.core.document.image.ImageKind
import diw.wallet.core.util.DiwJson
import diw.wallet.core.w3c.W3cEncoding
import diw.wallet.core.w3c.W3cVcCredential
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborDouble
import org.multipaz.cbor.CborFloat
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
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
    private val dataUrl = Regex("^data:image/[a-z0-9.+-]+;base64,(.+)$", RegexOption.IGNORE_CASE)
    private val base64Text = Regex("^[A-Za-z0-9+/_-]{16,}={0,2}$")

    /** True when [b] starts like an image file of a kind the wallet knows (JPEG, PNG, GIF, WebP, TIFF, HEIF, JPEG 2000...). */
    fun isImage(b: ByteArray): Boolean = ImageKind.of(b) != null

    /**
     * The image in a text value: a data: URL, or base64 / base64url text that decodes to an image. Short values count
     * too (a test PID carries a 1 x 1 PNG); the decoded bytes must start like an image, so other text is never taken.
     */
    fun fromText(v: String): ByteArray? {
        val t = v.trim()
        dataUrl.matchEntire(t)?.let { m -> return decode(m.groupValues[1].filterNot { it.isWhitespace() })?.takeIf { isImage(it) } }
        if (!base64Text.matches(t)) return null
        return decode(t)?.takeIf { isImage(it) }
    }

    private fun decode(s: String): ByteArray? = runCatching {
        s.trimEnd('=').replace('+', '-').replace('/', '_').fromBase64Url()
    }.getOrNull()

    /** What a picture claim shows as text. */
    fun describe(b: ByteArray): String = "圖片（" + (ImageKind.of(b)?.title?.let { "$it，" } ?: "") + "${(b.size + 1023) / 1024} KB）"
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
                is MdocClaim -> plainCbor(claim.value)?.let { return it }
                is JsonClaim -> return render(claim.value)
                else -> {}
            }
        }
        if (claim is JsonClaim) sexCode(name, claim.value)?.let { return it }
        // Elements the document type does not describe are rendered by Multipaz as CBOR diagnostics ("\"PID\"", [..]).
        if (claim is MdocClaim && claim.attribute == null) plainCbor(claim.value)?.let { return it }
        // Even described structured elements (mDL driving_privileges and the like) are rendered by Multipaz as raw
        // CBOR diagnostics, so nested date tags show up as 1004("2025-02-28"). Render those ourselves to read cleanly.
        if (claim is MdocClaim && (claim.value is CborArray || claim.value is CborMap)) return mdocStructured(claim.value)
        return claim.render()
    }

    /** Text and lists of text as they read, without CBOR quoting; null for other values. */
    private fun plainCbor(v: DataItem): String? = when (v) {
        is Tstr -> v.value
        is CborArray -> v.items.takeIf { items -> items.all { it is Tstr } }?.joinToString(", ") { (it as Tstr).value }
        else -> null
    }

    /**
     * A structured CBOR value (a map or array, such as mDL driving_privileges) as readable text: date tags become
     * plain dates, maps become "key: value" pairs and arrays are joined, so no CBOR diagnostic notation leaks through.
     */
    private fun mdocStructured(v: DataItem): String = when (v) {
        is Tstr -> v.value
        is CborInt -> v.asNumber.toString()
        is CborDouble -> v.value.toString()
        is CborFloat -> v.value.toString()
        is Simple -> runCatching { if (v.asBoolean) "是" else "否" }.getOrDefault("")
        is Bstr -> v.value.let { if (ClaimPictures.isImage(it)) ClaimPictures.describe(it) else "${(it.size + 1023) / 1024} KB" }
        is Tagged -> when (v.tagNumber) {
            Tagged.FULL_DATE_STRING -> runCatching { v.asDateString.toString() }.getOrElse { mdocStructured(v.taggedItem) }
            Tagged.DATE_TIME_STRING -> runCatching { v.asDateTimeString.toString() }.getOrElse { mdocStructured(v.taggedItem) }
            else -> mdocStructured(v.taggedItem)
        }
        is CborArray -> v.items.joinToString("；") { mdocStructured(it) }
        is CborMap -> v.items.entries.joinToString("，") { (k, x) ->
            val key = (k as? Tstr)?.value?.let { mdocFieldLabels[it] ?: it } ?: mdocStructured(k)
            "$key: ${mdocStructured(x)}"
        }
        else -> v.toString()
    }

    /**
     * Readable names for the keys inside structured mdoc values such as mDL driving_privileges and its nested codes
     * (restrictions and endorsements). The code itself is always shown as its value; the full per-jurisdiction meaning
     * of a vehicle category or restriction code is left to the planned localisation work.
     */
    private val mdocFieldLabels = mapOf(
        "vehicle_category_code" to "類別代號",
        "issue_date" to "核發日",
        "expiry_date" to "到期日",
        "codes" to "附註",
        "code" to "代號",
        "sign" to "條件",
        "value" to "值",
    )

    /** ISO/IEC 5218 sex codes (the PID's sex claim) as words. */
    private fun sexCode(name: String, v: JsonElement): String? {
        if (name != "sex" && name != "gender") return null
        val code = (v as? JsonPrimitive)?.content?.toIntOrNull() ?: return null
        val word = when (code) { 0 -> "未知"; 1 -> "男"; 2 -> "女"; 9 -> "不適用"; else -> return null }
        return "$word（$code）"
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
        val text = picture?.let { ClaimPictures.describe(it) } ?: sexCode(label.substringAfterLast('.'), v) ?: render(v)
        return DisplayClaim(label, text, label.split('.'), picture)
    }

    private fun render(v: JsonElement): String = when (v) {
        is JsonPrimitive -> v.content
        is JsonArray -> v.joinToString(", ") { render(it) }
        is JsonObject -> v.entries.joinToString(", ") { (k, x) -> "$k: ${render(x)}" }
    }
}
