package diw.wallet.core.w3c

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.long
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

/** Read-only helpers over the W3C Verifiable Credentials Data Model 1.1 and 2.0, in JWT, SD-JWT and JSON-LD form. */
object W3cVc {
    const val CONTEXT_V1 = "https://www.w3.org/2018/credentials/v1"
    const val CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"

    /** JWT payload of a JWT or SD-JWT encoded credential; null for JSON-LD. */
    fun jwtPayloadOrNull(raw: String, encoding: W3cEncoding): JsonObject? = when (encoding) {
        W3cEncoding.JSON_LD -> null
        else -> runCatching { base64UrlJson(raw.substringBefore('~').trim().split('.')[1]) }.getOrNull()
    }

    /**
     * The credential object: the vc claim (VCDM 1.1 JWT), the payload itself (VCDM 2.0 vc+jwt), or the JSON-LD document.
     * For an SD-JWT, selectively disclosable members stay as _sd digests; [diw.wallet.core.credential.ClaimReader] resolves them.
     */
    fun credentialObject(raw: String, encoding: W3cEncoding): JsonObject = when (encoding) {
        W3cEncoding.JSON_LD -> DiwJson.parseToJsonElement(raw) as? JsonObject
            ?: throw ProtocolException("invalid_credential", "JSON-LD credential is not an object")
        else -> {
            val payload = jwtPayloadOrNull(raw, encoding) ?: throw ProtocolException("invalid_credential", "Malformed JWT credential")
            payload.obj("vc") ?: payload
        }
    }

    fun types(vc: JsonObject): List<String> = vc.strList("type")

    /** Issuer identifier: JWT iss, else the issuer member (string or object with id). */
    fun issuer(vc: JsonObject, jwt: JsonObject?): String? = jwt?.str("iss") ?: vc.idOf("issuer")

    /** Holder identifier: JWT sub, else credentialSubject.id. */
    fun subject(vc: JsonObject, jwt: JsonObject?): String? =
        jwt?.str("sub") ?: (vc["credentialSubject"] as? JsonObject)?.str("id")
            ?: ((vc["credentialSubject"] as? JsonArray)?.firstOrNull() as? JsonObject)?.str("id")

    fun validity(vc: JsonObject, jwt: JsonObject?): Pair<Instant?, Instant?> {
        val from = jwt?.long("nbf")?.let { Instant.fromEpochSeconds(it) }
            ?: date(vc.str("validFrom")) ?: date(vc.str("issuanceDate")) ?: jwt?.long("iat")?.let { Instant.fromEpochSeconds(it) }
        val until = jwt?.long("exp")?.let { Instant.fromEpochSeconds(it) } ?: date(vc.str("validUntil")) ?: date(vc.str("expirationDate"))
        return from to until
    }

    /** credentialStatus entries (one object or an array, as TWDIW uses for revocation and suspension). */
    fun statusEntries(vc: JsonObject): List<JsonObject> = when (val s = vc["credentialStatus"]) {
        is JsonObject -> listOf(s)
        is JsonArray -> s.filterIsInstance<JsonObject>()
        else -> emptyList()
    }

    fun date(s: String?): Instant? = s?.let { runCatching { Instant.parse(it) }.getOrNull() }

    /** Human-readable credential type: the most specific type, with TWDIW's taxId_name_timestamp shape shortened. */
    fun displayType(types: List<String>): String? {
        val t = types.lastOrNull { it != "VerifiableCredential" } ?: return null
        val parts = t.split('_')
        return if (parts.size >= 3 && parts.first().all { it.isDigit() } && parts.last().all { it.isDigit() })
            parts.subList(1, parts.size - 1).joinToString("_") else t
    }
}
