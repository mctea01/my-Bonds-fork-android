package diw.wallet.core.w3c

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url

/** One SD-JWT disclosure: [salt], claim [name] (null for an array element) and [value]. */
data class Disclosure(val encoded: String, val salt: String, val name: String?, val value: JsonElement) {
    val digest: String get() = SdJwtDisclosures.digest(encoded)
}

/** A compact SD-JWT split into its issuer JWT, disclosures and optional key binding JWT. */
data class SdJwtParts(val issuerJwt: String, val disclosures: List<Disclosure>, val keyBinding: String?) {
    /** The compact form with only [keep] disclosures, ending in '~' ready for a key binding JWT or none. */
    fun withDisclosures(keep: List<Disclosure>): String = (listOf(issuerJwt) + keep.map { it.encoded }).joinToString("~") + "~"
}

/**
 * SD-JWT (RFC 9901) disclosure processing that does not depend on the issuer key type or the credential
 * format: works for SD-JWT VC and for W3C credentials wrapped in SD-JWT (TWDIW).
 */
object SdJwtDisclosures {
    fun digest(encoded: String): String = PlatformCrypto.sha256(encoded.encodeToByteArray()).toBase64Url()

    fun parse(compact: String): SdJwtParts {
        val parts = compact.trim().split('~')
        val jwt = parts.first()
        val rest = parts.drop(1)
        val kb = rest.lastOrNull()?.takeIf { it.count { c -> c == '.' } == 2 }
        val disclosures = (if (kb != null) rest.dropLast(1) else rest).filter { it.isNotEmpty() }.map { decode(it) }
        return SdJwtParts(jwt, disclosures, kb)
    }

    fun decode(encoded: String): Disclosure {
        val arr = try {
            DiwJson.parseToJsonElement(encoded.fromBase64Url().decodeToString()) as JsonArray
        } catch (e: Exception) {
            throw ProtocolException("invalid_credential", "Malformed SD-JWT disclosure", e)
        }
        val salt = (arr.getOrNull(0) as? JsonPrimitive)?.content ?: throw ProtocolException("invalid_credential", "Disclosure without salt")
        return when (arr.size) {
            3 -> Disclosure(encoded, salt, (arr[1] as? JsonPrimitive)?.content ?: throw ProtocolException("invalid_credential", "Disclosure name is not a string"), arr[2])
            2 -> Disclosure(encoded, salt, null, arr[1])
            else -> throw ProtocolException("invalid_credential", "Disclosure must have 2 or 3 elements")
        }
    }

    /**
     * Checks that every disclosure is committed to by a digest in the payload or in another disclosure, that no
     * digest is used twice, and that _sd_alg is sha-256. Returns the payload with all disclosures applied.
     */
    fun resolve(payload: JsonObject, disclosures: List<Disclosure>): JsonObject {
        val alg = payload.str("_sd_alg") ?: "sha-256"
        if (alg != "sha-256") throw ProtocolException("invalid_credential", "Unsupported _sd_alg $alg")
        val byDigest = mutableMapOf<String, Disclosure>()
        for (d in disclosures) {
            if (byDigest.put(d.digest, d) != null) throw ProtocolException("invalid_credential", "Disclosure repeated")
        }
        val used = mutableSetOf<String>()
        val resolved = apply(payload, byDigest, used) as JsonObject
        val unused = byDigest.keys - used
        if (unused.isNotEmpty()) throw ProtocolException("invalid_credential", "A disclosure is not committed to by the issuer")
        return JsonObject(resolved - "_sd_alg")
    }

    private fun apply(e: JsonElement, byDigest: Map<String, Disclosure>, used: MutableSet<String>): JsonElement = when (e) {
        is JsonObject -> {
            val out = linkedMapOf<String, JsonElement>()
            for ((k, v) in e) if (k != "_sd") out[k] = apply(v, byDigest, used)
            (e["_sd"] as? JsonArray)?.forEach { h ->
                val digest = (h as? JsonPrimitive)?.content ?: return@forEach
                val d = byDigest[digest] ?: return@forEach
                if (!used.add(digest)) throw ProtocolException("invalid_credential", "Digest used twice")
                val name = d.name ?: throw ProtocolException("invalid_credential", "Array element disclosure used for an object member")
                if (name in out || name == "_sd" || name == "...") throw ProtocolException("invalid_credential", "Disclosed name $name clashes with the payload")
                out[name] = apply(d.value, byDigest, used)
            }
            JsonObject(out)
        }
        is JsonArray -> JsonArray(e.mapNotNull { item ->
            val ref = (item as? JsonObject)?.takeIf { it.size == 1 }?.get("...") as? JsonPrimitive
            if (ref == null) apply(item, byDigest, used) else {
                val d = byDigest[ref.content] ?: return@mapNotNull null
                if (!used.add(ref.content)) throw ProtocolException("invalid_credential", "Digest used twice")
                if (d.name != null) throw ProtocolException("invalid_credential", "Object member disclosure used for an array element")
                apply(d.value, byDigest, used)
            }
        })
        else -> e
    }

    /**
     * The disclosures needed to reveal [paths] (each a list of object member names) and their ancestors.
     * Disclosures for members on a path, and for the objects that contain them, are kept; others are dropped.
     */
    fun select(payload: JsonObject, disclosures: List<Disclosure>, paths: List<List<String>>): List<Disclosure> {
        val byDigest = disclosures.associateBy { it.digest }
        val keep = linkedSetOf<Disclosure>()
        fun walk(node: JsonElement, path: List<String>) {
            if (path.isEmpty()) {
                // The whole subtree is requested: keep every disclosure under it.
                collectAll(node, byDigest, keep)
                return
            }
            val obj = node as? JsonObject ?: return
            val head = path.first()
            obj[head]?.let { walk(it, path.drop(1)); return }
            (obj["_sd"] as? JsonArray)?.forEach { h ->
                val d = byDigest[(h as? JsonPrimitive)?.content] ?: return@forEach
                if (d.name == head) { keep += d; walk(d.value, path.drop(1)) }
            }
        }
        for (p in paths) walk(payload, p)
        return disclosures.filter { it in keep }
    }

    private fun collectAll(node: JsonElement, byDigest: Map<String, Disclosure>, keep: MutableSet<Disclosure>) {
        when (node) {
            is JsonObject -> {
                (node["_sd"] as? JsonArray)?.forEach { h -> byDigest[(h as? JsonPrimitive)?.content]?.let { keep += it; collectAll(it.value, byDigest, keep) } }
                node.forEach { (k, v) -> if (k != "_sd") collectAll(v, byDigest, keep) }
            }
            is JsonArray -> node.forEach { item ->
                val ref = ((item as? JsonObject)?.get("...") as? JsonPrimitive)?.content
                if (ref != null) byDigest[ref]?.let { keep += it; collectAll(it.value, byDigest, keep) } else collectAll(item, byDigest, keep)
            }
            else -> {}
        }
    }
}
