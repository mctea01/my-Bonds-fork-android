package diw.wallet.core.document

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.crypto.digests.KeccakDigest

/**
 * OpenAttestation (OpenCerts) documents. Version 2: every value in data is salted as "salt:type:value"; the target
 * hash is keccak256 of the sorted keccak256 hashes of each flattened {path: value} pair (plus the obfuscated
 * hashes), and a Merkle proof links it to the root the issuer published. The issuer's publication (an Ethereum
 * document store or a DNS record) is not queried: OpenCerts files are imported and kept, not verified online.
 */
internal object OpenCerts {
    private val json = Json { ignoreUnknownKeys = true }

    fun looksLike(o: JsonObject): Boolean =
        ("data" in o && "signature" in o && (o["signature"] as? JsonObject)?.get("type")?.jsonPrimitive?.contentOrNull == "SHA3MerkleProof") ||
            (o["version"] as? JsonPrimitive)?.contentOrNull?.contains("openattestation") == true

    fun inspect(o: JsonObject): OpenCertInfo {
        val version = (o["version"] as? JsonPrimitive)?.contentOrNull ?: "open-attestation/2.0"
        val data = o["data"] as? JsonObject
        if (data == null) {
            return OpenCertInfo(version, (o["name"] as? JsonPrimitive)?.contentOrNull, emptyList(), emptyList(), emptyMap(), Check.NOT_CHECKED, Check.NOT_CHECKED)
        }
        val flat = LinkedHashMap<String, JsonElement>()
        flatten(data, "", flat)
        val hashes = flat.map { (k, v) -> keccakHex(stringify(JsonObject(mapOf(k to v)))) }
        val obfuscated = ((o["privacy"] as? JsonObject)?.get("obfuscatedData") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
        val target = keccakHex(stringify(JsonArray((hashes + obfuscated).sorted().map { JsonPrimitive(it) })))
        val sig = o["signature"]?.jsonObject
        val targetHash = (sig?.get("targetHash") as? JsonPrimitive)?.contentOrNull
        val root = (sig?.get("merkleRoot") as? JsonPrimitive)?.contentOrNull
        val proof = (sig?.get("proof") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
        val integrity = if (targetHash != null && root != null && target.equals(targetHash, true) &&
            proof.fold(targetHash) { acc, p -> combine(acc, p) }.equals(root, true)) Check.PASS else Check.FAIL

        val values = flat.mapValues { (_, v) -> unsalt(v) }
        val issuers = values.filterKeys { Regex("issuers\\.\\d+\\.name").matches(it) }.values.filterNotNull()
        val proofs = ArrayList<String>()
        val issuerIdx = values.keys.mapNotNull { Regex("issuers\\.(\\d+)\\..*").matchEntire(it)?.groupValues?.get(1)?.toInt() }.distinct()
        for (i in issuerIdx) {
            val p = "issuers.$i."
            values[p + "identityProof.type"]?.let { t -> proofs.add(t + (values[p + "identityProof.location"]?.let { "：$it" } ?: "")) }
            listOf("documentStore", "certificateStore", "tokenRegistry").forEach { k -> values[p + k]?.let { proofs.add("$k $it") } }
        }
        val fields = values.filterValues { it != null }.mapValues { it.value!! }.entries.take(60).associate { it.key to it.value }
        return OpenCertInfo(
            version = version,
            name = values["name"] ?: values["\$template.name"],
            issuers = issuers,
            identityProofs = proofs,
            fields = fields,
            integrity = integrity,
            issuerVerified = Check.NOT_CHECKED,
        )
    }

    fun parse(bytes: ByteArray): JsonObject? = runCatching { json.parseToJsonElement(bytes.decodeToString().removePrefix("﻿")).jsonObject }.getOrNull()

    /** The value of a salted "salt:type:value" string, or the plain value. */
    private fun unsalt(v: JsonElement): String? {
        val s = (v as? JsonPrimitive)?.contentOrNull ?: return if (v is JsonNull) null else v.toString()
        val m = Regex("^[0-9a-fA-F-]{36}:(string|number|boolean|null|undefined):(.*)$", RegexOption.DOT_MATCHES_ALL).matchEntire(s) ?: return s
        return when (m.groupValues[1]) {
            "null", "undefined" -> null
            else -> m.groupValues[2]
        }
    }

    /** flat/flatley semantics: nested objects and arrays become dot paths; empty ones stay as values. */
    private fun flatten(e: JsonElement, prefix: String, out: MutableMap<String, JsonElement>) {
        when {
            e is JsonObject && e.isNotEmpty() -> e.forEach { (k, v) -> flatten(v, if (prefix.isEmpty()) k else "$prefix.$k", out) }
            e is JsonArray && e.isNotEmpty() -> e.forEachIndexed { i, v -> flatten(v, if (prefix.isEmpty()) "$i" else "$prefix.$i", out) }
            else -> out[prefix] = e
        }
    }

    private fun combine(a: String, b: String): String {
        val x = DocCryptoUtil.unhex(a.removePrefix("0x"))
        val y = DocCryptoUtil.unhex(b.removePrefix("0x"))
        val (first, second) = if (compare(x, y) <= 0) x to y else y to x
        return keccakHex(first + second)
    }

    private fun compare(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    fun keccakHex(s: String): String = keccakHex(s.toByteArray(Charsets.UTF_8))

    fun keccakHex(b: ByteArray): String {
        val d = KeccakDigest(256)
        d.update(b, 0, b.size)
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return DocCryptoUtil.hex(out)
    }

    /** JSON.stringify with JavaScript's escaping and key order. */
    fun stringify(e: JsonElement): String = when (e) {
        is JsonNull -> "null"
        is JsonPrimitive -> if (e.isString) jsString(e.content) else e.content
        is JsonArray -> e.joinToString(",", "[", "]") { stringify(it) }
        is JsonObject -> e.entries.joinToString(",", "{", "}") { jsString(it.key) + ":" + stringify(it.value) }
    }

    private fun jsString(s: String): String {
        val b = StringBuilder(s.length + 2).append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> b.append("\\\"")
                c == '\\' -> b.append("\\\\")
                c == '\b' -> b.append("\\b")
                c == '\u000C' -> b.append("\\f")
                c == '\n' -> b.append("\\n")
                c == '\r' -> b.append("\\r")
                c == '\t' -> b.append("\\t")
                c < ' ' -> b.append("\\u" + c.code.toString(16).padStart(4, '0'))
                c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> { b.append(c).append(s[i + 1]); i++ }
                c.isSurrogate() -> b.append("\\u" + c.code.toString(16).padStart(4, '0'))
                else -> b.append(c)
            }
            i++
        }
        return b.append('"').toString()
    }
}
