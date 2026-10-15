package diw.wallet.core.document.opencerts

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.util.DiwJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/** How an issuer publishes what it issued: an Ethereum document store, a token registry, or a DID signature. */
enum class OaMethod { DOCUMENT_STORE, TOKEN_REGISTRY, DID, NONE }

/** One issuer of an OpenAttestation document, with how it proves its identity and publishes issuance. */
data class OaIssuer(
    val name: String?,
    val url: String?,
    val method: OaMethod,
    /** Document store, token registry or DID, by [method]. */
    val value: String?,
    /** DNS-TXT, DNS-DID or none. */
    val identityType: String?,
    /** The domain of a DNS identity proof. */
    val identityLocation: String?,
    /** The DID key (did:ethr:0x...#controller) a DNS-DID record must name. */
    val identityKey: String?,
    /** Revocation of DID signed documents: NONE, REVOCATION_STORE or OCSP_RESPONDER. */
    val revocationType: String? = null,
    val revocationLocation: String? = null,
)

/** A signature of the Merkle root by a DID key (OpenAttestationSignature2018). */
data class OaDidSignature(val key: String, val signature: String)

/** A signatory printed on the certificate, with the signature image when there is one. */
class OaSignatory(val name: String?, val position: String?, val organisation: String?, val image: ByteArray?)

/** A file attached to the document. */
class OaAttachment(val name: String, val type: String?, val bytes: ByteArray)

/** What the certificate shows, read from its data for the file screen. */
class OpenCertView(
    val title: String?,
    val recipient: List<Pair<String, String>>,
    val main: List<Pair<String, String>>,
    val issuers: List<OaIssuer>,
    val signatories: List<OaSignatory>,
    /** Column labels and rows of the transcript. */
    val transcriptColumns: List<String>,
    val transcript: List<List<String>>,
    val images: List<Pair<String, ByteArray>>,
    val attachments: List<OaAttachment>,
    val other: List<Pair<String, String>>,
    val templateName: String?,
    val templateUrl: String?,
)

/**
 * A wrapped OpenAttestation document (OpenCerts), version 2 or 3: its integrity (the salted data hashes to the target
 * hash, which a Merkle proof links to the root the issuer published), its issuers, and what it shows. Version 2
 * salts every value as "salt:type:value" and hashes each flattened {path: value} pair; version 3 keeps the values
 * plain and lists the salts in the proof. Online checks are in [OpenAttestationOnline].
 */
class OpenAttestationDocument private constructor(val raw: JsonObject) {
    val v3: Boolean = raw["openAttestationMetadata"] is JsonObject || (raw["version"] as? JsonPrimitive)?.contentOrNull?.contains("3.0") == true

    /** The document data: the unsalted data of version 2, the document without its proof for version 3. */
    val data: JsonObject = if (v3) JsonObject(raw - "proof") else unsalt(raw["data"] as? JsonObject ?: JsonObject(emptyMap())) as JsonObject

    private val proofObject: JsonObject? = (if (v3) raw["proof"] else raw["signature"]) as? JsonObject

    val targetHash: String? = proofObject.text("targetHash")
    val merkleRoot: String? = proofObject.text("merkleRoot")
    val proofs: List<String> = ((proofObject?.get(if (v3) "proofs" else "proof")) as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()

    val version: String = (raw["version"] as? JsonPrimitive)?.contentOrNull ?: if (v3) "open-attestation/3.0" else "open-attestation/2.0"

    /** Whether the content hashes to the target hash and the Merkle proof leads to the root. */
    val integrity: Check by lazy { runCatching { if (checkIntegrity()) Check.PASS else Check.FAIL }.getOrDefault(Check.FAIL) }

    val issuers: List<OaIssuer> by lazy { if (v3) listOf(v3Issuer()) else v2Issuers() }

    /** Signatures of the Merkle root by DID keys. */
    val didSignatures: List<OaDidSignature> by lazy {
        if (v3) {
            val key = proofObject.text("key")
            val sig = proofObject.text("signature")
            if (key != null && sig != null) listOf(OaDidSignature(key, sig)) else emptyList()
        } else {
            (raw["proof"] as? JsonArray)?.mapNotNull { p ->
                val o = p as? JsonObject ?: return@mapNotNull null
                if (o.text("type") != "OpenAttestationSignature2018") return@mapNotNull null
                val key = o.text("verificationMethod") ?: return@mapNotNull null
                val sig = o.text("signature") ?: return@mapNotNull null
                OaDidSignature(key, sig)
            }.orEmpty()
        }
    }

    val name: String? get() = data.text("name") ?: (if (v3) (data["credentialSubject"] as? JsonObject).text("name") else null)

    val templateUrl: String? get() = template().text("url")

    /** Scalar values by flattened path, without images and other long encoded values. */
    fun fields(limit: Int = 60): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        flattenDots(data, "", out)
        return out.filterValues { v -> !(v.startsWith("data:") || v.length > 400) }.entries.take(limit).associate { it.key to it.value }
    }

    private fun template(): JsonObject? = (if (v3) (data["openAttestationMetadata"] as? JsonObject)?.get("template") else data["\$template"]) as? JsonObject

    private fun checkIntegrity(): Boolean {
        val target = targetHash ?: return false
        val root = merkleRoot ?: return false
        val digest = if (v3) v3Digest() ?: return false else v2Digest()
        if (!digest.equals(target.removePrefix("0x"), ignoreCase = true)) return false
        return proofs.fold(target.removePrefix("0x")) { acc, p -> combine(acc, p) }.equals(root.removePrefix("0x"), ignoreCase = true)
    }

    private fun v2Digest(): String {
        val flat = LinkedHashMap<String, JsonElement>()
        flattenElements(raw["data"] ?: JsonObject(emptyMap()), "", flat)
        val hashes = flat.map { (k, v) -> keccakHex(stringify(JsonObject(mapOf(k to v)))) }
        val obfuscated = ((raw["privacy"] as? JsonObject)?.get("obfuscatedData") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
        return keccakHex(stringify(JsonArray((hashes + obfuscated).sorted().map { JsonPrimitive(it) })))
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun v3Digest(): String? {
        val saltsText = proofObject.text("salts") ?: return null
        val salts = (DiwJson.parseToJsonElement(Base64.decode(saltsText).decodeToString()) as? JsonArray)?.mapNotNull { s ->
            val o = s as? JsonObject ?: return@mapNotNull null
            val value = o.text("value") ?: return@mapNotNull null
            val path = o.text("path") ?: return@mapNotNull null
            if (value.length != 64) return null
            path to value
        } ?: return null
        val leaves = LinkedHashMap<String, JsonElement>()
        flattenV3(data, "", leaves)
        // No value may be added or removed: every visible leaf has exactly one salt.
        if (leaves.size != salts.size) return null
        val hashes = salts.filter { (path, _) -> path in leaves }.map { (path, salt) ->
            keccakHex(stringify(JsonObject(mapOf(path to JsonPrimitive("$salt:" + jsText(leaves.getValue(path)))))))
        }
        val obfuscated = (((proofObject?.get("privacy") as? JsonObject)?.get("obfuscated")) as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
        return keccakHex(stringify(JsonArray((obfuscated + hashes).sorted().map { JsonPrimitive(it) })))
    }

    private fun v2Issuers(): List<OaIssuer> = ((data["issuers"] as? JsonArray) ?: JsonArray(emptyList())).mapNotNull { e ->
        val o = e as? JsonObject ?: return@mapNotNull null
        val proof = o["identityProof"] as? JsonObject
        val store = o.text("documentStore") ?: o.text("certificateStore")
        val token = o.text("tokenRegistry")
        val did = o.text("id")?.takeIf { it.startsWith("did:") }
        val method = when {
            store != null -> OaMethod.DOCUMENT_STORE
            token != null -> OaMethod.TOKEN_REGISTRY
            did != null || proof.text("type") == "DID" || proof.text("type") == "DNS-DID" -> OaMethod.DID
            else -> OaMethod.NONE
        }
        val revocation = o["revocation"] as? JsonObject
        OaIssuer(
            name = o.text("name"), url = o.text("url"), method = method,
            value = store ?: token ?: did ?: proof.text("key")?.substringBefore('#'),
            identityType = proof.text("type"), identityLocation = proof.text("location"), identityKey = proof.text("key"),
            revocationType = revocation.text("type"), revocationLocation = revocation.text("location"),
        )
    }

    private fun v3Issuer(): OaIssuer {
        val meta = data["openAttestationMetadata"] as? JsonObject
        val proof = meta?.get("proof") as? JsonObject
        val identity = meta?.get("identityProof") as? JsonObject
        val issuer = data["issuer"] as? JsonObject
        val revocation = proof?.get("revocation") as? JsonObject
        val method = when (proof.text("method")) {
            "DOCUMENT_STORE" -> OaMethod.DOCUMENT_STORE
            "TOKEN_REGISTRY" -> OaMethod.TOKEN_REGISTRY
            "DID" -> OaMethod.DID
            else -> OaMethod.NONE
        }
        return OaIssuer(
            name = issuer.text("name"), url = issuer.text("id")?.takeIf { it.startsWith("http") }, method = method,
            value = proof.text("value"), identityType = identity.text("type"), identityLocation = identity.text("identifier"),
            identityKey = if (identity.text("type") == "DNS-DID") proofObject.text("key") else null,
            revocationType = revocation.text("type"), revocationLocation = revocation.text("location"),
        )
    }

    /** What the certificate shows, for the file screen. */
    fun view(): OpenCertView {
        val used = HashSet<String>()
        fun take(path: String): String? = textAt(data, path)?.also { used.add(path) }
        val subject = if (v3) "credentialSubject" else "recipient"
        val recipient = buildList {
            take("$subject.name")?.let { add("姓名" to it) }
            (data[subject] as? JsonObject)?.forEach { (k, v) ->
                if (k == "name" || k == "id" && v3) return@forEach
                (v as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }?.let { add((LABELS[k] ?: humanize(k)) to it); used.add("$subject.$k") }
            }
        }
        val main = buildList {
            for (key in listOf("id", "issuedOn", "issuanceDate", "validFrom", "expiresOn", "expirationDate", "admissionDate", "graduationDate", "attainmentDate", "description")) {
                take(key)?.let { add((LABELS[key] ?: humanize(key)) to it) }
            }
        }
        val additional = data["additionalData"] as? JsonObject
        val signatories = ((additional?.get("certSignatories")) as? JsonArray)?.mapNotNull { s ->
            val o = s as? JsonObject ?: return@mapNotNull null
            OaSignatory(o.text("name"), o.text("position"), o.text("organisation") ?: o.text("organization"), o.text("signature")?.let { dataUrlBytes(it) })
        }.orEmpty()
        val images = buildList {
            ((additional?.get("images")) as? JsonObject)?.forEach { (k, v) -> (v as? JsonPrimitive)?.contentOrNull?.let { dataUrlBytes(it) }?.let { add(humanize(k) to it) } }
            data.text("logo")?.let { dataUrlBytes(it) }?.let { add("標誌" to it) }
        }
        val rows = ((data["transcript"]) as? JsonArray)?.mapNotNull { it as? JsonObject }.orEmpty()
        val columns = rows.flatMap { it.keys }.distinct()
        val transcript = rows.map { r -> columns.map { c -> (r[c] as? JsonPrimitive)?.contentOrNull ?: "" } }
        val attachments = ((data["attachments"]) as? JsonArray)?.mapNotNull { a ->
            val o = a as? JsonObject ?: return@mapNotNull null
            val bytes = (o.text("data") ?: return@mapNotNull null).let { d -> runCatching { base64(d) }.getOrNull() } ?: return@mapNotNull null
            OaAttachment(o.text("filename") ?: o.text("fileName") ?: "attachment", o.text("type") ?: o.text("mimeType"), bytes)
        }.orEmpty()
        val skipped = Regex("^(\\\$template|issuers|issuer|transcript|attachments|logo|signature|privacy|proof|openAttestationMetadata|@context|type|version|schema|name|credentialSubject|recipient|additionalData\\.(certSignatories|images))(\\.|\\[|$)")
        val other = fields(200).filterKeys { it !in used && !skipped.containsMatchIn(it) }.map { (k, v) -> label(k) to v }
        return OpenCertView(
            title = name, recipient = recipient, main = main, issuers = issuers, signatories = signatories,
            transcriptColumns = columns.map { LABELS[it] ?: humanize(it) }, transcript = transcript, images = images,
            attachments = attachments, other = other, templateName = template().text("name"), templateUrl = templateUrl,
        )
    }

    /** The document as the issuer's renderer expects it: the unsalted data (version 2) or the document (version 3). */
    fun rendererDocument(): JsonObject = if (v3) raw else data

    companion object {
        /** Display labels of well known fields. */
        private val LABELS = mapOf(
            "id" to "證書編號", "issuedOn" to "發證日期", "issuanceDate" to "發證日期", "validFrom" to "生效日期", "expiresOn" to "到期日期",
            "expirationDate" to "到期日期", "admissionDate" to "入學日期", "graduationDate" to "畢業日期", "attainmentDate" to "取得日期",
            "description" to "說明", "studentId" to "學號", "nric" to "身分證號", "email" to "電子郵件", "course" to "課程",
            "programme" to "學程", "name" to "名稱", "grade" to "成績", "courseCredit" to "學分", "courseCode" to "課程代碼",
            "examinationDate" to "考試日期", "semester" to "學期", "merit" to "優異", "transcriptId" to "成績單編號",
        )

        fun looksLike(o: JsonObject): Boolean =
            ("data" in o && (o["signature"] as? JsonObject).text("type") == "SHA3MerkleProof") ||
                (o["proof"] as? JsonObject).text("type") == "OpenAttestationMerkleProofSignature2018" ||
                (o["version"] as? JsonPrimitive)?.contentOrNull?.contains("openattestation", ignoreCase = true) == true

        fun parse(bytes: ByteArray): OpenAttestationDocument? {
            val o = runCatching { DiwJson.parseToJsonElement(bytes.decodeToString().removePrefix("﻿")) as? JsonObject }.getOrNull() ?: return null
            return if (looksLike(o)) OpenAttestationDocument(o) else null
        }

        fun keccakHex(s: String): String = DocCryptoUtil.hex(DocCrypto.keccak256(s.encodeToByteArray()))

        /** keccak256 of the two hashes sorted and joined (the OpenAttestation Merkle step). */
        fun combine(a: String, b: String): String {
            val x = DocCryptoUtil.unhex(a.removePrefix("0x"))
            val y = DocCryptoUtil.unhex(b.removePrefix("0x"))
            val (first, second) = if (compare(x, y) <= 0) x to y else y to x
            return DocCryptoUtil.hex(DocCrypto.keccak256(first + second))
        }

        /** The hashes from the target hash up to the root: the target and each Merkle step (for revocation checks). */
        fun intermediateHashes(target: String, proofs: List<String>): List<String> {
            val out = arrayListOf(target.removePrefix("0x"))
            proofs.fold(target.removePrefix("0x")) { acc, p -> combine(acc, p).also { out.add(it) } }
            return out
        }

        private fun compare(a: ByteArray, b: ByteArray): Int {
            for (i in 0 until minOf(a.size, b.size)) {
                val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
                if (d != 0) return d
            }
            return a.size - b.size
        }

        /** "salt:type:value" strings of version 2 data back to their values. */
        private fun unsalt(e: JsonElement): JsonElement = when (e) {
            is JsonObject -> JsonObject(e.mapValues { unsalt(it.value) })
            is JsonArray -> JsonArray(e.map { unsalt(it) })
            is JsonPrimitive -> if (!e.isString) e else {
                val m = Regex("^[0-9a-fA-F-]{36}:(string|number|boolean|null|undefined):(.*)$", RegexOption.DOT_MATCHES_ALL).matchEntire(e.content)
                when (m?.groupValues?.get(1)) {
                    null -> e
                    "string" -> JsonPrimitive(m.groupValues[2])
                    "number" -> m.groupValues[2].let { v -> v.toLongOrNull()?.let { JsonPrimitive(it) } ?: v.toDoubleOrNull()?.let { JsonPrimitive(it) } ?: JsonPrimitive(v) }
                    "boolean" -> JsonPrimitive(m.groupValues[2] == "true")
                    else -> JsonNull
                }
            }
        }

        /** flat/flatley semantics of version 2: nested objects and arrays become dot paths; empty ones stay as values. */
        private fun flattenElements(e: JsonElement, prefix: String, out: MutableMap<String, JsonElement>) {
            when {
                e is JsonObject && e.isNotEmpty() -> e.forEach { (k, v) -> flattenElements(v, if (prefix.isEmpty()) k else "$prefix.$k", out) }
                e is JsonArray && e.isNotEmpty() -> e.forEachIndexed { i, v -> flattenElements(v, if (prefix.isEmpty()) "$i" else "$prefix.$i", out) }
                else -> out[prefix] = e
            }
        }

        /** traverseAndFlatten of version 3: object keys joined by dots, array items as [i]; only scalar leaves. */
        private fun flattenV3(e: JsonElement, path: String, out: MutableMap<String, JsonElement>) {
            when (e) {
                is JsonArray -> e.forEachIndexed { i, v -> flattenV3(v, "$path[$i]", out) }
                is JsonObject -> e.forEach { (k, v) -> flattenV3(v, if (path.isEmpty()) k else "$path.$k", out) }
                else -> out[path] = e
            }
        }

        private fun flattenDots(e: JsonElement, prefix: String, out: MutableMap<String, String>) {
            when (e) {
                is JsonObject -> e.forEach { (k, v) -> flattenDots(v, if (prefix.isEmpty()) k else "$prefix.$k", out) }
                is JsonArray -> e.forEachIndexed { i, v -> flattenDots(v, if (prefix.isEmpty()) "$i" else "$prefix.$i", out) }
                is JsonNull -> {}
                is JsonPrimitive -> out[prefix] = e.content
            }
        }

        /** A value as JavaScript's template string writes it. */
        private fun jsText(e: JsonElement): String = when {
            e is JsonNull -> "null"
            e is JsonPrimitive && e.isString -> e.content
            e is JsonPrimitive -> e.booleanOrNull?.toString() ?: e.longOrNull?.toString() ?: e.doubleOrNull?.let { d ->
                if (d == kotlin.math.floor(d) && kotlin.math.abs(d) < 1e21) d.toLong().toString() else d.toString()
            } ?: e.content
            else -> e.toString()
        }

        private fun textAt(o: JsonObject, path: String): String? {
            var cur: JsonElement? = o
            for (part in path.split('.')) cur = (cur as? JsonObject)?.get(part) ?: return null
            return (cur as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }
        }

        private fun JsonObject?.text(k: String): String? = (this?.get(k) as? JsonPrimitive)?.contentOrNull

        /** "additionalData.studentId" reads "Student Id"; array indexes are dropped. */
        private fun label(path: String): String =
            path.split('.').filter { it.toIntOrNull() == null }.takeLast(2).joinToString(" / ") { LABELS[it] ?: humanize(it) }

        private fun humanize(key: String): String =
            key.replace(Regex("([a-z0-9])([A-Z])"), "$1 $2").replace('_', ' ').replace('-', ' ').trim().replaceFirstChar { it.uppercase() }

        private fun dataUrlBytes(s: String): ByteArray? {
            if (!s.startsWith("data:")) return null
            val comma = s.indexOf(',')
            if (comma < 0 || !s.substring(0, comma).endsWith(";base64")) return null
            return runCatching { base64(s.substring(comma + 1)) }.getOrNull()
        }

        @OptIn(ExperimentalEncodingApi::class)
        private fun base64(s: String): ByteArray = Base64.Mime.decode(s)

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
}
