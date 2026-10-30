package diw.wallet.core.document.c2pa

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.util.DiwJson
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborDouble
import org.multipaz.cbor.CborFloat
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import kotlin.io.encoding.Base64

/** One action of a manifest (c2pa.actions): what was done, when, with which tool. */
@Serializable
data class C2paAction(
    val action: String,
    val time: String? = null,
    val softwareAgent: String? = null,
    val digitalSourceType: String? = null,
    val description: String? = null,
)

/** An ingredient: a file the asset was made from, with its relationship and the manifest it carried. */
@Serializable
data class C2paIngredient(val title: String?, val format: String?, val relationship: String?, val manifest: String?)

/** A CAWG identity assertion: who the named actor is and how that is bound ([sigType]). */
@Serializable
data class C2paIdentity(
    val sigType: String,
    val names: List<String>,
    val issuer: String? = null,
    val signature: Check = Check.NOT_CHECKED,
    val detail: List<String> = emptyList(),
)

/** A validation result in the C2PA specification's own codes (claimSignature.validated, assertion.dataHash.match...). */
@Serializable
data class C2paStatus(val code: String, val url: String?, val success: Boolean, val explanation: String? = null)

/** What one manifest says about the asset, with the results of checking it. */
@Serializable
data class C2paManifestInfo(
    val label: String,
    val active: Boolean,
    val claimVersion: Int,
    val title: String?,
    val format: String?,
    val generator: String?,
    val instanceId: String?,
    val signer: String? = null,
    val signedAt: Long? = null,
    val actions: List<C2paAction> = emptyList(),
    val ingredients: List<C2paIngredient> = emptyList(),
    val authors: List<String> = emptyList(),
    val identities: List<C2paIdentity> = emptyList(),
    /** AI training and data mining choices (c2pa.training-mining, cawg.training-mining). */
    val training: List<String> = emptyList(),
    val assertions: List<String> = emptyList(),
    val statuses: List<C2paStatus> = emptyList(),
)

/** The content credentials of a file: every manifest of its store, the active one first. */
@Serializable
data class C2paInfo(
    val activeManifest: String?,
    val manifests: List<C2paManifestInfo>,
    /** Where the store was found: JPEG APP11, PNG caBX, WebP C2PA chunk or a sidecar (.c2pa) file. */
    val container: String,
)

/** A JUMBF superbox: its label and type UUID, its content boxes and the superboxes inside it. */
class JumbfSuperbox internal constructor(
    val label: String?,
    val uuid: String,
    private val store: ByteArray,
    private val start: Int,
    private val header: Int,
    private val end: Int,
    val contents: List<Pair<String, ByteArray>>,
    val children: List<JumbfSuperbox>,
) {
    /** The bytes C2PA hashes for a hashed URI: the description box and the content boxes, not the superbox header. */
    val hashedBytes: ByteArray get() = store.copyOfRange(start + header, end)

    fun child(label: String): JumbfSuperbox? = children.firstOrNull { it.label == label }
    fun content(type: String): ByteArray? = contents.firstOrNull { it.first == type }?.second
}

/** A hashed URI of a claim: the JUMBF URL of an assertion, the digest of its box and the algorithm. */
class C2paHashedUri(val url: String, val hash: ByteArray, val algorithm: String?)

/** The COSE_Sign1 claim signature of a manifest (detached payload: the claim). */
class C2paCose(
    val protectedBytes: ByteArray,
    val algorithm: Int?,
    /** The signer certificate first. */
    val chain: List<ByteArray>,
    /** RFC 3161 tokens (or responses) of sigTst or sigTst2, with the header that held them. */
    val timestamps: List<Pair<String, ByteArray>>,
    val ocsps: List<ByteArray>,
    val signature: ByteArray,
    val payload: ByteArray?,
)

/** One manifest as read: the claim, its assertions and its signature, before any cryptographic check. */
class C2paManifest(
    val label: String,
    val box: JumbfSuperbox,
    val claimVersion: Int,
    val claimBytes: ByteArray,
    val claim: JsonObject,
    val assertionRefs: List<C2paHashedUri>,
    val algorithm: String?,
    val cose: C2paCose?,
)

/** A manifest store found in a file. [asset] is the whole file the hard binding is computed over (null for a sidecar). */
class C2paStore(val container: String, val root: JumbfSuperbox, val manifests: List<C2paManifest>, val asset: ByteArray?) {
    /** The active manifest: the last one in the store (C2PA 2.x, 11.1). */
    val active: C2paManifest? get() = manifests.lastOrNull()

    fun manifest(label: String): C2paManifest? = manifests.firstOrNull { it.label == label }

    /**
     * The superbox a JUMBF URI names: absolute (self#jumbf=/c2pa/<manifest>/...) or relative to [base]
     * (self#jumbf=c2pa.assertions/...).
     */
    fun resolve(url: String, base: C2paManifest): JumbfSuperbox? {
        val path = url.substringAfter("jumbf=", url)
        val parts = path.trim('/').split('/').filter { it.isNotEmpty() }
        var cur: JumbfSuperbox? = if (path.startsWith("/")) {
            if (parts.firstOrNull() != root.label) return null
            root
        } else base.box
        for (p in if (path.startsWith("/")) parts.drop(1) else parts) cur = cur?.child(p) ?: return null
        return cur
    }
}

/**
 * Reads C2PA manifest stores (C2PA 1.x and 2.x) in pure Kotlin: finds the JUMBF store in JPEG (APP11), PNG (caBX),
 * WebP (C2PA chunk) or a sidecar file, decodes the claims (v1 and v2) and assertions, and checks what needs no key:
 * the hashed URIs of the assertions and the data hash (hard binding) over the file. The claim signatures are checked
 * by the platform inspector, which also judges the signer certificate with the trust registry.
 */
object C2paManifests {
    private const val STORE_UUID = "6332706100110010800000aa00389b71"

    /** The manifest store of [bytes], or null when there is none (or the file is not a supported container). */
    fun read(bytes: ByteArray): C2paStore? {
        val (container, jumbf, asset) = locate(bytes) ?: return null
        val root = runCatching { superboxes(jumbf, 0, jumbf.size) }.getOrNull()?.firstOrNull { it.label == "c2pa" || it.uuid == STORE_UUID } ?: return null
        val manifests = root.children.mapNotNull { m -> runCatching { manifest(m) }.getOrNull() }
        if (manifests.isEmpty()) return null
        return C2paStore(container, root, manifests, asset)
    }

    /** True when [bytes] starts like a sidecar manifest store (a JUMBF superbox). */
    fun isSidecar(bytes: ByteArray): Boolean = bytes.size > 16 && ascii(bytes, 4, 4) == "jumb"

    private fun locate(b: ByteArray): Triple<String, ByteArray, ByteArray?>? = when {
        b.size > 4 && b[0] == 0xFF.toByte() && b[1] == 0xD8.toByte() -> jpeg(b)?.let { Triple("JPEG APP11", it, b) }
        b.size > 8 && b[0] == 0x89.toByte() && ascii(b, 1, 3) == "PNG" -> png(b)?.let { Triple("PNG caBX", it, b) }
        b.size > 12 && ascii(b, 0, 4) == "RIFF" && ascii(b, 8, 4) == "WEBP" -> webp(b)?.let { Triple("WebP C2PA", it, b) }
        isSidecar(b) -> Triple("sidecar", b, null)
        else -> null
    }

    /** APP11 segments of JPEG XT boxes (CI "JP"): the first holds the box header, the others repeat it and are joined. */
    private fun jpeg(b: ByteArray): ByteArray? {
        val boxes = LinkedHashMap<Int, ArrayList<ByteArray>>()
        var i = 2
        while (i + 4 <= b.size && b[i] == 0xFF.toByte()) {
            val marker = b[i + 1].toInt() and 0xFF
            if (marker == 0xD8 || marker == 0x01 || marker in 0xD0..0xD7) { i += 2; continue }
            if (marker == 0xDA || marker == 0xD9) break
            val len = u16(b, i + 2)
            if (len < 2 || i + 2 + len > b.size) break
            if (marker == 0xEB && len > 16 && ascii(b, i + 4, 2) == "JP") {
                val instance = u16(b, i + 6)
                val body = b.copyOfRange(i + 12, i + 2 + len)
                val parts = boxes.getOrPut(instance) { ArrayList() }
                parts.add(if (parts.isEmpty()) body else body.copyOfRange(8, body.size))
            }
            i += 2 + len
        }
        for (parts in boxes.values) {
            val all = parts.fold(ByteArray(0)) { acc, p -> acc + p }
            if (all.size > 16 && ascii(all, 4, 4) == "jumb") return all
        }
        return null
    }

    private fun png(b: ByteArray): ByteArray? {
        var i = 8
        while (i + 12 <= b.size) {
            val len = u32(b, i).toInt()
            if (len < 0 || i + 12 + len > b.size) return null
            if (ascii(b, i + 4, 4) == "caBX") return b.copyOfRange(i + 8, i + 8 + len)
            i += 12 + len
        }
        return null
    }

    private fun webp(b: ByteArray): ByteArray? {
        var i = 12
        while (i + 8 <= b.size) {
            val len = (b[i + 4].toInt() and 0xFF) or ((b[i + 5].toInt() and 0xFF) shl 8) or ((b[i + 6].toInt() and 0xFF) shl 16) or ((b[i + 7].toInt() and 0xFF) shl 24)
            if (len < 0 || i + 8 + len > b.size) return null
            if (ascii(b, i, 4) == "C2PA") return b.copyOfRange(i + 8, i + 8 + len)
            i += 8 + len + (len and 1)
        }
        return null
    }

    // ---------------------------------------------------------------- JUMBF (ISO/IEC 19566-5)

    private fun superboxes(s: ByteArray, from: Int, to: Int): List<JumbfSuperbox> {
        val out = ArrayList<JumbfSuperbox>()
        var off = from
        while (off + 8 <= to) {
            var len = u32(s, off)
            var header = 8
            if (len == 1L) { len = u64(s, off + 8); header = 16 }
            if (len == 0L) len = (to - off).toLong()
            if (len < header || off + len > to) throw IllegalArgumentException("JUMBF box out of range")
            val end = off + len.toInt()
            if (ascii(s, off + 4, 4) == "jumb") out.add(superbox(s, off, header, end))
            off = end
        }
        return out
    }

    private fun superbox(s: ByteArray, start: Int, header: Int, end: Int): JumbfSuperbox {
        val boxes = ArrayList<Triple<String, Int, Int>>()
        var off = start + header
        while (off + 8 <= end) {
            var len = u32(s, off)
            var h = 8
            if (len == 1L) { len = u64(s, off + 8); h = 16 }
            if (len == 0L) len = (end - off).toLong()
            if (len < h || off + len > end) throw IllegalArgumentException("JUMBF box out of range")
            boxes.add(Triple(ascii(s, off + 4, 4), off, h))
            off += len.toInt()
        }
        val ends = boxes.map { it.second }.drop(1) + end
        val desc = boxes.firstOrNull()?.takeIf { it.first == "jumd" } ?: throw IllegalArgumentException("JUMBF superbox without a description box")
        val d = s.copyOfRange(desc.second + desc.third, ends[0])
        val uuid = d.copyOfRange(0, 16).joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
        val toggles = d[16].toInt()
        val label = if (toggles and 0x02 != 0) {
            val z = (17 until d.size).firstOrNull { d[it] == 0.toByte() } ?: d.size
            d.copyOfRange(17, z).decodeToString()
        } else null
        val contents = ArrayList<Pair<String, ByteArray>>()
        val children = ArrayList<JumbfSuperbox>()
        for ((k, box) in boxes.withIndex()) {
            if (k == 0) continue
            if (box.first == "jumb") children.add(superbox(s, box.second, box.third, ends[k]))
            else contents.add(box.first to s.copyOfRange(box.second + box.third, ends[k]))
        }
        return JumbfSuperbox(label, uuid, s, start, header, end, contents, children)
    }

    // ---------------------------------------------------------------- claims and signatures

    private fun manifest(m: JumbfSuperbox): C2paManifest? {
        val label = m.label ?: return null
        val claimBox = m.child("c2pa.claim.v2") ?: m.child("c2pa.claim") ?: return null
        val claimBytes = claimBox.content("cbor") ?: return null
        val item = Cbor.decode(claimBytes)
        val claim = toJson(item) as? JsonObject ?: return null
        val version = if (claimBox.label == "c2pa.claim.v2") 2 else 1
        val refs = listOf("assertions", "created_assertions", "gathered_assertions").flatMap { key ->
            (item.getOrNullAny(key) as? CborArray)?.items.orEmpty().mapNotNull(::hashedUri)
        }
        val cose = m.child("c2pa.signature")?.content("cbor")?.let { runCatching { cose(it) }.getOrNull() }
        return C2paManifest(label, m, version, claimBytes, claim, refs, claim.str("alg"), cose)
    }

    internal fun hashedUri(d: DataItem): C2paHashedUri? {
        val m = d as? CborMap ?: return null
        val url = (m.getOrNullAny("url") as? Tstr)?.value ?: return null
        val hash = (m.getOrNullAny("hash") as? Bstr)?.value ?: return null
        return C2paHashedUri(url, hash, (m.getOrNullAny("alg") as? Tstr)?.value)
    }

    /** A COSE_Sign1 (tag 18 or untagged) with its certificate chain, time stamps and OCSP responses. */
    fun cose(bytes: ByteArray): C2paCose {
        var item = Cbor.decode(bytes)
        if (item is Tagged) item = item.taggedItem
        val a = (item as CborArray).items
        val protectedBytes = (a[0] as Bstr).value
        val prot = if (protectedBytes.isEmpty()) null else Cbor.decode(protectedBytes) as? CborMap
        val unprot = a[1] as? CborMap
        fun header(key: Long, name: String? = null): DataItem? =
            prot?.items?.entries?.firstOrNull { (k, _) -> (k as? CborInt)?.asNumber == key || (name != null && (k as? Tstr)?.value == name) }?.value
                ?: unprot?.items?.entries?.firstOrNull { (k, _) -> (k as? CborInt)?.asNumber == key || (name != null && (k as? Tstr)?.value == name) }?.value
        val alg = (header(1) as? CborInt)?.asNumber?.toInt()
        val chain = when (val x = header(33, "x5chain")) {
            is Bstr -> listOf(x.value)
            is CborArray -> x.items.mapNotNull { (it as? Bstr)?.value }
            else -> emptyList()
        }
        val timestamps = listOf("sigTst2", "sigTst").flatMap { name ->
            val tst = unprot?.getOrNullAny(name) ?: prot?.getOrNullAny(name)
            (tst?.getOrNullAny("tstTokens") as? CborArray)?.items.orEmpty().mapNotNull { (it.getOrNullAny("val") as? Bstr)?.value?.let { v -> name to v } }
        }
        val ocsps = (unprot?.getOrNullAny("rVals")?.getOrNullAny("ocspVals") as? CborArray)?.items.orEmpty().mapNotNull { (it as? Bstr)?.value }
        return C2paCose(protectedBytes, alg, chain, timestamps, ocsps, (a[3] as Bstr).value, (a[2] as? Bstr)?.value)
    }

    /** CBOR of ["Signature1", protected, h'', payload]: the bytes a COSE_Sign1 signature covers (RFC 9052 4.4). */
    fun toBeSigned(protectedBytes: ByteArray, payload: ByteArray): ByteArray =
        byteArrayOf(0x84.toByte()) + tstr("Signature1") + bstr(protectedBytes) + bstr(ByteArray(0)) + bstr(payload)

    /**
     * CBOR of ["CounterSignature", protected, h'', payload]: what a C2PA claim signature time stamp covers. For sigTst
     * the payload is the claim; for sigTst2 the signature value is tried as well.
     */
    fun counterSigned(protectedBytes: ByteArray, payload: ByteArray): ByteArray =
        byteArrayOf(0x84.toByte()) + tstr("CounterSignature") + bstr(protectedBytes) + bstr(ByteArray(0)) + bstr(payload)

    private fun head(major: Int, n: Int): ByteArray = when {
        n < 24 -> byteArrayOf((major shl 5 or n).toByte())
        n < 0x100 -> byteArrayOf((major shl 5 or 24).toByte(), n.toByte())
        n < 0x10000 -> byteArrayOf((major shl 5 or 25).toByte(), (n shr 8).toByte(), n.toByte())
        else -> byteArrayOf((major shl 5 or 26).toByte(), (n shr 24).toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
    }

    private fun bstr(b: ByteArray) = head(2, b.size) + b
    private fun tstr(s: String) = s.encodeToByteArray().let { head(3, it.size) + it }

    // ---------------------------------------------------------------- checks that need no key

    /** JCA name of a C2PA hash algorithm (sha256 when none is given). */
    fun jcaHash(alg: String?): String = when (alg?.lowercase()?.replace("-", "")) {
        "sha384" -> "SHA-384"
        "sha512" -> "SHA-512"
        else -> "SHA-256"
    }

    /** The hashed URIs of [m]'s claim, each with whether the assertion box it names is there and matches. */
    fun assertionStatuses(store: C2paStore, m: C2paManifest): List<C2paStatus> = m.assertionRefs.map { r ->
        val box = store.resolve(r.url, m)
        val abs = absolute(m, r.url)
        when {
            box == null -> C2paStatus("assertion.missing", abs, false, "找不到宣告 ${r.url}")
            DocCrypto.digest(jcaHash(r.algorithm ?: m.algorithm), box.hashedBytes).contentEquals(r.hash) -> C2paStatus("assertion.hashedURI.match", abs, true)
            else -> C2paStatus("assertion.hashedURI.mismatch", abs, false, "宣告 ${r.url} 的雜湊與聲明不符")
        }
    }

    /**
     * The hard binding of [m] over the asset: the data hash (c2pa.hash.data) recomputed with its exclusions. Null when
     * the manifest has no data hash; other bindings (boxes, BMFF, collections) are reported as not checked.
     */
    fun bindingStatus(store: C2paStore, m: C2paManifest): C2paStatus? {
        val signed = signedAssertions(m)
        val hashBox = signed.firstOrNull { it.label?.startsWith("c2pa.hash.data") == true }
        if (hashBox == null) {
            val other = signed.firstOrNull { l -> listOf("c2pa.hash.boxes", "c2pa.hash.bmff", "c2pa.hash.collection").any { l.label?.startsWith(it) == true } }
            if (other != null) return C2paStatus("assertion.hardBinding.notChecked", absolute(m, "self#jumbf=c2pa.assertions/${other.label}"), false, "這種綁定（${other.label}）錢包尚未檢查")
            val unsigned = m.box.child("c2pa.assertions")?.children.orEmpty().firstOrNull { it.label?.startsWith("c2pa.hash.") == true } ?: return null
            return C2paStatus("claim.hardBindings.missing", absolute(m, "self#jumbf=c2pa.assertions/${unsigned.label}"), false, "硬綁定宣告（${unsigned.label}）沒有被簽署的聲明引用")
        }
        val url = absolute(m, "self#jumbf=c2pa.assertions/${hashBox.label}")
        val asset = store.asset ?: return C2paStatus("assertion.dataHash.notChecked", url, false, "獨立的 manifest 檔沒有附上原始檔案，無法檢查")
        val d = Cbor.decode(hashBox.content("cbor") ?: return C2paStatus("assertion.dataHash.malformed", url, false))
        val expected = (d.getOrNullAny("hash") as? Bstr)?.value ?: return C2paStatus("assertion.dataHash.malformed", url, false)
        val ranges = (d.getOrNullAny("exclusions") as? CborArray)?.items.orEmpty().mapNotNull { e ->
            val start = (e.getOrNullAny("start") as? CborInt)?.asNumber ?: return@mapNotNull null
            val length = (e.getOrNullAny("length") as? CborInt)?.asNumber ?: return@mapNotNull null
            start to length
        }.sortedBy { it.first }
        if (ranges.any { it.first < 0 || it.second < 0 || it.first + it.second > asset.size }) {
            return C2paStatus("assertion.dataHash.mismatch", url, false, "排除範圍超出檔案大小")
        }
        val kept = ArrayList<ByteArray>()
        var pos = 0L
        for ((start, length) in ranges) {
            if (start > pos) kept.add(asset.copyOfRange(pos.toInt(), start.toInt()))
            pos = maxOf(pos, start + length)
        }
        if (pos < asset.size) kept.add(asset.copyOfRange(pos.toInt(), asset.size))
        val total = ByteArray(kept.sumOf { it.size })
        var o = 0
        for (k in kept) { k.copyInto(total, o); o += k.size }
        val alg = (d.getOrNullAny("alg") as? Tstr)?.value ?: m.algorithm
        return if (DocCrypto.digest(jcaHash(alg), total).contentEquals(expected)) C2paStatus("assertion.dataHash.match", url, true)
        else C2paStatus("assertion.dataHash.mismatch", url, false, "檔案內容與資料雜湊不符，簽署後被修改過")
    }

    /**
     * The assertion boxes of [m] that its signed claim references with a matching hash, in store order. Boxes the claim
     * does not reference (or whose hash does not match) are never read for bindings or display.
     */
    fun signedAssertions(m: C2paManifest): List<JumbfSuperbox> {
        val boxes = m.box.child("c2pa.assertions")?.children.orEmpty()
        val prefix = "/c2pa/${m.label}/"
        return boxes.filter { b ->
            m.assertionRefs.any { r ->
                val raw = r.url.substringAfter("jumbf=", r.url)
                val path = if (raw.startsWith("/")) raw.takeIf { it.startsWith(prefix) }?.removePrefix(prefix) else raw
                path == "c2pa.assertions/${b.label}" && DocCrypto.digest(jcaHash(r.algorithm ?: m.algorithm), b.hashedBytes).contentEquals(r.hash)
            }
        }
    }

    fun absolute(m: C2paManifest, url: String): String {
        val path = url.substringAfter("jumbf=", url)
        return if (path.startsWith("/")) "self#jumbf=$path" else "self#jumbf=/c2pa/${m.label}/$path"
    }

    // ---------------------------------------------------------------- what the manifest says

    /** The assertion labelled [label] (or a numbered instance of it) decoded to JSON, from its CBOR or JSON box. */
    fun assertion(m: C2paManifest, vararg labels: String): List<Pair<String, JsonElement>> {
        return signedAssertions(m).filter { b -> labels.any { l -> b.label == l || b.label?.startsWith("${l}__") == true } }.mapNotNull { b ->
            val v = b.content("cbor")?.let { runCatching { toJson(Cbor.decode(it)) }.getOrNull() }
                ?: b.content("json")?.let { runCatching { DiwJson.parseToJsonElement(it.decodeToString()) }.getOrNull() }
            v?.let { b.label!! to it }
        }
    }

    /** Assertion labels of [m] in store order. */
    fun labels(m: C2paManifest): List<String> = signedAssertions(m).mapNotNull { it.label }

    /** The claim generator: the name and version of the first generator info, or the v1 string. */
    fun generator(m: C2paManifest): String? {
        val info = m.claim["claim_generator_info"]
        val first = (info as? JsonArray)?.firstOrNull() as? JsonObject ?: info as? JsonObject
        return first?.let { listOfNotNull(it.str("name"), it.str("version")).joinToString(" ").ifBlank { null } } ?: m.claim.str("claim_generator")
    }

    fun actions(m: C2paManifest): List<C2paAction> = assertion(m, "c2pa.actions.v2", "c2pa.actions").flatMap { (_, v) ->
        ((v as? JsonObject)?.get("actions") as? JsonArray).orEmpty().mapNotNull { a ->
            val o = a as? JsonObject ?: return@mapNotNull null
            val agent = o["softwareAgent"]
            C2paAction(
                action = o.str("action") ?: return@mapNotNull null,
                time = o.str("when"),
                softwareAgent = (agent as? JsonObject)?.let { listOfNotNull(it.str("name"), it.str("version")).joinToString(" ") } ?: (agent as? JsonPrimitive)?.contentOrNull,
                digitalSourceType = o.str("digitalSourceType")?.substringAfterLast('/'),
                description = (o["parameters"] as? JsonObject)?.str("description") ?: o.str("reason"),
            )
        }
    }

    fun ingredients(store: C2paStore, m: C2paManifest): List<C2paIngredient> =
        assertion(m, "c2pa.ingredient.v3", "c2pa.ingredient.v2", "c2pa.ingredient").mapNotNull { (_, v) ->
            val o = v as? JsonObject ?: return@mapNotNull null
            val ref = (o["activeManifest"] ?: o["c2pa_manifest"]) as? JsonObject
            val manifest = ref?.str("url")?.substringAfter("jumbf=")?.trim('/')?.split('/')?.getOrNull(1)
            C2paIngredient(o.str("dc:title") ?: o.str("title"), o.str("dc:format") ?: o.str("format"), o.str("relationship"), manifest?.takeIf { store.manifest(it) != null } ?: manifest)
        }

    fun authors(m: C2paManifest): List<String> = assertion(m, "stds.schema-org.CreativeWork").flatMap { (_, v) ->
        when (val a = (v as? JsonObject)?.get("author")) {
            is JsonArray -> a.mapNotNull { (it as? JsonObject)?.str("name") ?: (it as? JsonPrimitive)?.contentOrNull }
            is JsonObject -> listOfNotNull(a.str("name"))
            is JsonPrimitive -> listOfNotNull(a.contentOrNull)
            else -> emptyList()
        }
    }

    fun training(m: C2paManifest): List<String> = assertion(m, "c2pa.training-mining", "cawg.training-mining").flatMap { (_, v) ->
        ((v as? JsonObject)?.get("entries") as? JsonObject)?.entries.orEmpty().map { (k, e) ->
            val use = (e as? JsonObject)?.str("use")
            val text = when (use) { "allowed" -> "允許"; "notAllowed" -> "不允許"; "constrained" -> "有條件允許"; else -> use ?: "未說明" }
            "${k.substringAfter('.')}：$text"
        }
    }

    /** The raw CAWG identity assertions of [m]: signer payload (CBOR), signature bytes and the sig_type. */
    fun identityAssertions(m: C2paManifest): List<Triple<DataItem, ByteArray, String>> {
        return signedAssertions(m).filter { it.label == "cawg.identity" || it.label?.startsWith("cawg.identity__") == true }.mapNotNull { b ->
            val d = runCatching { Cbor.decode(b.content("cbor") ?: return@mapNotNull null) }.getOrNull() ?: return@mapNotNull null
            val payload = d.getOrNullAny("signer_payload") ?: return@mapNotNull null
            val sig = (d.getOrNullAny("signature") as? Bstr)?.value ?: return@mapNotNull null
            Triple(payload, sig, (payload.getOrNullAny("sig_type") as? Tstr)?.value ?: "")
        }
    }

    // ---------------------------------------------------------------- helpers

    /** CBOR as JSON for display: byte strings as base64, tags dropped, non-string map keys as their text. */
    fun toJson(d: DataItem): JsonElement = when (d) {
        is CborMap -> JsonObject(d.items.entries.associate { (k, v) -> keyText(k) to toJson(v) })
        is CborArray -> JsonArray(d.items.map(::toJson))
        is Tstr -> JsonPrimitive(d.value)
        is Bstr -> JsonPrimitive(Base64.Default.encode(d.value))
        is CborInt -> JsonPrimitive(d.asNumber)
        is CborFloat -> JsonPrimitive(d.value)
        is CborDouble -> JsonPrimitive(d.value)
        is Tagged -> toJson(d.taggedItem)
        is Simple -> when (d) { Simple.TRUE -> JsonPrimitive(true); Simple.FALSE -> JsonPrimitive(false); else -> JsonNull }
        else -> JsonNull
    }

    private fun keyText(k: DataItem): String = when (k) {
        is Tstr -> k.value
        is CborInt -> k.asNumber.toString()
        else -> k.toString()
    }

    private fun ascii(b: ByteArray, off: Int, n: Int): String =
        if (off + n > b.size) "" else CharArray(n) { (b[off + it].toInt() and 0xFF).toChar() }.concatToString()

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun u32(b: ByteArray, o: Int): Long = (0 until 4).fold(0L) { acc, i -> (acc shl 8) or (b[o + i].toLong() and 0xFF) }
    private fun u64(b: ByteArray, o: Int): Long = (0 until 8).fold(0L) { acc, i -> (acc shl 8) or (b[o + i].toLong() and 0xFF) }
}

/** The value under the text key [key] of a CBOR map, or null for anything else. */
internal fun DataItem.getOrNullAny(key: String): DataItem? =
    (this as? CborMap)?.items?.entries?.firstOrNull { (k, _) -> (k as? Tstr)?.value == key }?.value

internal fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
