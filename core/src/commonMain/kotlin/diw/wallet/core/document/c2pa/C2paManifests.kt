package diw.wallet.core.document.c2pa

import diw.wallet.core.i18n.ct
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

/** One entry of the verifiedIdentities of a CAWG identity claims aggregation credential. */
@Serializable
data class C2paVerifiedIdentity(
    /** cawg.social_media, cawg.document_verification, cawg.web_site, cawg.affiliation, cawg.crypto_wallet... */
    val type: String,
    val name: String? = null,
    val username: String? = null,
    val address: String? = null,
    val uri: String? = null,
    val method: String? = null,
    val verifiedAt: String? = null,
    val providerId: String? = null,
    val providerName: String? = null,
)

/**
 * A CAWG identity assertion (1.3): who the named actor is and how that is bound ([sigType]), with the CAWG status
 * codes of its validation.
 */
@Serializable
data class C2paIdentity(
    val sigType: String,
    val names: List<String>,
    val issuer: String? = null,
    /** The binding and the signature: PASS when every failure code is absent. */
    val signature: Check = Check.NOT_CHECKED,
    val detail: List<String> = emptyList(),
    /** The assertion label (cawg.identity, cawg.identity__1...). */
    val label: String? = null,
    /** Roles of the named actor (signer_payload.role). */
    val roles: List<String> = emptyList(),
    /** Labels of the assertions the signer payload references. */
    val referenced: List<String> = emptyList(),
    /** Status codes in the CAWG specification's terms; url is the identity assertion's label. */
    val statuses: List<C2paStatus> = emptyList(),
    /** cawg.identity.trusted: valid, and the named actor is trusted under the CAWG trust model. */
    val trusted: Boolean = false,
    /** The X.509 signature (cawg.x509.cose) checked as a document signature: chain, trust tier, validity, time stamp. */
    val x509: diw.wallet.core.document.SignatureInfo? = null,
    /** The identities an identity claims aggregator verified (cawg.identity_claims_aggregation). */
    val verifiedIdentities: List<C2paVerifiedIdentity> = emptyList(),
    /** Trust of the aggregator's DID ([diw.wallet.core.trust.DidTrust]). */
    val issuerTrust: diw.wallet.core.document.TrustSummary? = null,
    val validFrom: String? = null,
    val validUntil: String? = null,
)

/** A validation result in the C2PA specification's own codes (claimSignature.validated, assertion.dataHash.match...). */
@Serializable
data class C2paStatus(
    val code: String,
    val url: String?,
    val success: Boolean,
    val explanation: String? = null,
    /** An informational code (neither success nor failure), such as cawg.x509.ocsp.skipped. */
    val informational: Boolean = false,
)

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
    /** Where the store was found: JPEG APP11, PNG caBX, BMFF uuid, PDF C2PA_Manifest... or a sidecar (.c2pa) file. */
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

    /** The whole superbox as stored, header included: a manifest copied unchanged into a new store keeps its hashes. */
    val rawBytes: ByteArray get() = store.copyOfRange(start, end)

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

/**
 * A manifest store found in a file. [asset] is the whole file the hard binding is computed over (null for a sidecar
 * read alone), [format] its container and [region] where the store is in it ([C2paLocated.region]).
 */
class C2paStore(
    val container: String,
    val root: JumbfSuperbox,
    val manifests: List<C2paManifest>,
    val asset: ByteArray?,
    val format: C2paFormat? = null,
    val region: C2paRange? = null,
) {
    /** The active manifest: the last one in the store (C2PA 2.x, 11.1). */
    val active: C2paManifest? get() = manifests.lastOrNull()

    fun manifest(label: String): C2paManifest? = manifests.firstOrNull { it.label == label }

    /**
     * The superbox a JUMBF URI names: absolute (self#jumbf=/c2pa/<manifest>/...) or relative to [base]
     * (self#jumbf=c2pa.assertions/...).
     */
    fun resolve(url: String, base: C2paManifest): JumbfSuperbox? {
        val path = C2paManifests.jumbfPath(url)
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
 * Reads C2PA manifest stores (C2PA 1.x and 2.x) in pure Kotlin: finds the JUMBF store in every container of
 * [C2paContainers] or a sidecar file, decodes the claims (v1 and v2) and assertions, and checks what needs no key:
 * the hashed URIs of the assertions and the hard binding over the file ([C2paBindings]). The claim signatures are
 * checked by the platform inspector, which also judges the signer certificate with the trust registry.
 */
object C2paManifests {
    private const val STORE_UUID = C2paContainers.STORE_UUID

    /** The manifest store of [bytes], or null when there is none (or the file is not a supported container). */
    fun read(bytes: ByteArray): C2paStore? {
        val located = C2paContainers.locate(bytes) ?: return null
        val jumbf = located.jumbf
        val root = runCatching { superboxes(jumbf, 0, jumbf.size) }.getOrNull()?.firstOrNull { it.label == "c2pa" || it.uuid == STORE_UUID } ?: return null
        val manifests = root.children.mapNotNull { m -> runCatching { manifest(m) }.getOrNull() }
        if (manifests.isEmpty()) return null
        val sidecar = located.format == C2paFormat.SIDECAR
        return C2paStore(located.format.title, root, manifests, if (sidecar) null else bytes, if (sidecar) null else located.format, located.region)
    }

    /** True when [bytes] starts like a sidecar manifest store (a JUMBF superbox). */
    fun isSidecar(bytes: ByteArray): Boolean = C2paContainers.isSidecar(bytes)

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
            box == null -> C2paStatus("assertion.missing", abs, false, ct("core_c2pa_assertion_missing", r.url))
            DocCrypto.digest(jcaHash(r.algorithm ?: m.algorithm), box.hashedBytes).contentEquals(r.hash) -> C2paStatus("assertion.hashedURI.match", abs, true)
            else -> C2paStatus("assertion.hashedURI.mismatch", abs, false, ct("core_c2pa_assertion_hash", r.url))
        }
    }

    /** The result of the hard binding of [m] over the asset ([C2paBindings]), or null when the manifest has none. */
    fun bindingStatus(store: C2paStore, m: C2paManifest): C2paStatus? = C2paBindings.check(store, m).firstOrNull()

    /** The hard binding's result first, then its informational statuses (additional exclusions, parts not checked). */
    fun bindingStatuses(store: C2paStore, m: C2paManifest): List<C2paStatus> = C2paBindings.check(store, m)

    /**
     * The assertion boxes of [m] that its signed claim references with a matching hash, in store order. Boxes the claim
     * does not reference (or whose hash does not match) are never read for bindings or display.
     */
    fun signedAssertions(m: C2paManifest): List<JumbfSuperbox> {
        val boxes = m.box.child("c2pa.assertions")?.children.orEmpty()
        val prefix = "/c2pa/${m.label}/"
        return boxes.filter { b ->
            m.assertionRefs.any { r ->
                val raw = jumbfPath(r.url)
                val path = if (raw.startsWith("/")) raw.takeIf { it.startsWith(prefix) }?.removePrefix(prefix) else raw
                path == "c2pa.assertions/${b.label}" && DocCrypto.digest(jcaHash(r.algorithm ?: m.algorithm), b.hashedBytes).contentEquals(r.hash)
            }
        }
    }

    /**
     * The path of a JUMBF URI. A path that starts with the store label without the leading slash
     * (self#jumbf=c2pa/<manifest>/...) is absolute, as c2pa-rs normalizes it.
     */
    fun jumbfPath(url: String): String {
        val path = url.substringAfter("jumbf=", url)
        return if (path.startsWith("c2pa/")) "/$path" else path
    }

    fun absolute(m: C2paManifest, url: String): String {
        val path = jumbfPath(url)
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
            val text = when (use) { "allowed" -> ct("core_c2pa_allowed"); "notAllowed" -> ct("core_c2pa_not_allowed"); "constrained" -> ct("core_c2pa_constrained"); else -> use ?: ct("core_c2pa_unstated") }
            ct("core_label_value", k.substringAfter('.'), text)
        }
    }

    /** The raw CAWG identity assertions of [m]: signer payload (CBOR), signature bytes and the sig_type. */
    fun identityAssertions(m: C2paManifest): List<Triple<DataItem, ByteArray, String>> =
        identityBoxes(m).mapNotNull { b ->
            val d = runCatching { Cbor.decode(b.content("cbor") ?: return@mapNotNull null) }.getOrNull() ?: return@mapNotNull null
            val payload = d.getOrNullAny("signer_payload") ?: return@mapNotNull null
            val sig = (d.getOrNullAny("signature") as? Bstr)?.value ?: return@mapNotNull null
            Triple(payload, sig, (payload.getOrNullAny("sig_type") as? Tstr)?.value ?: "")
        }

    /** The CAWG identity assertion boxes of [m] that its signed claim references (cawg.identity and its instances). */
    fun identityBoxes(m: C2paManifest): List<JumbfSuperbox> =
        signedAssertions(m).filter { it.label == "cawg.identity" || it.label?.startsWith("cawg.identity__") == true }

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

    private fun u32(b: ByteArray, o: Int): Long = (0 until 4).fold(0L) { acc, i -> (acc shl 8) or (b[o + i].toLong() and 0xFF) }
    private fun u64(b: ByteArray, o: Int): Long = (0 until 8).fold(0L) { acc, i -> (acc shl 8) or (b[o + i].toLong() and 0xFF) }
}

/** The value under the text key [key] of a CBOR map, or null for anything else. */
internal fun DataItem.getOrNullAny(key: String): DataItem? =
    (this as? CborMap)?.items?.entries?.firstOrNull { (k, _) -> (k as? Tstr)?.value == key }?.value

internal fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }
