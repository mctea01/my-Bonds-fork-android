package diw.wallet.core.w3c.sd

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.w3c.ld.BlankNode
import diw.wallet.core.w3c.ld.Iri
import diw.wallet.core.w3c.ld.JsonLd
import diw.wallet.core.w3c.ld.Quad
import diw.wallet.core.w3c.ld.Rdfc10
import diw.wallet.core.w3c.ld.RdfTerm
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.util.toBase64Url

/** Maps the canonical (c14n) blank node ids of a dataset, keyed by input id, to the labels to use instead. */
fun interface LabelMapFactory {
    fun create(canonicalIdMap: Map<String, String>): Map<String, String>
}

/** N-Quads grouped by JSON pointer selections (DI 1.1 canonicalizeAndGroup). Indexes are positions in [nquads]. */
class SdGroup(val matching: Map<Int, String>, val nonMatching: Map<Int, String>, val deskolemized: List<Quad>)

class SdGroups(
    val groups: Map<String, SdGroup>,
    val skolemizedCompact: JsonObject,
    val labelMap: Map<String, String>,
    val nquads: List<String>,
)

/** The selective disclosure functions of W3C Data Integrity 1.1, section 4.7. Blank node ids carry no "_:" prefix. */
object SdPrimitives {
    private const val URN = "urn:custom-scheme:"

    /** 4.7.1: canonicalizes [quads] and relabels the canonical blank nodes with [factory]. */
    fun labelReplacementCanonicalize(quads: List<Quad>, factory: LabelMapFactory): Pair<Map<String, String>, List<String>> {
        val canonical = Rdfc10.canonicalize(quads)
        val labelMap = factory.create(canonical.issued)
        val byCanonical = canonical.issued.entries.associate { (input, c14n) -> c14n to (labelMap[input] ?: error("label map misses $input")) }
        val nquads = canonical.quads.map { q -> q.relabel { byCanonical.getValue(it) }.toNQuad() }.sortedWith { a, b -> Rdfc10.compareCodePoints(a, b) }
        return labelMap to nquads
    }

    /** 4.7.3: replaces canonical ids using [labelMap] (c14n id to new label). */
    fun labelMapFunction(labelMap: Map<String, String>) = LabelMapFactory { canonicalIdMap ->
        canonicalIdMap.mapValues { (_, c14n) -> labelMap[c14n] ?: throw ProtocolException("invalid_proof", "Label map has no entry for $c14n") }
    }

    /** 4.7.4: HMAC of each canonical id, sorted, then labelled b0, b1, ... by position (bbs-2023). */
    fun shuffledIdLabelMapFunction(hmacKey: ByteArray) = LabelMapFactory { canonicalIdMap ->
        val digests = canonicalIdMap.mapValues { (_, c14n) -> "u" + hmacSha256(hmacKey, c14n.encodeToByteArray()).toBase64Url() }
        val sorted = digests.values.sorted()
        digests.mapValues { (_, d) -> "b" + sorted.indexOf(d) }
    }

    /** 4.7.5: HMAC of each canonical id as the label (ecdsa-sd-2023). */
    fun hmacIdLabelMapFunction(hmacKey: ByteArray) = LabelMapFactory { canonicalIdMap ->
        canonicalIdMap.mapValues { (_, c14n) -> "u" + hmacSha256(hmacKey, c14n.encodeToByteArray()).toBase64Url() }
    }

    /** 4.7.10: gives every node object of an expanded document a custom-scheme URN id. */
    fun skolemizeExpanded(expanded: JsonArray, random: String, counter: IntArray = intArrayOf(0)): JsonArray = JsonArray(expanded.map { element ->
        if (element !is JsonObject || "@value" in element) return@map element
        val node = LinkedHashMap<String, JsonElement>()
        for ((property, value) in element) {
            node[property] = if (value is JsonArray) skolemizeExpanded(value, random, counter) else skolemizeExpanded(JsonArray(listOf(value)), random, counter)[0]
        }
        // A list object cannot take an id; its members are still skolemized above.
        if ("@list" !in element) {
            val id = (node["@id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            when {
                id == null -> node["@id"] = JsonPrimitive(URN + "_" + random + "_" + counter[0]++)
                id.startsWith("_:") -> node["@id"] = JsonPrimitive(URN + id.removePrefix("_:"))
            }
        }
        JsonObject(node)
    })

    /** 4.7.11: the skolemized expanded and compact forms of [document]. */
    suspend fun skolemizeCompact(document: JsonObject, jsonLd: JsonLd): Pair<JsonArray, JsonObject> {
        val context = document["@context"] ?: throw ProtocolException("invalid_proof", "Document has no @context")
        val expanded = jsonLd.expand(document)
        val random = PlatformCrypto.randomBytes(16).toBase64Url()
        val skolemized = skolemizeExpanded(expanded, random)
        return skolemized to jsonLd.compact(skolemized, context)
    }

    /** 4.7.12: the quads of a skolemized document with the custom-scheme URNs turned back into blank nodes. */
    suspend fun toDeskolemizedQuads(skolemized: JsonElement, jsonLd: JsonLd): List<Quad> = jsonLd.toRdf(skolemized).map(::deskolemize)

    fun deskolemize(q: Quad): Quad {
        fun t(term: RdfTerm?): RdfTerm? = if (term is Iri && term.value.startsWith(URN)) BlankNode(term.value.removePrefix(URN)) else term
        return Quad(t(q.subject)!!, q.predicate, t(q.obj)!!, t(q.graph))
    }

    /** 4.7.13. */
    fun jsonPointerToPaths(pointer: String): List<Any> {
        if (!pointer.startsWith("/")) throw ProtocolException("invalid_pointer", "JSON pointer must start with '/'")
        return pointer.split('/').drop(1).map { p ->
            if ('~' !in p) p.toIntOrNull()?.takeIf { p == it.toString() } ?: p else p.replace("~1", "/").replace("~0", "~")
        }
    }

    private object Undefined

    /** 4.7.16: the part of a compact document that [pointers] select (with the ids and types on their paths). */
    fun selectJsonLd(pointers: List<String>, document: JsonObject): JsonObject? {
        if (pointers.isEmpty()) return null
        val arrays = mutableListOf<MutableList<Any?>>()
        val selection = initialSelection(document)
        document["@context"]?.let { selection["@context"] = it }
        for (pointer in pointers) selectPaths(jsonPointerToPaths(pointer), document, selection, arrays)
        for (a in arrays) a.removeAll { it === Undefined }
        return toJson(selection) as JsonObject
    }

    private fun initialSelection(source: JsonElement): MutableMap<String, Any?> {
        val selection = LinkedHashMap<String, Any?>()
        if (source is JsonObject) {
            val id = source["id"]
            if (id is JsonPrimitive && id.isString && !id.content.startsWith("_:")) selection["id"] = id
            source["type"]?.let { selection["type"] = it }
        }
        return selection
    }

    private fun selectPaths(paths: List<Any>, document: JsonObject, selection: MutableMap<String, Any?>, arrays: MutableList<MutableList<Any?>>) {
        if (paths.isEmpty()) throw ProtocolException("invalid_pointer", "JSON pointer selects the whole document")
        var value: JsonElement = document
        var selectedParent: Any = selection
        var selectedValue: Any = selection
        for (path in paths) {
            selectedParent = selectedValue
            val parentValue = value
            value = child(parentValue, path) ?: throw ProtocolException("invalid_pointer", "JSON pointer does not match the document")
            val existing = getChild(selectedParent, path)
            selectedValue = if (existing == null || existing === Undefined) {
                val created: Any = if (value is JsonArray) mutableListOf<Any?>().also { arrays += it } else initialSelection(value)
                setChild(selectedParent, path, created)
                created
            } else existing
        }
        val finalValue: Any = when (value) {
            is JsonPrimitive, JsonNull -> value
            is JsonArray -> value
            is JsonObject -> LinkedHashMap((selectedValue as? MutableMap<*, *>)?.entries?.associate { it.key as String to it.value } ?: emptyMap()).apply { putAll(value) }
        }
        setChild(selectedParent, paths.last(), finalValue)
    }

    private fun child(parent: JsonElement, path: Any): JsonElement? = when (parent) {
        is JsonObject -> parent[path.toString()]
        is JsonArray -> (path as? Int)?.let { parent.getOrNull(it) }
        else -> null
    }

    @Suppress("UNCHECKED_CAST")
    private fun getChild(parent: Any, path: Any): Any? = when (parent) {
        is MutableMap<*, *> -> (parent as MutableMap<String, Any?>)[path.toString()]
        is MutableList<*> -> (path as? Int)?.let { (parent as MutableList<Any?>).getOrNull(it) }
        else -> null
    }

    @Suppress("UNCHECKED_CAST")
    private fun setChild(parent: Any, path: Any, value: Any) {
        when (parent) {
            is MutableMap<*, *> -> (parent as MutableMap<String, Any?>)[path.toString()] = value
            is MutableList<*> -> {
                val list = parent as MutableList<Any?>
                val index = path as? Int ?: throw ProtocolException("invalid_pointer", "JSON pointer indexes an array with a name")
                if (index > 10_000) throw ProtocolException("invalid_pointer", "JSON pointer index too large")
                while (list.size <= index) list.add(Undefined)
                list[index] = value
            }
            else -> throw ProtocolException("invalid_pointer", "JSON pointer goes through a value")
        }
    }

    private fun toJson(value: Any?): JsonElement = when (value) {
        is JsonElement -> value
        is Map<*, *> -> JsonObject(value.entries.associate { it.key as String to toJson(it.value) })
        is List<*> -> JsonArray(value.map(::toJson))
        null -> JsonNull
        else -> error("unexpected selection value")
    }

    /** 4.7.19. */
    suspend fun canonicalizeAndGroup(
        document: JsonObject,
        factory: LabelMapFactory,
        groupDefinitions: Map<String, List<String>>,
        jsonLd: JsonLd,
    ): SdGroups {
        val (expanded, compact) = skolemizeCompact(document, jsonLd)
        val deskolemized = toDeskolemizedQuads(expanded, jsonLd)
        val (labelMap, nquads) = labelReplacementCanonicalize(deskolemized, factory)
        val groups = groupDefinitions.mapValues { (_, pointers) ->
            val selection = selectJsonLd(pointers, compact)
            val selected = selection?.let { toDeskolemizedQuads(it, jsonLd) }.orEmpty()
            val selectedNQuads = selected.map { q ->
                q.relabel { labelMap[it] ?: throw ProtocolException("invalid_proof", "Selection has an unknown blank node") }.toNQuad()
            }.toSet()
            val matching = LinkedHashMap<Int, String>()
            val nonMatching = LinkedHashMap<Int, String>()
            nquads.forEachIndexed { i, nq -> if (nq in selectedNQuads) matching[i] = nq else nonMatching[i] = nq }
            SdGroup(matching, nonMatching, selected)
        }
        return SdGroups(groups, compact, labelMap, nquads)
    }

    /** 4.7.20 with SHA-256. */
    fun hashMandatory(mandatory: Collection<String>): ByteArray = PlatformCrypto.sha256(mandatory.joinToString("").encodeToByteArray())

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val block = 64
        val k = if (key.size > block) PlatformCrypto.sha256(key) else key
        val padded = k.copyOf(block)
        val inner = ByteArray(block) { (padded[it].toInt() xor 0x36).toByte() }
        val outer = ByteArray(block) { (padded[it].toInt() xor 0x5c).toByte() }
        return PlatformCrypto.sha256(outer + PlatformCrypto.sha256(inner + data))
    }
}
