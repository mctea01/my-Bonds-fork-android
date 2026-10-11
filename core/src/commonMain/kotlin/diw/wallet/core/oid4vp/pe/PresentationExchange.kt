package diw.wallet.core.oid4vp.pe

import diw.wallet.core.oid4vp.ext.WalletCredential
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.bool
import diw.wallet.core.util.int
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull

data class PeField(
    val paths: List<JsonPath>,
    val filter: JsonObject?,
    val optional: Boolean,
    val intentToRetain: Boolean,
    val id: String?,
    val name: String?,
    val purpose: String?,
)

data class InputDescriptor(
    val id: String,
    val name: String?,
    val purpose: String?,
    /** Formats this descriptor accepts; null means any format the definition accepts. */
    val formats: Set<String>?,
    val groups: List<String>,
    val fields: List<PeField>,
    val limitDisclosure: String?,
    val raw: JsonObject,
)

data class SubmissionRequirement(
    val name: String?,
    val rule: String,
    val count: Int?,
    val min: Int?,
    val max: Int?,
    val from: String?,
    val fromNested: List<SubmissionRequirement>,
)

/** DIF Presentation Exchange 2.x presentation_definition. */
data class PresentationDefinition(
    val id: String,
    val name: String?,
    val purpose: String?,
    val descriptors: List<InputDescriptor>,
    val requirements: List<SubmissionRequirement>,
    val formats: Set<String>?,
    val raw: JsonObject,
) {
    companion object {
        fun parse(json: JsonObject): PresentationDefinition {
            val id = json.str("id") ?: throw ProtocolException("invalid_request", "presentation_definition without id")
            val descriptors = json.arr("input_descriptors")?.filterIsInstance<JsonObject>()?.map { d ->
                val constraints = d.obj("constraints")
                InputDescriptor(
                    id = d.str("id") ?: throw ProtocolException("invalid_request", "input_descriptor without id"),
                    name = d.str("name"),
                    purpose = d.str("purpose"),
                    formats = d.obj("format")?.keys,
                    groups = d.strList("group"),
                    fields = constraints?.arr("fields")?.filterIsInstance<JsonObject>()?.map { f ->
                        PeField(
                            paths = f.strList("path").map { JsonPath.parse(it) },
                            filter = f.obj("filter"),
                            optional = f.bool("optional") ?: false,
                            intentToRetain = f.bool("intent_to_retain") ?: false,
                            id = f.str("id"),
                            name = f.str("name"),
                            purpose = f.str("purpose"),
                        )
                    }.orEmpty(),
                    limitDisclosure = constraints?.str("limit_disclosure"),
                    raw = d,
                )
            } ?: throw ProtocolException("invalid_request", "presentation_definition without input_descriptors")
            return PresentationDefinition(id, json.str("name"), json.str("purpose"), descriptors, parseRequirements(json.arr("submission_requirements")), json.obj("format")?.keys, json)
        }

        private fun parseRequirements(arr: JsonArray?): List<SubmissionRequirement> = arr.orEmpty().filterIsInstance<JsonObject>().map {
            SubmissionRequirement(it.str("name"), it.str("rule") ?: "all", it.int("count"), it.int("min"), it.int("max"), it.str("from"), parseRequirements(it.arr("from_nested")))
        }
    }
}

/** A field matched in a credential: the path that matched, as member names from the credential JSON root when possible. */
data class FieldMatch(val field: PeField, val path: JsonPath, val value: JsonElement, val memberPath: List<String>?)

/** A credential satisfying an input descriptor. */
data class DescriptorMatch(val descriptor: InputDescriptor, val credential: WalletCredential, val fields: List<FieldMatch>)

/** Presentation Exchange 2.x evaluation against the wallet's credentials. */
object PresentationExchange {
    /** Candidates per input descriptor id, in wallet order. */
    fun match(definition: PresentationDefinition, credentials: List<WalletCredential>): Map<String, List<DescriptorMatch>> =
        definition.descriptors.associate { d -> d.id to credentials.mapNotNull { c -> matchOne(definition, d, c) } }

    fun matchOne(definition: PresentationDefinition, d: InputDescriptor, c: WalletCredential): DescriptorMatch? {
        val accepted = d.formats ?: definition.formats
        if (accepted != null && accepted.none { it in c.formats }) return null
        val matched = mutableListOf<FieldMatch>()
        for (f in d.fields) {
            val m = matchField(f, c)
            if (m == null) {
                if (!f.optional) return null
            } else matched += m
        }
        return DescriptorMatch(d, c, matched)
    }

    private fun matchField(f: PeField, c: WalletCredential): FieldMatch? {
        val roots = buildList {
            add(c.json to emptyList<String>())
            if (c.w3c != null && c.w3c !== c.json) add(c.w3c to (if (c.json["vc"] === c.w3c || c.json["vc"] == c.w3c) listOf("vc") else emptyList()))
        }
        for (path in f.paths) {
            for ((root, prefix) in roots) {
                for (value in path.select(root)) {
                    if (f.filter == null || JsonSchemaFilter.matches(f.filter, value)) {
                        return FieldMatch(f, path, value, path.memberNames?.let { prefix + it })
                    }
                }
            }
        }
        return null
    }

    /**
     * Chooses credentials per submission_requirements (all descriptors when there are none). Each descriptor takes its
     * first candidate unless [chosen] names another. Throws access_denied when the requirements cannot be met.
     */
    fun select(
        definition: PresentationDefinition,
        candidates: Map<String, List<DescriptorMatch>>,
        chosen: Map<String, Int> = emptyMap(),
    ): List<DescriptorMatch> {
        fun pick(id: String): DescriptorMatch? = candidates[id]?.let { it.getOrNull(chosen[id] ?: 0) ?: it.firstOrNull() }
        if (definition.requirements.isEmpty()) {
            return definition.descriptors.map { d ->
                pick(d.id) ?: throw ProtocolException("access_denied", "No stored credential satisfies '${d.name ?: d.id}'")
            }
        }
        val out = linkedMapOf<String, DescriptorMatch>()
        for (r in definition.requirements) {
            val picked = evaluate(r, definition, ::pick)
                ?: throw ProtocolException("access_denied", "Submission requirement '${r.name ?: r.from ?: r.rule}' cannot be met")
            picked.forEach { out[it.descriptor.id] = it }
        }
        return out.values.toList()
    }

    private fun evaluate(r: SubmissionRequirement, def: PresentationDefinition, pick: (String) -> DescriptorMatch?): List<DescriptorMatch>? {
        // Each member is a list of matches (one per descriptor of a group, or the result of a nested requirement).
        val members: List<List<DescriptorMatch>?> = if (r.from != null) {
            def.descriptors.filter { r.from in it.groups }.map { d -> pick(d.id)?.let { listOf(it) } }
        } else r.fromNested.map { evaluate(it, def, pick) }
        val available = members.filterNotNull()
        return when (r.rule) {
            "all" -> if (members.all { it != null } && members.isNotEmpty()) available.flatten() else null
            "pick" -> {
                val need = r.count ?: r.min ?: 1
                val max = r.count ?: r.max ?: available.size
                if (available.size < need) null else available.take(minOf(max, available.size)).flatten()
            }
            else -> throw ProtocolException("invalid_request", "Unknown submission requirement rule ${r.rule}")
        }
    }
}

/** The JSON Schema subset used in Presentation Exchange filters. */
object JsonSchemaFilter {
    fun matches(schema: JsonObject, value: JsonElement): Boolean {
        schema.str("type")?.let { if (!typeMatches(it, value)) return false }
        (schema["type"] as? JsonArray)?.let { types -> if (types.none { typeMatches((it as JsonPrimitive).content, value) }) return false }
        schema["const"]?.let { if (!equalJson(it, value)) return false }
        schema.arr("enum")?.let { e -> if (e.none { equalJson(it, value) }) return false }
        val p = value as? JsonPrimitive
        schema.str("pattern")?.let { pattern ->
            if (p == null || !p.isString || runCatching { Regex(pattern).containsMatchIn(p.content) }.getOrDefault(false).not()) return false
        }
        schema.int("minLength")?.let { if (p == null || !p.isString || p.content.length < it) return false }
        schema.int("maxLength")?.let { if (p == null || !p.isString || p.content.length > it) return false }
        val num = p?.takeIf { !it.isString }?.doubleOrNull ?: p?.content?.toDoubleOrNull()?.takeIf { schema.str("format") == null }
        number(schema, "minimum")?.let { if (num == null || num < it) return false }
        number(schema, "maximum")?.let { if (num == null || num > it) return false }
        number(schema, "exclusiveMinimum")?.let { if (num == null || num <= it) return false }
        number(schema, "exclusiveMaximum")?.let { if (num == null || num >= it) return false }
        // Date formats (PE uses formatMinimum / formatMaximum with format date or date-time); ISO text compares lexically.
        schema.str("formatMinimum")?.let { if (p == null || p.content < it) return false }
        schema.str("formatMaximum")?.let { if (p == null || p.content > it) return false }
        schema.str("formatExclusiveMinimum")?.let { if (p == null || p.content <= it) return false }
        schema.str("formatExclusiveMaximum")?.let { if (p == null || p.content >= it) return false }
        schema.obj("contains")?.let { c ->
            val arr = value as? JsonArray ?: (if (value is JsonPrimitive) JsonArray(listOf(value)) else return false)
            if (arr.none { matches(c, it) }) return false
        }
        schema.obj("items")?.let { item -> (value as? JsonArray)?.let { if (!it.all { e -> matches(item, e) }) return false } }
        schema.int("minItems")?.let { if ((value as? JsonArray)?.size?.let { s -> s >= it } != true) return false }
        schema.int("maxItems")?.let { if ((value as? JsonArray)?.size?.let { s -> s <= it } != true) return false }
        schema.obj("not")?.let { if (matches(it, value)) return false }
        schema.arr("allOf")?.let { a -> if (!a.filterIsInstance<JsonObject>().all { matches(it, value) }) return false }
        schema.arr("anyOf")?.let { a -> if (a.filterIsInstance<JsonObject>().none { matches(it, value) }) return false }
        schema.arr("oneOf")?.let { a -> if (a.filterIsInstance<JsonObject>().count { matches(it, value) } != 1) return false }
        schema.obj("properties")?.let { props ->
            val o = value as? JsonObject ?: return false
            for ((k, s) in props) { val v = o[k] ?: continue; if (s is JsonObject && !matches(s, v)) return false }
            schema.strList("required").forEach { if (it !in o) return false }
        }
        return true
    }

    private fun number(schema: JsonObject, name: String): Double? = (schema[name] as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull

    private fun typeMatches(type: String, v: JsonElement): Boolean = when (type) {
        "string" -> v is JsonPrimitive && v.isString
        "number" -> v is JsonPrimitive && !v.isString && v.doubleOrNull != null
        "integer" -> v is JsonPrimitive && !v.isString && v.content.toLongOrNull() != null
        "boolean" -> v is JsonPrimitive && !v.isString && v.booleanOrNull != null
        "array" -> v is JsonArray
        "object" -> v is JsonObject
        "null" -> v is JsonNull
        else -> true
    }

    private fun equalJson(a: JsonElement, b: JsonElement): Boolean = when {
        a is JsonPrimitive && b is JsonPrimitive -> a.content == b.content && (a.isString == b.isString || a.doubleOrNull == b.doubleOrNull)
        else -> a == b
    }
}
