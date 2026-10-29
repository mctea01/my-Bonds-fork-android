package diw.wallet.core.federation

import diw.wallet.core.util.ProtocolException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * OpenID Federation 1.0 metadata policies (section 6.1): the standard operators value, add, default, one_of,
 * subset_of, superset_of and essential, merged from the Trust Anchor down and applied to the leaf's metadata.
 * Operators this wallet does not know are ignored unless a statement lists them in metadata_policy_crit.
 */
object MetadataPolicy {
    val OPERATORS = setOf("value", "add", "default", "one_of", "subset_of", "superset_of", "essential")

    private fun fail(message: String): Nothing = throw ProtocolException("invalid_trust_chain", "metadata_policy: $message")

    /** One parameter's operators as a map of operator name to its value. */
    private fun operators(o: JsonElement, where: String, crit: Set<String>): Map<String, JsonElement> {
        val obj = o as? JsonObject ?: fail("$where is not an object")
        return obj.filter { (k, _) ->
            if (k in OPERATORS) true
            else if (k in crit) fail("$where uses the critical operator $k, which this wallet does not support")
            else false
        }
    }

    private fun list(e: JsonElement?, where: String): List<JsonElement> = when (e) {
        null -> emptyList()
        is JsonArray -> e.toList()
        else -> fail("$where must be an array")
    }

    /**
     * Combines [superior] (nearer the Trust Anchor) with [subordinate] for one entity type, as section 6.1.3.2 says:
     * value and default must agree, add and superset_of take the union, one_of and subset_of the intersection,
     * essential is true when either is.
     */
    fun merge(superior: JsonObject, subordinate: JsonObject, crit: Set<String>): JsonObject {
        val names = superior.keys + subordinate.keys
        return JsonObject(names.associateWith { name ->
            val a = superior[name]?.let { operators(it, name, crit) }.orEmpty()
            val b = subordinate[name]?.let { operators(it, name, crit) }.orEmpty()
            val out = LinkedHashMap<String, JsonElement>()
            for (op in OPERATORS) {
                val x = a[op]
                val y = b[op]
                if (x == null && y == null) continue
                out[op] = when {
                    x == null -> y!!
                    y == null -> x
                    else -> when (op) {
                        "value", "default" -> if (x == y) x else fail("$name: $op ${x} conflicts with $y")
                        "add", "superset_of" -> JsonArray((list(x, name) + list(y, name)).distinct())
                        "one_of", "subset_of" -> {
                            val i = list(x, name).filter { it in list(y, name) }
                            if (op == "one_of" && i.isEmpty()) fail("$name: one_of has no common value")
                            JsonArray(i)
                        }
                        "essential" -> JsonPrimitive((x as? JsonPrimitive)?.content == "true" || (y as? JsonPrimitive)?.content == "true")
                        else -> y
                    }
                }
            }
            check(name, out)
            JsonObject(out)
        })
    }

    /** The combinations section 6.1.3.1 forbids or constrains. */
    private fun check(name: String, ops: Map<String, JsonElement>) {
        val value = ops["value"]
        val add = ops["add"]?.let { list(it, name) }
        val oneOf = ops["one_of"]?.let { list(it, name) }
        val subset = ops["subset_of"]?.let { list(it, name) }
        val superset = ops["superset_of"]?.let { list(it, name) }
        if (oneOf != null && (subset != null || superset != null)) fail("$name: one_of cannot be combined with subset_of or superset_of")
        if (oneOf != null && add != null) fail("$name: one_of cannot be combined with add")
        if (value != null && value !is JsonNull) {
            if (oneOf != null && value !in oneOf) fail("$name: value is not one of one_of")
            if (value is JsonArray) {
                if (subset != null && !subset.containsAll(value)) fail("$name: value is not a subset of subset_of")
                if (superset != null && !value.containsAll(superset)) fail("$name: value is not a superset of superset_of")
                if (add != null && !value.containsAll(add)) fail("$name: value does not contain add")
            }
        }
        if (add != null && subset != null && !subset.containsAll(add)) fail("$name: add is not a subset of subset_of")
        if (subset != null && superset != null && !subset.containsAll(superset)) fail("$name: superset_of is not a subset of subset_of")
        ops["essential"]?.let { e ->
            val p = e as? JsonPrimitive
            if (p == null || p.isString || p.content !in setOf("true", "false")) fail("$name: essential must be a boolean")
        }
    }

    /** Applies a merged policy to one entity type's metadata, in the order of section 6.1.4.2. */
    fun apply(policy: JsonObject, metadata: JsonObject): JsonObject {
        val out = LinkedHashMap(metadata)
        for ((name, element) in policy) {
            val ops = element as? JsonObject ?: continue
            ops["value"]?.let { if (it is JsonNull) out.remove(name) else out[name] = it }
            ops["add"]?.let { add ->
                val current = out[name]?.let { list(it, name) }.orEmpty()
                out[name] = JsonArray((current + list(add, name)).distinct())
            }
            ops["default"]?.let { if (out[name] == null || out[name] is JsonNull) out[name] = it }
            ops["one_of"]?.let { oneOf -> out[name]?.let { v -> if (v !in list(oneOf, name)) fail("$name is not one of the allowed values") } }
            ops["subset_of"]?.let { subset ->
                out[name]?.let { v ->
                    val allowed = list(subset, name)
                    val kept = list(v, name).filter { it in allowed }
                    if (kept.isEmpty()) out.remove(name) else out[name] = JsonArray(kept)
                }
            }
            ops["superset_of"]?.let { superset ->
                out[name]?.let { v -> if (!list(v, name).containsAll(list(superset, name))) fail("$name does not contain every required value") }
            }
            if ((ops["essential"] as? JsonPrimitive)?.content == "true" && out[name] == null) fail("$name is essential but missing")
        }
        return JsonObject(out)
    }
}
