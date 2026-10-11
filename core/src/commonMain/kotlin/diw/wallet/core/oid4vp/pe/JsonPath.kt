package diw.wallet.core.oid4vp.pe

import diw.wallet.core.util.ProtocolException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * The JSONPath subset used by Presentation Exchange in practice: $, .name, ['name'], ["name"], [index], [*], .*
 * and ..name (descendants). Filters and scripts are not supported; a path using them never matches.
 */
class JsonPath private constructor(val source: String, private val steps: List<Step>) {
    private sealed class Step {
        data class Member(val name: String) : Step()
        data class Index(val index: Int) : Step()
        object Wildcard : Step()
        data class Descendant(val name: String?) : Step()
    }

    /** Values selected by the path in [root]. */
    fun select(root: JsonElement): List<JsonElement> {
        var current = listOf(root)
        for (s in steps) {
            current = current.flatMap { node ->
                when (s) {
                    is Step.Member -> listOfNotNull((node as? JsonObject)?.get(s.name))
                    is Step.Index -> listOfNotNull((node as? JsonArray)?.let { a -> (if (s.index < 0) a.size + s.index else s.index).let { a.getOrNull(it) } })
                    Step.Wildcard -> when (node) {
                        is JsonObject -> node.values.toList()
                        is JsonArray -> node.toList()
                        else -> emptyList()
                    }
                    is Step.Descendant -> descendants(node).flatMap { d ->
                        if (s.name == null) listOf(d) else listOfNotNull((d as? JsonObject)?.get(s.name))
                    }
                }
            }
            if (current.isEmpty()) return emptyList()
        }
        return current
    }

    /** Member names along the path when it uses only member steps (used to choose selective disclosures). */
    val memberNames: List<String>? get() = steps.map { (it as? Step.Member)?.name ?: return null }

    private fun descendants(e: JsonElement): List<JsonElement> = listOf(e) + when (e) {
        is JsonObject -> e.values.flatMap { descendants(it) }
        is JsonArray -> e.flatMap { descendants(it) }
        else -> emptyList()
    }

    override fun toString() = source

    companion object {
        fun parse(path: String): JsonPath {
            val p = path.trim()
            if (!p.startsWith("$")) throw ProtocolException("invalid_request", "JSONPath must start with $: $path")
            val steps = mutableListOf<Step>()
            var i = 1
            fun readName(): String {
                val start = i
                while (i < p.length && p[i] != '.' && p[i] != '[') i++
                return p.substring(start, i)
            }
            while (i < p.length) {
                when {
                    p.startsWith("..", i) -> {
                        i += 2
                        if (i < p.length && p[i] == '*') { i++; steps += Step.Descendant(null) }
                        else if (i < p.length && p[i] == '[') steps += Step.Descendant(null)
                        else steps += Step.Descendant(readName())
                    }
                    p[i] == '.' -> {
                        i++
                        if (i < p.length && p[i] == '*') { i++; steps += Step.Wildcard } else steps += Step.Member(readName())
                    }
                    p[i] == '[' -> {
                        val end = closingBracket(p, i)
                        val inner = p.substring(i + 1, end).trim()
                        i = end + 1
                        steps += when {
                            inner == "*" -> Step.Wildcard
                            (inner.startsWith("'") && inner.endsWith("'")) || (inner.startsWith("\"") && inner.endsWith("\"")) ->
                                Step.Member(inner.substring(1, inner.length - 1).replace("\\'", "'").replace("\\\"", "\""))
                            inner.toIntOrNull() != null -> Step.Index(inner.toInt())
                            else -> throw ProtocolException("invalid_request", "Unsupported JSONPath expression [$inner] in $path")
                        }
                    }
                    else -> throw ProtocolException("invalid_request", "Malformed JSONPath $path")
                }
            }
            return JsonPath(p, steps)
        }

        private fun closingBracket(p: String, open: Int): Int {
            var quote: Char? = null
            var i = open + 1
            while (i < p.length) {
                val c = p[i]
                if (quote != null) {
                    if (c == '\\') i++ else if (c == quote) quote = null
                } else if (c == '\'' || c == '"') quote = c else if (c == ']') return i
                i++
            }
            throw ProtocolException("invalid_request", "Unclosed [ in JSONPath $p")
        }
    }
}
