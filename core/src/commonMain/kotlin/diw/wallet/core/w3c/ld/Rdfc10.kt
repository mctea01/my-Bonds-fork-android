package diw.wallet.core.w3c.ld

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.ProtocolException

/**
 * RDF Dataset Canonicalization (W3C RDFC-1.0) with SHA-256.
 *
 * [maxWork] bounds the number of N-degree hash calls and permutations, so a crafted dataset (many
 * indistinguishable blank nodes) is rejected instead of taking exponential time.
 */
object Rdfc10 {
    /** The canonical dataset: [quads] sorted by their N-Quads lines, and the issued map input id to c14n id. */
    class Result(val quads: List<Quad>, val issued: Map<String, String>) {
        val nquads: List<String> by lazy { quads.map { it.toNQuad() } }
        fun text(): String = nquads.joinToString("")
    }

    fun canonicalize(input: List<Quad>, maxWork: Int = 100_000): Result {
        val dataset = input.distinct()
        val state = State(dataset, maxWork)
        return state.run()
    }

    private class Issuer(val prefix: String, val issued: LinkedHashMap<String, String> = LinkedHashMap(), var counter: Int = 0) {
        fun issue(id: String): String = issued.getOrPut(id) { prefix + counter++ }
        fun has(id: String) = id in issued
        fun copy() = Issuer(prefix, LinkedHashMap(issued), counter)
    }

    private class State(val dataset: List<Quad>, val maxWork: Int) {
        val quadsOf = HashMap<String, MutableList<Quad>>()
        val firstDegree = HashMap<String, String>()
        val canonical = Issuer("c14n")
        var work = 0

        fun run(): Result {
            for (q in dataset) for (b in q.blankNodes().distinct()) quadsOf.getOrPut(b) { mutableListOf() }.add(q)
            val hashToNodes = sortedMapOf<String, MutableList<String>>()
            for (b in quadsOf.keys) hashToNodes.getOrPut(hashFirstDegree(b)) { mutableListOf() }.add(b)
            val remaining = sortedMapOf<String, MutableList<String>>()
            for ((h, nodes) in hashToNodes) if (nodes.size == 1) canonical.issue(nodes[0]) else remaining[h] = nodes
            for ((_, nodes) in remaining) {
                val paths = mutableListOf<Pair<String, Issuer>>()
                for (n in nodes) {
                    if (canonical.has(n)) continue
                    val temp = Issuer("b")
                    temp.issue(n)
                    paths += hashNDegree(n, temp)
                }
                paths.sortBy { it.first }
                for ((_, issuer) in paths) for (id in issuer.issued.keys) canonical.issue(id)
            }
            val out = dataset.map { q -> q.relabel { canonical.issued[it] ?: error("unlabelled blank node") } }
            val sorted = out.map { it to it.toNQuad() }.sortedWith { a, b -> compareCodePoints(a.second, b.second) }
            return Result(sorted.map { it.first }, LinkedHashMap(canonical.issued))
        }

        fun hashFirstDegree(ref: String): String = firstDegree.getOrPut(ref) {
            val lines = quadsOf.getValue(ref).map { q -> q.relabel { if (it == ref) "a" else "z" }.toNQuad() }.sortedWith { a, b -> compareCodePoints(a, b) }
            sha256Hex(lines.joinToString(""))
        }

        fun hashRelated(related: String, quad: Quad, issuer: Issuer, position: Char): String {
            val id = canonical.issued[related]?.let { "_:$it" } ?: issuer.issued[related]?.let { "_:$it" } ?: hashFirstDegree(related)
            val input = StringBuilder().append(position)
            if (position != 'g') input.append('<').append(quad.predicate.value).append('>')
            input.append(id)
            return sha256Hex(input.toString())
        }

        fun hashNDegree(identifier: String, start: Issuer): Pair<String, Issuer> {
            if (++work > maxWork) throw ProtocolException("invalid_rdf", "RDF canonicalization exceeded its work limit")
            var issuer = start
            val hashToRelated = sortedMapOf<String, MutableList<String>>()
            for (q in quadsOf.getValue(identifier)) {
                for ((term, pos) in listOf(q.subject to 's', q.obj to 'o', q.graph to 'g')) {
                    if (term is BlankNode && term.id != identifier) {
                        hashToRelated.getOrPut(hashRelated(term.id, q, issuer, pos)) { mutableListOf() }.add(term.id)
                    }
                }
            }
            val data = StringBuilder()
            for ((hash, related) in hashToRelated) {
                data.append(hash)
                var chosenPath = ""
                var chosenIssuer: Issuer? = null
                for (perm in permutations(related)) {
                    if (++work > maxWork) throw ProtocolException("invalid_rdf", "RDF canonicalization exceeded its work limit")
                    var copy = issuer.copy()
                    val path = StringBuilder()
                    val recursion = mutableListOf<String>()
                    var skip = false
                    for (r in perm) {
                        val c = canonical.issued[r]
                        if (c != null) path.append("_:").append(c)
                        else {
                            if (!copy.has(r)) recursion += r
                            path.append("_:").append(copy.issue(r))
                        }
                        if (chosenPath.isNotEmpty() && compareCodePoints(path.toString(), chosenPath) > 0) { skip = true; break }
                    }
                    if (skip) continue
                    for (r in recursion) {
                        val (h, next) = hashNDegree(r, copy)
                        path.append("_:").append(next.issue(r)).append('<').append(h).append('>')
                        copy = next
                        if (chosenPath.isNotEmpty() && compareCodePoints(path.toString(), chosenPath) > 0) { skip = true; break }
                    }
                    if (skip) continue
                    if (chosenPath.isEmpty() || compareCodePoints(path.toString(), chosenPath) < 0) {
                        chosenPath = path.toString()
                        chosenIssuer = copy
                    }
                }
                data.append(chosenPath)
                issuer = chosenIssuer ?: issuer
            }
            return sha256Hex(data.toString()) to issuer
        }
    }

    /** All orderings of [items] (Heap's algorithm order does not matter: every permutation is compared). */
    private fun permutations(items: List<String>): Sequence<List<String>> = sequence {
        val a = items.toMutableList()
        val c = IntArray(a.size)
        yield(a.toList())
        var i = 0
        while (i < a.size) {
            if (c[i] < i) {
                if (i % 2 == 0) a.swap(0, i) else a.swap(c[i], i)
                yield(a.toList())
                c[i]++
                i = 0
            } else {
                c[i] = 0
                i++
            }
        }
    }

    private fun MutableList<String>.swap(x: Int, y: Int) { val t = this[x]; this[x] = this[y]; this[y] = t }

    /** Unicode code point order (UTF-16 code unit order differs only for supplementary characters). */
    fun compareCodePoints(a: String, b: String): Int {
        var i = 0
        var j = 0
        while (i < a.length && j < b.length) {
            val ca = codePointAt(a, i)
            val cb = codePointAt(b, j)
            if (ca != cb) return ca.compareTo(cb)
            i += if (ca > 0xFFFF) 2 else 1
            j += if (cb > 0xFFFF) 2 else 1
        }
        return (a.length - i).compareTo(b.length - j)
    }

    private fun codePointAt(s: String, i: Int): Int {
        val c = s[i]
        if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) {
            return ((c.code - 0xD800) shl 10) + (s[i + 1].code - 0xDC00) + 0x10000
        }
        return c.code
    }

    fun sha256Hex(s: String): String = PlatformCrypto.sha256(s.encodeToByteArray()).joinToString("") {
        (it.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}
