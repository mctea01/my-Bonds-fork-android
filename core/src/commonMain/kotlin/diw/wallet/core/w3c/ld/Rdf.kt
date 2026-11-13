package diw.wallet.core.w3c.ld

import diw.wallet.core.util.ProtocolException

/** An RDF term of an N-Quad. */
sealed interface RdfTerm

data class Iri(val value: String) : RdfTerm

/** A blank node; [id] has no "_:" prefix. */
data class BlankNode(val id: String) : RdfTerm

data class Literal(val value: String, val datatype: String = XSD_STRING, val language: String? = null) : RdfTerm

/** An RDF quad; [graph] is null for the default graph. */
data class Quad(val subject: RdfTerm, val predicate: Iri, val obj: RdfTerm, val graph: RdfTerm? = null) {
    /** The canonical N-Quads line, including the trailing newline. */
    fun toNQuad(): String = NQuads.line(this)

    /** This quad with every blank node renamed by [label] (identity when it returns its input). */
    fun relabel(label: (String) -> String): Quad {
        fun term(t: RdfTerm?): RdfTerm? = if (t is BlankNode) BlankNode(label(t.id)) else t
        return Quad(term(subject)!!, predicate, term(obj)!!, term(graph))
    }

    fun blankNodes(): List<String> = listOfNotNull(subject, obj, graph).filterIsInstance<BlankNode>().map { it.id }
}

const val XSD_STRING = "http://www.w3.org/2001/XMLSchema#string"
const val RDF_LANG_STRING = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"

/** Canonical N-Quads (RDF 1.2 canonical form, as RDFC-1.0 and rdf-canonize write it) and a strict line parser. */
object NQuads {
    fun line(q: Quad): String = buildString {
        term(q.subject); append(' ')
        term(q.predicate); append(' ')
        term(q.obj); append(' ')
        q.graph?.let { term(it); append(' ') }
        append(".\n")
    }

    fun serialize(quads: Iterable<Quad>): List<String> = quads.map(::line)

    private fun StringBuilder.term(t: RdfTerm) {
        when (t) {
            is Iri -> append('<').append(t.value).append('>')
            is BlankNode -> append("_:").append(t.id)
            is Literal -> {
                append('"')
                for (c in t.value) {
                    when (c) {
                        '\b' -> append("\\b")
                        '\t' -> append("\\t")
                        '\n' -> append("\\n")
                        '\u000C' -> append("\\f")
                        '\r' -> append("\\r")
                        '"' -> append("\\\"")
                        '\\' -> append("\\\\")
                        else -> if (c.code < 0x20 || c.code == 0x7f) {
                            append("\\u").append(c.code.toString(16).uppercase().padStart(4, '0'))
                        } else append(c)
                    }
                }
                append('"')
                when {
                    t.language != null -> append('@').append(t.language)
                    t.datatype != XSD_STRING -> append("^^<").append(t.datatype).append('>')
                }
            }
        }
    }

    /** Parses N-Quads lines (one statement per line, as produced by [line]). */
    fun parse(text: String): List<Quad> = text.split('\n').map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.map(::parseLine)

    fun parseLine(line: String): Quad {
        val p = Parser(line)
        val s = p.term()
        val pr = p.term() as? Iri ?: throw ProtocolException("invalid_rdf", "N-Quad predicate must be an IRI")
        val o = p.term()
        p.skip()
        val g = if (p.peek() != '.') p.term() else null
        p.skip()
        if (p.peek() != '.') throw ProtocolException("invalid_rdf", "N-Quad must end with '.'")
        if (s is Literal || g is Literal) throw ProtocolException("invalid_rdf", "Literal in subject or graph position")
        return Quad(s, pr, o, g)
    }

    private class Parser(val s: String) {
        var i = 0
        fun peek(): Char = if (i < s.length) s[i] else '\u0000'
        fun skip() { while (i < s.length && (s[i] == ' ' || s[i] == '\t')) i++ }
        fun term(): RdfTerm {
            skip()
            return when (peek()) {
                '<' -> Iri(iri())
                '_' -> {
                    if (!s.startsWith("_:", i)) fail()
                    i += 2
                    val start = i
                    while (i < s.length && s[i] != ' ' && s[i] != '\t') i++
                    BlankNode(s.substring(start, i))
                }
                '"' -> literal()
                else -> fail()
            }
        }
        private fun iri(): String {
            i++
            val end = s.indexOf('>', i).takeIf { it >= 0 } ?: fail()
            return s.substring(i, end).also { i = end + 1 }
        }
        private fun literal(): Literal {
            i++
            val b = StringBuilder()
            while (true) {
                if (i >= s.length) fail()
                val c = s[i++]
                if (c == '"') break
                if (c != '\\') { b.append(c); continue }
                if (i >= s.length) fail()
                when (val e = s[i++]) {
                    'b' -> b.append('\b'); 't' -> b.append('\t'); 'n' -> b.append('\n'); 'f' -> b.append('\u000C')
                    'r' -> b.append('\r'); '"' -> b.append('"'); '\'' -> b.append('\''); '\\' -> b.append('\\')
                    'u', 'U' -> {
                        val n = if (e == 'u') 4 else 8
                        if (i + n > s.length) fail()
                        val cp = s.substring(i, i + n).toIntOrNull(16) ?: fail()
                        i += n
                        if (cp > 0xFFFF) {
                            val v = cp - 0x10000
                            b.append((0xD800 + (v shr 10)).toChar()).append((0xDC00 + (v and 0x3FF)).toChar())
                        } else b.append(cp.toChar())
                    }
                    else -> fail()
                }
            }
            return when (peek()) {
                '@' -> {
                    i++
                    val start = i
                    while (i < s.length && s[i] != ' ' && s[i] != '\t') i++
                    Literal(b.toString(), RDF_LANG_STRING, s.substring(start, i))
                }
                '^' -> {
                    if (!s.startsWith("^^<", i)) fail()
                    i += 2
                    Literal(b.toString(), iri())
                }
                else -> Literal(b.toString())
            }
        }
        fun fail(): Nothing = throw ProtocolException("invalid_rdf", "Malformed N-Quad")
    }
}
