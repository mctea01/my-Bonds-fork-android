package diw.wallet.core.document

import org.w3c.dom.Attr
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.xml.parsers.DocumentBuilderFactory

/** Namespace-aware XML parsing that never loads external DTDs or entities (also on Android). */
internal object XmlParsing {
    /**
     * Android's bundled DOM only accepts ASCII names, so a document whose root element or DOCTYPE is Chinese (every
     * official document "函" or exchange form) fails there; Android uses the Xerces factory shipped with the app instead.
     */
    private fun factory(): DocumentBuilderFactory {
        val android = runCatching { Class.forName("android.os.Build") }.isSuccess
        if (android) runCatching {
            return Class.forName("org.apache.xerces.jaxp.DocumentBuilderFactoryImpl").getDeclaredConstructor().newInstance() as DocumentBuilderFactory
        }
        return DocumentBuilderFactory.newInstance()
    }

    fun parse(bytes: ByteArray): Document {
        val f = factory()
        f.isNamespaceAware = true
        f.isExpandEntityReferences = true
        f.isCoalescing = false
        for ((feature, value) in listOf(
            "http://apache.org/xml/features/nonvalidating/load-external-dtd" to false,
            "http://xml.org/sax/features/external-general-entities" to false,
            "http://xml.org/sax/features/external-parameter-entities" to false,
        )) runCatching { f.setFeature(feature, value) }
        runCatching { f.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "") }
        runCatching { f.setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "") }
        val builder = f.newDocumentBuilder()
        builder.setEntityResolver { _, _ -> org.xml.sax.InputSource(ByteArrayInputStream(ByteArray(0))) }
        builder.setErrorHandler(null)
        return builder.parse(ByteArrayInputStream(bytes))
    }

    fun children(e: Node): List<Element> {
        val out = ArrayList<Element>()
        var c = e.firstChild
        while (c != null) {
            if (c is Element) out.add(c)
            c = c.nextSibling
        }
        return out
    }

    fun child(e: Node, ns: String?, local: String): Element? = children(e).firstOrNull { it.localName == local && (ns == null || it.namespaceURI == ns) }

    fun childrenNamed(e: Node, ns: String?, local: String): List<Element> = children(e).filter { it.localName == local && (ns == null || it.namespaceURI == ns) }

    fun descendants(e: Node, ns: String?, local: String): List<Element> {
        val out = ArrayList<Element>()
        fun walk(n: Node) {
            var c = n.firstChild
            while (c != null) {
                if (c is Element) {
                    if (c.localName == local && (ns == null || c.namespaceURI == ns)) out.add(c)
                    walk(c)
                }
                c = c.nextSibling
            }
        }
        walk(e)
        return out
    }

    fun text(e: Element?): String? = e?.textContent?.trim()

    /** The element whose ID-like attribute (Id, ID, id, xml:id, wsu:Id) equals [id]. */
    fun byId(doc: Document, id: String): Element? {
        var found: Element? = null
        fun walk(n: Node) {
            if (found != null) return
            if (n is Element) {
                val attrs = n.attributes
                for (i in 0 until attrs.length) {
                    val a = attrs.item(i) as Attr
                    if ((a.localName ?: a.name) in setOf("Id", "ID", "id") && a.value == id) { found = n; return }
                }
            }
            var c = n.firstChild
            while (c != null) { walk(c); c = c.nextSibling }
        }
        walk(doc)
        return found
    }
}

/**
 * XML canonicalization over a DOM: Canonical XML 1.0 and 1.1 (with and without comments) and Exclusive XML
 * Canonicalization 1.0. The input is a whole document or an element (document subset of that element's subtree);
 * [exclude] removes elements (the enveloped signature, or every signature for an XPath Filter 2.0 subtract).
 */
internal object XmlC14n {
    const val C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    const val C14N_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
    const val C14N11 = "http://www.w3.org/2006/12/xml-c14n11"
    const val C14N11_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
    const val EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
    const val EXC_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
    private const val XMLNS = "http://www.w3.org/2000/xmlns/"
    private const val XML = "http://www.w3.org/XML/1998/namespace"

    val supported = setOf(C14N, C14N_COMMENTS, C14N11, C14N11_COMMENTS, EXC, EXC_COMMENTS)

    fun canonicalize(node: Node, algorithm: String, exclude: Collection<Node> = emptyList(), inclusivePrefixes: Set<String> = emptySet()): ByteArray {
        if (algorithm !in supported) throw IllegalArgumentException("Unsupported canonicalization $algorithm")
        val w = Writer(
            comments = algorithm.endsWith("#WithComments") || algorithm == EXC_COMMENTS,
            exclusive = algorithm == EXC || algorithm == EXC_COMMENTS,
            c11 = algorithm == C14N11 || algorithm == C14N11_COMMENTS,
            exclude = exclude,
            inclusivePrefixes = inclusivePrefixes,
        )
        when (node) {
            is Document -> w.document(node)
            is Element -> w.apex(node)
            else -> throw IllegalArgumentException("Cannot canonicalize ${node.nodeType}")
        }
        return w.out.toByteArray()
    }

    private class Writer(
        val comments: Boolean,
        val exclusive: Boolean,
        val c11: Boolean,
        val exclude: Collection<Node>,
        val inclusivePrefixes: Set<String>,
    ) {
        val out = ByteArrayOutputStream()

        fun write(s: String) = out.write(s.toByteArray(Charsets.UTF_8))

        fun document(doc: Document) {
            var seenRoot = false
            var c = doc.firstChild
            while (c != null) {
                when (c.nodeType) {
                    Node.ELEMENT_NODE -> { if (exclude.none { it === c }) element(c as Element, emptyMap(), true); seenRoot = true }
                    Node.PROCESSING_INSTRUCTION_NODE -> { if (seenRoot) write("\n"); pi(c); if (!seenRoot) write("\n") }
                    Node.COMMENT_NODE -> if (comments) { if (seenRoot) write("\n"); comment(c); if (!seenRoot) write("\n") }
                }
                c = c.nextSibling
            }
        }

        /** An element subtree: namespaces (and for inclusive canonicalization the xml: attributes) come from its ancestors too. */
        fun apex(e: Element) = element(e, emptyMap(), true)

        /** In-scope namespace declarations of [e]: its own and its ancestors' (nearest wins). */
        fun inScope(e: Element): Map<String, String> {
            val chain = generateSequence(e as Node) { it.parentNode }.filterIsInstance<Element>().toList().asReversed()
            val map = LinkedHashMap<String, String>()
            for (el in chain) {
                val attrs = el.attributes
                for (i in 0 until attrs.length) {
                    val a = attrs.item(i) as Attr
                    if (a.namespaceURI == XMLNS) map[if (a.prefix == null) "" else a.localName] = a.value
                }
            }
            return map
        }

        fun element(e: Element, rendered: Map<String, String>, isApex: Boolean) {
            val scope = inScope(e)
            val nsOut = sortedMapOf<String, String>()
            if (exclusive) {
                val used = HashSet<String>()
                used.add(e.prefix ?: "")
                val attrs = e.attributes
                for (i in 0 until attrs.length) {
                    val a = attrs.item(i) as Attr
                    if (a.namespaceURI != XMLNS && a.prefix != null && a.prefix != "xml") used.add(a.prefix)
                }
                used.addAll(inclusivePrefixes.map { if (it == "#default") "" else it }.filter { it in scope || it == "" })
                for (p in used) {
                    val v = scope[p] ?: ""
                    if (p == "") {
                        if (v.isEmpty() && (rendered[""] ?: "").isEmpty()) continue
                    } else if (scope[p] == null) continue
                    if (rendered[p] != v) nsOut[p] = v
                }
            } else {
                for ((p, v) in scope) {
                    if (p == "xml") continue
                    if (p == "" && v.isEmpty()) {
                        if ((rendered[""] ?: "").isNotEmpty()) nsOut[""] = ""
                        continue
                    }
                    if (rendered[p] != v) nsOut[p] = v
                }
                if (scope[""] == null && (rendered[""] ?: "").isNotEmpty()) nsOut[""] = ""
            }
            val nextRendered = HashMap(rendered).apply { putAll(nsOut) }

            // Ordinary attributes, plus the xml: attributes inherited by the apex of a subset (inclusive only).
            val plain = ArrayList<Triple<String, String, String>>() // (namespace, local, rendering)
            val own = HashSet<String>()
            val attrs = e.attributes
            for (i in 0 until attrs.length) {
                val a = attrs.item(i) as Attr
                if (a.namespaceURI == XMLNS) continue
                plain.add(Triple(a.namespaceURI ?: "", a.localName ?: a.name, a.name + "=\"" + attrEscape(a.value) + "\""))
                if (a.namespaceURI == XML) own.add(a.localName)
            }
            if (isApex && !exclusive && e.parentNode is Element) {
                val inherited = LinkedHashMap<String, String>()
                for (anc in generateSequence(e.parentNode) { it.parentNode }.filterIsInstance<Element>()) {
                    val aa = anc.attributes
                    for (i in 0 until aa.length) {
                        val a = aa.item(i) as Attr
                        if (a.namespaceURI == XML && a.localName !in own && a.localName !in inherited) {
                            if (c11 && a.localName in setOf("id", "base")) continue
                            inherited[a.localName] = a.value
                        }
                    }
                }
                for ((k, v) in inherited) plain.add(Triple(XML, k, "xml:$k=\"" + attrEscape(v) + "\""))
            }
            plain.sortWith(compareBy({ it.first }, { it.second }))

            write("<" + e.nodeName)
            for ((p, v) in nsOut) write(if (p == "") " xmlns=\"" + attrEscape(v) + "\"" else " xmlns:$p=\"" + attrEscape(v) + "\"")
            for (a in plain) write(" " + a.third)
            write(">")
            var c = e.firstChild
            while (c != null) {
                node(c, nextRendered)
                c = c.nextSibling
            }
            write("</" + e.nodeName + ">")
        }

        fun node(n: Node, rendered: Map<String, String>) {
            if (exclude.any { it === n }) return
            when (n.nodeType) {
                Node.ELEMENT_NODE -> element(n as Element, rendered, false)
                Node.TEXT_NODE, Node.CDATA_SECTION_NODE -> write(textEscape(n.nodeValue))
                Node.COMMENT_NODE -> if (comments) comment(n)
                Node.PROCESSING_INSTRUCTION_NODE -> pi(n)
                Node.ENTITY_REFERENCE_NODE -> {
                    var c = n.firstChild
                    while (c != null) { node(c, rendered); c = c.nextSibling }
                }
            }
        }

        fun pi(n: Node) {
            val data = n.nodeValue.orEmpty()
            write("<?" + n.nodeName + (if (data.isEmpty()) "" else " $data") + "?>")
        }

        fun comment(n: Node) = write("<!--" + n.nodeValue + "-->")

        fun textEscape(s: String): String {
            val b = StringBuilder(s.length)
            for (ch in s) when (ch) {
                '&' -> b.append("&amp;")
                '<' -> b.append("&lt;")
                '>' -> b.append("&gt;")
                '\r' -> b.append("&#xD;")
                else -> b.append(ch)
            }
            return b.toString()
        }

        fun attrEscape(s: String): String {
            val b = StringBuilder(s.length)
            for (ch in s) when (ch) {
                '&' -> b.append("&amp;")
                '<' -> b.append("&lt;")
                '"' -> b.append("&quot;")
                '\t' -> b.append("&#x9;")
                '\n' -> b.append("&#xA;")
                '\r' -> b.append("&#xD;")
                else -> b.append(ch)
            }
            return b.toString()
        }
    }
}
