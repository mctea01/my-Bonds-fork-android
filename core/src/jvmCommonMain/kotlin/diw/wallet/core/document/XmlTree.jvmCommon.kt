package diw.wallet.core.document

import org.w3c.dom.Attr
import org.w3c.dom.Element
import org.w3c.dom.Node

actual object XmlTree {
    actual fun parse(bytes: ByteArray): XmlTreeDocument? {
        val doc = runCatching { XmlParsing.parse(bytes) }.getOrNull() ?: return null
        val root = doc.documentElement ?: return null
        val order = runCatching { attributeOrder(bytes) }.getOrNull()
        if (order != null) {
            val cursor = Cursor(order)
            val tree = convert(root, cursor)
            if (cursor.ok && cursor.next == order.size) return XmlTreeDocument(tree, doc.doctype?.systemId)
        }
        return XmlTreeDocument(convert(root, null), doc.doctype?.systemId)
    }

    /** The attribute names of each start tag as written, in document order (the DOM gives them sorted by name). */
    private class Cursor(val tags: List<List<String>>) {
        var next = 0
        var ok = true
    }

    private fun convert(e: Element, cursor: Cursor?): XmlElement {
        val attrs = LinkedHashMap<String, String>()
        val list = e.attributes
        for (i in 0 until list.length) {
            val a = list.item(i) as Attr
            val name = a.localName ?: a.name
            if (a.name.startsWith("xmlns")) continue
            attrs[name] = a.value
        }
        val written = cursor?.let { c -> c.tags.getOrNull(c.next).also { c.next++ } }
        val ordered = if (cursor != null && written != null && written.size == attrs.size && written.toSet() == attrs.keys) {
            LinkedHashMap<String, String>().also { m -> written.forEach { m[it] = attrs.getValue(it) } }
        } else {
            if (cursor != null && (written == null || written.toSet() != attrs.keys)) cursor.ok = false
            attrs
        }
        val children = ArrayList<XmlElement>()
        val text = StringBuilder()
        var c = e.firstChild
        while (c != null) {
            when (c.nodeType) {
                Node.ELEMENT_NODE -> children.add(convert(c as Element, cursor))
                Node.TEXT_NODE, Node.CDATA_SECTION_NODE -> text.append(c.nodeValue)
                Node.ENTITY_REFERENCE_NODE -> text.append(c.textContent ?: "")
            }
            c = c.nextSibling
        }
        return XmlElement(e.localName ?: e.nodeName, ordered, children, text.toString().trim(), text.toString())
    }

    /**
     * The local attribute names (no namespace declarations) of every start tag in [bytes], in document order.
     * Markup is ASCII in UTF-8 and the GB encodings, so the bytes are scanned as Latin-1; a document this cannot
     * follow (UTF-16, entities that add elements) gives a list that does not match the DOM and is not used.
     */
    internal fun attributeOrder(bytes: ByteArray): List<List<String>> {
        val s = String(bytes, Charsets.ISO_8859_1)
        val out = ArrayList<List<String>>()
        var i = 0
        fun after(token: String, from: Int): Int = s.indexOf(token, from).let { if (it < 0) s.length else it + token.length }
        while (i < s.length) {
            val lt = s.indexOf('<', i)
            if (lt < 0 || lt + 1 >= s.length) break
            when {
                s.startsWith("<!--", lt) -> i = after("-->", lt + 4)
                s.startsWith("<![CDATA[", lt) -> i = after("]]>", lt + 9)
                s.startsWith("<?", lt) -> i = after("?>", lt + 2)
                s.startsWith("<!", lt) -> {
                    var j = lt + 2
                    var depth = 0
                    while (j < s.length) {
                        val ch = s[j]
                        if (ch == '[') depth++ else if (ch == ']') depth-- else if (ch == '>' && depth <= 0) break
                        j++
                    }
                    i = j + 1
                }
                s[lt + 1] == '/' -> i = after(">", lt)
                else -> {
                    var j = lt + 1
                    while (j < s.length && !s[j].isWhitespace() && s[j] != '>' && s[j] != '/') j++
                    val names = ArrayList<String>()
                    while (j < s.length) {
                        while (j < s.length && s[j].isWhitespace()) j++
                        if (j >= s.length || s[j] == '>' || s[j] == '/') break
                        val start = j
                        while (j < s.length && s[j] != '=' && !s[j].isWhitespace() && s[j] != '>') j++
                        val name = s.substring(start, j)
                        while (j < s.length && s[j].isWhitespace()) j++
                        if (j >= s.length || s[j] != '=') break
                        j++
                        while (j < s.length && s[j].isWhitespace()) j++
                        if (j >= s.length) break
                        val q = s[j]
                        if (q != '"' && q != '\'') break
                        j = s.indexOf(q, j + 1).let { if (it < 0) s.length else it + 1 }
                        if (name != "xmlns" && !name.startsWith("xmlns:")) names.add(name.substringAfter(':'))
                    }
                    out.add(names)
                    i = after(">", j)
                }
            }
        }
        return out
    }
}
