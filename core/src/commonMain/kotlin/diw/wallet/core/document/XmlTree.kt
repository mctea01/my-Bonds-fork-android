package diw.wallet.core.document

/** An XML element as plain data: its local name, attributes, child elements and its own (direct) text, trimmed. */
data class XmlElement(
    val name: String,
    val attributes: Map<String, String>,
    val children: List<XmlElement>,
    val text: String,
) {
    fun child(name: String): XmlElement? = children.firstOrNull { it.name == name }

    fun all(name: String): List<XmlElement> = children.filter { it.name == name }

    /** The text of this element and all its descendants, in document order, trimmed. */
    fun deepText(): String = buildString {
        fun walk(e: XmlElement) {
            if (e.text.isNotEmpty()) { if (isNotEmpty()) append(' '); append(e.text) }
            e.children.forEach(::walk)
        }
        walk(this@XmlElement)
    }.trim()

    /** All descendants named [name], depth first. */
    fun descendants(name: String): List<XmlElement> = buildList {
        fun walk(e: XmlElement) { e.children.forEach { c -> if (c.name == name) add(c); walk(c) } }
        walk(this@XmlElement)
    }
}

/** A parsed XML document and the system identifier of its DOCTYPE, if any (such as "104_2_utf8.dtd"). */
data class XmlTreeDocument(val root: XmlElement, val systemId: String?)

/** XML parsing that never loads external DTDs or entities; a leading byte order mark is accepted. */
expect object XmlTree {
    /** The document, or null when [bytes] is not well formed XML. */
    fun parse(bytes: ByteArray): XmlTreeDocument?
}
