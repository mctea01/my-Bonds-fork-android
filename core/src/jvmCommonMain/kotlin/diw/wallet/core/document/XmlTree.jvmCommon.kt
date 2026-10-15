package diw.wallet.core.document

import org.w3c.dom.Attr
import org.w3c.dom.Element
import org.w3c.dom.Node

actual object XmlTree {
    actual fun parse(bytes: ByteArray): XmlTreeDocument? {
        val doc = runCatching { XmlParsing.parse(bytes) }.getOrNull() ?: return null
        val root = doc.documentElement ?: return null
        return XmlTreeDocument(convert(root), doc.doctype?.systemId)
    }

    private fun convert(e: Element): XmlElement {
        val attrs = LinkedHashMap<String, String>()
        val list = e.attributes
        for (i in 0 until list.length) {
            val a = list.item(i) as Attr
            val name = a.localName ?: a.name
            if (a.name.startsWith("xmlns")) continue
            attrs[name] = a.value
        }
        val children = ArrayList<XmlElement>()
        val text = StringBuilder()
        var c = e.firstChild
        while (c != null) {
            when (c.nodeType) {
                Node.ELEMENT_NODE -> children.add(convert(c as Element))
                Node.TEXT_NODE, Node.CDATA_SECTION_NODE -> text.append(c.nodeValue)
                Node.ENTITY_REFERENCE_NODE -> text.append(c.textContent ?: "")
            }
            c = c.nextSibling
        }
        return XmlElement(e.localName ?: e.nodeName, attrs, children, text.toString().trim())
    }
}
