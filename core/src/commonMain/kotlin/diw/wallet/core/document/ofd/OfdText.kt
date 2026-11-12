package diw.wallet.core.document.ofd

import kotlin.math.abs
import kotlin.math.max

/**
 * Plain text of OFD pages, line by line as a reader sees it, the same way the PDF text layer is laid out: the
 * characters of every text object are placed on the page and grouped into lines by baseline, top to bottom, left
 * to right; runs on one line that are visibly apart are separated by a space. Pages are separated by a blank line.
 */
object OfdText {
    fun extract(pkg: OfdPackage, maxPages: Int = 50): String = pkg.pages.take(maxPages).joinToString("\n\n") { page(it) }

    fun page(page: OfdPage): String = layout(page.objects.filterIsInstance<OfdObject.Text>().flatMap { it.glyphs() })

    fun layout(glyphs: List<OfdGlyph>): String {
        val visible = glyphs.filter { it.text.isNotBlank() || it.text == " " }
        if (visible.isEmpty()) return ""
        // Text drawn twice at the same place (simulated bold) counts once.
        val unique = visible.distinctBy { Triple((it.x * 4).toLong(), (it.y * 4).toLong(), it.text) }
        val sorted = unique.sortedWith(compareBy<OfdGlyph> { it.y }.thenBy { it.x })
        val lines = ArrayList<MutableList<OfdGlyph>>()
        var lineY = Double.NaN
        var lineSize = 0.0
        for (g in sorted) {
            val tolerance = max(0.4, 0.45 * max(lineSize, g.size))
            if (lines.isEmpty() || abs(g.y - lineY) > tolerance) {
                lines.add(ArrayList())
                lineY = g.y
                lineSize = g.size
            }
            lines.last().add(g)
        }
        return lines.joinToString("\n") { line ->
            val sb = StringBuilder()
            var end = Double.NaN
            for (g in line.sortedBy { it.x }) {
                if (!end.isNaN() && g.x - end > 0.25 * g.size && sb.isNotEmpty() && !sb.last().isWhitespace() && g.text != " ") sb.append(' ')
                sb.append(g.text)
                end = if (end.isNaN()) g.x + g.width else max(end, g.x + g.width)
            }
            sb.toString().trim()
        }.lines().filter { it.isNotEmpty() }.joinToString("\n")
    }
}

/**
 * Values of a custom tag file (GB/T 33190 section 16). Tag files are often not well formed XML (invoices from
 * some producers write elements with an empty prefix, "<:InvoiceNo>"), so they are read with a tolerant tokenizer:
 * an element holding ObjectRef children takes the text of the page objects they name, a leaf element its own text.
 * Names are local (without prefix); nested elements are named by their own name.
 */
object OfdTags {
    private val token = Regex("<!--.*?-->|<\\?.*?\\?>|<!\\[CDATA\\[(.*?)]]>|<(/?)([^\\s>/!?]*)([^>]*?)(/?)>|([^<]+)", RegexOption.DOT_MATCHES_ALL)

    fun values(bytes: ByteArray, texts: Map<String, String>): List<Pair<String, String>> {
        val s = bytes.decodeToString().removePrefix("﻿")
        val out = ArrayList<Pair<String, String>>()
        class Open(val name: String) { val text = StringBuilder(); val refs = StringBuilder(); var children = 0 }
        val stack = ArrayList<Open>()
        for (m in token.findAll(s)) {
            val v = m.value
            when {
                v.startsWith("<!--") || v.startsWith("<?") -> {}
                m.groups[1] != null -> stack.lastOrNull()?.text?.append(m.groupValues[1])
                m.groups[6] != null -> stack.lastOrNull()?.text?.append(unescape(m.groupValues[6]))
                else -> {
                    val closing = m.groupValues[2] == "/"
                    val name = m.groupValues[3].substringAfterLast(':')
                    val selfClosing = m.groupValues[5] == "/"
                    if (!closing) {
                        stack.lastOrNull()?.let { it.children++ }
                        if (!selfClosing) stack.add(Open(name))
                        continue
                    }
                    val idx = stack.indexOfLast { it.name == name }
                    if (idx < 0) continue
                    while (stack.size > idx + 1) stack.removeAt(stack.size - 1)
                    val e = stack.removeAt(stack.size - 1)
                    val parent = stack.lastOrNull()
                    if (name == "ObjectRef") {
                        val ids = e.text.toString().trim().split(Regex("\\s+"))
                        val joined = ids.mapNotNull { texts[it] }.joinToString("")
                        if (parent != null) parent.refs.append(joined)
                        continue
                    }
                    val value = if (e.refs.isNotEmpty()) e.refs.toString() else if (e.children == 0) e.text.toString() else ""
                    val clean = value.replace(Regex("\\s+"), " ").trim()
                    if (clean.isNotEmpty() && stack.isNotEmpty()) out.add(name to clean)
                }
            }
        }
        return out
    }

    private fun unescape(s: String) = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}
