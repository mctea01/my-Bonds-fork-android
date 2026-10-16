package diw.wallet.core.document.pdf

import kotlin.math.abs
import kotlin.math.max
import kotlin.math.sqrt

/**
 * Plain text of a PDF, line by line as a reader sees it: content streams (and form XObjects) are interpreted for
 * text placement only, glyphs are mapped to Unicode through ToUnicode CMaps, the Unicode CMaps of CJK fonts
 * (Uni*-UCS2 / UTF16) or the simple font encodings, and glyphs are grouped into lines by baseline. Runs on one line
 * that are visibly apart are separated by a space. Images, vector graphics and annotations are ignored.
 */
object PdfTextExtractor {
    private const val MAX_FORM_DEPTH = 8
    private const val MAX_OPERATIONS = 2_000_000

    /** Text of the first [maxPages] pages; pages are separated by a blank line. */
    fun extract(pdf: PdfFile, maxPages: Int = 50): String =
        pages(pdf).take(maxPages).joinToString("\n\n") { pageText(pdf, it) }

    /** The page dictionaries in order, each with its inherited Resources, MediaBox and Rotate filled in. */
    fun pages(pdf: PdfFile): List<PdfDict> {
        val out = ArrayList<PdfDict>()
        val seen = HashSet<PdfObject>()
        fun walk(node: PdfObject?, inherited: Map<String, PdfObject>, depth: Int) {
            if (depth > 64 || (node is PdfRef && !seen.add(node))) return
            val d = pdf.dict(node) ?: return
            val inherit = HashMap(inherited)
            for (k in listOf("Resources", "MediaBox", "CropBox", "Rotate")) d[k]?.let { inherit[k] = it }
            val kids = pdf.array(d["Kids"])
            if (kids != null && d.name("Type") != "Page") {
                kids.forEach { walk(it, inherit, depth + 1) }
            } else {
                out.add(PdfDict(LinkedHashMap(d.entries).apply { inherit.forEach { (k, v) -> putIfAbsent(k, v) } }))
            }
        }
        walk(pdf.catalog["Pages"], emptyMap(), 0)
        return out
    }

    /** Text of one page dictionary (as returned by [pages]). */
    fun pageText(pdf: PdfFile, page: PdfDict): String {
        val content = when (val c = pdf.resolve(page["Contents"])) {
            is PdfStream -> pdf.decode(c)
            is PdfArray -> c.mapNotNull { pdf.resolve(it) as? PdfStream }.fold(ByteArray(0)) { acc, s -> acc + pdf.decode(s) + byteArrayOf(10) }
            else -> ByteArray(0)
        }
        val glyphs = ArrayList<Glyph>()
        Interpreter(pdf, glyphs).run(content, pdf.dict(page["Resources"]), Matrix.IDENTITY, 0)
        return layout(glyphs)
    }

    // ---------------------------------------------------------------- layout

    private class Glyph(val x: Double, val y: Double, val width: Double, val size: Double, val text: String)

    private fun layout(glyphs: List<Glyph>): String {
        if (glyphs.isEmpty()) return ""
        // Text drawn twice at the same place (simulated bold) counts once.
        val unique = glyphs.distinctBy { Triple((it.x * 2).toLong(), (it.y * 2).toLong(), it.text) }
        val sorted = unique.sortedWith(compareByDescending<Glyph> { it.y }.thenBy { it.x })
        val lines = ArrayList<MutableList<Glyph>>()
        var lineY = Double.NaN
        var lineSize = 0.0
        for (g in sorted) {
            val tolerance = max(1.0, 0.45 * max(lineSize, g.size))
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
                if (!end.isNaN() && g.x - end > 0.25 * g.size && sb.isNotEmpty() && !sb.last().isWhitespace() && !g.text.startsWith(" ")) sb.append(' ')
                sb.append(g.text)
                end = if (end.isNaN()) g.x + g.width else max(end, g.x + g.width)
            }
            sb.toString().trimEnd()
        }.trim('\n')
    }

    // ---------------------------------------------------------------- content streams

    private class Matrix(val a: Double, val b: Double, val c: Double, val d: Double, val e: Double, val f: Double) {
        /** this x other (apply this first, then other). */
        fun times(o: Matrix) = Matrix(
            a * o.a + b * o.c, a * o.b + b * o.d,
            c * o.a + d * o.c, c * o.b + d * o.d,
            e * o.a + f * o.c + o.e, e * o.b + f * o.d + o.f,
        )

        companion object {
            val IDENTITY = Matrix(1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
            fun translate(x: Double, y: Double) = Matrix(1.0, 0.0, 0.0, 1.0, x, y)
            fun of(n: List<Double>) = if (n.size == 6) Matrix(n[0], n[1], n[2], n[3], n[4], n[5]) else IDENTITY
        }
    }

    private class State(
        var ctm: Matrix = Matrix.IDENTITY,
        var font: PdfFont? = null,
        var size: Double = 0.0,
        var charSpacing: Double = 0.0,
        var wordSpacing: Double = 0.0,
        var scale: Double = 1.0,
        var leading: Double = 0.0,
        var rise: Double = 0.0,
    ) {
        fun copy() = State(ctm, font, size, charSpacing, wordSpacing, scale, leading, rise)
    }

    /** A keyword in a content stream or CMap (an operator, or a CMap keyword such as beginbfchar). */
    internal class Keyword(val word: String)

    /** Operands and operators of a content stream or CMap, in order; malformed bytes are skipped. */
    internal fun tokens(data: ByteArray, onInlineImage: (PdfParser) -> Unit = ::skipInlineImage): Sequence<Any> = sequence {
        val p = PdfParser(data)
        while (true) {
            p.skipWhitespace()
            if (p.pos >= data.size) break
            val c = data[p.pos].toInt() and 0xFF
            val numberStart = c == '+'.code || c == '-'.code || c == '.'.code || c in '0'.code..'9'.code
            if (PdfParser.isRegular(c) && !numberStart) {
                when (val word = p.readToken()) {
                    "true" -> yield(PdfBool(true))
                    "false" -> yield(PdfBool(false))
                    "null" -> yield(PdfNull)
                    "BI" -> onInlineImage(p)
                    else -> yield(Keyword(word))
                }
                continue
            }
            if (c == ']'.code || c == ')'.code || c == '{'.code || c == '}'.code || c == '>'.code) { p.pos++; continue }
            val start = p.pos
            val o = try { p.parseObject() } catch (e: PdfException) { null }
            if (o == null || p.pos <= start) { p.pos = start + 1; continue }
            yield(o)
        }
    }

    /** Skips an inline image: its dictionary up to ID, then the data up to an EI between white space. */
    private fun skipInlineImage(p: PdfParser) {
        val b = p.bytes
        val id = PdfParser.indexOf(b, "ID".encodeToByteArray(), p.pos)
        if (id < 0) { p.pos = b.size; return }
        var i = id + 3
        while (i + 1 < b.size) {
            if (b[i] == 'E'.code.toByte() && b[i + 1] == 'I'.code.toByte() &&
                PdfParser.isWhite(b[i - 1].toInt() and 0xFF) && (i + 2 >= b.size || !PdfParser.isRegular(b[i + 2].toInt() and 0xFF))
            ) {
                p.pos = i + 2
                return
            }
            i++
        }
        p.pos = b.size
    }

    private class Interpreter(val pdf: PdfFile, val out: MutableList<Glyph>) {
        private val fonts = HashMap<PdfObject, PdfFont>()
        private var operations = 0

        fun run(content: ByteArray, resources: PdfDict?, base: Matrix, depth: Int) {
            var gs = State(ctm = base)
            val stack = ArrayList<State>()
            var tm = Matrix.IDENTITY
            var tlm = Matrix.IDENTITY
            val operands = ArrayList<PdfObject>()
            fun num(i: Int) = (operands.getOrNull(i) as? PdfNumber)?.let { runCatching { it.double }.getOrNull() } ?: 0.0
            fun nums() = operands.map { (it as? PdfNumber)?.let { n -> runCatching { n.double }.getOrNull() } ?: 0.0 }
            fun nextLine(tx: Double, ty: Double) {
                tlm = Matrix.translate(tx, ty).times(tlm)
                tm = tlm
            }
            fun show(bytes: ByteArray) {
                val font = gs.font ?: return
                for ((code, length) in font.codes(bytes)) {
                    val trm = Matrix(gs.size * gs.scale, 0.0, 0.0, gs.size, 0.0, gs.rise).times(tm).times(gs.ctm)
                    val w0 = font.width(code) / 1000.0
                    val space = if (length == 1 && code == 32) gs.wordSpacing else 0.0
                    val tx = (w0 * gs.size + gs.charSpacing + space) * gs.scale
                    val text = font.unicode(code)
                    if (!text.isNullOrEmpty()) {
                        val size = sqrt(trm.c * trm.c + trm.d * trm.d)
                        val width = tx * sqrt(tm.a * tm.a + tm.b * tm.b) * sqrt(gs.ctm.a * gs.ctm.a + gs.ctm.b * gs.ctm.b)
                        out.add(Glyph(trm.e, trm.f, abs(width), size, text))
                    }
                    tm = Matrix.translate(tx, 0.0).times(tm)
                }
            }
            for (t in tokens(content)) {
                if (t is PdfObject) {
                    operands.add(t)
                    continue
                }
                if (++operations > MAX_OPERATIONS) return
                when ((t as Keyword).word) {
                    "q" -> stack.add(gs.copy())
                    "Q" -> if (stack.isNotEmpty()) gs = stack.removeAt(stack.size - 1)
                    "cm" -> gs.ctm = Matrix.of(nums()).times(gs.ctm)
                    "BT" -> { tm = Matrix.IDENTITY; tlm = Matrix.IDENTITY }
                    "Tf" -> {
                        gs.font = (operands.getOrNull(0) as? PdfName)?.let { font(resources, it.name) }
                        gs.size = num(1)
                    }
                    "Tc" -> gs.charSpacing = num(0)
                    "Tw" -> gs.wordSpacing = num(0)
                    "Tz" -> gs.scale = num(0) / 100.0
                    "TL" -> gs.leading = num(0)
                    "Ts" -> gs.rise = num(0)
                    "Td" -> nextLine(num(0), num(1))
                    "TD" -> { gs.leading = -num(1); nextLine(num(0), num(1)) }
                    "Tm" -> { tlm = Matrix.of(nums()); tm = tlm }
                    "T*" -> nextLine(0.0, -gs.leading)
                    "Tj" -> (operands.lastOrNull() as? PdfString)?.let { show(it.bytes) }
                    "'" -> { nextLine(0.0, -gs.leading); (operands.lastOrNull() as? PdfString)?.let { show(it.bytes) } }
                    "\"" -> {
                        gs.wordSpacing = num(0)
                        gs.charSpacing = num(1)
                        nextLine(0.0, -gs.leading)
                        (operands.lastOrNull() as? PdfString)?.let { show(it.bytes) }
                    }
                    "TJ" -> (operands.lastOrNull() as? PdfArray)?.forEach { item ->
                        when (item) {
                            is PdfString -> show(item.bytes)
                            is PdfNumber -> tm = Matrix.translate(-runCatching { item.double }.getOrDefault(0.0) / 1000.0 * gs.size * gs.scale, 0.0).times(tm)
                            else -> {}
                        }
                    }
                    "Do" -> (operands.lastOrNull() as? PdfName)?.let { form(resources, it.name, gs.ctm, depth) }
                }
                operands.clear()
            }
        }

        private fun form(resources: PdfDict?, name: String, ctm: Matrix, depth: Int) {
            if (depth >= MAX_FORM_DEPTH) return
            val xobjects = pdf.dict(resources?.get("XObject")) ?: return
            val s = pdf.resolve(xobjects[name]) as? PdfStream ?: return
            if (s.dict.name("Subtype") != "Form") return
            val matrix = pdf.array(s.dict["Matrix"])?.map { (pdf.resolve(it) as? PdfNumber)?.double ?: 0.0 }?.let { Matrix.of(it) } ?: Matrix.IDENTITY
            val data = runCatching { pdf.decode(s) }.getOrNull() ?: return
            run(data, pdf.dict(s.dict["Resources"]) ?: resources, matrix.times(ctm), depth + 1)
        }

        private fun font(resources: PdfDict?, name: String): PdfFont? {
            val ref = pdf.dict(resources?.get("Font"))?.get(name) ?: return null
            fonts[ref]?.let { return it }
            val d = pdf.dict(ref) ?: return null
            return runCatching { PdfFont.of(pdf, d) }.getOrNull()?.also { fonts[ref] = it }
        }
    }
}

/** How one font maps the bytes of a shown string to character codes, Unicode text and widths (1/1000 text space). */
internal class PdfFont private constructor(
    private val codespace: CodeSpace,
    private val toUnicode: Map<Int, String>,
    private val fallback: (Int) -> String?,
    private val widthOf: (Int) -> Double,
) {
    fun codes(bytes: ByteArray): List<Pair<Int, Int>> = codespace.split(bytes)
    fun unicode(code: Int): String? = toUnicode[code] ?: fallback(code)
    fun width(code: Int): Double = widthOf(code)

    /** Byte lengths of the codes of a font: fixed, UTF-16 (2 or 4 bytes), or CMap codespace ranges. */
    internal class CodeSpace(private val ranges: List<Triple<Int, ByteArray, ByteArray>>, private val utf16: Boolean = false) {
        fun split(b: ByteArray): List<Pair<Int, Int>> {
            val out = ArrayList<Pair<Int, Int>>()
            var i = 0
            while (i < b.size) {
                val len = length(b, i).coerceAtMost(b.size - i).coerceAtLeast(1)
                var code = 0
                for (k in 0 until len) code = (code shl 8) or (b[i + k].toInt() and 0xFF)
                out.add(code to len)
                i += len
            }
            return out
        }

        private fun length(b: ByteArray, i: Int): Int {
            if (utf16) {
                val hi = b[i].toInt() and 0xFF
                return if (hi in 0xD8..0xDB) 4 else 2
            }
            for ((len, lo, hi) in ranges.sortedBy { it.first }) {
                if (i + len > b.size) continue
                var inRange = true
                for (k in 0 until len) {
                    val v = b[i + k].toInt() and 0xFF
                    if (v < (lo[k].toInt() and 0xFF) || v > (hi[k].toInt() and 0xFF)) { inRange = false; break }
                }
                if (inRange) return len
            }
            return ranges.minOfOrNull { it.first } ?: 1
        }

        companion object {
            val ONE_BYTE = CodeSpace(listOf(Triple(1, byteArrayOf(0), byteArrayOf(-1))))
            val TWO_BYTES = CodeSpace(listOf(Triple(2, byteArrayOf(0, 0), byteArrayOf(-1, -1))))
            val UTF16 = CodeSpace(emptyList(), utf16 = true)
        }
    }

    /** A parsed CMap: its codespace ranges and code to Unicode (bfchar, bfrange) or code to CID (cidchar, cidrange) entries. */
    internal class CMap(val codespace: List<Triple<Int, ByteArray, ByteArray>>, val unicode: Map<Int, String>, val cids: Map<Int, Int>)

    companion object {
        private const val MAX_RANGE = 65536

        fun of(pdf: PdfFile, font: PdfDict): PdfFont {
            val toUnicode = (pdf.resolve(font["ToUnicode"]) as? PdfStream)?.let { s -> runCatching { parseCMap(pdf.decode(s)) }.getOrNull() }
            return if (font.name("Subtype") == "Type0") type0(pdf, font, toUnicode) else simple(pdf, font, toUnicode)
        }

        private fun type0(pdf: PdfFile, font: PdfDict, toUnicode: CMap?): PdfFont {
            val descendant = pdf.array(font["DescendantFonts"])?.firstOrNull()?.let { pdf.dict(it) }
            val encoding = pdf.resolve(font["Encoding"])
            val encodingName = (encoding as? PdfName)?.name ?: ""
            val embedded = (encoding as? PdfStream)?.let { s -> runCatching { parseCMap(pdf.decode(s)) }.getOrNull() }
            val unicodeEncoding = encodingName.startsWith("Uni") && (encodingName.contains("UCS2") || encodingName.contains("UTF16"))
            val codespace = when {
                encodingName.startsWith("Identity") -> CodeSpace.TWO_BYTES
                unicodeEncoding && encodingName.contains("UTF16") -> CodeSpace.UTF16
                unicodeEncoding -> CodeSpace.TWO_BYTES
                embedded != null && embedded.codespace.isNotEmpty() -> CodeSpace(embedded.codespace)
                toUnicode != null && toUnicode.codespace.isNotEmpty() -> CodeSpace(toUnicode.codespace)
                else -> CodeSpace.TWO_BYTES
            }
            // CID of a code: Identity, an embedded CMap, else unknown (the default width applies).
            val cidOf: (Int) -> Int? = when {
                encodingName.startsWith("Identity") -> { c -> c }
                embedded != null -> { c -> embedded.cids[c] }
                else -> { _ -> null }
            }
            val defaultWidth = (pdf.resolve(descendant?.get("DW")) as? PdfNumber)?.double ?: 1000.0
            val widths = cidWidths(pdf, pdf.array(descendant?.get("W")))
            val fallback: (Int) -> String? = if (unicodeEncoding) { c -> codePointText(c) } else { _ -> null }
            return PdfFont(codespace, toUnicode?.unicode.orEmpty(), fallback) { code -> cidOf(code)?.let { widths[it] } ?: defaultWidth }
        }

        private fun cidWidths(pdf: PdfFile, w: PdfArray?): Map<Int, Double> {
            val out = HashMap<Int, Double>()
            if (w == null) return out
            var i = 0
            val items = w.map { pdf.resolve(it) }
            while (i < items.size) {
                val first = (items[i] as? PdfNumber)?.int ?: break
                val next = items.getOrNull(i + 1)
                if (next is PdfArray) {
                    next.forEachIndexed { k, v -> (pdf.resolve(v) as? PdfNumber)?.double?.let { out[first + k] = it } }
                    i += 2
                } else {
                    val last = (next as? PdfNumber)?.int ?: break
                    val width = (items.getOrNull(i + 2) as? PdfNumber)?.double ?: break
                    if (last - first in 0 until MAX_RANGE) for (c in first..last) out[c] = width
                    i += 3
                }
            }
            return out
        }

        private fun simple(pdf: PdfFile, font: PdfDict, toUnicode: CMap?): PdfFont {
            val encoding = pdf.resolve(font["Encoding"])
            val base = when (encoding) {
                is PdfName -> encoding.name
                is PdfDict -> encoding.name("BaseEncoding")
                else -> null
            }
            val table = Array<String?>(256) { c -> baseChar(base, c) }
            (encoding as? PdfDict)?.let { pdf.array(it["Differences"]) }?.let { diffs ->
                var code = 0
                for (item in diffs.map { pdf.resolve(it) }) {
                    when (item) {
                        is PdfNumber -> code = item.int
                        is PdfName -> { if (code in 0..255) table[code] = glyphText(item.name); code++ }
                        else -> {}
                    }
                }
            }
            val firstChar = (pdf.resolve(font["FirstChar"]) as? PdfNumber)?.int ?: 0
            val widths = pdf.array(font["Widths"])?.map { (pdf.resolve(it) as? PdfNumber)?.double ?: 0.0 }.orEmpty()
            val missing = (pdf.dict(font["FontDescriptor"])?.get("MissingWidth") as? PdfNumber)?.double ?: 500.0
            // Type 3 widths are in glyph space; scale them to the 1/1000 text space units used for other fonts.
            val type3Scale = if (font.name("Subtype") == "Type3") {
                ((pdf.array(font["FontMatrix"])?.firstOrNull()?.let { pdf.resolve(it) } as? PdfNumber)?.double ?: 0.001) * 1000.0
            } else 1.0
            return PdfFont(CodeSpace.ONE_BYTE, toUnicode?.unicode.orEmpty(), { c -> table.getOrNull(c) }) { code ->
                (widths.getOrNull(code - firstChar) ?: missing) * type3Scale
            }
        }

        /** The character a byte stands for in a base encoding: ASCII for printable codes, CP1252 or Latin-1 above. */
        private fun baseChar(base: String?, c: Int): String? = when {
            c in 0x20..0x7E -> when {
                base == null || base == "StandardEncoding" -> when (c) { 0x27 -> "’"; 0x60 -> "‘"; else -> c.toChar().toString() }
                else -> c.toChar().toString()
            }
            c < 0x20 -> null
            base == "WinAnsiEncoding" && c in 0x80..0x9F -> CP1252_HIGH[c - 0x80].takeIf { it != '\u0000' }?.toString()
            base == "MacRomanEncoding" || base == null || base == "StandardEncoding" -> null
            c >= 0xA0 -> c.toChar().toString()
            else -> null
        }

        private val CP1252_HIGH: CharArray = ("€\u0000‚ƒ„…†‡ˆ‰Š‹Œ\u0000Ž\u0000" +
            "\u0000‘’“”•–—˜™š›œ\u0000žŸ").toCharArray()

        private val GLYPH_NAMES = mapOf(
            "space" to " ", "exclam" to "!", "quotedbl" to "\"", "numbersign" to "#", "dollar" to "$", "percent" to "%",
            "ampersand" to "&", "quotesingle" to "'", "parenleft" to "(", "parenright" to ")", "asterisk" to "*", "plus" to "+",
            "comma" to ",", "hyphen" to "-", "period" to ".", "slash" to "/", "zero" to "0", "one" to "1", "two" to "2",
            "three" to "3", "four" to "4", "five" to "5", "six" to "6", "seven" to "7", "eight" to "8", "nine" to "9",
            "colon" to ":", "semicolon" to ";", "less" to "<", "equal" to "=", "greater" to ">", "question" to "?", "at" to "@",
            "bracketleft" to "[", "backslash" to "\\", "bracketright" to "]", "asciicircum" to "^", "underscore" to "_",
            "grave" to "`", "braceleft" to "{", "bar" to "|", "braceright" to "}", "asciitilde" to "~", "quoteleft" to "‘",
            "quoteright" to "’", "quotedblleft" to "“", "quotedblright" to "”", "endash" to "–",
            "emdash" to "—", "bullet" to "•", "nbspace" to " ", "minus" to "−", "degree" to "°",
        )

        /** Unicode text of an Adobe glyph name: uniXXXX sequences, uXXXX[XX], single letters and common punctuation. */
        internal fun glyphText(raw: String): String? {
            val name = raw.substringBefore('.').substringBefore('_').ifEmpty { return null }
            GLYPH_NAMES[name]?.let { return it }
            if (name.length == 1 && name[0].isLetter()) return name
            if (name.startsWith("uni") && name.length >= 7 && (name.length - 3) % 4 == 0) {
                val units = (3 until name.length step 4).map { name.substring(it, it + 4).toIntOrNull(16) ?: return null }
                return units.joinToString("") { it.toChar().toString() }
            }
            if (name.startsWith("u") && name.length in 5..7) return name.substring(1).toIntOrNull(16)?.let { codePointText(it) }
            return null
        }

        internal fun codePointText(cp: Int): String? = when {
            cp in 0xD800..0xDFFF && cp <= 0xFFFF -> null
            cp in 0x10000..0x10FFFF -> {
                val v = cp - 0x10000
                charArrayOf((0xD800 + (v shr 10)).toChar(), (0xDC00 + (v and 0x3FF)).toChar()).concatToString()
            }
            cp in 0x20..0xFFFF -> cp.toChar().toString()
            cp in 0x01..0x1F -> null
            else -> null
        }

        /** A UTF-16BE code-point run; 4-byte codes of UTF-16 encodings are surrogate pairs. */
        private fun utf16Text(b: ByteArray): String = PdfText.utf16be(b).filter { it != '\u0000' }

        /** Parses a CMap (ToUnicode or an embedded encoding): codespace ranges, bfchar / bfrange, cidchar / cidrange. */
        internal fun parseCMap(data: ByteArray): CMap {
            val codespace = ArrayList<Triple<Int, ByteArray, ByteArray>>()
            val unicode = HashMap<Int, String>()
            val cids = HashMap<Int, Int>()
            val operands = ArrayList<PdfObject>()
            var section: String? = null
            fun code(o: PdfObject?): Pair<Int, Int>? {
                val b = (o as? PdfString)?.bytes ?: return null
                if (b.isEmpty() || b.size > 4) return null
                var v = 0
                for (x in b) v = (v shl 8) or (x.toInt() and 0xFF)
                return v to b.size
            }
            for (t in PdfTextExtractor.tokens(data) { it.pos = it.bytes.size }) {
                if (t is PdfObject) {
                    if (section != null) operands.add(t)
                    continue
                }
                val word = (t as PdfTextExtractor.Keyword).word
                when (word) {
                    "begincodespacerange", "beginbfchar", "beginbfrange", "begincidchar", "begincidrange" -> { section = word; operands.clear(); continue }
                    "endcodespacerange" -> operands.chunked(2).forEach { pair ->
                        val lo = (pair.getOrNull(0) as? PdfString)?.bytes ?: return@forEach
                        val hi = (pair.getOrNull(1) as? PdfString)?.bytes ?: return@forEach
                        if (lo.size == hi.size && lo.size in 1..4) codespace.add(Triple(lo.size, lo, hi))
                    }
                    "endbfchar" -> operands.chunked(2).forEach { pair ->
                        val c = code(pair.getOrNull(0)) ?: return@forEach
                        val dst = pair.getOrNull(1)
                        val text = when (dst) {
                            is PdfString -> utf16Text(dst.bytes)
                            is PdfName -> glyphText(dst.name)
                            else -> null
                        }
                        if (text != null) unicode[c.first] = text
                    }
                    "endbfrange" -> operands.chunked(3).forEach { triple ->
                        val lo = code(triple.getOrNull(0))?.first ?: return@forEach
                        val hi = code(triple.getOrNull(1))?.first ?: return@forEach
                        if (hi < lo || hi - lo >= MAX_RANGE) return@forEach
                        when (val dst = triple.getOrNull(2)) {
                            is PdfString -> {
                                val b = dst.bytes
                                if (b.size < 2) {
                                    for (c in lo..hi) codePointText(((b.firstOrNull()?.toInt() ?: 0) and 0xFF) + (c - lo))?.let { unicode[c] = it }
                                } else {
                                    // The last UTF-16 unit is incremented within the range.
                                    val prefix = b.copyOf(b.size - 2)
                                    val last = ((b[b.size - 2].toInt() and 0xFF) shl 8) or (b[b.size - 1].toInt() and 0xFF)
                                    for (c in lo..hi) {
                                        val u = last + (c - lo)
                                        if (u > 0xFFFF) break
                                        unicode[c] = utf16Text(prefix + byteArrayOf((u shr 8).toByte(), u.toByte()))
                                    }
                                }
                            }
                            is PdfArray -> dst.forEachIndexed { k, item ->
                                if (lo + k <= hi) (item as? PdfString)?.let { unicode[lo + k] = utf16Text(it.bytes) }
                            }
                            else -> {}
                        }
                    }
                    "endcidchar" -> operands.chunked(2).forEach { pair ->
                        val c = code(pair.getOrNull(0)) ?: return@forEach
                        (pair.getOrNull(1) as? PdfNumber)?.int?.let { cids[c.first] = it }
                    }
                    "endcidrange" -> operands.chunked(3).forEach { triple ->
                        val lo = code(triple.getOrNull(0))?.first ?: return@forEach
                        val hi = code(triple.getOrNull(1))?.first ?: return@forEach
                        val cid = (triple.getOrNull(2) as? PdfNumber)?.int ?: return@forEach
                        if (hi >= lo && hi - lo < MAX_RANGE) for (c in lo..hi) cids[c] = cid + (c - lo)
                    }
                }
                section = null
                operands.clear()
            }
            return CMap(codespace, unicode, cids)
        }
    }
}
