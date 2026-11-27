package diw.wallet.core.document.zkpdf

import diw.wallet.core.document.pdf.*

/** PDF structure and decoding helpers for the public side of zkPDF. */
object PdfZkSupport {
    fun signedRevision(pdf: ByteArray, byteRange: IntArray, password: String = ""): PdfFile = zkPdfInput {
        val end = byteRangeEnd(pdf.size, byteRange)
        val covered = pdf.copyOf(end)
        val eof = PdfParser.lastIndexOf(covered, "%%EOF".encodeToByteArray())
        require(eof >= 0 && (eof + 5 until end).all { PdfParser.isWhite(covered[it].toInt() and 255) })
        PdfFile(covered, password).also {
            require(!it.reconstructed && it.revisions.first().xrefOffset < eof)
            require(it.encryptionProblem == null)
        }
    }

    fun pageContentObject(pdf: PdfFile, index: Int): Int = zkPdfInput {
        require(!pdf.reconstructed)
        val page = PdfTextExtractor.pages(pdf).getOrNull(index) ?: error("Page unavailable")
        val ref = page["Contents"] as? PdfRef ?: error("Content must be an indirect stream")
        require(ref.gen == pdf.generation(ref.num) && pdf.getObject(ref.num) is PdfStream)
        ref.num
    }

    /**
     * Object numbers of the streams that [page] shows besides its fonts, in the order they are found: its content
     * streams, its thumbnail, every XObject of its resources (form XObjects with the XObjects and patterns of their
     * own resources, images with their masks), tiling patterns, and the appearance streams of its annotations with
     * their resources, except those of signature fields (the signature itself stays public). These are the streams whose data a masked file must not keep for a page that is not proven
     * (p4-circuits.md 3.11). Only object structure is read, so it works on the masked file as well.
     */
    fun drawnStreams(pdf: PdfFile, page: PdfDict): List<Int> = zkPdfInput {
        val out = LinkedHashSet<Int>()
        fun stream(o: PdfObject?): PdfStream? {
            val ref = o as? PdfRef ?: return null
            if (ref.num in out) return null
            val s = pdf.getObject(ref.num) as? PdfStream ?: return null
            out.add(ref.num)
            return s
        }
        lateinit var resources: (PdfObject?, Int) -> Unit
        fun xobject(s: PdfStream, depth: Int) {
            when (s.dict.name("Subtype")) {
                "Form" -> resources(s.dict["Resources"], depth + 1)
                "Image" -> { stream(s.dict["SMask"]); stream(s.dict["Mask"]) }
            }
        }
        fun appearance(o: PdfObject?, depth: Int) {
            stream(o)?.let { resources(it.dict["Resources"], depth + 1); return }
            pdf.dict(o)?.entries?.values?.forEach { state -> stream(state)?.let { resources(it.dict["Resources"], depth + 1) } }
        }
        resources = fun(o: PdfObject?, depth: Int) {
            require(depth <= 16) { "Resources nested too deeply" }
            val r = pdf.dict(o) ?: return
            pdf.dict(r["XObject"])?.entries?.values?.forEach { x -> stream(x)?.let { xobject(it, depth) } }
            pdf.dict(r["Pattern"])?.entries?.values?.forEach { p -> stream(p)?.let { resources(it.dict["Resources"], depth + 1) } }
        }
        when (val contents = page["Contents"]) {
            is PdfRef -> if (stream(contents) == null) pdf.array(contents)?.forEach { stream(it) }
            is PdfArray -> contents.forEach { stream(it) }
            else -> {}
        }
        stream(page["Thumb"])
        resources(page["Resources"], 0)
        pdf.array(page["Annots"])?.forEach { a ->
            val annotation = pdf.dict(a) ?: return@forEach
            // A signature field shows the signature, which the masked file keeps public anyway.
            if (annotation.name("Subtype") == "Widget" &&
                (annotation.name("FT") ?: pdf.dict(annotation["Parent"])?.name("FT")) == "Sig") return@forEach
            val ap = pdf.dict(annotation["AP"]) ?: return@forEach
            listOf("N", "R", "D").forEach { appearance(ap[it], 0) }
        }
        out.toList()
    }

    fun streamExtent(pdf: PdfFile, num: Int): IntRange = zkPdfInput {
        require(!pdf.reconstructed)
        val offset = pdf.offsetOf(num) ?: error("Stream must be stored directly")
        val parser = PdfParser(pdf.bytes, offset) { dictionary ->
            val length = (pdf.resolve(dictionary["Length"]) as? PdfNumber)?.long
                ?: error("Stream length unavailable")
            require(length in 0..pdf.bytes.size.toLong())
            length.toInt()
        }
        val (actual, generation, value) = parser.parseIndirect()
        require(actual == num && generation == pdf.generation(num) && value is PdfStream)
        val range = parser.lastStreamExtent ?: error("Stream extent unavailable")
        val declared = (pdf.resolve(value.dict["Length"]) as? PdfNumber)?.long
        require(declared == range.count().toLong())
        range
    }

    /** Null for unencrypted files, unsupported handlers, or a non-empty user password. */
    fun rc4KeyStream(pdf: PdfFile, num: Int, length: Int): ByteArray? = zkPdfInput {
        require(length >= 0)
        if (!pdf.encrypted) return@zkPdfInput null
        // The encryption dictionary itself is never encrypted. Read its raw
        // object instead of passing /O and /U through normal object decryption.
        val enc = when (val reference = pdf.trailer["Encrypt"]) {
            is PdfDict -> reference
            is PdfRef -> {
                val offset = pdf.offsetOf(reference.num) ?: return@zkPdfInput null
                val (number, generation, value) = PdfParser(pdf.bytes, offset).parseIndirect()
                require(number == reference.num && generation == reference.gen)
                value as? PdfDict ?: return@zkPdfInput null
            }
            else -> return@zkPdfInput null
        }
        if (enc.name("Filter") != "Standard" || (enc["V"] as? PdfNumber)?.int != 2 ||
            (enc["R"] as? PdfNumber)?.int != 3) return@zkPdfInput null
        val bits = (enc["Length"] as? PdfNumber)?.int ?: 40
        if (bits !in 40..128 || bits % 8 != 0) return@zkPdfInput null
        val handler = try { StandardSecurity.open(enc, pdf.firstId(), "") } catch (_: PdfException) {
            return@zkPdfInput null
        }
        require(length <= streamExtent(pdf, num).count())
        handler.decryptStream(ByteArray(length), num, pdf.generation(num))
    }

    fun fontDecoders(pdf: PdfFile, index: Int): Map<String, ZkFontDecoder> = zkPdfInput {
        val page = PdfTextExtractor.pages(pdf).getOrNull(index) ?: error("Page unavailable")
        val resources = pdf.dict(page["Resources"])
        val fonts = pdf.dict(resources?.get("Font")) ?: return@zkPdfInput emptyMap()
        fonts.entries.mapValues { (_, reference) ->
            val dictionary = pdf.dict(reference) ?: error("Font unavailable")
            val kind = if (dictionary.name("Subtype") == "Type0") {
                require(dictionary.name("Encoding") == "Identity-H" && pdf.resolve(dictionary["ToUnicode"]) is PdfStream)
                2
            } else {
                require(dictionary.name("Subtype") in setOf("Type1", "MMType1", "TrueType", "Type3"))
                1
            }
            FontDecoder(PdfFont.of(pdf, dictionary), kind)
        }
    }

    private class FontDecoder(private val font: PdfFont, override val kind: Int) : ZkFontDecoder {
        override fun decode(raw: ByteArray, literal: Boolean): String = zkPdfInput {
            val decoded = decodeZkString(raw, literal)
            require(kind != 2 || decoded.size % 2 == 0)
            font.codes(decoded).joinToString("") { (code, _) -> font.unicode(code) ?: error("Unmapped font code") }
        }

        override fun digitCodes(): IntArray? {
            val codes = IntArray(10) { -1 }
            for (code in 0 until if (kind == 1) 256 else 65536) {
                val text = font.unicode(code) ?: continue
                if (text.length != 1 || text[0] !in '0'..'9') continue
                val digit = text[0] - '0'
                if (codes[digit] != -1) return null
                codes[digit] = code
            }
            return codes.takeIf { it.all { code -> code >= 0 } }
        }
    }
}

interface ZkFontDecoder {
    val kind: Int
    /** Raw source bytes without delimiters; false denotes ASCII hex source, not already decoded bytes. */
    fun decode(raw: ByteArray, literal: Boolean): String
    fun digitCodes(): IntArray?
}

/** Reuses the existing PDF string parser, including octal escapes, nested parentheses and odd hex nibbles. */
internal fun decodeZkString(raw: ByteArray, literal: Boolean): ByteArray {
    val source = byteArrayOf(if (literal) 40 else 60) + raw + byteArrayOf(if (literal) 41 else 62)
    val parser = PdfParser(source)
    val string = parser.parseObject() as? PdfString ?: error("Invalid PDF string")
    require(parser.pos == source.size)
    return string.bytes
}

/** Never propagate parser diagnostics that might quote document bytes or a password. */
internal inline fun <T> zkPdfInput(block: () -> T): T = try {
    block()
} catch (_: Exception) {
    throw PdfException("Unsupported or malformed zkPDF input")
}
