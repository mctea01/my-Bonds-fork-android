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
