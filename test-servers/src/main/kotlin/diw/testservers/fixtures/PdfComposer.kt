package diw.testservers.fixtures

import diw.wallet.core.document.pdf.PdfArray
import diw.wallet.core.document.pdf.PdfDates
import diw.wallet.core.document.pdf.PdfNumber
import diw.wallet.core.document.pdf.PdfObject
import diw.wallet.core.document.pdf.PdfOutput
import diw.wallet.core.document.pdf.PdfRef
import diw.wallet.core.document.pdf.PdfString
import diw.wallet.core.document.pdf.PdfWriter
import diw.wallet.core.document.pdf.PdfDict
import diw.wallet.core.document.pdf.PdfName

import diw.wallet.core.document.DocCrypto
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Writes simple text documents as PDF: A4 pages, the predefined Traditional Chinese CID font (MSung-Light with
 * UniCNS-UCS2-H, which readers supply without embedding), headings and wrapped paragraphs, and attached files
 * (PDF/A-3 style /AF associations) such as the verifiable credential a certificate stands for.
 */
object PdfComposer {
    sealed class Block {
        class Heading(val text: String) : Block()
        class Paragraph(val text: String) : Block()
        /** A label and its value on one line (wrapped when long). */
        class Field(val label: String, val value: String) : Block()
        class Spacer(val height: Double = 12.0) : Block()
    }

    class Attachment(val name: String, val mediaType: String, val data: ByteArray, val description: String? = null)

    private const val W = 595.0
    private const val H = 842.0
    private const val MARGIN = 56.0

    fun compose(
        title: String,
        blocks: List<Block>,
        attachments: List<Attachment> = emptyList(),
        author: String? = null,
        now: Instant = Clock.System.now(),
    ): ByteArray {
        val pages = layout(blocks)
        val out = PdfOutput()
        out.append("%PDF-1.7\n%âãÏÓ\n".let { s -> ByteArray(s.length) { s[it].code.toByte() } })
        var n = 1
        val catalogNum = n++
        val pagesNum = n++
        val fontNum = n++
        val cidNum = n++
        val descNum = n++
        val infoNum = n++
        val pageNums = pages.map { Pair(n++, n++) }
        val fileNums = attachments.map { Pair(n++, n++) }

        val fileRefs = fileNums.map { PdfRef(it.first, 0) }
        val catalog = LinkedHashMap<String, PdfObject>()
        catalog["Type"] = PdfName("Catalog")
        catalog["Pages"] = PdfRef(pagesNum, 0)
        catalog["Lang"] = PdfWriter.text("zh-TW")
        if (attachments.isNotEmpty()) {
            val names = ArrayList<PdfObject>()
            attachments.forEachIndexed { i, a -> names.add(PdfWriter.text(a.name)); names.add(fileRefs[i]) }
            catalog["Names"] = PdfDict.of("EmbeddedFiles" to PdfDict.of("Names" to PdfArray(names)))
            catalog["AF"] = PdfArray(fileRefs)
            catalog["PageMode"] = PdfName("UseAttachments")
        }
        out.obj(catalogNum, 0, PdfWriter.serialize(PdfDict(catalog)))
        out.obj(pagesNum, 0, PdfWriter.serialize(PdfDict.of(
            "Type" to PdfName("Pages"), "Count" to PdfNumber.of(pages.size),
            "Kids" to PdfArray(pageNums.map { PdfRef(it.first, 0) }),
        )))
        out.obj(fontNum, 0, PdfWriter.serialize(PdfDict.of(
            "Type" to PdfName("Font"), "Subtype" to PdfName("Type0"), "BaseFont" to PdfName("MSung-Light"),
            "Encoding" to PdfName("UniCNS-UCS2-H"), "DescendantFonts" to PdfArray(listOf(PdfRef(cidNum, 0))),
        )))
        out.obj(cidNum, 0, PdfWriter.serialize(PdfDict.of(
            "Type" to PdfName("Font"), "Subtype" to PdfName("CIDFontType0"), "BaseFont" to PdfName("MSung-Light"),
            "CIDSystemInfo" to PdfDict.of("Registry" to PdfString("Adobe".encodeToByteArray()), "Ordering" to PdfString("CNS1".encodeToByteArray()), "Supplement" to PdfNumber.of(4)),
            "FontDescriptor" to PdfRef(descNum, 0), "DW" to PdfNumber.of(1000),
            "W" to PdfArray(listOf(PdfNumber.of(1), PdfNumber.of(95), PdfNumber.of(500))),
        )))
        out.obj(descNum, 0, PdfWriter.serialize(PdfDict.of(
            "Type" to PdfName("FontDescriptor"), "FontName" to PdfName("MSung-Light"), "Flags" to PdfNumber.of(6),
            "FontBBox" to PdfArray(listOf(-160, -249, 1015, 1071).map { PdfNumber.of(it) }), "ItalicAngle" to PdfNumber.of(0),
            "Ascent" to PdfNumber.of(880), "Descent" to PdfNumber.of(-120), "CapHeight" to PdfNumber.of(880), "StemV" to PdfNumber.of(93),
        )))
        val info = LinkedHashMap<String, PdfObject>()
        info["Title"] = PdfWriter.text(title)
        author?.let { info["Author"] = PdfWriter.text(it) }
        info["Producer"] = PdfWriter.text("DIW MY WALLET")
        info["CreationDate"] = PdfWriter.text(PdfDates.format(now))
        out.obj(infoNum, 0, PdfWriter.serialize(PdfDict(info)))
        pages.forEachIndexed { i, ops ->
            val (pageNum, contentNum) = pageNums[i]
            out.obj(pageNum, 0, PdfWriter.serialize(PdfDict.of(
                "Type" to PdfName("Page"), "Parent" to PdfRef(pagesNum, 0),
                "MediaBox" to PdfArray(listOf(PdfNumber.of(0), PdfNumber.of(0), PdfNumber.of(595), PdfNumber.of(842))),
                "Resources" to PdfDict.of("Font" to PdfDict.of("F1" to PdfRef(fontNum, 0))),
                "Contents" to PdfRef(contentNum, 0),
            )))
            out.stream(contentNum, 0, PdfDict.of(), ops.encodeToByteArray())
        }
        attachments.forEachIndexed { i, a ->
            val (specNum, efNum) = fileNums[i]
            val spec = LinkedHashMap<String, PdfObject>()
            spec["Type"] = PdfName("Filespec")
            spec["F"] = PdfString(a.name.map { if (it.code in 0x20..0x7E) it else '_' }.joinToString("").encodeToByteArray(), true)
            spec["UF"] = PdfWriter.text(a.name)
            spec["EF"] = PdfDict.of("F" to PdfRef(efNum, 0), "UF" to PdfRef(efNum, 0))
            spec["AFRelationship"] = PdfName("Data")
            a.description?.let { spec["Desc"] = PdfWriter.text(it) }
            out.obj(specNum, 0, PdfWriter.serialize(PdfDict(spec)))
            out.stream(efNum, 0, PdfDict.of(
                "Type" to PdfName("EmbeddedFile"), "Subtype" to PdfName(a.mediaType),
                "Params" to PdfDict.of("Size" to PdfNumber.of(a.data.size), "ModDate" to PdfWriter.text(PdfDates.format(now))),
            ), a.data)
        }
        out.xrefTable(PdfDict.of(
            "Size" to PdfNumber.of(n), "Root" to PdfRef(catalogNum, 0), "Info" to PdfRef(infoNum, 0),
            "ID" to PdfArray(List(2) { PdfString(DocCrypto.randomBytes(16), true) }.let { listOf(it[0], it[0]) }),
        ), includeFreeHead = true)
        return out.bytes()
    }

    /** Content streams, one per page. */
    private fun layout(blocks: List<Block>): List<String> {
        val pages = ArrayList<String>()
        var sb = StringBuilder()
        var y = H - MARGIN
        fun newPage() { pages.add(sb.toString()); sb = StringBuilder(); y = H - MARGIN }
        fun line(text: String, size: Double, x: Double = MARGIN) {
            if (y - size < MARGIN) newPage()
            y -= size * 1.5
            sb.append("BT /F1 ").append(fmt(size)).append(" Tf ").append(fmt(x)).append(' ').append(fmt(y)).append(" Td ")
            sb.append(ucs2(text)).append(" Tj ET\n")
        }
        for (b in blocks) when (b) {
            is Block.Heading -> wrap(b.text, 18.0, W - 2 * MARGIN).forEach { line(it, 18.0) }
            is Block.Paragraph -> b.text.split('\n').forEach { para -> wrap(para, 11.0, W - 2 * MARGIN).forEach { line(it, 11.0) } }
            is Block.Field -> {
                val labelWidth = 120.0
                val lines = wrap(b.value, 11.0, W - 2 * MARGIN - labelWidth)
                lines.forEachIndexed { i, l ->
                    if (y - 11.0 < MARGIN) newPage()
                    y -= 16.5
                    if (i == 0) sb.append("BT /F1 11 Tf ").append(fmt(MARGIN)).append(' ').append(fmt(y)).append(" Td ").append(ucs2(b.label)).append(" Tj ET\n")
                    sb.append("BT /F1 11 Tf ").append(fmt(MARGIN + labelWidth)).append(' ').append(fmt(y)).append(" Td ").append(ucs2(l)).append(" Tj ET\n")
                }
            }
            is Block.Spacer -> { y -= b.height; if (y < MARGIN) newPage() }
        }
        pages.add(sb.toString())
        return pages
    }

    private fun width(c: Char, size: Double) = (if (c.code in 0x20..0x7E) 500 else 1000) * size / 1000

    private fun wrap(text: String, size: Double, max: Double): List<String> {
        if (text.isEmpty()) return listOf("")
        val out = ArrayList<String>()
        var cur = StringBuilder()
        var w = 0.0
        for (c in text) {
            val cw = width(c, size)
            if (w + cw > max && cur.isNotEmpty()) { out.add(cur.toString()); cur = StringBuilder(); w = 0.0 }
            cur.append(c); w += cw
        }
        out.add(cur.toString())
        return out
    }

    private fun ucs2(s: String): String {
        val b = StringBuilder("<")
        for (c in s) {
            val v = if (c.isSurrogate() || c.code < 0x20) '?'.code else c.code
            b.append(v.toString(16).uppercase().padStart(4, '0'))
        }
        return b.append('>').toString()
    }

    private fun fmt(d: Double): String {
        val r = kotlin.math.round(d * 100) / 100
        return if (r == kotlin.math.floor(r)) r.toLong().toString() else r.toString()
    }
}
