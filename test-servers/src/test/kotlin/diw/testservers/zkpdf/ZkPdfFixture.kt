package diw.testservers.zkpdf

import diw.wallet.core.document.pdf.*
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.encryption.AccessPermission
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy
import java.io.ByteArrayOutputStream
import java.util.zip.DeflaterOutputStream

/** All PDF bytes, font maps and encrypted variants are generated from synthetic text. */
object ZkPdfFixture {
    val content = """
        BT /F1 12 Tf 1 0 0 1 60 780 Tm (Synthetic \(A\):) Tj
        1 0 0 1 200 780 Tm [(20) 0 (26)] TJ
        /F2 12 Tf 1 0 0 1 60 750 Tm <200020011000100110021003100410051006100710081009> Tj ET
    """.trimIndent() + "\n"

    val cmap = """
        /CIDInit /ProcSet findresource begin 12 dict begin begincmap
        /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
        /CMapName /Synthetic-UCS def /CMapType 2 def
        1 begincodespacerange <0000> <FFFF> endcodespacerange
        3 beginbfchar <2000> <6E2C> <2001> <8A66> <1000> <0030> endbfchar
        2 beginbfrange <1001> <1004> <0031> <1005> <1009> [<0035> <0036> <0037> <0038> <0039>] endbfrange
        endcmap CMapName currentdict /CMap defineresource pop end end
    """.trimIndent()

    fun pdf(text: String = content, cmapText: String = cmap, differences: String = "225 /uni00C1",
        arrayContents: Boolean = false, wrongLength: Boolean = false, formText: String? = null): ByteArray {
        val out = PdfOutput()
        out.append("%PDF-1.7\n")
        out.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>")
        val xobjects = if (formText != null) "/XObject << /Fm1 9 0 R >>" else ""
        out.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R /F2 6 0 R >> $xobjects >> >>")
        val contents = if (arrayContents) "[4 0 R]" else "4 0 R"
        out.obj(3, 0, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents $contents >>")
        val compressed = ByteArrayOutputStream().also { sink ->
            DeflaterOutputStream(sink).use { it.write(text.toByteArray()) }
        }.toByteArray()
        if (wrongLength) {
            out.offsets[4] = out.size to 0
            out.append("4 0 obj\n<< /Length ${compressed.size + 2} /Filter /FlateDecode >>\nstream\n")
            out.append(compressed)
            out.append("\nendstream\nendobj\n")
        } else out.stream(4, 0, PdfDict.of("Filter" to PdfName("FlateDecode")), compressed)
        out.obj(5, 0, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [$differences] >> >>")
        out.obj(6, 0, "<< /Type /Font /Subtype /Type0 /BaseFont /Synthetic /Encoding /Identity-H /DescendantFonts [7 0 R] /ToUnicode 8 0 R >>")
        out.obj(7, 0, "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Synthetic /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 1000 /W [4096 4105 500] >>")
        out.stream(8, 0, PdfDict.of(), cmapText.toByteArray())
        if (formText != null) out.stream(9, 0, PdfDict.of("Type" to PdfName("XObject"), "Subtype" to PdfName("Form"),
            "BBox" to PdfArray(listOf(0, 0, 595, 842).map { PdfNumber.of(it) }),
            "Resources" to PdfDict.of("Font" to PdfDict.of("F1" to PdfRef(6, 0)))), formText.toByteArray())
        out.xrefTable(PdfDict.of("Size" to PdfNumber.of(if (formText != null) 10 else 9), "Root" to PdfRef(1, 0),
            "ID" to PdfArray(List(2) { PdfString(ByteArray(16) { i -> i.toByte() }, true) })), true)
        return out.bytes()
    }

    fun encrypt(bytes: ByteArray, user: String = "", bits: Int = 128, aes: Boolean = false): ByteArray =
        Loader.loadPDF(bytes).use { document ->
            val policy = StandardProtectionPolicy("synthetic-owner-password", user, AccessPermission())
            policy.encryptionKeyLength = bits
            policy.isPreferAES = aes
            document.protect(policy)
            ByteArrayOutputStream().also { document.save(it) }.toByteArray()
        }

    fun replaceContent(bytes: ByteArray): ByteArray {
        val file = PdfFile(bytes)
        val out = PdfOutput(bytes)
        out.stream(4, 0, PdfDict.of(), "BT /F1 12 Tf 60 700 Td (Later revision) Tj ET".toByteArray())
        out.xrefTable(file.trailer.with("Prev", PdfNumber.of(file.revisions.first().xrefOffset)), false)
        return out.bytes()
    }

    fun corruptUserCheck(bytes: ByteArray): ByteArray {
        val file = PdfFile(bytes)
        val ref = file.trailer["Encrypt"] as PdfRef
        val (_, _, value) = PdfParser(bytes, file.offsetOf(ref.num)!!).parseIndirect()
        val dictionary = (value as PdfDict).with("U", PdfString(ByteArray(32), true))
        val out = PdfOutput(bytes)
        out.obj(ref.num, ref.gen, PdfWriter.serialize(dictionary))
        out.xrefTable(file.trailer.with("Prev", PdfNumber.of(file.revisions.first().xrefOffset)), false)
        return out.bytes()
    }

    fun appendPublicMarker(bytes: ByteArray): ByteArray {
        val file = PdfFile(bytes)
        val out = PdfOutput(bytes)
        out.obj(file.size, 0, "<< /SyntheticMarker true >>")
        out.xrefTable(file.trailer.with("Size", PdfNumber.of(file.size + 1))
            .with("Prev", PdfNumber.of(file.revisions.first().xrefOffset)), false)
        return out.bytes()
    }
}
