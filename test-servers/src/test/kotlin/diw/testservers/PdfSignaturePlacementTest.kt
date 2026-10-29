package diw.testservers

import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfSignatures
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Signature widget placement (C12 viewing): PdfSignatures.placements maps a signature field's /Rect to a top-left
 * normalized box on its page, applies the page /Rotate, and marks a zero-sized widget as not visible.
 */
class PdfSignaturePlacementTest {

    /** A one-page PDF with one AcroForm signature field whose widget has [rect] on a [w]x[h] page rotated [rotate]. */
    private fun pdf(rect: String, w: Int = 200, h: Int = 100, rotate: Int = 0): ByteArray {
        val objs = listOf(
            "<</Type/Catalog/Pages 2 0 R/AcroForm 5 0 R>>",
            "<</Type/Pages/Kids[3 0 R]/Count 1>>",
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 $w $h]/Rotate $rotate/Annots[4 0 R]>>",
            "<</Type/Annot/Subtype/Widget/FT/Sig/T(Sig1)/Rect[$rect]/P 3 0 R/F 4>>",
            "<</Fields[4 0 R]/SigFlags 3>>",
        )
        val sb = StringBuilder("%PDF-1.7\n")
        val offsets = IntArray(objs.size + 1)
        objs.forEachIndexed { i, body ->
            offsets[i + 1] = sb.length
            sb.append("${i + 1} 0 obj\n$body\nendobj\n")
        }
        val xref = sb.length
        sb.append("xref\n0 ${objs.size + 1}\n0000000000 65535 f \n")
        for (i in 1..objs.size) sb.append(offsets[i].toString().padStart(10, '0')).append(" 00000 n \n")
        sb.append("trailer\n<</Size ${objs.size + 1}/Root 1 0 R>>\nstartxref\n$xref\n%%EOF\n")
        return sb.toString().encodeToByteArray()
    }

    @Test
    fun rectBecomesTopLeftFraction() {
        val p = PdfSignatures(PdfFile(pdf("50 20 150 60"))).placements()
        assertEquals(1, p.size)
        val it = p.single()
        assertEquals("Sig1", it.fieldName)
        assertEquals(0, it.page)
        assertTrue(it.visible)
        assertEquals(0.25f, it.x0, 1e-4f)
        assertEquals(0.75f, it.x1, 1e-4f)
        assertEquals(0.40f, it.y0, 1e-4f) // (100 - 60) / 100
        assertEquals(0.80f, it.y1, 1e-4f) // (100 - 20) / 100
    }

    @Test
    fun pageRotationIsApplied() {
        // Rotate 90 clockwise sends the unrotated top-left box (x, y) to (1 - y, x).
        val it = PdfSignatures(PdfFile(pdf("50 20 150 60", rotate = 90))).placements().single()
        assertTrue(it.visible)
        // Unrotated: x 0.25..0.75, y 0.40..0.80. After (1-y, x): x 0.20..0.60, y 0.25..0.75.
        assertEquals(0.20f, it.x0, 1e-4f)
        assertEquals(0.60f, it.x1, 1e-4f)
        assertEquals(0.25f, it.y0, 1e-4f)
        assertEquals(0.75f, it.y1, 1e-4f)
    }

    @Test
    fun zeroRectIsInvisible() {
        val it = PdfSignatures(PdfFile(pdf("0 0 0 0"))).placements().single()
        assertEquals("Sig1", it.fieldName)
        assertTrue(!it.visible)
    }
}
