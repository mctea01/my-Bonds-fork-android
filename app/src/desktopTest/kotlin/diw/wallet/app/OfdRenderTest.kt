package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asSkiaBitmap
import androidx.compose.ui.text.font.createFontFamilyResolver
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.ofd.OfdPackage
import diw.wallet.core.document.sign.DocumentSigning
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** OFD pages drawn with Compose graphics: text, paths, the seal picture where it was stamped. */
class OfdRenderTest {
    private val renderer = OfdRenderer(createFontFamilyResolver()) { decodeImageBytes(it.bytes) }

    private fun pixels(image: ImageBitmap): IntArray = IntArray(image.width * image.height).also { image.readPixels(it) }

    private fun save(name: String, image: ImageBitmap) {
        val dir = System.getenv("DIW_OFD_OUT") ?: return
        val data = org.jetbrains.skia.Image.makeFromBitmap(image.asSkiaBitmap()).encodeToData(org.jetbrains.skia.EncodedImageFormat.PNG)!!.bytes
        File(dir).apply { mkdirs() }.resolve("$name.png").writeBytes(data)
    }

    /** The share of pixels that are not white. */
    private fun ink(p: IntArray) = p.count { (it and 0xFFFFFF) != 0xFFFFFF }.toDouble() / p.size

    @Test
    fun drawsTextPathsAndSeal() {
        val bytes = File("../test-servers/src/test/resources/documents/signed-sesv4.ofd").readBytes()
        val pkg = assertNotNull(OfdPackage.read(DocumentSigning.unzip(bytes)))
        val page = pkg.pages.single()
        val plain = renderer.render(page, 800)
        assertEquals(800, plain.width)
        assertTrue(kotlin.math.abs((800 * page.box.h / page.box.w) - plain.height) <= 1.0, "page height")
        assertTrue(ink(pixels(plain)) > 0.001, "text drawn")

        val stamp = DocumentInspector.ofdStamps(bytes).single()
        val seal = assertNotNull(stamp.picture?.let { decodeImageBytes(it) }, "seal picture " + stamp.pictureFormat)
        val sealed = renderer.render(page, 800, listOf(OfdRenderer.Overlay(seal, stamp.boundary.x, stamp.boundary.y, stamp.boundary.w, stamp.boundary.h)))
        assertTrue(ink(pixels(sealed)) > ink(pixels(plain)), "seal drawn")
        save("ofd-seal", sealed)
    }

    private val ns = "xmlns:ofd=\"http://www.ofdspec.org/2016\""

    /** A 100 by 100 mm page with [content] and the synthetic test font as resource 2. */
    private fun page(content: String) = assertNotNull(
        OfdPackage.read(
            DocumentSigning.unzip(
                DocumentSigning.zip(
                    listOf(
                        "OFD.xml" to "<ofd:OFD $ns Version=\"1.0\" DocType=\"OFD\"><ofd:DocBody><ofd:DocInfo><ofd:DocID>g</ofd:DocID></ofd:DocInfo>" +
                            "<ofd:DocRoot>Doc_0/Document.xml</ofd:DocRoot></ofd:DocBody></ofd:OFD>",
                        "Doc_0/Document.xml" to "<ofd:Document $ns><ofd:CommonData><ofd:MaxUnitID>99</ofd:MaxUnitID>" +
                            "<ofd:PageArea><ofd:PhysicalBox>0 0 100 100</ofd:PhysicalBox></ofd:PageArea><ofd:PublicRes>PublicRes.xml</ofd:PublicRes>" +
                            "</ofd:CommonData><ofd:Pages><ofd:Page ID=\"1\" BaseLoc=\"Pages/Page_0/Content.xml\"/></ofd:Pages></ofd:Document>",
                        "Doc_0/PublicRes.xml" to "<ofd:Res $ns BaseLoc=\"Res\"><ofd:Fonts><ofd:Font ID=\"2\" FontName=\"DiwTest\">" +
                            "<ofd:FontFile>diw-test.ttf</ofd:FontFile></ofd:Font></ofd:Fonts></ofd:Res>",
                        "Doc_0/Pages/Page_0/Content.xml" to "<ofd:Page $ns><ofd:Content><ofd:Layer ID=\"3\">$content</ofd:Layer></ofd:Content></ofd:Page>",
                    ).map { it.first to it.second.encodeToByteArray() } +
                        ("Doc_0/Res/diw-test.ttf" to File("../test-servers/src/test/resources/documents/fonts/diw-test.ttf").readBytes()),
                ),
            ),
        ),
    ).pages.single()

    private fun at(p: IntArray, x: Int, y: Int) = p[y * 1000 + x] and 0xFFFFFF

    @Test
    fun drawsEmbeddedGlyphsClipsShadingsAndPatterns() {
        val seg = "<ofd:Segment Position=\"0\"><ofd:Color Value=\"255 0 0\"/></ofd:Segment><ofd:Segment Position=\"1\"><ofd:Color Value=\"0 0 255\"/></ofd:Segment>"
        val content =
            // Glyph A of the embedded font (a square ring) 40 mm high at baseline y = 40.
            "<ofd:TextObject ID=\"10\" Boundary=\"0 0 60 50\" Font=\"2\" Size=\"40\"><ofd:FillColor Value=\"0 0 0\"/>" +
                "<ofd:TextCode X=\"0\" Y=\"40\">A</ofd:TextCode></ofd:TextObject>" +
                // An axial gradient over 60..100 clipped to its left half (60..80).
                "<ofd:PathObject ID=\"11\" Boundary=\"60 0 40 30\" Fill=\"true\" Stroke=\"false\">" +
                "<ofd:Clips><ofd:Clip><ofd:Area><ofd:Path Boundary=\"0 0 20 30\"><ofd:AbbreviatedData>M 0 0 L 20 0 L 20 30 L 0 30 C</ofd:AbbreviatedData></ofd:Path></ofd:Area></ofd:Clip></ofd:Clips>" +
                "<ofd:FillColor><ofd:AxialShd StartPoint=\"0 0\" EndPoint=\"40 0\">$seg</ofd:AxialShd></ofd:FillColor>" +
                "<ofd:AbbreviatedData>M 0 0 L 40 0 L 40 30 L 0 30 C</ofd:AbbreviatedData></ofd:PathObject>" +
                // A Gouraud triangle with a red corner at (0, 60).
                "<ofd:PathObject ID=\"12\" Boundary=\"0 60 30 30\" Fill=\"true\" Stroke=\"false\"><ofd:FillColor><ofd:GouraudShd>" +
                "<ofd:Point X=\"0\" Y=\"0\" EdgeFlag=\"0\"><ofd:Color Value=\"255 0 0\"/></ofd:Point>" +
                "<ofd:Point X=\"30\" Y=\"0\" EdgeFlag=\"0\"><ofd:Color Value=\"0 255 0\"/></ofd:Point>" +
                "<ofd:Point X=\"0\" Y=\"30\" EdgeFlag=\"0\"><ofd:Color Value=\"0 0 255\"/></ofd:Point>" +
                "</ofd:GouraudShd></ofd:FillColor><ofd:AbbreviatedData>M 0 0 L 30 0 L 30 30 L 0 30 C</ofd:AbbreviatedData></ofd:PathObject>" +
                // A pattern: a 3 mm green square in every 6 mm cell.
                "<ofd:PathObject ID=\"13\" Boundary=\"50 50 30 30\" Fill=\"true\" Stroke=\"false\"><ofd:FillColor>" +
                "<ofd:Pattern Width=\"6\" Height=\"6\"><ofd:CellContent>" +
                "<ofd:PathObject ID=\"14\" Boundary=\"0 0 3 3\" Fill=\"true\" Stroke=\"false\"><ofd:FillColor Value=\"0 128 0\"/>" +
                "<ofd:AbbreviatedData>M 0 0 L 3 0 L 3 3 L 0 3 C</ofd:AbbreviatedData></ofd:PathObject>" +
                "</ofd:CellContent></ofd:Pattern></ofd:FillColor><ofd:AbbreviatedData>M 0 0 L 30 0 L 30 30 L 0 30 C</ofd:AbbreviatedData></ofd:PathObject>"
        val image = renderer.render(page(content), 1000)
        save("ofd-graphics", image)
        val p = pixels(image)
        // 10 pixels per mm. The ring of A: x 4..20 mm, y 12..40 mm; its hole x 8..16, y 16..36.
        assertEquals(0x000000, at(p, 60, 300), "the glyph's ring")
        assertEquals(0xFFFFFF, at(p, 120, 260), "the glyph's hole")
        assertEquals(0xFFFFFF, at(p, 250, 300), "beyond the glyph")
        // The gradient shows only inside the clip.
        val left = at(p, 605, 150)
        assertTrue((left shr 16) > 200 && (left and 0xFF) < 60, "red at the start of the gradient")
        assertTrue((at(p, 790, 150) and 0xFF) > 80, "turning blue towards the clip edge")
        assertEquals(0xFFFFFF, at(p, 900, 150), "clipped away")
        // Gouraud corners and the space outside the triangle.
        assertTrue((at(p, 15, 615) shr 16) > 200, "red corner")
        assertEquals(0xFFFFFF, at(p, 280, 880), "outside the triangle")
        // Pattern: squares at 0..3 of every 6 mm cell, gaps between.
        assertEquals(0x008000, at(p, 515, 515))
        assertEquals(0x008000, at(p, 575, 575))
        assertEquals(0xFFFFFF, at(p, 545, 545))
        assertEquals(0xFFFFFF, at(p, 850, 850), "outside the pattern's path")
    }

    @Test
    fun drawsSealPictures() {
        val resolver = createFontFamilyResolver()
        for ((name, personal) in listOf("測試科技股份有限公司" to false, "王小明" to true)) {
            val img = SealPicture.draw(name, personal, resolver, 240)
            save(if (personal) "seal-person" else "seal-org", img)
            val p = pixels(img)
            val red = p.count { (it ushr 24) > 128 && (it shr 16 and 0xFF) > 150 && (it shr 8 and 0xFF) < 80 }
            assertTrue(red > p.size / 30, "seal red drawn: $red")
            if (!personal) assertEquals(0, p[0] ushr 24, "the corner outside the round seal stays transparent")
        }
    }

    /** A local file for a visual check: DIW_OFD_SAMPLE names it, DIW_OFD_OUT where its pages go. */
    @Test
    fun drawsLocalSample() {
        val path = System.getenv("DIW_OFD_SAMPLE") ?: return
        val bytes = File(path).readBytes()
        val pkg = assertNotNull(OfdPackage.read(DocumentSigning.unzip(bytes)))
        pkg.pages.take(3).forEachIndexed { i, p -> save("ofd-sample-$i", renderer.render(p, 1080)) }
    }
}
