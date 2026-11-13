package diw.testservers

import diw.wallet.core.document.image.ImageConversion
import diw.wallet.core.document.image.Jbig2
import diw.wallet.core.document.ofd.FontProgram
import diw.wallet.core.document.ofd.OfdColor
import diw.wallet.core.document.ofd.OfdColorStop
import diw.wallet.core.document.ofd.OfdMatrix
import diw.wallet.core.document.ofd.OfdObject
import diw.wallet.core.document.ofd.OfdPackage
import diw.wallet.core.document.ofd.OfdPathCommand
import diw.wallet.core.document.ofd.OfdShade
import diw.wallet.core.document.ofd.OfdShadePoint
import diw.wallet.core.document.ofd.OfdShading
import diw.wallet.core.document.sign.DocumentSigning
import java.io.ByteArrayInputStream
import javax.imageio.ImageIO
import kotlin.math.abs
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** OFD graphics beyond plain text and paths: embedded fonts, clips, shadings, patterns, CGTransform and JBIG2 images. */
class OfdGraphicsTest {
    private fun resource(name: String) = javaClass.getResourceAsStream("/documents/$name")!!.readBytes()

    /** Bounds of the end points of [cmds] (control points left out). */
    private fun ends(cmds: List<OfdPathCommand>): List<Double> {
        val xs = ArrayList<Double>()
        val ys = ArrayList<Double>()
        for (c in cmds) when (c) {
            is OfdPathCommand.Move -> { xs.add(c.x); ys.add(c.y) }
            is OfdPathCommand.Line -> { xs.add(c.x); ys.add(c.y) }
            is OfdPathCommand.Quad -> { xs.add(c.x); ys.add(c.y) }
            is OfdPathCommand.Cubic -> { xs.add(c.x); ys.add(c.y) }
            OfdPathCommand.Close -> {}
        }
        return listOf(xs.min(), ys.min(), xs.max(), ys.max())
    }

    private fun checkFont(p: FontProgram, composite: Boolean) {
        assertEquals(1000, p.unitsPerEm)
        assertEquals(4, p.glyphCount)
        assertEquals(1, p.glyphId(0x41))
        assertEquals(2, p.glyphId(0x4E2D))
        assertEquals(3, p.glyphId(0x1F600), "cmap format 12")
        assertEquals(0, p.glyphId(0x42))
        assertTrue(p.outline(0).none { it is OfdPathCommand.Line || it is OfdPathCommand.Cubic || it is OfdPathCommand.Quad })
        val a = p.outline(1)
        assertEquals(2, a.count { it is OfdPathCommand.Move }, "two contours")
        assertEquals(listOf(100.0, 0.0, 500.0, 700.0), ends(a))
        assertEquals(listOf(0.0, -100.0, 600.0, 800.0), ends(p.outline(3)))
        if (composite) assertEquals(listOf(100.0, -100.0, 1300.0, 800.0), ends(p.outline(2)), "scaled and moved components")
        assertTrue(p.outline(9).isEmpty())
    }

    @Test
    fun readsTrueTypeCffCidAndCollections() {
        val ttf = assertNotNull(FontProgram.parse(resource("fonts/diw-test.ttf")))
        checkFont(ttf, composite = true)
        assertTrue(ttf.outline(3).any { it is OfdPathCommand.Quad })
        val otf = assertNotNull(FontProgram.parse(resource("fonts/diw-test.otf")))
        checkFont(otf, composite = false)
        assertTrue(otf.outline(3).any { it is OfdPathCommand.Cubic })
        checkFont(assertNotNull(FontProgram.parse(resource("fonts/diw-test-cid.otf")), "CID-keyed CFF"), composite = false)
        checkFont(assertNotNull(FontProgram.parse(resource("fonts/diw-test.ttc")), "first font of a collection"), composite = true)

        // A bare CFF program, as some OFD producers embed it: the glyphs without a cmap.
        val sfnt = resource("fonts/diw-test.otf")
        fun u32(o: Int) = ((sfnt[o].toLong() and 0xFF) shl 24) or ((sfnt[o + 1].toLong() and 0xFF) shl 16) or ((sfnt[o + 2].toLong() and 0xFF) shl 8) or (sfnt[o + 3].toLong() and 0xFF)
        val count = ((sfnt[4].toInt() and 0xFF) shl 8) or (sfnt[5].toInt() and 0xFF)
        val entry = (0 until count).map { 12 + it * 16 }.first { String(sfnt, it, 4, Charsets.US_ASCII) == "CFF " }
        val cff = sfnt.copyOfRange(u32(entry + 8).toInt(), (u32(entry + 8) + u32(entry + 12)).toInt())
        val bare = assertNotNull(FontProgram.parse(cff))
        assertEquals(4, bare.glyphCount)
        assertEquals(listOf(100.0, 0.0, 500.0, 700.0), ends(bare.outline(1)))

        assertNull(FontProgram.parse("not a font at all".encodeToByteArray()))
    }

    private val ns = "xmlns:ofd=\"http://www.ofdspec.org/2016\""

    private fun page(content: String): ByteArray = DocumentSigning.zip(
        listOf(
            "OFD.xml" to "<ofd:OFD $ns Version=\"1.0\" DocType=\"OFD\"><ofd:DocBody><ofd:DocInfo><ofd:DocID>g</ofd:DocID></ofd:DocInfo>" +
                "<ofd:DocRoot>Doc_0/Document.xml</ofd:DocRoot></ofd:DocBody></ofd:OFD>",
            "Doc_0/Document.xml" to "<ofd:Document $ns><ofd:CommonData><ofd:MaxUnitID>99</ofd:MaxUnitID>" +
                "<ofd:PageArea><ofd:PhysicalBox>0 0 100 100</ofd:PhysicalBox></ofd:PageArea><ofd:PublicRes>PublicRes.xml</ofd:PublicRes>" +
                "</ofd:CommonData><ofd:Pages><ofd:Page ID=\"1\" BaseLoc=\"Pages/Page_0/Content.xml\"/></ofd:Pages></ofd:Document>",
            "Doc_0/PublicRes.xml" to "<ofd:Res $ns BaseLoc=\"Res\"><ofd:Fonts><ofd:Font ID=\"2\" FontName=\"DiwTest\"><ofd:FontFile>diw-test.ttf</ofd:FontFile></ofd:Font></ofd:Fonts></ofd:Res>",
            "Doc_0/Pages/Page_0/Content.xml" to "<ofd:Page $ns><ofd:Content><ofd:Layer ID=\"3\">$content</ofd:Layer></ofd:Content></ofd:Page>",
        ).map { it.first to it.second.encodeToByteArray() } + ("Doc_0/Res/diw-test.ttf" to resource("fonts/diw-test.ttf")),
    )

    @Test
    fun readsClipsShadingsPatternsAndGlyphIndices() {
        val seg = "<ofd:Segment Position=\"0\"><ofd:Color Value=\"255 0 0\"/></ofd:Segment><ofd:Segment Position=\"1\"><ofd:Color Value=\"0 0 255\"/></ofd:Segment>"
        val square = "<ofd:AbbreviatedData>M 0 0 L 20 0 L 20 20 L 0 20 C</ofd:AbbreviatedData>"
        val content =
            // An axial shading clipped to the left half of the object.
            "<ofd:PathObject ID=\"10\" Boundary=\"10 10 40 20\" Fill=\"true\" Stroke=\"false\">" +
                "<ofd:Clips><ofd:Clip><ofd:Area><ofd:Path Boundary=\"0 0 20 20\">$square</ofd:Path></ofd:Area></ofd:Clip></ofd:Clips>" +
                "<ofd:FillColor><ofd:AxialShd StartPoint=\"0 0\" EndPoint=\"40 0\" Extend=\"3\" MapType=\"Reflect\" MapUnit=\"10\">$seg</ofd:AxialShd></ofd:FillColor>" +
                "<ofd:AbbreviatedData>M 0 0 L 40 0 L 40 20 L 0 20 C</ofd:AbbreviatedData></ofd:PathObject>" +
                // A radial (elliptical) shading on the stroke.
                "<ofd:PathObject ID=\"11\" Boundary=\"0 40 20 20\" LineWidth=\"1\" MiterLimit=\"2\"><ofd:StrokeColor>" +
                "<ofd:RadialShd StartPoint=\"10 10\" EndPoint=\"10 10\" StartRadius=\"0\" EndRadius=\"10\" Eccentricity=\"0.5\" Angle=\"30\" Extend=\"2\">$seg</ofd:RadialShd>" +
                "</ofd:StrokeColor>$square</ofd:PathObject>" +
                // Gouraud triangles: three points, then one more joined to the last two.
                "<ofd:PathObject ID=\"12\" Boundary=\"30 40 20 20\" Fill=\"true\" Stroke=\"false\"><ofd:FillColor><ofd:GouraudShd Extend=\"1\">" +
                "<ofd:Point X=\"0\" Y=\"0\" EdgeFlag=\"0\"><ofd:Color Value=\"255 0 0\"/></ofd:Point>" +
                "<ofd:Point X=\"20\" Y=\"0\" EdgeFlag=\"0\"><ofd:Color Value=\"0 255 0\"/></ofd:Point>" +
                "<ofd:Point X=\"0\" Y=\"20\" EdgeFlag=\"0\"><ofd:Color Value=\"0 0 255\"/></ofd:Point>" +
                "<ofd:Point X=\"20\" Y=\"20\" EdgeFlag=\"1\"><ofd:Color Value=\"0 0 0\"/></ofd:Point>" +
                "<ofd:BackColor Value=\"255 255 255\"/></ofd:GouraudShd></ofd:FillColor>$square</ofd:PathObject>" +
                // A lattice of two rows of two points, under the name the schema of the standard gives it.
                "<ofd:PathObject ID=\"13\" Boundary=\"60 40 20 20\" Fill=\"true\" Stroke=\"false\"><ofd:FillColor><ofd:LaGourandShd VerticesPerRow=\"2\">" +
                "<ofd:Point X=\"0\" Y=\"0\"><ofd:Color Value=\"255 0 0\"/></ofd:Point><ofd:Point X=\"20\" Y=\"0\"><ofd:Color Value=\"0 255 0\"/></ofd:Point>" +
                "<ofd:Point X=\"0\" Y=\"20\"><ofd:Color Value=\"0 0 255\"/></ofd:Point><ofd:Point X=\"20\" Y=\"20\"><ofd:Color Value=\"0 0 0\"/></ofd:Point>" +
                "</ofd:LaGourandShd></ofd:FillColor>$square</ofd:PathObject>" +
                // A pattern of small squares, mirrored every other column.
                "<ofd:PathObject ID=\"14\" Boundary=\"0 70 30 30\" Fill=\"true\" Stroke=\"false\"><ofd:FillColor>" +
                "<ofd:Pattern Width=\"5\" Height=\"5\" XStep=\"6\" YStep=\"6\" ReflectMethod=\"Column\"><ofd:CellContent>" +
                "<ofd:PathObject ID=\"15\" Boundary=\"0 0 3 3\" Fill=\"true\" Stroke=\"false\"><ofd:FillColor Value=\"0 128 0\"/>" +
                "<ofd:AbbreviatedData>M 0 0 L 3 0 L 3 3 L 0 3 C</ofd:AbbreviatedData></ofd:PathObject>" +
                "</ofd:CellContent></ofd:Pattern></ofd:FillColor>$square</ofd:PathObject>" +
                // Text whose first two characters are one glyph, given by index.
                "<ofd:TextObject ID=\"16\" Boundary=\"40 70 50 10\" Font=\"2\" Size=\"5\">" +
                "<ofd:CGTransform CodePosition=\"0\" CodeCount=\"2\" GlyphCount=\"1\"><ofd:Glyphs>3</ofd:Glyphs></ofd:CGTransform>" +
                "<ofd:TextCode X=\"0\" Y=\"5\" DeltaX=\"5 5\">AB中</ofd:TextCode>" +
                "<ofd:CGTransform CodePosition=\"0\" CodeCount=\"1\" GlyphCount=\"1\"><ofd:Glyphs>1</ofd:Glyphs></ofd:CGTransform>" +
                "<ofd:TextCode X=\"15\" Y=\"5\">A</ofd:TextCode></ofd:TextObject>"
        val pkg = assertNotNull(OfdPackage.read(DocumentSigning.unzip(page(content))))
        val objects = pkg.pages.single().objects.associateBy { it.id }

        val axial = objects["10"] as OfdObject.Path
        val a = assertNotNull(axial.fillShade as? OfdShade.Axial)
        assertEquals(40.0, a.x1)
        assertTrue(a.extendStart && a.extendEnd)
        assertEquals("Reflect", a.mapType)
        assertEquals(10.0, a.mapUnit)
        assertEquals(OfdColor(255, 0, 0), a.stops.first().color)
        val clip = axial.clips.single().areas.single()
        assertEquals(10.0, clip.matrix.e, 1e-9, "the clip is in the object's space")
        assertEquals(10.0, clip.matrix.f, 1e-9)
        assertEquals(5, clip.commands.size)

        val radial = objects["11"] as OfdObject.Path
        val r = assertNotNull(radial.strokeShade as? OfdShade.Radial)
        assertEquals(10.0, r.r1)
        assertEquals(0.5, r.eccentricity)
        assertEquals(30.0, r.angle)
        assertTrue(!r.extendStart && r.extendEnd)
        assertEquals(2.0, radial.miterLimit)

        val g = assertNotNull((objects["12"] as OfdObject.Path).fillShade as? OfdShade.Gouraud)
        assertEquals(2, g.triangles.size)
        assertEquals(OfdShadePoint(20.0, 20.0, OfdColor(0, 0, 0)), g.triangles[1][2])
        assertEquals(listOf(20.0, 0.0), g.triangles[1].take(1).flatMap { listOf(it.x, it.y) }, "the new triangle shares the last two points")
        assertTrue(g.extend)
        assertEquals(OfdColor(255, 255, 255), g.back)
        assertEquals(2, ((objects["13"] as OfdObject.Path).fillShade as OfdShade.Gouraud).triangles.size)

        val pattern = assertNotNull((objects["14"] as OfdObject.Path).fillShade as? OfdShade.Pattern)
        assertEquals(6.0, pattern.xStep)
        assertEquals("Column", pattern.reflect)
        assertEquals(OfdColor(0, 128, 0), (pattern.objects.single() as OfdObject.Path).fill)

        val text = objects["16"] as OfdObject.Text
        assertNotNull(text.font?.file, "the embedded font file")
        assertEquals(listOf(3), text.glyphIds(0))
        assertEquals(emptyList(), text.glyphIds(1), "joined to the glyph before")
        assertNull(text.glyphIds(2), "no CGTransform: found through the cmap")
        assertEquals(listOf(1), text.glyphIds(3), "positions run on into the next TextCode")
        assertEquals(listOf(0, 1, 2, 3), text.glyphs().map { it.index })
    }

    private fun rgb(c: Int) = c and 0xFFFFFF
    private fun alpha(c: Int) = c ushr 24

    @Test
    fun rastersShadings() {
        val stops = listOf(OfdColorStop(0.0, OfdColor(255, 0, 0)), OfdColorStop(1.0, OfdColor(0, 0, 255)))
        // Axial over 0..10 of a 20 pixel row; past the end it only shows when extended.
        val axial = OfdShade.Axial(0.0, 0.0, 10.0, 0.0, stops, false, false, "Direct", 0.0)
        val px = assertNotNull(OfdShading.raster(axial, 20, 1, OfdMatrix.IDENTITY))
        assertTrue((px[0] shr 16 and 0xFF) > 230 && (px[0] and 0xFF) < 25, "red at the start")
        assertTrue((px[9] and 0xFF) > 230, "blue at the end")
        assertEquals(0, alpha(px[15]), "nothing past the end")
        val ext = assertNotNull(OfdShading.raster(axial.copy(extendEnd = true), 20, 1, OfdMatrix.IDENTITY))
        assertEquals(0x0000FF, rgb(ext[15]))
        // Repeat starts over every 5 units.
        val rep = assertNotNull(OfdShading.raster(axial.copy(mapType = "Repeat", mapUnit = 5.0), 10, 1, OfdMatrix.IDENTITY))
        assertTrue(abs((rep[0] shr 16 and 0xFF) - (rep[5] shr 16 and 0xFF)) <= 2)
        // Scaled raster: 2 pixels per unit.
        val scaled = assertNotNull(OfdShading.raster(axial, 20, 1, OfdMatrix.scale(2.0, 2.0)))
        assertTrue((scaled[19] and 0xFF) > 230)

        val radial = OfdShade.Radial(10.0, 10.0, 0.0, 10.0, 10.0, 10.0, 0.0, 0.0, stops, false, false, "Direct", 0.0)
        val rp = assertNotNull(OfdShading.raster(radial, 20, 20, OfdMatrix.IDENTITY))
        assertTrue((rp[10 * 20 + 10] shr 16 and 0xFF) > 200, "red at the centre")
        assertTrue((rp[10 * 20 + 18] and 0xFF) > 180, "blue near the rim")
        assertEquals(0, alpha(rp[0]), "the corner lies outside the circle")
        // Squeezed to an ellipse along x: a point 6 units up is past the rim, 6 units right is inside.
        val ellipse = assertNotNull(OfdShading.raster(radial.copy(eccentricity = 0.8), 20, 20, OfdMatrix.IDENTITY))
        assertTrue(alpha(ellipse[10 * 20 + 16]) > 0)
        assertEquals(0, alpha(ellipse[3 * 20 + 10]))

        val tri = OfdShade.Gouraud(
            listOf(listOf(OfdShadePoint(0.0, 0.0, OfdColor(255, 0, 0)), OfdShadePoint(10.0, 0.0, OfdColor(0, 255, 0)), OfdShadePoint(0.0, 10.0, OfdColor(0, 0, 255)))),
            false, null,
        )
        val tp = assertNotNull(OfdShading.raster(tri, 10, 10, OfdMatrix.IDENTITY))
        assertTrue((tp[0] shr 16 and 0xFF) > 200, "red corner")
        assertEquals(0, alpha(tp[9 * 10 + 9]), "outside the triangle")
        val back = assertNotNull(OfdShading.raster(tri.copy(extend = true, back = OfdColor(255, 255, 255)), 10, 10, OfdMatrix.IDENTITY))
        assertEquals(0xFFFFFF, rgb(back[9 * 10 + 9]))

        // The PNG other decoders read back.
        val png = OfdShading.png(20, 20, rp)
        val img = assertNotNull(ImageIO.read(ByteArrayInputStream(png)))
        assertEquals(20, img.width)
        assertEquals(rp[10 * 20 + 10], img.getRGB(10, 10))
        assertEquals(0, alpha(img.getRGB(0, 0)))
        assertNull(OfdShading.raster(OfdShade.Pattern(1.0, 1.0, 1.0, 1.0, OfdMatrix.IDENTITY, "Normal", false, emptyList()), 4, 4, OfdMatrix.IDENTITY))
    }

    /**
     * A JBIG2 file with its own header (sequential organisation) and one generic region, from the pdf.js test suite
     * (jbig2_file_header.pdf, Apache License 2.0).
     */
    private val jbig2File = (
        "974a42320d0a1a0a0100000001000000003000010000001300000080000000600000000000000000010000000000012600010000003e" +
            "00000080000000600000000000000000000003fffdff02fefefeab5e45b44cd954041e0f931e83ff7fff7fff7fff106b99658488a5" +
            "5599fb2bdf8b1fffac00000002310001000000000000000333000100000000"
        ).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun decodesJbig2() {
        assertTrue(Jbig2.isFile(jbig2File))
        val bmp = Jbig2.decode(jbig2File)
        assertEquals(128, bmp.width)
        assertEquals(96, bmp.height)
        var black = 0
        for (y in 0 until bmp.height) for (x in 0 until bmp.width) if (bmp[x, y] != 0) black++
        assertEquals(5043, black)
        assertTrue(bmp[20, 40] != 0)
        assertEquals(0, bmp[60, 40])
        assertTrue(bmp[100, 20] != 0)
        assertEquals(0, bmp[100, 48])

        // Through the image conversion the OFD viewer uses: black stays black.
        val png = assertNotNull(ImageConversion.jbig2(jbig2File))
        val img = assertNotNull(ImageIO.read(ByteArrayInputStream(png)))
        assertEquals(128, img.width)
        assertEquals(0, img.getRGB(20, 40) and 0xFFFFFF)
        assertEquals(0xFFFFFF, img.getRGB(60, 40) and 0xFFFFFF)

        assertFailsWith<Exception> { Jbig2.decode(jbig2File.copyOf(40)) }
        assertContentEquals(jbig2File.copyOf(8), byteArrayOf(0x97.toByte(), 0x4A, 0x42, 0x32, 0x0D, 0x0A, 0x1A, 0x0A))
    }
}
